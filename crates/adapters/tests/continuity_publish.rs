//! `adapters::tests::continuity_publish` — M14-2 gates G-M14-1 and G-M14-2 against a real PostgreSQL.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, postgres, serde_json, sqlx, tokio,
//!   uuid]; services=[PostgreSQL(owner) r=[private.memory_records] w=[control.private_reasoning_domains,
//!   control.tenants, control.workspaces, private.evidence_objects, private.memory_evidence,
//!   private.memory_records], PostgreSQL(role_gateway)
//!   r=[private.continuity_facet_slots, private.continuity_facet_versions]];
//!   env=[HUMAUX_REQUIRE_DB, HUMAUX_TEST_PG_DSN]; modules=[adapters::continuity_repo, adapters::postgres,
//!   domain::continuity, domain::error, domain::identity, domain::ids, humaux-testkit, testkit::fixture_purge]
//! Called-by: [cargo-test]
//! Invariants: [G-M14-1: two overlapping publishes of one scalar slot leave exactly one version, one winner and one
//!   typed CONFLICT carrying that version; G-M14-2: 80 concurrent list writers leave exactly 80 items (the full union)
//!   in 80 versions, and a conflicted list writer retries and unions the winner's item; the block is proved through
//!   pg_blocking_pids, never a sleep; every fixture tenant is purged by the one fixture purge; a missing database is a
//!   failure when HUMAUX_REQUIRE_DB=1, never a silent pass]
//! Spec: Baseline §25.3.1; §52 D-B; §79.2; §80.1; ADR-0094

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use humaux_adapters::{
    continuity_repo::{
        self, ContinuityMemorySource, PublishContinuityFacet, PublishFacetOutcome,
        RegisterContinuityProject,
    },
    postgres::RuntimeDbPool,
};
use humaux_domain::{
    continuity::{ContinuityFacetKind, ContinuityPublishState, ProjectId},
    error::{ConflictReason, ErrorCode},
    identity::{AuthorizationScope, BoundedSet, PrincipalId},
    ids::{TenantId, WorkspaceId},
};
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, fixture_purge, run_db_fixture};
use postgres::{Client, NoTls};
use serde_json::{Value, json};
use tokio::runtime::Runtime;
use uuid::Uuid;

const WRITERS: usize = 80;
const WRITER_ATTEMPTS: usize = 100;
const THREAD_TIMEOUT: Duration = Duration::from_secs(60);
const BLOCK_TIMEOUT: Duration = Duration::from_secs(15);

fn dsn_as_role(admin_dsn: &str, role: &str) -> String {
    let sep = if admin_dsn.contains('?') { '&' } else { '?' };
    format!("{admin_dsn}{sep}options=-c%20role%3D{role}")
}

fn runtime() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
}

fn gateway_pool(rt: &Runtime, dsn: &str) -> RuntimeDbPool {
    // dep: PostgreSQL(role_gateway) — the typed pool `register_project` takes
    rt.block_on(RuntimeDbPool::connect(dsn))
        .expect("role_gateway pool")
}

/// A plain `role_gateway` pool: the door takes a caller-owned transaction, so the test opens it on
/// its own connection (the typed wrappers deliberately do not expose theirs, §6.2.3).
fn gateway_raw(rt: &Runtime, dsn: &str) -> sqlx::Pool<sqlx::Postgres> {
    // dep: PostgreSQL(role_gateway) — caller-owned write transactions for the publish door
    rt.block_on(sqlx::Pool::<sqlx::Postgres>::connect(dsn))
        .expect("role_gateway raw pool")
}

struct Handle {
    admin_dsn: String,
    gateway_dsn: String,
    tenant: Uuid,
    workspace: Uuid,
    principal: Uuid,
    memory: Uuid,
    memory_hash: [u8; 32],
    project: Uuid,
}

impl Handle {
    fn scope(&self) -> AuthorizationScope {
        AuthorizationScope::new(
            TenantId(self.tenant),
            PrincipalId(self.principal),
            None,
            BoundedSet::new([WorkspaceId(self.workspace)]).expect("one workspace"),
        )
    }

    fn memory_source(&self) -> [ContinuityMemorySource; 1] {
        [ContinuityMemorySource {
            memory_id: self.memory,
            content_sha256: self.memory_hash,
        }]
    }

    fn admin(&self) -> Client {
        // dep: PostgreSQL(owner) — open a superuser PG connection for this test
        Client::connect(&self.admin_dsn, NoTls).expect("admin connect")
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        let Ok(purge) = fixture_purge::purge_tenant_fixture_sql(&self.tenant.to_string()) else {
            eprintln!("continuity_publish cleanup: tenant id is not canonical");
            return;
        };
        // dep: PostgreSQL(owner) — purge this test's rows with the owner connection
        let Ok(mut admin) = Client::connect(&self.admin_dsn, NoTls) else {
            eprintln!("continuity_publish cleanup: admin connect failed");
            return;
        };
        if let Err(error) = admin.batch_execute(&purge) {
            eprintln!(
                "continuity_publish cleanup failed for tenant {}: {error}",
                self.tenant
            );
        }
    }
}

struct Fixture;

impl DbIntegrationFixture for Fixture {
    type Handle = Handle;

    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        let admin_dsn =
            std::env::var("HUMAUX_TEST_PG_DSN").map_err(|_| DbFixtureSkipReason::NoDatabaseUrl)?;
        // dep: PostgreSQL(owner) — the fixture seeds and later purges with the owner connection
        let mut admin = Client::connect(&admin_dsn, NoTls)
            .map_err(|error| DbFixtureSkipReason::ConnectFailed(error.to_string()))?;
        admin
            .query_opt("SELECT 1 FROM private.continuity_facet_slots LIMIT 1", &[])
            .map_err(|error| {
                DbFixtureSkipReason::IsolationSetupFailed(format!(
                    "missing object: private.continuity_facet_slots (migration 0136): {error}"
                ))
            })?;
        let tenant = Uuid::now_v7();
        let workspace = Uuid::now_v7();
        let principal = Uuid::now_v7();
        let memory = Uuid::now_v7();
        let domain = Uuid::now_v7();
        let project = Uuid::now_v7();
        let content = json!({"continuity": "publish source"});
        seed(&mut admin, tenant, workspace, domain, memory, &content).map_err(|error| {
            DbFixtureSkipReason::IsolationSetupFailed(format!("seed: {error:?}"))
        })?;
        let memory_hash: Vec<u8> = admin
            .query_one(
                "SELECT sha256(convert_to(content::text,'UTF8')) \
                 FROM private.memory_records WHERE memory_id=$1",
                &[&memory],
            )
            .map_err(|error| DbFixtureSkipReason::IsolationSetupFailed(error.to_string()))?
            .get(0);
        let memory_hash: [u8; 32] = memory_hash.try_into().map_err(|_| {
            DbFixtureSkipReason::IsolationSetupFailed("memory content hash width".to_string())
        })?;
        let gateway_dsn = dsn_as_role(&admin_dsn, "role_gateway");
        let handle = Handle {
            admin_dsn,
            gateway_dsn,
            tenant,
            workspace,
            principal,
            memory,
            memory_hash,
            project,
        };
        let title = format!("continuity publish {tenant}");
        let rt = runtime();
        let pool = gateway_pool(&rt, &handle.gateway_dsn);
        rt.block_on(continuity_repo::register_project(
            &pool,
            &handle.scope(),
            &RegisterContinuityProject {
                workspace_id: WorkspaceId(workspace),
                project_id: ProjectId(project),
                title: &title,
            },
        ))
        .map_err(|error| {
            DbFixtureSkipReason::IsolationSetupFailed(format!("register project: {error}"))
        })?;
        Ok(handle)
    }
}

fn seed(
    admin: &mut Client,
    tenant: Uuid,
    workspace: Uuid,
    domain: Uuid,
    memory: Uuid,
    content: &Value,
) -> Result<(), postgres::Error> {
    let evidence = Uuid::now_v7();
    let evidence_hash = vec![0x5a_u8; 32];
    // §8.6: the deferred `memory_records_requires_evidence` trigger needs the link by COMMIT.
    admin.batch_execute("BEGIN")?;
    admin.execute(
        "INSERT INTO control.tenants(tenant_id,name,state) VALUES($1,$2,'ACTIVE')",
        &[&tenant, &format!("e2e-continuity-publish {tenant}")],
    )?;
    admin.execute(
        "INSERT INTO control.workspaces(workspace_id,tenant_id,name) VALUES($1,$2,'w1')",
        &[&workspace, &tenant],
    )?;
    admin.execute(
        "INSERT INTO control.private_reasoning_domains(reasoning_domain_id,tenant_id,name) \
         VALUES($1,$2,'w1')",
        &[&domain, &tenant],
    )?;
    admin.execute(
        "INSERT INTO private.evidence_objects( \
          evidence_id,tenant_id,evidence_kind,payload_sha256,data_class,origin_class, \
          visibility_class,reasoning_domain_id) \
         VALUES($1,$2,'EVENT',$3,'PRIVATE','AuthenticatedAgent','TENANT_SHARED',$4)",
        &[&evidence, &tenant, &evidence_hash, &domain],
    )?;
    admin.execute(
        "INSERT INTO private.memory_records( \
          memory_id,tenant_id,memory_type,content,visibility_class,authority_class, \
          confidence,status,asserted_at) \
         VALUES($1,$2,'DECISION',$3,'TENANT_SHARED','ProjectDecision',1,'active',now())",
        &[&memory, &tenant, content],
    )?;
    admin.execute(
        "INSERT INTO private.memory_evidence(memory_id,evidence_id,role) VALUES($1,$2,'SUPPORTING')",
        &[&memory, &evidence],
    )?;
    admin.batch_execute("COMMIT")?;
    Ok(())
}

fn command<'a>(
    workspace: Uuid,
    project: Uuid,
    kind: ContinuityFacetKind,
    body: &'a Value,
    memories: &'a [ContinuityMemorySource],
    removals: &'a [String],
) -> PublishContinuityFacet<'a> {
    PublishContinuityFacet {
        workspace_id: WorkspaceId(workspace),
        project_id: ProjectId(project),
        facet_kind: kind,
        published_state: ContinuityPublishState::Current,
        body,
        memories,
        evidence: &[],
        removals,
    }
}

fn one_publish(
    rt: &Runtime,
    pool: &sqlx::Pool<sqlx::Postgres>,
    scope: &AuthorizationScope,
    command: &PublishContinuityFacet<'_>,
) -> Result<PublishFacetOutcome, ErrorCode> {
    rt.block_on(async {
        // dep: PostgreSQL(role_gateway) — one write transaction per publish attempt
        let mut tx = pool
            .begin()
            .await
            .map_err(|_| ErrorCode::DependencyUnavailable)?;
        let outcome = continuity_repo::publish_facets_in_txn(&mut tx, scope, command).await?;
        if matches!(outcome, PublishFacetOutcome::Published(_)) {
            tx.commit()
                .await
                .map_err(|_| ErrorCode::DependencyUnavailable)?;
        } else {
            tx.rollback()
                .await
                .map_err(|_| ErrorCode::DependencyUnavailable)?;
        }
        Ok(outcome)
    })
}

fn blocked_by_winner(admin: &mut Client, pid: i32) -> bool {
    let deadline = Instant::now() + BLOCK_TIMEOUT;
    while Instant::now() < deadline {
        let blocked: bool = admin
            .query_one("SELECT cardinality(pg_blocking_pids($1)) > 0", &[&pid])
            .expect("pg_blocking_pids")
            .get(0);
        if blocked {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

fn version_census(admin: &mut Client, project: Uuid, kind: &str) -> (i64, i64, i64) {
    let row = admin
        .query_one(
            "SELECT count(*),coalesce(min(facet_version),0),coalesce(max(facet_version),0) \
             FROM private.continuity_facet_versions \
             WHERE project_id=$1 AND facet_kind=$2",
            &[&project, &kind],
        )
        .expect("version census");
    (row.get(0), row.get(1), row.get(2))
}

fn slot_of(admin: &mut Client, project: Uuid, kind: &str) -> (i64, Option<Uuid>, Option<String>) {
    let row = admin
        .query_one(
            "SELECT slot_version,current_version_id,slot_state \
             FROM private.continuity_facet_slots \
             WHERE project_id=$1 AND facet_kind=$2",
            &[&project, &kind],
        )
        .expect("slot row");
    (row.get(0), row.get(1), row.get(2))
}

fn current_body(admin: &mut Client, project: Uuid, kind: &str) -> Value {
    let text: String = admin
        .query_one(
            "SELECT version.body::text \
             FROM private.continuity_facet_slots slot \
             JOIN private.continuity_facet_versions version \
               ON version.tenant_id=slot.tenant_id AND version.workspace_id=slot.workspace_id \
              AND version.project_id=slot.project_id AND version.facet_kind=slot.facet_kind \
              AND version.facet_version=slot.slot_version \
              AND version.facet_version_id=slot.current_version_id \
             WHERE slot.project_id=$1 AND slot.facet_kind=$2",
            &[&project, &kind],
        )
        .expect("current body")
        .get(0);
    serde_json::from_str(&text).expect("json body")
}

fn source_ids(body: &Value) -> Vec<String> {
    let mut ids: Vec<String> = body["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["source_id"].as_str().expect("source_id").to_string())
        .collect();
    ids.sort();
    ids
}

/// A bounded start barrier: every writer registers after its real connection is open, and no writer publishes until
/// all of them have. Unlike `std::sync::Barrier`, a writer whose connection fails ends the wait with a failed gate
/// instead of hanging the whole CI job on a missing party.
struct StartBarrier {
    parties: usize,
    ready: AtomicUsize,
    release: AtomicBool,
}

impl StartBarrier {
    fn new(parties: usize) -> Self {
        Self {
            parties,
            ready: AtomicUsize::new(0),
            release: AtomicBool::new(false),
        }
    }

    fn arrive(&self) -> bool {
        self.ready.fetch_add(1, Ordering::SeqCst);
        let deadline = Instant::now() + THREAD_TIMEOUT;
        while !self.release.load(Ordering::SeqCst) {
            if Instant::now() > deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(2));
        }
        true
    }

    fn release_when_ready(&self) -> bool {
        let deadline = Instant::now() + THREAD_TIMEOUT;
        while self.ready.load(Ordering::SeqCst) < self.parties {
            if Instant::now() > deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(5));
        }
        self.release.store(true, Ordering::SeqCst);
        true
    }
}

/// G-M14-1 (ADR-0094 D-B): two overlapping scalar publishes on one slot leave exactly one version, one winner and
/// one typed CONFLICT carrying that version. The overlap is proved by PostgreSQL reporting the loser blocked on the
/// winner's slot lock, not by a sleep.
#[test]
fn g_m14_1_two_scalar_publishes_leave_one_winner_and_one_conflict() {
    run_db_fixture::<Fixture, _>("g_m14_1_scalar_cas", |fixture| {
        let scope = fixture.scope();
        let memories = fixture.memory_source();
        let project = fixture.project;
        let workspace = fixture.workspace;

        let (winner_outcome_tx, winner_outcome_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (commit_tx, commit_rx) = mpsc::channel::<Result<(), String>>();
        let dsn = fixture.gateway_dsn.clone();
        let scope_a = scope.clone();
        let winner = thread::spawn(move || {
            let rt = runtime();
            let pool = gateway_raw(&rt, &dsn);
            let body = json!({"goal": "writer a"});
            let command = command(
                workspace,
                project,
                ContinuityFacetKind::Goal,
                &body,
                &memories,
                &[],
            );
            let (mut tx, outcome) = rt.block_on(async {
                // dep: PostgreSQL(role_gateway) — the winner's slot lock is held until it commits
                let mut tx = pool.begin().await.expect("winner begin");
                let outcome =
                    continuity_repo::publish_facets_in_txn(&mut tx, &scope_a, &command).await;
                (tx, outcome)
            });
            winner_outcome_tx.send(outcome).expect("winner outcome");
            release_rx.recv_timeout(THREAD_TIMEOUT).expect("release");
            commit_tx
                .send(rt.block_on(tx.commit()).map_err(|error| error.to_string()))
                .expect("winner commit");
        });
        let winner_outcome = winner_outcome_rx
            .recv_timeout(THREAD_TIMEOUT)
            .expect("winner outcome")
            .expect("winner published");
        let PublishFacetOutcome::Published(winner_result) = winner_outcome else {
            panic!("the first writer must publish, got {winner_outcome:?}");
        };
        assert_eq!(
            (winner_result.facet_version, winner_result.slot_version),
            (1, 1)
        );

        let (pid_tx, pid_rx) = mpsc::channel::<i32>();
        let (loser_tx, loser_rx) = mpsc::channel();
        let dsn = fixture.gateway_dsn.clone();
        let scope_b = scope.clone();
        let loser = thread::spawn(move || {
            let rt = runtime();
            let pool = gateway_raw(&rt, &dsn);
            let body = json!({"goal": "writer b"});
            let command = command(
                workspace,
                project,
                ContinuityFacetKind::Goal,
                &body,
                &memories,
                &[],
            );
            rt.block_on(async {
                // dep: PostgreSQL(role_gateway) — the loser blocks on the winner's slot lock
                let mut tx = pool.begin().await.expect("loser begin");
                let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(&mut *tx)
                    .await
                    .expect("loser pid");
                pid_tx.send(pid).expect("pid");
                let outcome =
                    continuity_repo::publish_facets_in_txn(&mut tx, &scope_b, &command).await;
                if matches!(outcome, Ok(PublishFacetOutcome::Published(_))) {
                    tx.commit().await.expect("loser commit");
                } else {
                    tx.rollback().await.expect("loser rollback");
                }
                loser_tx.send(outcome).expect("loser outcome");
            });
        });

        let pid = pid_rx.recv_timeout(THREAD_TIMEOUT).expect("loser pid");
        let mut admin = fixture.admin();
        assert!(
            blocked_by_winner(&mut admin, pid),
            "the loser must block on the winner's slot lock, not race it"
        );
        release_tx.send(()).expect("release winner");
        commit_rx
            .recv_timeout(THREAD_TIMEOUT)
            .expect("winner commit")
            .expect("winner committed");
        let loser_outcome = loser_rx
            .recv_timeout(THREAD_TIMEOUT)
            .expect("loser outcome")
            .expect("loser answered");
        assert_eq!(
            loser_outcome,
            PublishFacetOutcome::Conflict {
                reason: ConflictReason::FACET_SLOT_VERSION_CONFLICT,
                current_slot_version: 1,
            }
        );
        winner.join().expect("winner thread");
        loser.join().expect("loser thread");

        assert_eq!(version_census(&mut admin, project, "GOAL"), (1, 1, 1));
        let (slot_version, current, state) = slot_of(&mut admin, project, "GOAL");
        assert_eq!(slot_version, 1);
        assert_eq!(current, Some(winner_result.facet_version_id.0));
        assert_eq!(state.as_deref(), Some("CURRENT"));
    });
}

/// G-M14-2: 80 concurrent list writers, each one item, leave exactly the union of all 80 items in exactly 80
/// versions. A whole-list replace loses the earlier writers' items, which is the red this gate exists for.
#[test]
fn g_m14_2_eighty_writers_union_exactly() {
    run_db_fixture::<Fixture, _>("g_m14_2_list_union", |fixture| {
        let dsn = Arc::new(fixture.gateway_dsn.clone());
        let scope = Arc::new(fixture.scope());
        let barrier = Arc::new(StartBarrier::new(WRITERS));
        let memory = fixture.memory;
        let memory_hash = fixture.memory_hash;
        let project = fixture.project;
        let workspace = fixture.workspace;
        let mut writers = Vec::with_capacity(WRITERS);
        for index in 0..WRITERS {
            let dsn = Arc::clone(&dsn);
            let scope = Arc::clone(&scope);
            let barrier = Arc::clone(&barrier);
            writers.push(thread::spawn(move || {
                let rt = runtime();
                let pool = gateway_raw(&rt, &dsn);
                let body =
                    json!({"items":[{"source_id": format!("writer-{index:02}"), "text": "union"}]});
                let memories = [ContinuityMemorySource {
                    memory_id: memory,
                    content_sha256: memory_hash,
                }];
                let command = command(
                    workspace,
                    project,
                    ContinuityFacetKind::Decisions,
                    &body,
                    &memories,
                    &[],
                );
                if !barrier.arrive() {
                    return Err(format!("writer {index}: start barrier timed out"));
                }
                for _ in 0..WRITER_ATTEMPTS {
                    match one_publish(&rt, &pool, &scope, &command) {
                        Ok(PublishFacetOutcome::Published(_)) => return Ok(()),
                        Ok(PublishFacetOutcome::Conflict { .. }) => {}
                        Err(error) => return Err(format!("writer {index}: {error:?}")),
                    }
                }
                Err(format!("writer {index}: {WRITER_ATTEMPTS} attempts"))
            }));
        }
        assert!(
            barrier.release_when_ready(),
            "all {WRITERS} writers must open a connection before any publishes"
        );
        for writer in writers {
            writer
                .join()
                .expect("writer thread")
                .expect("writer published");
        }

        let mut admin = fixture.admin();
        assert_eq!(
            version_census(&mut admin, project, "DECISIONS"),
            (WRITERS as i64, 1, WRITERS as i64)
        );
        let (slot_version, current, state) = slot_of(&mut admin, project, "DECISIONS");
        assert_eq!(slot_version, WRITERS as i64);
        assert_eq!(state.as_deref(), Some("CURRENT"));
        assert!(current.is_some());
        let expected: Vec<String> = (0..WRITERS)
            .map(|index| format!("writer-{index:02}"))
            .collect();
        let body = current_body(&mut admin, project, "DECISIONS");
        assert_eq!(
            body["items"].as_array().expect("items").len(),
            WRITERS,
            "the merged body must hold exactly one item per writer"
        );
        assert_eq!(
            source_ids(&body),
            expected,
            "exactly the union of all 80 writers"
        );
    });
}

/// G-M14-2's retry half (ADR-0094 D-D): a list writer that loses the slot re-reads, merges and publishes the winner's
/// item together with its own in one version. Proved through `pg_blocking_pids` like G-M14-1.
#[test]
fn g_m14_2_conflicted_list_writer_retries_and_unions() {
    run_db_fixture::<Fixture, _>("g_m14_2_list_retry", |fixture| {
        let scope = fixture.scope();
        let memories = fixture.memory_source();
        let project = fixture.project;
        let workspace = fixture.workspace;

        let (winner_outcome_tx, winner_outcome_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (commit_tx, commit_rx) = mpsc::channel::<Result<(), String>>();
        let dsn = fixture.gateway_dsn.clone();
        let scope_a = scope.clone();
        let winner = thread::spawn(move || {
            let rt = runtime();
            let pool = gateway_raw(&rt, &dsn);
            let body = json!({"items":[{"source_id":"a","text":"winner"}]});
            let command = command(
                workspace,
                project,
                ContinuityFacetKind::Decisions,
                &body,
                &memories,
                &[],
            );
            let (mut tx, outcome) = rt.block_on(async {
                // dep: PostgreSQL(role_gateway) — the winner's slot lock is held until it commits
                let mut tx = pool.begin().await.expect("winner begin");
                let outcome =
                    continuity_repo::publish_facets_in_txn(&mut tx, &scope_a, &command).await;
                (tx, outcome)
            });
            winner_outcome_tx.send(outcome).expect("winner outcome");
            release_rx.recv_timeout(THREAD_TIMEOUT).expect("release");
            commit_tx
                .send(rt.block_on(tx.commit()).map_err(|error| error.to_string()))
                .expect("winner commit");
        });
        let winner_outcome = winner_outcome_rx
            .recv_timeout(THREAD_TIMEOUT)
            .expect("winner outcome")
            .expect("winner published");
        let PublishFacetOutcome::Published(winner_result) = winner_outcome else {
            panic!("the winner must publish, got {winner_outcome:?}");
        };
        assert_eq!(
            (winner_result.facet_version, winner_result.slot_version),
            (1, 1)
        );

        let (pid_tx, pid_rx) = mpsc::channel::<i32>();
        let (loser_tx, loser_rx) = mpsc::channel();
        let dsn = fixture.gateway_dsn.clone();
        let scope_b = scope.clone();
        let loser = thread::spawn(move || {
            let rt = runtime();
            let pool = gateway_raw(&rt, &dsn);
            let body = json!({"items":[{"source_id":"b","text":"loser"}]});
            let command = command(
                workspace,
                project,
                ContinuityFacetKind::Decisions,
                &body,
                &memories,
                &[],
            );
            rt.block_on(async {
                // dep: PostgreSQL(role_gateway) — the loser blocks on the winner's slot lock
                let mut tx = pool.begin().await.expect("loser begin");
                let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(&mut *tx)
                    .await
                    .expect("loser pid");
                pid_tx.send(pid).expect("pid");
                let outcome =
                    continuity_repo::publish_facets_in_txn(&mut tx, &scope_b, &command).await;
                if matches!(outcome, Ok(PublishFacetOutcome::Published(_))) {
                    tx.commit().await.expect("loser commit");
                } else {
                    tx.rollback().await.expect("loser rollback");
                }
                loser_tx.send(outcome).expect("loser outcome");
            });
        });

        let pid = pid_rx.recv_timeout(THREAD_TIMEOUT).expect("loser pid");
        let mut admin = fixture.admin();
        assert!(
            blocked_by_winner(&mut admin, pid),
            "the loser must block on the winner's slot lock, not race it"
        );
        release_tx.send(()).expect("release winner");
        commit_rx
            .recv_timeout(THREAD_TIMEOUT)
            .expect("winner commit")
            .expect("winner committed");
        let loser_outcome = loser_rx
            .recv_timeout(THREAD_TIMEOUT)
            .expect("loser outcome")
            .expect("loser retried, not failed");
        let PublishFacetOutcome::Published(loser_result) = loser_outcome else {
            panic!("a list writer must retry its conflict, got {loser_outcome:?}");
        };
        assert_eq!(
            (loser_result.facet_version, loser_result.slot_version),
            (2, 2)
        );
        winner.join().expect("winner thread");
        loser.join().expect("loser thread");

        assert_eq!(version_census(&mut admin, project, "DECISIONS"), (2, 1, 2));
        let (slot_version, _, state) = slot_of(&mut admin, project, "DECISIONS");
        assert_eq!(slot_version, 2);
        assert_eq!(state.as_deref(), Some("CURRENT"));
        assert_eq!(
            source_ids(&current_body(&mut admin, project, "DECISIONS")),
            vec!["a".to_string(), "b".to_string()]
        );
    });
}

/// The door refuses what is not a publishable facet publication before it writes anything.
#[test]
fn publish_rejects_unpublishable_and_scalar_removal_inputs() {
    run_db_fixture::<Fixture, _>("continuity_publish_rejects", |fixture| {
        let scope = fixture.scope();
        let memories = fixture.memory_source();
        let rt = runtime();
        let pool = gateway_raw(&rt, &fixture.gateway_dsn);
        let empty = json!({"items":[]});
        let removals = vec!["a".to_string()];
        for (kind, removals) in [
            (ContinuityFacetKind::ActiveTasks, &[][..]),
            (ContinuityFacetKind::Goal, &removals[..]),
        ] {
            let input = command(
                fixture.workspace,
                fixture.project,
                kind,
                &empty,
                &memories,
                removals,
            );
            assert_eq!(
                one_publish(&rt, &pool, &scope, &input),
                Err(ErrorCode::InvalidInput)
            );
        }
        let malformed = json!({"items":[{"text":"no source id"}]});
        let input = command(
            fixture.workspace,
            fixture.project,
            ContinuityFacetKind::Decisions,
            &malformed,
            &memories,
            &[],
        );
        assert_eq!(
            one_publish(&rt, &pool, &scope, &input),
            Err(ErrorCode::InvalidInput)
        );
        let goal = json!({"goal":"published"});
        let input = command(
            fixture.workspace,
            fixture.project,
            ContinuityFacetKind::Goal,
            &goal,
            &memories,
            &[],
        );
        assert!(matches!(
            one_publish(&rt, &pool, &scope, &input),
            Ok(PublishFacetOutcome::Published(_))
        ));
        let mut admin = fixture.admin();
        assert_eq!(
            version_census(&mut admin, fixture.project, "GOAL"),
            (1, 1, 1)
        );
    });
}
