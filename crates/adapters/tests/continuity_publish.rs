//! `adapters::tests::continuity_publish` — CAS, merge and G-289 source-closure gates against real PostgreSQL.
//! Depends-on: crates=[humaux-adapters, humaux-application, humaux-contracts, humaux-domain, humaux-testkit, postgres, serde_json, sqlx, tokio,
//!   uuid]; services=[PostgreSQL(owner) r=[ops.commit_seq_seq, private.continuity_facet_memory_links, private.continuity_facet_evidence_links, private.memory_records] w=[control.memberships, control.users, control.workspace_memberships, control.private_reasoning_domains,
//!   control.tenants, control.workspaces, ops.outbox, projection.stream_log, private.evidence_objects, private.memory_evidence,
//!   private.memory_records], PostgreSQL(role_gateway)
//!   r=[private.continuity_facet_slots, private.continuity_facet_versions] x=[private.publish_continuity_facet]];
//!   env=[HUMAUX_REQUIRE_DB, HUMAUX_TEST_PG_DSN]; modules=[contracts::config_registry, adapters::continuity_repo, adapters::postgres,
//!   adapters::continuity_read, application::continuity, domain::context, domain::continuity, domain::error, domain::identity, domain::ids, humaux-testkit, testkit::fixture_purge]
//! Called-by: [cargo-test]
//! Invariants: [G-M14-1: two overlapping publishes of one scalar slot leave exactly one version, one winner and one
//!   typed CONFLICT carrying that version; G-M14-2: 80 concurrent list writers leave exactly 80 items (the full union)
//!   in 80 versions, and a conflicted list writer retries and unions the winner's item; the block is proved through
//!   pg_blocking_pids, never a sleep; every fixture tenant is purged by the one fixture purge; a missing database is a
//!   failure when HUMAUX_REQUIRE_DB=1, never a silent pass; g_m14_2_eighty_writers_union_exactly is lane(a:shared_db)
//!   (it holds exactly one gateway session per writer — 80 live sessions at the start barrier and 80 distinct
//!   gateway backends across the run, never more — and max_connections is 100), so it runs alone in
//!   `cargo xtask serial-lane`; G-289-a/b/c retain exact inherited source hashes, reader visibility and lifecycle; G-289-d rejects invisible caller sources with 23514]
//! Spec: Baseline §25.3.1; §52 D-B; §79.2; §80.1; ADR-0094

use std::{
    collections::BTreeSet,
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
    postgres::{PoolSettings, RuntimeDbPool},
};
use humaux_domain::{
    continuity::{ContinuityFacetKind, ContinuityPublishState, ProjectId},
    error::{ConflictReason, ErrorCode},
    identity::{AuthorizationScope, BoundedSet, PrincipalId},
    ids::{TenantId, UserId, WorkspaceId},
};
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, fixture_purge, run_db_fixture};
use postgres::{Client, NoTls};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use tokio::runtime::Runtime;
use uuid::Uuid;

const WRITERS: usize = 80;
const WRITER_ATTEMPTS: usize = 100;
const THREAD_TIMEOUT: Duration = Duration::from_secs(60);
const BLOCK_TIMEOUT: Duration = Duration::from_secs(15);
/// `application_name` of every G-M14-2 writer session: what the test's exact-80 count filters on.
/// `pg_stat_activity.usename` cannot name the gateway — the role is entered through `options=-c role=…`
/// (`dsn_as_role`), so the login role is the owner's.
const WRITER_APP_NAME: &str = "g_m14_2_writer";

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
    // dep: PostgreSQL(role_gateway) — the typed pool `register_project` takes: exactly one session, and
    // the pool is dropped at the end of `Fixture::isolate`, before any G-M14-2 writer opens its own
    rt.block_on(RuntimeDbPool::connect_with(
        dsn,
        &PoolSettings {
            max_connections: 1,
            min_connections: 1,
            acquire_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(60),
            max_lifetime: Duration::from_secs(600),
            statement_timeout: Duration::from_secs(30),
            idle_in_transaction_timeout: Duration::from_secs(30),
            application_name: "continuity_publish_fixture".to_owned(),
        },
    ))
    .expect("role_gateway pool")
}

/// Exactly one `role_gateway` session: the door takes a caller-owned transaction, so a caller needs
/// one. `max_connections(1)` is the invariant, not a tuning knob — sqlx returns a finished
/// transaction's connection on a spawned task, so with its default ceiling of 10 the next acquire can
/// open a second backend while the first is still returning.
fn gateway_raw(rt: &Runtime, dsn: &str) -> sqlx::Pool<sqlx::Postgres> {
    // dep: PostgreSQL(role_gateway) — caller-owned write transactions for the publish door
    rt.block_on(
        PgPoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .connect(dsn),
    )
    .expect("role_gateway raw pool")
}

/// A G-M14-2 writer's only session: one connection, named so the test can count its own sessions.
fn writer_pool(rt: &Runtime, dsn: &str) -> sqlx::Pool<sqlx::Postgres> {
    let sep = if dsn.contains('?') { '&' } else { '?' };
    // dep: PostgreSQL(role_gateway) — one session per writer; every retried transaction reuses it
    rt.block_on(
        PgPoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .connect(&format!("{dsn}{sep}application_name={WRITER_APP_NAME}")),
    )
    .expect("role_gateway writer pool")
}

/// The `application_name`-tagged sessions of this test's writers in `pg_stat_activity`.
fn writer_sessions(admin: &mut Client) -> i64 {
    admin
        .query_one(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE application_name=$1 AND datname=current_database()",
            &[&WRITER_APP_NAME],
        )
        .expect("writer sessions")
        .get(0)
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
    users: Vec<Uuid>,
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
            return;
        }
        admin
            .execute(
                "DELETE FROM control.users WHERE user_id=ANY($1)",
                &[&self.users],
            )
            .expect("purge only this fixture's users");
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
            users: Vec::new(),
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
        list_merge_attempts: humaux_contracts::config_registry::continuity_list_merge_attempts(
            None,
        )
        .expect("registered continuity default"),
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
) -> Result<(PublishFacetOutcome, i32), ErrorCode> {
    rt.block_on(async {
        // dep: PostgreSQL(role_gateway) — one write transaction per publish attempt
        let mut tx = pool
            .begin()
            .await
            .map_err(|_| ErrorCode::DependencyUnavailable)?;
        // The session that served this attempt: exactly one per writer when the pool ceiling is one.
        let backend: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
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
        Ok((outcome, backend))
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

    /// Blocks until every writer has arrived, without releasing them: the test reads the barrier's
    /// session count there, the only instant at which every writer is connected and none has published.
    fn wait_ready(&self) -> bool {
        let deadline = Instant::now() + THREAD_TIMEOUT;
        while self.ready.load(Ordering::SeqCst) < self.parties {
            if Instant::now() > deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(5));
        }
        true
    }

    fn release(&self) {
        self.release.store(true, Ordering::SeqCst);
    }
}

/// One winner and one loser on the same slot, overlapping: the winner publishes and holds its slot lock until the
/// caller releases it; the loser's first attempt must be reported blocked by `pg_blocking_pids` before that release.
/// The helper returns both outcomes (winner first) with both transactions committed or rolled back.
fn race_two_writers(
    fixture: &Handle,
    kind: ContinuityFacetKind,
    first: Value,
    second: Value,
) -> (PublishFacetOutcome, PublishFacetOutcome) {
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
        let command = command(workspace, project, kind, &first, &memories, &[]);
        // dep: PostgreSQL(role_gateway) — this transaction keeps the slot lock until `release`
        let (tx, outcome) = rt.block_on(async {
            let mut tx = pool.begin().await.expect("winner begin");
            let outcome = continuity_repo::publish_facets_in_txn(&mut tx, &scope_a, &command).await;
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
        .expect("winner answered");
    let (pid_tx, pid_rx) = mpsc::channel::<i32>();
    let (loser_tx, loser_rx) = mpsc::channel();
    let dsn = fixture.gateway_dsn.clone();
    let scope_b = scope.clone();
    let loser = thread::spawn(move || {
        let rt = runtime();
        let pool = gateway_raw(&rt, &dsn);
        let command = command(workspace, project, kind, &second, &memories, &[]);
        rt.block_on(async {
            // dep: PostgreSQL(role_gateway) — the loser must block on the winner's slot lock
            let mut tx = pool.begin().await.expect("loser begin");
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *tx)
                .await
                .expect("loser pid");
            pid_tx.send(pid).expect("pid");
            let outcome = continuity_repo::publish_facets_in_txn(&mut tx, &scope_b, &command).await;
            if matches!(outcome, Ok(PublishFacetOutcome::Published(_))) {
                tx.commit().await.expect("loser commit");
            } else {
                tx.rollback().await.expect("loser rollback");
            }
            loser_tx.send(outcome).expect("loser outcome");
        });
    });
    let mut admin = fixture.admin();
    let pid = pid_rx.recv_timeout(THREAD_TIMEOUT).expect("loser pid");
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
    winner.join().expect("winner thread");
    loser.join().expect("loser thread");
    (winner_outcome, loser_outcome)
}

/// G-M14-1 (ADR-0094 D-B): two overlapping scalar publishes on one slot leave exactly one version, one winner and
/// one typed CONFLICT carrying that version.
#[test]
fn g_m14_1_two_scalar_publishes_leave_one_winner_and_one_conflict() {
    run_db_fixture::<Fixture, _>("g_m14_1_scalar_cas", |fixture| {
        let project = fixture.project;
        let (winner_outcome, loser_outcome) = race_two_writers(
            &fixture,
            ContinuityFacetKind::Goal,
            json!({"goal": "writer a"}),
            json!({"goal": "writer b"}),
        );
        let PublishFacetOutcome::Published(winner_result) = winner_outcome else {
            panic!("the first writer must publish, got {winner_outcome:?}");
        };
        assert_eq!(
            (winner_result.facet_version, winner_result.slot_version),
            (1, 1)
        );
        assert_eq!(
            loser_outcome,
            PublishFacetOutcome::Conflict {
                reason: ConflictReason::FACET_SLOT_VERSION_CONFLICT,
                current_slot_version: 1,
            }
        );
        let mut admin = fixture.admin();
        assert_eq!(version_census(&mut admin, project, "GOAL"), (1, 1, 1));
        let (slot_version, current, state) = slot_of(&mut admin, project, "GOAL");
        assert_eq!(slot_version, 1);
        assert_eq!(current, Some(winner_result.facet_version_id.0));
        assert_eq!(state.as_deref(), Some("CURRENT"));
    });
}

/// One writer's bounded retry: publish, accept a lost CAS and retry, or fail after `WRITER_ATTEMPTS`.
/// Returns every gateway backend the writer used: with a one-connection pool that set has exactly one id.
fn publish_until_settled(
    rt: &Runtime,
    pool: &sqlx::Pool<sqlx::Postgres>,
    scope: &AuthorizationScope,
    command: &PublishContinuityFacet<'_>,
    index: usize,
) -> Result<BTreeSet<i32>, String> {
    let mut backends = BTreeSet::new();
    for _ in 0..WRITER_ATTEMPTS {
        match one_publish(rt, pool, scope, command) {
            Ok((PublishFacetOutcome::Published(_), backend)) => {
                backends.insert(backend);
                return Ok(backends);
            }
            Ok((PublishFacetOutcome::Conflict { .. }, backend)) => {
                backends.insert(backend);
            }
            Err(error) => return Err(format!("writer {index}: {error:?}")),
        }
    }
    Err(format!("writer {index}: {WRITER_ATTEMPTS} attempts"))
}

/// G-M14-2: 80 concurrent list writers, each one item, leave exactly the union of all 80 items in exactly 80
/// versions. A whole-list replace loses the earlier writers' items, which is the red this gate exists for.
///
/// Serial lane (`lane(a:shared_db)`): real concurrency requires all `WRITERS` connections open at once, and the
/// shared cluster's `max_connections` is 100, so beside the workspace tier's other binaries it exhausts the cluster.
#[test]
#[ignore = "lane(a:shared_db) holds WRITERS=80 real gateway connections at once (G-M14-2 needs all 80), which beside the workspace tier's other binaries exhausts the shared cluster (max_connections 100)"]
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
                let pool = writer_pool(&rt, &dsn);
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
                publish_until_settled(&rt, &pool, &scope, &command, index)
            }));
        }
        let mut admin = fixture.admin();
        assert!(
            barrier.wait_ready(),
            "all {WRITERS} writers must open a connection before any publishes"
        );
        let at_barrier = writer_sessions(&mut admin);
        assert_eq!(
            at_barrier, WRITERS as i64,
            "each of the {WRITERS} writers must hold exactly one gateway session"
        );
        barrier.release();
        let mut backends = BTreeSet::new();
        for writer in writers {
            backends.extend(
                writer
                    .join()
                    .expect("writer thread")
                    .expect("writer published"),
            );
        }
        assert_eq!(
            backends.len(),
            WRITERS,
            "the {WRITERS} writers must use exactly one gateway session each"
        );

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

/// G-M14-2's retry half (ADR-0094 D-D): a list writer that loses the slot re-reads, merges and publishes the
/// winner's item together with its own in one new version.
#[test]
fn g_m14_2_conflicted_list_writer_retries_and_unions() {
    run_db_fixture::<Fixture, _>("g_m14_2_list_retry", |fixture| {
        let project = fixture.project;
        let (winner_outcome, loser_outcome) = race_two_writers(
            &fixture,
            ContinuityFacetKind::Decisions,
            json!({"items":[{"source_id":"a","text":"winner"}]}),
            json!({"items":[{"source_id":"b","text":"loser"}]}),
        );
        let PublishFacetOutcome::Published(winner_result) = winner_outcome else {
            panic!("the winner must publish, got {winner_outcome:?}");
        };
        assert_eq!(
            (winner_result.facet_version, winner_result.slot_version),
            (1, 1)
        );
        let PublishFacetOutcome::Published(loser_result) = loser_outcome else {
            panic!("a list writer must retry its conflict, got {loser_outcome:?}");
        };
        assert_eq!(
            (loser_result.facet_version, loser_result.slot_version),
            (2, 2)
        );
        let mut admin = fixture.admin();
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
        let removals = ["a".to_string()];
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
                one_publish(&rt, &pool, &scope, &input).map(|(outcome, _)| outcome),
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
            one_publish(&rt, &pool, &scope, &input).map(|(outcome, _)| outcome),
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
            Ok((PublishFacetOutcome::Published(_), _))
        ));
        let mut admin = fixture.admin();
        assert_eq!(
            version_census(&mut admin, fixture.project, "GOAL"),
            (1, 1, 1)
        );
    });
}

/// §25.3.1 / #292: read, merge and SQL failures cannot poison the caller's transaction or GUC.
#[test]
fn publish_failure_restores_outer_transaction_and_workspace() {
    run_db_fixture::<Fixture, _>("publish_failure_outer_txn", |fixture| {
        let rt = runtime();
        let pool = gateway_raw(&rt, &fixture.gateway_dsn);
        let scope = fixture.scope();
        let memories = fixture.memory_source();
        let goal = json!({"goal":"failed publication"});
        let malformed = json!({"items":[{"text":"missing identity"}]});
        let cases = [
            (
                Uuid::now_v7(),
                ContinuityFacetKind::Goal,
                &goal,
                &memories[..],
                ErrorCode::NotFound,
            ),
            (
                fixture.project,
                ContinuityFacetKind::Goal,
                &goal,
                &[][..],
                ErrorCode::InvalidInput,
            ),
            (
                fixture.project,
                ContinuityFacetKind::Decisions,
                &malformed,
                &memories[..],
                ErrorCode::InvalidInput,
            ),
        ];
        let caller_workspace = Uuid::now_v7();
        assert_ne!(caller_workspace, fixture.workspace);
        for (project, kind, body, sources, expected) in cases {
            let input = command(fixture.workspace, project, kind, body, sources, &[]);
            rt.block_on(async {
                // dep: PostgreSQL(role_gateway) — caller transaction survives each failed publish
                let mut tx = pool.begin().await.expect("outer transaction");
                sqlx::query("SELECT set_config('humaux.workspace_id',$1,true)")
                    .bind(caller_workspace.to_string())
                    .execute(&mut *tx)
                    .await
                    .expect("caller workspace");
                assert_eq!(
                    continuity_repo::publish_facets_in_txn(&mut tx, &scope, &input).await,
                    Err(expected)
                );
                let value: (i32, String) =
                    sqlx::query_as("SELECT 42::int, current_setting('humaux.workspace_id')")
                        .fetch_one(&mut *tx)
                        .await
                        .expect("follow-up statement must succeed");
                assert_eq!(
                    value,
                    (42, caller_workspace.to_string()),
                    "caller setting restored"
                );
                assert_attempt_savepoint_released(&mut tx).await;
                tx.commit().await.expect("outer commit");
            });
        }
        assert_eq!(
            version_census(&mut fixture.admin(), fixture.project, "GOAL"),
            (0, 0, 0)
        );
    });
}

// §25.3.1: probing a released savepoint aborts only this disposable outer transaction.
async fn assert_attempt_savepoint_released(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>) {
    sqlx::query("SAVEPOINT caller_probe")
        .execute(&mut **tx)
        .await
        .expect("caller probe");
    let error = sqlx::query("ROLLBACK TO SAVEPOINT continuity_publish_attempt")
        .execute(&mut **tx)
        .await
        .expect_err("attempt savepoint must be released");
    assert_eq!(
        error
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("3B001"),
        "no such savepoint"
    );
    assert_eq!(
        error.as_database_error().expect("database error").message(),
        "savepoint \"continuity_publish_attempt\" does not exist"
    );
    sqlx::query("ROLLBACK TO SAVEPOINT caller_probe")
        .execute(&mut **tx)
        .await
        .expect("recover probe");
    sqlx::query("RELEASE SAVEPOINT caller_probe")
        .execute(&mut **tx)
        .await
        .expect("release probe");
}

struct MergePrivacyFixture {
    handle: Handle,
    user_a: Uuid,
    user_b: Uuid,
    memory_b: ContinuityMemorySource,
    evidence_a: humaux_adapters::continuity_repo::ContinuityEvidenceSource,
}

fn merge_privacy_fixture(mut handle: Handle) -> MergePrivacyFixture {
    let user_a = Uuid::now_v7();
    let user_b = Uuid::now_v7();
    handle.users.extend([user_a, user_b]);
    let mut admin = handle.admin();
    for user in [user_a, user_b] {
        admin
            .execute(
                "INSERT INTO control.users(user_id,state) VALUES($1,'ACTIVE')",
                &[&user],
            )
            .unwrap();
        admin
            .execute(
                "INSERT INTO control.memberships(tenant_id,user_id,role,state) \
             VALUES($1,$2,'MEMBER','ACTIVE')",
                &[&handle.tenant, &user],
            )
            .unwrap();
        admin.execute(
            "INSERT INTO control.workspace_memberships(tenant_id,workspace_id,user_id,role,state) \
             VALUES($1,$2,$3,'MEMBER','ACTIVE')",
            &[&handle.tenant, &handle.workspace, &user]).unwrap();
    }
    admin.execute(
        "UPDATE private.memory_records SET visibility_class='USER_PRIVATE',visibility_user_id=$2 \
         WHERE memory_id=$1", &[&handle.memory, &user_a]).unwrap();
    let memory_b = seed_merge_memory(&mut admin, &handle);
    let evidence_a = seed_merge_evidence(&mut admin, &handle, user_a);
    MergePrivacyFixture {
        handle,
        user_a,
        user_b,
        memory_b,
        evidence_a,
    }
}

fn seed_merge_memory(admin: &mut Client, handle: &Handle) -> ContinuityMemorySource {
    let id = Uuid::now_v7();
    admin.batch_execute("BEGIN").unwrap();
    admin.execute(
        "INSERT INTO private.memory_records(memory_id,tenant_id,memory_type,content,visibility_class, \
         authority_class,confidence,status,asserted_at) \
         VALUES($1,$2,'DECISION','{\"public\":\"B\"}','TENANT_SHARED','ProjectDecision',1,'active',now())",
        &[&id, &handle.tenant]).unwrap();
    admin
        .execute(
            "INSERT INTO private.memory_evidence(memory_id,evidence_id,role) \
         SELECT $1,evidence_id,'SUPPORTING' FROM private.memory_evidence WHERE memory_id=$2",
            &[&id, &handle.memory],
        )
        .unwrap();
    let hash: Vec<u8> = admin.query_one(
        "SELECT sha256(convert_to(content::text,'UTF8')) FROM private.memory_records WHERE memory_id=$1",
        &[&id]).unwrap().get(0);
    admin.batch_execute("COMMIT").unwrap();
    ContinuityMemorySource {
        memory_id: id,
        content_sha256: hash.try_into().unwrap(),
    }
}

fn seed_merge_evidence(
    admin: &mut Client,
    handle: &Handle,
    user: Uuid,
) -> humaux_adapters::continuity_repo::ContinuityEvidenceSource {
    let id = Uuid::now_v7();
    let hash = [0x6b_u8; 32];
    admin.execute(
        "INSERT INTO private.evidence_objects(evidence_id,tenant_id,evidence_kind,payload_sha256, \
         data_class,origin_class,visibility_class,visibility_user_id,reasoning_domain_id) \
         SELECT $1,$2,'EVENT',$3,'PRIVATE','AuthenticatedAgent','USER_PRIVATE',$4,reasoning_domain_id \
         FROM control.private_reasoning_domains WHERE tenant_id=$2",
        &[&id, &handle.tenant, &hash.to_vec(), &user]).unwrap();
    let seq: i64 = admin
        .query_one("SELECT nextval('ops.commit_seq_seq')", &[])
        .unwrap()
        .get(0);
    admin.execute(
        "INSERT INTO projection.stream_log(tenant_id,scope_kind,scope_id,domain,projection_kind, \
         projection_version,stream_seq,commit_seq,state,settled_at) \
         VALUES($1,'tenant',$1,'knowledge','continuity-289','v1',$2,$2,'DONE',now())",
        &[&handle.tenant, &seq]).unwrap();
    admin
        .execute(
            "INSERT INTO ops.outbox(tenant_id,commit_seq,stream_seq,event_type,evidence_id) \
         VALUES($1,$2,$2,'EVIDENCE_ACCEPTED',$3)",
            &[&handle.tenant, &seq, &id],
        )
        .unwrap();
    humaux_adapters::continuity_repo::ContinuityEvidenceSource {
        evidence_id: id,
        payload_sha256: hash,
    }
}

fn merge_scope(handle: &Handle, user: Uuid) -> AuthorizationScope {
    AuthorizationScope::new(
        TenantId(handle.tenant),
        PrincipalId(user),
        Some(UserId(user)),
        BoundedSet::new([WorkspaceId(handle.workspace)]).unwrap(),
    )
}

fn merge_read(handle: &Handle, user: Uuid) -> Value {
    let rt = runtime();
    let pool = Arc::new(gateway_pool(&rt, &handle.gateway_dsn));
    let port = humaux_adapters::continuity_read::PostgresContinuityReadPort::new(pool);
    let value = rt
        .block_on(humaux_application::continuity::read_project_continuity(
            &port,
            &merge_scope(handle, user),
            ProjectId(handle.project),
            None,
            humaux_domain::context::ContextBudget::new(10_000, 10_000).unwrap(),
        ))
        .unwrap();
    let value = serde_json::to_value(value).unwrap();
    assert_eq!(value["facets"].as_array().unwrap().len(), 17);
    let mut facets = value["facets"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|facet| facet["kind"] == "DECISIONS");
    let facet = facets.next().unwrap().clone();
    assert_eq!(facets.count(), 0);
    facet
}

fn merge_publish(
    fixture: &MergePrivacyFixture,
    user: Uuid,
    body: &Value,
    memories: &[ContinuityMemorySource],
    evidence: &[humaux_adapters::continuity_repo::ContinuityEvidenceSource],
) -> Result<PublishFacetOutcome, ErrorCode> {
    let rt = runtime();
    let pool = gateway_raw(&rt, &fixture.handle.gateway_dsn);
    let mut cmd = command(
        fixture.handle.workspace,
        fixture.handle.project,
        ContinuityFacetKind::Decisions,
        body,
        memories,
        &[],
    );
    cmd.evidence = evidence;
    one_publish(&rt, &pool, &merge_scope(&fixture.handle, user), &cmd).map(|(result, _)| result)
}

fn assert_merge_links(fixture: &MergePrivacyFixture, version: Uuid, with_memory: bool) {
    let mut admin = fixture.handle.admin();
    let rows = admin
        .query(
            "SELECT memory_id,memory_sha256 FROM private.continuity_facet_memory_links \
         WHERE facet_version_id=$1 ORDER BY memory_id",
            &[&version],
        )
        .unwrap();
    let actual: BTreeSet<(Uuid, Vec<u8>)> = rows.iter().map(|r| (r.get(0), r.get(1))).collect();
    let mut expected = BTreeSet::from([(
        fixture.memory_b.memory_id,
        fixture.memory_b.content_sha256.to_vec(),
    )]);
    if with_memory {
        expected.insert((fixture.handle.memory, fixture.handle.memory_hash.to_vec()));
    }
    assert_eq!(rows.len(), expected.len());
    assert_eq!(actual, expected);
    let rows = admin
        .query(
            "SELECT evidence_id,evidence_sha256 FROM private.continuity_facet_evidence_links \
         WHERE facet_version_id=$1",
            &[&version],
        )
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].get::<_, Uuid>(0), rows[0].get::<_, Vec<u8>>(1)),
        (
            fixture.evidence_a.evidence_id,
            fixture.evidence_a.payload_sha256.to_vec()
        )
    );
}

fn assert_merge_stale(handle: &Handle, user: Uuid) {
    let facet = merge_read(handle, user);
    assert_eq!(
        facet["status"], "STALE",
        "G-289-a: inherited sources must constrain B's merged read"
    );
    assert_eq!(
        facet
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["diagnostic_code", "kind", "mode", "status"])
    );
}

fn private_merge_scenario(handle: Handle, with_memory: bool) {
    let fixture = merge_privacy_fixture(handle);
    let body_a = json!({"items":[{"source_id":"a","text":"A private item"}]});
    let body_b = json!({"items":[{"source_id":"b","text":"B shared item"}]});
    let memory_a = if with_memory {
        fixture.handle.memory_source().to_vec()
    } else {
        vec![]
    };
    if with_memory {
        fixture.handle.admin().execute(
            "UPDATE private.evidence_objects SET visibility_class='TENANT_SHARED',visibility_user_id=NULL \
             WHERE evidence_id=$1", &[&fixture.evidence_a.evidence_id]).unwrap();
    }
    assert!(matches!(
        merge_publish(
            &fixture,
            fixture.user_a,
            &body_a,
            &memory_a,
            std::slice::from_ref(&fixture.evidence_a)
        )
        .unwrap(),
        PublishFacetOutcome::Published(_)
    ));
    assert_merge_stale(&fixture.handle, fixture.user_b);
    let result = merge_publish(
        &fixture,
        fixture.user_b,
        &body_b,
        std::slice::from_ref(&fixture.memory_b),
        &[],
    )
    .unwrap();
    let PublishFacetOutcome::Published(result) = result else {
        panic!("B merge must publish")
    };
    assert_merge_stale(&fixture.handle, fixture.user_b);
    assert_merge_links(&fixture, result.facet_version_id.0, with_memory);
    let facet = merge_read(&fixture.handle, fixture.user_a);
    assert_eq!(
        facet["status"], "CURRENT",
        "G-289-b: A retains authorized merged access"
    );
    assert_eq!(
        facet["current"]["body"],
        json!({"items":[
        {"source_id":"a","text":"A private item"},{"source_id":"b","text":"B shared item"}]})
    );
    if with_memory {
        fixture
            .handle
            .admin()
            .execute(
                "UPDATE private.memory_records SET status='revoked' WHERE memory_id=$1",
                &[&fixture.handle.memory],
            )
            .unwrap();
        for user in [fixture.user_a, fixture.user_b] {
            assert_merge_stale(&fixture.handle, user);
        }
    }
}

#[test]
fn g_289_a_b_c_memory_inheritance_preserves_reader_visibility_and_lifecycle() {
    run_db_fixture::<Fixture, _>("g_289_memory", |handle| {
        private_merge_scenario(handle, true)
    });
}

#[test]
fn g_289_a_b_evidence_inheritance_preserves_reader_visibility() {
    run_db_fixture::<Fixture, _>("g_289_evidence", |handle| {
        private_merge_scenario(handle, false)
    });
}

fn invisible_caller_sqlstate(fixture: &MergePrivacyFixture, evidence: bool) -> Option<String> {
    let h = &fixture.handle;
    // dep: PostgreSQL(role_gateway) — §25.3.1 caller-link refusal must use the runtime role
    let mut gateway = Client::connect(&h.gateway_dsn, NoTls).unwrap();
    gateway.batch_execute("BEGIN").unwrap();
    gateway.query_one(
        "SELECT set_config('humaux.tenant_id',$1,true),set_config('humaux.workspace_id',$2,true), \
         set_config('humaux.principal_id',$3,true),set_config('humaux.user_id',$3,true)",
        &[&h.tenant.to_string(), &h.workspace.to_string(), &fixture.user_b.to_string()]).unwrap();
    let (memories, hashes, sources, source_hashes) = if evidence {
        (
            vec![],
            vec![],
            vec![fixture.evidence_a.evidence_id],
            vec![fixture.evidence_a.payload_sha256.to_vec()],
        )
    } else {
        (vec![h.memory], vec![h.memory_hash.to_vec()], vec![], vec![])
    };
    let result = gateway.query(
        "SELECT * FROM private.publish_continuity_facet($1,$2,$3,$4,$4,'DECISIONS',0, \
         'CURRENT',$5,$6,$7,$8,$9,true)",
        &[
            &h.tenant,
            &h.workspace,
            &h.project,
            &fixture.user_b,
            &json!({"items":[]}),
            &memories,
            &hashes,
            &sources,
            &source_hashes,
        ],
    );
    let code = result
        .err()
        .and_then(|error| error.code().map(|code| code.code().to_owned()));
    gateway.batch_execute("ROLLBACK").unwrap();
    code
}

#[test]
fn g_289_d_invisible_caller_links_still_raise_23514() {
    run_db_fixture::<Fixture, _>("g_289_caller", |handle| {
        let fixture = merge_privacy_fixture(handle);
        for evidence in [false, true] {
            assert_eq!(
                invisible_caller_sqlstate(&fixture, evidence),
                Some("23514".to_owned()),
                "G-289-d: caller's invisible source must still be refused"
            );
            let memories = if evidence {
                vec![]
            } else {
                fixture.handle.memory_source().to_vec()
            };
            let sources = if evidence {
                vec![fixture.evidence_a.clone()]
            } else {
                vec![]
            };
            assert_eq!(
                merge_publish(
                    &fixture,
                    fixture.user_b,
                    &json!({"items":[]}),
                    &memories,
                    &sources
                ),
                Err(ErrorCode::InvalidInput)
            );
        }
        let mut admin = fixture.handle.admin();
        assert_eq!(
            version_census(&mut admin, fixture.handle.project, "DECISIONS"),
            (0, 0, 0)
        );
        assert_eq!(
            slot_of(&mut admin, fixture.handle.project, "DECISIONS"),
            (0, None, None)
        );
    });
}

#[test]
fn g_289_removal_retains_basis_and_conflicting_hash_cannot_replace_it() {
    run_db_fixture::<Fixture, _>("g_289_removal_hash", |handle| {
        let fixture = merge_privacy_fixture(handle);
        let first = json!({"items":[{"source_id":"a","text":"A private item"}]});
        assert!(matches!(
            merge_publish(
                &fixture,
                fixture.user_a,
                &first,
                &fixture.handle.memory_source(),
                std::slice::from_ref(&fixture.evidence_a)
            )
            .unwrap(),
            PublishFacetOutcome::Published(_)
        ));
        let incoming = json!({"items":[{"source_id":"b","text":"B shared item"}]});
        let rt = runtime();
        let pool = gateway_raw(&rt, &fixture.handle.gateway_dsn);
        let sources = std::slice::from_ref(&fixture.memory_b);
        let removals = ["a".to_owned()];
        let cmd = command(
            fixture.handle.workspace,
            fixture.handle.project,
            ContinuityFacetKind::Decisions,
            &incoming,
            sources,
            &removals,
        );
        let (outcome, _) = one_publish(
            &rt,
            &pool,
            &merge_scope(&fixture.handle, fixture.user_b),
            &cmd,
        )
        .unwrap();
        let PublishFacetOutcome::Published(result) = outcome else {
            panic!("removal merge must publish")
        };
        assert_merge_links(&fixture, result.facet_version_id.0, true);
        assert_merge_stale(&fixture.handle, fixture.user_b);
        let facet = merge_read(&fixture.handle, fixture.user_a);
        assert_eq!(facet["status"], "CURRENT");
        assert_eq!(facet["current"]["body"], incoming);
        let mut admin = fixture.handle.admin();
        let hash: Vec<u8> = admin
            .query_one(
                "UPDATE private.memory_records SET content='{\"changed\":true}' WHERE memory_id=$1 \
             RETURNING sha256(convert_to(content::text,'UTF8'))",
                &[&fixture.handle.memory],
            )
            .unwrap()
            .get(0);
        let changed = ContinuityMemorySource {
            memory_id: fixture.handle.memory,
            content_sha256: hash.try_into().unwrap(),
        };
        assert_ne!(changed.content_sha256, fixture.handle.memory_hash);
        assert_eq!(
            merge_publish(&fixture, fixture.user_a, &incoming, &[changed], &[]),
            Err(ErrorCode::InvalidInput)
        );
        assert_eq!(
            version_census(&mut admin, fixture.handle.project, "DECISIONS"),
            (2, 1, 2)
        );
        assert_eq!(
            slot_of(&mut admin, fixture.handle.project, "DECISIONS"),
            (
                2,
                Some(result.facet_version_id.0),
                Some("CURRENT".to_owned())
            )
        );
        assert_merge_links(&fixture, result.facet_version_id.0, true);
    });
}
