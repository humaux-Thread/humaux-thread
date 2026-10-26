//! `adapters::tests::coord_task_run` — M29 T04a gates G-T04a-1..5: §30.2 lease expiry, fencing token, lease owner, the
//!   §30.1 state closed set (§78.2) and the ADR-0046 epoch bump on close, plus G-T04a-6..8 (#76): the verification
//!   judges the run after the task lock is held, and the write-time recheck; against a real Postgres.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, postgres, sqlx, tokio]; services=[PostgreSQL(any)
//!   r=[coord.task_runs_one_open_lease_per_task] w=[control.tenants, coord.task_runs, coord.tasks],
//!   PostgreSQL(role_gateway)];
//!   env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::coord_repo, adapters::postgres, domain::coordination,
//!   domain::error, domain::identity, domain::ids, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [every test owns a throwaway control.tenants row and deletes its coord rows on drop; lease expiry is
//!   moved on the DB clock by SQL, never by sleeping; every rejection case has a passing positive control in the same
//!   test; a two-connection test proves its block through pg_blocking_pids, never a timed sleep; no DSN or
//!   unreachable DB goes through the §79.2 three-state skip]
//! Spec: Baseline §30.1; §30.2; §78.2; §79.2; §80.1; ADR-0046 D-C
//!
//! Runs on the real `coord.tasks` / `coord.task_runs` (migration 0248) through `role_gateway`, rows
//! scoped to a tenant this file creates (the repo's DB-lane convention, as in `jobs_claim.rs`).
//! `verify_task_run` is called inside a test-owned `role_gateway` transaction that carries only the
//! tenant GUC, the way T04c's caller will hold it. G-T04a-6/7 run the two connections of #76 on scoped threads: the
//! owner connection plays the close (or the held verification) and the test waits until PostgreSQL itself reports the
//! other backend blocked on it.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use humaux_adapters::coord_repo::{self, VerifiedTaskRun};
use humaux_adapters::postgres::RuntimeDbPool;
use humaux_domain::coordination::{FencingToken, TaskRunId, TaskState};
use humaux_domain::error::ErrorCode;
use humaux_domain::identity::{AuthorizationScope, BoundedSet, PrincipalId};
use humaux_domain::ids::{TaskId, TenantId, WorkspaceId};
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use sqlx::types::Uuid;

/// Test-local lease length; long enough that no test run reaches it on its own.
const TTL: Duration = Duration::from_secs(300);

fn dsn_as_role(admin_dsn: &str, role: &str) -> String {
    let sep = if admin_dsn.contains('?') { '&' } else { '?' };
    format!("{admin_dsn}{sep}options=-c%20role%3D{role}")
}

struct Handle {
    rt: tokio::runtime::Runtime,
    gateway: RuntimeDbPool,
    /// Plain `role_gateway` pool for caller-owned transactions around `verify_task_run`.
    raw: sqlx::Pool<sqlx::Postgres>,
    admin: Client,
    /// Owner DSN, for the extra owner connections of the two-connection tests.
    admin_dsn: String,
    tenant_id: Uuid,
}

impl Drop for Handle {
    fn drop(&mut self) {
        if let Err(error) = self.admin.batch_execute(&format!(
            "DELETE FROM coord.task_runs WHERE tenant_id = '{0}'; \
             DELETE FROM coord.tasks WHERE tenant_id = '{0}';",
            self.tenant_id,
        )) {
            eprintln!(
                "coord_task_run cleanup failed for tenant {}: {error}",
                self.tenant_id
            );
        }
        let _ = self.admin.batch_execute(&format!(
            "DELETE FROM control.tenants WHERE tenant_id = '{0}';",
            self.tenant_id,
        ));
    }
}

struct CoordFixture;

impl DbIntegrationFixture for CoordFixture {
    type Handle = Handle;

    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        let dsn =
            std::env::var("HUMAUX_TEST_PG_DSN").map_err(|_| DbFixtureSkipReason::NoDatabaseUrl)?;
        // dep: PostgreSQL(any) — open a role-scoped PG connection/pool for this test
        let mut admin = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        let migrated: bool = admin
            .query_one(
                "SELECT to_regclass('coord.task_runs_one_open_lease_per_task') IS NOT NULL",
                &[],
            )
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?
            .get(0);
        if !migrated {
            return Err(DbFixtureSkipReason::IsolationSetupFailed(
                "missing object: coord.task_runs_one_open_lease_per_task (migration 0248)"
                    .to_string(),
            ));
        }
        let tenant_id: Uuid = admin
            .query_one(
                "INSERT INTO control.tenants (name) VALUES ($1) RETURNING tenant_id",
                &[&"coord_task_run.rs throwaway tenant"],
            )
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?
            .get(0);
        let gateway_dsn = dsn_as_role(&dsn, "role_gateway");
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        let gateway = rt
            // dep: PostgreSQL(role_gateway) — open a role-scoped PG connection/pool for this test
            .block_on(RuntimeDbPool::connect(&gateway_dsn))
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        let raw = rt
            // dep: PostgreSQL(role_gateway) — open a role-scoped PG connection/pool for this test
            .block_on(sqlx::Pool::<sqlx::Postgres>::connect(&gateway_dsn))
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        Ok(Handle {
            rt,
            gateway,
            raw,
            admin,
            admin_dsn: dsn,
            tenant_id,
        })
    }
}

fn scope(tenant: Uuid) -> AuthorizationScope {
    AuthorizationScope::new(
        TenantId(tenant),
        PrincipalId::new(),
        None,
        BoundedSet::new([WorkspaceId::new()]).expect("one workspace"),
    )
}

fn submit(h: &Handle, s: &AuthorizationScope) -> TaskId {
    h.rt.block_on(coord_repo::submit(
        &h.gateway,
        s,
        "coord_task_run",
        "coord_task_run description",
    ))
    .expect("submit")
}

fn claim(
    h: &Handle,
    s: &AuthorizationScope,
    task: TaskId,
) -> Result<coord_repo::ClaimedTaskRun, ErrorCode> {
    h.rt.block_on(coord_repo::claim(&h.gateway, s, task, TTL))
}

fn heartbeat(
    h: &Handle,
    s: &AuthorizationScope,
    run: TaskRunId,
    token: FencingToken,
) -> Result<(), ErrorCode> {
    h.rt.block_on(coord_repo::heartbeat(&h.gateway, s, run, token, TTL))
        .map(|_| ())
}

fn complete(
    h: &Handle,
    s: &AuthorizationScope,
    run: TaskRunId,
    token: FencingToken,
) -> Result<(), ErrorCode> {
    h.rt.block_on(coord_repo::complete(
        &h.gateway,
        s,
        run,
        token,
        "coord_task_run summary",
    ))
}

fn fail(
    h: &Handle,
    s: &AuthorizationScope,
    run: TaskRunId,
    token: FencingToken,
) -> Result<(), ErrorCode> {
    h.rt.block_on(coord_repo::fail(
        &h.gateway,
        s,
        run,
        token,
        "coord_task_run summary",
    ))
}

/// A `role_gateway` transaction carrying the scope's tenant GUC, the shape every caller of the port holds.
async fn begin_scoped(
    raw: &sqlx::Pool<sqlx::Postgres>,
    s: &AuthorizationScope,
) -> sqlx::Transaction<'static, sqlx::Postgres> {
    // dep: PostgreSQL(any) — transaction entry for the verify call
    let mut txn = raw.begin().await.expect("begin");
    sqlx::query("SELECT set_config('humaux.tenant_id', $1, true)")
        .bind(s.tenant_id().0.to_string())
        .execute(&mut *txn)
        .await
        .expect("tenant GUC");
    txn
}

/// `verify_task_run` in its own scoped transaction, rolled back when it returns.
async fn verify_once(
    raw: &sqlx::Pool<sqlx::Postgres>,
    s: &AuthorizationScope,
    run: TaskRunId,
    token: FencingToken,
) -> Result<VerifiedTaskRun, ErrorCode> {
    let mut txn = begin_scoped(raw, s).await;
    let out = coord_repo::verify_task_run(&mut txn, s, run, token).await;
    txn.rollback().await.expect("rollback");
    out
}

/// `verify_task_run` inside a caller-owned transaction carrying the scope's tenant GUC.
fn verify(
    h: &Handle,
    s: &AuthorizationScope,
    run: TaskRunId,
    token: FencingToken,
) -> Result<VerifiedTaskRun, ErrorCode> {
    h.rt.block_on(verify_once(&h.raw, s, run, token))
}

/// `recheck_run_live_in_txn` in its own scoped transaction, rolled back when it returns.
fn recheck(
    h: &Handle,
    s: &AuthorizationScope,
    run: TaskRunId,
    token: FencingToken,
) -> Result<(), ErrorCode> {
    h.rt.block_on(async {
        let mut txn = begin_scoped(&h.raw, s).await;
        let out = coord_repo::recheck_run_live_in_txn(&mut txn, s, run, token).await;
        txn.rollback().await.expect("rollback");
        out
    })
}

/// Moves the run's lease into the past on the DB clock (no sleep).
fn expire(h: &mut Handle, run: TaskRunId) {
    let n = h
        .admin
        .execute(
            "UPDATE coord.task_runs SET lease_expires_at = clock_timestamp() - interval '1 second' \
             WHERE task_run_id = $1",
            &[&run.0],
        )
        .expect("expire lease");
    assert_eq!(n, 1, "exactly the one run is expired");
}

fn task_state(h: &mut Handle, task: TaskId) -> String {
    h.admin
        .query_one(
            "SELECT state FROM coord.tasks WHERE task_id = $1",
            &[&task.0],
        )
        .expect("task row")
        .get(0)
}

fn task_epoch(h: &mut Handle, task: TaskId) -> i64 {
    h.admin
        .query_one(
            "SELECT authorization_epoch FROM coord.tasks WHERE task_id = $1",
            &[&task.0],
        )
        .expect("task row")
        .get(0)
}

/// G-T04a-1: a lease past `lease_expires_at` on the DB clock fails verification, heartbeat and
/// close.
#[test]
fn g_t04a_1_expired_lease_fails_verification() {
    run_db_fixture::<CoordFixture, _>("g_t04a_1_expired_lease_fails_verification", |mut h| {
        let a = scope(h.tenant_id);
        let task = submit(&h, &a);
        let run = claim(&h, &a, task).expect("claim");
        let verified = verify(&h, &a, run.task_run_id, run.fencing_token).expect("live lease");
        assert_eq!(verified.task_id(), task);
        assert_eq!(verified.lease_owner(), a.principal());

        expire(&mut h, run.task_run_id);
        assert_eq!(
            verify(&h, &a, run.task_run_id, run.fencing_token),
            Err(ErrorCode::Conflict)
        );
        assert_eq!(
            heartbeat(&h, &a, run.task_run_id, run.fencing_token),
            Err(ErrorCode::Conflict)
        );
        assert_eq!(
            complete(&h, &a, run.task_run_id, run.fencing_token),
            Err(ErrorCode::Conflict)
        );
        assert_eq!(task_state(&mut h, task), "CLAIMED");
    });
}

/// G-T04a-2: after a re-claim, the previous token is rejected on both the old run and the new
/// one; the new token works.
#[test]
fn g_t04a_2_reclaim_rejects_old_token() {
    run_db_fixture::<CoordFixture, _>("g_t04a_2_reclaim_rejects_old_token", |mut h| {
        let a = scope(h.tenant_id);
        let b = scope(h.tenant_id);
        let task = submit(&h, &a);
        let first = claim(&h, &a, task).expect("first claim");
        assert_eq!(
            claim(&h, &b, task),
            Err(ErrorCode::Conflict),
            "a live lease is not claimable"
        );

        expire(&mut h, first.task_run_id);
        let second = claim(&h, &a, task).expect("re-claim after expiry");
        assert!(second.fencing_token > first.fencing_token);
        assert_ne!(second.task_run_id, first.task_run_id);

        let old = first.fencing_token;
        for run in [first.task_run_id, second.task_run_id] {
            assert_eq!(verify(&h, &a, run, old), Err(ErrorCode::Conflict));
            assert_eq!(heartbeat(&h, &a, run, old), Err(ErrorCode::Conflict));
            assert_eq!(complete(&h, &a, run, old), Err(ErrorCode::Conflict));
        }

        heartbeat(&h, &a, second.task_run_id, second.fencing_token).expect("current heartbeat");
        assert_eq!(task_state(&mut h, task), "WORKING");
        verify(&h, &a, second.task_run_id, second.fencing_token).expect("current token");
        complete(&h, &a, second.task_run_id, second.fencing_token).expect("current complete");
        assert_eq!(task_state(&mut h, task), "COMPLETED");
    });
}

/// G-T04a-3: a caller other than `lease_owner` is rejected, and so is another tenant; the owner
/// passes.
#[test]
fn g_t04a_3_non_owner_rejected() {
    run_db_fixture::<CoordFixture, _>("g_t04a_3_non_owner_rejected", |mut h| {
        let a = scope(h.tenant_id);
        let b = scope(h.tenant_id);
        let foreign = scope(TenantId::new().0);
        let task = submit(&h, &a);
        let run = claim(&h, &a, task).expect("claim");
        let owner: Uuid = h
            .admin
            .query_one(
                "SELECT lease_owner FROM coord.task_runs WHERE task_run_id = $1",
                &[&run.task_run_id.0],
            )
            .expect("run row")
            .get(0);
        assert_eq!(owner, a.principal().0, "lease_owner is the scope principal");

        let (id, token) = (run.task_run_id, run.fencing_token);
        assert_eq!(verify(&h, &b, id, token), Err(ErrorCode::Forbidden));
        assert_eq!(heartbeat(&h, &b, id, token), Err(ErrorCode::Forbidden));
        assert_eq!(complete(&h, &b, id, token), Err(ErrorCode::Forbidden));
        assert_eq!(fail(&h, &b, id, token), Err(ErrorCode::Forbidden));
        assert_eq!(verify(&h, &foreign, id, token), Err(ErrorCode::NotFound));

        verify(&h, &a, id, token).expect("owner verifies");
        fail(&h, &a, id, token).expect("owner fails the run");
        assert_eq!(task_state(&mut h, task), "FAILED");
    });
}

/// G-T04a-4 (§78.2): the `tasks_state_check` labels equal `TaskState::ALL` as a set, and every
/// label round-trips.
#[test]
fn g_t04a_4_task_state_closed_set_matches_db() {
    run_db_fixture::<CoordFixture, _>("g_t04a_4_task_state_closed_set_matches_db", |mut h| {
        let def: String = h
            .admin
            .query_one(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
                 WHERE conrelid = 'coord.tasks'::regclass AND conname = 'tasks_state_check'",
                &[],
            )
            .expect("tasks_state_check")
            .get(0);
        let db: BTreeSet<&str> = def.split('\'').skip(1).step_by(2).collect();
        let rust: BTreeSet<&str> = TaskState::ALL.iter().map(|s| s.as_db_str()).collect();
        assert_eq!(rust.len(), TaskState::ALL.len(), "distinct spellings");
        assert_eq!(
            db, rust,
            "CHECK labels vs TaskState::ALL; constraint: {def}"
        );
        for label in &db {
            let state = TaskState::from_db_str(label).expect("label maps to a variant");
            assert_eq!(state.as_db_str(), *label);
        }
        let default: String = h
            .admin
            .query_one(
                "SELECT pg_get_expr(d.adbin, d.adrelid) FROM pg_attrdef d \
                 JOIN pg_attribute a ON a.attrelid = d.adrelid AND a.attnum = d.adnum \
                 WHERE d.adrelid = 'coord.tasks'::regclass AND a.attname = 'state'",
                &[],
            )
            .expect("state default")
            .get(0);
        assert!(
            default.contains(&format!("'{}'", TaskState::Submitted.as_db_str())),
            "state defaults to SUBMITTED: {default}"
        );
    });
}

/// G-T04a-5 (ADR-0046 D-C, migration 0173 §3): complete and fail each bump `authorization_epoch` by
/// exactly one, each on its own task; claim, heartbeat and re-claim leave it unchanged.
#[test]
fn g_t04a_5_terminal_close_bumps_authorization_epoch() {
    run_db_fixture::<CoordFixture, _>(
        "g_t04a_5_terminal_close_bumps_authorization_epoch",
        |mut h| {
            let a = scope(h.tenant_id);
            for outcome in [TaskState::Completed, TaskState::Failed] {
                let task = submit(&h, &a);
                let before = task_epoch(&mut h, task);
                let first = claim(&h, &a, task).expect("claim");
                heartbeat(&h, &a, first.task_run_id, first.fencing_token).expect("heartbeat");
                expire(&mut h, first.task_run_id);
                let run = claim(&h, &a, task).expect("re-claim");
                assert_eq!(
                    task_epoch(&mut h, task),
                    before,
                    "claim, heartbeat and re-claim keep the epoch"
                );
                let closed = match outcome {
                    TaskState::Completed => complete(&h, &a, run.task_run_id, run.fencing_token),
                    _ => fail(&h, &a, run.task_run_id, run.fencing_token),
                };
                closed.expect("owner closes the run");
                assert_eq!(
                    task_epoch(&mut h, task),
                    before + 1,
                    "{} bumps the epoch by exactly one",
                    outcome.as_db_str()
                );
                assert_eq!(task_state(&mut h, task), outcome.as_db_str());
            }
        },
    );
}

/// How many backends PostgreSQL reports as waiting on a lock held by backend `pid`.
fn blocked_by(admin: &mut Client, pid: i32) -> i64 {
    admin
        .query_one(
            "SELECT count(*) FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid))",
            &[&pid],
        )
        .expect("pg_blocking_pids")
        .get(0)
}

/// Returns once some backend is blocked on a lock held by backend `pid`. The wait is on PostgreSQL's own report, so no
/// sleep length is tuned to CI speed; the 60 s bound only turns a hang into a failure.
fn wait_blocked_by(admin: &mut Client, pid: i32) {
    let give_up = Instant::now() + Duration::from_secs(60);
    while blocked_by(admin, pid) == 0 {
        assert!(
            Instant::now() < give_up,
            "no backend became blocked on pid {pid}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A's side of `coord_repo::close`, left uncommitted: its task row FOR UPDATE, the run finished and the task moved to
/// `outcome` with its epoch bumped, on a connection of its own. Returns that connection (transaction open) and its pid.
fn open_close(dsn: &str, task: TaskId, run: TaskRunId, outcome: TaskState) -> (Client, i32) {
    // dep: PostgreSQL(any) — owner connection that holds the close open
    let mut closer = Client::connect(dsn, NoTls).expect("connect closer");
    closer.batch_execute("BEGIN").expect("begin close");
    closer
        .query(
            "SELECT 1 FROM coord.tasks WHERE task_id = $1 FOR UPDATE",
            &[&task.0],
        )
        .expect("lock task");
    closer
        .execute(
            "UPDATE coord.task_runs SET finished_at = clock_timestamp(), outcome_summary = 'coord_task_run summary' \
             WHERE task_run_id = $1",
            &[&run.0],
        )
        .expect("finish run");
    closer
        .execute(
            "UPDATE coord.tasks SET state = $2, authorization_epoch = authorization_epoch + 1 WHERE task_id = $1",
            &[&task.0, &outcome.as_db_str()],
        )
        .expect("move task");
    let pid = closer
        .query_one("SELECT pg_backend_pid()", &[])
        .expect("pid")
        .get(0);
    (closer, pid)
}

/// G-T04a-6 (#76, §30.2): `verify_task_run` that has to wait for the task row while a close holds it must judge the run
/// as that close committed it. Before the fix one statement read the run and waited for the lock, kept the run version
/// of its first snapshot after the wait, and verified a finished run. Both closes (complete and fail) are covered.
#[test]
fn g_t04a_6_verify_waiting_for_a_close_sees_the_close() {
    run_db_fixture::<CoordFixture, _>(
        "g_t04a_6_verify_waiting_for_a_close_sees_the_close",
        |mut h| {
            let a = scope(h.tenant_id);
            for outcome in [TaskState::Completed, TaskState::Failed] {
                let task = submit(&h, &a);
                let run = claim(&h, &a, task).expect("claim");
                verify(&h, &a, run.task_run_id, run.fencing_token)
                    .expect("positive control: the open run verifies");

                let (rt, raw, dsn) = (&h.rt, &h.raw, h.admin_dsn.as_str());
                let admin = &mut h.admin;
                let verdict = std::thread::scope(|s| {
                    // Owned by this closure, so a failed wait below drops it (the server rolls back) before the
                    // scope joins the verifier.
                    let (mut closer, closer_pid) = open_close(dsn, task, run.task_run_id, outcome);
                    let verifier = s.spawn(|| {
                        rt.block_on(verify_once(raw, &a, run.task_run_id, run.fencing_token))
                    });
                    wait_blocked_by(admin, closer_pid);
                    closer.batch_execute("COMMIT").expect("commit the close");
                    verifier.join().expect("verifier thread")
                });
                assert_eq!(
                    verdict,
                    Err(ErrorCode::Conflict),
                    "{}: a run finished while the verification waited is not verified",
                    outcome.as_db_str()
                );
                assert_eq!(task_state(&mut h, task), outcome.as_db_str());
            }
        },
    );
}

/// G-T04a-7 (#76): the other order. A verification that got the task row first holds it until its transaction ends, so
/// a close (complete and fail alike) waits for it and then proceeds.
#[test]
// ponytail: nesting past clippy.toml's 5 (§78.4 / G-M01-8, measured 39973585345); M01-6 refactors nothing
#[allow(clippy::excessive_nesting)]
fn g_t04a_7_close_waits_for_a_held_verification() {
    run_db_fixture::<CoordFixture, _>("g_t04a_7_close_waits_for_a_held_verification", |mut h| {
        let a = scope(h.tenant_id);
        for outcome in [TaskState::Completed, TaskState::Failed] {
            let task = submit(&h, &a);
            let run = claim(&h, &a, task).expect("claim");
            let (rt, raw, gateway) = (&h.rt, &h.raw, &h.gateway);
            let admin = &mut h.admin;
            std::thread::scope(|s| {
                let mut txn = rt.block_on(begin_scoped(raw, &a));
                rt.block_on(coord_repo::verify_task_run(
                    &mut txn,
                    &a,
                    run.task_run_id,
                    run.fencing_token,
                ))
                .expect("B verifies the open run");
                let verifier_pid: i32 = rt
                    .block_on(sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *txn))
                    .expect("pid");
                let closer = s.spawn(|| {
                    rt.block_on(async {
                        let (run, token) = (run.task_run_id, run.fencing_token);
                        match outcome {
                            TaskState::Completed => {
                                coord_repo::complete(
                                    gateway,
                                    &a,
                                    run,
                                    token,
                                    "coord_task_run summary",
                                )
                                .await
                            }
                            _ => {
                                coord_repo::fail(gateway, &a, run, token, "coord_task_run summary")
                                    .await
                            }
                        }
                    })
                });
                wait_blocked_by(admin, verifier_pid);
                let finished: bool = admin
                    .query_one(
                        "SELECT finished_at IS NOT NULL FROM coord.task_runs WHERE task_run_id = $1",
                        &[&run.task_run_id.0],
                    )
                    .expect("run row")
                    .get(0);
                assert!(
                    !finished,
                    "the close has not got past the held verification"
                );
                rt.block_on(txn.rollback()).expect("B ends its transaction");
                closer
                    .join()
                    .expect("closer thread")
                    .expect("the close proceeds once the verification's transaction ended");
            });
            assert_eq!(task_state(&mut h, task), outcome.as_db_str());
            assert_eq!(
                verify(&h, &a, run.task_run_id, run.fencing_token),
                Err(ErrorCode::Conflict),
                "{}: the closed run no longer verifies",
                outcome.as_db_str()
            );
        }
    });
}

/// G-T04a-8 (#91): `recheck_run_live_in_txn` is the verification's judgement again, as one statement on the DB clock:
/// it passes for the open, unexpired, owned run with the current token, and is Conflict for an expired lease, a stale
/// token, another principal, a finished run and an unknown run.
#[test]
fn g_t04a_8_recheck_judges_the_lease_again() {
    run_db_fixture::<CoordFixture, _>("g_t04a_8_recheck_judges_the_lease_again", |mut h| {
        let a = scope(h.tenant_id);
        let b = scope(h.tenant_id);
        let task = submit(&h, &a);
        let first = claim(&h, &a, task).expect("claim");
        let (id, token) = (first.task_run_id, first.fencing_token);
        recheck(&h, &a, id, token).expect("positive control: the open run passes");
        assert_eq!(
            recheck(&h, &b, id, token),
            Err(ErrorCode::Conflict),
            "another principal"
        );
        assert_eq!(
            recheck(&h, &a, id, FencingToken(token.0 + 1)),
            Err(ErrorCode::Conflict),
            "a token the task has not reached"
        );
        assert_eq!(
            recheck(&h, &a, TaskRunId(Uuid::new_v4()), token),
            Err(ErrorCode::Conflict),
            "an unknown run"
        );

        expire(&mut h, id);
        assert_eq!(
            recheck(&h, &a, id, token),
            Err(ErrorCode::Conflict),
            "an expired lease"
        );
        let second = claim(&h, &a, task).expect("re-claim after expiry");
        assert_eq!(
            recheck(&h, &a, id, token),
            Err(ErrorCode::Conflict),
            "the old run, superseded by a re-claim"
        );
        recheck(&h, &a, second.task_run_id, second.fencing_token).expect("the new run passes");
        complete(&h, &a, second.task_run_id, second.fencing_token).expect("close");
        assert_eq!(
            recheck(&h, &a, second.task_run_id, second.fencing_token),
            Err(ErrorCode::Conflict),
            "a finished run"
        );
    });
}
