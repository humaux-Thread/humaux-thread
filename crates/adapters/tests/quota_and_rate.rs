//! `adapters::tests::quota_and_rate` — §72.2.1 acceptance candidates for quota reservations and renewal.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, postgres, serde_json, sqlx, tokio];
//!   services=[PostgreSQL(any) w=[control.entitlement_snapshots, control.memberships, control.quota_windows,
//!   control.tenants, control.usage_reservations, control.users]
//!   x=[control.issue_quota_window, control.renew_quota_period], PostgreSQL(role_gateway),
//!   PostgreSQL(role_maintenance)];
//!   env=[HUMAUX_GATEWAY_PG_DSN, HUMAUX_MAINTENANCE_PG_DSN, HUMAUX_TEST_PG_DSN]; modules=[adapters::postgres,
//!   adapters::quota_repo, adapters::request_guard_repo, domain::error,
//!   domain::identity, domain::ids, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [dedicated RequestGuard fixture; quota reservation and renewal authority stay in PG]
//! Spec: Baseline §72.2.1; §73.2; §79.2; ADR-0062 E5; ADR-0065 D-D; ADR-0072
//!
//! These tests intentionally require the dedicated RequestGuard fixture after migration 0113.

use std::future::Future;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use humaux_adapters::{
    postgres::{MaintenanceDbPool, RuntimeDbPool},
    quota_repo::{self, ReservationStatus, ReserveResult},
    request_guard_repo,
};
use humaux_domain::{
    error::ErrorCode,
    identity::{AuthorizationScope, BoundedSet, PrincipalId},
    ids::{TenantId, UserId},
};
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use sqlx::postgres::PgConnectOptions;
use sqlx::types::Uuid;
use tokio::sync::Barrier;

const FIXTURE_DB: &str = "humaux_thread_request_guard_20260828";
const TENANT_ID: Uuid = Uuid::from_u128(0x0bad_cafe_0000_4000_8000_0000_0000_0101);
const USER_ID: Uuid = Uuid::from_u128(0x0bad_cafe_0000_4000_8000_0000_0000_0102);
const PRINCIPAL_ID: Uuid = Uuid::from_u128(0x0bad_cafe_0000_4000_8000_0000_0000_0103);
const TENANT2_ID: Uuid = Uuid::from_u128(0x0bad_cafe_0000_4000_8000_0000_0000_0111);
/// ADR-0072 D-C: the renewal lead the gate passes (deployments set it through the daemon's LEAD_SECONDS key).
const RENEWAL_LEAD: Duration = Duration::from_secs(3600);
/// The gate's current period ends this many seconds after seeding: the staging steps must finish before it (the
/// test asserts so by name), and the wait after it is bounded by it plus 30 s.
const BOUNDARY_SECS: i32 = 30;

struct Handle {
    rt: tokio::runtime::Runtime,
    runtime: RuntimeDbPool,
    maintenance: MaintenanceDbPool,
    admin: Client,
    gateway: Client,
    auth: AuthorizationScope,
    auth2: AuthorizationScope,
    /// Last field: released only after `Drop` has deleted the fixture rows.
    _serial: std::sync::MutexGuard<'static, ()>,
}

/// Every `Fixture` test seeds and (in `Drop`) deletes the same TENANT_ID / TENANT2_ID rows, so two of them in one
/// process must not overlap: under the default parallel harness one test's Drop deleted the tenant another was using
/// (`TenantBoundary`, card 38 S3 run of `--include-ignored`). The serial lane ran them one at a time anyway.
static SHARED_FIXTURE: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Fixture;

fn setup_failed<T>(_: T) -> DbFixtureSkipReason {
    DbFixtureSkipReason::IsolationSetupFailed("quota fixture setup failed".into())
}

/// ADR-0047 D-D: the dedicated request-guard fixture is whatever `HUMAUX_TEST_PG_DSN` names —
/// under `cargo xtask serial-lane` a per-run `humaux_thread_request_guard_<stamp>` database the
/// lane provisions and migrates — and every role DSN must name that same database. The
/// machine-local `61719 / FIXTURE_DB` pair stays an accepted legacy target.
///
/// Pinning *only* that pair made every test in this file report `IsolationSetupFailed` on any
/// standard node: a printed SKIP, or a fail under `HUMAUX_REQUIRE_DB=1`. The identical rule
/// already landed in `support/operation_receipt_fixture.rs` and `g80_31_handoff.rs`; this is a
/// read of that rule, not a second one.
fn same_target(role: &PgConnectOptions, owner: &PgConnectOptions) -> bool {
    (role.get_port() == 61719 && role.get_database() == Some(FIXTURE_DB))
        || (role.get_port() == owner.get_port() && role.get_database() == owner.get_database())
}

impl DbIntegrationFixture for Fixture {
    type Handle = Handle;

    #[allow(clippy::too_many_lines)] // One isolated fixture validates the complete role and schema preflight before tests run.
    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        let serial = SHARED_FIXTURE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let owner_dsn =
            std::env::var("HUMAUX_TEST_PG_DSN").map_err(|_| DbFixtureSkipReason::NoDatabaseUrl)?;
        let options = PgConnectOptions::from_str(&owner_dsn).map_err(setup_failed)?;
        if options.get_host() != "127.0.0.1" || owner_dsn.contains(['?', '#']) {
            return Err(setup_failed(()));
        }
        // dep: PostgreSQL(any) — open a role-scoped PG connection/pool for this test
        let mut admin = Client::connect(&owner_dsn, NoTls).map_err(setup_failed)?;
        let ready: bool = admin
            .query_one(
                "SELECT to_regclass('control.usage_reservations') IS NOT NULL",
                &[],
            )
            .map_err(setup_failed)?
            .get(0);
        if !ready {
            return Err(DbFixtureSkipReason::IsolationSetupFailed(
                "migration 0113 is not applied".into(),
            ));
        }
        admin
            .execute(
                "INSERT INTO control.tenants(tenant_id,name,state) VALUES($1,'quota fixture','ACTIVE'),($2,'quota fixture two','ACTIVE') ON CONFLICT DO NOTHING",
                &[&TENANT_ID, &TENANT2_ID],
            )
            .map_err(setup_failed)?;
        admin
            .execute(
                "INSERT INTO control.users(user_id,state) VALUES($1,'ACTIVE') ON CONFLICT DO NOTHING",
                &[&USER_ID],
            )
            .map_err(setup_failed)?;
        admin
            .execute(
                "INSERT INTO control.memberships(tenant_id,user_id,role,state) VALUES($1,$2,'member','ACTIVE') ON CONFLICT DO NOTHING",
                &[&TENANT_ID, &USER_ID],
            )
            .map_err(setup_failed)?;
        admin
            .execute(
                "INSERT INTO control.memberships(tenant_id,user_id,role,state) VALUES($1,$2,'member','ACTIVE') ON CONFLICT DO NOTHING",
                &[&TENANT2_ID, &USER_ID],
            )
            .map_err(setup_failed)?;
        let gateway_dsn = std::env::var("HUMAUX_GATEWAY_PG_DSN").map_err(setup_failed)?;
        let maintenance_dsn = std::env::var("HUMAUX_MAINTENANCE_PG_DSN").map_err(setup_failed)?;
        let gateway_options = PgConnectOptions::from_str(&gateway_dsn).map_err(setup_failed)?;
        let maintenance_options =
            PgConnectOptions::from_str(&maintenance_dsn).map_err(setup_failed)?;
        if gateway_options.get_username() != "role_gateway"
            || maintenance_options.get_username() != "role_maintenance"
            || gateway_options.get_host() != "127.0.0.1"
            || maintenance_options.get_host() != "127.0.0.1"
            || !same_target(&gateway_options, &options)
            || !same_target(&maintenance_options, &options)
            || gateway_dsn.contains(['?', '#'])
            || maintenance_dsn.contains(['?', '#'])
        {
            return Err(setup_failed(()));
        }
        // dep: PostgreSQL(any) — open a role-scoped PG connection/pool for this test
        let mut gateway = Client::connect(&gateway_dsn, NoTls).map_err(setup_failed)?;
        let role_ok: bool = gateway
            .query_one(
                "SELECT current_user='role_gateway' AND session_user='role_gateway'
                 AND NOT (SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user)",
                &[],
            )
            .map_err(setup_failed)?
            .get(0);
        if !role_ok {
            return Err(setup_failed(()));
        }
        let rt = tokio::runtime::Runtime::new().map_err(setup_failed)?;
        let runtime = rt
            // dep: PostgreSQL(role_gateway) — open a role-scoped PG connection/pool for this test
            .block_on(RuntimeDbPool::connect(&gateway_dsn))
            .map_err(setup_failed)?;
        let maintenance = rt
            // dep: PostgreSQL(role_maintenance) — open a role-scoped PG connection/pool for this test
            .block_on(MaintenanceDbPool::connect(&maintenance_dsn))
            .map_err(setup_failed)?;
        let auth = AuthorizationScope::new(
            TenantId(TENANT_ID),
            PrincipalId(PRINCIPAL_ID),
            Some(UserId(USER_ID)),
            BoundedSet::new([]).map_err(setup_failed)?,
        );
        let auth2 = AuthorizationScope::new(
            TenantId(TENANT2_ID),
            PrincipalId(PRINCIPAL_ID),
            Some(UserId(USER_ID)),
            BoundedSet::new([]).map_err(setup_failed)?,
        );
        Ok(Handle {
            rt,
            runtime,
            maintenance,
            admin,
            gateway,
            auth,
            auth2,
            _serial: serial,
        })
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        let _ = self.admin.batch_execute(&format!(
            "DELETE FROM control.usage_reservations WHERE tenant_id IN ('{TENANT_ID}','{TENANT2_ID}');
             DELETE FROM control.quota_windows WHERE tenant_id IN ('{TENANT_ID}','{TENANT2_ID}');
             DELETE FROM control.entitlement_snapshots WHERE tenant_id IN ('{TENANT_ID}','{TENANT2_ID}');
             DELETE FROM control.memberships WHERE tenant_id IN ('{TENANT_ID}','{TENANT2_ID}');
             DELETE FROM control.users WHERE user_id='{USER_ID}';
             DELETE FROM control.tenants WHERE tenant_id IN ('{TENANT_ID}','{TENANT2_ID}');"
        ));
    }
}

fn snapshot(handle: &mut Handle, tenant: Uuid, limit: i64) {
    let effective = format!(
        "jsonb_build_object('mcp.billable_operations.per_period', jsonb_build_object('limit',{limit},'period','subscription_period','charge_policy','success_only','period_start',to_char((clock_timestamp()-interval '1 second') AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'),'period_end',to_char((clock_timestamp()+interval '1 hour') AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')))"
    );
    handle
        .admin
        .execute(
            &format!(
                "INSERT INTO control.entitlement_snapshots(tenant_id,effective,source_grant_ids,computed_at)
                 VALUES($1,{effective},ARRAY[$2]::uuid[],clock_timestamp())
                 ON CONFLICT (tenant_id) DO UPDATE SET effective=EXCLUDED.effective,source_grant_ids=EXCLUDED.source_grant_ids,computed_at=EXCLUDED.computed_at"
            ),
            &[&tenant, &Uuid::now_v7()],
        )
        .expect("admin seeds projected snapshot");
}

fn issue_for(handle: &mut Handle, tenant: Uuid, limit: i64) {
    snapshot(handle, tenant, limit);
    handle
        .rt
        .block_on(quota_repo::issue_window(
            &handle.maintenance,
            TenantId(tenant),
        ))
        .expect("maintenance issues projected quota window");
}

fn issue(handle: &mut Handle, limit: i64) {
    issue_for(handle, TENANT_ID, limit);
}

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("bounded concurrent fixture operation")
}

async fn issue_at_barrier(
    pool: &MaintenanceDbPool,
    barrier: Arc<Barrier>,
    tenant: TenantId,
) -> Result<quota_repo::QuotaWindow, ErrorCode> {
    barrier.wait().await;
    quota_repo::issue_window(pool, tenant).await
}

async fn reserve_at_barrier<'a>(
    pool: &'a RuntimeDbPool,
    auth: &'a AuthorizationScope,
    barrier: Arc<Barrier>,
    request_id: Uuid,
    fingerprint: &'a str,
) -> Result<ReserveResult, ErrorCode> {
    barrier.wait().await;
    quota_repo::reserve_bmo(
        pool,
        auth,
        request_id,
        "mcp.read",
        fingerprint,
        Duration::from_secs(60),
    )
    .await
}

fn change_limit_preserving_period(handle: &mut Handle, limit: i64) {
    handle
        .admin
        .execute(
            "UPDATE control.entitlement_snapshots
             SET effective=jsonb_set(effective,'{mcp.billable_operations.per_period,limit}',to_jsonb($2::bigint))
             WHERE tenant_id=$1",
            &[&TENANT_ID, &limit],
        )
        .expect("admin changes only projected limit");
}

fn change_period_end_preserving_start(handle: &mut Handle) {
    handle
        .admin
        .execute(
            "UPDATE control.entitlement_snapshots
             SET effective=jsonb_set(effective,'{mcp.billable_operations.per_period,period_end}',
                 to_jsonb(to_char((q.window_end + interval '1 hour') AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')))
             FROM (SELECT window_end FROM control.quota_windows WHERE tenant_id=$1 AND entitlement_key=$2 LIMIT 1) q
             WHERE tenant_id=$1",
            &[&TENANT_ID, &quota_repo::BMO_ENTITLEMENT],
        )
        .expect("admin changes only projected period end");
}

#[test]
#[ignore = "lane(a:request_guard) requires migration 0113 and the dedicated request-guard PostgreSQL fixture"]
fn concurrent_issuer_is_single_window_and_retry_does_not_rewrite_limit() {
    run_db_fixture::<Fixture, _>("quota_concurrent_issuer", |mut h| {
        snapshot(&mut h, TENANT_ID, 3);
        let barrier = Arc::new(Barrier::new(4));
        let (a, b, c, d) = h.rt.block_on(bounded(async {
            tokio::join!(
                issue_at_barrier(&h.maintenance, barrier.clone(), TenantId(TENANT_ID)),
                issue_at_barrier(&h.maintenance, barrier.clone(), TenantId(TENANT_ID)),
                issue_at_barrier(&h.maintenance, barrier.clone(), TenantId(TENANT_ID)),
                issue_at_barrier(&h.maintenance, barrier, TenantId(TENANT_ID)),
            )
        }));
        assert_eq!(
            [a.is_ok(), b.is_ok(), c.is_ok(), d.is_ok()]
                .into_iter()
                .filter(|v| *v)
                .count(),
            4
        );
        assert_eq!(
            h.admin
                .query_one(
                    "SELECT count(*) FROM control.quota_windows WHERE tenant_id=$1",
                    &[&TENANT_ID]
                )
                .unwrap()
                .get::<_, i64>(0),
            1
        );
        change_limit_preserving_period(&mut h, 99);
        assert!(
            h.rt.block_on(quota_repo::issue_window(
                &h.maintenance,
                TenantId(TENANT_ID)
            ))
            .is_ok()
        );
        assert_eq!(h.admin.query_one("SELECT hard_limit FROM control.quota_windows WHERE tenant_id=$1 AND entitlement_key=$2", &[&TENANT_ID, &quota_repo::BMO_ENTITLEMENT]).unwrap().get::<_, i64>(0), 3);
        change_period_end_preserving_start(&mut h);
        assert!(
            h.rt.block_on(quota_repo::issue_window(
                &h.maintenance,
                TenantId(TENANT_ID)
            ))
            .is_err()
        );
    });
}

#[test]
#[ignore = "lane(a:request_guard) requires migration 0113 and the dedicated request-guard PostgreSQL fixture"]
fn concurrent_capacity_one_creates_one_and_same_request_is_idempotent() {
    run_db_fixture::<Fixture, _>("quota_concurrent_reservations", |mut h| {
        issue(&mut h, 1);
        let fp = "e".repeat(64);
        let barrier = Arc::new(Barrier::new(4));
        let requests = [
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
        ];
        let (a, b, c, d) = h.rt.block_on(bounded(async {
            tokio::join!(
                reserve_at_barrier(&h.runtime, &h.auth, barrier.clone(), requests[0], &fp),
                reserve_at_barrier(&h.runtime, &h.auth, barrier.clone(), requests[1], &fp),
                reserve_at_barrier(&h.runtime, &h.auth, barrier.clone(), requests[2], &fp),
                reserve_at_barrier(&h.runtime, &h.auth, barrier, requests[3], &fp),
            )
        }));
        let results = [a, b, c, d];
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Ok(ReserveResult::Created(_))))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Err(ErrorCode::QuotaExhausted)))
                .count(),
            3
        );
        let counters = h.admin.query_one("SELECT reserved, consumed FROM control.quota_windows WHERE tenant_id=$1 AND entitlement_key=$2", &[&TENANT_ID, &quota_repo::BMO_ENTITLEMENT]).unwrap();
        assert_eq!(
            (counters.get::<_, i64>(0), counters.get::<_, i64>(1)),
            (1, 0)
        );

        issue_for(&mut h, TENANT2_ID, 4);
        let same = Uuid::now_v7();
        let same_fp = "f".repeat(64);
        let barrier = Arc::new(Barrier::new(4));
        let (a, b, c, d) = h.rt.block_on(bounded(async {
            tokio::join!(
                reserve_at_barrier(&h.runtime, &h.auth2, barrier.clone(), same, &same_fp),
                reserve_at_barrier(&h.runtime, &h.auth2, barrier.clone(), same, &same_fp),
                reserve_at_barrier(&h.runtime, &h.auth2, barrier.clone(), same, &same_fp),
                reserve_at_barrier(&h.runtime, &h.auth2, barrier, same, &same_fp),
            )
        }));
        let results = [a, b, c, d];
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Ok(ReserveResult::Created(_))))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Ok(ReserveResult::Existing(_))))
                .count(),
            3
        );
        assert_eq!(h.admin.query_one("SELECT count(*) FROM control.usage_reservations WHERE tenant_id=$1 AND request_id=$2", &[&TENANT2_ID, &same]).unwrap().get::<_, i64>(0), 1);
    });
}

#[test]
#[ignore = "lane(a:request_guard) requires migration 0113 and the dedicated request-guard PostgreSQL fixture"]
fn issuer_is_projection_only_and_runtime_cannot_issue_or_insert_window() {
    run_db_fixture::<Fixture, _>("quota_issuer_projection_and_acl", |mut h| {
        assert!(
            h.rt.block_on(quota_repo::issue_window(
                &h.maintenance,
                TenantId(TENANT_ID)
            ))
            .is_err()
        );
        issue(&mut h, 2);
        let no_guc = h.gateway.query_one(
            "SELECT control.issue_quota_window($1,$2)",
            &[&TENANT_ID, &quota_repo::BMO_ENTITLEMENT],
        );
        assert!(no_guc.is_err(), "gateway cannot issue without tenant GUC");
        let direct_insert = h.gateway.execute(
            "INSERT INTO control.quota_windows(tenant_id,entitlement_key,window_start,window_end,hard_limit)
             VALUES($1,$2,clock_timestamp(),clock_timestamp()+interval '1 hour',1)",
            &[&TENANT_ID, &quota_repo::BMO_ENTITLEMENT],
        );
        assert!(
            direct_insert.is_err(),
            "gateway cannot insert quota windows"
        );
        let denied = h.admin.query_one(
            "SELECT has_table_privilege('role_gateway','control.quota_windows','INSERT')
             OR has_function_privilege('role_gateway','control.issue_quota_window(uuid,text)','EXECUTE')",
            &[],
        ).expect("admin checks ACL").get::<_, bool>(0);
        assert!(!denied);
    });
}

/// A snapshot whose BMO period started a second ago and ends `ends_in_secs` from now (the onboarding shape).
fn snapshot_ending_in(handle: &mut Handle, tenant: Uuid, limit: i64, ends_in_secs: i32) {
    handle
        .admin
        .execute(
            "INSERT INTO control.entitlement_snapshots(tenant_id,effective,source_grant_ids,computed_at)
             VALUES($1,jsonb_build_object('mcp.billable_operations.per_period',jsonb_build_object(
               'limit',$2::bigint,'period','subscription_period','charge_policy','success_only',
               'period_start',to_char((clock_timestamp()-interval '1 second') AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'),
               'period_end',to_char((clock_timestamp()+make_interval(secs=>$3::int)) AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'))),
               '{}'::uuid[],clock_timestamp())
             ON CONFLICT (tenant_id) DO UPDATE SET effective=EXCLUDED.effective,computed_at=EXCLUDED.computed_at,
               successor=NULL,successor_from=NULL",
            &[&tenant, &limit, &ends_in_secs],
        )
        .expect("admin seeds a period ending soon");
}

fn renew(handle: &Handle, tenant: Uuid) -> Result<quota_repo::Renewal, ErrorCode> {
    handle.rt.block_on(quota_repo::renew_period(
        &handle.maintenance,
        TenantId(tenant),
        RENEWAL_LEAD,
        1,
        4,
    ))
}

async fn renew_at_barrier(
    pool: &MaintenanceDbPool,
    barrier: Arc<Barrier>,
) -> Result<quota_repo::Renewal, ErrorCode> {
    barrier.wait().await;
    quota_repo::renew_period(pool, TenantId(TENANT_ID), RENEWAL_LEAD, 1, 4).await
}

fn window_count(handle: &mut Handle, tenant: Uuid) -> i64 {
    handle
        .admin
        .query_one(
            "SELECT count(*) FROM control.quota_windows WHERE tenant_id=$1",
            &[&tenant],
        )
        .expect("admin counts windows")
        .get(0)
}

/// The successor window's end in unix microseconds, `None` while no successor is staged.
fn successor_end_micros(handle: &mut Handle, tenant: Uuid) -> Option<i64> {
    handle
        .admin
        .query_opt(
            "SELECT (extract(epoch FROM w.window_end) * 1000000)::bigint
             FROM control.quota_windows w
             JOIN control.entitlement_snapshots s
               ON s.tenant_id = w.tenant_id AND w.window_start = s.successor_from
             WHERE w.tenant_id = $1",
            &[&tenant],
        )
        .expect("admin reads the successor window")
        .map(|row| row.get(0))
}

/// Card W0 / ADR-0072 gate (§72.2.1): before a renewing tenant's period ends, the renewal step stages the next period
/// on the snapshot and issues its window contiguous with the current one, with the snapshot's limit and the
/// configured length, and reports that window's end as the horizon; a later change of `effective` drops the staged
/// successor and the next call re-stages it from the new `effective`; after the old end — with no maintenance call at
/// the boundary — the gateway's entitlement read is the successor and a reservation lands in the successor window.
/// Four concurrent renewals and every rerun stage exactly one successor; the first call after the boundary promotes it
/// and stages nothing; a SUSPENDED tenant is not renewed; no runtime role may execute the door. Fault injections
/// (each one red here): (1) delete the `INSERT INTO control.quota_windows` of 0245 ⇒ one window, and the reservation
/// after the boundary is QuotaExhausted; (2) delete `v_successor IS NOT NULL OR` from the loop exit ⇒ every call
/// re-stages the pending successor up to its limit (staged sums to 16, the rerun stages 4); (3) delete the
/// `t.state = 'ACTIVE'` predicate ⇒ the suspended tenant gets a second window; (4) revert
/// `request_guard_repo::read_effective_entitlements` to read `effective` only ⇒ the read after the boundary is the
/// ended period, not the successor.
#[test]
#[ignore = "lane(a:request_guard) requires migration 0245 and the dedicated request-guard PostgreSQL fixture"]
#[allow(clippy::too_many_lines)] // one tenant pair through the boundary: issue, stage, re-stage, promote, suspended, ACL
fn quota_window_renews_before_period_end() {
    run_db_fixture::<Fixture, _>("quota_window_renews_before_period_end", |mut h| {
        for tenant in [TENANT_ID, TENANT2_ID] {
            snapshot_ending_in(&mut h, tenant, 3, BOUNDARY_SECS);
            h.rt.block_on(quota_repo::issue_window(&h.maintenance, TenantId(tenant)))
                .expect("maintenance issues the current window");
        }
        h.admin
            .execute(
                "UPDATE control.tenants SET state='SUSPENDED' WHERE tenant_id=$1",
                &[&TENANT2_ID],
            )
            .expect("admin suspends the second tenant");

        let barrier = Arc::new(Barrier::new(4));
        let (a, b, c, d) = h.rt.block_on(bounded(async {
            tokio::join!(
                renew_at_barrier(&h.maintenance, barrier.clone()),
                renew_at_barrier(&h.maintenance, barrier.clone()),
                renew_at_barrier(&h.maintenance, barrier.clone()),
                renew_at_barrier(&h.maintenance, barrier),
            )
        }));
        let staged: Vec<i32> = [a, b, c, d]
            .into_iter()
            .map(|r| r.expect("concurrent renewal").staged)
            .collect();
        assert_eq!(
            staged.iter().sum::<i32>(),
            1,
            "exactly one successor: {staged:?}"
        );
        let rerun = renew(&h, TENANT_ID).expect("rerun");
        assert_eq!(rerun.staged, 0, "a pending successor is never staged twice");
        let successor_end = successor_end_micros(&mut h, TENANT_ID);
        assert!(successor_end.is_some(), "a successor window is staged");
        assert_eq!(
            rerun
                .horizon
                .map(|end| i64::try_from(end.unix_timestamp_nanos() / 1000).expect("micros fit")),
            successor_end,
            "the horizon is the successor window's end"
        );
        assert_eq!(window_count(&mut h, TENANT_ID), 2);
        let shaped: Option<bool> = h
            .admin
            .query_one(
                "SELECT n.window_start = c.window_end
                    AND n.window_end = ((c.window_end AT TIME ZONE 'UTC') + interval '1 month') AT TIME ZONE 'UTC'
                    AND n.hard_limit = 3 AND n.reserved = 0 AND n.consumed = 0
                    AND s.successor_from = n.window_start
                    AND (s.successor -> 'mcp.billable_operations.per_period' ->> 'period_start')::timestamptz
                        = c.window_end
                    AND (s.successor -> 'mcp.billable_operations.per_period' ->> 'period_end')::timestamptz
                        = n.window_end
                    AND (s.successor -> 'mcp.billable_operations.per_period' ->> 'limit')::bigint = 3
                 FROM control.quota_windows c
                 JOIN control.quota_windows n ON n.tenant_id = c.tenant_id AND n.window_start > c.window_start
                 JOIN control.entitlement_snapshots s ON s.tenant_id = c.tenant_id
                 WHERE c.tenant_id = $1",
                &[&TENANT_ID],
            )
            .expect("admin reads the staged period")
            .get(0);
        assert_eq!(
            shaped,
            Some(true),
            "the successor starts at the current end, is one month long, with the snapshot limit"
        );

        // ADR-0072 L3: lowering the limit on `effective` drops the stale successor; the next call re-stages from the
        // new `effective` (the issued successor window keeps its immutable limit).
        h.admin
            .execute(
                "UPDATE control.entitlement_snapshots
                 SET effective = jsonb_set(effective, '{mcp.billable_operations.per_period,limit}', '2'::jsonb)
                 WHERE tenant_id = $1",
                &[&TENANT_ID],
            )
            .expect("admin lowers the projected limit");
        let dropped: bool = h
            .admin
            .query_one(
                "SELECT successor IS NULL AND successor_from IS NULL
                 FROM control.entitlement_snapshots WHERE tenant_id = $1",
                &[&TENANT_ID],
            )
            .expect("admin reads the snapshot")
            .get(0);
        assert!(dropped, "a changed effective drops the stale successor");
        let restaged = renew(&h, TENANT_ID).expect("re-stage after the change");
        assert_eq!(restaged.staged, 1, "the next call re-stages the successor");
        let restaged_limit: Option<i64> = h
            .admin
            .query_one(
                "SELECT (successor -> 'mcp.billable_operations.per_period' ->> 'limit')::bigint
                 FROM control.entitlement_snapshots WHERE tenant_id = $1",
                &[&TENANT_ID],
            )
            .expect("admin reads the re-staged successor")
            .get(0);
        assert_eq!(
            restaged_limit,
            Some(2),
            "the successor carries the new limit"
        );
        assert_eq!(successor_end_micros(&mut h, TENANT_ID), successor_end);
        assert_eq!(window_count(&mut h, TENANT_ID), 2);
        let before_boundary: Option<bool> = h
            .admin
            .query_one(
                "SELECT clock_timestamp() < successor_from FROM control.entitlement_snapshots WHERE tenant_id=$1",
                &[&TENANT_ID],
            )
            .expect("admin reads the clock")
            .get(0);
        assert_eq!(
            before_boundary,
            Some(true),
            "the staging steps finished before the boundary (raise BOUNDARY_SECS on a slower runner)"
        );

        // The old period ends with no maintenance call in between.
        let deadline =
            Instant::now() + Duration::from_secs(u64::from(BOUNDARY_SECS.unsigned_abs()) + 30);
        while h
            .admin
            .query_one(
                "SELECT clock_timestamp() > successor_from FROM control.entitlement_snapshots WHERE tenant_id=$1",
                &[&TENANT_ID],
            )
            .expect("admin reads the clock")
            .get::<_, Option<bool>>(0)
            != Some(true)
        {
            assert!(Instant::now() < deadline, "the current period never ended");
            std::thread::sleep(Duration::from_millis(200));
        }
        let successor: serde_json::Value = h
            .admin
            .query_one(
                "SELECT successor FROM control.entitlement_snapshots WHERE tenant_id=$1",
                &[&TENANT_ID],
            )
            .expect("admin reads the successor")
            .get(0);
        let facts =
            h.rt.block_on(request_guard_repo::read_effective_entitlements(
                &h.runtime, &h.auth,
            ))
            .expect("the gateway reads an entitlement after the boundary");
        assert_eq!(facts.effective, successor, "the successor is in force");
        let reserved =
            h.rt.block_on(quota_repo::reserve_bmo(
                &h.runtime,
                &h.auth,
                Uuid::now_v7(),
                "mcp.read",
                &"b".repeat(64),
                Duration::from_secs(60),
            ))
            .expect("a reservation after the boundary succeeds");
        assert!(matches!(reserved, ReserveResult::Created(_)));
        let in_successor: Option<bool> = h
            .admin
            .query_one(
                "SELECT bool_and(r.window_start = s.successor_from)
                 FROM control.usage_reservations r JOIN control.entitlement_snapshots s USING (tenant_id)
                 WHERE r.tenant_id = $1",
                &[&TENANT_ID],
            )
            .expect("admin reads the reservation")
            .get(0);
        assert_eq!(
            in_successor,
            Some(true),
            "the reservation is charged to the successor window"
        );

        let promoted = renew(&h, TENANT_ID).expect("the first call after the boundary");
        assert_eq!(
            promoted.staged, 0,
            "the successor's own end is a month away"
        );
        assert_eq!(window_count(&mut h, TENANT_ID), 2);
        let row = h
            .admin
            .query_one(
                "SELECT successor IS NULL AND successor_from IS NULL, effective
                 FROM control.entitlement_snapshots WHERE tenant_id=$1",
                &[&TENANT_ID],
            )
            .expect("admin reads the promoted snapshot");
        assert!(row.get::<_, bool>(0), "the successor was promoted");
        assert_eq!(row.get::<_, serde_json::Value>(1), successor);

        assert_eq!(
            renew(&h, TENANT2_ID).expect("a suspended tenant is a no-op"),
            quota_repo::Renewal {
                staged: 0,
                horizon: None
            }
        );
        assert_eq!(
            window_count(&mut h, TENANT2_ID),
            1,
            "a suspended tenant is never renewed"
        );
        let gateway_can: bool = h
            .admin
            .query_one(
                "SELECT has_function_privilege('role_gateway',
                   'control.renew_quota_period(uuid,text,interval,interval,integer)','EXECUTE')",
                &[],
            )
            .expect("admin checks the ACL")
            .get(0);
        assert!(!gateway_can, "only role_maintenance renews");
    });
}

#[test]
#[ignore = "lane(a:request_guard) requires migration 0113 and the dedicated request-guard PostgreSQL fixture"]
fn reservation_capacity_replay_consumption_release_and_reap_are_terminal() {
    run_db_fixture::<Fixture, _>("quota_reservation_lifecycle", |mut h| {
        issue(&mut h, 1);
        issue_for(&mut h, TENANT2_ID, 1);
        let request = Uuid::now_v7();
        let other =
            h.rt.block_on(quota_repo::reserve_bmo(
                &h.runtime,
                &h.auth2,
                request,
                "mcp.read",
                &"a".repeat(64),
                Duration::from_secs(60),
            ))
            .expect("same request id is independent across tenants");
        assert!(matches!(other, ReserveResult::Created(_)));
        let fp = "a".repeat(64);
        let first =
            h.rt.block_on(quota_repo::reserve_bmo(
                &h.runtime,
                &h.auth,
                request,
                "mcp.read",
                &fp,
                Duration::from_secs(60),
            ))
            .expect("first reservation");
        let reservation = match first {
            ReserveResult::Created(r) => r,
            ReserveResult::Existing(_) => panic!("fresh request"),
        };
        assert!(matches!(
            h.rt.block_on(quota_repo::reserve_bmo(
                &h.runtime,
                &h.auth,
                request,
                "mcp.read",
                &fp,
                Duration::from_secs(60)
            )),
            Ok(ReserveResult::Existing(ReservationStatus::Reserved))
        ));
        assert_eq!(
            h.rt.block_on(quota_repo::finish_reservation(
                &h.runtime,
                &h.auth,
                &reservation,
                true
            )),
            Ok(ReservationStatus::Consumed)
        );
        assert_eq!(
            h.rt.block_on(quota_repo::finish_reservation(
                &h.runtime,
                &h.auth,
                &reservation,
                true
            )),
            Ok(ReservationStatus::Consumed)
        );
        assert_eq!(
            h.rt.block_on(quota_repo::finish_reservation(
                &h.runtime,
                &h.auth,
                &reservation,
                false
            )),
            Err(ErrorCode::Conflict)
        );
        assert!(matches!(
            h.rt.block_on(quota_repo::reserve_bmo(
                &h.runtime,
                &h.auth,
                Uuid::now_v7(),
                "mcp.read",
                &fp,
                Duration::from_micros(1)
            )),
            Err(ErrorCode::QuotaExhausted)
        ));
    });
}

#[test]
#[ignore = "lane(a:request_guard) requires migration 0113 and the dedicated request-guard PostgreSQL fixture"]
fn mismatched_replay_and_invalid_inputs_fail_closed() {
    run_db_fixture::<Fixture, _>("quota_argument_binding", |mut h| {
        issue(&mut h, 2);
        let request = Uuid::now_v7();
        let fp = "b".repeat(64);
        let r = match h
            .rt
            .block_on(quota_repo::reserve_bmo(
                &h.runtime,
                &h.auth,
                request,
                "mcp.write",
                &fp,
                Duration::from_secs(60),
            ))
            .unwrap()
        {
            ReserveResult::Created(r) => r,
            ReserveResult::Existing(_) => panic!("fresh request"),
        };
        assert!(matches!(
            h.rt.block_on(quota_repo::reserve_bmo(
                &h.runtime,
                &h.auth,
                request,
                "mcp.other",
                &fp,
                Duration::from_secs(60)
            )),
            Err(ErrorCode::Conflict)
        ));
        assert_eq!(
            h.rt.block_on(quota_repo::finish_reservation(
                &h.runtime, &h.auth, &r, false
            )),
            Ok(ReservationStatus::Released)
        );
    });
}

#[test]
#[ignore = "lane(a:request_guard) requires migration 0113 and the dedicated request-guard PostgreSQL fixture"]
fn expired_reservation_is_reaped_without_charging() {
    run_db_fixture::<Fixture, _>("quota_expiry_reap", |mut h| {
        issue(&mut h, 1);
        let result =
            h.rt.block_on(quota_repo::reserve_bmo(
                &h.runtime,
                &h.auth,
                Uuid::now_v7(),
                "mcp.read",
                &"d".repeat(64),
                Duration::from_secs(2),
            ))
            .unwrap();
        let reservation = match result {
            ReserveResult::Created(r) => r,
            ReserveResult::Existing(_) => panic!("fresh request"),
        };
        let mut expired = false;
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            expired = h
                .admin
                .query_one(
                    "SELECT clock_timestamp() >= expires_at FROM control.usage_reservations WHERE reservation_id=$1",
                    &[&reservation.id()],
                )
                .expect("read DB clock against reservation lease")
                .get(0);
            if expired {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(expired, "database clock must prove lease expiry");
        assert_eq!(
            h.rt.block_on(quota_repo::reap_expired(
                &h.maintenance,
                TenantId(TENANT_ID),
                10
            ))
            .unwrap(),
            1
        );
        let row = h
            .admin
            .query_one(
                "SELECT status, finished_at IS NOT NULL FROM control.usage_reservations WHERE reservation_id=$1",
                &[&reservation.id()],
            )
            .expect("read reaped reservation");
        assert_eq!(row.get::<_, String>(0), "RELEASED");
        assert!(row.get::<_, bool>(1));
        let counters = h
            .admin
            .query_one(
                "SELECT reserved, consumed FROM control.quota_windows WHERE tenant_id=$1 AND entitlement_key=$2",
                &[&TENANT_ID, &quota_repo::BMO_ENTITLEMENT],
            )
            .expect("read released counters");
        assert_eq!(counters.get::<_, i64>(0), 0);
        assert_eq!(counters.get::<_, i64>(1), 0);
        assert_eq!(
            h.rt.block_on(quota_repo::reap_expired(
                &h.maintenance,
                TenantId(TENANT_ID),
                10
            ))
            .unwrap(),
            0
        );
        assert_eq!(
            h.rt.block_on(quota_repo::finish_reservation(
                &h.runtime,
                &h.auth,
                &reservation,
                true
            )),
            Err(ErrorCode::Conflict)
        );
        let after = h
            .admin
            .query_one(
                "SELECT reserved, consumed FROM control.quota_windows WHERE tenant_id=$1 AND entitlement_key=$2",
                &[&TENANT_ID, &quota_repo::BMO_ENTITLEMENT],
            )
            .expect("read terminal counters");
        assert_eq!((after.get::<_, i64>(0), after.get::<_, i64>(1)), (0, 0));
    });
}
