//! `adapters::tests::request_guard` — RequestGuard persistence acceptance against the dedicated real gateway-login
//!   fixture.
//! Depends-on: crates=[humaux-adapters, humaux-application, humaux-domain, humaux-testkit, postgres, sqlx, tokio];
//!   services=[PostgreSQL(owner) r=[control.audit_events, control.billing_payments, control.entitlement_snapshots,
//!   control.quota_windows, control.usage_reservations] w=[control.entitlement_snapshots, control.memberships,
//!   control.tenants, control.users] x=[control.audit_event_insert], PostgreSQL(role_gateway)];
//!   env=[HUMAUX_GATEWAY_PG_DSN, HUMAUX_TEST_PG_DSN]; modules=[adapters::entitlement_repo, adapters::independent_audit, application::independent_audit, application::read_quota, adapters::postgres, adapters::request_guard_repo,
//!   domain::audit, domain::error, domain::identity, domain::ids, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [the effective entitlement snapshot gates every read request (missing = EntitlementRequired,
//!   cross-tenant = TenantBoundary) and the §77 audit row commits with the quota transition; the gateway tests are
//!   #[ignore] lane tests]
//! Spec: ADR-0047; ADR-0137

use std::str::FromStr;
use std::time::{Duration, SystemTime};

use humaux_adapters::{
    entitlement_repo::mcp_entitlement_for_tenants,
    independent_audit::PostgresIndependentAudit,
    postgres::{RuntimeDbPool, load_pool_settings},
    request_guard_repo,
};
use humaux_application::independent_audit::{AuditIdentity, record_independent_audit};
use humaux_application::read_quota::McpEntitlement::{Enabled, EntitlementRequired};
use humaux_domain::{
    audit::{AuditEvent, AuditEventId, AuditMetadata, SYSTEM_TENANT_ID},
    error::ErrorCode,
    identity::{AuthorizationScope, BoundedSet, PrincipalId},
    ids::{TenantId, UserId, WorkspaceId},
};
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls, error::SqlState};
use sqlx::postgres::PgConnectOptions;
use sqlx::types::Uuid;

const FIXTURE_DB: &str = "humaux_thread_request_guard_20260828";
const TENANT_ID: Uuid = Uuid::from_u128(0x0bad_cafe_0000_4000_8000_0000_0000_0001);
const USER_ID: Uuid = Uuid::from_u128(0x0bad_cafe_0000_4000_8000_0000_0000_0002);

struct Handle {
    rt: tokio::runtime::Runtime,
    runtime: RuntimeDbPool,
    admin: Client,
    gateway: Client,
    authorization: AuthorizationScope,
}

fn setup_failed<T>(_: T) -> DbFixtureSkipReason {
    DbFixtureSkipReason::IsolationSetupFailed("request guard fixture setup failed".into())
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

    fn isolate() -> Result<Handle, DbFixtureSkipReason> {
        let admin_dsn =
            std::env::var("HUMAUX_TEST_PG_DSN").map_err(|_| DbFixtureSkipReason::NoDatabaseUrl)?;
        let admin_options = PgConnectOptions::from_str(&admin_dsn).map_err(setup_failed)?;
        if admin_options.get_host() != "127.0.0.1" || admin_dsn.contains(['?', '#']) {
            return Err(setup_failed(()));
        }
        // dep: PostgreSQL(owner) — test opens a direct PG connection for setup/verification
        let mut admin = Client::connect(&admin_dsn, NoTls).map_err(setup_failed)?;
        let gateway_dsn = std::env::var("HUMAUX_GATEWAY_PG_DSN").map_err(setup_failed)?;
        let gateway_options = PgConnectOptions::from_str(&gateway_dsn).map_err(setup_failed)?;
        if gateway_options.get_username() != "role_gateway"
            || gateway_options.get_host() != "127.0.0.1"
            || !same_target(&gateway_options, &admin_options)
            || gateway_dsn.contains(['?', '#'])
        {
            return Err(setup_failed(()));
        }
        // dep: PostgreSQL(owner) — test opens a direct PG connection for setup/verification
        let mut gateway = Client::connect(&gateway_dsn, NoTls).map_err(setup_failed)?;
        let role_ok: bool = gateway
            .query_one(
                "SELECT current_user = 'role_gateway' AND session_user = 'role_gateway' \
                 AND NOT (SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user)",
                &[],
            )
            .map_err(setup_failed)?
            .get(0);
        if !role_ok {
            return Err(setup_failed(()));
        }
        let required: bool = admin
            .query_one(
                "SELECT to_regclass('control.entitlement_snapshots') IS NOT NULL \
                 AND to_regprocedure('control.audit_event_insert(uuid,timestamptz,uuid,text,text,text,text,text,text,text,text,inet,text,text[],text,text,jsonb)') IS NOT NULL",
                &[],
            )
            .map_err(setup_failed)?
            .get(0);
        if !required {
            return Err(setup_failed(()));
        }
        admin
            .execute(
                "INSERT INTO control.tenants(tenant_id,name,state) VALUES($1,'request guard fixture','ACTIVE') \
                 ON CONFLICT (tenant_id) DO NOTHING",
                &[&TENANT_ID],
            )
            .map_err(setup_failed)?;
        admin
            .execute(
                "INSERT INTO control.users(user_id,state) VALUES($1,'ACTIVE') ON CONFLICT (user_id) DO NOTHING",
                &[&USER_ID],
            )
            .map_err(setup_failed)?;
        admin
            .execute(
                "INSERT INTO control.memberships(tenant_id,user_id,role,state) \
                 VALUES($1,$2,'member','ACTIVE') ON CONFLICT DO NOTHING",
                &[&TENANT_ID, &USER_ID],
            )
            .map_err(setup_failed)?;
        let rt = tokio::runtime::Runtime::new().map_err(setup_failed)?;
        let runtime = rt
            // dep: PostgreSQL(role_gateway) — test opens a direct PG connection for setup/verification
            .block_on(RuntimeDbPool::connect(&gateway_dsn))
            .map_err(setup_failed)?;
        let authorization = AuthorizationScope::new(
            TenantId(TENANT_ID),
            PrincipalId(USER_ID),
            Some(UserId(USER_ID)),
            BoundedSet::<WorkspaceId>::new([]).map_err(setup_failed)?,
        );
        Ok(Handle {
            rt,
            runtime,
            admin,
            gateway,
            authorization,
        })
    }
}

struct Fixture;

fn seed_snapshot(handle: &mut Handle, effective: &str, source_grant_id: Uuid) {
    handle
        .admin
        .execute(
            "INSERT INTO control.entitlement_snapshots(tenant_id,effective,source_grant_ids,computed_at) \
             VALUES($1,$2::text::jsonb,ARRAY[$3]::uuid[],clock_timestamp()) \
             ON CONFLICT (tenant_id) DO UPDATE SET \
               effective=EXCLUDED.effective, source_grant_ids=EXCLUDED.source_grant_ids, \
               computed_at=EXCLUDED.computed_at",
            &[&TENANT_ID, &effective, &source_grant_id],
        )
        .expect("admin seeds projected entitlement snapshot");
}

fn event(tenant_id: TenantId, request_id: &str) -> AuditEvent {
    let mut metadata = AuditMetadata::new();
    metadata
        .insert("role", "member")
        .expect("allowlisted metadata");
    AuditEvent {
        event_id: AuditEventId::new(),
        ts: SystemTime::now(),
        tenant_id,
        actor_type: "user".into(),
        actor_id: USER_ID.to_string(),
        action: "MCP_AUTH_LOGIN".into(),
        resource_type: "request_guard".into(),
        resource_id: "fixture".into(),
        result: "ALLOWED".into(),
        request_id: request_id.into(),
        trace_id: "trace-fixture".into(),
        client_ip: "127.0.0.1".into(),
        user_agent_hash: "fixture-user-agent-hash".into(),
        risk_tags: vec!["fixture".into()],
        before_fingerprint: None,
        after_fingerprint: None,
        metadata,
    }
}

#[test]
#[ignore = "lane(a:request_guard) requires the dedicated request-guard PostgreSQL fixture"]
fn effective_entitlements_are_read_only_from_the_projected_snapshot() {
    run_db_fixture::<Fixture, _>(
        "effective_entitlements_are_read_only_from_the_projected_snapshot",
        |mut handle| {
            let grant_id = Uuid::now_v7();
            seed_snapshot(
                &mut handle,
                r#"{"request:read":{"enabled":true}}"#,
                grant_id,
            );
            let facts = handle
                .rt
                .block_on(request_guard_repo::read_effective_entitlements(
                    &handle.runtime,
                    &handle.authorization,
                ))
                .expect("gateway reads the effective projection");
            assert_eq!(facts.effective["request:read"]["enabled"], true);
            assert_eq!(facts.source_grant_ids, vec![grant_id]);

            handle
                .admin
                .execute(
                    "DELETE FROM control.entitlement_snapshots WHERE tenant_id=$1",
                    &[&TENANT_ID],
                )
                .expect("remove snapshot to prove no default plan");
            assert_eq!(
                handle
                    .rt
                    .block_on(request_guard_repo::read_effective_entitlements(
                        &handle.runtime,
                        &handle.authorization,
                    )),
                Err(ErrorCode::EntitlementRequired)
            );

            seed_snapshot(&mut handle, "[]", grant_id);
            assert_eq!(
                handle
                    .rt
                    .block_on(request_guard_repo::read_effective_entitlements(
                        &handle.runtime,
                        &handle.authorization,
                    )),
                Err(ErrorCode::Internal)
            );
        },
    );
}

fn batch_scopes(admin: &mut Client, tenants: &[Uuid]) -> Vec<AuthorizationScope> {
    admin
        .execute(
            "INSERT INTO control.tenants(tenant_id,name,state) \
             SELECT tenant_id,'chooser batch fixture','ACTIVE' FROM unnest($1::uuid[]) AS t(tenant_id)",
            &[&tenants],
        )
        .expect("seed candidate tenants");
    admin
        .execute(
            "INSERT INTO control.memberships(tenant_id,user_id,role,state) \
             SELECT tenant_id,$2,'member','ACTIVE' FROM unnest($1::uuid[]) AS t(tenant_id)",
            &[&tenants, &USER_ID],
        )
        .expect("seed the session user's candidate memberships");
    tenants
        .iter()
        .map(|tenant| {
            AuthorizationScope::new(
                TenantId(*tenant),
                PrincipalId(USER_ID),
                Some(UserId(USER_ID)),
                BoundedSet::new([]).unwrap(),
            )
        })
        .collect()
}

fn batch_table_state(admin: &mut Client, tenants: &[Uuid]) -> Vec<Option<String>> {
    admin
        .query_one(
            "SELECT ARRAY[
               (SELECT jsonb_agg(to_jsonb(s) ORDER BY to_jsonb(s))::text FROM control.entitlement_snapshots s WHERE tenant_id=ANY($1)),
               (SELECT jsonb_agg(to_jsonb(w) ORDER BY to_jsonb(w))::text FROM control.quota_windows w WHERE tenant_id=ANY($1)),
               (SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r))::text FROM control.usage_reservations r WHERE tenant_id=ANY($1)),
               (SELECT jsonb_agg(to_jsonb(p) ORDER BY to_jsonb(p))::text FROM control.billing_payments p WHERE tenant_id=ANY($1))
             ]",
            &[&tenants],
        )
        .expect("read commercial rows for change detection")
        .get(0)
}

#[test]
#[ignore = "lane(a:request_guard) requires the dedicated request-guard PostgreSQL fixture"]
fn commercial_entitlement_batch_reads_current_policy_without_writes() {
    run_db_fixture::<Fixture, _>(
        "commercial_entitlement_batch_reads_current_policy_without_writes",
        |mut h| {
            let tenants: [Uuid; 5] = std::array::from_fn(|_| Uuid::now_v7());
            let scopes = batch_scopes(&mut h.admin, &tenants);
            h.admin
                .execute(
                    "WITH clock AS (SELECT clock_timestamp() AS at),
                     terms AS (
                       SELECT at, jsonb_build_object('limit',4,'period','subscription_period',
                                'charge_policy','success_only','period_start',at - interval '2 days',
                                'period_end',at + interval '2 days') AS active FROM clock
                     ), policies AS (
                       SELECT at,
                              jsonb_build_object('mcp.billable_operations.per_period', active) AS valid,
                              jsonb_build_object('mcp.billable_operations.per_period',
                                  active || jsonb_build_object('period_end',at - interval '1 day')) AS expired
                       FROM terms
                     )
                     INSERT INTO control.entitlement_snapshots
                         (tenant_id,effective,source_grant_ids,computed_at,successor,successor_from)
                     SELECT v.tenant_id,v.effective,ARRAY[]::uuid[],p.at,v.successor,v.successor_from
                     FROM policies p CROSS JOIN LATERAL (VALUES
                        ($1::uuid,p.valid,NULL::jsonb,NULL::timestamptz),
                        ($2::uuid,p.expired,NULL,NULL),
                        ($3::uuid,p.expired,p.valid,p.at - interval '1 day'),
                        ($4::uuid,p.valid,p.expired,p.at + interval '1 day')
                     ) v(tenant_id,effective,successor,successor_from)",
                    &[&tenants[0], &tenants[2], &tenants[3], &tenants[4]],
                )
                .expect("seed distinct valid, expired and before/after successor projections");

            let before = batch_table_state(&mut h.admin, &tenants);
            let decisions =
                h.rt.block_on(mcp_entitlement_for_tenants(&h.runtime, &scopes))
                    .expect("entitlement absence is an explicit decision in a complete batch");
            assert_eq!(decisions.len(), tenants.len());
            for (tenant, expected) in tenants.iter().zip([
                Enabled,
                EntitlementRequired,
                EntitlementRequired,
                Enabled,
                Enabled,
            ]) {
                assert_eq!(decisions[&TenantId(*tenant)], expected, "tenant {tenant}");
            }
            assert_eq!(batch_table_state(&mut h.admin, &tenants), before);

            h.admin
                .execute(
                    "UPDATE control.entitlement_snapshots SET effective='[]' WHERE tenant_id=$1",
                    &[&tenants[2]],
                )
                .expect("inject malformed projection after the first readable candidates");
            assert_eq!(
                h.rt.block_on(mcp_entitlement_for_tenants(&h.runtime, &scopes)),
                Err(ErrorCode::Internal),
            );
        },
    );
}

#[test]
#[ignore = "lane(a:disposable) takes an exclusive lock on the entitlement projection"]
fn commercial_entitlement_batch_rejects_dependency_timeout() {
    run_db_fixture::<Fixture, _>(
        "commercial_entitlement_batch_rejects_dependency_timeout",
        |mut h| {
            let tenants: [Uuid; 2] = std::array::from_fn(|_| Uuid::now_v7());
            let scopes = batch_scopes(&mut h.admin, &tenants);
            let dsn = std::env::var("HUMAUX_GATEWAY_PG_DSN").expect("fixture gateway DSN");
            let mut settings = load_pool_settings(Some("1")).expect("test pool settings");
            settings.statement_timeout = Duration::from_secs(1);
            // dep: PostgreSQL(role_gateway) — fixture-only statement timeout for the blocked read.
            let runtime =
                h.rt.block_on(RuntimeDbPool::connect_with(&dsn, &settings))
                    .expect("connect timed gateway pool");

            let mut lock = h.admin.transaction().expect("isolated fault transaction");
            lock.batch_execute("LOCK TABLE control.entitlement_snapshots IN ACCESS EXCLUSIVE MODE")
                .expect("hold projection lock until the gateway times out");
            assert_eq!(
                h.rt.block_on(mcp_entitlement_for_tenants(&runtime, &scopes)),
                Err(ErrorCode::DependencyUnavailable),
            );
        },
    );
}

#[test]
#[ignore = "lane(a:request_guard) requires the dedicated request-guard PostgreSQL fixture"]
fn gateway_audit_writer_requires_bound_force_rls_scope() {
    run_db_fixture::<Fixture, _>(
        "gateway_audit_writer_requires_bound_force_rls_scope",
        |mut handle| {
            let request_id = format!("guard-audit-{}", Uuid::now_v7());
            let audit = event(TenantId(TENANT_ID), &request_id);
            let stored = handle
                .rt
                .block_on(record_independent_audit(
                    &PostgresIndependentAudit::new(&handle.runtime),
                    AuditIdentity::Authorized {
                        tenant_id: handle.authorization.tenant_id(),
                        user_id: handle.authorization.user_id(),
                    },
                    &audit,
                ))
                .expect("gateway function writes after matching tenant GUC");
            assert_eq!(stored, audit.event_id);
            let metadata: String = handle
                .admin
                .query_one(
                    "SELECT metadata::text FROM control.audit_events WHERE audit_event_id=$1",
                    &[&stored.0],
                )
                .expect("admin observes audit row")
                .get(0);
            assert!(metadata.contains("role"));

            let denied = handle.gateway.query_one(
            "SELECT control.audit_event_insert( \
               $1,clock_timestamp(),$2,'user','fixture','MCP_AUTH_LOGIN','request_guard', \
               'fixture','DENIED',$3,'trace','127.0.0.1'::inet,'hash',ARRAY['fixture'],NULL,NULL,'{}'::jsonb)",
            &[&Uuid::now_v7(), &TENANT_ID, &format!("unguc-{}", Uuid::now_v7())],
        );
            assert_eq!(
                denied
                    .expect_err("SECURITY DEFINER cannot bypass FORCE RLS")
                    .code(),
                Some(&SqlState::INSUFFICIENT_PRIVILEGE)
            );
        },
    );
}

#[test]
#[ignore = "lane(a:request_guard) requires the dedicated request-guard PostgreSQL fixture"]
fn audit_tenant_is_closed_to_authenticated_scope_or_system() {
    run_db_fixture::<Fixture, _>(
        "audit_tenant_is_closed_to_authenticated_scope_or_system",
        |handle| {
            let wrong = event(TenantId(Uuid::now_v7()), "wrong-tenant");
            assert_eq!(
                handle.rt.block_on(record_independent_audit(
                    &PostgresIndependentAudit::new(&handle.runtime),
                    AuditIdentity::Authorized {
                        tenant_id: handle.authorization.tenant_id(),
                        user_id: handle.authorization.user_id(),
                    },
                    &wrong,
                )),
                Err(ErrorCode::TenantBoundary)
            );

            let system = event(SYSTEM_TENANT_ID, &format!("system-{}", Uuid::now_v7()));
            let stored = handle
                .rt
                .block_on(record_independent_audit(
                    &PostgresIndependentAudit::new(&handle.runtime),
                    AuditIdentity::System,
                    &system,
                ))
                .expect("fixed system tenant is valid for unattributable events");
            assert_eq!(stored, system.event_id);
        },
    );
}
