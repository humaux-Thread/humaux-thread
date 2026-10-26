//! `adapters::tests::core_never_auto` — G-M20-1 leg 2 (ADR-0088 D-A): a tenant created through the core provisioning path has
//!   no AUTO contribution policy.
//! Depends-on: crates=[humaux-adapters, humaux-testkit, postgres, sha2, time, tokio, uuid];
//!   services=[PostgreSQL(any) r=[control.contribution_policies]
//!   x=[control.ensure_admission_tier, control.publish_plan_version],
//!   PostgreSQL(role_maintenance)]; env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::membership_repo, adapters::postgres,
//!   adapters::provisioning, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [the tenant is onboarded by `provisioning::onboard_tenant`, the one production onboarding path; afterwards it
//!   has no policy row and in particular no AUTO row (the DB defaults stay DISABLED/MANUAL, the AUTO default is cloud-only);
//!   a missing database is a visible §79.2 skip, a FAIL under HUMAUX_REQUIRE_DB]
//! Spec: Baseline §12.1.1; §79.2; ADR-0088 D-A

use humaux_adapters::{
    membership_repo::AdminAction,
    postgres::MaintenanceDbPool,
    provisioning::{self, NewApiKey, TenantRequest},
};
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const PROVIDER: &str = "m20prov";
const REGION: &str = "m20reg";

fn dsn_as_role(admin_dsn: &str, role: &str) -> String {
    let sep = if admin_dsn.contains('?') { '&' } else { '?' };
    format!("{admin_dsn}{sep}options=-c%20role%3D{role}")
}

struct Handle {
    rt: tokio::runtime::Runtime,
    maintenance: MaintenanceDbPool,
    admin: Client,
}

struct CoreFixture;

impl DbIntegrationFixture for CoreFixture {
    type Handle = Handle;

    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        let dsn =
            std::env::var("HUMAUX_TEST_PG_DSN").map_err(|_| DbFixtureSkipReason::NoDatabaseUrl)?;
        // dep: PostgreSQL(any) — the setup/inspection connection
        let admin = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        // dep: PostgreSQL(role_maintenance) — the pool the production onboarding path runs on
        let maintenance = rt
            .block_on(MaintenanceDbPool::connect(&dsn_as_role(
                &dsn,
                "role_maintenance",
            )))
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        Ok(Handle {
            rt,
            maintenance,
            admin,
        })
    }
}

/// Publishes a plan version nobody else uses and the two deployment admission tiers, as the owner / `role_maintenance`.
fn seed_plan_and_tiers(admin: &mut Client, plan_key: &str) {
    admin
        .execute(
            "SELECT control.publish_plan_version($1, 1, 0, 'USD', 'month', \
             jsonb_build_object('mcp.billable_operations.per_period', \
               jsonb_build_object('limit', 1000::bigint, 'period', 'subscription_period', \
                                  'charge_policy', 'success_only')), \
             16, '{}'::jsonb, true)",
            &[&plan_key],
        )
        .expect("publish the fixture plan");
    // dep: PostgreSQL(role_maintenance) — the deployment tiers through the 0186 door, as the only role that may call it
    admin
        .batch_execute(&format!(
            "SET ROLE role_maintenance; \
             SELECT control.ensure_admission_tier('{PROVIDER}', NULL, NULL, NULL, 10, 10); \
             SELECT control.ensure_admission_tier('{PROVIDER}', '{REGION}', NULL, NULL, 10, 10); \
             RESET ROLE;"
        ))
        .expect("deployment tiers");
}

/// G-M20-1 leg 2: onboarding a tenant through `provisioning::onboard_tenant` leaves it with no AUTO policy, and no policy row.
#[test]
fn g_m20_1_core_provisioned_tenant_has_no_auto_policy() {
    run_db_fixture::<CoreFixture, _>(
        "g_m20_1_core_provisioned_tenant_has_no_auto_policy",
        |mut h| {
            let suffix = Uuid::new_v4().simple().to_string();
            let plan_key = format!("m20_{}", &suffix[..12]);
            seed_plan_and_tiers(&mut h.admin, &plan_key);
            let name = format!("m20-core-{suffix}");
            let scopes = vec!["memory:write".to_owned(), "context:read".to_owned()];
            let now = OffsetDateTime::now_utc();
            let request = TenantRequest {
                name: &name,
                owner_email: "m20-core-owner@example.com",
                workspace_name: "default",
                reasoning_domain_name: "default",
                plan_key: &plan_key,
                plan_version: 1,
                period_start: now - Duration::seconds(1),
                period_end: now + Duration::days(30),
                provider_id: PROVIDER,
                region: REGION,
                tenant_tpm: 10,
                tenant_rpm: 10,
                scopes: &scopes,
                collection: "m20_core_collection",
            };
            let admin_action = AdminAction {
                actor: "m20-4a-test",
                reason: "G-M20-1 leg 2",
                ticket: "M20-4a",
                trace_id: "m20-4a-trace",
                step_up_auth_context: "test-mfa",
            };
            let mut mint = |tenant: Uuid| NewApiKey {
                prefix: provisioning::api_key_prefix(tenant, "k1"),
                key_hash: Sha256::digest(tenant.as_bytes()).to_vec(),
                fingerprint: "m20-4a-test".to_owned(),
            };
            let receipt =
                h.rt.block_on(provisioning::onboard_tenant(
                    &h.maintenance,
                    &request,
                    &mut mint,
                    &admin_action,
                ))
                .expect("core onboarding");
            let rows: Vec<(String, String)> = h
                .admin
                .query(
                    "SELECT contribution_mode, effective_to IS NULL FROM control.contribution_policies \
                      WHERE tenant_id = $1",
                    &[&receipt.tenant_id],
                )
                .expect("read the tenant's policy rows")
                .iter()
                .map(|row| (row.get(0), row.get::<_, bool>(1).to_string()))
                .collect();
            let auto: i64 = h
                .admin
                .query_one(
                    "SELECT count(*) FROM control.contribution_policies \
                      WHERE tenant_id = $1 AND contribution_mode = 'AUTO_AFTER_USER_DISTILLATION'",
                    &[&receipt.tenant_id],
                )
                .expect("count AUTO rows")
                .get(0);
            assert_eq!(auto, 0, "core onboarding wrote an AUTO policy: {rows:?}");
            assert_eq!(rows, Vec::<(String, String)>::new());
        },
    );
}
