//! `adapters::tests::entitlement_projector` — the persisted entitlement projector of migration 0267 against a real
//!   PostgreSQL throwaway database: `recompute` is deterministic and idempotent over a tenant's grants, keeps the period
//!   the renewal door advanced, leaves a grantless tenant alone; onboarding grants a plan version and leaves the snapshot
//!   to the projector; no runtime role reads the raw grants (G-M04-13).
//! Depends-on: crates=[humaux-adapters, humaux-application, humaux-domain, humaux-testkit, postgres, serde_json, tokio,
//!   uuid]; services=[PostgreSQL(owner) w=[control.entitlement_grants, control.entitlement_snapshots, control.tenants]
//!   x=[control.ensure_admission_tier, control.ensure_user, control.entitlement_grants_for_projection,
//!   control.onboard_tenant, control.write_entitlement_snapshot], PostgreSQL(role_maintenance)];
//!   env=[]; modules=[adapters::entitlement_repo, adapters::plan_repo, adapters::postgres,
//!   adapters::tests::support::throwaway_db, application::entitlement, domain::error, domain::ids, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [every test owns its throwaway database humaux_thread_m04_ent_<pid>_<n>, created and migrated by the
//!   fixture and dropped by its Drop even on panic; recompute runs as role_maintenance through entitlement_repo, the
//!   stored rows are read back as the database owner so the assertions judge the table and not the repository's reading
//!   of it; every expected snapshot is the full effective object, never a presence check; no DSN or unreachable DB is a
//!   visible §79.2 skip]
//! Spec: Baseline §76; §71.1; §72.2.1; §78.2; §79.2

use humaux_adapters::entitlement_repo::{self, RecomputeOutcome};
use humaux_adapters::plan_repo;
use humaux_adapters::postgres::MaintenanceDbPool;
use humaux_application::entitlement::GrantSource;
use humaux_domain::error::ErrorCode;
use humaux_domain::ids::TenantId;
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::error::SqlState;
use postgres::{Client, NoTls};
use serde_json::{Value, json};
use uuid::Uuid;

#[path = "support/throwaway_db.rs"]
#[allow(dead_code)]
mod throwaway_db;
use throwaway_db::ThrowawayDb;

const PER_PERIOD: &str = "mcp.billable_operations.per_period";
const EMERGENCY: &str = "mcp.billable_operations.emergency";
const BYOK: &str = "feature.byok";

fn dsn_as_role(admin_dsn: &str, role: &str) -> String {
    let sep = if admin_dsn.contains('?') { '&' } else { '?' };
    format!("{admin_dsn}{sep}options=-c%20role%3D{role}")
}

/// Fields drop in order: the pool and the owner connection close before `_db` drops the database.
struct Handle {
    rt: tokio::runtime::Runtime,
    maintenance: MaintenanceDbPool,
    admin: Client,
    _db: ThrowawayDb,
}

struct ProjectorFixture;

impl DbIntegrationFixture for ProjectorFixture {
    type Handle = Handle;

    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        let setup = |e: String| DbFixtureSkipReason::IsolationSetupFailed(e);
        let db = throwaway_db::create("m04_ent")?;
        let dsn = db.dsn();
        // dep: PostgreSQL(owner) — the fixture's owner connection to this test's throwaway database
        let admin = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        let rt = tokio::runtime::Runtime::new().map_err(|e| setup(e.to_string()))?;
        // dep: PostgreSQL(role_maintenance) — the projector doors' only caller role
        let maintenance = rt
            .block_on(MaintenanceDbPool::connect(&dsn_as_role(
                &dsn,
                "role_maintenance",
            )))
            .map_err(|e| setup(e.to_string()))?;
        Ok(Handle {
            rt,
            maintenance,
            admin,
            _db: db,
        })
    }
}

impl Handle {
    fn tenant(&mut self, name: &str) -> Uuid {
        self.admin
            .query_one(
                "INSERT INTO control.tenants (name, state) VALUES ($1, 'ACTIVE') RETURNING tenant_id",
                &[&name],
            )
            .expect("insert tenant")
            .get(0)
    }

    /// One grant row, written as the owner (the production writer, onboarding, is the owner definer).
    fn grant(&mut self, tenant: Uuid, source: &str, feature: &str, value: &Value, priority: i32) {
        self.admin
            .execute(
                "INSERT INTO control.entitlement_grants (tenant_id, source, feature, value, valid_from, priority) \
                 VALUES ($1, $2, $3, $4, now() - interval '1 minute', $5)",
                &[&tenant, &source, &feature, value, &priority],
            )
            .expect("insert grant");
    }

    fn revoke_all(&mut self, tenant: Uuid, source: &str) {
        self.admin
            .execute(
                "UPDATE control.entitlement_grants SET revoked_at = now() WHERE tenant_id = $1 AND source = $2",
                &[&tenant, &source],
            )
            .expect("revoke grants");
    }

    fn recompute(&self, tenant: Uuid) -> Result<RecomputeOutcome, ErrorCode> {
        self.rt.block_on(entitlement_repo::recompute(
            &self.maintenance,
            TenantId(tenant),
        ))
    }

    fn effective(&mut self, tenant: Uuid) -> Value {
        self.admin
            .query_one(
                "SELECT effective FROM control.entitlement_snapshots WHERE tenant_id = $1",
                &[&tenant],
            )
            .expect("snapshot row")
            .get(0)
    }

    fn computed_at(&mut self, tenant: Uuid) -> String {
        self.admin
            .query_one(
                "SELECT computed_at::text FROM control.entitlement_snapshots WHERE tenant_id = $1",
                &[&tenant],
            )
            .expect("snapshot row")
            .get(0)
    }

    fn source_grant_id_count(&mut self, tenant: Uuid) -> i64 {
        self.admin
            .query_one(
                "SELECT cardinality(source_grant_ids)::bigint FROM control.entitlement_snapshots WHERE tenant_id = $1",
                &[&tenant],
            )
            .expect("snapshot row")
            .get(0)
    }
}

fn plan_policy() -> Value {
    json!({
        "limit": 7, "period": "subscription_period", "charge_policy": "success_only",
        "period_start": "2030-01-01T00:00:00.000Z", "period_end": "2030-02-01T00:00:00.000Z",
    })
}

/// Seeds `plan_versions` (a values-file array) as role_maintenance through the owner door.
fn seed_plans(h: &Handle, plan_versions: &Value) {
    let specs = plan_repo::parse_catalogue(&json!({ "plan_versions": plan_versions }).to_string())
        .expect("the plans parse");
    h.rt.block_on(plan_repo::seed(&h.maintenance, &specs))
        .expect("the plans seed");
}

/// §76: recompute turns grants into exactly the snapshot they say, again and again. A higher-priority ADMIN override
/// wins its feature only while active; revoking it restores the plan's value; a second recompute with nothing changed
/// writes nothing (computed_at stays). Fault: let a revoked grant project, or rewrite the snapshot on every call ⇒ red.
#[test]
fn recompute_is_deterministic_idempotent_and_follows_overrides() {
    run_db_fixture::<ProjectorFixture, _>(
        "recompute_is_deterministic_idempotent_and_follows_overrides",
        |mut h| {
            let tenant = h.tenant("projector one");
            h.grant(tenant, "PLAN", PER_PERIOD, &plan_policy(), 0);
            h.grant(tenant, "PLAN", EMERGENCY, &json!({ "limit": 3 }), 0);
            h.grant(tenant, "PLAN", BYOK, &json!(true), 0);

            assert_eq!(h.recompute(tenant), Ok(RecomputeOutcome::Written));
            let plan_only = json!({
                PER_PERIOD: plan_policy(),
                EMERGENCY: { "limit": 3 },
                BYOK: true,
            });
            assert_eq!(h.effective(tenant), plan_only);
            assert_eq!(h.source_grant_id_count(tenant), 3);

            let stamped = h.computed_at(tenant);
            assert_eq!(h.recompute(tenant), Ok(RecomputeOutcome::Unchanged));
            assert_eq!(h.effective(tenant), plan_only);
            assert_eq!(
                h.computed_at(tenant),
                stamped,
                "an identical recompute writes nothing"
            );

            h.grant(tenant, "ADMIN", EMERGENCY, &json!({ "limit": 99 }), 10);
            assert_eq!(h.recompute(tenant), Ok(RecomputeOutcome::Written));
            assert_eq!(
                h.effective(tenant),
                json!({ PER_PERIOD: plan_policy(), EMERGENCY: { "limit": 99 }, BYOK: true })
            );
            assert_eq!(h.source_grant_id_count(tenant), 3);

            h.revoke_all(tenant, "ADMIN");
            assert_eq!(h.recompute(tenant), Ok(RecomputeOutcome::Written));
            assert_eq!(h.effective(tenant), plan_only);

            h.revoke_all(tenant, "PLAN");
            assert_eq!(h.recompute(tenant), Ok(RecomputeOutcome::Written));
            assert_eq!(h.effective(tenant), json!({}));
            assert_eq!(h.source_grant_id_count(tenant), 0);
        },
    );
}

/// §72.2.1: a recompute never moves a period the renewal door advanced — the stored boundaries win over the grant's —
/// while every other term follows the grants. Fault: take the boundaries from the winning grant ⇒ red (the window
/// would be re-cut over a period already issued).
#[test]
fn recompute_keeps_the_period_the_renewal_advanced() {
    run_db_fixture::<ProjectorFixture, _>(
        "recompute_keeps_the_period_the_renewal_advanced",
        |mut h| {
            let tenant = h.tenant("projector two");
            h.grant(tenant, "PLAN", PER_PERIOD, &plan_policy(), 0);
            assert_eq!(h.recompute(tenant), Ok(RecomputeOutcome::Written));

            // What control.renew_quota_period leaves after promoting the next period.
            h.admin
                .execute(
                    "UPDATE control.entitlement_snapshots \
                        SET effective = jsonb_set(jsonb_set(effective, \
                              ARRAY['mcp.billable_operations.per_period', 'period_start'], '\"2030-03-01T00:00:00.000Z\"'), \
                              ARRAY['mcp.billable_operations.per_period', 'period_end'], '\"2030-04-01T00:00:00.000Z\"') \
                      WHERE tenant_id = $1",
                    &[&tenant],
                )
                .expect("advance the stored period");

            // An override states a new limit and no boundaries at all.
            h.grant(
                tenant,
                "ADMIN",
                PER_PERIOD,
                &json!({ "limit": 9, "period": "subscription_period", "charge_policy": "success_only" }),
                10,
            );
            assert_eq!(h.recompute(tenant), Ok(RecomputeOutcome::Written));
            assert_eq!(
                h.effective(tenant),
                json!({ PER_PERIOD: {
                    "limit": 9, "period": "subscription_period", "charge_policy": "success_only",
                    "period_start": "2030-03-01T00:00:00.000Z", "period_end": "2030-04-01T00:00:00.000Z",
                }})
            );
            assert_eq!(h.recompute(tenant), Ok(RecomputeOutcome::Unchanged));
        },
    );
}

/// A tenant with no grant row at all (onboarded before grants existed) keeps its stored snapshot: NoGrants, never an
/// empty overwrite. Fault: write the empty projection when there are no rows ⇒ red.
#[test]
fn a_tenant_without_grants_keeps_its_snapshot() {
    run_db_fixture::<ProjectorFixture, _>("a_tenant_without_grants_keeps_its_snapshot", |mut h| {
        let tenant = h.tenant("projector legacy");
        h.admin
            .execute(
                "INSERT INTO control.entitlement_snapshots (tenant_id, effective, source_grant_ids) VALUES ($1, $2, '{}')",
                &[&tenant, &json!({ PER_PERIOD: plan_policy() })],
            )
            .expect("legacy snapshot");
        assert_eq!(h.recompute(tenant), Ok(RecomputeOutcome::NoGrants));
        assert_eq!(h.effective(tenant), json!({ PER_PERIOD: plan_policy() }));
    });
}

/// A tenant with no grants writes nothing whether or not it exists, and the nil tenant is refused before any SQL.
/// Fault: drop the nil check ⇒ red.
#[test]
fn recompute_for_an_unknown_tenant_writes_nothing() {
    run_db_fixture::<ProjectorFixture, _>(
        "recompute_for_an_unknown_tenant_writes_nothing",
        |mut h| {
            assert_eq!(h.recompute(Uuid::new_v4()), Ok(RecomputeOutcome::NoGrants));
            assert_eq!(h.recompute(Uuid::nil()), Err(ErrorCode::InvalidInput));
            let snapshots: i64 = h
                .admin
                .query_one("SELECT count(*) FROM control.entitlement_snapshots", &[])
                .expect("count")
                .get(0);
            assert_eq!(snapshots, 0);
        },
    );
}

/// G-M04-13 (§76): no runtime role touches the raw grants, and the two projector doors refuse a caller whose tenant
/// GUC does not name the tenant. Fault: GRANT SELECT on the table to role_gateway ⇒ the gateway read below succeeds ⇒ red
/// (the ACL matrix gate is the structural half, `entitlement_grants_are_owner_only` in maintenance::rls_check).
#[test]
fn no_runtime_role_reads_the_grants_and_the_doors_pin_the_tenant() {
    run_db_fixture::<ProjectorFixture, _>(
        "no_runtime_role_reads_the_grants_and_the_doors_pin_the_tenant",
        |mut h| {
            let tenant = h.tenant("projector acl");
            let other = h.tenant("projector acl other");
            h.grant(tenant, "PLAN", BYOK, &json!(true), 0);
            for role in [
                "role_gateway",
                "role_private_worker",
                "role_consolidation_worker",
                "role_public_worker",
                "role_retrieval_worker",
                "role_batch_issuer",
                "role_admin",
                "role_maintenance",
            ] {
                // dep: PostgreSQL(owner) — SET LOCAL ROLE to each runtime role, rolled back with the transaction
                let mut txn = h.admin.transaction().expect("txn");
                txn.batch_execute(&format!("SET LOCAL ROLE {role}"))
                    .expect("set role");
                let read = txn.query("SELECT count(*) FROM control.entitlement_grants", &[]);
                let error = read.expect_err(role);
                assert_eq!(
                    error.code(),
                    Some(&SqlState::INSUFFICIENT_PRIVILEGE),
                    "{role}: {error}"
                );
            }
            for role in ["role_gateway", "role_private_worker", "role_admin"] {
                // dep: PostgreSQL(owner) — SET LOCAL ROLE to a role without EXECUTE, rolled back with the transaction
                let mut txn = h.admin.transaction().expect("txn");
                txn.batch_execute(&format!("SET LOCAL ROLE {role}"))
                    .expect("set role");
                let error = txn
                    .query(
                        "SELECT * FROM control.entitlement_grants_for_projection($1)",
                        &[&tenant],
                    )
                    .expect_err(role);
                assert_eq!(
                    error.code(),
                    Some(&SqlState::INSUFFICIENT_PRIVILEGE),
                    "{role}: {error}"
                );
            }
            // role_maintenance holds the doors, but only for the tenant its GUC names.
            // dep: PostgreSQL(owner) — SET LOCAL ROLE role_maintenance, rolled back with the transaction
            let mut txn = h.admin.transaction().expect("txn");
            txn.batch_execute("SET LOCAL ROLE role_maintenance")
                .expect("set role");
            txn.execute(
                "SELECT set_config('humaux.tenant_id', $1, true)",
                &[&other.to_string()],
            )
            .expect("guc");
            let error = txn
                .query(
                    "SELECT * FROM control.entitlement_grants_for_projection($1)",
                    &[&tenant],
                )
                .expect_err("a foreign tenant");
            assert_eq!(
                error.code(),
                Some(&SqlState::INSUFFICIENT_PRIVILEGE),
                "{error}"
            );
            drop(txn);
            // dep: PostgreSQL(owner) — SET LOCAL ROLE role_maintenance, rolled back with the transaction
            let mut txn = h.admin.transaction().expect("txn");
            txn.batch_execute("SET LOCAL ROLE role_maintenance")
                .expect("set role");
            txn.execute(
                "SELECT set_config('humaux.tenant_id', $1, true)",
                &[&other.to_string()],
            )
            .expect("guc");
            let error = txn
                .query(
                    "SELECT control.write_entitlement_snapshot($1, $2, '{}', now())",
                    &[&tenant, &json!({})],
                )
                .expect_err("a foreign tenant");
            assert_eq!(
                error.code(),
                Some(&SqlState::INSUFFICIENT_PRIVILEGE),
                "{error}"
            );
        },
    );
}

/// §78.2: the Rust grant sources are exactly the values `control.entitlement_grants.source` accepts. Fault: a variant
/// without its CHECK value (or the reverse) ⇒ red.
#[test]
fn grant_source_enum_matches_the_check() {
    run_db_fixture::<ProjectorFixture, _>("grant_source_enum_matches_the_check", |mut h| {
        let definition: String = h
            .admin
            .query_one(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
                  WHERE conrelid = 'control.entitlement_grants'::regclass AND contype = 'c' \
                    AND pg_get_constraintdef(oid) LIKE '%source%'",
                &[],
            )
            .expect("the source CHECK")
            .get(0);
        let mut in_check: Vec<&str> = definition
            .split('\'')
            .enumerate()
            .filter(|(i, _)| i % 2 == 1)
            .map(|(_, literal)| literal)
            .collect();
        in_check.sort_unstable();
        let mut in_rust: Vec<&str> = GrantSource::ALL.map(GrantSource::as_str).to_vec();
        in_rust.sort_unstable();
        assert_eq!(in_check, in_rust, "{definition}");
    });
}

/// §71.1 / §76: onboarding grants a plan version — one PLAN grant per template key, the per-period one carrying the
/// onboarding period — and writes no snapshot; the projector then stores exactly the plan's terms. A draft, an unknown
/// plan and a plan without a per-period window are refused and leave no tenant behind. Fault: write the snapshot in the
/// door, or grant a draft ⇒ red.
#[test]
fn onboarding_grants_the_plan_and_the_projector_stores_its_terms() {
    run_db_fixture::<ProjectorFixture, _>(
        "onboarding_grants_the_plan_and_the_projector_stores_its_terms",
        |mut h| {
            seed_plans(
                &h,
                &json!([
                    { "plan_key": "t_ok", "version": 1, "price_cents": 0, "currency": "USD", "billing_interval": "month",
                      "lease_block": 4, "published": true, "provider_product_ref": {},
                      "entitlement_template": {
                        PER_PERIOD: { "limit": 5, "period": "subscription_period", "charge_policy": "success_only" },
                        EMERGENCY: { "limit": 2 },
                        BYOK: true } },
                    { "plan_key": "t_draft", "version": 1, "price_cents": 0, "currency": "USD", "billing_interval": "month",
                      "lease_block": 4, "published": false, "provider_product_ref": {},
                      "entitlement_template": {
                        PER_PERIOD: { "limit": 5, "period": "subscription_period", "charge_policy": "success_only" } } },
                    { "plan_key": "t_flat", "version": 1, "price_cents": 0, "currency": "USD", "billing_interval": "month",
                      "lease_block": 4, "published": true, "provider_product_ref": {},
                      "entitlement_template": { EMERGENCY: { "limit": 2 } } },
                ]),
            );
            h.admin
                .batch_execute(
                    "SELECT control.ensure_admission_tier('prov', NULL, NULL, NULL, 10, 10); \
                     SELECT control.ensure_admission_tier('prov', 'reg', NULL, NULL, 10, 10);",
                )
                .expect("deployment tiers");
            let owner: Uuid = h
                .admin
                .query_one(
                    "SELECT user_id FROM control.ensure_user($1, $1)",
                    &[&"owner@example.com"],
                )
                .expect("ensure_user")
                .get(0);
            let onboard = |h: &mut Handle, name: &str, plan: &str| {
                let mut txn = h.admin.transaction().expect("txn");
                let row = txn.query_one(
                    "SELECT tenant_id FROM control.onboard_tenant($1, $2, 'default', 'default', $3, 1, \
                     '2098-12-01T00:00:00Z'::timestamptz, '2099-01-01T00:00:00Z'::timestamptz, 'prov', 'reg', 10, 10, \
                     ARRAY['private_memory','PRIVATE_MEMORY','v1'])",
                    &[&name, &owner, &plan],
                );
                match row {
                    Ok(row) => {
                        let tenant: Uuid = row.get(0);
                        txn.commit().expect("commit");
                        Ok(tenant)
                    }
                    Err(e) => Err(e
                        .as_db_error()
                        .map(|d| (d.code().clone(), d.message().to_owned()))),
                }
            };

            for (name, plan, reason) in [
                ("draft tenant", "t_draft", "plan_version_not_offered"),
                ("unknown tenant", "t_nowhere", "plan_version_not_offered"),
                ("flat tenant", "t_flat", "plan_version_without_period_quota"),
            ] {
                let refused = onboard(&mut h, name, plan).expect_err(plan);
                assert_eq!(
                    refused,
                    Some((
                        SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE,
                        reason.to_owned()
                    ))
                );
            }
            let tenants: i64 = h
                .admin
                .query_one("SELECT count(*) FROM control.tenants", &[])
                .expect("count")
                .get(0);
            assert_eq!(tenants, 0, "a refused onboarding leaves no tenant");

            let tenant = onboard(&mut h, "ok tenant", "t_ok").expect("onboard");
            let grants: Vec<(String, String, Value, i32)> = h
                .admin
                .query(
                    "SELECT source, feature, value, priority FROM control.entitlement_grants \
                      WHERE tenant_id = $1 AND revoked_at IS NULL AND valid_until IS NULL ORDER BY feature",
                    &[&tenant],
                )
                .expect("grants")
                .iter()
                .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
                .collect();
            assert_eq!(
                grants,
                [
                    ("PLAN".to_owned(), BYOK.to_owned(), json!(true), 0),
                    (
                        "PLAN".to_owned(),
                        EMERGENCY.to_owned(),
                        json!({ "limit": 2 }),
                        0
                    ),
                    (
                        "PLAN".to_owned(),
                        PER_PERIOD.to_owned(),
                        json!({
                            "limit": 5, "period": "subscription_period", "charge_policy": "success_only",
                            "period_start": "2098-12-01T00:00:00.000Z", "period_end": "2099-01-01T00:00:00.000Z",
                        }),
                        0
                    ),
                ]
            );
            let snapshots: i64 = h
                .admin
                .query_one(
                    "SELECT count(*) FROM control.entitlement_snapshots WHERE tenant_id = $1",
                    &[&tenant],
                )
                .expect("count")
                .get(0);
            assert_eq!(snapshots, 0, "onboarding writes grants, never the snapshot");

            assert_eq!(h.recompute(tenant), Ok(RecomputeOutcome::Written));
            assert_eq!(
                h.effective(tenant),
                json!({
                    PER_PERIOD: {
                        "limit": 5, "period": "subscription_period", "charge_policy": "success_only",
                        "period_start": "2098-12-01T00:00:00.000Z", "period_end": "2099-01-01T00:00:00.000Z",
                    },
                    EMERGENCY: { "limit": 2 },
                    BYOK: true,
                })
            );
            assert_eq!(h.recompute(tenant), Ok(RecomputeOutcome::Unchanged));
        },
    );
}
