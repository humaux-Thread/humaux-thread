//! `adapters::tests::cost_repo` — M04-15 real PostgreSQL refusal, margin and ACL contracts.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, sqlx, tokio]; services=[PostgreSQL(owner) w=[control.tenants, control.billing_payments] r=[ops.tenant_cost_events, ops.tenant_margin_v], PostgreSQL(role_private_worker), PostgreSQL(role_migration_owner)]; env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::cost_repo, adapters::tests::support::throwaway_db, domain::error, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [each DB test owns a migrated throwaway database; missing DSN fails; exact rows and all runtime ACLs]
//! Spec: Baseline §19; §76; §78.2; §79.2; M04 D11, D13(b)

#[path = "support/throwaway_db.rs"]
mod throwaway_db;

use humaux_adapters::cost_repo::{self, CostEvent, CostKind};
use humaux_domain::error::ErrorCode;
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use sqlx::{
    Connection, PgConnection, Row,
    types::{Uuid, time::Date},
};

struct Fixture;
impl DbIntegrationFixture for Fixture {
    type Handle = throwaway_db::ThrowawayDb;
    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        std::env::var("HUMAUX_TEST_PG_DSN").expect("fail: HUMAUX_TEST_PG_DSN is required");
        throwaway_db::create("m04_cost")
    }
}

fn event(tenant_id: Uuid, cost: f64, period: Option<Date>) -> CostEvent {
    CostEvent {
        tenant_id,
        cost_kind: CostKind::WorkerComputeUnits,
        quantity: 1.0,
        unit: "unit".into(),
        estimated_unit_cost: Some(cost),
        estimated_cost: cost,
        source: "M04-15 fixture".into(),
        period,
    }
}

async fn tenant(conn: &mut PgConnection) -> Uuid {
    sqlx::query_scalar("INSERT INTO control.tenants (name) VALUES ('e2e-cost') RETURNING tenant_id")
        .fetch_one(conn)
        .await
        .unwrap()
}

#[test]
fn cost_kind_contract() {
    assert_eq!(
        CostKind::ALL.map(CostKind::as_str),
        [
            "storage byte-hours",
            "artifact GB-month",
            "vector points / vector storage",
            "DB rows/storage class",
            "network egress",
            "parser pages",
            "worker compute units",
            "email sends",
            "external model tokens",
        ]
    );
}

#[test]
fn g_m04_15a_missing_period_refused() {
    run_db_fixture::<Fixture, _>("G-M04-15a", |db| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // dep: PostgreSQL(owner) — connection to this test's migrated throwaway database
            let mut conn = PgConnection::connect(&db.dsn()).await.unwrap();
            let tenant = tenant(&mut conn).await;
            // dep: PostgreSQL(owner) — transaction in the isolated database
            let mut txn = conn.begin().await.unwrap();
            // dep: PostgreSQL(role_private_worker) — exercise the producer role
            sqlx::query("SET LOCAL ROLE role_private_worker").execute(&mut *txn).await.unwrap();
            assert_eq!(cost_repo::record_in_txn(&mut txn, event(tenant, 1.0, None)).await,
                Err(ErrorCode::InvalidInput), "G-M04-15a: missing period refusal");
            sqlx::query("RESET ROLE").execute(&mut *txn).await.unwrap();
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM ops.tenant_cost_events WHERE tenant_id=$1")
                .bind(tenant).fetch_one(&mut *txn).await.unwrap();
            assert_eq!(count, 0, "G-M04-15a: refusal writes zero rows and leaves transaction usable");
            txn.rollback().await.unwrap();
            let default: Option<String> = sqlx::query_scalar("SELECT column_default FROM information_schema.columns \
                WHERE table_schema='ops' AND table_name='tenant_cost_events' AND column_name='period'")
                .fetch_one(&mut conn).await.unwrap();
            assert_eq!(default, None, "0294 must remove the implicit current-month period");
        });
    });
}

async fn seed_payments(conn: &mut PgConnection, tenant: Uuid) {
    for (kind, cents, start) in [
        ("CHARGE", 1000_i64, "2026-10-01T00:00:00Z"),
        ("REFUND", 300, "2026-10-02T00:00:00Z"),
        ("CHARGEBACK", 200, "2026-11-01T00:30:00+01:00"),
        ("CHARGE", 100, "2026-11-01T00:00:00Z"),
    ] {
        sqlx::query("INSERT INTO control.billing_payments \
            (tenant_id, provider, provider_txn_ref, kind, amount_cents, currency, period_start, period_end, occurred_at) \
            VALUES ($1, 'creem', $2, $3, $4, 'USD', $5::text::timestamptz, \
            $5::text::timestamptz + interval '1 month', now())")
            .bind(tenant).bind(format!("{tenant}-{kind}-{start}")).bind(kind).bind(cents)
            .bind(start).execute(&mut *conn).await.unwrap();
    }
}

async fn margin_rows(conn: &mut PgConnection, tenant: Uuid) -> Vec<(String, i64, f64, f64)> {
    // dep: PostgreSQL(owner) — read transaction in the isolated database
    let mut txn = conn.begin().await.unwrap();
    // dep: PostgreSQL(role_migration_owner) — FORCE RLS owner execution
    // §76: the consumer role is not granted SELECT; judge owner execution under FORCE RLS.
    sqlx::query("SET LOCAL ROLE role_migration_owner")
        .execute(&mut *txn)
        .await
        .unwrap();
    sqlx::query("SET LOCAL TIME ZONE 'Pacific/Honolulu'")
        .execute(&mut *txn)
        .await
        .unwrap();
    sqlx::query("SELECT set_config('humaux.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *txn)
        .await
        .unwrap();
    let rows = sqlx::query(
        "SELECT tenant_id, period::text, revenue_cents, cost_usd::float8, margin_usd::float8 \
        FROM ops.tenant_margin_v ORDER BY period",
    )
    .fetch_all(&mut *txn)
    .await
    .unwrap();
    let values = rows
        .into_iter()
        .map(|row| {
            assert_eq!(
                row.get::<Uuid, _>(0),
                tenant,
                "FORCE RLS must exclude the other tenant"
            );
            (row.get(1), row.get(2), row.get(3), row.get(4))
        })
        .collect();
    txn.rollback().await.unwrap();
    values
}

#[test]
fn g_m04_15b_view_sums_and_privileges() {
    run_db_fixture::<Fixture, _>("G-M04-15b", |db| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // dep: PostgreSQL(owner) — connection to this test's migrated throwaway database
            let mut conn = PgConnection::connect(&db.dsn()).await.unwrap();
            let a = tenant(&mut conn).await;
            let b = tenant(&mut conn).await;
            seed_payments(&mut conn, a).await;
            let month = Date::from_ordinal_date(2026, 274).unwrap(); // October 1 fixture
            // dep: PostgreSQL(owner) — transaction in the isolated database
            let mut txn = conn.begin().await.unwrap();
            // dep: PostgreSQL(role_private_worker) — exercise the producer role
            sqlx::query("SET LOCAL ROLE role_private_worker")
                .execute(&mut *txn)
                .await
                .unwrap();
            for (tenant, cost) in [(a, 0.50), (a, 0.25), (b, 1.00)] {
                cost_repo::record_in_txn(&mut txn, event(tenant, cost, Some(month)))
                    .await
                    .unwrap();
            }
            txn.commit().await.unwrap();
            let rows = margin_rows(&mut conn, a).await;
            assert_eq!(rows.len(), 2);
            assert_eq!(
                rows,
                [
                    ("2026-10-01".into(), 500, 0.75, 4.25),
                    ("2026-11-01".into(), 100, 0.0, 1.0)
                ],
                "G-M04-15b: refund and chargeback subtract"
            );
            let rows = margin_rows(&mut conn, b).await;
            assert_eq!(rows.len(), 1);
            assert_eq!(rows, [("2026-10-01".into(), 0, 1.0, -1.0)]);
            for role in [
                "role_gateway",
                "role_private_worker",
                "role_consolidation_worker",
                "role_public_worker",
                "role_retrieval_worker",
                "role_batch_issuer",
                "role_admin",
                "role_maintenance",
                "role_health_reader",
            ] {
                let held: bool = sqlx::query_scalar(
                    "SELECT has_table_privilege($1, 'ops.tenant_margin_v', 'SELECT')",
                )
                .bind(role)
                .fetch_one(&mut conn)
                .await
                .unwrap();
                assert!(!held, "§76: {role} must hold no SELECT");
            }
            let public_grants: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_class c, \
                LATERAL aclexplode(c.relacl) a WHERE c.oid='ops.tenant_margin_v'::regclass AND a.grantee=0")
                .fetch_one(&mut conn).await.unwrap();
            assert_eq!(public_grants, 0, "§76: no PUBLIC privileges");
        });
    });
}
