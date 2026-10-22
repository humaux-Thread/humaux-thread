//! `adapters::tests::authority_g59_5` — G-M07-9 / §59.1 G59-5: the four required Authority columns of
//!   `private.memory_records` are enforced by the schema, not only by `Authority::new`.
//! Depends-on: crates=[humaux-domain, humaux-testkit, postgres]; services=[PostgreSQL(any)
//!   w=[control.tenants, private.memory_records]]; env=[HUMAUX_TEST_PG_DSN]; modules=[domain::ids, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [one all-valid INSERT must succeed so each rejection is attributable to the injected value; all seven
//!   INSERTs run inside one transaction that is rolled back, no row survives]
//! Spec: Baseline §59.1 G59-5; §79.2; §80.1
//!
//! Six injections, none optional (§59.1 G59-5: injecting only 1.5 leaves the four NOT NULL columns and the CHECK's
//! lower bound with no sample, so that part would be vacuously true): confidence 1.5 and -0.5 must hit the CHECK
//! (23514), and NULL in `authority_class` / `confidence` / `status` / `asserted_at` must each hit NOT NULL (23502)
//! on exactly that column. Skip contract (§79.2): no DSN / unreachable ⇒ visible SKIP.

use humaux_domain::ids::TenantId;
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::error::SqlState;
use postgres::{Client, NoTls};
use std::time::SystemTime;

struct Handle {
    client: Client,
}

struct Fixture;

impl DbIntegrationFixture for Fixture {
    type Handle = Handle;

    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        let dsn =
            std::env::var("HUMAUX_TEST_PG_DSN").map_err(|_| DbFixtureSkipReason::NoDatabaseUrl)?;
        // dep: PostgreSQL(any) — superuser connection; the transaction is rolled back
        let client = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        Ok(Handle { client })
    }
}

const INSERT: &str = "INSERT INTO private.memory_records \
    (tenant_id, memory_type, content, visibility_class, authority_class, confidence, status, asserted_at) \
    VALUES ($1, 'NOTE', '{}'::jsonb, 'TENANT_SHARED', $2, $3, $4, $5)";

#[test]
fn g59_5_six_injections_are_rejected_by_the_schema() {
    run_db_fixture::<Fixture, _>("g59_5_six_injections", |mut handle| {
        let tenant = TenantId::new().0;
        let mut txn = handle.client.transaction().expect("begin");
        // dep: PostgreSQL(any) — pool/txn query execution
        txn.execute(
            "INSERT INTO control.tenants (tenant_id, name) VALUES ($1, 'g59-5')",
            &[&tenant],
        )
        .expect("seed tenant");
        let now = SystemTime::now();

        // Positive control: the all-valid row is accepted, so every rejection below is caused by its one bad value.
        let mut sp = txn.transaction().expect("savepoint");
        sp.execute(
            INSERT,
            &[
                &tenant,
                &Some("PrivateKnowledge"),
                &Some(0.5f32),
                &Some("active"),
                &Some(now),
            ],
        )
        .expect("G59-5 positive control: a fully valid row must insert");
        sp.rollback().expect("rollback savepoint");

        // (label, class, confidence, status, asserted_at): exactly one bad value per row.
        type Row = (
            &'static str,
            Option<&'static str>,
            Option<f32>,
            Option<&'static str>,
            Option<SystemTime>,
        );
        let ok_c = Some("PrivateKnowledge");
        let ok_f = Some(0.5f32);
        let ok_s = Some("active");
        let ok_t = Some(now);
        let cases: [Row; 6] = [
            ("confidence=1.5", ok_c, Some(1.5), ok_s, ok_t),
            ("confidence=-0.5", ok_c, Some(-0.5), ok_s, ok_t),
            ("authority_class=NULL", None, ok_f, ok_s, ok_t),
            ("confidence=NULL", ok_c, None, ok_s, ok_t),
            ("status=NULL", ok_c, ok_f, None, ok_t),
            ("asserted_at=NULL", ok_c, ok_f, ok_s, None),
        ];
        for (label, class, conf, status, at) in cases {
            let mut sp = txn.transaction().expect("savepoint");
            let err = sp
                .execute(INSERT, &[&tenant, &class, &conf, &status, &at])
                .expect_err(&format!("G59-5 injection {label} must be rejected"));
            let db = err.as_db_error().expect("database error");
            if label.starts_with("confidence=") && !label.ends_with("NULL") {
                assert_eq!(db.code(), &SqlState::CHECK_VIOLATION, "{label}: {db}");
                assert!(
                    db.constraint().is_some_and(|c| c.contains("confidence")),
                    "{label}: CHECK must be the confidence one, got {:?}",
                    db.constraint()
                );
            } else {
                let column = label.split('=').next().unwrap();
                assert_eq!(db.code(), &SqlState::NOT_NULL_VIOLATION, "{label}: {db}");
                assert_eq!(db.column(), Some(column), "{label}: wrong column");
            }
            sp.rollback().expect("rollback savepoint");
        }
        txn.rollback().expect("rollback");
    });
}
