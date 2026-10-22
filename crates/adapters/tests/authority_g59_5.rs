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
//! on exactly that column. The CHECK branch pins the exact constraint name generated for the unnamed column CHECK
//! at `0004_private_evidence_memory.sql:130`; no case derives its expected object from its label (#175 item 1).
//! Skip contract (§79.2): no DSN / unreachable ⇒ visible SKIP.

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

// The confidence CHECK is declared inline/unnamed at 0004_private_evidence_memory.sql:130, so
// PostgreSQL generates `<table>_<column>_check` for it. Pinning that exact name (not a
// substring) keeps a later CHECK whose name also contains "confidence" from masking a dropped
// bound (#175 item 1).
const CONFIDENCE_CHECK: &str = "memory_records_confidence_check";

/// The schema object a rejection must name — never inferred from the case label.
enum Target {
    Column(&'static str),
    Constraint(&'static str),
}

/// One G59-5 injection: exactly one of the value fields is bad, as before.
struct Injection {
    label: &'static str,
    class: Option<&'static str>,
    confidence: Option<f32>,
    status: Option<&'static str>,
    asserted_at: Option<SystemTime>,
    sqlstate: SqlState,
    target: Target,
}

/// The six injected rows, in the order they run.
fn injections(now: SystemTime) -> [Injection; 6] {
    let ok_c = Some("PrivateKnowledge");
    let ok_f = Some(0.5f32);
    let ok_s = Some("active");
    let ok_t = Some(now);
    [
        Injection {
            label: "confidence=1.5",
            class: ok_c,
            confidence: Some(1.5),
            status: ok_s,
            asserted_at: ok_t,
            sqlstate: SqlState::CHECK_VIOLATION,
            target: Target::Constraint(CONFIDENCE_CHECK),
        },
        Injection {
            label: "confidence=-0.5",
            class: ok_c,
            confidence: Some(-0.5),
            status: ok_s,
            asserted_at: ok_t,
            sqlstate: SqlState::CHECK_VIOLATION,
            target: Target::Constraint(CONFIDENCE_CHECK),
        },
        Injection {
            label: "authority_class=NULL",
            class: None,
            confidence: ok_f,
            status: ok_s,
            asserted_at: ok_t,
            sqlstate: SqlState::NOT_NULL_VIOLATION,
            target: Target::Column("authority_class"),
        },
        Injection {
            label: "confidence=NULL",
            class: ok_c,
            confidence: None,
            status: ok_s,
            asserted_at: ok_t,
            sqlstate: SqlState::NOT_NULL_VIOLATION,
            target: Target::Column("confidence"),
        },
        Injection {
            label: "status=NULL",
            class: ok_c,
            confidence: ok_f,
            status: None,
            asserted_at: ok_t,
            sqlstate: SqlState::NOT_NULL_VIOLATION,
            target: Target::Column("status"),
        },
        Injection {
            label: "asserted_at=NULL",
            class: ok_c,
            confidence: ok_f,
            status: ok_s,
            asserted_at: None,
            sqlstate: SqlState::NOT_NULL_VIOLATION,
            target: Target::Column("asserted_at"),
        },
    ]
}

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

        for case in &injections(now) {
            let mut sp = txn.transaction().expect("savepoint");
            let err = sp
                .execute(
                    INSERT,
                    &[
                        &tenant,
                        &case.class,
                        &case.confidence,
                        &case.status,
                        &case.asserted_at,
                    ],
                )
                .expect_err(&format!("G59-5 injection {} must be rejected", case.label));
            let db = err.as_db_error().expect("database error");
            assert_eq!(db.code(), &case.sqlstate, "{}: {db}", case.label);
            match &case.target {
                Target::Constraint(name) => assert_eq!(
                    db.constraint(),
                    Some(*name),
                    "{}: CHECK must be exactly {name}, got {:?}",
                    case.label,
                    db.constraint()
                ),
                Target::Column(name) => {
                    assert_eq!(db.column(), Some(*name), "{}: wrong column", case.label)
                }
            }
            sp.rollback().expect("rollback savepoint");
        }
        txn.rollback().expect("rollback");
    });
}
