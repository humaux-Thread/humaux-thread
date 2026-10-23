//! `adapters::tests::auth_contract` — G-M02-16 (§78.2): the Rust enums behind `control.email_challenges.purpose` and
//!   `control.auth_events.event_type` equal their CHECK lists exactly, both directions, as sets.
//! Depends-on: crates=[humaux-application, humaux-testkit, postgres]; services=[PostgreSQL(any) r=[control.auth_events,
//!   control.email_challenges]]; env=[HUMAUX_TEST_PG_DSN]; modules=[application::auth, application::login, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [each comparison is a set equality plus an exact count on both sides, so neither a missing value, an extra
//!   value nor a duplicate passes; the migration-text tests always run, the catalog tests read the live constraint and a
//!   missing database is a visible §79.2 skip, a FAIL under HUMAUX_REQUIRE_DB]
//! Spec: Baseline §78.2; §79.2

use std::collections::BTreeSet;

use humaux_application::auth::AuthEventType;
use humaux_application::login::ChallengePurpose;
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};

const LOGIN_MIGRATION: &str = include_str!("../../../migrations/0266_login_challenge.sql");

/// Every single-quoted literal in `text`, in order.
fn quoted_literals(text: &str) -> Vec<String> {
    text.split('\'')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

/// The literal list of the first `CHECK (<column> IN (...))` clause of the 0266 text.
fn migration_check_list(column: &str) -> Vec<String> {
    let needle = format!("CHECK ({column} IN (");
    let start = LOGIN_MIGRATION
        .find(&needle)
        .unwrap_or_else(|| panic!("0266 has no `{needle}...` clause"))
        + needle.len();
    let end = start
        + LOGIN_MIGRATION[start..]
            .find(')')
            .expect("unterminated CHECK IN (...) clause");
    quoted_literals(&LOGIN_MIGRATION[start..end])
}

fn rust_purposes() -> Vec<String> {
    ChallengePurpose::ALL
        .iter()
        .map(|p| p.as_db_str().to_owned())
        .collect()
}

fn rust_events() -> Vec<String> {
    AuthEventType::ALL
        .iter()
        .map(|e| e.as_db_str().to_owned())
        .collect()
}

/// Asserts `rust` and `db` are the same set and that neither side repeats a value.
fn assert_same_set(what: &str, rust: &[String], db: &[String], expected_len: usize) {
    let rust_set: BTreeSet<&String> = rust.iter().collect();
    let db_set: BTreeSet<&String> = db.iter().collect();
    assert_eq!(rust.len(), expected_len, "{what}: Rust variant count");
    assert_eq!(db.len(), expected_len, "{what}: CHECK list length");
    assert_eq!(rust_set.len(), expected_len, "{what}: Rust duplicates");
    assert_eq!(db_set.len(), expected_len, "{what}: CHECK duplicates");
    assert_eq!(rust_set, db_set, "{what}: Rust enum set != CHECK list set");
}

#[test]
fn g_m02_16_purpose_enum_equals_the_check_list_in_the_migration() {
    assert_same_set(
        "purpose",
        &rust_purposes(),
        &migration_check_list("purpose"),
        2,
    );
}

#[test]
fn g_m02_16_auth_event_enum_equals_the_check_list_in_the_migration() {
    assert_same_set(
        "auth_event",
        &rust_events(),
        &migration_check_list("event_type"),
        11,
    );
}

struct CatalogFixture;

impl DbIntegrationFixture for CatalogFixture {
    type Handle = Client;

    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        let dsn =
            std::env::var("HUMAUX_TEST_PG_DSN").map_err(|_| DbFixtureSkipReason::NoDatabaseUrl)?;
        // dep: PostgreSQL(any) — the shared test database, read-only
        Client::connect(&dsn, NoTls).map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))
    }
}

/// The literals of the one CHECK on `table` whose definition starts with `CHECK ((<column> `.
fn catalog_check_list(client: &mut Client, table: &str, column: &str) -> Vec<String> {
    let prefix = format!("CHECK (({column} %");
    let rows = client
        .query(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
              WHERE conrelid = to_regclass($1) AND contype = 'c' \
                AND pg_get_constraintdef(oid) LIKE $2",
            &[&table, &prefix],
        )
        .expect("read the CHECK constraints");
    assert_eq!(
        rows.len(),
        1,
        "{table}.{column}: exactly one CHECK on the column"
    );
    let def: String = rows[0].get(0);
    // Drops the `::text` casts' own text: only quoted literals are values.
    quoted_literals(&def)
}

#[test]
fn g_m02_16_purpose_enum_equals_the_live_check_list() {
    run_db_fixture::<CatalogFixture, _>(
        "g_m02_16_purpose_enum_equals_the_live_check_list",
        |mut c| {
            let db = catalog_check_list(&mut c, "control.email_challenges", "purpose");
            assert_same_set("purpose (live)", &rust_purposes(), &db, 2);
        },
    );
}

#[test]
fn g_m02_16_auth_event_enum_equals_the_live_check_list() {
    run_db_fixture::<CatalogFixture, _>(
        "g_m02_16_auth_event_enum_equals_the_live_check_list",
        |mut c| {
            let db = catalog_check_list(&mut c, "control.auth_events", "event_type");
            assert_same_set("auth_event (live)", &rust_events(), &db, 11);
        },
    );
}
