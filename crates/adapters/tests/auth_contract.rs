//! `adapters::tests::auth_contract` — G-M02-16 (§78.2): the Rust enums behind `control.email_challenges.purpose`,
//!   `control.auth_events.event_type` and the four closed columns of the OAuth tables (client kind, grant status, grant
//!   revoke reason, refresh-token status) equal their CHECK lists exactly, both directions, as sets.
//! Depends-on: crates=[humaux-adapters, humaux-application, humaux-testkit, postgres]; services=[PostgreSQL(any)
//!   r=[control.auth_events, control.email_challenges, control.oauth_client_registrations, control.oauth_grants,
//!   control.oauth_refresh_tokens]]; env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::oauth_repo, application::auth,
//!   application::login, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [each comparison is a set equality plus an exact count on both sides, so neither a missing value, an extra
//!   value nor a duplicate passes; the migration-text tests always run, the catalog tests read the live constraint and a
//!   missing database is a visible §79.2 skip, a FAIL under HUMAUX_REQUIRE_DB]
//! Spec: Baseline §78.2; §79.2

use std::collections::BTreeSet;

use humaux_adapters::oauth_repo::{ClientKind, GrantStatus, RefreshTokenStatus, RevokeReason};
use humaux_application::auth::AuthEventType;
use humaux_application::login::ChallengePurpose;
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};

const LOGIN_MIGRATION: &str = include_str!("../../../migrations/0266_login_challenge.sql");
const OAUTH_MIGRATION: &str = include_str!("../../../migrations/0268_oauth_persistence.sql");

/// Every single-quoted literal in `text`, in order.
fn quoted_literals(text: &str) -> Vec<String> {
    text.split('\'')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

/// The literal list of the first `CHECK (<column> IN (...))` clause of `text`.
fn check_list_in(text: &str, column: &str) -> Vec<String> {
    let needle = format!("CHECK ({column} IN (");
    let start = text
        .find(&needle)
        .unwrap_or_else(|| panic!("no `{needle}...` clause"))
        + needle.len();
    let end = start
        + text[start..]
            .find(')')
            .expect("unterminated CHECK IN (...) clause");
    quoted_literals(&text[start..end])
}

/// The literal list of the first `CHECK (<column> IN (...))` clause of the 0266 text.
fn migration_check_list(column: &str) -> Vec<String> {
    check_list_in(LOGIN_MIGRATION, column)
}

/// The same for `column` of `CREATE TABLE <table> (...)` in the 0268 text, so two tables may share a column name.
fn oauth_migration_check_list(table: &str, column: &str) -> Vec<String> {
    let header = format!("CREATE TABLE {table} (");
    let start = OAUTH_MIGRATION
        .find(&header)
        .unwrap_or_else(|| panic!("0268 has no `{header}`"));
    let body = &OAUTH_MIGRATION[start..];
    let end = body.find("\n);").expect("unterminated CREATE TABLE");
    check_list_in(&body[..end], column)
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

fn spellings<const N: usize, T: Copy>(all: [T; N], as_db: fn(T) -> &'static str) -> Vec<String> {
    all.iter().map(|v| as_db(*v).to_owned()).collect()
}

/// One closed column of the OAuth tables: its Rust enum's spellings, the table it lives in and the exact variant count.
struct OauthColumn {
    table: &'static str,
    column: &'static str,
    rust: Vec<String>,
    expected_len: usize,
}

/// The four closed columns of migration 0268, one entry per Rust enum.
fn oauth_columns() -> Vec<OauthColumn> {
    vec![
        OauthColumn {
            table: "control.oauth_client_registrations",
            column: "kind",
            rust: spellings(ClientKind::ALL, ClientKind::as_db_str),
            expected_len: 4,
        },
        OauthColumn {
            table: "control.oauth_grants",
            column: "status",
            rust: spellings(GrantStatus::ALL, GrantStatus::as_db_str),
            expected_len: 2,
        },
        OauthColumn {
            table: "control.oauth_grants",
            column: "revoke_reason",
            rust: spellings(RevokeReason::ALL, RevokeReason::as_db_str),
            expected_len: 4,
        },
        OauthColumn {
            table: "control.oauth_refresh_tokens",
            column: "status",
            rust: spellings(RefreshTokenStatus::ALL, RefreshTokenStatus::as_db_str),
            expected_len: 3,
        },
    ]
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

#[test]
fn g_m02_16_oauth_enums_equal_the_check_lists_in_the_migration() {
    let columns = oauth_columns();
    assert_eq!(columns.len(), 4, "one entry per OAuth enum");
    for c in &columns {
        assert_same_set(
            &format!("{}.{}", c.table, c.column),
            &c.rust,
            &oauth_migration_check_list(c.table, c.column),
            c.expected_len,
        );
    }
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

#[test]
fn g_m02_16_oauth_enums_equal_the_live_check_lists() {
    run_db_fixture::<CatalogFixture, _>(
        "g_m02_16_oauth_enums_equal_the_live_check_lists",
        |mut c| {
            let columns = oauth_columns();
            assert_eq!(columns.len(), 4, "one entry per OAuth enum");
            for col in &columns {
                let db = catalog_check_list(&mut c, col.table, col.column);
                assert_same_set(
                    &format!("{}.{} (live)", col.table, col.column),
                    &col.rust,
                    &db,
                    col.expected_len,
                );
            }
        },
    );
}
