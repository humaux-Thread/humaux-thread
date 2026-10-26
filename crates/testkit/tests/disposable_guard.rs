//! `testkit::tests::disposable_guard` — G-M19-11: the throwaway-database guard refuses every non-disposable name.
//! Depends-on: crates=[postgres]; services=[PostgreSQL(any)]; env=[HUMAUX_TEST_PG_DSN]; modules=[humaux-testkit, testkit::disposable]
//! Called-by: [cargo-test]
//! Invariants: [the verdict table is exact: twelve names over the shapes exact, separator-suffixed, empty suffix, word-boundary lookalike, non-prefixed, empty, case-shifted, infix; the live call runs on the database the
//!   test DSN names and, with HUMAUX_REQUIRE_DB set (CI), a missing DSN fails instead of skipping]
//! Spec: module design M19 D11; ADR-0092; §79.2

use humaux_testkit::disposable::{DISPOSABLE_DB_PREFIX, is_disposable, require_disposable};
use humaux_testkit::{ExternalDep, skip_or_fail};
use postgres::{Client, NoTls};

#[test]
fn prefix_is_the_one_ratified_value() {
    assert_eq!(DISPOSABLE_DB_PREFIX, "humaux_thread_ci");
}

#[test]
fn verdict_table_is_exact() {
    let table: [(String, bool); 12] = [
        ("humaux_thread_ci".to_owned(), true),
        ("humaux_thread_ci_local_1".to_owned(), true),
        ("humaux_thread_ci_x".to_owned(), true),
        // An empty suffix after the separator is not a suffix.
        ("humaux_thread_ci_".to_owned(), false),
        // The prefix must end at a word boundary: `_prod` and `2` are other databases, not suffixes of the CI one.
        ("humaux_thread_cinema_prod".to_owned(), false),
        ("humaux_thread_ci2".to_owned(), false),
        ("humaux_thread".to_owned(), false),
        ("humaux_thread_prod".to_owned(), false),
        ("postgres".to_owned(), false),
        (String::new(), false),
        // A case-shifted prefix, derived so no env-shaped literal sits in the source.
        (DISPOSABLE_DB_PREFIX.to_uppercase(), false),
        (format!("old_{DISPOSABLE_DB_PREFIX}"), false),
    ];
    for (name, expected) in table {
        assert_eq!(is_disposable(&name), expected, "verdict for {name:?}");
    }
}

#[test]
fn live_call_on_the_test_database_passes() {
    let Ok(dsn) = std::env::var("HUMAUX_TEST_PG_DSN") else {
        skip_or_fail(
            "live_call_on_the_test_database_passes",
            "HUMAUX_TEST_PG_DSN",
            ExternalDep::Postgres,
        );
        return;
    };
    // dep: PostgreSQL(any) — opens the connection the guard reads current_database() from
    let mut conn = Client::connect(&dsn, NoTls).expect("connect to the test database");
    let name = require_disposable(&mut conn).expect("the CI database is disposable");
    assert!(
        name.starts_with(DISPOSABLE_DB_PREFIX),
        "guard returned {name:?}"
    );
}
