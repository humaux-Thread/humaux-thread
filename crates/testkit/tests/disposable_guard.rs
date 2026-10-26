//! `testkit::tests::disposable_guard` — G-M19-11: the throwaway-database guard refuses every non-disposable name.
//! Depends-on: crates=[humaux-testkit, postgres]; services=[PostgreSQL(any)]; env=[HUMAUX_TEST_PG_DSN]; modules=[testkit::disposable]
//! Called-by: [cargo-test]
//! Invariants: [the verdict table is exact: six name shapes, each with its one verdict; the live call runs on the database the
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
    let table: [(&str, bool); 9] = [
        ("humaux_thread_ci", true),
        ("humaux_thread_ci_local_1", true),
        ("humaux_thread_ci_", true),
        ("humaux_thread", false),
        ("humaux_thread_prod", false),
        ("postgres", false),
        ("", false),
        ("HUMAUX_THREAD_CI", false),
        ("old_humaux_thread_ci", false),
    ];
    for (name, expected) in table {
        assert_eq!(is_disposable(name), expected, "verdict for {name:?}");
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
