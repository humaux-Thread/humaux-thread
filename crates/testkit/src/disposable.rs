//! `testkit::disposable` — the throwaway-database guard every destructive test leg calls first (M19 D11, G-M19-11).
//! Depends-on: crates=[postgres]; services=[PostgreSQL(any)]; env=[]; modules=[]
//! Called-by: [tests]
//! Invariants: [a database is disposable only when its name is DISPOSABLE_DB_PREFIX or PREFIX_ plus a non-empty suffix,
//!   compared byte for byte: an empty name, a case-shifted prefix, a prefix in the middle and a word-boundary lookalike are refused; the verdict is read from the
//!   connection itself (current_database()), never from a DSN string or an env var the caller could have mistyped]
//! Spec: module design M19 D11; ADR-0092 (deletion tests on throwaway databases only); §79.2
//!
//! Test infrastructure only: no runtime path calls it. The purge door and the retention executor (later M19 cards) refuse
//! to run a test that did not pass [`require_disposable`] on the connection it is about to use.

use postgres::Client;

// ponytail: one prefix, a list if a second disposable cluster appears
/// CI's database is exactly `humaux_thread_ci`; a local developer names theirs `humaux_thread_ci_*`.
pub const DISPOSABLE_DB_PREFIX: &str = "humaux_thread_ci";

/// Pure verdict on a database name: `true` only for [`DISPOSABLE_DB_PREFIX`] itself or `PREFIX_<non-empty suffix>`; a name
/// that merely starts with the prefix (`humaux_thread_cinema_prod`, `humaux_thread_ci2`) is another database.
pub fn is_disposable(database_name: &str) -> bool {
    let prefix = DISPOSABLE_DB_PREFIX;
    database_name == prefix
        || (database_name.len() > prefix.len() + 1
            && database_name.starts_with(prefix)
            && database_name[prefix.len()..].starts_with('_'))
}

/// Reads `current_database()` on `conn` and returns it when [`is_disposable`] accepts it; otherwise `Err` naming the
/// database so the refusal is visible in the test output. A failed read is also `Err`: an unknown database is not a
/// disposable one.
pub fn require_disposable(conn: &mut Client) -> Result<String, String> {
    // dep: PostgreSQL(any) — reads the name of the database the caller is connected to
    let row = conn
        .query_one("SELECT current_database()::text", &[])
        .map_err(|e| format!("cannot read current_database(): {e}"))?;
    let name: String = row.get(0);
    if is_disposable(&name) {
        Ok(name)
    } else {
        Err(format!(
            "refusing a destructive test leg on database {name:?}: its name does not start with {DISPOSABLE_DB_PREFIX:?} (M19 D11)"
        ))
    }
}
