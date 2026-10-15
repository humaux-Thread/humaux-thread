//! `adapters::tests::support::truncate_probe` — runs a TRUNCATE that an append-only guard must reject without ever
//!   making a concurrent test session the deadlock victim (run 38683479316: 40P01 between test binaries).
//! Depends-on: crates=[postgres]; services=[]; env=[]; modules=[]
//! Called-by: [adapters::tests::disclosure_ledger, adapters::tests::ledger_append_only]
//! Invariants: [one attempt holds its locks for at most PROBE_BUDGET, below PostgreSQL's default deadlock_timeout
//!   (1 s), so a session queued behind the probe never runs deadlock detection; retries change nothing the caller
//!   asserts: the error returned is the first one that is not a lost lock race]
//! Spec: Baseline §79; §7.4; §77; §19.1; §75.2
//!
//! `TRUNCATE … CASCADE` takes ACCESS EXCLUSIVE on the named table, then on every table referencing it — the reverse
//! of an FK insert, which holds the child and then asks for the parent. An advisory lock only orders the sessions
//! that take it; test binaries run in parallel since nextest (PR #33), so a writer elsewhere can close the cycle.

use postgres::Client;
use postgres::error::SqlState;

/// `statement_timeout` for one attempt: it bounds the whole TRUNCATE, every lock wait of the CASCADE included (a
/// per-wait `lock_timeout` would let N children add up past `deadlock_timeout`).
const PROBE_BUDGET: &str = "200ms";

/// Runs `sql` — a TRUNCATE the guard must reject — in a never-committed transaction and returns its error; if the
/// guard regressed and TRUNCATE succeeded, `expect_err` panics and the rollback on drop discards it.
// ponytail: up to 100 attempts × 200 ms of lock contention (each attempt also queues other writers behind its ACCESS
// EXCLUSIVE for as long) before the probe gives up; M24-7a (a database per test binary) removes the concurrent
// writers, and this loop with them.
pub fn truncate_rejection(admin: &mut Client, sql: &str) -> postgres::Error {
    for _ in 0..100 {
        let mut txn = admin.transaction().expect("begin txn");
        txn.batch_execute(&format!("SET LOCAL statement_timeout = '{PROBE_BUDGET}'"))
            .expect("set statement_timeout");
        let err = txn
            .execute(sql, &[])
            .expect_err("TRUNCATE must be rejected by the append-only guard");
        // 40P01 too: with a deadlock_timeout below PROBE_BUDGET the probe can still be the victim; never masks 42501.
        let lost_the_race = err.code() == Some(&SqlState::QUERY_CANCELED)
            || err.code() == Some(&SqlState::T_R_DEADLOCK_DETECTED);
        if !lost_the_race {
            return err;
        }
    }
    panic!("{sql}: lost the lock race to concurrent sessions 100 times in a row");
}
