//! `xtask::rls_check` — `cargo xtask rls-check`: a thin delegation to `humaux_maintenance::rls_check` (ADR-0066 D-Q).
//! Depends-on: crates=[humaux-maintenance]; services=[]; env=[CARGO_MANIFEST_DIR, HUMAUX_TEST_PG_DSN];
//!   modules=[maintenance::rls_check]
//! Called-by: [xtask::main]
//! Invariants: [the dev behaviour is unchanged: the table-set check reads the source tree's Baseline and the DB checks
//!   run against `HUMAUX_TEST_PG_DSN`; an unset DSN is a `fail` (G80-26 is a must-pass gate), never a pass]
//! Spec: Baseline §48.2; ADR-0066 D-Q

/// The Baseline the table-set derivation reads in the source tree.
const SPEC_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../docs/architecture/Baseline_2.9.md"
);

/// `cargo xtask rls-check`.
pub fn run(args: &[String]) -> i32 {
    let mut forwarded = vec!["--spec".to_owned(), SPEC_PATH.to_owned()];
    match std::env::var("HUMAUX_TEST_PG_DSN") {
        Ok(dsn) if !dsn.is_empty() => forwarded.extend(["--dsn".to_owned(), dsn]),
        _ => {
            eprintln!("rls-check: fail — env var HUMAUX_TEST_PG_DSN not set");
            return 1;
        }
    }
    forwarded.extend_from_slice(args);
    humaux_maintenance::rls_check::run(&forwarded)
}
