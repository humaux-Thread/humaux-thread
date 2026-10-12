//! `xtask::migrate` — `cargo xtask migrate`: a thin delegation to `humaux_maintenance::migrate` (ADR-0066 D-Q).
//! Depends-on: crates=[humaux-maintenance]; services=[]; env=[HUMAUX_TEST_PG_DSN]; modules=[maintenance::migrate]
//! Called-by: [xtask::e2e_onboard, xtask::main, xtask::serial_lane]
//! Invariants: [the dev behaviour is unchanged: the set is read from `migrations/` (cwd-relative), the DSN is `--dsn`
//!   or `HUMAUX_TEST_PG_DSN`, and neither ⇒ `not_applicable` naming the missing object, exit 0 (§57.1)]
//! Spec: Baseline §46; ADR-0066 D-Q
//!
//! The runner, its HXMIGRAT lock, manifest checks, drift detection and the OPS-9 live-session refusal live in
//! `humaux-maintenance migrate`, which a production node runs without a toolchain.

const DSN_ENV: &str = "HUMAUX_TEST_PG_DSN";

/// `cargo xtask migrate [--dsn <url>] [flags of humaux-maintenance migrate]`.
pub fn run(args: &[String]) -> i32 {
    let mut forwarded = vec!["--migrations-dir".to_owned(), "migrations".to_owned()];
    if !args.iter().any(|a| a == "--dsn") {
        let Some(dsn) = std::env::var(DSN_ENV).ok().filter(|v| !v.is_empty()) else {
            eprintln!(
                "migrate: not_applicable (missing object: --dsn or ${DSN_ENV} env var — no target database configured)"
            );
            return 0;
        };
        forwarded.extend(["--dsn".to_owned(), dsn]);
    }
    forwarded.extend_from_slice(args);
    humaux_maintenance::migrate::run(&forwarded)
}
