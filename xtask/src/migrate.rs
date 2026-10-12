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
    // The dev default only when the caller gave none: `flag_value` takes the first occurrence, so a default
    // inserted ahead of an explicit `--migrations-dir <dir>` silently applied the repository's full set to the
    // caller's target (PR #2 Codex P2).
    let env_dsn = std::env::var(DSN_ENV).ok();
    if !args.iter().any(|a| a == "--dsn") && env_dsn.as_deref().is_none_or(str::is_empty) {
        eprintln!(
            "migrate: not_applicable (missing object: --dsn or ${DSN_ENV} env var — no target database configured)"
        );
        return 0;
    }
    humaux_maintenance::migrate::run(&forwarded_args(args, env_dsn.as_deref()))
}

/// The arguments [`run`] forwards for `args` (pure, for the test): the dev `--migrations-dir migrations` default
/// only when the caller gave none, `--dsn <dsn>` only when the caller gave none and the env var is set.
pub fn forwarded_args(args: &[String], env_dsn: Option<&str>) -> Vec<String> {
    let mut forwarded = if args.iter().any(|a| a == "--migrations-dir") {
        Vec::new()
    } else {
        vec!["--migrations-dir".to_owned(), "migrations".to_owned()]
    };
    if !args.iter().any(|a| a == "--dsn")
        && let Some(dsn) = env_dsn.filter(|v| !v.is_empty())
    {
        forwarded.extend(["--dsn".to_owned(), dsn.to_owned()]);
    }
    forwarded.extend_from_slice(args);
    forwarded
}

#[cfg(test)]
mod tests {
    use super::forwarded_args;

    /// PR #2 Codex P2: an explicit `--migrations-dir` is honoured (no default ahead of it). Fault: always insert
    /// the default ⇒ red.
    #[test]
    fn explicit_migrations_dir_is_not_shadowed_by_the_default() {
        let own = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            forwarded_args(
                &own(&["--migrations-dir", "/tmp/scratch"]),
                Some("postgres://x")
            ),
            own(&["--dsn", "postgres://x", "--migrations-dir", "/tmp/scratch"])
        );
        assert_eq!(
            forwarded_args(&own(&[]), Some("postgres://x")),
            own(&["--migrations-dir", "migrations", "--dsn", "postgres://x"])
        );
        assert_eq!(
            forwarded_args(&own(&["--dsn", "postgres://y"]), Some("postgres://x")),
            own(&["--migrations-dir", "migrations", "--dsn", "postgres://y"])
        );
    }
}
