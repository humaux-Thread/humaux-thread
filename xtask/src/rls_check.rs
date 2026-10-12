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

/// `cargo xtask rls-check [--spec <path>] [--dsn <url>] …`: the dev defaults (`--spec` = the source tree's Baseline,
/// `--dsn` = `HUMAUX_TEST_PG_DSN`) only when the caller gave none — `flag_value` takes the first occurrence, so a
/// default ahead of an explicit flag shadowed it (PR #2 Codex P2); no DSN from either side is a `fail`.
pub fn run(args: &[String]) -> i32 {
    let env_dsn = std::env::var("HUMAUX_TEST_PG_DSN").ok();
    let Some(forwarded) = forwarded_args(args, env_dsn.as_deref()) else {
        eprintln!("rls-check: fail — no --dsn and env var HUMAUX_TEST_PG_DSN not set");
        return 1;
    };
    humaux_maintenance::rls_check::run(&forwarded)
}

/// The arguments [`run`] forwards (pure, for the test); `None` when neither `--dsn` nor `env_dsn` gives a DSN.
pub fn forwarded_args(args: &[String], env_dsn: Option<&str>) -> Option<Vec<String>> {
    let has = |flag: &str| args.iter().any(|a| a == flag);
    let mut forwarded = Vec::new();
    if !has("--spec") {
        forwarded.extend(["--spec".to_owned(), SPEC_PATH.to_owned()]);
    }
    if !has("--dsn") {
        let dsn = env_dsn.filter(|v| !v.is_empty())?;
        forwarded.extend(["--dsn".to_owned(), dsn.to_owned()]);
    }
    forwarded.extend_from_slice(args);
    Some(forwarded)
}

#[cfg(test)]
mod tests {
    use super::{SPEC_PATH, forwarded_args};

    /// PR #2 Codex P2: explicit `--dsn` / `--spec` are forwarded unshadowed; the defaults fill only the gaps; no DSN
    /// at all is `None` (a fail). Fault: always prepend the defaults ⇒ red.
    #[test]
    fn explicit_flags_are_not_shadowed_by_the_defaults() {
        let own = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            forwarded_args(&own(&["--dsn", "postgres://explicit"]), None),
            Some(own(&["--spec", SPEC_PATH, "--dsn", "postgres://explicit"]))
        );
        assert_eq!(
            forwarded_args(&own(&["--spec", "/tmp/spec.md"]), Some("postgres://env")),
            Some(own(&["--dsn", "postgres://env", "--spec", "/tmp/spec.md"]))
        );
        assert_eq!(forwarded_args(&own(&[]), None), None);
        assert_eq!(forwarded_args(&own(&[]), Some("")), None);
    }
}
