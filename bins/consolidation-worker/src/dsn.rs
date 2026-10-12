//! `consolidation-worker::dsn` — the one place this process resolves its role_consolidation_worker DSN: `HUMAUX_CONSOLIDATION_WORKER_PG_DSN`, with
//!   the pre-card-39 name `CONSOLIDATION_WORKER_PG_DSN` accepted as a deprecated alias for one release (ADR-0066 D-O).
//! Depends-on: crates=[humaux-telemetry]; services=[]; env=[HUMAUX_CONSOLIDATION_WORKER_PG_DSN, alias:CONSOLIDATION_WORKER_PG_DSN];
//!   modules=[humaux-telemetry]
//! Called-by: [consolidation-worker::main]
//! Invariants: [reads no environment itself (the caller passes the lookup); the new name wins; both names set with
//!   different values is a configuration error naming both; neither set names the NEW key]
//! Spec: §78.1; ADR-0066 D-O

/// The canonical key (ADR-0066 D-O).
pub const KEY: &str = "HUMAUX_CONSOLIDATION_WORKER_PG_DSN";
/// The pre-card-39 name, accepted until the release after card 39 with a WARN naming [`KEY`].
pub const DEPRECATED_KEY: &str = "CONSOLIDATION_WORKER_PG_DSN";

/// The DSN plus the deprecation WARN line to print once at boot when only [`DEPRECATED_KEY`] was set.
pub fn resolve(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<(String, Option<String>), String> {
    humaux_telemetry::renamed_key(KEY, lookup(KEY), DEPRECATED_KEY, lookup(DEPRECATED_KEY))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        }
    }

    /// Fault: prefer the old name when both are set ⇒ red.
    #[test]
    fn new_name_wins() {
        let (dsn, warn) = resolve(env(&[
            (KEY, "postgres://n"),
            (DEPRECATED_KEY, "postgres://n"),
        ]))
        .expect("resolved");
        assert_eq!((dsn.as_str(), warn), ("postgres://n", None));
        assert_eq!(
            resolve(env(&[(KEY, "postgres://n")])).map(|r| r.0),
            Ok("postgres://n".into())
        );
    }

    /// Fault: accept the old name silently ⇒ red.
    #[test]
    fn old_name_warns() {
        let (dsn, warn) =
            resolve(env(&[(DEPRECATED_KEY, "postgres://o")])).expect("alias accepted");
        assert_eq!(dsn, "postgres://o");
        let warn = warn.expect("a deprecation WARN");
        assert!(
            warn.starts_with("WARN ") && warn.contains(DEPRECATED_KEY) && warn.contains(KEY),
            "{warn}"
        );
    }

    /// Fault: let either name win silently when they disagree ⇒ red.
    #[test]
    fn both_different_refuse() {
        let error = resolve(env(&[
            (KEY, "postgres://n"),
            (DEPRECATED_KEY, "postgres://o"),
        ]))
        .unwrap_err();
        assert!(
            error.contains(KEY) && error.contains(DEPRECATED_KEY),
            "{error}"
        );
        assert_eq!(
            resolve(env(&[])),
            Err(format!("missing required configuration: {KEY}"))
        );
    }
}
