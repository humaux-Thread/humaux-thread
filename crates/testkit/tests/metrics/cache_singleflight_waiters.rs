// witness: family=cache_singleflight_waiters labels=cache
//! `testkit::tests::metrics::cache_singleflight_waiters` — Metric Witness for `cache_singleflight_waiters{cache}`
//!   (§80.2 W-side; registry row §41.2 「§51 single-flight section enter/leave · 1」).
//! Depends-on: crates=[humaux-telemetry]; services=[]; env=[]; modules=[telemetry::cache]
//! Called-by: []
//! Invariants: [drives the family's one emit (`telemetry::cache::set_cache_singleflight_waiters`, called by `cache::bounded`) and asserts
//!   the exact value read back and the rendered sample, never mere presence]
//! Spec: Baseline §51; §41.2; §80.2; M12 design §2; ADR-0061 D-A
//!
//! The gauge is seeded at 0 (ADR-0061 D-A), so presence proves nothing: this sets 7 and asserts it comes back
//! and renders. Compiled and run standalone by `cargo xtask metrics-registry` (`run_witness_probe`).

use humaux_telemetry::cache::{CacheName, cache_singleflight_waiters, render, set_cache_singleflight_waiters};

/// A set value is read back exactly and rendered with the §41.2 label key `cache`.
#[test]
fn set_value_is_read_back_and_rendered() {
    set_cache_singleflight_waiters(CacheName::EmbedQuery, 7);
    assert_eq!(cache_singleflight_waiters(CacheName::EmbedQuery), 7.0, "cache_singleflight_waiters is the callers in the section (§41.2)");
    let mut out = String::new();
    render(&mut out);
    assert!(out.contains("# TYPE cache_singleflight_waiters gauge\n"), "{out}");
    let line = out
        .lines()
        .find(|l| l.starts_with("cache_singleflight_waiters{cache=\"embed_query\"} "))
        .unwrap_or_else(|| panic!("no embed_query series in {out}"));
    let value: f64 = line.rsplit(' ').next().and_then(|v| v.parse().ok()).expect("a sample value");
    assert_eq!(value, 7.0, "{line}");
}
