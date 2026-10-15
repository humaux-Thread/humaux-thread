// witness: family=cache_bytes labels=cache
//! `testkit::tests::metrics::cache_bytes` — Metric Witness for `cache_bytes{cache}`
//!   (§80.2 W-side; registry row §41.2 「§51 weighted-bytes publish · 1」).
//! Depends-on: crates=[humaux-telemetry]; services=[]; env=[]; modules=[telemetry::cache]
//! Called-by: []
//! Invariants: [drives the family's one emit (`telemetry::cache::set_cache_bytes`, called by `cache::bounded`) and asserts
//!   the exact value read back and the rendered sample, never mere presence]
//! Spec: Baseline §51; §41.2; §80.2; M12 design §2; ADR-0061 D-A
//!
//! The gauge is seeded at 0 (ADR-0061 D-A), so presence proves nothing: this sets 4096 and asserts it comes back
//! and renders. Compiled and run standalone by `cargo xtask metrics-registry` (`run_witness_probe`).

use humaux_telemetry::cache::{CacheName, cache_bytes, render, set_cache_bytes};

/// A set value is read back exactly and rendered with the §41.2 label key `cache`.
#[test]
fn set_value_is_read_back_and_rendered() {
    set_cache_bytes(CacheName::EmbedQuery, 4096);
    assert_eq!(cache_bytes(CacheName::EmbedQuery), 4096.0, "cache_bytes is the bytes accounted (§41.2)");
    let mut out = String::new();
    render(&mut out);
    assert!(out.contains("# TYPE cache_bytes gauge\n"), "{out}");
    let line = out
        .lines()
        .find(|l| l.starts_with("cache_bytes{cache=\"embed_query\"} "))
        .unwrap_or_else(|| panic!("no embed_query series in {out}"));
    let value: f64 = line.rsplit(' ').next().and_then(|v| v.parse().ok()).expect("a sample value");
    assert_eq!(value, 4096.0, "{line}");
}
