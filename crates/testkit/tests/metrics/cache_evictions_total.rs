// witness: family=cache_evictions_total labels=cache,cause
//! `testkit::tests::metrics::cache_evictions_total` — Metric Witness for `cache_evictions_total{cache,cause}`
//!   (§80.2 W-side; registry row §41.2 「§51 cache entry removal · 1」).
//! Depends-on: crates=[humaux-telemetry]; services=[]; env=[]; modules=[telemetry::cache]
//! Called-by: []
//! Invariants: [drives the family's one emit (`telemetry::cache::count_cache_eviction`, called by `cache::bounded`'s
//!   eviction listener) and asserts the exact per-cause delta and the rendered label set, never mere presence]
//! Spec: Baseline §51; §67.2; §41.2; §80.2; M12 design §2; ADR-0061 D-A
//!
//! The encoder seeds every series at 0 (ADR-0061 D-A), so presence proves nothing: this asserts the increment.
//! Compiled and run standalone by `cargo xtask metrics-registry` (`run_witness_probe`).

use humaux_telemetry::cache::{CacheName, EvictionCause, cache_evictions_total, count_cache_eviction, render};

/// The counters are process-global and libtest runs these tests on parallel threads; both hold this lock.
static COUNTERS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Each removal adds exactly 1 to its own cause and nothing to the others.
#[test]
fn each_removal_adds_one_to_its_own_cause() {
    let _serial = COUNTERS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for cause in EvictionCause::ALL {
        let before = EvictionCause::ALL.map(|c| cache_evictions_total(CacheName::EmbedQuery, c));
        count_cache_eviction(CacheName::EmbedQuery, cause);
        for (i, other) in EvictionCause::ALL.into_iter().enumerate() {
            let want = before[i] + u64::from(other == cause);
            assert_eq!(
                cache_evictions_total(CacheName::EmbedQuery, other),
                want,
                "cache_evictions_total{{cause={}}} after one {} removal (§41.2: 1 per removal)",
                other.as_str(),
                cause.as_str()
            );
        }
    }
}

/// The exposition carries the §41.2 label keys `cache`, `cause` and a non-zero `size` sample.
#[test]
fn family_renders_cache_and_cause_with_samples() {
    let _serial = COUNTERS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    count_cache_eviction(CacheName::EmbedQuery, EvictionCause::Size);
    let mut out = String::new();
    render(&mut out);
    assert!(out.contains("# TYPE cache_evictions_total counter\n"), "{out}");
    let line = out
        .lines()
        .find(|l| l.starts_with("cache_evictions_total{cache=\"embed_query\",cause=\"size\"} "))
        .unwrap_or_else(|| panic!("no size series in {out}"));
    let value: f64 = line.rsplit(' ').next().and_then(|v| v.parse().ok()).expect("a sample value");
    assert!(value >= 1.0, "{line}");
}
