// witness: family=cache_requests_total labels=cache,result
//! `testkit::tests::metrics::cache_requests_total` — Metric Witness for `cache_requests_total{cache,result}`
//!   (§80.2 W-side; registry row §41.2 「§51 cache lookup return · 1」).
//! Depends-on: crates=[humaux-telemetry]; services=[]; env=[]; modules=[telemetry::cache]
//! Called-by: []
//! Invariants: [drives the family's one emit (`telemetry::cache::count_cache_request`, called by `cache::bounded` once
//!   per lookup) and asserts the exact per-result delta and the rendered label set, never mere presence]
//! Spec: Baseline §51; §51.3; §41.2; §80.2; M12 design §2
//!
//! The encoder seeds every series at 0 (ADR-0061 D-A), so presence proves nothing: this asserts the increment,
//! including `result=error` (§51.3: a cache failure is a counted miss). Compiled and run standalone by
//! `cargo xtask metrics-registry` (`run_witness_probe`).

use humaux_telemetry::cache::{CacheName, CacheResult, cache_requests_total, count_cache_request, render};

/// The counters are process-global and libtest runs these tests on parallel threads; both hold this lock.
static COUNTERS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Each lookup adds exactly 1 to its own result and nothing to the others.
#[test]
fn each_lookup_adds_one_to_its_own_result() {
    let _serial = COUNTERS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for result in CacheResult::ALL {
        let before = CacheResult::ALL.map(|r| cache_requests_total(CacheName::EmbedQuery, r));
        count_cache_request(CacheName::EmbedQuery, result);
        for (i, other) in CacheResult::ALL.into_iter().enumerate() {
            let want = before[i] + u64::from(other == result);
            assert_eq!(
                cache_requests_total(CacheName::EmbedQuery, other),
                want,
                "cache_requests_total{{result={}}} after one {} lookup (§41.2: 1 per lookup)",
                other.as_str(),
                result.as_str()
            );
        }
    }
}

/// The exposition carries the §41.2 label keys `cache`, `result` and a non-zero `error` sample.
#[test]
fn family_renders_cache_and_result_with_samples() {
    let _serial = COUNTERS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    count_cache_request(CacheName::EmbedQuery, CacheResult::Error);
    let mut out = String::new();
    render(&mut out);
    assert!(out.contains("# TYPE cache_requests_total counter\n"), "{out}");
    let line = out
        .lines()
        .find(|l| l.starts_with("cache_requests_total{cache=\"embed_query\",result=\"error\"} "))
        .unwrap_or_else(|| panic!("no error series in {out}"));
    let value: f64 = line.rsplit(' ').next().and_then(|v| v.parse().ok()).expect("a sample value");
    assert!(value >= 1.0, "{line}");
}
