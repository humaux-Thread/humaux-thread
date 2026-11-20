//! `telemetry::cache` — the four §51 cache families (`cache_requests_total`, `cache_evictions_total`, `cache_bytes`,
//!   `cache_singleflight_waiters`, §41.2) and their closed label sets.
//! Depends-on: crates=[humaux-domain]; services=[]; env=[]; modules=[telemetry::metrics]
//! Called-by: [gateway::bootstrap, gateway::guard, tests]
//! Invariants: [each family has exactly one `.inc(` / `.set(` site (§41.2 R4); `cache`, `result` and `cause` are
//!   closed enums so a tenant id or free text can never become a label (§41.2 R5); a cache fault is counted, never
//!   raised (§51.3)]
//! Spec: Baseline §51; §41.2; §67.2
//!
//! The G80-6 witness drives the emitters used by the gateway's cache observer. The gateway's `/metrics` route
//! calls [`render`] for these families.

pub use humaux_domain::vocab::{CacheName, CacheResult, EvictionCause};

use crate::metrics::{Counters, Gauges, families, write_family};

const N_NAMES: usize = CacheName::ALL.len();
const N_RESULTS: usize = CacheResult::ALL.len();
const N_CAUSES: usize = EvictionCause::ALL.len();

// §41.2 row `cache_requests_total{cache,result}`; one slot per (cache, result).
static CACHE_REQUESTS_TOTAL: Counters<{ N_NAMES * N_RESULTS }> = Counters::new();
// §41.2 row `cache_evictions_total{cache,cause}`; one slot per (cache, cause).
static CACHE_EVICTIONS_TOTAL: Counters<{ N_NAMES * N_CAUSES }> = Counters::new();
// §41.2 row `cache_bytes{cache}`.
static CACHE_BYTES: Gauges<N_NAMES> = Gauges::new();
// §41.2 row `cache_singleflight_waiters{cache}`.
static CACHE_SINGLEFLIGHT_WAITERS: Gauges<N_NAMES> = Gauges::new();

const fn request_slot(cache: CacheName, result: CacheResult) -> usize {
    cache as usize * N_RESULTS + result as usize
}

const fn eviction_slot(cache: CacheName, cause: EvictionCause) -> usize {
    cache as usize * N_CAUSES + cause as usize
}

/// Counts one cache lookup (§41.2: exactly 1 emit site). Public so the witness drives the emit; the one production
/// caller is `cache::bounded`'s lookup return.
pub fn count_cache_request(cache: CacheName, result: CacheResult) {
    // labels: cache,result
    CACHE_REQUESTS_TOTAL.inc(request_slot(cache, result), 1);
}

/// Counts one removed entry (§41.2: exactly 1 emit site); the one production caller is `cache::bounded`'s eviction
/// listener.
pub fn count_cache_eviction(cache: CacheName, cause: EvictionCause) {
    // labels: cache,cause
    CACHE_EVICTIONS_TOTAL.inc(eviction_slot(cache, cause), 1);
}

/// Publishes the bytes currently accounted to `cache` (§41.2: exactly 1 emit site).
pub fn set_cache_bytes(cache: CacheName, bytes: u64) {
    // labels: cache
    CACHE_BYTES.set(cache as usize, bytes as f64);
}

/// Publishes how many callers are inside `cache`'s single-flight section (§41.2: exactly 1 emit site).
pub fn set_cache_singleflight_waiters(cache: CacheName, waiters: u64) {
    // labels: cache
    CACHE_SINGLEFLIGHT_WAITERS.set(cache as usize, waiters as f64);
}

/// This process's `cache_requests_total{cache,result}`.
pub fn cache_requests_total(cache: CacheName, result: CacheResult) -> u64 {
    CACHE_REQUESTS_TOTAL.get(request_slot(cache, result))
}

/// This process's `cache_evictions_total{cache,cause}`.
pub fn cache_evictions_total(cache: CacheName, cause: EvictionCause) -> u64 {
    CACHE_EVICTIONS_TOTAL.get(eviction_slot(cache, cause))
}

/// This process's `cache_bytes{cache}`.
pub fn cache_bytes(cache: CacheName) -> f64 {
    CACHE_BYTES.get(cache as usize)
}

/// This process's `cache_singleflight_waiters{cache}`.
pub fn cache_singleflight_waiters(cache: CacheName) -> f64 {
    CACHE_SINGLEFLIGHT_WAITERS.get(cache as usize)
}

/// Renders the four families seeded over their closed sets (ADR-0061 D-A: every series exists from the first scrape).
pub fn render(out: &mut String) {
    let mut requests: Vec<([&'static str; 2], f64)> = Vec::new();
    let mut evictions: Vec<([&'static str; 2], f64)> = Vec::new();
    for cache in CacheName::ALL {
        for result in CacheResult::ALL {
            requests.push((
                [cache.as_str(), result.as_str()],
                cache_requests_total(cache, result) as f64,
            ));
        }
        for cause in EvictionCause::ALL {
            evictions.push((
                [cache.as_str(), cause.as_str()],
                cache_evictions_total(cache, cause) as f64,
            ));
        }
    }
    let as_samples = |rows: &[([&'static str; 2], f64)]| -> Vec<(Vec<&'static str>, f64)> {
        rows.iter().map(|(v, n)| (v.to_vec(), *n)).collect()
    };
    for (family, rows) in [
        (&families::CACHE_REQUESTS_TOTAL, as_samples(&requests)),
        (&families::CACHE_EVICTIONS_TOTAL, as_samples(&evictions)),
    ] {
        let samples: Vec<(&[&'static str], f64)> =
            rows.iter().map(|(v, n)| (v.as_slice(), *n)).collect();
        write_family(out, family, &samples);
    }
    for (family, read) in [
        (&families::CACHE_BYTES, cache_bytes as fn(CacheName) -> f64),
        (
            &families::CACHE_SINGLEFLIGHT_WAITERS,
            cache_singleflight_waiters,
        ),
    ] {
        let values: Vec<([&'static str; 1], f64)> = CacheName::ALL
            .iter()
            .map(|c| ([c.as_str()], read(*c)))
            .collect();
        let samples: Vec<(&[&'static str], f64)> =
            values.iter().map(|(v, n)| (v.as_slice(), *n)).collect();
        write_family(out, family, &samples);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every family renders with its §41.2 label keys and a counted request lands on its own series.
    #[test]
    fn render_is_seeded_and_counts_per_series() {
        let before = cache_requests_total(CacheName::EmbedQuery, CacheResult::Bypass);
        count_cache_request(CacheName::EmbedQuery, CacheResult::Bypass);
        assert_eq!(
            cache_requests_total(CacheName::EmbedQuery, CacheResult::Bypass),
            before + 1
        );
        let mut out = String::new();
        render(&mut out);
        for family in [
            "cache_requests_total",
            "cache_evictions_total",
            "cache_bytes",
            "cache_singleflight_waiters",
        ] {
            assert!(out.contains(&format!("# TYPE {family} ")), "{out}");
        }
        assert!(
            out.contains("cache_requests_total{cache=\"embed_query\",result=\"hit\"} "),
            "{out}"
        );
        assert!(
            out.contains("cache_evictions_total{cache=\"embed_query\",cause=\"size\"} "),
            "{out}"
        );
    }
}
