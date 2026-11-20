//! `cache::tests::support` — shared cache fixture wiring to the production metrics emitters (§41.2).
//! Depends-on: crates=[humaux-telemetry]; services=[]; env=[]; modules=[cache::bounded, telemetry::cache]
//! Called-by: [cache::tests::bounds, cache::tests::embedding_key, cache::tests::failure, cache::tests::isolation, cache::tests::singleflight]
//! Invariants: [metric assertions use the production counters and gauges]
//! Spec: Baseline §41.2; §51

use humaux_cache::bounded::CacheObserver;
use humaux_telemetry::cache::{
    count_cache_eviction, count_cache_request, set_cache_bytes, set_cache_singleflight_waiters,
};

/// Observer for fixtures that exercise the same emitters as gateway.
pub(super) const CACHE_OBSERVER: CacheObserver = CacheObserver {
    request: count_cache_request,
    eviction: count_cache_eviction,
    bytes: set_cache_bytes,
    singleflight_waiters: set_cache_singleflight_waiters,
};
