//! `cache::tests::failure` — G-M12-3: failure is a miss (§51.3, M12 D7).
//! Depends-on: crates=[humaux-domain, humaux-telemetry, tokio]; services=[]; env=[]; modules=[cache::bounded, cache::key, domain::ids, telemetry::cache]
//! Called-by: [cargo-test]
//! Invariants: [a compute error is returned to its caller, counted as `result=error` and never cached; a disabled or
//!   zero-capacity cache still serves every call]
//! Spec: Baseline §51; §41.2; M12 design §6 D7, §8 G-M12-3

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use humaux_cache::{BoundedCache, CacheConfig, EmbeddingMode, EmbeddingQueryKey};
use humaux_domain::ids::{TenantId, UserId};
use humaux_telemetry::cache::{CacheName, CacheResult, cache_requests_total};

type Cache = BoundedCache<EmbeddingQueryKey, Vec<u8>>;

/// The request counters are process-global and libtest runs these tests on parallel threads: each test holds this
/// lock for its whole body so its deltas are its own.
static COUNTERS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn config(capacity_bytes: u64, enabled: bool) -> CacheConfig {
    CacheConfig {
        capacity_bytes,
        per_tenant_bytes: 1 << 20,
        ttl: Duration::from_secs(3600),
        enabled,
    }
}

fn key() -> EmbeddingQueryKey {
    EmbeddingQueryKey {
        tenant_id: TenantId::new(),
        user_id: Some(UserId::new()),
        generation_fingerprint: [1; 32],
        dimension: 1024,
        mode: EmbeddingMode::Query,
        input_sha256: [2; 32],
    }
}

fn count(result: CacheResult) -> u64 {
    cache_requests_total(CacheName::EmbedQuery, result)
}

/// An `Err` is returned, counted as `error`, not cached: the next call recomputes, and only its `Ok` is cached.
#[tokio::test]
async fn error_is_not_cached_and_next_call_recomputes() {
    let _serial = COUNTERS.lock().await;
    let cache = Cache::new(CacheName::EmbedQuery, config(1 << 20, true));
    let computes = AtomicUsize::new(0);
    let k = key();
    let (errors, misses, hits) = (
        count(CacheResult::Error),
        count(CacheResult::Miss),
        count(CacheResult::Hit),
    );

    let first = cache
        .get_or_try_compute(k.clone(), async {
            computes.fetch_add(1, Ordering::SeqCst);
            Err::<Vec<u8>, &str>("provider unavailable")
        })
        .await;
    assert_eq!(first, Err("provider unavailable"));
    assert_eq!(computes.load(Ordering::SeqCst), 1);
    assert_eq!(count(CacheResult::Error), errors + 1);

    let second = cache
        .get_or_try_compute(k.clone(), async {
            computes.fetch_add(1, Ordering::SeqCst);
            Ok::<_, &str>(vec![5_u8; 8])
        })
        .await;
    assert_eq!(second, Ok(vec![5_u8; 8]));
    assert_eq!(
        computes.load(Ordering::SeqCst),
        2,
        "the error must not have been cached"
    );
    assert_eq!(count(CacheResult::Miss), misses + 1);

    let third = cache
        .get_or_try_compute(k, async {
            computes.fetch_add(1, Ordering::SeqCst);
            Err::<Vec<u8>, &str>("must not run")
        })
        .await;
    assert_eq!(third, Ok(vec![5_u8; 8]));
    assert_eq!(computes.load(Ordering::SeqCst), 2);
    assert_eq!(count(CacheResult::Hit), hits + 1);
}

/// A zero-capacity and a disabled cache serve every call by computing it, counted as `bypass`.
#[tokio::test]
async fn zero_capacity_and_disabled_caches_still_serve() {
    let _serial = COUNTERS.lock().await;
    for (label, cfg) in [
        ("zero capacity", config(0, true)),
        ("disabled", config(1 << 20, false)),
    ] {
        let cache = Cache::new(CacheName::EmbedQuery, cfg);
        let computes = AtomicUsize::new(0);
        let k = key();
        let bypasses = count(CacheResult::Bypass);
        for _ in 0..2 {
            let got = cache
                .get_or_try_compute(k.clone(), async {
                    computes.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, &str>(vec![3_u8; 8])
                })
                .await;
            assert_eq!(got, Ok(vec![3_u8; 8]), "{label}");
        }
        assert_eq!(
            computes.load(Ordering::SeqCst),
            2,
            "{label}: every call computes"
        );
        assert_eq!(count(CacheResult::Bypass), bypasses + 2, "{label}");
    }
}
