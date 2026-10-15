//! `cache::tests::bounds` — G-M12-5: the byte bound and the per-tenant cap (M12 D5).
//! Depends-on: crates=[humaux-cache, humaux-domain, humaux-telemetry]; services=[]; env=[]; modules=[cache::bounded, cache::key, telemetry::cache]
//! Called-by: []
//! Invariants: [the weighted size never exceeds `capacity_bytes` and equals the bytes of the surviving entries; a
//!   tenant at its cap is bypassed and evicts nobody else's entries]
//! Spec: Baseline §51; §67.2; M12 design §6 D5, §8 G-M12-5

use std::time::Duration;

use humaux_cache::{BoundedCache, CacheConfig, CacheKey, EmbeddingMode, EmbeddingQueryKey};
use humaux_domain::ids::{TenantId, UserId};
use humaux_telemetry::cache::{CacheName, CacheResult, cache_requests_total};

type Cache = BoundedCache<EmbeddingQueryKey, Vec<u8>>;

const VALUE_LEN: usize = 200;

/// The request counters are process-global; each test holds this lock for its whole body.
static COUNTERS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn key(tenant: TenantId, user: UserId, n: u64) -> EmbeddingQueryKey {
    let mut input = [0_u8; 32];
    input[..8].copy_from_slice(&n.to_le_bytes());
    EmbeddingQueryKey {
        tenant_id: tenant,
        user_id: Some(user),
        generation_fingerprint: [1; 32],
        dimension: 1024,
        mode: EmbeddingMode::Query,
        input_sha256: input,
    }
}

fn entry_weight(k: &EmbeddingQueryKey) -> u64 {
    (k.key_bytes() + VALUE_LEN) as u64
}

fn config(capacity_bytes: u64, per_tenant_bytes: u64) -> CacheConfig {
    CacheConfig {
        capacity_bytes,
        per_tenant_bytes,
        ttl: Duration::from_secs(3600),
        enabled: true,
    }
}

async fn insert(cache: &Cache, k: EmbeddingQueryKey) {
    let got = cache
        .get_or_try_compute::<(), _>(k, async { Ok(vec![0_u8; VALUE_LEN]) })
        .await;
    assert_eq!(got, Ok(vec![0_u8; VALUE_LEN]));
}

/// True when `k` is served from the cache; a miss errors out instead of inserting, so probing changes nothing.
async fn is_cached(cache: &Cache, k: EmbeddingQueryKey) -> bool {
    cache
        .get_or_try_compute(k, async { Err::<Vec<u8>, ()>(()) })
        .await
        .is_ok()
}

/// After inserting twice the capacity in bytes, the weighted size is within capacity and equals the bytes of the
/// entries that actually survive (so the weigher counts bytes, not entries).
#[tokio::test]
async fn weighted_size_stays_within_capacity() {
    let _serial = COUNTERS.lock().await;
    let (tenant, user) = (TenantId::new(), UserId::new());
    let weight = entry_weight(&key(tenant, user, 0));
    let capacity = 50 * weight;
    let cache = Cache::new(CacheName::EmbedQuery, config(capacity, u64::MAX / 2));
    for n in 0..100 {
        insert(&cache, key(tenant, user, n)).await;
    }
    let size = cache.weighted_size().await;
    assert!(
        size <= capacity,
        "weighted size {size} exceeds capacity {capacity}"
    );
    let mut survivors = 0_u64;
    for n in 0..100 {
        if is_cached(&cache, key(tenant, user, n)).await {
            survivors += 1;
        }
    }
    assert_eq!(cache.weighted_size().await, survivors * weight);
    assert!(
        survivors > 0 && survivors * weight <= capacity,
        "{survivors} survivors"
    );
}

/// A tenant at its byte cap is bypassed; another tenant's entries stay intact.
#[tokio::test]
async fn tenant_over_cap_is_bypassed_and_others_stay_intact() {
    let _serial = COUNTERS.lock().await;
    let (greedy, polite) = (TenantId::new(), TenantId::new());
    let (u_greedy, u_polite) = (UserId::new(), UserId::new());
    let weight = entry_weight(&key(greedy, u_greedy, 0));
    let cache = Cache::new(CacheName::EmbedQuery, config(1000 * weight, 3 * weight));
    for n in 0..2 {
        insert(&cache, key(polite, u_polite, n)).await;
    }
    let bypasses = cache_requests_total(CacheName::EmbedQuery, CacheResult::Bypass);
    for n in 0..5 {
        insert(&cache, key(greedy, u_greedy, n)).await;
    }
    assert_eq!(
        cache_requests_total(CacheName::EmbedQuery, CacheResult::Bypass),
        bypasses + 2,
        "5 inserts against a 3-entry cap bypass 2"
    );
    assert_eq!(
        cache.weighted_size().await,
        5 * weight,
        "3 greedy + 2 polite entries"
    );
    for n in 0..2 {
        assert!(
            is_cached(&cache, key(polite, u_polite, n)).await,
            "polite entry {n}"
        );
    }
    for n in 0..3 {
        assert!(
            is_cached(&cache, key(greedy, u_greedy, n)).await,
            "greedy entry {n} within cap"
        );
    }
    for n in 3..5 {
        assert!(
            !is_cached(&cache, key(greedy, u_greedy, n)).await,
            "greedy entry {n} over cap"
        );
    }
}
