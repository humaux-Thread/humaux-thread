//! `cache::tests::embedding_key` — G-M12-1: the query-embedding key is complete (DOD-059, §51).
//! Depends-on: crates=[humaux-cache, humaux-domain, humaux-telemetry]; services=[]; env=[]; modules=[cache::key, cache::bounded]
//! Called-by: []
//! Invariants: [changing any one key field is a different key and a miss; an identical key is a hit]
//! Spec: Baseline §51; §51.1; M12 design §8 G-M12-1

use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use humaux_cache::{BoundedCache, CacheConfig, EmbeddingMode, EmbeddingQueryKey};
use humaux_domain::ids::{TenantId, UserId};
use humaux_telemetry::cache::CacheName;

type Cache = BoundedCache<EmbeddingQueryKey, Vec<u8>>;

fn config() -> CacheConfig {
    CacheConfig {
        capacity_bytes: 1 << 20,
        per_tenant_bytes: 1 << 20,
        ttl: Duration::from_secs(3600),
        enabled: true,
    }
}

fn base(tenant: TenantId, user: UserId) -> EmbeddingQueryKey {
    EmbeddingQueryKey {
        tenant_id: tenant,
        user_id: Some(user),
        generation_fingerprint: [1; 32],
        dimension: 1024,
        mode: EmbeddingMode::Query,
        input_sha256: [2; 32],
    }
}

async fn lookup(cache: &Cache, computes: &AtomicUsize, key: EmbeddingQueryKey) {
    let got = cache
        .get_or_try_compute::<Infallible, _>(key, async {
            computes.fetch_add(1, Ordering::SeqCst);
            Ok(vec![0_u8; 16])
        })
        .await;
    assert_eq!(got, Ok(vec![0_u8; 16]));
}

/// Each of tenant, user (changed and absent), fingerprint, dimension and input bytes yields a distinct key and a
/// miss; the identical key is a hit. `mode` has one variant today, so it cannot vary here.
#[tokio::test]
async fn every_field_change_is_a_distinct_key_and_a_miss() {
    let (tenant, user) = (TenantId::new(), UserId::new());
    let original = base(tenant, user);
    let mut variants = Vec::new();
    let mut v = original.clone();
    v.tenant_id = TenantId::new();
    variants.push(("tenant_id", v));
    let mut v = original.clone();
    v.user_id = Some(UserId::new());
    variants.push(("user_id changed", v));
    let mut v = original.clone();
    v.user_id = None;
    variants.push(("user_id absent", v));
    let mut v = original.clone();
    v.generation_fingerprint = [9; 32];
    variants.push(("generation_fingerprint", v));
    let mut v = original.clone();
    v.dimension = 768;
    variants.push(("dimension", v));
    let mut v = original.clone();
    v.input_sha256 = [8; 32];
    variants.push(("input_sha256", v));

    let cache = Cache::new(CacheName::EmbedQuery, config());
    let computes = AtomicUsize::new(0);
    lookup(&cache, &computes, original.clone()).await;
    assert_eq!(computes.load(Ordering::SeqCst), 1);
    lookup(&cache, &computes, original.clone()).await;
    assert_eq!(computes.load(Ordering::SeqCst), 1, "identical key must hit");
    for (i, (field, variant)) in variants.into_iter().enumerate() {
        assert_ne!(variant, original, "{field} must be part of key equality");
        lookup(&cache, &computes, variant).await;
        assert_eq!(
            computes.load(Ordering::SeqCst),
            2 + i,
            "changing {field} must miss (§51)"
        );
    }
}
