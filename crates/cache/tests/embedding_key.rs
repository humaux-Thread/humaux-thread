//! `cache::tests::embedding_key` — G-M12-1: the query-embedding key is complete (DOD-059, §51).
//! Depends-on: crates=[humaux-domain, humaux-telemetry, tokio]; services=[]; env=[]; modules=[cache::bounded, cache::key, domain::ids, telemetry::cache]
//! Called-by: [cargo-test]
//! Invariants: [changing any one key field is a different key and a miss; an identical key is a hit]
//! Spec: Baseline §51; M12 design §8 G-M12-1

use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use humaux_cache::{BoundedCache, CacheConfig, EmbeddingQueryKey};
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

/// A user key built from the six inputs, so each test varies exactly one of them.
fn user_key(
    tenant: TenantId,
    user: UserId,
    fp: u8,
    dimension: u32,
    input: u8,
) -> EmbeddingQueryKey {
    EmbeddingQueryKey::for_user(tenant, user, [fp; 32], dimension, [input; 32])
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
    let original = user_key(tenant, user, 1, 1024, 2);
    let variants = vec![
        ("tenant_id", user_key(TenantId::new(), user, 1, 1024, 2)),
        (
            "user_id changed",
            user_key(tenant, UserId::new(), 1, 1024, 2),
        ),
        (
            "user_id absent (service principal)",
            EmbeddingQueryKey::for_service_principal(tenant, [1; 32], 1024, [2; 32]),
        ),
        ("generation_fingerprint", user_key(tenant, user, 9, 1024, 2)),
        ("dimension", user_key(tenant, user, 1, 768, 2)),
        ("input_sha256", user_key(tenant, user, 1, 1024, 8)),
    ];

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
