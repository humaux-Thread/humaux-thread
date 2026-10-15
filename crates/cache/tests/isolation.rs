//! `cache::tests::isolation` — G-M12-2: identical text in two tenants (or two users) is two entries (M12 D3).
//! Depends-on: crates=[humaux-domain, humaux-telemetry, tokio]; services=[]; env=[]; modules=[cache::bounded, cache::key, domain::ids, telemetry::cache]
//! Called-by: [cargo-test]
//! Invariants: [the privacy namespace (tenant, user) is part of every private key; a value computed for one namespace
//!   is never returned to another]
//! Spec: Baseline §51; M12 design §6 D3, §8 G-M12-2

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

fn key(tenant: TenantId, user: Option<UserId>) -> EmbeddingQueryKey {
    match user {
        Some(user) => EmbeddingQueryKey::for_user(tenant, user, [1; 32], 1024, [2; 32]),
        None => EmbeddingQueryKey::for_service_principal(tenant, [1; 32], 1024, [2; 32]),
    }
}

async fn lookup(cache: &Cache, computes: &AtomicUsize, key: EmbeddingQueryKey, tag: u8) -> Vec<u8> {
    cache
        .get_or_try_compute::<Infallible, _>(key, async {
            computes.fetch_add(1, Ordering::SeqCst);
            Ok(vec![tag; 4])
        })
        .await
        .unwrap_or_default()
}

/// Same text, two tenants: two computations, and each tenant gets its own value back.
#[tokio::test]
async fn same_text_two_tenants_computes_twice() {
    let cache = Cache::new(CacheName::EmbedQuery, config());
    let computes = AtomicUsize::new(0);
    let user = UserId::new();
    let (a, b) = (TenantId::new(), TenantId::new());
    assert_eq!(
        lookup(&cache, &computes, key(a, Some(user)), 1).await,
        vec![1; 4]
    );
    assert_eq!(
        lookup(&cache, &computes, key(b, Some(user)), 2).await,
        vec![2; 4]
    );
    assert_eq!(computes.load(Ordering::SeqCst), 2);
    assert_eq!(
        lookup(&cache, &computes, key(a, Some(user)), 9).await,
        vec![1; 4]
    );
    assert_eq!(
        lookup(&cache, &computes, key(b, Some(user)), 9).await,
        vec![2; 4]
    );
    assert_eq!(computes.load(Ordering::SeqCst), 2);
}

/// Same text, same tenant, two users (and a service principal): three computations.
#[tokio::test]
async fn same_text_two_users_computes_per_user() {
    let cache = Cache::new(CacheName::EmbedQuery, config());
    let computes = AtomicUsize::new(0);
    let tenant = TenantId::new();
    let users = [Some(UserId::new()), Some(UserId::new()), None];
    for (i, user) in users.into_iter().enumerate() {
        let tag = u8::try_from(i).unwrap_or(u8::MAX);
        assert_eq!(
            lookup(&cache, &computes, key(tenant, user), tag).await,
            vec![tag; 4]
        );
    }
    assert_eq!(computes.load(Ordering::SeqCst), 3);
}
