//! `cache::tests::singleflight` — G-M12-4: identical concurrent misses run one compute (M12 D7).
//! Depends-on: crates=[humaux-domain, humaux-telemetry, tokio]; services=[]; env=[]; modules=[cache::bounded, cache::key, domain::ids, telemetry::cache]
//! Called-by: [cargo-test]
//! Invariants: [32 concurrent identical misses run exactly one compute; a cancelled first waiter strands nobody]
//! Spec: Baseline §51; M12 design §6 D7, §8 G-M12-4

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use humaux_cache::{BoundedCache, CacheConfig, EmbeddingMode, EmbeddingQueryKey};
use humaux_domain::ids::{TenantId, UserId};
use humaux_telemetry::cache::CacheName;

type Cache = BoundedCache<EmbeddingQueryKey, Vec<u8>>;

fn cache() -> Arc<Cache> {
    Arc::new(Cache::new(
        CacheName::EmbedQuery,
        CacheConfig {
            capacity_bytes: 1 << 20,
            per_tenant_bytes: 1 << 20,
            ttl: Duration::from_secs(3600),
            enabled: true,
        },
    ))
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

/// 32 concurrent identical misses: exactly one compute, every caller gets the value.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn thirty_two_identical_misses_compute_once() {
    let cache = cache();
    let computes = Arc::new(AtomicUsize::new(0));
    let k = key();
    let tasks: Vec<_> = (0..32)
        .map(|_| {
            let (cache, computes, k) = (Arc::clone(&cache), Arc::clone(&computes), k.clone());
            tokio::spawn(async move {
                cache
                    .get_or_try_compute::<Infallible, _>(k, async {
                        computes.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        Ok(vec![7_u8; 8])
                    })
                    .await
            })
        })
        .collect();
    for task in tasks {
        assert_eq!(task.await.ok(), Some(Ok(vec![7_u8; 8])));
    }
    assert_eq!(computes.load(Ordering::SeqCst), 1);
}

/// The first waiter is cancelled mid-compute: the 31 others still get the value; exactly one of them takes over
/// the compute, so the total is 2 (the cancelled one plus the takeover).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_first_waiter_strands_nobody() {
    let cache = cache();
    let computes = Arc::new(AtomicUsize::new(0));
    let k = key();
    let first = {
        let (cache, computes, k) = (Arc::clone(&cache), Arc::clone(&computes), k.clone());
        tokio::spawn(async move {
            cache
                .get_or_try_compute::<Infallible, _>(k, async {
                    computes.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<Result<Vec<u8>, Infallible>>().await
                })
                .await
        })
    };
    while computes.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    let others: Vec<_> = (0..31)
        .map(|_| {
            let (cache, computes, k) = (Arc::clone(&cache), Arc::clone(&computes), k.clone());
            tokio::spawn(async move {
                cache
                    .get_or_try_compute::<Infallible, _>(k, async {
                        computes.fetch_add(1, Ordering::SeqCst);
                        Ok(vec![7_u8; 8])
                    })
                    .await
            })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(300)).await;
    first.abort();
    for task in others {
        assert_eq!(task.await.ok(), Some(Ok(vec![7_u8; 8])));
    }
    assert_eq!(computes.load(Ordering::SeqCst), 2);
}
