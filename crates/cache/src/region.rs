//! `cache::region` — shared byte-weighted storage and TTL (§67.2, ADR-0133).
//! Depends-on: crates=[moka, tokio]; services=[]; env=[]; modules=[]
//! Called-by: [cache::bounded, gateway::route_cache, tests]
//! Invariants: [settings come from the caller; each instance has its own key space; values carry no authority]
//! Spec: Baseline §51; §67.2; §78.1; ADR-0133

use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use moka::notification::RemovalCause;

/// Weighted process-local storage. The caller owns the key namespace and the meaning of its values.
pub struct BoundedRegion<K, V> {
    pub(crate) cache: Cache<K, V>,
}

impl<K, V> BoundedRegion<K, V>
where
    K: Hash + Eq + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Creates an independent region using a caller-supplied byte weight and expiration.
    pub fn new(
        capacity_bytes: u64,
        ttl: Duration,
        weight: impl Fn(&K, &V) -> u32 + Send + Sync + 'static,
    ) -> Self {
        Self::with_eviction_listener(capacity_bytes, ttl, weight, |_, _, _| {})
    }

    pub(crate) fn with_eviction_listener(
        capacity_bytes: u64,
        ttl: Duration,
        weight: impl Fn(&K, &V) -> u32 + Send + Sync + 'static,
        eviction: impl Fn(Arc<K>, V, RemovalCause) + Send + Sync + 'static,
    ) -> Self {
        let cache = Cache::builder()
            .max_capacity(capacity_bytes)
            .weigher(weight)
            .time_to_live(ttl)
            .eviction_listener(eviction)
            .build();
        Self { cache }
    }

    /// Looks up a key in this instance.
    pub async fn get(&self, key: &K) -> Option<V> {
        self.cache.get(key).await
    }

    /// Publishes or replaces a hint after the caller has checked its current facts.
    pub async fn insert(&self, key: K, value: V) {
        self.cache.insert(key, value).await;
    }

    /// Removes the current hint for a key.
    pub async fn invalidate(&self, key: &K) {
        self.cache.invalidate(key).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn instances_are_isolated_and_hints_can_be_invalidated() {
        let a = BoundedRegion::new(64, Duration::from_secs(30), |_, _| 32);
        let b = BoundedRegion::new(64, Duration::from_secs(30), |_, _| 32);
        let key = [7_u8; 32];
        a.insert(key, 1).await;
        assert_eq!(a.get(&key).await, Some(1));
        assert_eq!(b.get(&key).await, None);
        b.insert(key, 2).await;
        a.invalidate(&key).await;
        assert_eq!(a.get(&key).await, None);
        assert_eq!(b.get(&key).await, Some(2));
    }
}
