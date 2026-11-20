//! `gateway::route_cache` — provisional credential routes (ADR-0133, M03 D4).
//! Depends-on: crates=[humaux-application, humaux-cache]; services=[]; env=[]; modules=[application::api_key, cache::region]
//! Called-by: [gateway::auth, gateway::bootstrap, gateway::guard, tests]
//! Invariants: [keys cover the full wire credential under a purpose-separated HMAC; cached hints carry no authority]
//! Spec: Baseline §73.5.1; §78.1; ADR-0133

use std::{mem::size_of, time::Duration};

use humaux_application::api_key::{CredentialRouteHint, compute_api_key_hash};
use humaux_cache::BoundedRegion;

/// Opaque route-cache key. It has no secret-bearing display or debug representation.
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub struct RouteCacheKey([u8; 32]);

/// Instance-local credential routing hints. The live identity check remains the authority (§73.5.1).
pub struct CredentialRouteCache {
    key: Vec<u8>,
    region: BoundedRegion<RouteCacheKey, CredentialRouteHint>,
}

impl CredentialRouteCache {
    /// Creates a region with registry-supplied capacity and TTL.
    pub fn new(pepper: &[u8], bytes: u64, ttl: Duration) -> Self {
        Self {
            key: compute_api_key_hash(pepper, "humaux.gateway.credential_route.v1"),
            region: BoundedRegion::new(bytes, ttl, |_, _| {
                (size_of::<RouteCacheKey>() + size_of::<CredentialRouteHint>()) as u32
            }),
        }
    }

    /// Derives the key from the complete parsed wire credential.
    pub fn key(&self, wire: &str) -> RouteCacheKey {
        RouteCacheKey(
            compute_api_key_hash(&self.key, wire)
                .try_into()
                .expect("HMAC-SHA256 returns 32 bytes"),
        )
    }

    /// Returns a provisional route for this credential.
    pub async fn lookup(&self, key: &RouteCacheKey) -> Option<CredentialRouteHint> {
        self.region.get(key).await
    }

    /// Publishes a routing tuple. A later request still verifies the complete credential.
    pub async fn insert(&self, key: RouteCacheKey, hint: CredentialRouteHint) {
        self.region.insert(key, hint).await;
    }

    pub(crate) async fn invalidate(&self, key: &RouteCacheKey) {
        self.region.invalidate(key).await;
    }
}
