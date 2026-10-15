//! `cache::key` — the cache key and value traits and the query-embedding key.
//! Depends-on: crates=[humaux-domain]; services=[]; env=[]; modules=[domain::ids]
//! Called-by: [cache::bounded, tests]
//! Invariants: [`EmbeddingQueryKey` derives `Hash`/`Eq` over every field, so changing any one field is a different
//!   key (§51, M12 D3/D4); the input hash covers the exact provider bytes with no case or whitespace folding]
//! Spec: Baseline §51; §20.0

use std::hash::{Hash, Hasher};
use std::sync::Arc;

use humaux_domain::ids::{TenantId, UserId};

/// A cache key. `tenant` is the namespace the per-tenant byte cap is charged to (M12 D5).
///
/// Contract (§51, M12 D3): an implementor's `Hash`/`Eq` must cover the tenant returned by `tenant`, so two tenants
/// never share an entry; `key_bytes` should count heap data the key owns.
// ponytail: the contract is per implementor and not enforced by the type system; a key whose Hash/Eq omits the
// tenant still compiles. Upgrade = seal the trait or add a shared contract test every key type must pass.
pub trait CacheKey: Hash + Eq + Send + Sync + 'static {
    /// The tenant this entry is charged to.
    fn tenant(&self) -> TenantId;

    /// Bytes this key adds to an entry's weight. The default is the inline size and ignores heap data, so a key that
    /// owns heap data must override it.
    fn key_bytes(&self) -> usize {
        std::mem::size_of_val(self)
    }
}

/// A cached value; its size is the other half of the entry weight.
pub trait CacheValue: Clone + Send + Sync + 'static {
    /// Heap plus inline bytes this value holds.
    fn value_bytes(&self) -> usize;
}

impl CacheValue for Vec<u8> {
    fn value_bytes(&self) -> usize {
        self.len()
    }
}

impl CacheValue for Arc<[f32]> {
    fn value_bytes(&self) -> usize {
        self.len() * std::mem::size_of::<f32>()
    }
}

/// What the embedded text is for; part of the key because a document and a query vector of the same text differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmbeddingMode {
    /// A retrieval query, after the deterministic query preparation (§20.0).
    Query,
}

/// Key of the query-embedding cache (M12 D3/D4). Covers §51's version list through `generation_fingerprint`
/// (provider, model, revision, dimension, preprocessing of the serving generation) and the exact input hash.
///
/// Fields are private and the only constructors name the principal kind, so a user request cannot be keyed into the
/// tenant-wide (`None`) namespace by passing a missing user id.
#[derive(Debug, Clone)]
pub struct EmbeddingQueryKey {
    tenant_id: TenantId,
    /// `None` only for tenant-scoped service principals.
    user_id: Option<UserId>,
    generation_fingerprint: [u8; 32],
    dimension: u32,
    mode: EmbeddingMode,
    input_sha256: [u8; 32],
}

impl EmbeddingQueryKey {
    /// Key for a query made on behalf of one user: entries are private to `(tenant, user)` (M12 D3).
    pub fn for_user(
        tenant_id: TenantId,
        user_id: UserId,
        generation_fingerprint: [u8; 32],
        dimension: u32,
        input_sha256: [u8; 32],
    ) -> Self {
        Self::new(
            tenant_id,
            Some(user_id),
            generation_fingerprint,
            dimension,
            input_sha256,
        )
    }

    /// Key for a tenant-scoped service principal, which has no user: entries are shared by that tenant's service
    /// principals only, never with a user namespace or another tenant.
    pub fn for_service_principal(
        tenant_id: TenantId,
        generation_fingerprint: [u8; 32],
        dimension: u32,
        input_sha256: [u8; 32],
    ) -> Self {
        Self::new(
            tenant_id,
            None,
            generation_fingerprint,
            dimension,
            input_sha256,
        )
    }

    fn new(
        tenant_id: TenantId,
        user_id: Option<UserId>,
        generation_fingerprint: [u8; 32],
        dimension: u32,
        input_sha256: [u8; 32],
    ) -> Self {
        Self {
            tenant_id,
            user_id,
            generation_fingerprint,
            dimension,
            mode: EmbeddingMode::Query,
            input_sha256,
        }
    }
}

impl CacheKey for EmbeddingQueryKey {
    fn tenant(&self) -> TenantId {
        self.tenant_id
    }
}

impl PartialEq for EmbeddingQueryKey {
    fn eq(&self, o: &Self) -> bool {
        self.tenant_id == o.tenant_id
            && self.user_id == o.user_id
            && self.dimension == o.dimension
            && self.mode == o.mode
            && self.input_sha256 == o.input_sha256
    }
}

impl Eq for EmbeddingQueryKey {}

impl Hash for EmbeddingQueryKey {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.tenant_id.hash(h);
        self.user_id.hash(h);
        self.dimension.hash(h);
        self.mode.hash(h);
        self.input_sha256.hash(h);
    }
}
