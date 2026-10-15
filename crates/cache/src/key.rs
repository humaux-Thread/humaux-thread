//! `cache::key` — the cache key and value traits and the query-embedding key.
//! Depends-on: crates=[humaux-domain]; services=[]; env=[]; modules=[domain::ids]
//! Called-by: [cache::bounded, tests]
//! Invariants: [`EmbeddingQueryKey` derives `Hash`/`Eq` over every field, so changing any one field is a different
//!   key (§51, M12 D3/D4); the input hash covers the exact provider bytes with no case or whitespace folding]
//! Spec: Baseline §51; §20.0

use std::hash::Hash;
use std::sync::Arc;

use humaux_domain::ids::{TenantId, UserId};

/// A cache key. `tenant` is the namespace the per-tenant byte cap is charged to (M12 D5).
pub trait CacheKey: Hash + Eq + Send + Sync + 'static {
    /// The tenant this entry is charged to.
    fn tenant(&self) -> TenantId;

    /// Bytes this key adds to an entry's weight.
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EmbeddingQueryKey {
    /// Privacy namespace, part 1: two tenants never share an entry.
    pub tenant_id: TenantId,
    /// Privacy namespace, part 2: `None` only for tenant-scoped service principals.
    pub user_id: Option<UserId>,
    /// Embedding fingerprint of the serving generation being searched.
    pub generation_fingerprint: [u8; 32],
    /// Vector dimension requested.
    pub dimension: u32,
    /// Query or document embedding.
    pub mode: EmbeddingMode,
    /// SHA-256 of the exact bytes sent to the provider.
    pub input_sha256: [u8; 32],
}

impl CacheKey for EmbeddingQueryKey {
    fn tenant(&self) -> TenantId {
        self.tenant_id
    }
}
