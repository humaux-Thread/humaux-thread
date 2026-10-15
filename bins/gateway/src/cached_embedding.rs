//! `gateway::cached_embedding` — `CachedEmbeddingPort`: the §51 query-embedding cache in front of the ADR-0012
//!   `RetrievalEmbeddingPort` (M12 D2).
//! Depends-on: crates=[async-trait, humaux-application, humaux-cache, humaux-domain, humaux-telemetry, sha2];
//!   services=[]; env=[]; modules=[application::retrieval_embedding_port, cache::bounded, cache::key, domain::error,
//!   telemetry::cache]
//! Called-by: [gateway::bootstrap, tests]
//! Invariants: [the key namespace comes from the trusted `AuthorizationScope` only: tenant + user, or tenant alone for a
//!   service principal with no user (M12 D3); only an `Embedded` whose stamp equals the configured generation stamp is
//!   cached, everything else passes through uncached (M12 D4, G-M12-7); an inner `Err`, `Skipped` or `Unavailable` is
//!   returned unchanged and never cached (§51.3); sizes and TTL come from the config registry (§78.1)]
//! Spec: Baseline §51; §51.3; §67.2; §78.1; ADR-0012; ADR-0076
//!
//! A hit skips the `ops.retrieval_embedding_rpc_calls` registration row, the UDS hop and the provider call. No
//! authorization decision is cached: the value is the vector of the caller's own query bytes, the key is private to
//! the caller's namespace, and the final PostgreSQL gate of `recall.search` still runs on every request.
//!
//! ponytail: the generation stamp is configuration (`HUMAUX_GATEWAY_EMBEDDING_{PROVIDER_ID,MODEL_ID,MODEL_REVISION}`),
//! not the `projection.embedding_fingerprints` row of the label, because `role_gateway` cannot read that table. A
//! stamp that disagrees with the worker makes every call a miss (the safe direction). Upgrade = grant `role_gateway`
//! SELECT on that table and load the label's row at boot.
//! ponytail: a hit skips the worker's gitleaks seal; a query that passed it once is not rescanned until its entry
//! expires, so a scanner rule update reaches cached queries after the TTL or a restart. Upgrade = put the scanner
//! version into the generation stamp.

use std::sync::Arc;

use async_trait::async_trait;
use humaux_application::retrieval_embedding_port::{
    RetrievalEmbeddingInput, RetrievalEmbeddingOutcome, RetrievalEmbeddingPort,
};
use humaux_cache::{BoundedCache, CacheConfig, EmbeddingQueryKey};
use humaux_domain::error::ErrorCode;
use humaux_telemetry::cache::CacheName;
use sha2::{Digest, Sha256};

/// Domain tag of [`GenerationStamp::fingerprint`]; bump it, never reuse it, if the field list changes.
const GENERATION_DOMAIN: &str = "humaux.embed-query-cache.generation.v1";

/// The serving generation the gateway searches (§51 version list): the embedding label plus the model stamp its
/// vectors were made with. Every field comes from the config registry (§78.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationStamp {
    /// `HUMAUX_GATEWAY_EMBEDDING_VERSION`: the label naming the vector space.
    pub embedding_version: String,
    /// Provider id the retrieval worker reports for this generation.
    pub provider_id: String,
    /// Model id the retrieval worker reports for this generation.
    pub model_id: String,
    /// Immutable model revision; never an alias (M12 D4).
    pub model_revision: String,
    /// `HUMAUX_GATEWAY_EMBEDDING_DIMENSION`.
    pub dimension: u32,
}

impl GenerationStamp {
    /// sha256 over the domain tag and every field, each length-prefixed so no two field tuples collide by
    /// concatenation (the `projection::embedding_fingerprint` idiom).
    fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for field in [
            GENERATION_DOMAIN.as_bytes(),
            self.embedding_version.as_bytes(),
            self.provider_id.as_bytes(),
            self.model_id.as_bytes(),
            self.model_revision.as_bytes(),
            &self.dimension.to_be_bytes(),
        ] {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field);
        }
        hasher.finalize().into()
    }

    /// M12 D4 / G-M12-7: a returned stamp is cacheable only when it is exactly this generation's, and the vector has
    /// its length.
    fn matches(
        &self,
        provider_id: &str,
        model_id: &str,
        model_revision: &str,
        dimension: u32,
        len: usize,
    ) -> bool {
        provider_id == self.provider_id
            && model_id == self.model_id
            && model_revision == self.model_revision
            && dimension == self.dimension
            && len == self.dimension as usize
    }
}

/// Decorator over a [`RetrievalEmbeddingPort`] that serves repeated identical queries of one namespace from the
/// in-process [`BoundedCache`] (M12 D2).
pub struct CachedEmbeddingPort {
    inner: Arc<dyn RetrievalEmbeddingPort>,
    cache: BoundedCache<EmbeddingQueryKey, Arc<[f32]>>,
    stamp: GenerationStamp,
    generation_fingerprint: [u8; 32],
}

impl CachedEmbeddingPort {
    /// Wraps `inner`; a disabled or zero-capacity `config` makes this a pass-through that still counts `bypass`.
    pub fn new(
        inner: Arc<dyn RetrievalEmbeddingPort>,
        stamp: GenerationStamp,
        config: CacheConfig,
    ) -> Self {
        Self {
            inner,
            cache: BoundedCache::new(CacheName::EmbedQuery, config),
            generation_fingerprint: stamp.fingerprint(),
            stamp,
        }
    }
}

#[async_trait]
impl RetrievalEmbeddingPort for CachedEmbeddingPort {
    async fn embed_query(
        &self,
        input: RetrievalEmbeddingInput<'_>,
    ) -> Result<RetrievalEmbeddingOutcome, ErrorCode> {
        let scope = input.authorization;
        // §20.0 / M12 D4: the exact bytes the worker embeds, no case or whitespace folding.
        let input_sha256: [u8; 32] = Sha256::digest(input.query.as_bytes()).into();
        // M12 D3: the namespace is read off the trusted scope, never off a caller-supplied field.
        let key = match scope.user_id() {
            Some(user) => EmbeddingQueryKey::for_user(
                scope.tenant_id(),
                user,
                self.generation_fingerprint,
                input.dimension,
                input_sha256,
            ),
            None => EmbeddingQueryKey::for_service_principal(
                scope.tenant_id(),
                self.generation_fingerprint,
                input.dimension,
                input_sha256,
            ),
        };
        let (inner, stamp) = (self.inner.as_ref(), &self.stamp);
        // The `Err` arm carries the inner result unchanged: the cache stores only the `Ok` vector (§51.3).
        let got = self
            .cache
            .get_or_try_compute(key, async move {
                match inner.embed_query(input).await {
                    Ok(RetrievalEmbeddingOutcome::Embedded {
                        vector,
                        provider_id,
                        model_id,
                        model_revision,
                        dimension,
                    }) if stamp.matches(
                        &provider_id,
                        &model_id,
                        &model_revision,
                        dimension,
                        vector.len(),
                    ) =>
                    {
                        Ok(Arc::<[f32]>::from(vector))
                    }
                    other => Err(other),
                }
            })
            .await;
        match got {
            // Only a matching stamp was ever stored, so the configured stamp is the stored one.
            Ok(vector) => Ok(RetrievalEmbeddingOutcome::Embedded {
                vector: vector.to_vec(),
                provider_id: self.stamp.provider_id.clone(),
                model_id: self.stamp.model_id.clone(),
                model_revision: self.stamp.model_revision.clone(),
                dimension: self.stamp.dimension,
            }),
            Err(passthrough) => passthrough,
        }
    }
}
