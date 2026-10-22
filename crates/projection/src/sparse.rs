//! `projection::sparse` — the local BM25 lane's authorization filter and its policy-skip decision (§17.6 standard path:
//!   the Qdrant cluster's built-in `qdrant/bm25`, processed inside the Data Cell, never an external Managed Retrieval
//!   Provider).
//! Depends-on: crates=[humaux-domain]; services=[]; env=[]; modules=[domain::identity, projection::dense]
//! Called-by: [gateway::recall, tests]
//! Invariants: [the filter an Executed lane carries is `build_dense_filter` with the caller's narrowing — with none it is
//!   tenant + the §6.1.2 visibility disjunction, never wider than the AuthorizationScope; the gateway sends the
//!   unnarrowed one as `params.idf.corpus`, so Qdrant counts document frequencies over the authorized universe only and
//!   other users' private term frequencies never affect ranking (§17.2, ADR-0083 D-A / V5); the policy skip is the one
//!   branch that does not run the lane, and it has no fallback]
//! Spec: Baseline §17.2; §6.1.1; §17.6; §3; §78.3; ADR-0083 D-A; D-E
//!
//! §17.2 freezes: the IDF corpus must not be wider than the AuthorizationScope, or other users' private term
//! frequencies still move the current user's ranking although their rows are filtered out. IDF is computed by Qdrant over
//! the `params.idf.corpus` filter (ADR-0083 D-E: this module no longer computes it); this module only guarantees that
//! the filter comes from [`crate::dense::build_dense_filter`], the same tenant + visibility predicate the dense lane
//! uses, rather than a second hand-written one.
//!
//! §17.6 freezes: when tenant policy forbids even in-Cell text processing, the sparse lane is `SKIPPED_BY_POLICY`; it
//! never falls back to an external provider. [`build_sparse_lane`] returns [`SparseLane::SkippedByPolicy`] straight away
//! when `local_text_processing_allowed` is false, and its body holds no other path.
//!
//! This crate imports no HTTP, serde_json or Qdrant SDK (§3 / §78.3): feeding the query text to `qdrant/bm25` is
//! `adapters::qdrant`'s job.

use crate::dense::{DenseQueryFilter, FieldMatch, build_dense_filter};
use humaux_domain::identity::AuthorizationScope;

/// One sparse-lane construction (§17.6). Not a third error enum next to `ErrorCode` / `DegradeCode`: a lane skipped by
/// policy is neither a terminating error nor a quality degradation, it is a lane that did not run.
#[derive(Debug, Clone, PartialEq)]
pub enum SparseLane {
    /// The lane runs. `filter` is [`build_dense_filter`]'s predicate for `narrow_by` (§17.6: "retrieval filter ->
    /// tenant_id + AuthorizationScope visibility + query filters" is the dense lane's predicate, not a second one).
    /// With empty `narrow_by` it is exactly the §17.2 IDF corpus: tenant + visibility and nothing narrower.
    Executed { filter: DenseQueryFilter },
    /// §17.6: tenant policy does not allow text processing inside the Data Cell, so the lane does not run and nothing
    /// falls back to an external provider.
    SkippedByPolicy,
}

impl SparseLane {
    /// A fixed string for telemetry and logs; not part of the `ErrorCode` / `DegradeCode` registry (see the type).
    pub fn as_str(&self) -> &'static str {
        match self {
            SparseLane::Executed { .. } => "EXECUTED",
            SparseLane::SkippedByPolicy => "SKIPPED_BY_POLICY",
        }
    }
}

/// Builds the local BM25 lane (§17.6). `scope` is a `&AuthorizationScope`, not an `Option`: like
/// [`build_dense_filter`], there is no entry that skips the tenant and visibility injection (§17.1).
///
/// `local_text_processing_allowed == false` returns [`SparseLane::SkippedByPolicy`] without building a filter.
pub fn build_sparse_lane(
    scope: &AuthorizationScope,
    narrow_by: &[FieldMatch],
    local_text_processing_allowed: bool,
) -> SparseLane {
    if !local_text_processing_allowed {
        return SparseLane::SkippedByPolicy;
    }
    SparseLane::Executed {
        filter: build_dense_filter(scope, narrow_by),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use humaux_domain::identity::{BoundedSet, PrincipalId};
    use humaux_domain::ids::{TenantId, WorkspaceId};

    fn scope() -> AuthorizationScope {
        AuthorizationScope::new(
            TenantId::new(),
            PrincipalId::new(),
            None,
            BoundedSet::new(Vec::<WorkspaceId>::new()).unwrap(),
        )
    }

    // ---- §17.6: policy skip has no fallback branch ----

    #[test]
    fn build_sparse_lane_skipped_by_policy_when_local_text_processing_disallowed() {
        let lane = build_sparse_lane(&scope(), &[], false);
        assert_eq!(lane, SparseLane::SkippedByPolicy);
        assert_eq!(lane.as_str(), "SKIPPED_BY_POLICY");
    }

    #[test]
    fn build_sparse_lane_executes_and_reuses_dense_filter_shape() {
        let s = scope();
        let SparseLane::Executed { filter } = build_sparse_lane(&s, &[], true) else {
            panic!("expected Executed");
        };
        // The same predicate build_dense_filter produces directly: tenant + visibility, nothing narrower (§17.2).
        assert_eq!(
            filter.as_condition(),
            build_dense_filter(&s, &[]).as_condition()
        );
    }
}
