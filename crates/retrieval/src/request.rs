//! `retrieval::request` — Retrieval request construction (§55.1): one typed path shared by every future lane.
//! Depends-on: crates=[humaux-contracts, humaux-domain, serde]; services=[];
//!   env=[]; modules=[contracts::config_registry, contracts::retrieval_config, domain::authority, domain::selection, retrieval::planner, retrieval::predicate_registry]
//! Called-by: [application::retrieve, gateway::context, gateway::memory, gateway::recall, humaux-local-secret-scan, retrieval-worker::rpc, retrieval::completeness, retrieval::envelope, tests]
//! Invariants: [build_request records which RetrievalIntent constructor ran as a closed IntentKind; nothing else
//!   sets it]
//! Spec: §55.1; §41.2; ADR-0061 D-C

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

use humaux_contracts::retrieval_config::RETRIEVAL_CANDIDATE_CAP;
pub use humaux_contracts::retrieval_config::{
    QueryTransform, RegisteredRetrievalProfile, RetrievalConfigError,
    resolve_registered_retrieval_profile,
};
use humaux_domain::authority::MemoryId;

use crate::planner::{self, PlannerDecision};
use crate::predicate_registry::PredicateEntry;

/// §55.6 / ADR-0083 D-D: `cand_k = min(top_k * cand_multiplier, RETRIEVAL_CANDIDATE_CAP)`. The one place the formula is
/// computed, shared by [`build_request`] and the envelope's §23.3 consistency check so the two cannot drift.
pub(crate) fn candidate_depth(top_k: u32, cand_multiplier: u32) -> u32 {
    top_k
        .saturating_mul(cand_multiplier)
        .min(RETRIEVAL_CANDIDATE_CAP)
}

/// Effective request identity, minted only by build_request. No raw-string or deserialization
/// constructor is exposed, so provenance must reuse an actual request identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ProfileFingerprint(String);

impl ProfileFingerprint {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The existing deterministic planner inputs that a retrieval call actually needs. Query and
/// catalog snapshots are intentionally here; auth, provider choice, and lane I/O stay outside
/// this pure crate.
#[derive(Debug, Clone)]
pub struct RetrievalIntent {
    input: RetrievalInput,
}

/// §41.2 `humaux_retrieval_requests_total.intent`: which [`RetrievalIntent`] constructor built the
/// request. A closed set, one value per `RetrievalInput` variant (ADR-0061 D-C).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IntentKind {
    Text,
    Context,
    DirectGet,
    MemoryEnumerate,
}

impl IntentKind {
    /// Every value, in render order; the label's cardinality bound (ADR-0061 D-A).
    pub(crate) const ALL: [Self; 4] = [
        Self::Text,
        Self::Context,
        Self::DirectGet,
        Self::MemoryEnumerate,
    ];

    /// The `intent` label value.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Context => "context",
            Self::DirectGet => "direct_get",
            Self::MemoryEnumerate => "memory_enumerate",
        }
    }
}

#[derive(Debug, Clone)]
enum RetrievalInput {
    Text {
        query: String,
        predicate_registry: Vec<PredicateEntry>,
        indexed_columns: BTreeSet<String>,
        enumerable_scopes: BTreeSet<String>,
    },
    Context,
    DirectGet {
        memory_id: MemoryId,
    },
    MemoryEnumerate,
}

impl RetrievalIntent {
    pub fn new(
        query: String,
        predicate_registry: Vec<PredicateEntry>,
        indexed_columns: BTreeSet<String>,
        enumerable_scopes: BTreeSet<String>,
    ) -> Result<Self, RequestBuildError> {
        if query.trim().is_empty() {
            return Err(RequestBuildError::EmptyQuery);
        }
        Ok(Self {
            input: RetrievalInput::Text {
                query,
                predicate_registry,
                indexed_columns,
                enumerable_scopes,
            },
        })
    }

    /// Trusted Context operation intent. It has no text query and bypasses keyword planning;
    /// authorization of this operation belongs to the caller, not to a caller-selected class.
    #[must_use]
    pub fn trusted_context() -> Self {
        Self {
            input: RetrievalInput::Context,
        }
    }

    /// Trusted direct-get intent. The typed identifier bypasses text planning; authorization
    /// and visibility checks remain the responsibility of the application caller.
    #[must_use]
    pub fn trusted_memory_get(memory_id: MemoryId) -> Self {
        Self {
            input: RetrievalInput::DirectGet { memory_id },
        }
    }

    /// Trusted authorized enumeration. Pagination limits do not replace the registered
    /// retrieval profile and no fabricated query is sent through keyword planning.
    #[must_use]
    pub fn trusted_memory_enumerate() -> Self {
        Self {
            input: RetrievalInput::MemoryEnumerate,
        }
    }
}

/// The constructed retrieval plan. Fields are private: the sole literal is in
/// [`build_request`], so a production/eval/benchmark/shadow caller cannot drift its pool depth.
/// A text query that exists only because [`build_request`] constructed its request. Its inner
/// request is private: callers cannot manufacture arbitrary raw text for an external provider.
pub struct TrustedRetrievalQuery<'a>(&'a RetrievalRequest);

impl TrustedRetrievalQuery<'_> {
    pub fn text(&self) -> &str {
        self.0.query.as_deref().expect("text-only trusted query")
    }

    /// The effective registered-profile identity minted by [`build_request`]. Query sealing
    /// copies this opaque value into the sealed request so provider provenance cannot accept a
    /// caller-written profile string alongside otherwise genuine sealed bytes.
    pub fn profile_fingerprint_identity(&self) -> &ProfileFingerprint {
        self.0.profile_fingerprint_identity()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetrievalRequest {
    intent: IntentKind,
    query: Option<String>,
    planner_decision: PlannerDecision,
    query_transform: QueryTransform,
    profile_id: String,
    top_k: u32,
    cand_multiplier: u32,
    cand_k: u32,
    profile_fingerprint: ProfileFingerprint,
}

impl RetrievalRequest {
    pub(crate) fn intent(&self) -> IntentKind {
        self.intent
    }

    #[must_use]
    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }

    /// Narrows a request built from text into the only query input the local scanner accepts.
    /// Context, DirectGet, and enumeration intents have no egressable text query.
    pub fn trusted_query(&self) -> Option<TrustedRetrievalQuery<'_>> {
        self.query.as_ref().map(|_| TrustedRetrievalQuery(self))
    }

    #[must_use]
    pub fn planner_decision(&self) -> &PlannerDecision {
        &self.planner_decision
    }

    #[must_use]
    pub fn query_transform(&self) -> QueryTransform {
        self.query_transform
    }

    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    #[must_use]
    pub fn top_k(&self) -> u32 {
        self.top_k
    }

    #[must_use]
    pub fn cand_k(&self) -> u32 {
        self.cand_k
    }

    #[must_use]
    pub fn cand_k_formula(&self) -> String {
        format!(
            "min(top_k*{}, {RETRIEVAL_CANDIDATE_CAP})",
            self.cand_multiplier
        )
    }

    #[must_use]
    pub fn profile_fingerprint(&self) -> &str {
        self.profile_fingerprint.as_str()
    }

    #[must_use]
    pub fn profile_fingerprint_identity(&self) -> &ProfileFingerprint {
        &self.profile_fingerprint
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestBuildError {
    EmptyQuery,
}

impl fmt::Display for RequestBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyQuery => write!(f, "retrieval query must not be blank"),
        }
    }
}

impl std::error::Error for RequestBuildError {}

/// §55.1's single legal request constructor. Candidate depth comes only from the registered
/// profile; callers cannot supply `limit`, `top_k`, `cand_k`, or a debug override.
pub fn build_request(
    intent: RetrievalIntent,
    profile: &RegisteredRetrievalProfile,
) -> Result<RetrievalRequest, RequestBuildError> {
    let cand_k = candidate_depth(profile.top_k(), profile.cand_multiplier());
    let (intent, query, planner_decision) = match intent.input {
        RetrievalInput::Text {
            query,
            predicate_registry,
            indexed_columns,
            enumerable_scopes,
        } => {
            let planner_decision = planner::decide(
                &query,
                &predicate_registry,
                &indexed_columns,
                &enumerable_scopes,
            );
            (IntentKind::Text, Some(query), planner_decision)
        }
        RetrievalInput::Context => (
            IntentKind::Context,
            None,
            PlannerDecision::Class(planner::QueryClass::Continuity),
        ),
        RetrievalInput::DirectGet { memory_id } => (
            IntentKind::DirectGet,
            None,
            PlannerDecision::DirectGet(crate::planner::DirectGetLocator::MemoryId(
                memory_id.0.to_string(),
            )),
        ),
        RetrievalInput::MemoryEnumerate => (
            IntentKind::MemoryEnumerate,
            None,
            PlannerDecision::Enumerate {
                predicate_id: humaux_domain::selection::AUTHORIZED_MEMORY_ENUMERATION_V1.to_owned(),
            },
        ),
    };
    Ok(RetrievalRequest {
        intent,
        query,
        planner_decision,
        query_transform: profile.query_transform(),
        profile_id: profile.profile_id().to_string(),
        top_k: profile.top_k(),
        cand_multiplier: profile.cand_multiplier(),
        cand_k,
        profile_fingerprint: ProfileFingerprint(request_profile_fingerprint(profile, cand_k)),
    })
}

fn request_profile_fingerprint(profile: &RegisteredRetrievalProfile, cand_k: u32) -> String {
    let mut effective = BTreeMap::new();
    effective.insert(
        "candidate_cap".to_string(),
        RETRIEVAL_CANDIDATE_CAP.to_string(),
    );
    // ADR-0083 D-D: all five registry entries identify the request; G23-4 refuses to pool runs across any of them.
    effective.insert(
        "candidate_multiplier".to_string(),
        profile.cand_multiplier().to_string(),
    );
    effective.insert("leg_depth".to_string(), profile.leg_depth().to_string());
    effective.insert("rrf_k".to_string(), profile.rrf_k().to_string());
    effective.insert(
        "sparse_leg_enabled".to_string(),
        profile.sparse_leg_enabled().to_string(),
    );
    effective.insert(
        "sparse_timeout_ms".to_string(),
        profile.sparse_timeout_ms().to_string(),
    );
    effective.insert("cand_k".to_string(), cand_k.to_string());
    effective.insert(
        "query_transform".to_string(),
        match profile.query_transform() {
            QueryTransform::Deterministic => "deterministic".to_string(),
        },
    );
    effective.insert("profile_id".to_string(), profile.profile_id().to_string());
    effective.insert("top_k".to_string(), profile.top_k().to_string());
    format!(
        "sha256:{}",
        humaux_contracts::config_registry::effective_config_fingerprint(&effective)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent(query: &str) -> RetrievalIntent {
        RetrievalIntent::new(query.to_string(), vec![], BTreeSet::new(), BTreeSet::new())
            .expect("fixture intent")
    }

    fn profile() -> RegisteredRetrievalProfile {
        humaux_contracts::retrieval_config::resolve_registered_retrieval_profile(&BTreeMap::new())
            .expect("registered defaults")
    }

    #[test]
    fn builds_the_planner_bound_default_request_and_depth() {
        let profile = profile();
        let request = build_request(intent("find \"frozen contract\""), &profile)
            .expect("default profile is valid");
        assert_eq!(request.query(), Some("find \"frozen contract\""));
        assert_eq!(
            request.planner_decision(),
            &PlannerDecision::Class(crate::planner::QueryClass::Literal)
        );
        assert_eq!(request.top_k(), 5);
        assert_eq!(request.cand_k(), 25);
        assert!(request.profile_fingerprint().starts_with("sha256:"));
        assert_eq!(request.profile_fingerprint().len(), 71);
    }

    #[test]
    fn rejects_empty_intent() {
        assert!(matches!(
            RetrievalIntent::new(String::new(), vec![], BTreeSet::new(), BTreeSet::new()),
            Err(RequestBuildError::EmptyQuery)
        ));
    }

    #[test]
    fn trusted_memory_get_preserves_id_and_reuses_profile_fingerprint() {
        let profile = profile();
        let memory_id = MemoryId::new();
        let request = build_request(RetrievalIntent::trusted_memory_get(memory_id), &profile)
            .expect("direct-get request");
        let text = build_request(intent("ordinary text"), &profile).expect("text request");
        assert_eq!(request.query(), None);
        assert_eq!(
            request.planner_decision(),
            &PlannerDecision::DirectGet(crate::planner::DirectGetLocator::MemoryId(
                memory_id.0.to_string(),
            ))
        );
        assert_eq!(request.profile_fingerprint(), text.profile_fingerprint());
    }

    #[test]
    fn trusted_memory_enumerate_preserves_the_registered_profile() {
        let profile = profile();
        let request = build_request(RetrievalIntent::trusted_memory_enumerate(), &profile)
            .expect("enumerate request");
        let text = build_request(intent("ordinary text"), &profile).expect("text request");
        assert_eq!(request.query(), None);
        assert_eq!(
            request.planner_decision(),
            &PlannerDecision::Enumerate {
                predicate_id: humaux_domain::selection::AUTHORIZED_MEMORY_ENUMERATION_V1.to_owned(),
            }
        );
        assert_eq!(request.profile_fingerprint(), text.profile_fingerprint());
    }

    #[test]
    fn trusted_context_has_no_fabricated_query_and_uses_continuity() {
        let request =
            build_request(RetrievalIntent::trusted_context(), &profile()).expect("context request");
        assert_eq!(request.query(), None);
        assert_eq!(
            request.planner_decision(),
            &PlannerDecision::Class(crate::planner::QueryClass::Continuity)
        );
    }

    #[test]
    fn trusted_context_reuses_the_registered_profile_fingerprint() {
        let profile = profile();
        let text = build_request(intent("ordinary text"), &profile).expect("text request");
        let context =
            build_request(RetrievalIntent::trusted_context(), &profile).expect("context request");
        assert_eq!(text.profile_fingerprint(), context.profile_fingerprint());
    }

    fn request_from(entries: &[(&str, &str)]) -> RetrievalRequest {
        let raw: BTreeMap<String, String> = entries
            .iter()
            .map(|(key, value)| (format!("retrieval.profile.{key}"), value.to_string()))
            .collect();
        let profile = resolve_registered_retrieval_profile(&raw).expect("registered value");
        build_request(intent("same query"), &profile).expect("request")
    }

    fn request_with(key: &str, value: &str) -> RetrievalRequest {
        request_from(&[(key, value)])
    }

    /// G6c1-1: changing any one of the five ADR-0083 D-D entries changes the fingerprint, so G23-4 refuses to pool
    /// runs across it. `top_k = 100` saturates the cap (multipliers 5 and 6 both give `cand_k` 200), so `cand_k`
    /// cannot move the fingerprint and each row isolates its own key. Fault: leave one of them out of
    /// `request_profile_fingerprint` => its row goes red.
    #[test]
    fn each_hybrid_registry_entry_moves_the_request_fingerprint() {
        let base = request_from(&[("top_k", "100")]);
        for (key, value) in [
            ("cand_multiplier", "6"),
            ("leg_depth", "201"),
            ("rrf_k", "61"),
            ("sparse_leg_enabled", "true"),
            ("sparse_timeout_ms", "1001"),
        ] {
            let changed = request_from(&[("top_k", "100"), (key, value)]);
            assert_eq!(
                base.cand_k(),
                changed.cand_k(),
                "{key}: cand_k must not be what moves it"
            );
            assert_ne!(
                base.profile_fingerprint(),
                changed.profile_fingerprint(),
                "{key}"
            );
            assert!(
                crate::envelope::require_single_fingerprint([
                    base.profile_fingerprint(),
                    changed.profile_fingerprint(),
                ])
                .is_err(),
                "{key}"
            );
        }
    }

    /// ADR-0083 D-D: `cand_k` and its wire formula follow the registered multiplier; the default renders as before.
    #[test]
    fn cand_k_and_its_formula_follow_the_registered_multiplier() {
        let default = build_request(intent("same query"), &profile()).expect("request");
        assert_eq!(default.cand_k(), 25);
        assert_eq!(default.cand_k_formula(), "min(top_k*5, 200)");
        let wider = request_with("cand_multiplier", "10");
        assert_eq!(wider.cand_k(), 50);
        assert_eq!(wider.cand_k_formula(), "min(top_k*10, 200)");
        assert_eq!(request_with("cand_multiplier", "200").cand_k(), 200);
    }

    #[test]
    fn fingerprint_is_query_independent_but_rejects_mixed_effective_request_profiles() {
        let profile = profile();
        let default_request = build_request(intent("first query"), &profile).expect("request");
        let same_profile = build_request(intent("second query"), &profile).expect("request");
        assert_eq!(
            default_request.profile_fingerprint(),
            same_profile.profile_fingerprint()
        );
        assert_eq!(default_request.cand_k(), 25);

        let mut raw = BTreeMap::new();
        raw.insert("retrieval.profile.top_k".to_string(), "10".to_string());
        let deeper = resolve_registered_retrieval_profile(&raw).expect("registered depth");
        let deeper_request = build_request(intent("first query"), &deeper).expect("request");
        assert_eq!(deeper_request.cand_k(), 50);
        assert_ne!(
            default_request.profile_fingerprint(),
            deeper_request.profile_fingerprint()
        );
        assert!(
            crate::envelope::require_single_fingerprint([
                default_request.profile_fingerprint(),
                deeper_request.profile_fingerprint(),
            ])
            .is_err()
        );
    }
}
