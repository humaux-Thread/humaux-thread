//! `domain::reasoning_types` — shared private-reasoning identifiers, SHA-256 digests, version counters, and closed purpose/call-kind enums (§11.2.1, §11.5, §11.8, §12.1, ADR-0130 D2).
//! Depends-on: crates=[uuid]; services=[]; env=[]; modules=[]
//! Called-by: []
//! Invariants: [§78.2 closed-set enums, no stringly-typed domain escape hatch]
//! Spec: §11.2.1; §11.5; §11.8; §12.1; §78.2; ADR-0130
//!
//! Pure contract kernel value types and closed-set enums for private reasoning and Phase 9
//! contribution de-identification. Shared across `knowledge_curation`, `public_knowledge`, and
//! `provider_execution` without carrying execution ports or I/O behavior (ADR-0130 D2).

use uuid::Uuid;

/// §11.2.1: which `USER_REASONING` profile a `PrivateReasoningPort` request is bound to —
/// `PrivateReasoningDomainId` scopes "谁的 Key 能处理" separately from tenant/user visibility.
/// Minted here (not `domain::ids`) for the same reason `MemoryId`/`EvidenceId` are minted in
/// `domain::authority`: this module is its first consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PrivateReasoningDomainId(pub uuid::Uuid);

/// Phase 9 R3 caller authority: the exact immutable reasoning route Binding logical identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReasoningRouteBindingId(pub uuid::Uuid);

/// Phase 9 R3 caller authority: the exact immutable version of [`ReasoningRouteBindingId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReasoningRouteBindingVersion(pub i64);

/// Resolver-derived immutable profile version retained for audit/context compatibility.
/// It is never accepted in a sealed request or other caller authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserReasoningProfileVersion(pub i64);

/// Durable caller-owned identity of one logical contribution reasoning call. Retries carry the
/// same value; a new user execution carries a new value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LogicalReasoningCallId(pub Uuid);

/// The two Phase 9 contribution calls have independent durable identities and prompt contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContributionReasoningCallKind {
    /// Phase 9 coverage probe call kind.
    CoverageProbe,
    /// Phase 9 typed assessment call kind.
    TypedAssessment,
}

impl ContributionReasoningCallKind {
    /// Stable database label for [`ContributionReasoningCallKind`].
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::CoverageProbe => "COVERAGE_PROBE",
            Self::TypedAssessment => "TYPED_ASSESSMENT",
        }
    }
}

/// Independent canonical call intent. It deliberately excludes route health/admission timestamps
/// and provider wire serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReasoningIntentSha256(pub [u8; 32]);

/// SHA-256 over the request's input manifest — identifies *what* was sent for inference
/// without the payload itself needing to leave the sealed RPC body (§11.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentSha256(pub [u8; 32]);

/// §11.8: one LLM call's purpose. A fixed, closed set — no `Other(String)` — because the
/// receiving `humaux-private-worker` RPC handler branches its own audit/quota accounting on
/// this value (§11.5 BYOK usage accounting) and a stringly-typed escape hatch would defeat
/// that accounting (§78.2 "禁止 stringly-typed domain").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateReasoningPurpose {
    /// Private distillation reasoning call.
    Distill,
    /// Private memory consolidation reasoning call.
    Consolidate,
    /// Private vision reasoning call.
    Vision,
    /// §12.1: private de-identification before the exact-byte contribution gate.
    ContributionDeidentify,
}

/// Opaque reference into the provider call log (§11.5 usage accounting) — this crate never
/// interprets it, only threads it through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderTraceRef(pub String);
