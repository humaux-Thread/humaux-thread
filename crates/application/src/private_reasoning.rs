//! `application::private_reasoning` — Sealed private reasoning execution contract shared by contribution and curation.
//! Depends-on: crates=[async-trait, hex, humaux-domain, sha2, uuid]; services=[]; env=[]; modules=[domain::reasoning_types]
//! Called-by: [adapters::structured_reasoning]
//! Invariants: [sealed requests contain identifiers and hashes; errors and output bytes are redacted]
//! Spec: §11.8; ADR-0130 step 5

use humaux_domain::reasoning_types::{
    ContentSha256, ContributionReasoningCallKind, LogicalReasoningCallId, PrivateReasoningDomainId,
    PrivateReasoningPurpose, ProviderTraceRef, ReasoningIntentSha256, ReasoningRouteBindingId,
    ReasoningRouteBindingVersion,
};
use uuid::Uuid;

/// Contribution-only attempt authority carried inside the otherwise general sealed request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContributionReasoningAttempt {
    pub logical_call_id: LogicalReasoningCallId,
    pub call_kind: ContributionReasoningCallKind,
    pub intent_schema_version: u32,
    pub intent_sha256: ReasoningIntentSha256,
}

/// §11.8 verbatim: the sealed request `humaux-consolidation-worker` sends over internal mTLS.
/// Carries no DB capability and no raw content — only identifiers and a hash of what the
/// caller wants inferred over; the private-worker RPC handler fetches/decrypts everything else
/// itself (§11.8: "payload 只通过内部 mTLS RPC body 传递，不携带 DB capability").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedPrivateReasoningRequest {
    pub reasoning_domain_id: PrivateReasoningDomainId,
    pub binding_id: ReasoningRouteBindingId,
    pub binding_version: ReasoningRouteBindingVersion,
    pub input_manifest_hash: ContentSha256,
    pub purpose: PrivateReasoningPurpose,
    /// Required by the Phase 9 contribution reasoner; absent for unrelated sealed call purposes.
    pub contribution_attempt: Option<ContributionReasoningAttempt>,
}

/// §11.8 verbatim: what `PrivateReasoningPort::infer` returns on success.
///
/// `output_bytes` is the inference output *over private memory content* (§11.8) — a derived
/// `#[derive(Debug)]` would print it verbatim on any stray `{:?}` (a log line, a panic
/// message), which is exactly the class of leak `crates/application/src/auth.rs`'s
/// `EncodedPasswordHash`/`PlaintextCode`/`CodeHash` hand-written `Debug` impls already exist to
/// prevent for other private-content-shaped fields. [`Debug`] below is hand-written for the
/// same reason: only the identifiers survive, never the bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateReasoningResult {
    pub output_bytes: Vec<u8>,
    pub output_sha256: ContentSha256,
    pub provider_trace: ProviderTraceRef,
    /// Durable receipt for the exact provider attempt.
    pub model_call_id: Uuid,
    /// Exact Binding authority admitted for this result.
    pub binding_id: ReasoningRouteBindingId,
    pub binding_version: ReasoningRouteBindingVersion,
}

impl std::fmt::Debug for PrivateReasoningResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateReasoningResult")
            .field(
                "output_bytes",
                &format_args!("[REDACTED; {} bytes]", self.output_bytes.len()),
            )
            .field("output_sha256", &self.output_sha256)
            .field("provider_trace", &self.provider_trace)
            .field("model_call_id", &self.model_call_id)
            .field("binding_id", &self.binding_id)
            .field("binding_version", &self.binding_version)
            .finish()
    }
}

/// `PrivateReasoningPort::infer`'s failure — adapter-local (the RPC transport error, or the
/// private-worker's own `ErrorCode`/`DegradeCode` collapsed to a message), not one of the
/// workspace's two frozen domain error enums (§52) reused for a third purpose.
///
/// The wrapped message is upstream text this crate does not control — an mTLS transport error
/// or a provider SDK error string, either of which can carry request fragments (verified live:
/// constructing one from a plaintext-secret-bearing upstream string and printing it with `{}`
/// reproduces the secret verbatim). Field is private with a redacting [`Display`]/[`Debug`]
/// (same convention as `auth.rs`'s `EncodedPasswordHash`/`CodeHash`) — callers get a stable
/// fingerprint for log correlation, never the raw text.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateReasoningError {
    message: String,
    existing_model_call_id: Option<Uuid>,
    /// A STATIC classification chosen at the raise site (`contribution_reasoner::fail`) — never
    /// user, tenant or provider text, so it is safe to print verbatim. `Display`/`Debug` stay
    /// redacted on purpose; a caller that must log WHY asks for this explicitly.
    ///
    /// Card 16's P0 is why this exists: the Distill hop deferred every row of one tenant forever
    /// and the only thing any log could say about it was a 4-byte fingerprint.
    class: Option<&'static str>,
}

impl PrivateReasoningError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            existing_model_call_id: None,
            class: None,
        }
    }

    /// A failure whose `label` is a compile-time constant, so the class can be logged.
    pub fn classified(label: &'static str) -> Self {
        Self {
            message: label.to_owned(),
            existing_model_call_id: None,
            class: Some(label),
        }
    }

    /// The static class, when the raise site had one.
    pub const fn class(&self) -> Option<&'static str> {
        self.class
    }

    /// Retry outcome for a logical call whose matching durable reservation already exists.
    pub fn existing_reservation(model_call_id: Uuid) -> Self {
        Self {
            message: "logical reasoning call already reserved".into(),
            existing_model_call_id: Some(model_call_id),
            class: Some("logical reasoning call already reserved"),
        }
    }

    pub fn existing_model_call_id(&self) -> Option<Uuid> {
        self.existing_model_call_id
    }

    /// Short, stable, non-reversible correlation tag for logs — enough to match two log lines
    /// about the same underlying error without ever printing its text.
    fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(self.message.as_bytes());
        hex::encode(&digest[..4])
    }
}

impl std::fmt::Debug for PrivateReasoningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PrivateReasoningError(REDACTED, fingerprint={})",
            self.fingerprint()
        )
    }
}

impl std::fmt::Display for PrivateReasoningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PrivateReasoningPort error (redacted, fingerprint={})",
            self.fingerprint()
        )
    }
}

impl std::error::Error for PrivateReasoningError {}

/// §11.8 verbatim: `humaux-consolidation-worker`'s only inference interface. Implemented in
/// `humaux-private-worker` (over internal mTLS) — this crate defines the boundary, not the
/// transport; a fake implementation drives this module's own tests without any network stack.
///
/// §11.8 hard boundary the trait's *implementation* must hold (enforced at the private-worker
/// RPC handler, out of this crate's file scope, tracked as G11-R1):
/// ```text
/// MAY decrypt USER BYOK and call UserReasoningProvider
/// MUST NOT accept memory_id to mutate
/// MUST NOT write memory_records / memory_evidence / rollups
/// MUST NOT receive any PgPool/Repository capability from caller
/// ```
#[async_trait::async_trait]
pub trait PrivateReasoningPort: Send + Sync {
    async fn infer(
        &self,
        req: SealedPrivateReasoningRequest,
    ) -> Result<PrivateReasoningResult, PrivateReasoningError>;
}
