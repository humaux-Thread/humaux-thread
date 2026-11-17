//! `application::distill` — Candidate confirmation/rejection use cases (§36; ADR-0130 D2/D7a).
//! Depends-on: crates=[async-trait, humaux-domain, serde_json, time, uuid]; services=[]; env=[]; modules=[domain::confirm, domain::error, domain::identity, domain::ids, domain::subject]
//! Called-by: [gateway::bootstrap, adapters::distill_repo, gateway::memory, gateway::mcp_application]
//! Invariants: [one store call owns the entire transaction; confirmation is explicit]
//! Spec: §36; ADR-0026; ADR-0130

use async_trait::async_trait;
use humaux_domain::{
    confirm::DestructiveOp,
    error::{ConflictReason, ErrorCode},
    identity::AuthorizationScope,
    ids::WorkspaceId,
    subject::SubjectDeclaration,
};
use serde_json::Value;
use std::time::{Duration, SystemTime};
use time::OffsetDateTime;
use uuid::Uuid;

/// Trusted request provenance; the adapter constructs the audit record (§77).
pub struct CandidateAudit {
    /// Trusted event_id from the ingress gate.
    pub event_id: Uuid,
    /// Trusted ts from the ingress gate.
    pub ts: SystemTime,
    /// Trusted tenant_id from the ingress gate.
    pub tenant_id: Uuid,
    /// Trusted actor_type from the ingress gate.
    pub actor_type: String,
    /// Trusted actor_id from the ingress gate.
    pub actor_id: String,
    /// Trusted action from the ingress gate.
    pub action: String,
    /// Trusted resource_type from the ingress gate.
    pub resource_type: String,
    /// Trusted resource_id from the ingress gate.
    pub resource_id: String,
    /// Trusted result from the ingress gate.
    pub result: String,
    /// Trusted request_id from the ingress gate.
    pub request_id: String,
    /// Trusted trace_id from the ingress gate.
    pub trace_id: String,
    /// Trusted client_ip from the ingress gate.
    pub client_ip: String,
    /// Trusted user_agent_hash from the ingress gate.
    pub user_agent_hash: String,
    /// Trusted risk_tags from the ingress gate.
    pub risk_tags: Vec<String>,
    /// Trusted before_fingerprint from the ingress gate.
    pub before_fingerprint: Option<String>,
    /// Trusted after_fingerprint from the ingress gate.
    pub after_fingerprint: Option<String>,
    /// Trusted metadata from the ingress gate.
    pub metadata: Vec<(String, String)>,
}

/// Gate-verified token binding; consumption remains inside the PG transaction.
pub struct CandidateConfirmation {
    /// Bound operation.
    pub op: DestructiveOp,
    /// Bound target.
    pub target_id: Uuid,
    /// Bound successor, if any.
    pub successor_id: Option<Uuid>,
    /// Presented token digest, never its secret.
    pub nonce_sha256: [u8; 32],
    /// Bound intent digest.
    pub request_sha256: Option<[u8; 32]>,
}

/// Trusted stream coordinates; ticket issuance remains in the adapter.
pub struct CandidateStream {
    /// Tenant coordinate.
    pub tenant_id: Uuid,
    /// Scope kind.
    pub scope_kind: String,
    /// Scope coordinate.
    pub scope_id: Uuid,
    /// Domain coordinate.
    pub domain: String,
    /// Projection kind.
    pub projection_kind: String,
    /// Projection version.
    pub projection_version: String,
}

/// Common confirmed request context from the ingress gate.
pub struct CandidateWrite {
    /// Request identity.
    pub request_id: Uuid,
    /// Exact request digest.
    pub request_fingerprint: String,
    /// Existing reservation policy.
    pub reservation_ttl: Duration,
    /// Candidate selected by the user.
    pub candidate_id: Uuid,
    /// Token binding to consume atomically.
    pub confirmation: CandidateConfirmation,
    /// Trusted completion provenance.
    pub audit: CandidateAudit,
}

/// Explicit user confirmation, distinct from automatic candidate acceptance.
pub struct ConfirmCandidate {
    /// Confirmed request context.
    pub write: CandidateWrite,
    /// Digest of the reviewed candidate.
    pub candidate_sha256: Vec<u8>,
    /// Trusted write stream.
    pub stream: CandidateStream,
    /// Existing consistency-token policy.
    pub consistency_token_ttl: Duration,
    /// Explicit subjects, resolved inside the same transaction.
    pub subjects: SubjectDeclaration,
}

/// A committed confirmation's business result.
#[derive(Debug, Clone)]
pub struct ConfirmDone {
    /// New Memory identity.
    pub memory_id: Uuid,
    /// New Evidence identity.
    pub evidence_id: Uuid,
    /// Confirmed candidate.
    pub candidate_id: Uuid,
    /// Stream position.
    pub stream_seq: i64,
    /// Commit position.
    pub commit_seq: i64,
    /// Consistency token.
    pub consistency_token: String,
    /// Resolved subjects.
    pub subject_ids: Vec<Uuid>,
}

/// Confirmation result using the existing terminal/refusal vocabulary.
pub enum ConfirmOutcome {
    /// Committed explicit confirmation.
    Confirmed(ConfirmDone),
    /// Refused without a mutation.
    Refused(ConflictReason),
}

/// Rejection writes no Evidence or Memory (§36).
pub enum RejectOutcome {
    /// Rejected candidate.
    Rejected(Uuid),
    /// Refused without a mutation.
    Refused(ConflictReason),
}

/// One PENDING candidate as `memory.enumerate {candidates:true}` returns it.
#[derive(Debug, Clone)]
pub struct PendingCandidate {
    pub candidate_id: Uuid,
    pub candidate_sha256: Vec<u8>,
    pub candidate_body: Value,
    pub requested_class: String,
    pub memory_type: String,
    pub rejection_reason: String,
    pub confidence: f32,
    pub source_evidence_id: Uuid,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// Whole-transaction candidate decision boundary (ADR-0130 D7a).
#[async_trait]
pub trait CandidateDecisionStore: Send + Sync {
    /// Confirm and publish through the existing lifecycle door in one transaction.
    async fn confirm(
        &self,
        auth: &AuthorizationScope,
        command: ConfirmCandidate,
    ) -> Result<ConfirmOutcome, ErrorCode>;
    /// Reject and settle its token/quota/audit in one transaction.
    async fn reject(
        &self,
        auth: &AuthorizationScope,
        command: CandidateWrite,
    ) -> Result<RejectOutcome, ErrorCode>;
    /// List PENDING candidates visible to `auth` in `workspace` (§36; ADR-0026 D-E).
    async fn list_pending(
        &self,
        auth: &AuthorizationScope,
        workspace: WorkspaceId,
        limit: i64,
    ) -> Result<Vec<PendingCandidate>, ErrorCode>;
}

/// Execute an explicit candidate confirmation (§36).
pub async fn confirm_candidate(
    store: &dyn CandidateDecisionStore,
    auth: &AuthorizationScope,
    command: ConfirmCandidate,
) -> Result<ConfirmOutcome, ErrorCode> {
    store.confirm(auth, command).await
}

/// Execute an explicit candidate rejection (§36).
pub async fn reject_candidate(
    store: &dyn CandidateDecisionStore,
    auth: &AuthorizationScope,
    command: CandidateWrite,
) -> Result<RejectOutcome, ErrorCode> {
    store.reject(auth, command).await
}

/// List visible PENDING candidates for a workspace (§36; ADR-0026 D-E).
pub async fn list_pending_candidates(
    store: &dyn CandidateDecisionStore,
    auth: &AuthorizationScope,
    workspace: WorkspaceId,
    limit: i64,
) -> Result<Vec<PendingCandidate>, ErrorCode> {
    store.list_pending(auth, workspace, limit).await
}
