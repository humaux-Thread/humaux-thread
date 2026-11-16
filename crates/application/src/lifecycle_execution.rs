//! `application::lifecycle_execution` — whole-transaction memory governance ports (§36; ADR-0130).
//! Depends-on: crates=[async-trait, humaux-domain, serde_json, time, uuid]; services=[]; env=[]; modules=[application::remember, domain::affect, domain::authority, domain::confirm, domain::error, domain::evidence, domain::identity, domain::subject]
//! Called-by: [adapters::memory_governance_repo, gateway::bootstrap, gateway::memory]
//! Invariants: [one port call owns one complete PG transaction; authorization and final read gate remain unchanged]
//! Spec: §36; ADR-0130
use crate::remember::AffectInput;
use async_trait::async_trait;
use humaux_domain::{
    affect::MoodHalfLife,
    authority::MemoryId,
    confirm::DestructiveOp,
    error::{ConflictReason, ErrorCode},
    evidence::EvidencePayloadSha256,
    identity::AuthorizationScope,
    subject::SubjectDeclaration,
};
use std::time::{Duration, SystemTime};
use time::OffsetDateTime;
use uuid::Uuid;
/// Trusted request provenance; the adapter constructs the audit record (§77).
pub struct LifecycleAudit {
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
pub struct LifecycleConfirmation {
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
pub struct LifecycleStream {
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

/// Trusted lifecycle command or committed result (§36).
pub struct SupersedeRequest {
    /// Trusted request id (§36).
    pub request_id: Uuid,
    /// Trusted request fingerprint (§36).
    pub request_fingerprint: String,
    /// Trusted reservation ttl (§36).
    pub reservation_ttl: Duration,
    /// Trusted target (§36).
    pub target: MemoryId,
    /// Trusted successor (§36).
    pub successor: MemoryId,
    /// Stream family the lifecycle ticket is issued on (the workspace's projection stream,
    /// same key `memory.get`/`recall` read their ledger from).
    pub stream: LifecycleStream,
    /// Trusted claim (§36).
    pub claim: LifecycleConfirmation,
    /// Trusted finished audit (§36).
    pub finished_audit: LifecycleAudit,
    /// §78.1 undo window: how long the resulting SUPERSEDE stays restorable. Stamped onto the
    /// lifecycle event's `undo_deadline` at write time (ADR-0020 D-A/D-D).
    pub undo_window: Duration,
}

/// Trusted lifecycle command or committed result (§36).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupersedeOutcome {
    /// Trusted superseded at (§36).
    pub superseded_at: OffsetDateTime,
    /// Trusted stream seq (§36).
    pub stream_seq: i64,
    /// Trusted commit seq (§36).
    pub commit_seq: i64,
}

/// Trusted lifecycle command or committed result (§36).
pub struct RestoreRequest {
    /// Trusted request id (§36).
    pub request_id: Uuid,
    /// Trusted request fingerprint (§36).
    pub request_fingerprint: String,
    /// Trusted reservation ttl (§36).
    pub reservation_ttl: Duration,
    /// Trusted target (§36).
    pub target: MemoryId,
    /// Trusted stream (§36).
    pub stream: LifecycleStream,
    /// Trusted claim (§36).
    pub claim: LifecycleConfirmation,
    /// Trusted finished audit (§36).
    pub finished_audit: LifecycleAudit,
    /// §15.5 lifetime of the returned consistency_token (the workspace remember policy's TTL).
    pub consistency_token_ttl: Duration,
}

/// Trusted lifecycle command or committed result (§36).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreDone {
    /// Trusted restored at (§36).
    pub restored_at: OffsetDateTime,
    /// Trusted stream seq (§36).
    pub stream_seq: i64,
    /// Trusted commit seq (§36).
    pub commit_seq: i64,
    /// Trusted consistency token (§36).
    pub consistency_token: String,
}

/// Trusted lifecycle command or committed result (§36).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreResult {
    Restored(RestoreDone),
    Refused(ConflictReason),
}

/// Trusted lifecycle command or committed result (§36).
pub struct ArchiveRequest {
    /// Trusted request id (§36).
    pub request_id: Uuid,
    /// Trusted request fingerprint (§36).
    pub request_fingerprint: String,
    /// Trusted reservation ttl (§36).
    pub reservation_ttl: Duration,
    /// Trusted target (§36).
    pub target: MemoryId,
    /// Trusted stream (§36).
    pub stream: LifecycleStream,
    /// Trusted claim (§36).
    pub claim: LifecycleConfirmation,
    /// Trusted finished audit (§36).
    pub finished_audit: LifecycleAudit,
    /// `MemoryArchive` sets `archived_at`; `MemoryUnarchive` clears it.
    pub op: DestructiveOp,
}

/// Trusted lifecycle command or committed result (§36).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveDone {
    /// The instant the flag flipped (`archived_at` for archive; the clear instant for unarchive).
    pub changed_at: OffsetDateTime,
    /// Trusted stream seq (§36).
    pub stream_seq: i64,
    /// Trusted commit seq (§36).
    pub commit_seq: i64,
}

/// Trusted lifecycle command or committed result (§36).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveResult {
    Done(ArchiveDone),
    Refused(ConflictReason),
}

/// Trusted lifecycle command or committed result (§36).
pub struct CorrectRequest {
    /// Trusted request id (§36).
    pub request_id: Uuid,
    /// Trusted request fingerprint (§36).
    pub request_fingerprint: String,
    /// Trusted reservation ttl (§36).
    pub reservation_ttl: Duration,
    /// The Memory being corrected, `M1`.
    pub target: MemoryId,
    /// The corrected content, stored verbatim as `E2`'s event payload and `M2`'s content.
    pub content: serde_json::Value,
    /// Digest of the exact raw bytes of `content` (§48.0①), for `E2`.
    pub payload_sha256: EvidencePayloadSha256,
    /// Stream family the lifecycle ticket + the new Evidence are issued on.
    pub stream: LifecycleStream,
    /// Trusted claim (§36).
    pub claim: LifecycleConfirmation,
    /// Trusted finished audit (§36).
    pub finished_audit: LifecycleAudit,
    /// §78.1 undo window: how long the resulting SUPERSEDE (reason USER_CORRECTION) stays
    /// restorable via `memory.restore` (a correction's undo IS card 3's restore of that
    /// SUPERSEDE).
    pub undo_window: Duration,
    /// §15.5 consistency_token lifetime for the token returned on `M2`'s new stream seq.
    pub consistency_token_ttl: Duration,
    /// §6.1.3 rules 1/2 (ADR-0028): explicit subjects `M2` is about, on top of what it inherits
    /// from `M1` (the 0154 trigger). Resolved under the tenant's RLS BEFORE the token is
    /// consumed — unknown ⇒ `INVALID_INPUT`, nothing written, token intact — and applied inside
    /// this same transaction.
    pub subjects: SubjectDeclaration,
    /// §8.5.1 (ADR-0030 D-E): `M2`'s affect annotations, re-supplied in full (`M1`'s rows ride
    /// with the superseded version). Target subjects resolve BEFORE the token is consumed
    /// (unknown ⇒ `INVALID_INPUT`, token intact); the rows are written inside this same
    /// transaction after the arbiter UPDATE — one `MEMORY_LIFECYCLE` ticket covers them.
    pub affects: Vec<AffectInput>,
    /// The frozen MOOD half-life policy stamped onto MOOD rows (`None` = not declared ⇒ a MOOD
    /// input is `DEPENDENCY_UNAVAILABLE`).
    pub mood_half_life: Option<MoodHalfLife>,
}

/// Trusted lifecycle command or committed result (§36).
#[derive(Debug, Clone)]
pub struct CorrectDone {
    /// The new active Memory version, `M2`.
    pub new_memory_id: MemoryId,
    /// The corrected (now-superseded) Memory, `M1`.
    pub superseded: MemoryId,
    /// The new DirectUserInput Evidence, `E2`.
    pub evidence_id: Uuid,
    /// Trusted superseded at (§36).
    pub superseded_at: OffsetDateTime,
    /// Trusted stream seq (§36).
    pub stream_seq: i64,
    /// Trusted commit seq (§36).
    pub commit_seq: i64,
    /// Trusted consistency token (§36).
    pub consistency_token: String,
    /// §6.1.3: every subject `M2` is linked to after the hook ran (inherited from `M1` +
    /// explicit), in link order.
    pub subject_ids: Vec<Uuid>,
    /// §8.5.1: `M2`'s affect rows (the re-supplied annotations), in write order.
    pub affect_ids: Vec<Uuid>,
}

/// Whole-transaction governance boundary (§36).
#[async_trait]
pub trait LifecycleStore: Send + Sync {
    /// Execute supersede without splitting its transaction (§36).
    async fn supersede(
        &self,
        auth: &AuthorizationScope,
        command: SupersedeRequest,
    ) -> Result<SupersedeOutcome, ErrorCode>;
    /// Execute restore without splitting its transaction (§36).
    async fn restore(
        &self,
        auth: &AuthorizationScope,
        command: RestoreRequest,
    ) -> Result<RestoreResult, ErrorCode>;
    /// Execute correct without splitting its transaction (§36).
    async fn correct(
        &self,
        auth: &AuthorizationScope,
        command: CorrectRequest,
    ) -> Result<CorrectDone, ErrorCode>;
    /// Execute archive without splitting its transaction (§36).
    async fn archive(
        &self,
        auth: &AuthorizationScope,
        command: ArchiveRequest,
    ) -> Result<ArchiveResult, ErrorCode>;
}

/// Execute the confirmed supersede use case (§36).
pub async fn supersede(
    store: &dyn LifecycleStore,
    auth: &AuthorizationScope,
    command: SupersedeRequest,
) -> Result<SupersedeOutcome, ErrorCode> {
    store.supersede(auth, command).await
}

/// Execute the confirmed restore use case (§36).
pub async fn restore(
    store: &dyn LifecycleStore,
    auth: &AuthorizationScope,
    command: RestoreRequest,
) -> Result<RestoreResult, ErrorCode> {
    store.restore(auth, command).await
}

/// Execute the confirmed correct use case (§36).
pub async fn correct(
    store: &dyn LifecycleStore,
    auth: &AuthorizationScope,
    command: CorrectRequest,
) -> Result<CorrectDone, ErrorCode> {
    store.correct(auth, command).await
}

/// Execute the confirmed archive use case (§36).
pub async fn archive(
    store: &dyn LifecycleStore,
    auth: &AuthorizationScope,
    command: ArchiveRequest,
) -> Result<ArchiveResult, ErrorCode> {
    store.archive(auth, command).await
}
