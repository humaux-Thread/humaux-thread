//! `application::remember` — Remember intake and whole-write application port (§34 / §58; ADR-0130 D2/D7a).
//! Depends-on: crates=[async-trait, humaux-domain, serde_json, time, uuid]; services=[];
//!   env=[]; modules=[domain::affect, domain::audit, domain::authority, domain::continuity, domain::coordination, domain::error, domain::evidence, domain::identity, domain::ids, domain::note, domain::source, domain::subject]
//! Called-by: [adapters::operation_receipt, adapters::remember, application::lifecycle_execution, gateway::bootstrap, gateway::guard, gateway::mcp_application, gateway::remember]
//! Invariants: [one port call owns the complete PG transaction; no transaction handles cross this boundary]
//! Spec: §8.5.1; §34.0.1; §58; §60

use humaux_domain::{
    affect::{AffectAnnotation, MoodHalfLife},
    audit::AuditEvent,
    authority::AuthorityClass,
    continuity::ProjectId,
    coordination::{FencingToken, TaskRunId},
    error::{ConflictReason, ErrorCode},
    evidence::{EvidenceOriginClass, EvidencePayloadSha256},
    identity::AuthorizationScope,
    ids::WorkspaceId,
    note::{NoteBody, NoteKind},
    source::SourceIdentity,
    subject::{SubjectDeclaration, SubjectKey},
};
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

/// One annotation to append (`memory.annotate_affect.affects[]` / `memory.correct.affects[]`).
/// `target_subject_key` is an exact trusted key resolved under RLS (rule 2); the annotation's own
/// `target_subject` is an explicit id (rule 1). At most one of the two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffectInput {
    /// Trusted annotation (§34).
    pub annotation: AffectAnnotation,
    /// Absent ⇒ `now()` at write time.
    pub observed_at: Option<OffsetDateTime>,
    /// Trusted target_subject_key (§34).
    pub target_subject_key: Option<SubjectKey>,
}

/// `remember()` input — already-resolved/validated fields for `private.evidence_objects` +
/// `private.events`, one call = one `evidence_kind = 'EVENT'` row pair (the only subtype this
/// task's `remember` MCP contract produces, §34; `'ARTIFACT'` rows are a different write path,
/// out of scope). Mapping raw MCP `remember(content, kind, source, ...)` input into this shape
/// (client-facing `kind` string -> one of the 9 `event_kind` CHECK values, `source.type` ->
/// [`EvidenceOriginClass`], etc.) belongs to ingress; §60 starts from a validated command.
#[derive(Debug, Clone)]
pub struct RememberCommand {
    /// Trusted tenant_id (§34).
    pub tenant_id: Uuid,
    /// Authenticated actor from the trusted gateway request context. This is deliberately
    /// distinct from `visibility_user_id`: workspace-shared Evidence has no visibility user,
    /// but RLS still needs the acting member in `humaux.user_id`.
    pub authorization_user_id: Option<Uuid>,
    /// `projection.stream_log` / `stream_checkpoints` locator (§15.1's other five PK columns,
    /// beyond `tenant_id`) — which pipeline this Evidence's stream_seq is issued against.
    pub scope_kind: String,
    /// Trusted scope_id (§34).
    pub scope_id: Uuid,
    /// Trusted domain (§34).
    pub domain: String,
    /// Trusted projection_kind (§34).
    pub projection_kind: String,
    /// Trusted projection_version (§34).
    pub projection_version: String,
    /// Explicit policy/configuration input for §15.5's token `expiry or policy` field.
    /// It is validated against the one issuance clock captured by [`remember`] before any DB
    /// write. This is an API break: callers must provide their own configured/policy expiry;
    /// the adapter intentionally has no business TTL default.
    pub consistency_token_expires_at: OffsetDateTime,
    /// `Some` = batch write (redeem one ticket, §34.1 row 1); `None` = single sync write, ticket
    /// untouched (§34.1 row 3, `expected_source = "none"`).
    pub batch_id: Option<Uuid>,
    /// §48.0① sole-constructor anchor — accepted as the already-hashed
    /// [`EvidencePayloadSha256`] (never a raw `[u8; 32]`) so this command struct cannot be
    /// built with a digest that skipped `evidence::payload_sha256`'s "no trim/NFC/NFKC/
    /// transcode" contract; the type has no `pub` field and no second constructor, so the only
    /// way a caller has one to put here is to have called that function.
    pub payload_sha256: EvidencePayloadSha256,
    /// Trusted data_class (§34).
    pub data_class: String,
    /// Trusted origin_class (§34).
    pub origin_class: EvidenceOriginClass,
    /// Trusted origin_principal_id (§34).
    pub origin_principal_id: Option<Uuid>,
    /// Trusted origin_connector_id (§34).
    pub origin_connector_id: Option<Uuid>,
    /// Trusted visibility_class (§34).
    pub visibility_class: String,
    /// Trusted visibility_user_id (§34).
    pub visibility_user_id: Option<Uuid>,
    /// Trusted visibility_workspace_id (§34).
    pub visibility_workspace_id: Option<Uuid>,
    /// Trusted reasoning_domain_id (§34).
    pub reasoning_domain_id: Uuid,
    /// Trusted occurred_at (§34).
    pub occurred_at: Option<OffsetDateTime>,
    /// Trusted event_kind (§34).
    pub event_kind: String,
    /// Trusted event_payload (§34).
    pub event_payload: serde_json::Value,
    /// §6.1.3 rules 1/2 (ADR-0028): the explicit `subject_ids` / `subject_keys` this Evidence is
    /// about. Resolved under the tenant's RLS before the first write and recorded on
    /// `private.evidence_subjects` in the same transaction; an unknown id/key is
    /// `INVALID_INPUT` and nothing is written.
    pub subjects: SubjectDeclaration,
    /// §8.5.1 (ADR-0030 D-C): the affects declared at `remember.put`. Their `target_subject`
    /// ids/keys are resolved with `subjects` BEFORE the first write; the rows land on
    /// `private.evidence_affects` in this same transaction (0157) and reach every memory born
    /// from this Evidence through the `memory_evidence` PRIMARY trigger. Empty = none.
    pub affects: Vec<AffectInput>,
    /// The frozen MOOD half-life policy stamped onto MOOD rows; required only when `affects`
    /// carries a MOOD (`DEPENDENCY_UNAVAILABLE` otherwise).
    pub mood_half_life: Option<MoodHalfLife>,
}

/// `remember()`'s accepted result (§34 / §15.5, verbatim field set).
#[derive(Debug, Clone)]
pub struct RememberAccepted {
    /// Trusted evidence_id (§34).
    pub evidence_id: Uuid,
    /// §34: "通过 processing_handle / memory / context 查询处理结果" — opaque to the caller,
    /// currently just the evidence id's string form (one Evidence : one handle, §34's own
    /// "一个 Evidence 后续可产生多条 memory_id" is a *query-time* fan-out, not something this
    /// handle itself encodes).
    pub processing_handle: String,
    /// §15.5 opaque read-your-writes token, emitted only after the Evidence transaction commits.
    /// Its one encoder is the adapter token encoder; it is not an
    /// authentication token, and `recall` validates tenant/workspace against the authenticated
    /// request context separately.
    pub consistency_token: String,
    /// Trusted ticket_ordinal (§34).
    pub ticket_ordinal: Option<i32>,
    /// Trusted batch_remaining (§34).
    pub batch_remaining: Option<i64>,
    /// Trusted status (§34).
    pub status: &'static str,
}

/// Trusted application inputs. This is not a deserializable MCP request or a credential.
#[derive(Clone)]
pub struct AtomicRememberRequest {
    /// Trusted request_id (§34).
    pub request_id: Uuid,
    /// Trusted idempotency_key (§34).
    pub idempotency_key: String,
    /// Trusted request_fingerprint (§34).
    pub request_fingerprint: String,
    /// Trusted workspace_id (§34).
    pub workspace_id: Option<WorkspaceId>,
    /// Trusted reservation_ttl (§34).
    pub reservation_ttl: Duration,
    /// Trusted replay_ttl (§34).
    pub replay_ttl: Duration,
    /// Trusted command (§34).
    pub command: RememberCommand,
    /// Trusted finished_audit (§34).
    pub finished_audit: AuditEvent,
}

/// Whether a sourced put wrote new Evidence or pointed its receipt at the Evidence its source identity already held
/// (ADR-0098 D1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dedupe {
    /// This call wrote the Evidence (every unsourced put, and a replay of any key).
    New,
    /// The identity already held an Evidence with the same bytes: this call wrote a receipt, an operation and its audit
    /// rows, and no Evidence, ticket or outbox row.
    Existing,
}

/// Committed or replayed whole-write outcome (§34.0.1).
#[derive(Debug)]
pub struct AtomicRememberResult {
    /// Trusted accepted (§34).
    pub accepted: RememberAccepted,
    /// Trusted replayed (§34).
    pub replayed: bool,
    /// [`Dedupe::Existing`] only on a fresh dedupe hit. A replay reports [`Dedupe::New`]: `replayed` is its answer.
    // ponytail: a replay of a dedupe-hit key does not recompute `Existing`; upgrade path is reading the Evidence's
    // origin principal against the receipt's when the wire (M06-2) needs the distinction.
    pub dedupe: Dedupe,
    /// ADR-0067: the Memory the same transaction wrote (or, on a replay, wrote originally) for a `memory.note_put`;
    /// `None` for `remember.put`.
    pub memory_id: Option<Uuid>,
    /// §18.2: the stored Evidence is `SECRET_MATERIAL` (no card, no vector). On a replay it is read from the stored
    /// row, so a changed gateway default cannot change the answer for the same idempotency key (PR #7 Codex P2).
    /// Resolved for `memory.note_put` only; always `false` for `remember.put`.
    pub secret_material: bool,
}

/// Why a sourced put was refused (ADR-0098 D1): the terminal [`ErrorCode`] plus, for a `CONFLICT`, the §52 D-B
/// sub-reason. It adds no code of its own, so `ErrorCode` stays at 18 codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourcedPutError {
    /// The terminal code; the transaction rolled back.
    pub code: ErrorCode,
    /// `Some(SOURCE_VERSION_CONFLICT)` when the source identity already holds different bytes, else `None`. The stored
    /// bytes are untouched and the idempotency key is left unused.
    pub conflict_reason: Option<ConflictReason>,
}

impl From<ErrorCode> for SourcedPutError {
    fn from(code: ErrorCode) -> Self {
        Self {
            code,
            conflict_reason: None,
        }
    }
}

/// Whole remember write, including receipt, quota, audit, stream and in-transaction doors (§34.0.1 / §60).
#[async_trait::async_trait]
pub trait RememberStore: Send + Sync {
    /// Commit once or return the existing refusal; never split the collaborating PG doors (ADR-0130 D7a).
    async fn store(
        &self,
        authorization: &AuthorizationScope,
        request: AtomicRememberRequest,
        task_run: Option<(TaskRunId, FencingToken)>,
        project: Option<ProjectId>,
        source: Option<SourceIdentity>,
    ) -> Result<AtomicRememberResult, SourcedPutError>;
}

/// Accept one remember operation through its complete transaction port (§34.0.1 / §58).
pub async fn remember(
    store: &dyn RememberStore,
    authorization: &AuthorizationScope,
    request: AtomicRememberRequest,
    task_run: Option<(TaskRunId, FencingToken)>,
    project: Option<ProjectId>,
    source: Option<SourceIdentity>,
) -> Result<AtomicRememberResult, SourcedPutError> {
    store
        .store(authorization, request, task_run, project, source)
        .await
}

/// One note as the gateway edge validated it (ADR-0067 D-C/D-D/D-E).
#[derive(Debug, Clone)]
pub struct NoteIntake {
    /// The author's classification; selects the stored `memory_type`.
    pub kind: NoteKind,
    /// The stored title: explicit or derived (`domain::note::note_title`).
    pub title: String,
    /// The validated verbatim body and its digest.
    pub body: NoteBody,
    /// The exact authority the caller asked for (default `PrivateKnowledge`); granted as asked or refused.
    pub requested: AuthorityClass,
}

/// Commit a new note, its receipt, BMO and audit together (ADR-0067 D-A / §34.0.1).
#[async_trait::async_trait]
pub trait NoteStore: Send + Sync {
    /// Return the committed or replayed result from the original receipt transaction.
    async fn put(
        &self,
        authorization: &AuthorizationScope,
        request: AtomicRememberRequest,
        note: NoteIntake,
    ) -> Result<AtomicRememberResult, ErrorCode>;
}

/// Accept a new identity note through the complete transaction port (ADR-0067 D-A).
pub async fn put_note(
    store: &dyn NoteStore,
    authorization: &AuthorizationScope,
    request: AtomicRememberRequest,
    note: NoteIntake,
) -> Result<AtomicRememberResult, ErrorCode> {
    store.put(authorization, request, note).await
}
