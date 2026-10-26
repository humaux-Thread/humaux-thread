//! `gateway::mcp_application` — Gateway implementation of the native MCP application port.
//! Depends-on: crates=[async-trait, axum, hex, humaux-adapters, humaux-contracts, humaux-domain, humaux-protocol, humaux-testkit, postgres, serde, serde_json, time, tokio, uuid];
//!   services=[PostgreSQL(role_gateway) r=[control.rate_buckets, private.memory_records]
//!   w=[control.w2_test_request_intervals] x=[private.publish_continuity_facet, private.register_continuity_project],
//!   HTTP(gateway)]; env=[HUMAUX_CONTINUITY_DIRECT_PREAUTH_SAME_KEY, HUMAUX_CONTINUITY_W2_BARRIER_RUN_ID,
//!   HUMAUX_CONTINUITY_W2_BARRIER_SIDE]; modules=[adapters::affect_repo, adapters::byok, adapters::confirm_token_repo,
//!   adapters::continuity_repo, adapters::coord_repo, adapters::distill_repo, adapters::memory_governance_repo, adapters::note_repo,
//!   adapters::operation_receipt, adapters::postgres, adapters::read_gate, adapters::read_materialize, adapters::subject_repo,
//!   domain::affect, domain::audit, domain::authority, domain::confirm, domain::context, domain::continuity,
//!   domain::coordination, domain::dataclass, domain::error, domain::evidence, domain::identity, domain::ids, domain::note, domain::subject,
//!   gateway::bootstrap, gateway::context,
//!   gateway::continuity, gateway::guard, gateway::memory, gateway::recall, gateway::remember, protocol::mcp,
//!   protocol::mcp_catalog]
//! Called-by: [gateway::bootstrap, tests]
//! Invariants: [the canonical catalog validates wire arguments before dispatch runs; a valid contract with no local implementation is denied by GatewayGuard, never silently no-op'd]
//! Spec: Baseline §33.10; §34.0.1; §78.1; ADR-0030; ADR-0031
//!
//! The canonical catalog validates wire arguments before this fixed dispatch
//! table runs.  Only routes with a complete local implementation appear here;
//! every other valid contract is admitted and denied by [`GatewayGuard`] rather
//! than becoming a successful no-op.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use humaux_adapters::{
    affect_repo,
    byok::json_has_nul,
    confirm_token_repo::ConfirmationClaim,
    continuity_repo::{ContinuityEvidenceSource, ContinuityMemorySource},
    coord_repo,
    distill_repo::{ConfirmOutcome, RejectOutcome},
    memory_governance_repo::{self, ArchiveResult, RestoreResult},
    note_repo::NoteIntake,
    operation_receipt::{self, AtomicRememberRequest, NoteReplaceOutcome, NoteReplaceRequest},
    postgres::RuntimeDbPool,
    read_gate::{MemoryEnumerationParams, MemoryGetTarget, NoteEnumerationFilter},
    read_materialize::Lifecycle,
    subject_repo,
};
use humaux_domain::{
    affect::{AffectWriteOp, MoodHalfLife},
    audit::AuditEvent,
    authority::MemoryId,
    confirm::{ConfirmToken, DestructiveOp},
    context::BindingPurpose,
    continuity::{ContinuityFacetKind, ProjectId},
    coordination::{FencingToken, TaskRunId, TaskState},
    dataclass::DataClass,
    error::ErrorCode,
    evidence::payload_sha256,
    identity::{AuthorizationScope, VisibilityClass},
    ids::{TaskId, WorkspaceId},
    note::{
        NoteBody, NoteKind, authorize_note, note_title, parse_requested_authority,
        replace_intent_sha256,
    },
    subject::{
        SubjectDeclaration, SubjectId, SubjectKey, SubjectKeyKind, SubjectKind, SubjectRole,
        SubjectWriteOp,
    },
};
use humaux_protocol::{
    mcp::{McpApplication, McpHttpContext, McpOperation, McpToolArguments, ToolName, ToolOutput},
    mcp_catalog::{CanonicalCatalog, OperationDescriptor},
};
use serde::Deserialize;
use serde_json::{Value, json, value::RawValue};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

/// The closed argument set of the four binding ops (§36 + §25.4.A(7)/(9) + card 22c's `purpose`).
///
/// A named struct rather than a 4-tuple: the last two fields are both `Option` and both only
/// meaningful on `memory.bind`, and a positional swap between them would compile.
struct BindingWriteArguments {
    memory: MemoryId,
    task: Option<TaskId>,
    replaces_binding_id: Option<Uuid>,
    purpose: Option<BindingPurpose>,
}

use crate::{
    context::{self, ContextBootstrap},
    continuity,
    guard::{
        AuthorizedRequest, ConfirmGate, ConfirmedOutcome, ConfirmedWrite, GatewayGuard, PreMint,
    },
    memory,
    recall::{self, RecallSearchRequest, SemanticRecallRuntime},
    remember::{
        self, PreparedEvidencePayload, PutClassification, RememberEventKind, RememberPolicy,
    },
};

/// The only real MCP business routes currently available from Gateway. Confirm-gated
/// destructive keys come from the closed `DestructiveOp` table (§78.2, ADR-0018), never a
/// second literal.
///
/// This list IS the delivery-point truth of the tool surface: the Baseline's
/// 「工具面交付实况」 table (§33 Canonical MCP Tool Details) is checked against it by
/// `xtask architecture-check`'s *tool surface truth* arm, in both directions, so a tool the
/// document calls wired but this array does not carry (or the reverse) is a red gate rather
/// than a silent drift.
///
/// Card 22 found it had already drifted: `memory.correct` / `memory.confirm` / `memory.reject`
/// have had working dispatch arms since ADR-0025/ADR-0026, while this array still said 15 —
/// nothing read it, so nothing noticed. The new gate also compares it against the `invoke`
/// dispatch below, which is what makes that class of drift impossible to repeat.
pub const SUPPORTED_OPERATION_KEYS: [&str; 28] = [
    "remember.put",
    "memory.note_put",
    "recall.search",
    "context.assemble",
    "memory.get",
    "memory.enumerate",
    "memory.grep",
    "continuity.get",
    "continuity.publish",
    DestructiveOp::MemorySupersede.operation_key(),
    DestructiveOp::MemoryPin.operation_key(),
    DestructiveOp::MemoryUnpin.operation_key(),
    DestructiveOp::MemoryBind.operation_key(),
    DestructiveOp::MemoryUnbind.operation_key(),
    DestructiveOp::MemoryRestore.operation_key(),
    DestructiveOp::MemoryArchive.operation_key(),
    DestructiveOp::MemoryUnarchive.operation_key(),
    DestructiveOp::MemoryCorrect.operation_key(),
    DestructiveOp::MemoryConfirm.operation_key(),
    DestructiveOp::MemoryReject.operation_key(),
    SubjectWriteOp::Register.operation_key(),
    SubjectWriteOp::LinkKey.operation_key(),
    AffectWriteOp::Annotate.operation_key(),
    "coordinate.task_submit",
    "coordinate.task_claim",
    "coordinate.task_heartbeat",
    "coordinate.task_complete",
    "coordinate.task_fail",
];

/// Bootstrap-owned, authenticated MCP dispatch.  It has no client-selected
/// tenant, user, stream, profile, or policy fields.
pub struct GatewayMcpApplication {
    catalog: Arc<CanonicalCatalog>,
    guard: Arc<GatewayGuard>,
    runtime_pool: Arc<RuntimeDbPool>,
    remember_policy: RememberPolicy,
    remember_event_kind: RememberEventKind,
    context_bootstrap: ContextBootstrap,
    semantic_recall: Option<Arc<SemanticRecallRuntime>>,
    /// §33.10 rule 9 token lifetime (ADR-0018). `None` keeps every confirm-gated route
    /// failing closed through `reject_unsupported`.
    confirm_token_ttl: Option<Duration>,
    /// §78.1 memory.restore undo window (ADR-0020). `None` keeps memory.supersede and
    /// memory.restore failing closed (both write the lifecycle log).
    undo_window: Option<Duration>,
    /// §8.5.1 / ADR-0030 D-B frozen mood half-life policy
    /// (`HUMAUX_GATEWAY_MOOD_HALF_LIFE_SECONDS`, §78.1). `None` keeps `memory.annotate_affect`
    /// failing closed through `reject_unsupported` (a MOOD row needs the policy to stamp).
    mood_half_life: Option<MoodHalfLife>,
    /// `memory.enumerate`'s manifest lifetime and size cap (`HUMAUX_GATEWAY_ENUMERATION_TTL_SECONDS`,
    /// `HUMAUX_GATEWAY_ENUMERATION_MANIFEST_CAP`; §78.1, ADR-0062 D-K). `None` keeps `memory.enumerate` failing closed
    /// through `reject_unsupported`.
    enumeration: Option<(Duration, usize)>,
    /// §30.2 / §78.1 lease the coordinate.task_claim / task_heartbeat routes grant
    /// (`HUMAUX_GATEWAY_TASK_LEASE_TTL_SECONDS`). `None` keeps every `coordinate.task_*` route failing closed through
    /// `reject_unsupported`.
    task_lease_ttl: Option<Duration>,
    #[cfg(test)]
    trusted_continuity_scope: Option<humaux_domain::identity::AuthorizationScope>,
}

impl GatewayMcpApplication {
    pub fn new(
        catalog: CanonicalCatalog,
        guard: Arc<GatewayGuard>,
        remember_policy: RememberPolicy,
        remember_event_kind: RememberEventKind,
        context_bootstrap: ContextBootstrap,
    ) -> Self {
        let runtime_pool = guard.runtime_pool();
        Self {
            catalog: Arc::new(catalog),
            guard,
            runtime_pool,
            remember_policy,
            remember_event_kind,
            context_bootstrap,
            semantic_recall: None,
            confirm_token_ttl: None,
            undo_window: None,
            mood_half_life: None,
            enumeration: None,
            task_lease_ttl: None,
            #[cfg(test)]
            trusted_continuity_scope: None,
        }
    }

    /// Enables the `coordinate.task_*` routes with the bootstrap-owned lease TTL
    /// (`HUMAUX_GATEWAY_TASK_LEASE_TTL_SECONDS`, §30.2, §78.1). A zero TTL is refused; the upper bound is the bootstrap's.
    pub fn with_task_lease_ttl(mut self, ttl: Duration) -> Result<Self, ErrorCode> {
        if ttl.is_zero() {
            return Err(ErrorCode::InvalidInput);
        }
        self.task_lease_ttl = Some(ttl);
        Ok(self)
    }

    /// Sets the §8.5.1 mood half-life (`HUMAUX_GATEWAY_MOOD_HALF_LIFE_SECONDS`, ADR-0030 D-B).
    /// A zero half-life is refused. Until set, `memory.annotate_affect` (and `memory.correct
    /// {affects}`) fail closed through `reject_unsupported`.
    pub fn with_mood_half_life(mut self, half_life: Duration) -> Result<Self, ErrorCode> {
        self.mood_half_life = Some(MoodHalfLife::new(half_life)?);
        Ok(self)
    }

    /// Enables the confirm-gated governance routes with the bootstrap-owned token TTL
    /// (`HUMAUX_GATEWAY_CONFIRM_TOKEN_TTL_SECONDS`, §78.1). A zero TTL is refused.
    pub fn with_confirm_token_ttl(mut self, ttl: Duration) -> Result<Self, ErrorCode> {
        if ttl.is_zero() {
            return Err(ErrorCode::InvalidInput);
        }
        self.confirm_token_ttl = Some(ttl);
        Ok(self)
    }

    /// Sets the §78.1 memory.restore undo window (`HUMAUX_GATEWAY_UNDO_WINDOW_SECONDS`,
    /// ADR-0020). A zero window is refused. Until set, memory.supersede and memory.restore
    /// fail closed through `reject_unsupported` (both append to the lifecycle log).
    pub fn with_undo_window(mut self, window: Duration) -> Result<Self, ErrorCode> {
        if window.is_zero() {
            return Err(ErrorCode::InvalidInput);
        }
        self.undo_window = Some(window);
        Ok(self)
    }

    /// Enables `memory.enumerate` with the bootstrap-owned manifest lifetime and cap
    /// (`HUMAUX_GATEWAY_ENUMERATION_TTL_SECONDS` / `HUMAUX_GATEWAY_ENUMERATION_MANIFEST_CAP`, §78.1, ADR-0062 D-K).
    /// A zero TTL or cap is refused.
    pub fn with_enumeration(
        mut self,
        ttl: Duration,
        manifest_cap: usize,
    ) -> Result<Self, ErrorCode> {
        if ttl.is_zero() || manifest_cap == 0 {
            return Err(ErrorCode::InvalidInput);
        }
        self.enumeration = Some((ttl, manifest_cap));
        Ok(self)
    }

    #[cfg(test)]
    pub(crate) fn with_trusted_continuity_scope(
        mut self,
        scope: humaux_domain::identity::AuthorizationScope,
    ) -> Self {
        self.trusted_continuity_scope = Some(scope);
        self
    }

    /// Adds the native semantic lane using trusted bootstrap dependencies. Existing local-only
    /// deployments keep failing `recall.search` closed until this is configured.
    #[must_use]
    pub fn with_semantic_recall(mut self, runtime: SemanticRecallRuntime) -> Self {
        let runtime = Arc::new(runtime);
        // §23.1② (card 18): the PG-only read routes (`memory.*`, `context.assemble`) hold no
        // Qdrant transport of their own, so they borrow this one purely to take the live
        // `visible` count. This is the only place that holds both values; without it those two
        // routes would keep reporting `cannot_establish` / `index_count_unavailable` on every
        // successful read while `recall.search` reported a real ratio.
        self.context_bootstrap.attach_index_face(&runtime);
        self.semantic_recall = Some(runtime);
        self
    }

    fn validated(
        &self,
        tool: ToolName,
        arguments: McpToolArguments<'_>,
    ) -> Result<(OperationDescriptor, String, Value), ErrorCode> {
        let decoded = Value::Object(arguments.decoded().clone());
        let descriptor = self.catalog.validate(tool, &decoded)?;
        // ADR-0058 R8 (b): PostgreSQL cannot store U+0000; every operation passes here before any
        // transaction opens, so no handler sees it (it surfaced as INTERNAL from the write before).
        if json_has_nul(&decoded) {
            return Err(ErrorCode::InvalidInput);
        }
        let raw = arguments.raw_json().ok_or(ErrorCode::InvalidInput)?;
        let raw_value: Value = serde_json::from_str(raw).map_err(|_| ErrorCode::InvalidInput)?;
        if raw_value != decoded {
            return Err(ErrorCode::InvalidInput);
        }
        Ok((descriptor, raw.to_owned(), raw_value))
    }

    async fn reject_unsupported(
        &self,
        context: &McpHttpContext,
        operation: &OperationDescriptor,
        requested_workspace: Option<WorkspaceId>,
    ) -> Result<ToolOutput, ErrorCode> {
        self.guard
            .reject_unsupported(context, operation, requested_workspace)
            .await?;
        Err(ErrorCode::DependencyUnavailable)
    }

    async fn remember_put(
        &self,
        context: &McpHttpContext,
        operation: &OperationDescriptor,
        raw_arguments: &str,
        value: &Value,
    ) -> Result<ToolOutput, ErrorCode> {
        let wire = RememberPutWire::from_raw(raw_arguments, value)?;
        // §6.1.3 rules 1/2 (ADR-0028): parse the declaration here (malformed ⇒ INVALID_INPUT
        // before admission); it is RESOLVED inside `remember_in_txn`, before the Evidence is
        // written, so an unknown id/key rejects with nothing accepted or metered.
        let subjects = subject_repo::parse_declaration(value)?;
        // §8.5.1 (ADR-0030 D-C): `affects` parse here the same way (closed sets, basis-point
        // ranges ⇒ INVALID_INPUT before admission), resolve their target subjects inside
        // `remember_in_txn` before the Evidence is written, and land on `evidence_affects` in
        // that same transaction; the Distill-born memory inherits them (0157 trigger).
        let affects = affect_repo::parse_affects(value)?;
        let mood_half_life = match (affects.is_empty(), self.mood_half_life) {
            (true, _) => None,
            (false, Some(half_life)) => Some(half_life),
            (false, None) => return self.reject_unsupported(context, operation, None).await,
        };
        // ADR-0032 D-B: per-call classification within the closed sets, process defaults
        // when absent (backward compatible). Reachability of the class is judged downstream
        // (`remember::command` for scope, the receipt transaction for the TENANT_SHARED role).
        let classification = PutClassification {
            visibility_class: wire
                .visibility_class
                .unwrap_or(self.remember_policy.visibility_class()),
            data_class: wire.data_class.unwrap_or(self.remember_policy.data_class()),
            event_kind: wire.event_kind.unwrap_or(self.remember_event_kind),
        };
        // ADR-0054 D-D: no process default pair — an omitted `workspace_id` routes to the
        // credential's bound workspace (the guard's `requested.or(bound)`).
        let requested_workspace = wire.workspace_id;
        let policy = self.remember_policy.clone();
        let bootstrap = self.context_bootstrap.clone();
        let result = self
            .guard
            .run_atomic_remember(
                context,
                operation,
                requested_workspace,
                raw_arguments,
                wire.idempotency_key,
                None,
                // Design v0.2 §15 T04c: verified in the receipt transaction before any write; a refusal is the whole call.
                wire.task_run,
                // ADR-0078 D-D A1: resolved there too; unknown / foreign / archived / invisible is one INVALID_INPUT.
                wire.project_id,
                move |request| {
                    // An unbound PAT naming no workspace has no route: nothing to write to.
                    let workspace = request
                        .workspace_id()
                        .ok_or(ErrorCode::DependencyUnavailable)?;
                    // ADR-0032 D-A (§34.0.1 Q9): the write stream is derived per request at
                    // the read routes' single derivation point — principal tenant + the
                    // membership-narrowed requested workspace + the process family. Pure, no
                    // PG round trip; the pair's checkpoint row is created idempotently by the
                    // first write (`stream_repo::issue_ticket_in_txn`).
                    let (_, stream) =
                        bootstrap.request_stream(request.authorization().tenant_id(), workspace);
                    remember::command(
                        request.authorization(),
                        &policy,
                        &stream,
                        wire.content,
                        classification,
                        None,
                        OffsetDateTime::now_utc(),
                        subjects,
                        affects,
                        mood_half_life,
                    )
                },
            )
            .await?;
        let accepted = result.accepted;
        output(json!({
            "evidence_id": accepted.evidence_id,
            "processing_handle": accepted.processing_handle,
            "consistency_token": accepted.consistency_token,
            "status": accepted.status,
            "replayed": result.replayed,
        }))
    }

    /// ADR-0067 D-A `memory.note_put`: the verbatim note lane. The same receipt transaction as `remember.put` writes the
    /// Evidence, the identity contract and the authorised Memory; the response names the real `memory_id`. An above-ceiling
    /// `requested_authority` is the business refusal `AUTHORITY_CEILING_EXCEEDED` (`isError`), nothing stored.
    async fn memory_note_put(
        &self,
        context: &McpHttpContext,
        operation: &OperationDescriptor,
        raw_arguments: &str,
        value: &Value,
    ) -> Result<ToolOutput, ErrorCode> {
        let wire = NotePutWire::from_raw(raw_arguments, value)?;
        if let Some((note_id, supersedes)) = wire.replace {
            return self
                .memory_note_replace(context, operation, raw_arguments, wire, note_id, supersedes)
                .await;
        }
        let subjects = subject_repo::parse_declaration(value)?;
        let affects = affect_repo::parse_affects(value)?;
        let mood_half_life = match (affects.is_empty(), self.mood_half_life) {
            (true, _) => None,
            (false, Some(half_life)) => Some(half_life),
            (false, None) => return self.reject_unsupported(context, operation, None).await,
        };
        let classification = PutClassification {
            visibility_class: wire
                .visibility_class
                .unwrap_or(self.remember_policy.visibility_class()),
            data_class: wire.data_class.unwrap_or(self.remember_policy.data_class()),
            event_kind: RememberEventKind::ManualNote,
        };
        let policy = self.remember_policy.clone();
        let bootstrap = self.context_bootstrap.clone();
        let (kind, requested) = (wire.note.kind, wire.note.requested);
        // The refusal is decided after admission (inside `prepare`), so an unauthenticated caller learns nothing about the
        // ceiling; the closure can only return an `ErrorCode`, so it leaves the business refusal here.
        let mut refused = false;
        let refused_slot = &mut refused;
        let result = self
            .guard
            .run_atomic_remember(
                context,
                operation,
                wire.workspace_id,
                raw_arguments,
                wire.idempotency_key,
                Some(wire.note),
                None,
                None,
                move |request| {
                    if authorize_note(kind, requested).is_err() {
                        *refused_slot = true;
                        return Err(ErrorCode::Forbidden);
                    }
                    let workspace = request
                        .workspace_id()
                        .ok_or(ErrorCode::DependencyUnavailable)?;
                    let (_, stream) =
                        bootstrap.request_stream(request.authorization().tenant_id(), workspace);
                    let now = OffsetDateTime::now_utc();
                    remember::command(
                        request.authorization(),
                        &policy,
                        &stream,
                        wire.content,
                        classification,
                        // D-G: an identity note's occurred_at is the server receipt time.
                        Some(now),
                        now,
                        subjects,
                        affects,
                        mood_half_life,
                    )
                },
            )
            .await;
        if refused && matches!(result, Err(ErrorCode::Forbidden)) {
            return self.ceiling_refusal(&wire.requested_authority_wire);
        }
        let stored = result?;
        // §18.2: a SECRET_MATERIAL Memory never gets a card or a vector — the response must not promise indexing. Read
        // from the stored Evidence (a replay answers for the original write, not the current default; PR #7 Codex P2).
        let indexing = if stored.secret_material {
            "excluded"
        } else {
            "scheduled"
        };
        let memory_id = stored.memory_id.ok_or(ErrorCode::Internal)?;
        let value = json!({
            "memory_id": memory_id,
            // ADR-0067 D-J: a fresh note's note_id is its first version's memory_id.
            "note_id": memory_id,
            "evidence_id": stored.accepted.evidence_id,
            "consistency_token": stored.accepted.consistency_token,
            "status": "stored",
            "indexing": indexing,
        });
        self.catalog.validate_output(ToolName::Memory, &value)?;
        output(value)
    }

    /// ADR-0067 D-C: the business refusal `AUTHORITY_CEILING_EXCEEDED` (`isError`), nothing stored.
    fn ceiling_refusal(&self, requested_authority_wire: &str) -> Result<ToolOutput, ErrorCode> {
        self.business_refusal(json!({
            "code": "AUTHORITY_CEILING_EXCEEDED",
            "requested_authority": requested_authority_wire,
            "origin": "AuthenticatedAgent",
            "reason": "the requested authority exceeds the ceiling of the server-fixed origin; nothing was stored",
        }))
    }

    /// A `memory.note_put` business refusal: a validated result shape carried with `isError` (§52.1 keeps 18 codes).
    fn business_refusal(&self, value: Value) -> Result<ToolOutput, ErrorCode> {
        self.catalog.validate_output(ToolName::Memory, &value)?;
        let mut refusal = output(value)?;
        refusal.is_error = true;
        Ok(refusal)
    }

    /// ADR-0067 D-J `memory.note_put` with `note_id` + `supersedes`: a replacement through the shared ADR-0018 gate, the
    /// token bound to the intent digest `H` (`note::replace_intent_sha256`). First call: the pre-mint leg runs the
    /// transaction's checks without writing — a committed key answers its stored result, a stale `supersedes` is the
    /// business refusal `STALE_NOTE_VERSION`, an invisible note `NOT_FOUND` — and only then a token is minted (0 BMO).
    /// Second call: `operation_receipt::note_replace_atomically` commits the new version.
    #[allow(clippy::too_many_lines)] // one gate call with its two legs and the three result shapes it can render
    async fn memory_note_replace(
        &self,
        context: &McpHttpContext,
        operation: &OperationDescriptor,
        raw_arguments: &str,
        wire: NotePutWire,
        note_id: Uuid,
        supersedes: Uuid,
    ) -> Result<ToolOutput, ErrorCode> {
        let Some(ttl) = self.confirm_token_ttl else {
            return self.reject_unsupported(context, operation, None).await;
        };
        let intent = replace_intent_sha256(
            note_id,
            supersedes,
            wire.note.kind,
            &wire.note.title,
            &wire.note.body,
            wire.note.requested,
            &wire.idempotency_key,
        );
        // D-C: decided after admission (inside the legs), so an unauthenticated caller learns nothing about the ceiling.
        let ceiling_exceeded = authorize_note(wire.note.kind, wire.note.requested).is_err();
        let (refused, stale) = (AtomicBool::new(false), AtomicBool::new(false));
        let (refused_flag, stale_flag) = (&refused, &stale);
        let requested_authority_wire = wire.requested_authority_wire;
        let leg = NoteReplaceLeg {
            pool: self.runtime_pool.clone(),
            bootstrap: self.context_bootstrap.clone(),
            policy: self.remember_policy.clone(),
            content: wire.content,
            note: wire.note,
            idempotency_key: wire.idempotency_key,
            note_id,
            supersedes,
            intent,
        };
        let commit_leg = leg.clone();
        let outcome = self
            .guard
            .run_confirmed_write_checked(
                context,
                operation,
                wire.workspace_id,
                raw_arguments,
                ConfirmGate {
                    op: DestructiveOp::MemoryNoteReplace,
                    target_id: supersedes,
                    successor_id: None,
                    presented: wire.confirm_token,
                    ttl,
                    request_sha256: Some(intent),
                },
                move |pre: PreMint| async move {
                    let checked = if ceiling_exceeded {
                        refused_flag.store(true, Ordering::Relaxed);
                        Err(ErrorCode::Forbidden)
                    } else {
                        leg.run(
                            pre.request,
                            pre.finished_audit,
                            pre.reservation_ttl,
                            pre.replay_ttl,
                            None,
                        )
                        .await
                    };
                    match checked {
                        Ok(NoteReplaceOutcome::Stored(done)) => Ok(Some(done)),
                        Ok(NoteReplaceOutcome::Confirmable) => Ok(None),
                        Ok(NoteReplaceOutcome::StaleVersion) => {
                            stale_flag.store(true, Ordering::Relaxed);
                            Err(ErrorCode::Conflict)
                        }
                        Err(code) => Err(code),
                    }
                },
                move |write: ConfirmedWrite| async move {
                    let committed = if ceiling_exceeded {
                        refused_flag.store(true, Ordering::Relaxed);
                        Err(ErrorCode::Forbidden)
                    } else {
                        commit_leg
                            .run(
                                write.request,
                                write.finished_audit,
                                write.reservation_ttl,
                                write.replay_ttl,
                                Some(write.claim),
                            )
                            .await
                    };
                    match committed {
                        Ok(NoteReplaceOutcome::Stored(done)) => Ok(done),
                        Ok(NoteReplaceOutcome::StaleVersion) => {
                            stale_flag.store(true, Ordering::Relaxed);
                            Err(ErrorCode::Conflict)
                        }
                        Ok(NoteReplaceOutcome::Confirmable) => Err(ErrorCode::Internal),
                        Err(code) => Err(code),
                    }
                },
            )
            .await;
        if refused.load(Ordering::Relaxed) && matches!(outcome, Err(ErrorCode::Forbidden)) {
            return self.ceiling_refusal(&requested_authority_wire);
        }
        if stale.load(Ordering::Relaxed) && matches!(outcome, Err(ErrorCode::Conflict)) {
            return self.business_refusal(json!({
                "code": "STALE_NOTE_VERSION",
                "note_id": note_id,
                "supersedes": supersedes,
                "reason": "supersedes is not the note's current version; nothing was written",
            }));
        }
        let value = match outcome? {
            ConfirmedOutcome::ConfirmationRequired { token, expires_at } => json!({
                "confirmation_required": true,
                "confirm_token": token.encode(),
                "operation": operation.operation_key(),
                "target": { "memory_id": supersedes, "note_id": note_id },
                "expires_at": rfc3339(expires_at)?,
            }),
            ConfirmedOutcome::Executed(stored) => {
                // §18.2, read from the stored Evidence as on create.
                let indexing = if stored.secret_material {
                    "excluded"
                } else {
                    "scheduled"
                };
                json!({
                    "memory_id": stored.memory_id.ok_or(ErrorCode::Internal)?,
                    "note_id": note_id,
                    "supersedes": supersedes,
                    "evidence_id": stored.accepted.evidence_id,
                    "consistency_token": stored.accepted.consistency_token,
                    "status": "stored",
                    "indexing": indexing,
                })
            }
        };
        self.catalog.validate_output(ToolName::Memory, &value)?;
        output(value)
    }

    async fn context_assemble(
        &self,
        context: &McpHttpContext,
        operation: &OperationDescriptor,
        raw_arguments: &str,
        value: &Value,
    ) -> Result<ToolOutput, ErrorCode> {
        let requested_workspace = workspace(value)?;
        // card 22b review fix: `task_id` IS served now — it is the §25.4.A(7) TaskId the two
        // binding-backed selectors read, and leaving it on the fail-closed list meant the task
        // dimension could not be exercised on the wire at all. `context_repo` resolves it
        // against `coord.tasks` in the assemble transaction (NotFound when it names nothing).
        let requested_task = value
            .get("task_id")
            .map(|raw| {
                Uuid::parse_str(raw.as_str().ok_or(ErrorCode::InvalidInput)?)
                    .map_err(|_| ErrorCode::InvalidInput)
            })
            .transpose()?
            .map(TaskId);
        // These schema fields are valid contracts but this concrete route has no
        // semantics for them yet.  Admit/audit the request and then fail closed.
        if ["project_id", "query", "limit"]
            .iter()
            .any(|field| value.get(*field).is_some())
        {
            return self
                .reject_unsupported(context, operation, requested_workspace)
                .await;
        }
        let pool = self.runtime_pool.clone();
        let bootstrap = self.context_bootstrap.clone();
        let catalog = self.catalog.clone();
        let pending = self
            .guard
            .run_local_read(
                context,
                operation,
                requested_workspace,
                raw_arguments,
                move |request| async move {
                    context::assemble(
                        pool,
                        request.authorization().clone(),
                        request.workspace_id(),
                        requested_task,
                        bootstrap,
                        |result| {
                            let value =
                                serde_json::to_value(result).map_err(|_| ErrorCode::Internal)?;
                            catalog.validate_output(ToolName::Context, &value)?;
                            output(value)
                        },
                    )
                    .await
                },
            )
            .await?;
        // Failed output validation, quota settlement or audit drops the pending result.
        // Only the accepted result may publish its final completeness metric.
        Ok(pending.finish())
    }

    async fn memory_get(
        &self,
        context: &McpHttpContext,
        operation: &OperationDescriptor,
        raw_arguments: &str,
        value: &Value,
    ) -> Result<ToolOutput, ErrorCode> {
        // ADR-0067 D-J2: `memory_id` XOR `note_id` is the input schema's `oneOf`, enforced for every handler by
        // `CanonicalCatalog::validate` in `validated()`; only the id present is parsed, never a fallback between them.
        let target = match value.get("note_id") {
            Some(note_id) => MemoryGetTarget::Note(
                note_id
                    .as_str()
                    .and_then(|id| Uuid::parse_str(id).ok())
                    .ok_or(ErrorCode::InvalidInput)?,
            ),
            None => MemoryGetTarget::Memory(MemoryId::parse(
                value
                    .get("memory_id")
                    .and_then(Value::as_str)
                    .ok_or(ErrorCode::InvalidInput)?,
            )?),
        };
        let requested_workspace = workspace(value)?;
        // ADR-0067 D-H: absent = false, the pre-40b contract.
        let include_history = value
            .get("include_history")
            .map(|v| v.as_bool().ok_or(ErrorCode::InvalidInput))
            .transpose()?
            .unwrap_or(false);
        let pool = self.runtime_pool.clone();
        let bootstrap = self.context_bootstrap.clone();
        let catalog = self.catalog.clone();
        let pending = self
            .guard
            .run_local_read(
                context,
                operation,
                requested_workspace,
                raw_arguments,
                move |request| async move {
                    memory::get(
                        pool,
                        request.authorization().clone(),
                        request.workspace_id(),
                        bootstrap,
                        target,
                        include_history,
                        |result| {
                            let value =
                                serde_json::to_value(result).map_err(|_| ErrorCode::Internal)?;
                            catalog.validate_output(ToolName::Memory, &value)?;
                            output(value)
                        },
                    )
                    .await
                },
            )
            .await?;
        Ok(pending.finish())
    }

    async fn continuity_get(
        &self,
        context: &McpHttpContext,
        operation: &OperationDescriptor,
        raw_arguments: &str,
        value: &Value,
    ) -> Result<ToolOutput, ErrorCode> {
        let project_id = ProjectId::parse(
            value["project_id"]
                .as_str()
                .ok_or(ErrorCode::InvalidInput)?,
        )?;
        let requested_workspace = workspace(value)?;
        let pool = self.runtime_pool.clone();
        let budget = self.context_bootstrap.budget();
        let catalog = self.catalog.clone();
        #[cfg(test)]
        if let Some(authorization) = self.trusted_continuity_scope.clone() {
            return self
                .guard
                .run_continuity_read_with_trusted_scope(
                    context,
                    operation,
                    requested_workspace,
                    raw_arguments,
                    authorization,
                    move |request| async move {
                        continuity::get(
                            pool,
                            request.authorization().clone(),
                            project_id,
                            request.workspace_id(),
                            budget,
                            |result| {
                                let value = serde_json::to_value(result)
                                    .map_err(|_| ErrorCode::Internal)?;
                                catalog.validate_output(ToolName::Continuity, &value)?;
                                output(value)
                            },
                        )
                        .await
                    },
                )
                .await;
        }
        self.guard
            .run_continuity_read(
                context,
                operation,
                requested_workspace,
                raw_arguments,
                move |request| async move {
                    continuity::get(
                        pool,
                        request.authorization().clone(),
                        project_id,
                        request.workspace_id(),
                        budget,
                        |result| {
                            let value =
                                serde_json::to_value(result).map_err(|_| ErrorCode::Internal)?;
                            catalog.validate_output(ToolName::Continuity, &value)?;
                            output(value)
                        },
                    )
                    .await
                },
            )
            .await
    }

    /// ADR-0094 `continuity.publish`: the accepted-write path over [`GatewayGuard::run_local_write`]. The
    /// catalog has already checked the facet kind is one of the nine publishable ones; the adapter owns the
    /// transaction, the in-transaction slot read and the compare-and-set. A lost CAS is a successful
    /// `{code:"CONFLICT", reason, reason_label, current_slot_version}` result (§52 D-B), never a write.
    async fn continuity_publish(
        &self,
        context: &McpHttpContext,
        operation: &OperationDescriptor,
        raw_arguments: &str,
        value: &Value,
    ) -> Result<ToolOutput, ErrorCode> {
        let project_id = ProjectId::parse(
            value["project_id"]
                .as_str()
                .ok_or(ErrorCode::InvalidInput)?,
        )?;
        let facet_kind = value["facet_kind"]
            .as_str()
            .ok_or(ErrorCode::InvalidInput)?
            .parse::<ContinuityFacetKind>()?;
        let body = value.get("body").ok_or(ErrorCode::InvalidInput)?.clone();
        let (memories, evidence) = publish_sources(value)?;
        let removals = publish_removals(value)?;
        let requested_workspace = workspace(value)?;
        let pool = self.runtime_pool.clone();
        let catalog = self.catalog.clone();
        self.guard
            .run_local_write(
                context,
                operation,
                requested_workspace,
                raw_arguments,
                move |request| async move {
                    let workspace_id = request.workspace_id().ok_or(ErrorCode::InvalidInput)?;
                    let outcome = continuity::publish(
                        pool,
                        request.authorization().clone(),
                        continuity::PublishFacetCommand {
                            project_id,
                            workspace_id,
                            facet_kind,
                            body,
                            memories,
                            evidence,
                            removals,
                        },
                    )
                    .await?;
                    let value = publish_output(&outcome);
                    catalog.validate_output(ToolName::Continuity, &value)?;
                    output(value)
                },
            )
            .await
    }

    /// ADR-0069 `memory.grep`: the enumerate read gate (same admission, workspace rule and cursor lifetime), a literal
    /// line search instead of a manifest. No enumeration TTL configured ⇒ fail closed like `memory.enumerate`.
    async fn memory_grep(
        &self,
        context: &McpHttpContext,
        operation: &OperationDescriptor,
        raw_arguments: &str,
        value: &Value,
    ) -> Result<ToolOutput, ErrorCode> {
        let requested_workspace = workspace(value)?;
        let Some((ttl, _)) = self.enumeration else {
            return self.reject_unsupported(context, operation, None).await;
        };
        let pattern = value
            .get("pattern")
            .and_then(Value::as_str)
            .ok_or(ErrorCode::InvalidInput)?
            .to_owned();
        let page_size = u16::try_from(
            value
                .get("limit")
                .map_or(Ok(50), |v| v.as_u64().ok_or(ErrorCode::InvalidInput))?,
        )
        .map_err(|_| ErrorCode::InvalidInput)?;
        let cursor = value
            .get("cursor")
            .map(|v| v.as_str().map(str::to_owned).ok_or(ErrorCode::InvalidInput))
            .transpose()?;
        let statuses: Option<Vec<&str>> = value
            .get("statuses")
            .map(|v| {
                v.as_array()
                    .ok_or(ErrorCode::InvalidInput)?
                    .iter()
                    .map(|s| s.as_str().ok_or(ErrorCode::InvalidInput))
                    .collect()
            })
            .transpose()?;
        let archive = value
            .get("archive")
            .map(|v| v.as_str().ok_or(ErrorCode::InvalidInput))
            .transpose()?;
        let lifecycle = Lifecycle::for_enumerate(statuses.as_deref(), archive)?;
        let pool = self.runtime_pool.clone();
        let bootstrap = self.context_bootstrap.clone();
        let catalog = self.catalog.clone();
        let mac_key = self.guard.enumeration_mac_key();
        self.guard
            .run_local_read(
                context,
                operation,
                requested_workspace,
                raw_arguments,
                move |request| async move {
                    let value = memory::grep(
                        pool,
                        request.authorization().clone(),
                        request.workspace_id(),
                        bootstrap,
                        memory::GrepParams {
                            pattern: &pattern,
                            lifecycle,
                            page_size,
                            cursor: cursor.as_deref(),
                            ttl,
                            mac_key: &mac_key,
                        },
                    )
                    .await?;
                    catalog.validate_output(ToolName::Memory, &value)?;
                    output(value)
                },
            )
            .await
    }

    async fn memory_enumerate(
        &self,
        context: &McpHttpContext,
        operation: &OperationDescriptor,
        raw_arguments: &str,
        value: &Value,
    ) -> Result<ToolOutput, ErrorCode> {
        let requested_workspace = workspace(value)?;
        // ADR-0067 D-G: the note axes narrow the memory manifest only; the candidate and subject listings below would
        // silently drop them (and skip the window check), so the combination is refused.
        if (value.get("candidates").and_then(Value::as_bool) == Some(true)
            || value.get("subjects").and_then(Value::as_bool) == Some(true))
            && [
                "note_kinds",
                "since",
                "until",
                "statuses",
                "archive",
                "note_id",
            ]
            .iter()
            .any(|key| value.get(*key).is_some())
        {
            return Err(ErrorCode::InvalidInput);
        }
        // ADR-0026 D-E: `{candidates:true}` lists PENDING distill candidates instead of memories
        // (same read gate + workspace rule). The smaller schema change vs. a new op.
        if value.get("candidates").and_then(Value::as_bool) == Some(true) {
            return self
                .memory_enumerate_candidates(context, operation, raw_arguments, value)
                .await;
        }
        // ADR-0028: `{subjects:true}` lists the tenant's registered subjects (§6.1.3) — the
        // registry read-back, same read gate + workspace rule.
        if value.get("subjects").and_then(Value::as_bool) == Some(true) {
            return self
                .memory_enumerate_subjects(context, operation, raw_arguments, value)
                .await;
        }
        let Some((ttl, manifest_cap)) = self.enumeration else {
            return self.reject_unsupported(context, operation, None).await;
        };
        let page_size = u16::try_from(
            value
                .get("limit")
                .map_or(Ok(50), |v| v.as_u64().ok_or(ErrorCode::InvalidInput))?,
        )
        .map_err(|_| ErrorCode::InvalidInput)?;
        let cursor = value
            .get("cursor")
            .map(|v| v.as_str().map(str::to_owned).ok_or(ErrorCode::InvalidInput))
            .transpose()?;
        // §6.1.3 D-D (ADR-0028): an exact subject filter on the manifest predicate.
        let subject_id = value
            .get("subject_id")
            .map(|v| SubjectId::parse(v.as_str().ok_or(ErrorCode::InvalidInput)?))
            .transpose()?
            .map(|id| id.0);
        let notes = note_enumeration_filter(value)?;
        // ADR-0067 D-J2: items carry `status` whenever the request named `statuses`.
        let with_status = value.get("statuses").is_some();
        let pool = self.runtime_pool.clone();
        let bootstrap = self.context_bootstrap.clone();
        let catalog = self.catalog.clone();
        let mac_key = self.guard.enumeration_mac_key();
        let pending = self
            .guard
            .run_local_read(
                context,
                operation,
                requested_workspace,
                raw_arguments,
                move |request| async move {
                    memory::enumerate(
                        pool,
                        request.authorization().clone(),
                        request.workspace_id(),
                        bootstrap,
                        MemoryEnumerationParams {
                            cursor: cursor.as_deref(),
                            page_size,
                            ttl,
                            manifest_cap,
                            mac_key: &mac_key,
                            subject_id,
                        },
                        notes,
                        with_status,
                        |result| {
                            let value =
                                serde_json::to_value(result).map_err(|_| ErrorCode::Internal)?;
                            catalog.validate_output(ToolName::Memory, &value)?;
                            output(value)
                        },
                    )
                    .await
                },
            )
            .await?;
        Ok(pending.finish())
    }

    /// ADR-0026 D-E: `memory.enumerate {candidates:true}` — the tenant's PENDING distill
    /// candidates visible to the caller. Same read gate as memory.enumerate.
    async fn memory_enumerate_candidates(
        &self,
        context: &McpHttpContext,
        operation: &OperationDescriptor,
        raw_arguments: &str,
        value: &Value,
    ) -> Result<ToolOutput, ErrorCode> {
        let requested_workspace = workspace(value)?;
        let limit = i64::try_from(
            value
                .get("limit")
                .map_or(Ok(50), |v| v.as_u64().ok_or(ErrorCode::InvalidInput))?,
        )
        .map_err(|_| ErrorCode::InvalidInput)?
        .clamp(1, 100);
        let pool = self.runtime_pool.clone();
        let bootstrap = self.context_bootstrap.clone();
        let catalog = self.catalog.clone();
        self.guard
            .run_local_read(
                context,
                operation,
                requested_workspace,
                raw_arguments,
                move |request| async move {
                    let result = memory::list_candidates(
                        pool,
                        request.authorization().clone(),
                        request.workspace_id(),
                        bootstrap,
                        limit,
                    )
                    .await?;
                    let value = serde_json::to_value(result).map_err(|_| ErrorCode::Internal)?;
                    catalog.validate_output(ToolName::Memory, &value)?;
                    output(value)
                },
            )
            .await
    }

    /// §6.1.3 / ADR-0028: `memory.enumerate {subjects:true}` — the tenant's registered subjects
    /// with keys and roles, under RLS. Same read gate as memory.enumerate.
    async fn memory_enumerate_subjects(
        &self,
        context: &McpHttpContext,
        operation: &OperationDescriptor,
        raw_arguments: &str,
        value: &Value,
    ) -> Result<ToolOutput, ErrorCode> {
        let requested_workspace = workspace(value)?;
        let limit = i64::try_from(
            value
                .get("limit")
                .map_or(Ok(50), |v| v.as_u64().ok_or(ErrorCode::InvalidInput))?,
        )
        .map_err(|_| ErrorCode::InvalidInput)?
        .clamp(1, 100);
        let pool = self.runtime_pool.clone();
        let bootstrap = self.context_bootstrap.clone();
        let catalog = self.catalog.clone();
        self.guard
            .run_local_read(
                context,
                operation,
                requested_workspace,
                raw_arguments,
                move |request| async move {
                    let result = memory::list_subjects(
                        pool,
                        request.authorization().clone(),
                        request.workspace_id(),
                        bootstrap,
                        limit,
                    )
                    .await?;
                    let value = serde_json::to_value(result).map_err(|_| ErrorCode::Internal)?;
                    catalog.validate_output(ToolName::Memory, &value)?;
                    output(value)
                },
            )
            .await
    }

    /// §6.1.3 / ADR-0028 D-F (card 7 D-E1): `memory.subject_register` / `memory.subject_link_key`
    /// — the two non-destructive registry writes, through the guard's admitted-write runner (no
    /// confirm gate). Kinds/roles/key kinds are the closed domain sets; anything else is
    /// INVALID_INPUT before admission.
    async fn memory_subject_write(
        &self,
        context: &McpHttpContext,
        operation: &OperationDescriptor,
        raw_arguments: &str,
        value: &Value,
        op: SubjectWriteOp,
    ) -> Result<ToolOutput, ErrorCode> {
        let requested_workspace = workspace(value)?;
        let text = |field: &str| -> Result<String, ErrorCode> {
            value
                .get(field)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(ErrorCode::InvalidInput)
        };
        enum Write {
            Register {
                kind: SubjectKind,
                display_name: String,
                roles: Vec<SubjectRole>,
            },
            LinkKey {
                subject_id: SubjectId,
                key: SubjectKey,
            },
        }
        let write = match op {
            SubjectWriteOp::Register => Write::Register {
                kind: SubjectKind::parse(&text("kind")?).ok_or(ErrorCode::InvalidInput)?,
                display_name: text("display_name")?,
                roles: match value.get("roles") {
                    None => Vec::new(),
                    Some(list) => list
                        .as_array()
                        .ok_or(ErrorCode::InvalidInput)?
                        .iter()
                        .map(|r| {
                            r.as_str()
                                .and_then(SubjectRole::parse)
                                .ok_or(ErrorCode::InvalidInput)
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                },
            },
            SubjectWriteOp::LinkKey => Write::LinkKey {
                subject_id: SubjectId::parse(&text("subject_id")?)?,
                key: SubjectKey::new(
                    SubjectKeyKind::parse(&text("kind")?).ok_or(ErrorCode::InvalidInput)?,
                    text("value")?,
                )?,
            },
        };
        let pool = self.runtime_pool.clone();
        let bootstrap = self.context_bootstrap.clone();
        let catalog = self.catalog.clone();
        self.guard
            .run_local_write(
                context,
                operation,
                requested_workspace,
                raw_arguments,
                move |request| async move {
                    let authorization = request.authorization().clone();
                    let workspace = request.workspace_id();
                    let subject = match write {
                        Write::Register {
                            kind,
                            display_name,
                            roles,
                        } => {
                            memory::register_subject(
                                pool,
                                authorization,
                                workspace,
                                bootstrap,
                                kind,
                                display_name,
                                roles,
                            )
                            .await?
                        }
                        Write::LinkKey { subject_id, key } => {
                            memory::link_subject_key(
                                pool,
                                authorization,
                                workspace,
                                bootstrap,
                                subject_id,
                                key,
                            )
                            .await?
                        }
                    };
                    let value = serde_json::to_value(subject).map_err(|_| ErrorCode::Internal)?;
                    catalog.validate_output(ToolName::Memory, &value)?;
                    output(value)
                },
            )
            .await
    }

    /// §8.5.1 / ADR-0030 D-C `memory.annotate_affect` — the non-destructive affect write,
    /// through the guard's admitted-write runner (no confirm gate, like the subject registry
    /// ops). Kinds/labels/scope kinds are the closed domain sets and every basis-point value is
    /// range-checked by the domain constructors: anything outside is INVALID_INPUT before
    /// admission, never clamped.
    async fn memory_annotate_affect(
        &self,
        context: &McpHttpContext,
        operation: &OperationDescriptor,
        raw_arguments: &str,
        value: &Value,
    ) -> Result<ToolOutput, ErrorCode> {
        let memory_id =
            MemoryId::parse(value["memory_id"].as_str().ok_or(ErrorCode::InvalidInput)?)?;
        let inputs = affect_repo::parse_affects(value)?;
        if inputs.is_empty() {
            return Err(ErrorCode::InvalidInput);
        }
        let requested_workspace = workspace(value)?;
        let Some(mood_half_life) = self.mood_half_life else {
            return self
                .reject_unsupported(context, operation, requested_workspace)
                .await;
        };
        let pool = self.runtime_pool.clone();
        let bootstrap = self.context_bootstrap.clone();
        let catalog = self.catalog.clone();
        self.guard
            .run_local_write(
                context,
                operation,
                requested_workspace,
                raw_arguments,
                move |request| async move {
                    let result = memory::annotate_affect(
                        pool,
                        request.authorization().clone(),
                        request.workspace_id(),
                        bootstrap,
                        memory_id,
                        inputs,
                        mood_half_life,
                    )
                    .await?;
                    let value = serde_json::to_value(result).map_err(|_| ErrorCode::Internal)?;
                    catalog.validate_output(ToolName::Memory, &value)?;
                    output(value)
                },
            )
            .await
    }

    /// ADR-0078 Q10 `coordinate.task_submit` / `task_claim` / `task_heartbeat` / `task_complete` / `task_fail`, through the
    /// guard's admitted-write runner (no confirm gate: a task write deletes and supersedes nothing). The lease owner is
    /// the authenticated principal inside `coord_repo`, never a wire field; `task_run_id` and `fencing_token` reach the
    /// repository exactly as the client sent them, so §30.2's stale-writer judgement stays the repository's. A run that
    /// does not belong to the named `task_id` is `NOT_FOUND` before any write. Wire shape errors are `INVALID_INPUT`
    /// before admission.
    // ponytail: task_submit has no idempotency key in the frozen contract, so a retry after a lost response creates a
    // second task; add one to coordinate.schema.json (and coord.tasks) when a caller needs retry-safe submit.
    async fn coordinate_task(
        &self,
        context: &McpHttpContext,
        operation: &OperationDescriptor,
        raw_arguments: &str,
        value: &Value,
        op: TaskOp,
    ) -> Result<ToolOutput, ErrorCode> {
        let wire = TaskWire::parse(op, value)?;
        let Some(lease_ttl) = self.task_lease_ttl else {
            return self.reject_unsupported(context, operation, None).await;
        };
        let pool = self.runtime_pool.clone();
        let catalog = self.catalog.clone();
        self.guard
            .run_local_write(
                context,
                operation,
                None,
                raw_arguments,
                move |request| async move {
                    let scope = request.authorization();
                    let result = match wire {
                        TaskWire::Submit { title, description } => {
                            let task = coord_repo::submit(&pool, scope, &title, &description).await?;
                            json!({"task_id": task.0})
                        }
                        TaskWire::Claim { task } => {
                            let claimed = coord_repo::claim(&pool, scope, task, lease_ttl).await?;
                            json!({
                                "task_run_id": claimed.task_run_id.0,
                                "fencing_token": claimed.fencing_token.0,
                                "lease_expires_at": rfc3339(claimed.lease_expires_at)?,
                            })
                        }
                        TaskWire::Heartbeat { run } => {
                            run.belongs_to_task(&pool, scope).await?;
                            let expires =
                                coord_repo::heartbeat(&pool, scope, run.run, run.token, lease_ttl)
                                    .await?;
                            json!({"lease_expires_at": rfc3339(expires)?})
                        }
                        TaskWire::Complete { run, summary } => {
                            run.belongs_to_task(&pool, scope).await?;
                            coord_repo::complete(&pool, scope, run.run, run.token, &summary)
                                .await?;
                            json!({"task_id": run.task.0, "state": TaskState::Completed.as_db_str()})
                        }
                        TaskWire::Fail { run, summary } => {
                            run.belongs_to_task(&pool, scope).await?;
                            coord_repo::fail(&pool, scope, run.run, run.token, &summary).await?;
                            json!({"task_id": run.task.0, "state": TaskState::Failed.as_db_str()})
                        }
                    };
                    catalog.validate_output(ToolName::Coordinate, &result)?;
                    output(result)
                },
            )
            .await
    }

    /// §36 `memory.supersede` through the shared §33.10 confirm gate (ADR-0018). The
    /// schema carries no `workspace_id`: the route is the credential's bound workspace, and the
    /// write stream is derived per request from it exactly like the reads and `remember.put`
    /// (ADR-0031 / ADR-0032 / ADR-0054 — no process-bound pair); the token binds that workspace.
    async fn memory_supersede(
        &self,
        context: &McpHttpContext,
        operation: &OperationDescriptor,
        raw_arguments: &str,
        value: &Value,
    ) -> Result<ToolOutput, ErrorCode> {
        let target = MemoryId::parse(value["memory_id"].as_str().ok_or(ErrorCode::InvalidInput)?)?;
        let successor = MemoryId::parse(
            value["replacement_memory_id"]
                .as_str()
                .ok_or(ErrorCode::InvalidInput)?,
        )?;
        let presented = value
            .get("confirm_token")
            .map(|token| {
                token
                    .as_str()
                    .ok_or(ErrorCode::InvalidInput)
                    .and_then(ConfirmToken::decode)
            })
            .transpose()?;
        let (Some(ttl), Some(undo_window)) = (self.confirm_token_ttl, self.undo_window) else {
            return self.reject_unsupported(context, operation, None).await;
        };
        let pool = self.runtime_pool.clone();
        let pre_pool = self.runtime_pool.clone();
        let bootstrap = self.context_bootstrap.clone();
        let outcome = self
            .guard
            .run_confirmed_write_checked(
                context,
                operation,
                None,
                raw_arguments,
                ConfirmGate {
                    op: DestructiveOp::MemorySupersede,
                    target_id: target.0,
                    successor_id: Some(successor.0),
                    presented,
                    ttl,
                    request_sha256: None,
                },
                // ADR-0067 D-J (G26): neither operand may be a note; refused before any token exists.
                move |pre: PreMint| async move {
                    memory_governance_repo::refuse_note_targets(
                        &pre_pool,
                        pre.request.authorization(),
                        &[target.0, successor.0],
                    )
                    .await
                    .map(|()| None)
                },
                move |write| async move {
                    memory::supersede(pool, write, bootstrap, target, successor, undo_window).await
                },
            )
            .await?;
        match outcome {
            ConfirmedOutcome::ConfirmationRequired { token, expires_at } => {
                let value = json!({
                    "confirmation_required": true,
                    "confirm_token": token.encode(),
                    "operation": operation.operation_key(),
                    "target": {
                        "memory_id": target.0,
                        "replacement_memory_id": successor.0,
                    },
                    "expires_at": rfc3339(expires_at)?,
                });
                // Both supersede results are branches of memory.output.schema.json (tools/list
                // advertises it); validate like every other memory arm so the wire contract
                // cannot drift silently.
                self.catalog.validate_output(ToolName::Memory, &value)?;
                output(value)
            }
            ConfirmedOutcome::Executed(done) => {
                let value = json!({
                    "memory_id": target.0,
                    "replacement_memory_id": successor.0,
                    "superseded_at": rfc3339(done.superseded_at)?,
                    "stream_seq": done.stream_seq,
                    "commit_seq": done.commit_seq,
                });
                self.catalog.validate_output(ToolName::Memory, &value)?;
                output(value)
            }
        }
    }

    /// §Q4 `memory.correct` through the same §33.10 confirm gate (ADR-0025). One transaction
    /// inserts a new DirectUserInput Evidence + a new Memory version and supersedes the
    /// original (reason USER_CORRECTION); the original Evidence body is never edited in place.
    /// No successor on the wire (M2 is minted inside the confirmed transaction, so the token
    /// carries no successor). Same workspace rule as `memory.get` / `memory.supersede`.
    async fn memory_correct(
        &self,
        context: &McpHttpContext,
        operation: &OperationDescriptor,
        raw_arguments: &str,
        value: &Value,
    ) -> Result<ToolOutput, ErrorCode> {
        let target = MemoryId::parse(value["memory_id"].as_str().ok_or(ErrorCode::InvalidInput)?)?;
        let text = value["text"].as_str().ok_or(ErrorCode::InvalidInput)?;
        // The corrected content is stored verbatim as E2's payload and M2's content; the digest
        // is over the exact raw bytes (§48.0①: the sole constructor, no normalization).
        let content = Value::String(text.to_owned());
        let content_raw = serde_json::to_vec(&content).map_err(|_| ErrorCode::Internal)?;
        let digest = payload_sha256(&content_raw);
        let presented = value
            .get("confirm_token")
            .map(|token| {
                token
                    .as_str()
                    .ok_or(ErrorCode::InvalidInput)
                    .and_then(ConfirmToken::decode)
            })
            .transpose()?;
        let (Some(ttl), Some(undo_window)) = (self.confirm_token_ttl, self.undo_window) else {
            return self.reject_unsupported(context, operation, None).await;
        };
        let subjects = subject_repo::parse_declaration(value)?;
        // §8.5.1 / ADR-0030 D-E: a correction re-supplies the new version's affects (the old
        // rows ride with the superseded version). Parsed before the gate (malformed ⇒
        // INVALID_INPUT, token untouched); their target subjects resolve before the consume and
        // the rows are written inside correct_atomically's transaction — one ticket, no second
        // transaction.
        let affects = affect_repo::parse_affects(value)?;
        let mood_half_life = match (affects.is_empty(), self.mood_half_life) {
            (true, _) => None,
            (false, Some(half_life)) => Some(half_life),
            (false, None) => return self.reject_unsupported(context, operation, None).await,
        };
        let pool = self.runtime_pool.clone();
        let pre_pool = self.runtime_pool.clone();
        let bootstrap = self.context_bootstrap.clone();
        let consistency_token_ttl = self.remember_policy.consistency_token_ttl();
        let outcome = self
            .guard
            .run_confirmed_write_checked(
                context,
                operation,
                None,
                raw_arguments,
                ConfirmGate {
                    op: DestructiveOp::MemoryCorrect,
                    target_id: target.0,
                    successor_id: None,
                    presented,
                    ttl,
                    request_sha256: None,
                },
                // ADR-0067 D-J (G26): a note is versioned through memory.note_put, never corrected; refused pre-mint.
                move |pre: PreMint| async move {
                    memory_governance_repo::refuse_note_targets(
                        &pre_pool,
                        pre.request.authorization(),
                        &[target.0],
                    )
                    .await
                    .map(|()| None)
                },
                move |write| async move {
                    memory::correct(
                        pool,
                        write,
                        bootstrap,
                        target,
                        content,
                        digest,
                        undo_window,
                        consistency_token_ttl,
                        subjects,
                        affects,
                        mood_half_life,
                    )
                    .await
                },
            )
            .await?;
        let value = match outcome {
            ConfirmedOutcome::ConfirmationRequired { token, expires_at } => json!({
                "confirmation_required": true,
                "confirm_token": token.encode(),
                "operation": operation.operation_key(),
                "target": { "memory_id": target.0 },
                "expires_at": rfc3339(expires_at)?,
            }),
            ConfirmedOutcome::Executed(done) => json!({
                "memory_id": done.new_memory_id.0,
                "superseded": done.superseded.0,
                "evidence_id": done.evidence_id,
                "superseded_at": rfc3339(done.superseded_at)?,
                "stream_seq": done.stream_seq,
                "commit_seq": done.commit_seq,
                "consistency_token": done.consistency_token,
                "subject_ids": done.subject_ids,
                "affect_ids": done.affect_ids,
            }),
        };
        self.catalog.validate_output(ToolName::Memory, &value)?;
        output(value)
    }

    /// §36 `memory.restore` through the same §33.10 confirm gate (ADR-0020). Undoes a
    /// SUPERSEDE within the window: reuses card 1's token (no successor argument), returns the
    /// reactivated memory on a new stream seq with a new consistency_token, or a success-shaped
    /// `{code:"CONFLICT", reason:<u16>}` when the undo is refused (D-B — §52.1 keeps 18 codes).
    async fn memory_restore(
        &self,
        context: &McpHttpContext,
        operation: &OperationDescriptor,
        raw_arguments: &str,
        value: &Value,
    ) -> Result<ToolOutput, ErrorCode> {
        let target = MemoryId::parse(value["memory_id"].as_str().ok_or(ErrorCode::InvalidInput)?)?;
        let presented = value
            .get("confirm_token")
            .map(|token| {
                token
                    .as_str()
                    .ok_or(ErrorCode::InvalidInput)
                    .and_then(ConfirmToken::decode)
            })
            .transpose()?;
        // Both lifecycle-writing routes gate on the undo-window config together; restore reads
        // the stored deadline but stays disabled until the process declares the window.
        let (Some(ttl), Some(_window)) = (self.confirm_token_ttl, self.undo_window) else {
            return self.reject_unsupported(context, operation, None).await;
        };
        let pool = self.runtime_pool.clone();
        let pre_pool = self.runtime_pool.clone();
        let bootstrap = self.context_bootstrap.clone();
        let consistency_token_ttl = self.remember_policy.consistency_token_ttl();
        let outcome = self
            .guard
            .run_confirmed_write_checked(
                context,
                operation,
                None,
                raw_arguments,
                ConfirmGate {
                    op: DestructiveOp::MemoryRestore,
                    target_id: target.0,
                    successor_id: None,
                    presented,
                    ttl,
                    request_sha256: None,
                },
                // ADR-0067 D-J (G26): a note target is refused pre-mint; the confirmed leg also checks the successor.
                move |pre: PreMint| async move {
                    memory_governance_repo::refuse_note_targets(
                        &pre_pool,
                        pre.request.authorization(),
                        &[target.0],
                    )
                    .await
                    .map(|()| None)
                },
                move |write| async move {
                    memory::restore(pool, write, bootstrap, target, consistency_token_ttl).await
                },
            )
            .await?;
        let value = match outcome {
            ConfirmedOutcome::ConfirmationRequired { token, expires_at } => json!({
                "confirmation_required": true,
                "confirm_token": token.encode(),
                "operation": operation.operation_key(),
                "target": { "memory_id": target.0 },
                "expires_at": rfc3339(expires_at)?,
            }),
            ConfirmedOutcome::Executed(RestoreResult::Restored(done)) => json!({
                "memory_id": target.0,
                "restored_at": rfc3339(done.restored_at)?,
                "stream_seq": done.stream_seq,
                "commit_seq": done.commit_seq,
                "consistency_token": done.consistency_token,
            }),
            // D-B: a refused undo is a success-shaped CONFLICT-with-reason result, not an
            // ErrorCode (which would carry no reason through the frozen §52.1 error map).
            ConfirmedOutcome::Executed(RestoreResult::Refused(reason)) => json!({
                "code": "CONFLICT",
                "reason": reason.code(),
                "reason_label": reason.label().unwrap_or("UNKNOWN"),
            }),
        };
        self.catalog.validate_output(ToolName::Memory, &value)?;
        output(value)
    }

    /// §36/§10.1 `memory.confirm` through the same §33.10 confirm gate (ADR-0026, Card 6).
    /// Promotes a `private.distill_candidates` row into UserConfirmed Evidence + a new Memory.
    /// The gate target is the `candidate_id` (not a memory_id); `candidate_sha256` binds the
    /// confirm to the exact reviewed body. A refused confirm (already confirmed / expired) is a
    /// success-shaped `{code:CONFLICT, reason:<u16>}` (§52.1 keeps 18 codes).
    async fn memory_confirm(
        &self,
        context: &McpHttpContext,
        operation: &OperationDescriptor,
        raw_arguments: &str,
        value: &Value,
    ) -> Result<ToolOutput, ErrorCode> {
        let candidate_id = Uuid::parse_str(
            value["candidate_id"]
                .as_str()
                .ok_or(ErrorCode::InvalidInput)?,
        )
        .map_err(|_| ErrorCode::InvalidInput)?;
        let candidate_sha256 = hex::decode(
            value["candidate_sha256"]
                .as_str()
                .ok_or(ErrorCode::InvalidInput)?,
        )
        .map_err(|_| ErrorCode::InvalidInput)?;
        if candidate_sha256.len() != 32 {
            return Err(ErrorCode::InvalidInput);
        }
        let presented = value
            .get("confirm_token")
            .map(|token| {
                token
                    .as_str()
                    .ok_or(ErrorCode::InvalidInput)
                    .and_then(ConfirmToken::decode)
            })
            .transpose()?;
        let Some(ttl) = self.confirm_token_ttl else {
            return self.reject_unsupported(context, operation, None).await;
        };
        let subjects = subject_repo::parse_declaration(value)?;
        let pool = self.runtime_pool.clone();
        let bootstrap = self.context_bootstrap.clone();
        let consistency_token_ttl = self.remember_policy.consistency_token_ttl();
        let outcome = self
            .guard
            .run_confirmed_write(
                context,
                operation,
                None,
                raw_arguments,
                ConfirmGate {
                    op: DestructiveOp::MemoryConfirm,
                    target_id: candidate_id,
                    successor_id: None,
                    presented,
                    ttl,
                    request_sha256: None,
                },
                move |write| async move {
                    memory::confirm(
                        pool,
                        write,
                        bootstrap,
                        candidate_id,
                        candidate_sha256,
                        consistency_token_ttl,
                        subjects,
                    )
                    .await
                },
            )
            .await?;
        let value = match outcome {
            ConfirmedOutcome::ConfirmationRequired { token, expires_at } => json!({
                "confirmation_required": true,
                "confirm_token": token.encode(),
                "operation": operation.operation_key(),
                "target": { "candidate_id": candidate_id },
                "expires_at": rfc3339(expires_at)?,
            }),
            ConfirmedOutcome::Executed(ConfirmOutcome::Confirmed(done)) => json!({
                "memory_id": done.memory_id,
                "evidence_id": done.evidence_id,
                "candidate_id": done.candidate_id,
                "stream_seq": done.stream_seq,
                "commit_seq": done.commit_seq,
                "consistency_token": done.consistency_token,
                "subject_ids": done.subject_ids,
            }),
            ConfirmedOutcome::Executed(ConfirmOutcome::Refused(reason)) => json!({
                "code": "CONFLICT",
                "reason": reason.code(),
                "reason_label": reason.label().unwrap_or("UNKNOWN"),
            }),
        };
        self.catalog.validate_output(ToolName::Memory, &value)?;
        output(value)
    }

    /// §36 `memory.reject` through the same §33.10 confirm gate (ADR-0026, Card 6). Marks a
    /// pending candidate REJECTED; writes no Evidence/Memory.
    async fn memory_reject(
        &self,
        context: &McpHttpContext,
        operation: &OperationDescriptor,
        raw_arguments: &str,
        value: &Value,
    ) -> Result<ToolOutput, ErrorCode> {
        let candidate_id = Uuid::parse_str(
            value["candidate_id"]
                .as_str()
                .ok_or(ErrorCode::InvalidInput)?,
        )
        .map_err(|_| ErrorCode::InvalidInput)?;
        let presented = value
            .get("confirm_token")
            .map(|token| {
                token
                    .as_str()
                    .ok_or(ErrorCode::InvalidInput)
                    .and_then(ConfirmToken::decode)
            })
            .transpose()?;
        let Some(ttl) = self.confirm_token_ttl else {
            return self.reject_unsupported(context, operation, None).await;
        };
        let pool = self.runtime_pool.clone();
        let bootstrap = self.context_bootstrap.clone();
        let outcome =
            self.guard
                .run_confirmed_write(
                    context,
                    operation,
                    None,
                    raw_arguments,
                    ConfirmGate {
                        op: DestructiveOp::MemoryReject,
                        target_id: candidate_id,
                        successor_id: None,
                        presented,
                        ttl,
                        request_sha256: None,
                    },
                    move |write| async move {
                        memory::reject(pool, write, bootstrap, candidate_id).await
                    },
                )
                .await?;
        let value = match outcome {
            ConfirmedOutcome::ConfirmationRequired { token, expires_at } => json!({
                "confirmation_required": true,
                "confirm_token": token.encode(),
                "operation": operation.operation_key(),
                "target": { "candidate_id": candidate_id },
                "expires_at": rfc3339(expires_at)?,
            }),
            ConfirmedOutcome::Executed(RejectOutcome::Rejected(candidate_id)) => json!({
                "candidate_id": candidate_id,
                "state": "rejected",
            }),
            ConfirmedOutcome::Executed(RejectOutcome::Refused(reason)) => json!({
                "code": "CONFLICT",
                "reason": reason.code(),
                "reason_label": reason.label().unwrap_or("UNKNOWN"),
            }),
        };
        self.catalog.validate_output(ToolName::Memory, &value)?;
        output(value)
    }

    /// The closed arguments of the four binding ops (§36 + §25.4.A(7)/(9)).
    ///
    /// `task_id` is required by exactly the MANDATORY pair and refused on the PINNED pair; a
    /// bind with no task is `INVALID_INPUT`, never a tenant-wide MANDATORY binding by accident.
    /// `replaces_binding_id` is `memory.bind`'s authorized A->B replacement and is refused
    /// everywhere else.
    fn binding_write_arguments(
        value: &Value,
        op: DestructiveOp,
    ) -> Result<BindingWriteArguments, ErrorCode> {
        let memory = MemoryId::parse(value["memory_id"].as_str().ok_or(ErrorCode::InvalidInput)?)?;
        let uuid_arg = |name: &str| -> Result<Option<Uuid>, ErrorCode> {
            value
                .get(name)
                .map(|raw| {
                    Uuid::parse_str(raw.as_str().ok_or(ErrorCode::InvalidInput)?)
                        .map_err(|_| ErrorCode::InvalidInput)
                })
                .transpose()
        };
        let task = uuid_arg("task_id")?.map(TaskId);
        let replaces_binding_id = uuid_arg("replaces_binding_id")?;
        let mandatory = matches!(op, DestructiveOp::MemoryBind | DestructiveOp::MemoryUnbind);
        if mandatory != task.is_some() || (!mandatory && replaces_binding_id.is_some()) {
            return Err(ErrorCode::InvalidInput);
        }
        // card 22c / ADR-0046: `purpose` is REQUIRED on bind and refused on the other three.
        // No default: "reference or instruction" is the whole question this field exists to
        // answer, and a defaulted answer is one nobody gave.
        let purpose = match value.get("purpose") {
            Some(raw) => Some(
                BindingPurpose::parse_wire(raw.as_str().ok_or(ErrorCode::InvalidInput)?)
                    .ok_or(ErrorCode::InvalidInput)?,
            ),
            None => None,
        };
        if purpose.is_some() != matches!(op, DestructiveOp::MemoryBind) {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(BindingWriteArguments {
            memory,
            task,
            replaces_binding_id,
            purpose,
        })
    }

    /// §36 `memory.pin` / `memory.unpin` and, since card 22b (ADR-0045), `memory.bind` /
    /// `memory.unbind`, through the same §33.10 confirm gate (ADR-0019).
    ///
    /// One arm for all four: identical wire shape (`memory_id` + optional `confirm_token`,
    /// plus the required `task_id` for the MANDATORY pair), the closed `op` is the only
    /// difference, and the token is bound to it (a pin confirmation never executes an unpin,
    /// and a bind confirmation mints neither actor for the other pair — `ElevatedActor` and
    /// `ConfirmedUserActor` each refuse the other's ops). No `workspace_id` on the wire: the
    /// route is the credential's bound workspace (same rule as `memory.get` /
    /// `memory.supersede`); `task_id` IS on the wire because a task is not a credential route.
    // card 22c added the `purpose` leg (the intent digest for the confirm gate, the closed
    // wire value, and the two reported fields). Splitting the arm per op would duplicate the
    // whole ConfirmGate envelope four times over three closed values; the length is the price
    // of keeping "one confirm gate, four ops" literally one function.
    #[allow(clippy::too_many_lines)]
    async fn memory_binding_write(
        &self,
        context: &McpHttpContext,
        operation: &OperationDescriptor,
        raw_arguments: &str,
        value: &Value,
        op: DestructiveOp,
    ) -> Result<ToolOutput, ErrorCode> {
        let BindingWriteArguments {
            memory,
            task,
            replaces_binding_id,
            purpose,
        } = Self::binding_write_arguments(value, op)?;
        let presented = value
            .get("confirm_token")
            .map(|token| {
                token
                    .as_str()
                    .ok_or(ErrorCode::InvalidInput)
                    .and_then(ConfirmToken::decode)
            })
            .transpose()?;
        let Some(ttl) = self.confirm_token_ttl else {
            return self.reject_unsupported(context, operation, None).await;
        };
        let pool = self.runtime_pool.clone();
        let bootstrap = self.context_bootstrap.clone();
        let outcome = self
            .guard
            .run_confirmed_write(
                context,
                operation,
                None,
                raw_arguments,
                ConfirmGate {
                    op,
                    // §25.4.A(7)/(8): the MANDATORY pair's token binds the PAIR (memory, task).
                    // The successor leg is exactly what §33.10 rule 9 reserves for an
                    // operation's second argument (memory.supersede's replacement uses it), so
                    // a confirmation for "bind S to T" cannot execute "bind S to U".
                    target_id: memory.0,
                    // card 22c: the successor leg is the whole intent digest (task + purpose),
                    // not the bare task id — `humaux_domain::context::binding_confirmation_successor`,
                    // shared with the adapter's confirm check.
                    successor_id: task.map(|task| {
                        humaux_domain::context::binding_confirmation_successor(task, purpose)
                    }),
                    presented,
                    ttl,
                    request_sha256: None,
                },
                move |write| async move {
                    // D-E (card 13, ADR-0035): the binding lands at the request's authorized
                    // WORKSPACE route; carry it out so BindingWritten can report the scope.
                    let scope_workspace = write.request.workspace_id();
                    memory::write_binding(
                        pool,
                        write,
                        bootstrap,
                        op,
                        memory,
                        task,
                        replaces_binding_id,
                        purpose,
                    )
                    .await
                    .map(|done| (done, scope_workspace))
                },
            )
            .await?;
        let value = match outcome {
            ConfirmedOutcome::ConfirmationRequired { token, expires_at } => json!({
                "confirmation_required": true,
                "confirm_token": token.encode(),
                "operation": operation.operation_key(),
                "target": match task {
                    Some(task) => json!({ "memory_id": memory.0, "task_id": task.0 }),
                    None => json!({ "memory_id": memory.0 }),
                },
                "expires_at": rfc3339(expires_at)?,
            }),
            ConfirmedOutcome::Executed((done, scope_workspace)) => {
                // write_binding rejects a missing workspace before it can return Ok, so this is
                // always Some on the executed path; refuse rather than emit a scope-less binding.
                let scope_workspace = scope_workspace.ok_or(ErrorCode::Internal)?;
                // The four ops share one output branch and differ only in these three closed
                // values (memory.output.schema.json `BindingWritten`).
                let (mode, state, scope) = match op {
                    DestructiveOp::MemoryPin => (
                        "PINNED",
                        "pinned",
                        json!({"kind":"WORKSPACE","id":scope_workspace.0}),
                    ),
                    DestructiveOp::MemoryUnpin => (
                        "PINNED",
                        "unpinned",
                        json!({"kind":"WORKSPACE","id":scope_workspace.0}),
                    ),
                    _ => {
                        let task = task.ok_or(ErrorCode::Internal)?;
                        (
                            "MANDATORY",
                            if op == DestructiveOp::MemoryBind {
                                "bound"
                            } else {
                                "unbound"
                            },
                            json!({"kind":"TASK","id":task.0}),
                        )
                    }
                };
                let mut value = json!({
                    "memory_id": memory.0,
                    "binding_id": done.binding_id,
                    "mode": mode,
                    "state": state,
                    "inserted": done.inserted,
                    "scope": scope,
                });
                // card 22c (ADR-0046): bind, and only bind, reports what it was FOR and
                // whether an authorization actually exists now. `task_authorized` is the
                // adapter's read-back, not an echo of `purpose` — the idempotent arm writes
                // nothing, so the two can legitimately disagree.
                if let Some(purpose) = purpose {
                    value["purpose"] = json!(purpose.wire());
                    value["task_authorization"] = json!(if done.task_authorized {
                        "granted"
                    } else {
                        "none"
                    });
                }
                value
            }
        };
        // Both results are branches of memory.output.schema.json (tools/list advertises it).
        self.catalog.validate_output(ToolName::Memory, &value)?;
        output(value)
    }

    /// §36 `memory.archive` / `memory.unarchive` through the same §33.10 confirm gate
    /// (ADR-0024, Q3). One arm for both: identical wire shape (`memory_id` + optional
    /// `confirm_token`), the closed `op` is the only difference and the token is bound to it (an
    /// archive confirmation never runs an unarchive). No `workspace_id` on the wire: the route
    /// is the credential's bound workspace (same rule as `memory.get` / `memory.supersede`).
    /// Archive appends an ARCHIVE lifecycle event and sets `archived_at`; unarchive appends a
    /// RESTORE undoing it and clears `archived_at`. An already-in-state call is a success-shaped
    /// `{code:"CONFLICT", reason:1201}` (D-B — §52.1 keeps 18 codes).
    async fn memory_archive_write(
        &self,
        context: &McpHttpContext,
        operation: &OperationDescriptor,
        raw_arguments: &str,
        value: &Value,
        op: DestructiveOp,
    ) -> Result<ToolOutput, ErrorCode> {
        let memory = MemoryId::parse(value["memory_id"].as_str().ok_or(ErrorCode::InvalidInput)?)?;
        let presented = value
            .get("confirm_token")
            .map(|token| {
                token
                    .as_str()
                    .ok_or(ErrorCode::InvalidInput)
                    .and_then(ConfirmToken::decode)
            })
            .transpose()?;
        let Some(ttl) = self.confirm_token_ttl else {
            return self.reject_unsupported(context, operation, None).await;
        };
        let pool = self.runtime_pool.clone();
        let bootstrap = self.context_bootstrap.clone();
        let outcome =
            self.guard
                .run_confirmed_write(
                    context,
                    operation,
                    None,
                    raw_arguments,
                    ConfirmGate {
                        op,
                        target_id: memory.0,
                        successor_id: None,
                        presented,
                        ttl,
                        request_sha256: None,
                    },
                    move |write| async move {
                        memory::archive(pool, write, bootstrap, op, memory).await
                    },
                )
                .await?;
        let changed_field = if op == DestructiveOp::MemoryArchive {
            "archived_at"
        } else {
            "unarchived_at"
        };
        let value = match outcome {
            ConfirmedOutcome::ConfirmationRequired { token, expires_at } => json!({
                "confirmation_required": true,
                "confirm_token": token.encode(),
                "operation": operation.operation_key(),
                "target": { "memory_id": memory.0 },
                "expires_at": rfc3339(expires_at)?,
            }),
            ConfirmedOutcome::Executed(ArchiveResult::Done(done)) => json!({
                "memory_id": memory.0,
                changed_field: rfc3339(done.changed_at)?,
                "stream_seq": done.stream_seq,
                "commit_seq": done.commit_seq,
            }),
            // D-B: an already-in-state archive/unarchive is a success-shaped CONFLICT-with-reason.
            ConfirmedOutcome::Executed(ArchiveResult::Refused(reason)) => json!({
                "code": "CONFLICT",
                "reason": reason.code(),
                "reason_label": reason.label().unwrap_or("UNKNOWN"),
            }),
        };
        self.catalog.validate_output(ToolName::Memory, &value)?;
        output(value)
    }

    async fn recall_search(
        &self,
        context: &McpHttpContext,
        operation: &OperationDescriptor,
        raw_arguments: &str,
        value: &Value,
    ) -> Result<ToolOutput, ErrorCode> {
        let requested_workspace = workspace(value)?;
        let workspace_id = requested_workspace.ok_or(ErrorCode::DependencyUnavailable)?;
        let runtime = self
            .semantic_recall
            .clone()
            .ok_or(ErrorCode::DependencyUnavailable)?;
        let query = value["query"]
            .as_str()
            .ok_or(ErrorCode::InvalidInput)?
            .to_owned();
        let consistency_token = value
            .get("consistency_token")
            .map(|token| {
                token
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(ErrorCode::InvalidInput)
            })
            .transpose()?;
        let limit = value
            .get("limit")
            .map(|limit| {
                limit
                    .as_u64()
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or(ErrorCode::InvalidInput)
            })
            .transpose()?;
        // §6.1.3/ADR-0029: `subject_ids` is schema-validated as an array of uuid strings
        // upstream; a malformed element here is still INVALID_INPUT, never a silent drop.
        let subject_ids = value
            .get("subject_ids")
            .map(|ids| {
                ids.as_array()
                    .ok_or(ErrorCode::InvalidInput)?
                    .iter()
                    .map(|id| SubjectId::parse(id.as_str().ok_or(ErrorCode::InvalidInput)?))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        // §8.5.1/ADR-0030 D-D: the explicit affect query + optional mood point, parsed the one
        // way every affect-carrying op parses (closed sets, basis-point ranges, lo <= hi).
        let affect = affect_repo::parse_filter(value)?;
        let mood_congruence = affect_repo::parse_mood(value)?;
        let input = RecallSearchRequest {
            query,
            workspace_id,
            consistency_token,
            mode: value.get("mode").and_then(Value::as_str).map(str::to_owned),
            completeness_request: value
                .get("completeness_request")
                .and_then(Value::as_str)
                .map(str::to_owned),
            limit,
            subject_ids,
            affect,
            mood_congruence,
        };
        let pool = self.runtime_pool.clone();
        let bootstrap = self.context_bootstrap.clone();
        let catalog = self.catalog.clone();
        let pending = self
            .guard
            .run_retrieval_read(
                context,
                operation,
                requested_workspace,
                raw_arguments,
                move |request| async move {
                    recall::search(
                        pool,
                        runtime,
                        catalog,
                        request.authorization().clone(),
                        request.request_id(),
                        bootstrap,
                        input,
                    )
                    .await
                },
            )
            .await?;
        Ok(pending.finish())
    }
}

#[async_trait]
impl McpApplication for GatewayMcpApplication {
    async fn check_access(
        &self,
        context: &McpHttpContext,
        operation: McpOperation,
    ) -> Result<(), ErrorCode> {
        if matches!(operation, McpOperation::Preflight) {
            self.guard.preflight(context).await
        } else {
            self.guard.protocol(context, operation).await
        }
    }

    // One flat arm per wired operation key, deliberately. `xtask architecture-check`'s *tool
    // surface truth* arm PARSES this dispatch to recover the routed key set and compares it
    // against `SUPPORTED_OPERATION_KEYS` and §33's table in both directions; folding the four
    // binding ops (or any other family) into one predicate arm would hide those keys from the
    // gate that exists to notice them going missing. Length is the cost of that readability.
    #[allow(clippy::too_many_lines)]
    async fn invoke(
        &self,
        context: &McpHttpContext,
        tool: ToolName,
        arguments: McpToolArguments<'_>,
    ) -> Result<ToolOutput, ErrorCode> {
        let (operation, raw_arguments, value) = self.validated(tool, arguments)?;
        match operation.operation_key() {
            "remember.put" => {
                self.remember_put(context, &operation, &raw_arguments, &value)
                    .await
            }
            "memory.note_put" => {
                self.memory_note_put(context, &operation, &raw_arguments, &value)
                    .await
            }
            "context.assemble" => {
                self.context_assemble(context, &operation, &raw_arguments, &value)
                    .await
            }
            "recall.search" => {
                self.recall_search(context, &operation, &raw_arguments, &value)
                    .await
            }
            "memory.get" => {
                self.memory_get(context, &operation, &raw_arguments, &value)
                    .await
            }
            "memory.enumerate" => {
                self.memory_enumerate(context, &operation, &raw_arguments, &value)
                    .await
            }
            "memory.grep" => {
                self.memory_grep(context, &operation, &raw_arguments, &value)
                    .await
            }
            "continuity.get" => {
                self.continuity_get(context, &operation, &raw_arguments, &value)
                    .await
            }
            "continuity.publish" => {
                self.continuity_publish(context, &operation, &raw_arguments, &value)
                    .await
            }
            "coordinate.task_submit" => {
                self.coordinate_task(context, &operation, &raw_arguments, &value, TaskOp::Submit)
                    .await
            }
            "coordinate.task_claim" => {
                self.coordinate_task(context, &operation, &raw_arguments, &value, TaskOp::Claim)
                    .await
            }
            "coordinate.task_heartbeat" => {
                self.coordinate_task(
                    context,
                    &operation,
                    &raw_arguments,
                    &value,
                    TaskOp::Heartbeat,
                )
                .await
            }
            "coordinate.task_complete" => {
                self.coordinate_task(
                    context,
                    &operation,
                    &raw_arguments,
                    &value,
                    TaskOp::Complete,
                )
                .await
            }
            "coordinate.task_fail" => {
                self.coordinate_task(context, &operation, &raw_arguments, &value, TaskOp::Fail)
                    .await
            }
            key if key == DestructiveOp::MemorySupersede.operation_key() => {
                self.memory_supersede(context, &operation, &raw_arguments, &value)
                    .await
            }
            key if key == DestructiveOp::MemoryCorrect.operation_key() => {
                self.memory_correct(context, &operation, &raw_arguments, &value)
                    .await
            }
            key if key == DestructiveOp::MemoryConfirm.operation_key() => {
                self.memory_confirm(context, &operation, &raw_arguments, &value)
                    .await
            }
            key if key == DestructiveOp::MemoryReject.operation_key() => {
                self.memory_reject(context, &operation, &raw_arguments, &value)
                    .await
            }
            key if key == DestructiveOp::MemoryPin.operation_key() => {
                self.memory_binding_write(
                    context,
                    &operation,
                    &raw_arguments,
                    &value,
                    DestructiveOp::MemoryPin,
                )
                .await
            }
            key if key == DestructiveOp::MemoryUnpin.operation_key() => {
                self.memory_binding_write(
                    context,
                    &operation,
                    &raw_arguments,
                    &value,
                    DestructiveOp::MemoryUnpin,
                )
                .await
            }
            key if key == DestructiveOp::MemoryBind.operation_key() => {
                self.memory_binding_write(
                    context,
                    &operation,
                    &raw_arguments,
                    &value,
                    DestructiveOp::MemoryBind,
                )
                .await
            }
            key if key == DestructiveOp::MemoryUnbind.operation_key() => {
                self.memory_binding_write(
                    context,
                    &operation,
                    &raw_arguments,
                    &value,
                    DestructiveOp::MemoryUnbind,
                )
                .await
            }
            key if key == DestructiveOp::MemoryRestore.operation_key() => {
                self.memory_restore(context, &operation, &raw_arguments, &value)
                    .await
            }
            key if key == DestructiveOp::MemoryArchive.operation_key() => {
                self.memory_archive_write(
                    context,
                    &operation,
                    &raw_arguments,
                    &value,
                    DestructiveOp::MemoryArchive,
                )
                .await
            }
            key if key == DestructiveOp::MemoryUnarchive.operation_key() => {
                self.memory_archive_write(
                    context,
                    &operation,
                    &raw_arguments,
                    &value,
                    DestructiveOp::MemoryUnarchive,
                )
                .await
            }
            key if SubjectWriteOp::parse_operation_key(key).is_some() => {
                let op = SubjectWriteOp::parse_operation_key(key).ok_or(ErrorCode::Internal)?;
                self.memory_subject_write(context, &operation, &raw_arguments, &value, op)
                    .await
            }
            key if AffectWriteOp::parse_operation_key(key) == Some(AffectWriteOp::Annotate) => {
                self.memory_annotate_affect(context, &operation, &raw_arguments, &value)
                    .await
            }
            _ => {
                self.reject_unsupported(context, &operation, workspace(&value)?)
                    .await
            }
        }
    }
}

/// Which of the five wired `coordinate.task_*` operations [`GatewayMcpApplication::coordinate_task`] runs.
#[derive(Clone, Copy)]
enum TaskOp {
    Submit,
    Claim,
    Heartbeat,
    Complete,
    Fail,
}

/// The three wire fields that name one lease holder's run (ADR-0078 Q10). The token is the client's, kept verbatim.
struct RunRef {
    task: TaskId,
    run: TaskRunId,
    token: FencingToken,
}

impl RunRef {
    fn parse(value: &Value) -> Result<Self, ErrorCode> {
        Ok(Self {
            task: TaskId(wire_uuid(value, "task_id")?),
            run: TaskRunId(wire_uuid(value, "task_run_id")?),
            token: FencingToken(
                value
                    .get("fencing_token")
                    .and_then(Value::as_i64)
                    .filter(|token| *token >= 1)
                    .ok_or(ErrorCode::InvalidInput)?,
            ),
        })
    }

    /// ADR-0078 Q10: `NOT_FOUND` unless `run` is a run of `task`. `coord.task_runs.task_id` never changes, so this read and
    /// the verified write after it cannot disagree.
    async fn belongs_to_task(
        &self,
        pool: &RuntimeDbPool,
        scope: &AuthorizationScope,
    ) -> Result<(), ErrorCode> {
        if coord_repo::task_of_run(pool, scope, self.run).await? == self.task {
            Ok(())
        } else {
            Err(ErrorCode::NotFound)
        }
    }
}

/// A `coordinate.task_*` call decoded from validated arguments.
enum TaskWire {
    Submit { title: String, description: String },
    Claim { task: TaskId },
    Heartbeat { run: RunRef },
    Complete { run: RunRef, summary: String },
    Fail { run: RunRef, summary: String },
}

impl TaskWire {
    fn parse(op: TaskOp, value: &Value) -> Result<Self, ErrorCode> {
        let text = |field: &str| -> Result<String, ErrorCode> {
            value
                .get(field)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(ErrorCode::InvalidInput)
        };
        Ok(match op {
            TaskOp::Submit => Self::Submit {
                title: text("title")?,
                description: text("description")?,
            },
            TaskOp::Claim => Self::Claim {
                task: TaskId(wire_uuid(value, "task_id")?),
            },
            TaskOp::Heartbeat => Self::Heartbeat {
                run: RunRef::parse(value)?,
            },
            TaskOp::Complete => Self::Complete {
                run: RunRef::parse(value)?,
                summary: text("summary")?,
            },
            TaskOp::Fail => Self::Fail {
                run: RunRef::parse(value)?,
                summary: text("summary")?,
            },
        })
    }
}

fn wire_uuid(value: &Value, field: &str) -> Result<Uuid, ErrorCode> {
    value
        .get(field)
        .and_then(Value::as_str)
        .and_then(|raw| Uuid::parse_str(raw).ok())
        .ok_or(ErrorCode::InvalidInput)
}

/// `memory.note_put`'s validated arguments (ADR-0067): the same raw-content binding as [`RememberPutWire`], plus the note's
/// own decisions taken at the input edge (kind, verbatim body + digest, title, requested authority).
struct NotePutWire {
    content: PreparedEvidencePayload,
    note: NoteIntake,
    /// The caller's `requested_authority` spelling, echoed in the refusal (`None` = the default).
    requested_authority_wire: String,
    idempotency_key: String,
    workspace_id: Option<WorkspaceId>,
    visibility_class: Option<VisibilityClass>,
    data_class: Option<DataClass>,
    /// ADR-0067 D-J: `(note_id, supersedes)` of a replacement; `None` for a create.
    replace: Option<(Uuid, Uuid)>,
    /// ADR-0067 D-J: the second replacement call's token (only with `replace`).
    confirm_token: Option<ConfirmToken>,
}

#[derive(Deserialize)]
struct RawNotePutWire {
    content: Box<RawValue>,
    title: Option<String>,
    note_kind: String,
    requested_authority: Option<String>,
    idempotency_key: String,
    workspace_id: Option<Uuid>,
    visibility_class: Option<String>,
    data_class: Option<String>,
    note_id: Option<Uuid>,
    supersedes: Option<Uuid>,
    confirm_token: Option<String>,
}

impl NotePutWire {
    fn from_raw(raw_arguments: &str, decoded: &Value) -> Result<Self, ErrorCode> {
        let raw: RawNotePutWire =
            serde_json::from_str(raw_arguments).map_err(|_| ErrorCode::InvalidInput)?;
        let content: Value =
            serde_json::from_str(raw.content.get()).map_err(|_| ErrorCode::InvalidInput)?;
        if decoded.get("content") != Some(&content) {
            return Err(ErrorCode::InvalidInput);
        }
        let body = NoteBody::new(content.as_str().ok_or(ErrorCode::InvalidInput)?)?;
        let title = note_title(raw.title.as_deref(), &body)?;
        let kind = NoteKind::parse_wire(&raw.note_kind).ok_or(ErrorCode::InvalidInput)?;
        let requested_authority_wire = raw
            .requested_authority
            .unwrap_or_else(|| "PrivateKnowledge".to_owned());
        let requested =
            parse_requested_authority(&requested_authority_wire).ok_or(ErrorCode::InvalidInput)?;
        let replace = match (raw.note_id, raw.supersedes) {
            (Some(note_id), Some(supersedes)) => Some((note_id, supersedes)),
            (None, None) => None,
            _ => return Err(ErrorCode::InvalidInput),
        };
        let confirm_token = raw
            .confirm_token
            .as_deref()
            .map(ConfirmToken::decode)
            .transpose()?;
        // ADR-0067 D-J: a replacement has no scope input (the version inherits the head's visibility and data class) and
        // declares nothing its token does not bind; a token without a replacement is meaningless.
        let declares = raw.visibility_class.is_some()
            || raw.data_class.is_some()
            || ["subject_ids", "subject_keys", "affects"]
                .iter()
                .any(|field| decoded.get(*field).is_some());
        if (replace.is_some() && declares) || (replace.is_none() && confirm_token.is_some()) {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self {
            content: PreparedEvidencePayload::new(raw.content.get().as_bytes().to_vec(), content)?,
            note: NoteIntake {
                kind,
                title,
                body,
                requested,
            },
            requested_authority_wire,
            idempotency_key: raw.idempotency_key,
            workspace_id: raw.workspace_id.map(WorkspaceId),
            visibility_class: raw
                .visibility_class
                .as_deref()
                .map(remember::parse_visibility_class)
                .transpose()?,
            data_class: raw
                .data_class
                .as_deref()
                .map(remember::parse_data_class)
                .transpose()?,
            replace,
            confirm_token,
        })
    }
}

/// ADR-0067 D-J: everything one replacement leg needs to build its receipt request, owned so each leg's future is `Send`.
#[derive(Clone)]
struct NoteReplaceLeg {
    pool: Arc<RuntimeDbPool>,
    bootstrap: ContextBootstrap,
    policy: RememberPolicy,
    content: PreparedEvidencePayload,
    note: NoteIntake,
    idempotency_key: String,
    note_id: Uuid,
    supersedes: Uuid,
    intent: [u8; 32],
}

impl NoteReplaceLeg {
    /// One leg: the challenge when `claim` is `None`, the confirmed commit otherwise. The fingerprint is hex `H`; the
    /// classification is the deployment default, which the adapter replaces with the head's (D-J: no scope input).
    async fn run(
        self,
        request: AuthorizedRequest,
        finished_audit: AuditEvent,
        reservation_ttl: Duration,
        replay_ttl: Duration,
        claim: Option<ConfirmationClaim>,
    ) -> Result<NoteReplaceOutcome, ErrorCode> {
        let workspace = request
            .workspace_id()
            .ok_or(ErrorCode::DependencyUnavailable)?;
        let (_, stream) = self
            .bootstrap
            .request_stream(request.authorization().tenant_id(), workspace);
        let now = OffsetDateTime::now_utc();
        let command = remember::command(
            request.authorization(),
            &self.policy,
            &stream,
            self.content,
            PutClassification {
                visibility_class: self.policy.visibility_class(),
                data_class: self.policy.data_class(),
                event_kind: RememberEventKind::ManualNote,
            },
            // D-G: a version's occurred_at is the server receipt time.
            Some(now),
            now,
            SubjectDeclaration::default(),
            Vec::new(),
            None,
        )?;
        operation_receipt::note_replace_atomically(
            &self.pool,
            request.authorization(),
            AtomicRememberRequest {
                request_id: request.request_id(),
                idempotency_key: self.idempotency_key,
                request_fingerprint: hex::encode(self.intent),
                workspace_id: Some(workspace),
                reservation_ttl,
                replay_ttl,
                command,
                finished_audit,
            },
            self.note,
            NoteReplaceRequest {
                note_id: self.note_id,
                supersedes: self.supersedes,
                claim,
            },
            &crate::bootstrap::MEMORY_ATTRIBUTION,
        )
        .await
    }
}

struct RememberPutWire {
    content: PreparedEvidencePayload,
    idempotency_key: String,
    workspace_id: Option<WorkspaceId>,
    /// ADR-0032 D-B per-call overrides, each parsed into its closed set (unknown ⇒
    /// `INVALID_INPUT` before admission; the schema already refuses them at the catalog).
    visibility_class: Option<VisibilityClass>,
    data_class: Option<DataClass>,
    event_kind: Option<RememberEventKind>,
    /// Design v0.2 §15 T04c: the §30.2 run this put is written under, both halves or neither.
    task_run: Option<(TaskRunId, FencingToken)>,
    /// ADR-0078 D-D rung A1: the project this put declares, resolved server-side in the receipt transaction. Any uuid
    /// parses; whether it names a visible project is decided there, so a refusal is one `INVALID_INPUT` after admission.
    project_id: Option<ProjectId>,
}

#[derive(Deserialize)]
struct RawRememberPutWire {
    content: Box<RawValue>,
    idempotency_key: String,
    workspace_id: Option<Uuid>,
    visibility_class: Option<String>,
    data_class: Option<String>,
    event_kind: Option<String>,
    task_run: Option<RawTaskRunWire>,
    project_id: Option<Uuid>,
}

/// `remember.schema.json` `task_run`: both fields required, nothing else, so a half pair is unrepresentable.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTaskRunWire {
    task_run_id: Uuid,
    fencing_token: i64,
}

impl RememberPutWire {
    fn from_raw(raw_arguments: &str, decoded: &Value) -> Result<Self, ErrorCode> {
        let raw: RawRememberPutWire =
            serde_json::from_str(raw_arguments).map_err(|_| ErrorCode::InvalidInput)?;
        let content: Value =
            serde_json::from_str(raw.content.get()).map_err(|_| ErrorCode::InvalidInput)?;
        if decoded.get("content") != Some(&content) {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self {
            content: PreparedEvidencePayload::new(raw.content.get().as_bytes().to_vec(), content)?,
            idempotency_key: raw.idempotency_key,
            workspace_id: raw.workspace_id.map(WorkspaceId),
            visibility_class: raw
                .visibility_class
                .as_deref()
                .map(remember::parse_visibility_class)
                .transpose()?,
            data_class: raw
                .data_class
                .as_deref()
                .map(remember::parse_data_class)
                .transpose()?,
            event_kind: raw
                .event_kind
                .as_deref()
                .map(RememberEventKind::parse)
                .transpose()?,
            // §30.2: a token is a claimed `fencing_seq`, never below 1 (0248 CHECK); the schema's `minimum` says the same.
            task_run: match raw.task_run {
                Some(run) if run.fencing_token < 1 => return Err(ErrorCode::InvalidInput),
                Some(run) => Some((TaskRunId(run.task_run_id), FencingToken(run.fencing_token))),
                None => None,
            },
            project_id: raw.project_id.map(ProjectId),
        })
    }
}

fn workspace(value: &Value) -> Result<Option<WorkspaceId>, ErrorCode> {
    let Some(value) = value.get("workspace_id") else {
        return Ok(None);
    };
    let value = value.as_str().ok_or(ErrorCode::InvalidInput)?;
    Ok(Some(WorkspaceId(
        Uuid::parse_str(value).map_err(|_| ErrorCode::InvalidInput)?,
    )))
}

fn decode_sha256(value: &str) -> Result<[u8; 32], ErrorCode> {
    hex::decode(value)
        .map_err(|_| ErrorCode::InvalidInput)?
        .try_into()
        .map_err(|_| ErrorCode::InvalidInput)
}

/// §25.3.1: a publication carries its exact source set, `(id, sha256)`, never ids alone — 0136
/// rejects a source whose bytes or visibility no longer match instead of dropping it.
fn publish_sources(
    value: &Value,
) -> Result<(Vec<ContinuityMemorySource>, Vec<ContinuityEvidenceSource>), ErrorCode> {
    let sources = value.get("sources").ok_or(ErrorCode::InvalidInput)?;
    let memory_items = sources
        .get("memories")
        .and_then(Value::as_array)
        .ok_or(ErrorCode::InvalidInput)?;
    let mut memories = Vec::with_capacity(memory_items.len());
    for item in memory_items {
        let memory_id = item
            .get("memory_id")
            .and_then(Value::as_str)
            .ok_or(ErrorCode::InvalidInput)?;
        let content_sha256 = item
            .get("content_sha256")
            .and_then(Value::as_str)
            .ok_or(ErrorCode::InvalidInput)?;
        memories.push(ContinuityMemorySource {
            memory_id: Uuid::parse_str(memory_id).map_err(|_| ErrorCode::InvalidInput)?,
            content_sha256: decode_sha256(content_sha256)?,
        });
    }
    let evidence_items = sources
        .get("evidence")
        .and_then(Value::as_array)
        .ok_or(ErrorCode::InvalidInput)?;
    let mut evidence = Vec::with_capacity(evidence_items.len());
    for item in evidence_items {
        let evidence_id = item
            .get("evidence_id")
            .and_then(Value::as_str)
            .ok_or(ErrorCode::InvalidInput)?;
        let payload_sha256 = item
            .get("payload_sha256")
            .and_then(Value::as_str)
            .ok_or(ErrorCode::InvalidInput)?;
        evidence.push(ContinuityEvidenceSource {
            evidence_id: Uuid::parse_str(evidence_id).map_err(|_| ErrorCode::InvalidInput)?,
            payload_sha256: decode_sha256(payload_sha256)?,
        });
    }
    Ok((memories, evidence))
}

fn publish_removals(value: &Value) -> Result<Vec<String>, ErrorCode> {
    let Some(removals) = value.get("removals") else {
        return Ok(Vec::new());
    };
    removals
        .as_array()
        .ok_or(ErrorCode::InvalidInput)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or(ErrorCode::InvalidInput)
        })
        .collect()
}

fn publish_output(outcome: &continuity::PublishOutcome) -> Value {
    match outcome {
        continuity::PublishOutcome::Published(published) => json!({
            "contract_version": "1",
            "project_id": published.project_id.0.to_string(),
            "facet_kind": published.facet_kind.as_str(),
            "facet_version_id": published.result.facet_version_id.0.to_string(),
            "facet_version": published.result.facet_version,
            "slot_version": published.result.slot_version,
            "body_sha256": hex::encode(published.result.body_sha256),
        }),
        continuity::PublishOutcome::Conflict {
            reason,
            current_slot_version,
        } => json!({
            "code": "CONFLICT",
            "reason": reason.code(),
            "reason_label": reason.label().unwrap_or("UNKNOWN"),
            "current_slot_version": current_slot_version,
        }),
    }
}

/// ADR-0067 D-G / D-J2: `memory.enumerate`'s note and history axes, typed at the edge. An unknown kind, a bound that is
/// not RFC 3339, a `note_id` that is not a uuid, or a `statuses` / `archive` value [`Lifecycle::for_enumerate`] refuses
/// (`revoked` / `expired` included, L-6) is `INVALID_INPUT`; `since >= until` is refused by the adapter, next to the
/// predicate it would describe.
fn note_enumeration_filter(value: &Value) -> Result<NoteEnumerationFilter, ErrorCode> {
    let note_kinds = value
        .get("note_kinds")
        .map(|kinds| -> Result<Vec<NoteKind>, ErrorCode> {
            kinds
                .as_array()
                .ok_or(ErrorCode::InvalidInput)?
                .iter()
                .map(|kind| {
                    kind.as_str()
                        .and_then(NoteKind::parse_wire)
                        .ok_or(ErrorCode::InvalidInput)
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    let bound = |name: &str| {
        value
            .get(name)
            .map(|at| {
                at.as_str()
                    .and_then(|at| OffsetDateTime::parse(at, &Rfc3339).ok())
                    .ok_or(ErrorCode::InvalidInput)
            })
            .transpose()
    };
    let statuses = value
        .get("statuses")
        .map(|statuses| -> Result<Vec<&str>, ErrorCode> {
            statuses
                .as_array()
                .ok_or(ErrorCode::InvalidInput)?
                .iter()
                .map(|status| status.as_str().ok_or(ErrorCode::InvalidInput))
                .collect()
        })
        .transpose()?;
    let archive = value
        .get("archive")
        .map(|archive| archive.as_str().ok_or(ErrorCode::InvalidInput))
        .transpose()?;
    let note_id = value
        .get("note_id")
        .map(|id| {
            id.as_str()
                .and_then(|id| Uuid::parse_str(id).ok())
                .ok_or(ErrorCode::InvalidInput)
        })
        .transpose()?;
    Ok(NoteEnumerationFilter {
        note_kinds,
        occurred_since: bound("since")?,
        occurred_until: bound("until")?,
        note_id,
        lifecycle: Lifecycle::for_enumerate(statuses.as_deref(), archive)?,
    })
}

fn rfc3339(at: OffsetDateTime) -> Result<String, ErrorCode> {
    at.format(&Rfc3339).map_err(|_| ErrorCode::Internal)
}

fn output(structured_content: Value) -> Result<ToolOutput, ErrorCode> {
    if !structured_content.is_object() {
        return Err(ErrorCode::Internal);
    }
    let text = serde_json::to_string(&structured_content).map_err(|_| ErrorCode::Internal)?;
    Ok(ToolOutput {
        text,
        structured_content,
        is_error: false,
    })
}

#[cfg(test)]
#[allow(dead_code)]
#[path = "../../../crates/adapters/tests/support/operation_receipt_fixture.rs"]
mod operation_receipt_fixture;

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        collections::BTreeMap,
        ffi::OsString,
        net::{Ipv6Addr, SocketAddr},
        os::unix::ffi::OsStringExt,
        str::FromStr,
        sync::Arc,
        time::Duration,
    };

    use humaux_adapters::{postgres::RuntimeDbPool, quota_repo::RatePolicy};
    use humaux_domain::{
        context::ContextBudget,
        dataclass::DataClass,
        identity::{BoundedSet, PrincipalId, VisibilityClass},
        ids::{TenantId, UserId, WorkspaceId},
    };
    use humaux_protocol::{
        edge::{Cidr, TrustedProxyConfig, compute_api_key_hash},
        mcp::{McpAdapter, McpHttpConfig},
        mcp_catalog::CanonicalCatalog,
    };
    use humaux_testkit::run_db_fixture;
    use postgres::{Client, GenericClient, NoTls};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    use uuid::Uuid;

    use super::operation_receipt_fixture::{
        Fixture, Handle, SYNTHETIC_CREDENTIAL_PEPPER, SyntheticCredentialScopes,
    };
    use crate::guard::{GuardRatePolicies, GuardSettings};

    const HOST: &str = "mcp.test";
    const ORIGIN: &str = "https://mcp.test";
    const BARRIER_RUN_ID: &str = "HUMAUX_CONTINUITY_W2_BARRIER_RUN_ID";
    const BARRIER_SIDE: &str = "HUMAUX_CONTINUITY_W2_BARRIER_SIDE";
    const SAME_KEY_SENTINEL: &str = "W2_EXPECTED_SAME_KEY_429:v1";
    const SAME_KEY_PANIC: &str = "W2_EXPECTED_SAME_KEY_429_PANIC:v1";

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum BarrierSide {
        A,
        B,
    }

    impl BarrierSide {
        fn as_str(self) -> &'static str {
            match self {
                Self::A => "A",
                Self::B => "B",
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum BarrierConfig {
        Disabled,
        Enabled { run_id: Uuid, side: BarrierSide },
    }

    fn parse_barrier_config(
        run_id: Result<String, std::env::VarError>,
        side: Result<String, std::env::VarError>,
    ) -> Result<BarrierConfig, String> {
        match (run_id, side) {
            (Err(std::env::VarError::NotPresent), Err(std::env::VarError::NotPresent)) => {
                Ok(BarrierConfig::Disabled)
            }
            (Ok(run_id), Ok(side)) => {
                let parsed = Uuid::parse_str(&run_id)
                    .map_err(|_| format!("{BARRIER_RUN_ID} must be a canonical UUID"))?;
                if parsed.hyphenated().to_string() != run_id {
                    return Err(format!("{BARRIER_RUN_ID} must be a canonical UUID"));
                }
                let side = match side.as_str() {
                    "A" => BarrierSide::A,
                    "B" => BarrierSide::B,
                    _ => return Err(format!("{BARRIER_SIDE} must be A or B")),
                };
                Ok(BarrierConfig::Enabled {
                    run_id: parsed,
                    side,
                })
            }
            (Err(error), _) | (_, Err(error)) => Err(format!(
                "{BARRIER_RUN_ID} and {BARRIER_SIDE} must both be absent or both be valid: {error}"
            )),
        }
    }

    fn barrier_config() -> BarrierConfig {
        parse_barrier_config(std::env::var(BARRIER_RUN_ID), std::env::var(BARRIER_SIDE))
            .unwrap_or_else(|error| panic!("invalid W2 barrier configuration: {error}"))
    }

    fn rate() -> RatePolicy {
        RatePolicy::new(10_000, 10_000).expect("nonbinding continuity fixture rate")
    }

    fn test_guard(runtime: RuntimeDbPool) -> Arc<GatewayGuard> {
        Arc::new(
            GatewayGuard::new(
                runtime,
                GuardSettings {
                    credential_pepper: SYNTHETIC_CREDENTIAL_PEPPER.to_vec(),
                    credential_pepper_previous: None,
                    trusted_proxies: TrustedProxyConfig {
                        trusted_proxy_cidrs: vec![Cidr::from_str("127.0.0.1/32").unwrap()],
                        max_forwarded_hops: 1,
                    },
                    global_denylist: vec![],
                    global_emergency_allowlist: vec![],
                    tenant_network: BTreeMap::new(),
                    rates: GuardRatePolicies {
                        preauth_ip: rate(),
                        credential: rate(),
                        user: rate(),
                        tenant: rate(),
                        operation: rate(),
                        lock_timeout: Duration::from_secs(2),
                        preauth_ipv6_prefix_bits: 64,
                    },
                    reservation_ttl: Duration::from_secs(30),
                    handler_timeout: Duration::from_secs(5),
                    finalize_timeout: Duration::from_secs(2),
                    replay_ttl: Duration::from_secs(60),
                },
            )
            .expect("explicit guard settings"),
        )
    }

    fn test_application(
        handle: &Handle,
        runtime: RuntimeDbPool,
        scope: humaux_domain::identity::AuthorizationScope,
    ) -> GatewayMcpApplication {
        let policy = RememberPolicy::new(
            crate::remember::ProcessFamily::new("workspace", "knowledge", "ingest", "v1").unwrap(),
            handle.reasoning_domain_id,
            Duration::from_secs(60),
            DataClass::Internal,
            VisibilityClass::WorkspaceShared,
        )
        .unwrap();
        let bootstrap = ContextBootstrap::new(
            ContextBudget::new(2_048, 1_024).unwrap(),
            humaux_contracts::retrieval_config::resolve_registered_retrieval_profile(
                &Default::default(),
            )
            .unwrap(),
            &policy,
            std::time::Duration::from_secs(60),
        )
        .unwrap();
        GatewayMcpApplication::new(
            CanonicalCatalog::load().unwrap(),
            test_guard(runtime),
            policy,
            RememberEventKind::UserMessage,
            bootstrap,
        )
        .with_trusted_continuity_scope(scope)
    }

    fn set_context(
        client: &mut impl GenericClient,
        tenant: Uuid,
        workspace: Uuid,
        principal: Uuid,
        user: Uuid,
    ) {
        client
            .query_one(
                "SELECT set_config('humaux.tenant_id',$1,true),\
                        set_config('humaux.workspace_id',$2,true),\
                        set_config('humaux.principal_id',$3,true),\
                        set_config('humaux.user_id',$4,true)",
                &[
                    &tenant.to_string(),
                    &workspace.to_string(),
                    &principal.to_string(),
                    &user.to_string(),
                ],
            )
            .unwrap();
    }

    fn register_for(client: &mut Client, handle: &Handle, project: Uuid, title: &str) {
        client.batch_execute("BEGIN").unwrap();
        set_context(
            client,
            handle.tenant_id,
            handle.workspace_id,
            handle.principal_id,
            handle.user_id,
        );
        client
            .query_one(
                "SELECT private.register_continuity_project($1,$2,$3,$4,$5,$6)",
                &[
                    &handle.tenant_id,
                    &handle.workspace_id,
                    &project,
                    &handle.principal_id,
                    &Some(handle.user_id),
                    &title,
                ],
            )
            .unwrap();
        client.batch_execute("COMMIT").unwrap();
    }

    fn publish_goal(client: &mut Client, handle: &mut Handle, project: Uuid, memory: Uuid) {
        let memory_hash: Vec<u8> = handle
            .admin
            .query_one(
                "SELECT sha256(convert_to(content::text,'UTF8'))\
                 FROM private.memory_records WHERE tenant_id=$1 AND memory_id=$2",
                &[&handle.tenant_id, &memory],
            )
            .unwrap()
            .get(0);
        client.batch_execute("BEGIN").unwrap();
        set_context(
            client,
            handle.tenant_id,
            handle.workspace_id,
            handle.principal_id,
            handle.user_id,
        );
        client
            .query_one(
                "SELECT facet_version_id FROM private.publish_continuity_facet(\
                   $1,$2,$3,$4,$5,'GOAL',0,'CURRENT',$6,$7,$8,$9,$10)",
                &[
                    &handle.tenant_id,
                    &handle.workspace_id,
                    &project,
                    &handle.principal_id,
                    &Some(handle.user_id),
                    &json!({"goal":"native continuity"}),
                    &vec![memory],
                    &vec![memory_hash],
                    &Vec::<Uuid>::new(),
                    &Vec::<Vec<u8>>::new(),
                ],
            )
            .unwrap();
        client.batch_execute("COMMIT").unwrap();
    }

    async fn start(
        application: GatewayMcpApplication,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let catalog = CanonicalCatalog::load().unwrap().trusted_catalog().unwrap();
        let adapter = McpAdapter::new(
            Arc::new(application),
            catalog,
            McpHttpConfig::new(vec![HOST.into()], vec![ORIGIN.into()], 64 * 1024).unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                adapter
                    .router()
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        (address, server)
    }

    async fn stop_server(server: tokio::task::JoinHandle<()>) {
        server.abort();
        match server.await {
            Ok(()) => eprintln!(
                "continuity_server_join pid={} result=clean",
                std::process::id()
            ),
            Err(error) if error.is_cancelled() => eprintln!(
                "continuity_server_join pid={} result=cancelled",
                std::process::id()
            ),
            Err(error) => panic!("continuity test server failed: {error}"),
        }
    }

    async fn request_and_stop(
        address: SocketAddr,
        bearer: &str,
        project: Uuid,
        logical_request: &'static str,
        forwarded: Option<Ipv6Addr>,
        server: tokio::task::JoinHandle<()>,
    ) -> Value {
        let bearer = bearer.to_owned();
        let request = tokio::spawn(async move {
            request(address, &bearer, project, logical_request, forwarded).await
        });
        let result = request.await;
        stop_server(server).await;
        match result {
            Ok(value) => value,
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(error) => panic!("continuity request task failed: {error}"),
        }
    }

    fn barrier_sql(statement: &'static str) -> String {
        match statement {
            "ready" => "INSERT INTO control.w2_test_request_intervals(run_uuid,side,ready_at)\nVALUES($1,$2,clock_timestamp())".to_owned(),
            "start" => "UPDATE control.w2_test_request_intervals\nSET request_start_at=clock_timestamp()\nWHERE run_uuid=$1 AND side=$2 AND request_start_at IS NULL".to_owned(),
            "end" => "UPDATE control.w2_test_request_intervals\nSET request_end_at=clock_timestamp()\nWHERE run_uuid=$1 AND side=$2 AND request_start_at IS NOT NULL\n  AND request_end_at IS NULL".to_owned(),
            "both_ready" => "SELECT count(*) FROM control.w2_test_request_intervals\nWHERE run_uuid=$1 AND side IN ('A','B') AND ready_at IS NOT NULL".to_owned(),
            "both_end" => "SELECT count(*) FROM control.w2_test_request_intervals\nWHERE run_uuid=$1 AND side IN ('A','B') AND request_end_at IS NOT NULL".to_owned(),
            _ => unreachable!("fixed W2 barrier statement"),
        }
    }

    async fn barrier_statement(dsn: String, config: BarrierConfig, statement: &'static str) {
        let BarrierConfig::Enabled { run_id, side } = config else {
            return;
        };
        tokio::task::spawn_blocking(move || {
            // dep: PostgreSQL(role_gateway) — test fixture pool for a §33.10 dispatch-table integration test
            let mut client = Client::connect(&dsn, NoTls)
                .unwrap_or_else(|error| panic!("W2 barrier connect failed: {error}"));
            let side = side.as_str();
            match statement {
                "ready" => assert_eq!(
                    client
                        .execute(&barrier_sql(statement), &[&run_id, &side])
                        .unwrap(),
                    1,
                    "W2 barrier ready must insert exactly one row"
                ),
                "start" => assert_eq!(
                    client
                        .execute(&barrier_sql(statement), &[&run_id, &side])
                        .unwrap(),
                    1,
                    "W2 barrier start must update exactly one row"
                ),
                "end" => assert_eq!(
                    client
                        .execute(&barrier_sql(statement), &[&run_id, &side])
                        .unwrap(),
                    1,
                    "W2 barrier end must update exactly one row"
                ),
                "both_ready" | "both_end" => loop {
                    let sql = barrier_sql(statement);
                    let count: i64 = client.query_one(&sql, &[&run_id]).unwrap().get(0);
                    if count == 2 {
                        break;
                    }
                    if count > 2 {
                        panic!("W2 barrier {statement} observed unexpected row count {count}");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                },
                _ => unreachable!("fixed W2 barrier statement"),
            }
        })
        .await
        .unwrap_or_else(|error| panic!("W2 barrier worker failed: {error}"));
    }

    async fn barrier_request_and_stop(
        dsn: &str,
        config: BarrierConfig,
        address: SocketAddr,
        bearer: &str,
        project: Uuid,
        forwarded: Option<Ipv6Addr>,
        server: tokio::task::JoinHandle<()>,
    ) -> Value {
        barrier_statement(dsn.to_owned(), config, "ready").await;
        barrier_statement(dsn.to_owned(), config, "both_ready").await;
        barrier_statement(dsn.to_owned(), config, "start").await;
        let bearer = bearer.to_owned();
        let result =
            tokio::spawn(
                async move { request(address, &bearer, project, "A_then_B", forwarded).await },
            )
            .await;
        match result {
            Ok(value) => {
                barrier_statement(dsn.to_owned(), config, "end").await;
                stop_server(server).await;
                barrier_statement(dsn.to_owned(), config, "both_end").await;
                value
            }
            Err(error) if error.is_panic() => {
                stop_server(server).await;
                std::panic::resume_unwind(error.into_panic());
            }
            Err(error) => {
                stop_server(server).await;
                panic!("continuity request task failed: {error}");
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn request(
        address: SocketAddr,
        bearer: &str,
        project: Uuid,
        logical_request: &str,
        forwarded: Option<Ipv6Addr>,
    ) -> Value {
        let body = json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"tools/call",
            "params":{
                "name":"continuity",
                "arguments":{"project_id":project},
                "_meta":{
                    "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                    "io.modelcontextprotocol/clientInfo":{"name":"continuity-w2","version":"1"},
                    "io.modelcontextprotocol/clientCapabilities":{}
                }
            }
        })
        .to_string();
        let headers = [
            ("MCP-Protocol-Version", "2026-07-28"),
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", "continuity"),
            ("Authorization", bearer),
        ];
        // dep: HTTP(gateway) — test helper dials the gateway's own HTTP listener to exercise the wire contract
        let mut stream = TcpStream::connect(address).await.unwrap();
        let mut wire = format!(
            "POST /mcp HTTP/1.1\r\nHost: {HOST}\r\nOrigin: {ORIGIN}\r\nConnection: close\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (name, value) in headers {
            wire.push_str(name);
            wire.push_str(": ");
            wire.push_str(value);
            wire.push_str("\r\n");
        }
        if let Some(forwarded) = forwarded {
            wire.push_str("Forwarded: ");
            wire.push_str(&forwarded.to_string());
            wire.push_str("\r\n");
        }
        wire.push_str("\r\n");
        wire.push_str(&body);
        stream.write_all(wire.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response_bytes = response.len();
        let response = String::from_utf8(response).unwrap();
        let (head, encoded_body) = response.split_once("\r\n\r\n").unwrap();
        let status_line = head.lines().next().unwrap_or("<missing>");
        let mut content_length = None;
        let mut transfer_encoding = None;
        let mut content_type = None;
        let headers = head
            .lines()
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| {
                let name = name.trim();
                let value = value.trim();
                match name.to_ascii_lowercase().as_str() {
                    "content-length" => content_length = Some(value),
                    "transfer-encoding" => transfer_encoding = Some(value),
                    "content-type" => content_type = Some(value),
                    _ => {}
                }
                let value = if matches!(
                    name.to_ascii_lowercase().as_str(),
                    "authorization" | "cookie" | "set-cookie" | "x-api-key"
                ) {
                    "<redacted>"
                } else {
                    value
                };
                format!("{name}={value}")
            })
            .collect::<Vec<_>>()
            .join(", ");
        let encoded_body_bytes = encoded_body.len();
        let diagnostic = || {
            format!(
                "pid={} logical_request={logical_request} status_line={status_line:?} \
                 headers=[{headers}] response_bytes={response_bytes} \
                 encoded_body_bytes={encoded_body_bytes} content_length={content_length:?} \
                 transfer_encoding={transfer_encoding:?} content_type={content_type:?} \
                 body_prefix={:?}",
                std::process::id(),
                encoded_body
                    .as_bytes()
                    .get(..encoded_body_bytes.min(256))
                    .unwrap_or_default()
                    .escape_ascii()
                    .to_string(),
            )
        };
        let status = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or_else(|| panic!("continuity HTTP response missing status: {}", diagnostic()));
        assert!(
            transfer_encoding.is_none(),
            "continuity HTTP response unsupported transfer encoding: {}",
            diagnostic()
        );
        if let Some(content_length) = content_length {
            let content_length = content_length.parse::<usize>().unwrap_or_else(|_| {
                panic!(
                    "continuity HTTP response invalid Content-Length: {}",
                    diagnostic()
                )
            });
            assert_eq!(
                encoded_body_bytes,
                content_length,
                "continuity HTTP response Content-Length mismatch: {}",
                diagnostic()
            );
        }
        let body = if encoded_body.starts_with("event:") {
            encoded_body
                .lines()
                .find_map(|line| line.strip_prefix("data: "))
                .unwrap()
        } else {
            encoded_body
        };
        let value: Value = serde_json::from_str(body).unwrap_or_else(|error| {
            panic!(
                "continuity HTTP response parse failure: {} error={error}",
                diagnostic(),
            );
        });
        if status == 429 && direct_preauth_same_key() {
            assert_eq!(
                value["result"]["isError"],
                true,
                "strict same-key 429 must be an MCP error: {}",
                diagnostic()
            );
            assert_eq!(
                value["result"]["structuredContent"]["code"],
                "RATE_LIMITED",
                "strict same-key 429 must be RATE_LIMITED: {}",
                diagnostic()
            );
            eprintln!("{SAME_KEY_SENTINEL}");
            panic!("{SAME_KEY_PANIC}");
        }
        assert_eq!(
            status,
            200,
            "continuity HTTP response unexpected status: {}",
            diagnostic()
        );
        value
    }

    fn direct_preauth_same_key() -> bool {
        match std::env::var("HUMAUX_CONTINUITY_DIRECT_PREAUTH_SAME_KEY") {
            Err(std::env::VarError::NotPresent) => false,
            Ok(value) if value == "1" => true,
            _ => panic!("HUMAUX_CONTINUITY_DIRECT_PREAUTH_SAME_KEY must be unset or 1"),
        }
    }

    fn fixture_forwarded(tenant_id: Uuid) -> Option<Ipv6Addr> {
        (!direct_preauth_same_key()).then(|| {
            Ipv6Addr::from((0x2001_0db8_u128 << 96) | (tenant_id.as_u128() & ((1_u128 << 96) - 1)))
        })
    }

    #[test]
    fn w2_barrier_config_is_pure_and_fail_closed() {
        let run_id = Uuid::now_v7();
        assert_eq!(
            parse_barrier_config(
                Err(std::env::VarError::NotPresent),
                Err(std::env::VarError::NotPresent)
            ),
            Ok(BarrierConfig::Disabled)
        );
        assert_eq!(
            parse_barrier_config(Ok(run_id.to_string()), Ok("A".to_owned())),
            Ok(BarrierConfig::Enabled {
                run_id,
                side: BarrierSide::A,
            })
        );
        for (run_id, side) in [
            (Ok(run_id.to_string()), Err(std::env::VarError::NotPresent)),
            (Err(std::env::VarError::NotPresent), Ok("B".to_owned())),
            (Ok("not-a-uuid".to_owned()), Ok("A".to_owned())),
            (Ok(run_id.to_string().to_uppercase()), Ok("A".to_owned())),
            (Ok(run_id.to_string()), Ok("C".to_owned())),
            (
                Err(std::env::VarError::NotUnicode(OsString::from_vec(vec![
                    0xff,
                ]))),
                Ok("A".to_owned()),
            ),
        ] {
            assert!(parse_barrier_config(run_id, side).is_err());
        }
    }

    #[test]
    fn w2_barrier_sql_is_whitespace_separated_and_parameterized() {
        let cases = [
            (
                "ready",
                "INSERT INTO control.w2_test_request_intervals(run_uuid,side,ready_at)",
                &["$1", "$2"][..],
            ),
            (
                "start",
                "UPDATE control.w2_test_request_intervals",
                &["$1", "$2"][..],
            ),
            (
                "end",
                "UPDATE control.w2_test_request_intervals",
                &["$1", "$2"][..],
            ),
            (
                "both_ready",
                "SELECT count(*) FROM control.w2_test_request_intervals",
                &["$1"][..],
            ),
            (
                "both_end",
                "SELECT count(*) FROM control.w2_test_request_intervals",
                &["$1"][..],
            ),
        ];
        for (statement, prefix, placeholders) in cases {
            let sql = barrier_sql(statement);
            assert!(!sql.as_bytes().contains(&b'\\'), "{statement}: {sql:?}");
            assert!(sql.starts_with(prefix), "{statement}: {sql}");
            for placeholder in placeholders {
                assert!(sql.contains(placeholder), "{statement}: {sql}");
            }
            assert!(sql.contains("\n"), "{statement}: {sql}");
        }
        assert!(barrier_sql("ready").contains("VALUES($1,$2,clock_timestamp())"));
        assert!(barrier_sql("start").contains("SET request_start_at=clock_timestamp()"));
        assert!(barrier_sql("end").contains("SET request_end_at=clock_timestamp()"));
        assert!(barrier_sql("both_ready").contains("ready_at IS NOT NULL"));
        assert!(barrier_sql("both_end").contains("request_end_at IS NOT NULL"));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn trusted_multi_workspace_omission_resolves_exact_project_parent_not_first() {
        run_db_fixture::<Fixture, _>(
            "trusted_multi_workspace_omission_resolves_exact_project_parent_not_first",
            |mut handle| {
                let prefix = format!("ct{}", Uuid::now_v7().simple());
                let wire = format!("{prefix}.{}", "d".repeat(32));
                let credential = handle.seed_synthetic_service_credential_and_window(
                    SyntheticCredentialScopes::ContextRead,
                    &prefix,
                    &wire,
                    &compute_api_key_hash(SYNTHETIC_CREDENTIAL_PEPPER, &wire),
                    20,
                );
                let source = handle.seed_workspace_visible_context_record();
                let project = Uuid::now_v7();
                let parent_b = handle.workspace_id;
                assert_ne!(parent_b, Uuid::nil(), "fixture parent B must be non-nil");
                let workspace_a =
                    handle.seed_workspace_with_id(Uuid::from_u128(parent_b.as_u128() - 1));
                let scope_a_then_b = humaux_domain::identity::AuthorizationScope::new(
                    TenantId(handle.tenant_id),
                    PrincipalId(handle.principal_id),
                    Some(UserId(handle.user_id)),
                    BoundedSet::new([WorkspaceId(workspace_a), WorkspaceId(parent_b)]).unwrap(),
                );
                let scope_b_then_a = humaux_domain::identity::AuthorizationScope::new(
                    TenantId(handle.tenant_id),
                    PrincipalId(handle.principal_id),
                    Some(UserId(handle.user_id)),
                    BoundedSet::new([WorkspaceId(parent_b), WorkspaceId(workspace_a)]).unwrap(),
                );
                assert!(
                    workspace_a < parent_b,
                    "A must sort before B for the mutation control"
                );
                assert_eq!(
                    scope_a_then_b
                        .allowed_workspace_ids()
                        .iter()
                        .next()
                        .copied(),
                    Some(WorkspaceId(workspace_a)),
                    "the first allowed workspace is deliberately the wrong parent A"
                );
                let mut gateway = handle.gateway_client().unwrap();
                register_for(&mut gateway, &handle, project, "parent-b");
                publish_goal(&mut gateway, &mut handle, project, source.memory_id);
                let dsn = handle.gateway_dsn_for_process().to_owned();
                let forwarded = fixture_forwarded(handle.tenant_id);
                let barrier = barrier_config();
                if let Some(forwarded) = forwarded {
                    // Baseline §73.2 / ADR-0062 E5: the pre-auth bucket of an IPv6 client is its /64.
                    handle.seed_legacy_system_preauth_bucket(
                        humaux_adapters::quota_repo::preauth_ip_subject(forwarded.into(), 64),
                    );
                }
                let runtime_handle = handle.rt.handle().clone();
                let first_only = runtime_handle.block_on(async {
                    // dep: PostgreSQL(role_gateway) — test fixture pool for a dispatch-table integration test
                    let runtime = RuntimeDbPool::connect(&dsn).await.unwrap();
                    let scope = humaux_domain::identity::AuthorizationScope::new(
                        TenantId(handle.tenant_id),
                        PrincipalId(handle.principal_id),
                        Some(UserId(handle.user_id)),
                        BoundedSet::new([WorkspaceId(workspace_a)]).unwrap(),
                    );
                    let (address, server) = start(test_application(&handle, runtime, scope)).await;
                    request_and_stop(
                        address,
                        &credential.bearer,
                        project,
                        "first_only",
                        forwarded,
                        server,
                    )
                    .await
                });
                assert_eq!(
                    first_only["result"]["structuredContent"]["code"], "NOT_FOUND",
                    "a first-only A authorization cannot read the B parent"
                );
                if let Some(forwarded) = forwarded {
                    let row = handle
                        .admin
                        .query_one(
                            "SELECT capacity, refill_per_second FROM control.rate_buckets \
                         WHERE tenant_id='00000000-0000-0000-0000-000000000000' \
                           AND subject_kind='ip' AND subject_id=$1 \
                           AND operation='mcp' AND bucket_key='preauth'",
                            &[&humaux_adapters::quota_repo::preauth_ip_subject(
                                forwarded.into(),
                                64,
                            )],
                        )
                        .unwrap();
                    assert_eq!(row.get::<_, i64>(0), 10_000);
                    assert_eq!(row.get::<_, i64>(1), 10_000);
                }
                let first = runtime_handle.block_on(async {
                    // dep: PostgreSQL(role_gateway) — test fixture pool for a dispatch-table integration test
                    let runtime = RuntimeDbPool::connect(&dsn).await.unwrap();
                    let (address, server) =
                        start(test_application(&handle, runtime, scope_a_then_b)).await;
                    match barrier {
                        BarrierConfig::Disabled => {
                            request_and_stop(
                                address,
                                &credential.bearer,
                                project,
                                "A_then_B",
                                forwarded,
                                server,
                            )
                            .await
                        }
                        BarrierConfig::Enabled { .. } => {
                            barrier_request_and_stop(
                                &dsn,
                                barrier,
                                address,
                                &credential.bearer,
                                project,
                                forwarded,
                                server,
                            )
                            .await
                        }
                    }
                });
                let second = runtime_handle.block_on(async {
                    // dep: PostgreSQL(role_gateway) — test fixture pool for a dispatch-table integration test
                    let runtime = RuntimeDbPool::connect(&dsn).await.unwrap();
                    let (address, server) =
                        start(test_application(&handle, runtime, scope_b_then_a)).await;
                    request_and_stop(
                        address,
                        &credential.bearer,
                        project,
                        "B_then_A",
                        forwarded,
                        server,
                    )
                    .await
                });
                for value in [&first, &second] {
                    assert_ne!(value["result"]["isError"], true, "{value}");
                    assert_eq!(
                        value["result"]["structuredContent"]["project_id"],
                        project.to_string()
                    );
                    assert_eq!(
                        value["result"]["structuredContent"]["facets"]
                            .as_array()
                            .unwrap()
                            .len(),
                        17
                    );
                }
                assert_eq!(
                    first["result"]["structuredContent"]["project_id"],
                    second["result"]["structuredContent"]["project_id"]
                );
                assert_eq!(
                    first["result"]["structuredContent"]["facets"],
                    second["result"]["structuredContent"]["facets"],
                    "scope insertion order must not affect the B parent result"
                );
                assert_eq!(
                    first["result"]["structuredContent"]["coverage"],
                    second["result"]["structuredContent"]["coverage"]
                );
            },
        );
    }

    #[test]
    fn remember_preserves_content_bytes_and_rejects_mismatched_decoding() {
        let raw = r#"{"operation":"put","content":"kept\u0020raw","idempotency_key":"one"}"#;
        let decoded: Value = serde_json::from_str(raw).unwrap();
        assert!(
            CanonicalCatalog::load()
                .unwrap()
                .validate(ToolName::Remember, &decoded)
                .is_ok()
        );
        let prepared = RememberPutWire::from_raw(raw, &decoded).unwrap();
        assert_eq!(prepared.content.raw_json(), br#""kept\u0020raw""#);
        let mut unrelated = decoded;
        unrelated["content"] = json!("changed");
        assert!(matches!(
            RememberPutWire::from_raw(raw, &unrelated),
            Err(ErrorCode::InvalidInput)
        ));
    }
}
