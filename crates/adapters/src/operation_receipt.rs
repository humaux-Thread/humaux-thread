//! `adapters::operation_receipt` — §34.0.1 local `remember.put`: one transaction for business, BMO, audit, and
//!   receipt.
//! Depends-on: crates=[hex, humaux-domain, sqlx, time, uuid]; services=[PostgreSQL(any) r=[control.memberships, control.tenants, control.users, private.evidence_objects, private.memory_evidence, private.memory_records, private.note_heads, projection.stream_log] w=[control.operation_receipts]]; env=[]; modules=[adapters::confirm_token_repo, adapters::memory_governance_repo, adapters::note_repo, adapters::postgres, adapters::quota_repo, adapters::read_materialize, adapters::remember, adapters::request_guard_repo, adapters::retrieve, domain::audit, domain::authority, domain::confirm, domain::dataclass, domain::error, domain::evidence, domain::identity, domain::ids, domain::note]
//! Called-by: [gateway::guard, gateway::mcp_application, tests]
//! Invariants: [receipts are written in the operation's own transaction; a failed COMMIT response is an unknown
//!   outcome, never permission to repeat the write; tenant/visibility failures are TenantBoundary/NotFound; a note
//!   replacement checks its receipt before it locks the note head, and consumes its token only under that lock
//!   (ADR-0067 D-J)]
//! Spec: ADR-0067
//!
//! A failed COMMIT response is an unknown outcome, never permission to repeat a write.

use std::time::Duration;

use humaux_domain::{
    audit::{AuditEvent, AuditEventId, McpAuditAction},
    authority::MemoryId,
    confirm::DestructiveOp,
    dataclass::DataClass,
    error::ErrorCode,
    evidence::EvidenceOriginClass,
    identity::{AuthorizationScope, VisibilityClass, VisibilityDescriptor, can_read},
    ids::{UserId, WorkspaceId},
    note::replace_intent_sha256,
};
use sqlx::{Row, postgres::PgRow};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    confirm_token_repo::{self, ConfirmationClaim},
    memory_governance_repo,
    note_repo::{self, NoteIntake, NoteLineage},
    postgres::RuntimeDbPool,
    quota_repo::{self, ReservationStatus, ReserveResult},
    read_materialize,
    remember::{self, RememberAccepted, RememberCommand, RememberError},
    request_guard_repo::{self, AuditTenant},
    retrieve::{TokenClaims, issue_consistency_token},
};

const OPERATION: &str = "remember.put";
/// ADR-0067 D-A: the receipt / BMO operation of an identity note. A separate key from [`OPERATION`], so the same idempotency
/// key under the two operations is two operations.
pub const NOTE_OPERATION: &str = "memory.note_put";
type Txn<'c> = sqlx::Transaction<'c, sqlx::Postgres>;

/// §6.1.1 / ADR-0032 D-B: the `control.memberships.role` values whose ACTIVE holder may write
/// `TENANT_SHARED` Evidence through `remember.put`. A tenant-wide audience is the widest class
/// there is, so it is gated on the membership role rather than on the credential scope alone
/// (`memory:write` is what every member already holds); any other role is `INVALID_INPUT`
/// with nothing written or metered. §78.2: these are two of the three values of the column's
/// closed set — migration 0160 `memberships_role_known` CHECK (`OWNER | ADMIN | MEMBER`) plus
/// the `memberships_canonical_role` trigger that folds every write to that spelling — so an
/// exact match here is exact against the whole set, never a silent deny for a writer's
/// spelling. The set lives here once, next to the one statement that reads it.
pub const TENANT_SHARED_WRITER_ROLES: [&str; 2] = ["OWNER", "ADMIN"];

/// Trusted application inputs. This is not a deserializable MCP request or a credential.
pub struct AtomicRememberRequest {
    pub request_id: Uuid,
    pub idempotency_key: String,
    pub request_fingerprint: String,
    pub workspace_id: Option<WorkspaceId>,
    pub reservation_ttl: Duration,
    pub replay_ttl: Duration,
    pub command: RememberCommand,
    pub finished_audit: AuditEvent,
}

#[derive(Debug)]
pub struct AtomicRememberResult {
    pub accepted: RememberAccepted,
    pub replayed: bool,
    /// ADR-0067: the Memory the same transaction wrote (or, on a replay, wrote originally) for a `memory.note_put`;
    /// `None` for `remember.put`.
    pub memory_id: Option<Uuid>,
    /// §18.2: the stored Evidence is `SECRET_MATERIAL` (no card, no vector). On a replay it is read from the stored
    /// row, so a changed gateway default cannot change the answer for the same idempotency key (PR #7 Codex P2).
    /// Resolved for `memory.note_put` only; always `false` for `remember.put`.
    pub secret_material: bool,
}

/// ADR-0067 D-J: a `memory.note_put` replacement's own inputs, on top of a create's request and [`NoteIntake`].
#[derive(Debug, Clone)]
pub struct NoteReplaceRequest {
    /// The note being versioned.
    pub note_id: Uuid,
    /// The head version the caller expects (the CAS).
    pub supersedes: Uuid,
    /// `None` = the confirm challenge (checks only: nothing written, 0 BMO); `Some` = the confirmed commit, whose token
    /// is consumed in the same transaction.
    pub claim: Option<ConfirmationClaim>,
}

/// ADR-0067 D-J: how one replacement call ended. Business refusals with no `ErrorCode` of their own are variants
/// (§52.1 stays at 18 codes).
#[derive(Debug)]
pub enum NoteReplaceOutcome {
    /// Committed by this call, or (`replayed`) earlier under the same key and intent.
    Stored(AtomicRememberResult),
    /// Challenge leg: every check holds, the caller may mint a token. Nothing was written.
    Confirmable,
    /// `supersedes` is not the note's head: `STALE_NOTE_VERSION`. Nothing was written.
    StaleVersion,
}

fn db_error(error: sqlx::Error) -> ErrorCode {
    match error {
        sqlx::Error::RowNotFound => ErrorCode::NotFound,
        sqlx::Error::Database(ref database) => match database.code().as_deref() {
            Some("42501") => ErrorCode::Forbidden,
            Some("23503") => ErrorCode::TenantBoundary,
            // 55000: the ADR-0053 PROVISIONING write gate (a definite, rolled-back refusal).
            Some("23505" | "40001" | "40P01" | "55P03" | "55000") => ErrorCode::Conflict,
            Some("22023" | "22P02" | "22003") => ErrorCode::InvalidInput,
            _ => ErrorCode::Internal,
        },
        _ => ErrorCode::DependencyUnavailable,
    }
}

fn remember_error(error: RememberError) -> ErrorCode {
    match error {
        RememberError::ConsistencyTokenExpiryNotFuture => ErrorCode::Conflict,
        RememberError::BatchExhausted => ErrorCode::Conflict,
        // §6.1.3: an unresolvable subject declaration is INVALID_INPUT with nothing written.
        RememberError::Subject(code) | RememberError::Affect(code) | RememberError::Note(code) => {
            code
        }
        // §11.2.1 / ADR-0032 D-A: the caller tenant has no reasoning domain to process this
        // Evidence under — not provisioned for writes, nothing written, retryable once it is.
        RememberError::ReasoningDomainUnresolved | RememberError::TokenKeysUnset => {
            ErrorCode::DependencyUnavailable
        }
        RememberError::Db(error) => db_error(error),
    }
}

fn field<T>(row: &PgRow, name: &str) -> Result<T, ErrorCode>
where
    T: for<'r> sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(name).map_err(|_| ErrorCode::Internal)
}

fn valid_key(key: &str) -> bool {
    (1..=128).contains(&key.len())
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}

fn visibility_is_bound_to_route(
    authorization_user_id: Option<Uuid>,
    workspace_id: Option<WorkspaceId>,
    visibility_class: &str,
    visibility_user_id: Option<Uuid>,
    visibility_workspace_id: Option<Uuid>,
) -> bool {
    match visibility_class {
        "USER_PRIVATE" => {
            visibility_user_id == authorization_user_id && visibility_workspace_id.is_none()
        }
        "WORKSPACE_SHARED" => {
            workspace_id.is_some()
                && visibility_user_id.is_none()
                && visibility_workspace_id == workspace_id.map(|workspace| workspace.0)
        }
        "TENANT_SHARED" => visibility_user_id.is_none() && visibility_workspace_id.is_none(),
        _ => false,
    }
}

fn validate(
    auth: &AuthorizationScope,
    request: &AtomicRememberRequest,
    operation: &str,
) -> Result<AuthorizationScope, ErrorCode> {
    let cmd = &request.command;
    if auth.tenant_id().0.is_nil() || auth.principal().0.is_nil() || auth.user_id().is_none() {
        return Err(ErrorCode::Unauthorized);
    }
    if !valid_key(&request.idempotency_key)
        || request.request_id.is_nil()
        || request.reservation_ttl.is_zero()
        || request.replay_ttl.is_zero()
        || request.request_fingerprint.len() != 64
        || !request
            .request_fingerprint
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || cmd.batch_id.is_some()
    {
        return Err(ErrorCode::InvalidInput);
    }
    if cmd.tenant_id != auth.tenant_id().0
        || cmd.authorization_user_id != auth.user_id().map(|id| id.0)
        || cmd.origin_principal_id != Some(auth.principal().0)
        || cmd.origin_class != EvidenceOriginClass::AuthenticatedAgent
    {
        return Err(ErrorCode::TenantBoundary);
    }
    let effective_auth = match request.workspace_id {
        Some(workspace) if cmd.scope_kind == "workspace" && cmd.scope_id == workspace.0 => {
            auth.narrow(workspace)?
        }
        None if cmd.scope_kind == "tenant" && cmd.scope_id == auth.tenant_id().0 => auth.clone(),
        _ => return Err(ErrorCode::TenantBoundary),
    };
    if !visibility_is_bound_to_route(
        effective_auth.user_id().map(|user| user.0),
        request.workspace_id,
        &cmd.visibility_class,
        cmd.visibility_user_id,
        cmd.visibility_workspace_id,
    ) {
        return Err(ErrorCode::TenantBoundary);
    }
    let event = &request.finished_audit;
    if event.tenant_id != effective_auth.tenant_id()
        || event.actor_id != effective_auth.principal().0.to_string()
        || event.request_id != request.request_id.to_string()
        || event.action != "MCP_REQUEST_FINISHED"
        || event.resource_id != operation
        || event.result != "OK"
    {
        return Err(ErrorCode::InvalidInput);
    }
    Ok(effective_auth)
}

/// The same logical key must be supplied after an HTTP/COMMIT outcome is unknown.
/// Replays still need a fresh authorized scope from RequestGuard before entering here.
pub async fn remember_atomically(
    pool: &RuntimeDbPool,
    auth: &AuthorizationScope,
    request: AtomicRememberRequest,
) -> Result<AtomicRememberResult, ErrorCode> {
    stored(atomically(pool, auth, request, None, None).await?)
}

/// ADR-0067 D-A: `memory.note_put` — [`remember_atomically`]'s receipt / replay / BMO / audit machinery, plus the identity
/// contract and the authorised Memory in the same transaction. The `request.command` must be a `MANUAL_NOTE` event
/// (the gateway builds it); the receipt operation is [`NOTE_OPERATION`] and the audit's `resource_id` must equal it.
pub async fn note_put_atomically(
    pool: &RuntimeDbPool,
    auth: &AuthorizationScope,
    request: AtomicRememberRequest,
    note: NoteIntake,
) -> Result<AtomicRememberResult, ErrorCode> {
    stored(atomically(pool, auth, request, Some(note), None).await?)
}

/// ADR-0067 D-J `memory.note_put` with `note_id` + `supersedes`: [`note_put_atomically`]'s transaction, with the
/// replacement steps. Order: receipt lock + replay (a committed key answers its stored result whatever the token's state
/// now) -> head row `FOR UPDATE` + CAS + final gate -> (challenge: stop, nothing written) -> BMO -> consume the token ->
/// Evidence, version, contract, old row superseded, head moved (`note_repo::materialize_in_txn`) -> outbox + the old
/// version's retire ticket -> receipt -> COMMIT. `request.request_fingerprint` must be hex of the intent digest `H`.
pub async fn note_replace_atomically(
    pool: &RuntimeDbPool,
    auth: &AuthorizationScope,
    request: AtomicRememberRequest,
    note: NoteIntake,
    replace: NoteReplaceRequest,
) -> Result<NoteReplaceOutcome, ErrorCode> {
    atomically(pool, auth, request, Some(note), Some(replace)).await
}

/// A create / `remember.put` can only end in `Stored`.
fn stored(outcome: NoteReplaceOutcome) -> Result<AtomicRememberResult, ErrorCode> {
    match outcome {
        NoteReplaceOutcome::Stored(result) => Ok(result),
        NoteReplaceOutcome::Confirmable | NoteReplaceOutcome::StaleVersion => {
            Err(ErrorCode::Internal)
        }
    }
}

/// ADR-0067 D-J: the replacement's request binds its intent on its own — the fingerprint is hex `H`, recomputed here
/// from the note and the key, and a presented claim is this op on `supersedes` with exactly `H`. The exact-grant
/// authority check runs before anything is read.
fn validate_replace(
    request: &AtomicRememberRequest,
    note: &NoteIntake,
    replace: &NoteReplaceRequest,
) -> Result<(), ErrorCode> {
    let intent = replace_intent_sha256(
        replace.note_id,
        replace.supersedes,
        note.kind,
        &note.title,
        &note.body,
        note.requested,
        &request.idempotency_key,
    );
    if replace.note_id.is_nil()
        || replace.supersedes.is_nil()
        || request.request_fingerprint != hex::encode(intent)
    {
        return Err(ErrorCode::InvalidInput);
    }
    note_repo::authorize(note).map_err(remember_error)?;
    match &replace.claim {
        Some(claim)
            if claim.op != DestructiveOp::MemoryNoteReplace
                || claim.target_id != replace.supersedes
                || claim.successor_id.is_some()
                || claim.request_sha256 != Some(intent) =>
        {
            Err(ErrorCode::Conflict)
        }
        _ => Ok(()),
    }
}

/// ADR-0067 D-J step 1, under `SELECT … FOR UPDATE` of the note's head row. The head must pass the final read gate (an
/// unknown, invisible, forgotten, revoked or secret head is `NOT_FOUND`), equal `supersedes` (else `Ok(false)`:
/// stale) and be active and not archived (else `CONFLICT`). The command then inherits the head's visibility and data
/// class (no scope input), which must still bind to the request route.
async fn lock_note_head(
    txn: &mut Txn<'_>,
    auth: &AuthorizationScope,
    request: &mut AtomicRememberRequest,
    replace: &NoteReplaceRequest,
) -> Result<bool, ErrorCode> {
    let head: Uuid = sqlx::query_scalar(
        "SELECT head_memory_id FROM private.note_heads WHERE tenant_id = $1 AND note_id = $2 FOR UPDATE",
    )
    .bind(auth.tenant_id().0)
    .bind(replace.note_id)
    .fetch_optional(&mut **txn)
    .await
    .map_err(db_error)?
    .ok_or(ErrorCode::NotFound)?;
    // ADR-0067 D-J2: the head is judged under `memory.get`'s widest selection (history, archived) so that only the
    // hard gates (visibility, forget, secret, revoked/expired) answer NOT_FOUND; status and archive are refused below.
    let gated = read_materialize::final_memory_ids_about_in_txn(
        txn,
        auth,
        &[head],
        read_materialize::Lifecycle::for_get(true),
        &[],
        None,
    )
    .await?;
    if !gated.contains(&head) {
        return Err(ErrorCode::NotFound);
    }
    if head != replace.supersedes {
        return Ok(false);
    }
    let row = sqlx::query(
        "SELECT m.status, m.archived_at IS NOT NULL AS archived, m.visibility_class, m.visibility_user_id, \
                m.visibility_workspace_id, e.data_class \
           FROM private.memory_records m \
           JOIN private.memory_evidence me ON me.memory_id = m.memory_id AND me.role = 'PRIMARY' \
           JOIN private.evidence_objects e ON e.tenant_id = m.tenant_id AND e.evidence_id = me.evidence_id \
          WHERE m.tenant_id = $1 AND m.memory_id = $2",
    )
    .bind(auth.tenant_id().0)
    .bind(head)
    .fetch_optional(&mut **txn)
    .await
    .map_err(db_error)?
    .ok_or(ErrorCode::NotFound)?;
    if field::<String>(&row, "status")? != "active" || field::<bool>(&row, "archived")? {
        return Err(ErrorCode::Conflict);
    }
    let cmd = &mut request.command;
    cmd.visibility_class = field(&row, "visibility_class")?;
    cmd.visibility_user_id = field(&row, "visibility_user_id")?;
    cmd.visibility_workspace_id = field(&row, "visibility_workspace_id")?;
    cmd.data_class = field(&row, "data_class")?;
    if !visibility_is_bound_to_route(
        auth.user_id().map(|user| user.0),
        request.workspace_id,
        &cmd.visibility_class,
        cmd.visibility_user_id,
        cmd.visibility_workspace_id,
    ) {
        return Err(ErrorCode::NotFound);
    }
    Ok(true)
}

#[allow(clippy::too_many_lines)] // one receipt transaction, in §34.0.1 order
async fn atomically(
    pool: &RuntimeDbPool,
    auth: &AuthorizationScope,
    mut request: AtomicRememberRequest,
    note: Option<NoteIntake>,
    replace: Option<NoteReplaceRequest>,
) -> Result<NoteReplaceOutcome, ErrorCode> {
    let operation = if note.is_some() {
        NOTE_OPERATION
    } else {
        OPERATION
    };
    let auth = validate(auth, &request, operation)?;
    if let Some(replace) = &replace {
        validate_replace(&request, note.as_ref().ok_or(ErrorCode::Internal)?, replace)?;
    }
    let replay_duration =
        time::Duration::try_from(request.replay_ttl).map_err(|_| ErrorCode::InvalidInput)?;
    // dep: PostgreSQL(any) — opens a PostgreSQL transaction
    let mut txn = pool.pool().begin().await.map_err(db_error)?;
    let prior = lock_and_find_receipt(&mut txn, &auth, &request, operation).await?;
    if let Some(prior) = prior {
        let accepted = replay(&mut txn, &auth, &request, &prior).await?;
        let (memory_id, secret_material) = if note.is_some() {
            let (memory_id, data_class) =
                note_repo::output_memory(&mut txn, auth.tenant_id().0, accepted.evidence_id)
                    .await
                    .map_err(db_error)?
                    .ok_or(ErrorCode::NotFound)?;
            (
                Some(memory_id),
                data_class == DataClass::SecretMaterial.as_str(),
            )
        } else {
            (None, false)
        };
        txn.commit()
            .await
            .map_err(|_| ErrorCode::DependencyUnavailable)?;
        return Ok(NoteReplaceOutcome::Stored(AtomicRememberResult {
            accepted,
            replayed: true,
            memory_id,
            secret_material,
        }));
    }
    if let Some(replace) = &replace
        && !lock_note_head(&mut txn, &auth, &mut request, replace).await?
    {
        return Ok(NoteReplaceOutcome::StaleVersion);
    }
    // ADR-0032 D-B: TENANT_SHARED is reachable only for an OWNER/ADMIN member; judged in this
    // same transaction (one indexed membership read, only on that path) before any reservation
    // so a refused put leaves no Evidence, no BMO and no receipt.
    if request.command.visibility_class == "TENANT_SHARED"
        && !tenant_shared_write_allowed(&mut txn, &auth).await?
    {
        return Err(ErrorCode::InvalidInput);
    }
    // ADR-0067 D-J: the challenge writes nothing and costs no BMO; dropping `txn` releases the head lock.
    if replace
        .as_ref()
        .is_some_and(|replace| replace.claim.is_none())
    {
        return Ok(NoteReplaceOutcome::Confirmable);
    }
    let reservation = match quota_repo::reserve_bmo_in_txn(
        &mut txn,
        &auth,
        request.request_id,
        operation,
        &request.request_fingerprint,
        request.reservation_ttl,
    )
    .await?
    {
        ReserveResult::Created(reservation) => reservation,
        ReserveResult::Existing(_) => return Err(ErrorCode::Conflict),
    };
    let mut quota_audit = request.finished_audit.clone();
    quota_audit.event_id = AuditEventId::new();
    quota_audit.action = McpAuditAction::McpQuotaReserved.as_str().to_owned();
    request_guard_repo::audit_event_insert_in_txn(
        &mut txn,
        AuditTenant::Authenticated(&auth),
        &quota_audit,
    )
    .await?;

    // ADR-0067 D-J: the token is spent under the head lock, after the receipt check (a committed retry never gets here).
    if let Some(claim) = replace.as_ref().and_then(|replace| replace.claim.as_ref()) {
        confirm_token_repo::consume_in_txn(&mut txn, &auth, claim).await?;
    }
    let token_expires_at = request.command.consistency_token_expires_at;
    let secret_material =
        note.is_some() && request.command.data_class == DataClass::SecretMaterial.as_str();
    let lineage = replace
        .as_ref()
        .map_or(NoteLineage::Create, |replace| NoteLineage::Replace {
            note_id: replace.note_id,
            supersedes: replace.supersedes,
        });
    let pending = remember::remember_in_txn_with(
        &mut txn,
        request.command,
        note.as_ref().map(|note| (note, lineage)),
    )
    .await
    .map_err(remember_error)?;
    // ADR-0057 D-B: the superseded version's point is retired by a MEMORY_LIFECYCLE ticket on its home stream, as
    // `memory.correct` retires M1's.
    if let Some(replace) = &replace {
        memory_governance_repo::issue_lifecycle_ticket(
            &mut txn,
            &auth,
            pending.stream_key(),
            MemoryId(replace.supersedes),
        )
        .await?;
    }
    if quota_repo::finish_reservation_in_txn(&mut txn, &auth, &reservation, true).await?
        != ReservationStatus::Consumed
    {
        return Err(ErrorCode::Conflict); // Drops the transaction, including Evidence/outbox.
    }
    quota_audit.event_id = AuditEventId::new();
    quota_audit.action = McpAuditAction::McpQuotaConsumed.as_str().to_owned();
    request_guard_repo::audit_event_insert_in_txn(
        &mut txn,
        AuditTenant::Authenticated(&auth),
        &quota_audit,
    )
    .await?;
    let audit_id = request_guard_repo::audit_event_insert_in_txn(
        &mut txn,
        AuditTenant::Authenticated(&auth),
        &request.finished_audit,
    )
    .await?;
    let replay_expires_at = db_now(&mut txn)
        .await?
        .checked_add(replay_duration)
        .ok_or(ErrorCode::InvalidInput)?;
    let stream = pending.stream_key();
    sqlx::query(
        "INSERT INTO control.operation_receipts \
         (tenant_id,principal_id,operation,idempotency_key,request_fingerprint,user_id,workspace_id, \
          request_id,reservation_id,evidence_id,scope_kind,scope_id,domain,projection_kind, \
          projection_version,stream_seq,commit_seq,audit_event_id,replay_expires_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)",
    )
    .bind(auth.tenant_id().0).bind(auth.principal().0).bind(operation)
    .bind(&request.idempotency_key).bind(&request.request_fingerprint)
    .bind(auth.user_id().map(|id| id.0)).bind(request.workspace_id.map(|id| id.0))
    .bind(request.request_id).bind(reservation.id()).bind(pending.accepted().evidence_id)
    .bind(&stream.scope_kind).bind(stream.scope_id).bind(&stream.domain)
    .bind(&stream.projection_kind).bind(&stream.projection_version)
    .bind(pending.stream_seq()).bind(pending.commit_seq()).bind(audit_id.0).bind(replay_expires_at)
    .execute(&mut *txn).await.map_err(db_error)?;
    let finalized_at = db_now(&mut txn).await?;
    if finalized_at >= reservation.expires_at() || finalized_at >= token_expires_at {
        return Err(ErrorCode::Conflict);
    }
    // A COMMIT error cannot establish rollback. Only a subsequent receipt lookup
    // resolves durability; callers must not publish a terminal failure or refund.
    txn.commit()
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    let memory_id = pending.memory_id();
    Ok(NoteReplaceOutcome::Stored(AtomicRememberResult {
        accepted: pending.into_accepted(),
        replayed: false,
        memory_id,
        secret_material,
    }))
}

/// The transaction's `clock_timestamp()` — every §34.0.1 deadline is judged on the database
/// clock after the blocking writes, never on the gateway's.
async fn db_now(txn: &mut Txn<'_>) -> Result<OffsetDateTime, ErrorCode> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **txn)
        .await
        .map_err(db_error)
}

/// The §6.3 lifecycle triple the contribution path already requires (`contribution_entry_repo`):
/// an ACTIVE membership of an ACTIVE user in an ACTIVE tenant, holding one of
/// [`TENANT_SHARED_WRITER_ROLES`]. Fails closed on every other state.
async fn tenant_shared_write_allowed(
    txn: &mut Txn<'_>,
    auth: &AuthorizationScope,
) -> Result<bool, ErrorCode> {
    let Some(user) = auth.user_id() else {
        return Ok(false);
    };
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM control.memberships m \
         JOIN control.users u USING(user_id) JOIN control.tenants t USING(tenant_id) \
         WHERE m.tenant_id=$1 AND m.user_id=$2 AND m.state='ACTIVE' AND u.state='ACTIVE' \
           AND t.state='ACTIVE' AND m.role = ANY($3))",
    )
    .bind(auth.tenant_id().0)
    .bind(user.0)
    .bind(&TENANT_SHARED_WRITER_ROLES[..])
    .fetch_one(&mut **txn)
    .await
    .map_err(db_error)
}

/// §34.0.1 / ADR-0032 D-C: the receipt key is `(tenant, principal, scope_kind, scope_id,
/// operation, idempotency_key)` — the stream scope the write was issued against is part of
/// the key (migration 0158), `projection_version` never is. The advisory lock and the lookup
/// both carry the scope, so the same caller key under two streams is two operations, never a
/// `CONFLICT`, and two concurrent same-key writes on different streams never serialize on each
/// other. `scope_kind`/`scope_id` come from the validated command (they equal the routed
/// workspace by `validate`'s TenantBoundary check).
async fn lock_and_find_receipt(
    txn: &mut Txn<'_>,
    auth: &AuthorizationScope,
    request: &AtomicRememberRequest,
    operation: &str,
) -> Result<Option<PgRow>, ErrorCode> {
    sqlx::query(
        "SELECT set_config('humaux.tenant_id',$1,true), set_config('humaux.user_id',$2,true)",
    )
    .bind(auth.tenant_id().0.to_string())
    .bind(
        auth.user_id()
            .map(|id| id.0)
            .unwrap_or_else(Uuid::nil)
            .to_string(),
    )
    .execute(&mut **txn)
    .await
    .map_err(db_error)?;
    let locked: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!(
                "operation-receipt:{}:{}:{}:{}:{operation}:{}",
                auth.tenant_id().0,
                auth.principal().0,
                request.command.scope_kind,
                request.command.scope_id,
                request.idempotency_key
            ))
            .fetch_one(&mut **txn)
            .await
            .map_err(db_error)?;
    if !locked {
        return Err(ErrorCode::Conflict);
    }
    sqlx::query(
        "SELECT *, clock_timestamp() AS observed_at FROM control.operation_receipts \
         WHERE tenant_id=$1 AND principal_id=$2 AND scope_kind=$3 AND scope_id=$4 \
           AND operation=$5 AND idempotency_key=$6",
    )
    .bind(auth.tenant_id().0)
    .bind(auth.principal().0)
    .bind(&request.command.scope_kind)
    .bind(request.command.scope_id)
    .bind(operation)
    .bind(&request.idempotency_key)
    .fetch_optional(&mut **txn)
    .await
    .map_err(db_error)
}

async fn replay(
    txn: &mut Txn<'_>,
    auth: &AuthorizationScope,
    request: &AtomicRememberRequest,
    prior: &PgRow,
) -> Result<RememberAccepted, ErrorCode> {
    if field::<String>(prior, "request_fingerprint")? != request.request_fingerprint
        || field::<Option<Uuid>>(prior, "user_id")? != auth.user_id().map(|id| id.0)
        || field::<Option<Uuid>>(prior, "workspace_id")? != request.workspace_id.map(|id| id.0)
        || field::<String>(prior, "status")? != "COMMITTED"
        || field::<String>(prior, "scope_kind")? != request.command.scope_kind
        || field::<Uuid>(prior, "scope_id")? != request.command.scope_id
        || field::<String>(prior, "domain")? != request.command.domain
        || field::<String>(prior, "projection_kind")? != request.command.projection_kind
        || field::<OffsetDateTime>(prior, "replay_expires_at")?
            <= field::<OffsetDateTime>(prior, "observed_at")?
    {
        return Err(ErrorCode::Conflict);
    }
    let evidence_id = field::<Option<Uuid>>(prior, "evidence_id")?.ok_or(ErrorCode::NotFound)?;
    let evidence = sqlx::query(
        "SELECT e.tenant_id,e.visibility_class,e.visibility_user_id,e.visibility_workspace_id \
         FROM private.evidence_objects e \
         JOIN projection.stream_log s ON s.tenant_id=e.tenant_id \
         WHERE e.evidence_id=$1 AND e.tenant_id=$2 AND s.scope_kind=$3 AND s.scope_id=$4 \
           AND s.domain=$5 AND s.projection_kind=$6 AND s.projection_version=$7 \
           AND s.stream_seq=$8 AND s.commit_seq=$9 AND s.state<>'TOMBSTONED'",
    )
    .bind(evidence_id)
    .bind(auth.tenant_id().0)
    .bind(field::<String>(prior, "scope_kind")?)
    .bind(field::<Uuid>(prior, "scope_id")?)
    .bind(field::<String>(prior, "domain")?)
    .bind(field::<String>(prior, "projection_kind")?)
    .bind(field::<String>(prior, "projection_version")?)
    .bind(field::<i64>(prior, "stream_seq")?)
    .bind(field::<i64>(prior, "commit_seq")?)
    .fetch_optional(&mut **txn)
    .await
    .map_err(db_error)?
    .ok_or(ErrorCode::NotFound)?;
    let class = match field::<String>(&evidence, "visibility_class")?.as_str() {
        "USER_PRIVATE" => VisibilityClass::UserPrivate,
        "WORKSPACE_SHARED" => VisibilityClass::WorkspaceShared,
        "TENANT_SHARED" => VisibilityClass::TenantShared,
        _ => return Err(ErrorCode::Internal),
    };
    let visibility = VisibilityDescriptor {
        class,
        user_id: field::<Option<Uuid>>(&evidence, "visibility_user_id")?.map(UserId),
        workspace_id: field::<Option<Uuid>>(&evidence, "visibility_workspace_id")?.map(WorkspaceId),
    };
    if field::<Uuid>(&evidence, "tenant_id")? != auth.tenant_id().0 || !can_read(auth, &visibility)
    {
        return Err(ErrorCode::NotFound);
    }
    let issued_at = OffsetDateTime::now_utc();
    let expires_at = request
        .command
        .consistency_token_expires_at
        .min(field::<OffsetDateTime>(prior, "replay_expires_at")?);
    if expires_at <= issued_at {
        return Err(ErrorCode::Conflict);
    }
    let scope_kind: String = field(prior, "scope_kind")?;
    let scope_id: Uuid = field(prior, "scope_id")?;
    let consistency_token = issue_consistency_token(&TokenClaims {
        tenant_id: auth.tenant_id().0,
        workspace_id: if scope_kind == "workspace" {
            Some(scope_id)
        } else {
            None
        },
        scope_kind,
        scope_id,
        domain: field(prior, "domain")?,
        projection_kind: field(prior, "projection_kind")?,
        projection_version: field(prior, "projection_version")?,
        stream_seq: field(prior, "stream_seq")?,
        commit_seq: field(prior, "commit_seq")?,
        issued_at,
        expires_at,
    })
    // ADR-0059 D-G: an uninstalled key set is a missing dependency, never an unsigned token.
    .map_err(|_| ErrorCode::DependencyUnavailable)?;
    Ok(RememberAccepted {
        evidence_id,
        processing_handle: evidence_id.to_string(),
        consistency_token,
        ticket_ordinal: None,
        batch_remaining: None,
        status: "accepted",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idempotency_keys_are_bounded_opaque_identifiers() {
        assert!(valid_key("legacy:01234567-89ab-cdef-0123-456789abcdef"));
        for key in ["", "with space", "\n", "租户", "a/b", &"a".repeat(129)] {
            assert!(!valid_key(key));
        }
    }

    #[test]
    fn private_and_workspace_visibility_must_follow_the_authorized_route() {
        let actor = Uuid::new_v4();
        let another_user = Uuid::new_v4();
        let workspace = WorkspaceId(Uuid::new_v4());
        let another_workspace = Uuid::new_v4();

        assert!(visibility_is_bound_to_route(
            Some(actor),
            Some(workspace),
            "USER_PRIVATE",
            Some(actor),
            None,
        ));
        assert!(!visibility_is_bound_to_route(
            Some(actor),
            Some(workspace),
            "USER_PRIVATE",
            Some(another_user),
            None,
        ));
        assert!(visibility_is_bound_to_route(
            Some(actor),
            Some(workspace),
            "WORKSPACE_SHARED",
            None,
            Some(workspace.0),
        ));
        assert!(!visibility_is_bound_to_route(
            Some(actor),
            Some(workspace),
            "WORKSPACE_SHARED",
            None,
            Some(another_workspace),
        ));
    }
}
