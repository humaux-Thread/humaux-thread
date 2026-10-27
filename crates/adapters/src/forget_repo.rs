//! `adapters::forget_repo` — T4.8 §37/§37.2 physical IO: the maintenance tombstone exit ([`tombstone`]) alongside
//!   the 0278 owner accept door (ADR-0092 D-C), the §37 `DeletionPlan` step-completion writer
//!   ([`record_step`]), §65's idempotent purge-replay loop ([`replay_pending_steps`]), the current-computed
//!   `tombstoned_unpurged_over_sla` gauge ([`tombstoned_unpurged_over_sla`]), and — §23.4 G23-2 — the two PG-side
//!   overlay reads a literal/EXACT-channel lane needs ([`count_excluding_tombstoned`], [`state_of`]), sharing this
//!   module's own `state <> 'TOMBSTONED'` knowledge instead of a caller re-deriving it.
//! Depends-on: crates=[humaux-application, humaux-domain, humaux-projection, sqlx]; services=[PostgreSQL(any) r=[control.deletion_requests, control.deletion_targets, ops.deletion_plan_steps, private.evidence_objects, private.evidence_subjects, private.memory_evidence, private.memory_records, private.memory_text_v, projection.stream_log] w=[projection.stream_log] x=[control.deletion_request_accept, control.deletion_request_freeze, ops.record_deletion_plan_step]]; env=[]; modules=[adapters::confirm_token_repo, adapters::context_repo, adapters::postgres, adapters::read_gate, application::forget, domain::confirm, domain::error, domain::identity, projection::stream]
//! Called-by: [tests]
//! Invariants: [maintenance calls open their own transaction and set humaux.tenant_id first; request calls use the caller-owned transaction and set its AuthorizationScope; maintenance tombstones and
//!   plan-step bookkeeping run on role_maintenance; accept re-judges the frozen roots (never the whole closure) under its own AuthorizationScope before the gateway-only owner door (#346); a PG error aborts the step so the plan stays resumable; a
//!   deletion request and its targets are written only through control.deletion_request_freeze (ADR-0092 D-A), which takes
//!   (scope, roots) and derives the targets, hash and requester itself, after every root passed the caller's own
//!   AuthorizationScope (visibility_readable / readable_memory_ids, never a membership of the user's elsewhere); the preview reads Memory visibility through
//!   read_gate::readable_memory_ids (secret-backed Memories dropped) and Evidence through read_gate::visibility_readable,
//!   and counts after both filters (G-M19-1)]
//! Spec: Baseline §3; §78.3; §37; ADR-0092 D-A, D-B
//!
//! `humaux_application::forget` decides *what* to delete and *in what order* (pure, no IO,
//! §3/§78.3); this module is the only place that decision turns into SQL — same split as
//! `stream_repo.rs`'s `advance_prefix`/`sweep_lost` wrapping `humaux_projection::stream`.
//!
//! Maintenance entry points require [`MaintenanceDbPool`] (`role_maintenance`): 0011 permits only that role to make
//! the maintenance `* -> TOMBSTONED` edge; ADR-0092 D-C also admits the 0278 accept door. 0054 grants only maintenance the bookkeeping doors. Their transactions install the tenant
//! before touching FORCE-RLS tables (§6.2). Freeze and preview instead require the caller-owned `role_gateway`
//! transaction with the caller's AuthorizationScope (ADR-0092 D-A); tenant RLS alone never proves root readability.

use sqlx::Row;
use sqlx::types::Uuid;

use std::collections::BTreeSet;

use humaux_application::forget::{
    DeletionScopeKind, DeletionStep, DeletionTarget, DeletionTargetKind, ImpactPreview,
    VisibleMemory, manifest_hash,
};
use humaux_domain::confirm::DestructiveOp;
use humaux_domain::error::ErrorCode;
use humaux_domain::identity::AuthorizationScope;
use humaux_projection::stream::StreamKey;

use crate::context_repo::{set_authorization_local, visibility_from_row};
use crate::postgres::MaintenanceDbPool;
use crate::read_gate::{readable_memory_ids, visibility_readable};

type Txn<'c> = sqlx::Transaction<'c, sqlx::Postgres>;

/// DB-layer failure. Not one of §52's two frozen domain error enums — same "adapter-local,
/// not domain" reasoning as `stream_repo::StreamRepoError`.
#[derive(Debug)]
pub enum ForgetRepoError {
    Db(sqlx::Error),
    /// The freeze door refused the request: an existing [`ErrorCode`] plus a machine-readable sub-reason.
    Refused {
        /// The terminal error the request surfaces as.
        code: ErrorCode,
        /// Sub-reason, stable text (`root_unreadable`, `bad_roots`, `no_session_identity`, ...).
        reason: &'static str,
    },
}

impl From<sqlx::Error> for ForgetRepoError {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

impl std::fmt::Display for ForgetRepoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Db(e) => write!(f, "forget_repo DB error: {e}"),
            Self::Refused { code, reason } => {
                write!(
                    f,
                    "forget_repo: freeze refused ({}): {reason}",
                    code.as_str()
                )
            }
        }
    }
}

impl std::error::Error for ForgetRepoError {}

async fn set_tenant_local(txn: &mut Txn<'_>, tenant_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(&format!("SET LOCAL humaux.tenant_id = '{tenant_id}'"))
        .execute(&mut **txn)
        .await?;
    Ok(())
}

/// §37.2 maintenance exit: one `projection.stream_log` row identified by the six-column key and `stream_seq`.
/// ADR-0092 D-C names the 0278 owner accept door as the one other exit, restricted to frozen EVIDENCE targets.
///
/// Idempotent: the `AND state <> 'TOMBSTONED'` guard makes a replayed call after a crash a
/// true no-op (`rows_affected() == 0`, `Ok(false)`), never a second UPDATE attempt against an
/// already-terminal row — the DB trigger's own `OLD.state = NEW.state` early-return would
/// have allowed a redundant same-state UPDATE too, but this guard avoids even issuing it.
///
/// Returns `Ok(true)` iff this call is the one that performed the transition (§37 step 1);
/// `Ok(false)` means the row was already `TOMBSTONED` (replay) or did not exist for this key.
pub async fn tombstone(
    pool: &MaintenanceDbPool,
    key: &StreamKey,
    seq: u64,
) -> Result<bool, ForgetRepoError> {
    // dep: PostgreSQL(any) — opens a PostgreSQL transaction
    let mut txn = pool.pool().begin().await?;
    set_tenant_local(&mut txn, key.tenant_id.0).await?;

    let result = sqlx::query(
        "UPDATE projection.stream_log \
            SET state = 'TOMBSTONED' \
          WHERE tenant_id = $1 AND scope_kind = $2 AND scope_id = $3 AND domain = $4 \
            AND projection_kind = $5 AND projection_version = $6 AND stream_seq = $7 \
            AND state <> 'TOMBSTONED'",
    )
    .bind(key.tenant_id.0)
    .bind(&key.scope_kind)
    .bind(key.scope_id)
    .bind(&key.domain)
    .bind(&key.projection_kind)
    .bind(&key.projection_version)
    .bind(seq as i64)
    .execute(&mut *txn)
    .await?;
    txn.commit().await?;

    Ok(result.rows_affected() > 0)
}

/// §22.1 PostgreSQL EXACT channel / §23.4 G23-2 literal lane: rows in `[seq_lo, seq_hi]` whose
/// `state` is not `TOMBSTONED` — the production predicate a PG-side lane applies to stay
/// overlay-consistent with [`tombstone`]'s own state transition, instead of a caller
/// re-deriving `state <> 'TOMBSTONED'` itself at each call site (§23.1②: the overlay predicate
/// belongs in one place). Shares [`tombstone`]'s key shape and `role_maintenance` scoping.
pub async fn count_excluding_tombstoned(
    pool: &MaintenanceDbPool,
    key: &StreamKey,
    seq_lo: u64,
    seq_hi: u64,
) -> Result<i64, ForgetRepoError> {
    // dep: PostgreSQL(any) — opens a PostgreSQL transaction
    let mut txn = pool.pool().begin().await?;
    set_tenant_local(&mut txn, key.tenant_id.0).await?;

    let row = sqlx::query(
        "SELECT count(*) AS n FROM projection.stream_log \
          WHERE tenant_id = $1 AND scope_kind = $2 AND scope_id = $3 AND domain = $4 \
            AND projection_kind = $5 AND projection_version = $6 \
            AND stream_seq BETWEEN $7 AND $8 AND state <> 'TOMBSTONED'",
    )
    .bind(key.tenant_id.0)
    .bind(&key.scope_kind)
    .bind(key.scope_id)
    .bind(&key.domain)
    .bind(&key.projection_kind)
    .bind(&key.projection_version)
    .bind(seq_lo as i64)
    .bind(seq_hi as i64)
    .fetch_one(&mut *txn)
    .await?;
    txn.commit().await?;

    Ok(row.try_get::<i64, _>("n")?)
}

/// §23.4 G23-2 literal lane's per-row read: the current `state` for one `stream_seq`, `None`
/// if the row does not exist for this key. Shares [`tombstone`]'s key shape and
/// `role_maintenance` scoping — the production entry point a literal-lookup lane calls instead
/// of hand-writing the same `SELECT state FROM projection.stream_log WHERE ...` per caller.
pub async fn state_of(
    pool: &MaintenanceDbPool,
    key: &StreamKey,
    seq: u64,
) -> Result<Option<String>, ForgetRepoError> {
    // dep: PostgreSQL(any) — opens a PostgreSQL transaction
    let mut txn = pool.pool().begin().await?;
    set_tenant_local(&mut txn, key.tenant_id.0).await?;

    let row = sqlx::query(
        "SELECT state FROM projection.stream_log \
          WHERE tenant_id = $1 AND scope_kind = $2 AND scope_id = $3 AND domain = $4 \
            AND projection_kind = $5 AND projection_version = $6 AND stream_seq = $7",
    )
    .bind(key.tenant_id.0)
    .bind(&key.scope_kind)
    .bind(key.scope_id)
    .bind(&key.domain)
    .bind(&key.projection_kind)
    .bind(&key.projection_version)
    .bind(seq as i64)
    .fetch_optional(&mut *txn)
    .await?;
    txn.commit().await?;

    Ok(row.map(|r| r.try_get::<String, _>("state")).transpose()?)
}

/// §37/§65 step-completion writer: calls `ops.record_deletion_plan_step` (0054, `SECURITY
/// DEFINER`) so `role_maintenance` never needs a direct table grant on
/// `ops.deletion_plan_steps` (see 0054's file header for why). Idempotent — a replay of an
/// already-recorded step returns `Ok(false)`, never a duplicate row or an error
/// (`ON CONFLICT DO NOTHING` inside the function).
pub async fn record_step(
    pool: &MaintenanceDbPool,
    tenant_id: Uuid,
    deletion_request_id: Uuid,
    step: DeletionStep,
    outcome: &str,
    detail: Option<&str>,
) -> Result<bool, ForgetRepoError> {
    // dep: PostgreSQL(any) — opens a PostgreSQL transaction
    let mut txn = pool.pool().begin().await?;
    set_tenant_local(&mut txn, tenant_id).await?;

    let row =
        sqlx::query("SELECT ops.record_deletion_plan_step($1, $2, $3, $4, $5, $6) AS inserted")
            .bind(deletion_request_id)
            .bind(tenant_id)
            .bind(step.as_db_str())
            .bind(step.ordinal() as i16)
            .bind(outcome)
            .bind(detail)
            .fetch_one(&mut *txn)
            .await?;
    txn.commit().await?;

    Ok(row.try_get::<bool, _>("inserted")?)
}

/// Steps already recorded for one `deletion_request_id`, as the pure
/// [`DeletionStep`](humaux_application::forget::DeletionStep) set
/// [`humaux_application::forget::DeletionPlan::pending`] takes.
async fn completed_steps(
    txn: &mut Txn<'_>,
    tenant_id: Uuid,
    deletion_request_id: Uuid,
) -> Result<std::collections::BTreeSet<DeletionStep>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT step FROM ops.deletion_plan_steps \
          WHERE tenant_id = $1 AND deletion_request_id = $2",
    )
    .bind(tenant_id)
    .bind(deletion_request_id)
    .fetch_all(&mut **txn)
    .await?;
    Ok(rows
        .iter()
        .filter_map(|r| DeletionStep::from_db_str(r.get::<&str, _>("step")))
        .collect())
}

/// §65 purge-replay job: for every step in `plan` not yet recorded for
/// `deletion_request_id` (per [`humaux_application::forget::DeletionPlan::pending`]),
/// `execute` it and record completion. Idempotent under interruption — a crash between two
/// steps loses nothing: the next call recomputes `pending` from `ops.deletion_plan_steps` and
/// only (re)runs what is still missing, never repeats a recorded step (§65 "幂等：中断后重放
/// 不重复删").
///
/// `execute` performs the actual step-2..8 side effect (Authority rows / Relations /
/// Qdrant points / …); this function's own job is sequencing + idempotent bookkeeping, not
/// those subsystems themselves (Qdrant/object-store adapters are still §0.x placeholders
/// elsewhere in this crate — see `crates/adapters/src/qdrant.rs`'s own doc). `execute`
/// returning `Ok(outcome)` where `outcome != "DONE"` (e.g. `"EXTERNAL_PENDING"`) is still
/// recorded — a step that cannot fully complete yet is not an error, it is one of §37's
/// named non-`DONE` step outcomes.
///
/// Returns the steps this call actually executed (empty on a full replay of an
/// already-completed plan — the observable "already done, skipped" signal).
pub async fn replay_pending_steps<F>(
    pool: &MaintenanceDbPool,
    tenant_id: Uuid,
    deletion_request_id: Uuid,
    plan: &humaux_application::forget::DeletionPlan,
    mut execute: F,
) -> Result<Vec<DeletionStep>, ForgetRepoError>
where
    F: FnMut(DeletionStep) -> (&'static str, Option<String>),
{
    // dep: PostgreSQL(any) — opens a PostgreSQL transaction
    let mut txn = pool.pool().begin().await?;
    set_tenant_local(&mut txn, tenant_id).await?;
    let done = completed_steps(&mut txn, tenant_id, deletion_request_id).await?;
    txn.commit().await?;

    let mut executed = Vec::new();
    for step in plan.pending(&done) {
        let (outcome, detail) = execute(step);
        let newly_recorded = record_step(
            pool,
            tenant_id,
            deletion_request_id,
            step,
            outcome,
            detail.as_deref(),
        )
        .await?;
        if newly_recorded {
            executed.push(step);
        }
    }
    Ok(executed)
}

/// §41.2 / ADR-0092 D-C: exact frozen target count for accepted requests older than `sla` without a DONE
/// QDRANT_POINTS receipt. MEMORY targets count even though no Evidence stream seq was tombstoned (M19-3a).
pub async fn tombstoned_unpurged_over_sla(
    pool: &MaintenanceDbPool,
    tenant_id: Uuid,
    sla: std::time::Duration,
) -> Result<i64, ForgetRepoError> {
    // dep: PostgreSQL(any) — opens a PostgreSQL transaction
    let mut txn = pool.pool().begin().await?;
    set_tenant_local(&mut txn, tenant_id).await?;

    let row = sqlx::query(
        "SELECT count(*) AS n FROM control.deletion_targets t \
           JOIN control.deletion_requests d ON d.deletion_request_id = t.request_id AND d.tenant_id = t.tenant_id \
          WHERE t.tenant_id = $1 \
            AND d.logical_deleted_at < now() - (interval '1 second' * $2::bigint) \
            AND NOT EXISTS (SELECT 1 FROM ops.deletion_plan_steps p \
                 WHERE p.tenant_id = $1 AND p.deletion_request_id = d.deletion_request_id \
                   AND p.step = 'QDRANT_POINTS' AND p.outcome = 'DONE')",
    )
    .bind(tenant_id)
    .bind(sla.as_secs() as i64)
    .fetch_one(&mut *txn)
    .await?;
    txn.commit().await?;

    Ok(row.try_get::<i64, _>("n")?)
}

/// A request recorded by [`freeze_memory_in_txn`] / [`freeze_evidence_closure_in_txn`]: its id, the hash of the frozen
/// closure and the closure itself, all as the door stored them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenDeletion {
    /// `control.deletion_requests.deletion_request_id`.
    pub request_id: Uuid,
    /// SHA-256 over the canonical target list, computed by the door ([`manifest_hash`] is its reference encoding).
    pub manifest_hash: [u8; 32],
    /// The frozen closure, sorted.
    pub targets: Vec<DeletionTarget>,
}

/// Maps the door's SQLSTATE to an existing [`ErrorCode`] plus a sub-reason (0272): `P0002` an unreadable or foreign root,
/// `22023` a malformed argument, `42501` a session without tenant or user.
fn door_refusal(error: sqlx::Error) -> ForgetRepoError {
    let state = error
        .as_database_error()
        .and_then(|e| e.code().map(|c| c.into_owned()));
    match state.as_deref() {
        Some("P0002") => ForgetRepoError::Refused {
            code: ErrorCode::NotFound,
            reason: "root_unreadable",
        },
        Some("22023") => ForgetRepoError::Refused {
            code: ErrorCode::InvalidInput,
            reason: "bad_roots",
        },
        Some("42501") => ForgetRepoError::Refused {
            code: ErrorCode::Forbidden,
            reason: "no_session_identity",
        },
        _ => ForgetRepoError::Db(error),
    }
}

/// §6.1.1: every root is readable under `authorization` itself (M08's `visibility_readable` / `readable_memory_ids`), the
/// one readability truth; a missing root is unreadable. Runs before the door, which only checks tenant and existence.
async fn roots_readable(
    txn: &mut Txn<'_>,
    authorization: &AuthorizationScope,
    scope_kind: DeletionScopeKind,
    roots: &[Uuid],
) -> Result<bool, ErrorCode> {
    let wanted: BTreeSet<Uuid> = roots.iter().copied().collect();
    let candidates: Vec<Uuid> = wanted.iter().copied().collect();
    let readable: BTreeSet<Uuid> = match scope_kind {
        DeletionScopeKind::Memory => readable_memory_ids(txn, authorization, &candidates)
            .await?
            .into_iter()
            .collect(),
        _ => visible_evidence(txn, authorization, &candidates).await?.0,
    };
    Ok(readable == wanted)
}

/// Records one request through `control.deletion_request_freeze` (the only write path, 0272) and reads back what the door
/// stored. The door derives the targets, the hash and `requested_by`; nothing but `(scope, roots)` crosses the call.
async fn freeze_in_txn(
    txn: &mut Txn<'_>,
    authorization: &AuthorizationScope,
    scope_kind: DeletionScopeKind,
    roots: &[Uuid],
) -> Result<FrozenDeletion, ForgetRepoError> {
    let tenant_id = authorization.tenant_id().0;
    set_authorization_local(txn, authorization)
        .await
        .map_err(|code| ForgetRepoError::Refused {
            code,
            reason: "session_setup",
        })?;
    let readable = roots_readable(txn, authorization, scope_kind, roots)
        .await
        .map_err(|code| ForgetRepoError::Refused {
            code,
            reason: "root_check_failed",
        })?;
    if !readable {
        return Err(ForgetRepoError::Refused {
            code: ErrorCode::NotFound,
            reason: "root_unreadable",
        });
    }
    let request_id: Uuid =
        sqlx::query_scalar("SELECT control.deletion_request_freeze($1, $2, $3::uuid[])")
            .bind(tenant_id)
            .bind(scope_kind.as_db_str())
            .bind(roots)
            .fetch_one(&mut **txn)
            .await
            .map_err(door_refusal)?;
    let stored = load_request(txn, tenant_id, request_id)
        .await
        .map_err(|code| ForgetRepoError::Refused {
            code,
            reason: "frozen_request_unreadable",
        })?;
    let mut targets: Vec<DeletionTarget> = stored
        .memory_ids
        .iter()
        .map(|id| DeletionTarget {
            kind: DeletionTargetKind::Memory,
            id: *id,
        })
        .chain(stored.evidence_ids.iter().map(|id| DeletionTarget {
            kind: DeletionTargetKind::Evidence,
            id: *id,
        }))
        .collect();
    targets.sort();
    if manifest_hash(&targets) != stored.manifest_hash {
        return Err(ForgetRepoError::Refused {
            code: ErrorCode::Internal,
            reason: "manifest_hash_drift",
        });
    }
    Ok(FrozenDeletion {
        request_id,
        manifest_hash: stored.manifest_hash,
        targets,
    })
}

/// Freezes a `MEMORY`-scope request (ADR-0092 D-A): the Memory alone, its source Evidence retained. The Memory must be
/// readable by `authorization` before the door; the door checks tenant and existence (§6.1.1).
pub async fn freeze_memory_in_txn(
    txn: &mut Txn<'_>,
    authorization: &AuthorizationScope,
    memory_id: Uuid,
) -> Result<FrozenDeletion, ForgetRepoError> {
    freeze_in_txn(txn, authorization, DeletionScopeKind::Memory, &[memory_id]).await
}

/// Freezes an `EVIDENCE_CLOSURE`-scope request from explicit `roots` (ADR-0092 D-A, ADR-0079 D-J): the roots plus every
/// Memory with any input among them, whole. The door walks the tenant under a tenant-only predicate, so Memories the caller
/// cannot read are frozen too; the roots themselves must be readable by `authorization`. Run it as `role_gateway`.
pub async fn freeze_evidence_closure_in_txn(
    txn: &mut Txn<'_>,
    authorization: &AuthorizationScope,
    roots: &[Uuid],
) -> Result<FrozenDeletion, ForgetRepoError> {
    freeze_in_txn(
        txn,
        authorization,
        DeletionScopeKind::EvidenceClosure,
        roots,
    )
    .await
}

/// The frozen request row as the preview needs it.
struct StoredRequest {
    scope_kind: DeletionScopeKind,
    manifest_hash: [u8; 32],
    memory_ids: Vec<Uuid>,
    evidence_ids: Vec<Uuid>,
}

fn dependency(_: sqlx::Error) -> ErrorCode {
    ErrorCode::DependencyUnavailable
}

async fn load_request(
    txn: &mut Txn<'_>,
    tenant_id: Uuid,
    request_id: Uuid,
) -> Result<StoredRequest, ErrorCode> {
    let head = sqlx::query(
        "SELECT scope_kind, manifest_hash FROM control.deletion_requests \
          WHERE tenant_id = $1 AND deletion_request_id = $2",
    )
    .bind(tenant_id)
    .bind(request_id)
    .fetch_optional(&mut **txn)
    .await
    .map_err(dependency)?
    .ok_or(ErrorCode::NotFound)?;
    let scope_kind =
        DeletionScopeKind::from_db_str(head.try_get::<&str, _>("scope_kind").map_err(dependency)?)
            .ok_or(ErrorCode::Internal)?;
    let hash: Vec<u8> = head.try_get("manifest_hash").map_err(dependency)?;
    let manifest_hash: [u8; 32] = hash.try_into().map_err(|_| ErrorCode::Internal)?;
    let rows = sqlx::query(
        "SELECT kind, id FROM control.deletion_targets WHERE tenant_id = $1 AND request_id = $2",
    )
    .bind(tenant_id)
    .bind(request_id)
    .fetch_all(&mut **txn)
    .await
    .map_err(dependency)?;
    let mut stored = StoredRequest {
        scope_kind,
        manifest_hash,
        memory_ids: Vec::new(),
        evidence_ids: Vec::new(),
    };
    for row in rows {
        let kind =
            DeletionTargetKind::from_db_str(row.try_get::<&str, _>("kind").map_err(dependency)?)
                .ok_or(ErrorCode::Internal)?;
        let id: Uuid = row.try_get("id").map_err(dependency)?;
        match kind {
            DeletionTargetKind::Memory => stored.memory_ids.push(id),
            DeletionTargetKind::Evidence => stored.evidence_ids.push(id),
        }
    }
    Ok(stored)
}

async fn visible_titles(
    txn: &mut Txn<'_>,
    tenant_id: Uuid,
    readable: &[Uuid],
) -> Result<Vec<VisibleMemory>, ErrorCode> {
    let rows = sqlx::query(
        "SELECT m.memory_id, mt.title FROM private.memory_records m \
           LEFT JOIN private.memory_text_v mt ON mt.tenant_id = m.tenant_id AND mt.memory_id = m.memory_id \
          WHERE m.tenant_id = $1 AND m.memory_id = ANY($2) \
            AND NOT EXISTS ( \
                SELECT 1 FROM private.memory_evidence me \
                  JOIN private.evidence_objects eo ON eo.evidence_id = me.evidence_id AND eo.tenant_id = m.tenant_id \
                 WHERE me.memory_id = m.memory_id AND eo.data_class = 'SECRET_MATERIAL')",
    )
    .bind(tenant_id)
    .bind(readable)
    .fetch_all(&mut **txn)
    .await
    .map_err(dependency)?;
    rows.iter()
        .map(|row| -> Result<VisibleMemory, ErrorCode> {
            Ok(VisibleMemory {
                memory_id: row.try_get("memory_id").map_err(dependency)?,
                title: row.try_get("title").map_err(dependency)?,
            })
        })
        .collect()
}

/// Closure Evidence `authorization` may read (the §6.1.1 judgement per row, so another workspace's Evidence never counts),
/// and which of it links two or more subjects.
async fn visible_evidence(
    txn: &mut Txn<'_>,
    authorization: &AuthorizationScope,
    candidates: &[Uuid],
) -> Result<(BTreeSet<Uuid>, BTreeSet<Uuid>), ErrorCode> {
    let tenant_id = authorization.tenant_id().0;
    let rows = sqlx::query(
        "SELECT evidence_id, visibility_class, visibility_user_id, visibility_workspace_id \
           FROM private.evidence_objects WHERE tenant_id = $1 AND evidence_id = ANY($2)",
    )
    .bind(tenant_id)
    .bind(candidates)
    .fetch_all(&mut **txn)
    .await
    .map_err(dependency)?;
    let mut readable = BTreeSet::new();
    for row in &rows {
        if visibility_readable(authorization, &visibility_from_row(row)?) {
            readable.insert(row.try_get::<Uuid, _>("evidence_id").map_err(dependency)?);
        }
    }
    let ids: Vec<Uuid> = readable.iter().copied().collect();
    let multi = sqlx::query(
        "SELECT evidence_id FROM private.evidence_subjects WHERE tenant_id = $1 AND evidence_id = ANY($2) \
          GROUP BY evidence_id HAVING count(DISTINCT subject_id) >= 2",
    )
    .bind(tenant_id)
    .bind(&ids)
    .fetch_all(&mut **txn)
    .await
    .map_err(dependency)?;
    let multi: BTreeSet<Uuid> = multi
        .iter()
        .map(|r| r.try_get::<Uuid, _>("evidence_id").map_err(dependency))
        .collect::<Result<_, _>>()?;
    Ok((readable, multi))
}

/// D2 round-1 impact preview of a frozen request, for `authorization`. Memories are judged by
/// [`readable_memory_ids`] (the M08 gate) minus `SECRET_MATERIAL`-backed ones, Evidence by `visibility_readable` against the
/// caller's own scope; the counts, titles and multi-person list are built from those readable sets alone (G-M19-1), and
/// the stored `manifest_hash` is returned as frozen.
pub async fn preview_in_txn(
    txn: &mut Txn<'_>,
    authorization: &AuthorizationScope,
    request_id: Uuid,
) -> Result<ImpactPreview, ErrorCode> {
    let tenant_id = authorization.tenant_id().0;
    set_authorization_local(txn, authorization).await?;
    let stored = load_request(txn, tenant_id, request_id).await?;
    let readable: Vec<Uuid> = readable_memory_ids(txn, authorization, &stored.memory_ids)
        .await?
        .into_iter()
        .collect();
    let memories = visible_titles(txn, tenant_id, &readable).await?;
    let (evidence, multi_person) =
        visible_evidence(txn, authorization, &stored.evidence_ids).await?;
    Ok(ImpactPreview::from_visible(
        stored.scope_kind,
        &memories,
        &evidence,
        &multi_person,
        stored.manifest_hash,
    ))
}

/// ADR-0092 D-B/D-C: round 2 under the caller's transaction. The adapter first re-judges the frozen ROOTS under the
/// accept-time `authorization` (#346; an unreadable root is `NotFound`/`root_unreadable`, nothing written); then the 0278
/// door verifies and consumes the full token binding, rechecks the closure under root locks, and commits logical
/// deletion atomically (Baseline §37.2). A refusal aborts the transaction, so callers must roll it back, never commit it
/// as an accepted request.
pub async fn accept_in_txn(
    txn: &mut Txn<'_>,
    authorization: &AuthorizationScope,
    request_id: Uuid,
    claim: Option<&crate::confirm_token_repo::ConfirmationClaim>,
) -> Result<(), ForgetRepoError> {
    let refused = |code, reason| ForgetRepoError::Refused { code, reason };
    let claim = claim.ok_or_else(|| refused(ErrorCode::Conflict, "confirmation_required"))?;
    if claim.op != DestructiveOp::MemoryForget
        || claim.target_id != request_id
        || claim.successor_id.is_some()
    {
        return Err(refused(ErrorCode::Conflict, "confirmation_binding"));
    }
    crate::confirm_token_repo::set_authorization_local(txn, authorization)
        .await
        .map_err(|code| refused(code, "session_setup"))?;
    // #346 / §6.1.1: the door checks write scope and the token's workspace but never readability, so the roots are
    // re-judged here under the accept-time scope, exactly like freeze. Roots only: a legal closure may hold Memories
    // the caller cannot read (ADR-0092 D-A).
    let stored = load_request(txn, authorization.tenant_id().0, request_id)
        .await
        .map_err(|code| refused(code, "frozen_request_unreadable"))?;
    let roots = if matches!(stored.scope_kind, DeletionScopeKind::Memory) {
        &stored.memory_ids
    } else {
        &stored.evidence_ids
    };
    if !roots_readable(txn, authorization, stored.scope_kind, roots)
        .await
        .map_err(|code| refused(code, "root_check_failed"))?
    {
        return Err(refused(ErrorCode::NotFound, "root_unreadable"));
    }
    let workspace = crate::confirm_token_repo::sole_workspace(authorization)
        .map_err(|code| refused(code, "workspace_scope"))?;
    // dep: PostgreSQL(any) — the gateway-only owner door, with tenant/user taken from the transaction's session GUCs
    sqlx::query("SELECT control.deletion_request_accept($1, $2, $3, $4, $5, $6)")
        .bind(request_id)
        .bind(claim.nonce_sha256.as_slice())
        .bind(claim.op.operation_key())
        .bind(claim.request_sha256.as_ref().map(<[u8; 32]>::as_slice))
        .bind(workspace.0)
        .bind(authorization.principal().0)
        .execute(&mut **txn)
        .await
        .map_err(accept_refusal)?;
    Ok(())
}

fn accept_refusal(error: sqlx::Error) -> ForgetRepoError {
    let Some(db) = error.as_database_error() else {
        return ForgetRepoError::Db(error);
    };
    let reason = match db.message() {
        "deletion_request_accept: manifest_changed" => "manifest_changed",
        "deletion_request_accept: confirmation_binding" => "confirmation_binding",
        "deletion_request_accept: request_not_open" => "request_not_open",
        _ => "accept_refused",
    };
    match db.code().as_deref() {
        Some("40001") => ForgetRepoError::Refused {
            code: ErrorCode::Conflict,
            reason,
        },
        _ => door_refusal(error),
    }
}
