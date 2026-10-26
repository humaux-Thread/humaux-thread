//! `adapters::candidate_repo` — sole writer of curation_candidates; no formal reader (G-N09-2).
//! Depends-on: crates=[humaux-domain, sqlx, uuid]; services=[PostgreSQL(any) r=[private.curation_candidate_targets, private.curation_candidates] x=[control.assert_write_scope, private.propose_curation_candidate, private.decide_curation_candidate]]; env=[]; modules=[adapters::confirm_token_repo, adapters::postgres, domain::authority, domain::error, domain::identity, domain::knowledge]
//! Called-by: [tests]
//! Invariants: [acceptance confirms a manifest only; STALE rolls back without writes; no M07 calls]
//! Spec: Baseline §6.1.4; §11.6; §52; ADR-0113

use humaux_domain::{
    authority::AuthorityStatus,
    error::ErrorCode,
    identity::AuthorizationScope,
    knowledge::{CandidateKind, CandidateState},
};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{confirm_token_repo, postgres::RuntimeDbPool};

/// §52: stable refusal detail paired with the existing terminal vocabulary.
#[derive(Debug, PartialEq, Eq)]
pub struct CandidateFailure {
    /// Existing terminal error code.
    pub code: ErrorCode,
    /// Public sub-reason; never raw SQL.
    pub reason: &'static str,
}

/// ADR-0113: a concrete proposal; target revisions are captured by the SQL door.
pub struct Proposal {
    /// Provenance only: rule:<id>@<version> or model:<id>@<version>.
    pub proposed_by: String,
    /// Closed proposal kind.
    pub kind: CandidateKind,
    /// Digest of the concrete manifest payload.
    pub payload_hash: [u8; 32],
    /// Proposal confidence, never authority.
    pub score: f64,
    /// Distinct target memory versions.
    pub targets: Vec<Uuid>,
}

/// ADR-0113: candidate read surface, isolated from formal memory readers.
#[derive(Debug, PartialEq)]
pub struct Candidate {
    /// Provenance only; never an authority basis (ADR-0113 D-A).
    pub proposed_by: String,
    /// Proposal score; never an authority basis (ADR-0113 D-A).
    pub score: f64,
    /// Captured target revisions forming the concrete manifest.
    pub targets: Vec<TargetRevision>,
    /// Candidate identity.
    pub candidate_id: Uuid,
    /// Closed proposal kind.
    pub kind: CandidateKind,
    /// Closed decision state.
    pub state: CandidateState,
    /// Exact manifest digest required for acceptance.
    pub payload_hash: Vec<u8>,
}

/// ADR-0113: a target's immutable identity and captured lifecycle revision.
#[derive(Debug, PartialEq, Eq)]
pub struct TargetRevision {
    /// Concrete Memory version identity.
    pub memory_id: Uuid,
    /// Authority state captured at proposal time.
    pub status: AuthorityStatus,
    /// NULL means no lifecycle event yet.
    pub lifecycle_head: Option<Uuid>,
}

async fn target_revisions(
    txn: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<Vec<TargetRevision>, CandidateFailure> {
    let rows = sqlx::query("SELECT memory_id,status_at_propose,lifecycle_head_at_propose FROM private.curation_candidate_targets WHERE candidate_id=$1 ORDER BY memory_id")
        .bind(id).fetch_all(&mut **txn).await.map_err(db_error)?;
    rows.into_iter()
        .map(|row| {
            let status = match row
                .try_get::<&str, _>("status_at_propose")
                .map_err(db_error)?
            {
                "active" => AuthorityStatus::Active,
                "superseded" => AuthorityStatus::Superseded,
                "revoked" => AuthorityStatus::Revoked,
                "expired" => AuthorityStatus::Expired,
                _ => return Err(failure(ErrorCode::Internal, "candidate_revision_invalid")),
            };
            Ok(TargetRevision {
                memory_id: row.try_get("memory_id").map_err(db_error)?,
                status,
                lifecycle_head: row.try_get("lifecycle_head_at_propose").map_err(db_error)?,
            })
        })
        .collect()
}

fn failure(code: ErrorCode, reason: &'static str) -> CandidateFailure {
    CandidateFailure { code, reason }
}

fn db_error(error: sqlx::Error) -> CandidateFailure {
    let sqlx::Error::Database(db) = error else {
        return failure(ErrorCode::DependencyUnavailable, "candidate_dependency");
    };
    let code = match db.code().as_deref() {
        Some("42501") => ErrorCode::Forbidden,
        Some("28000") => ErrorCode::Unauthorized,
        Some("40001" | "40P01") => ErrorCode::Conflict,
        Some("22023" | "22P02" | "23514" | "23502" | "23505") => ErrorCode::InvalidInput,
        _ => ErrorCode::Internal,
    };
    let reason = match db.message() {
        "candidate_stale_payload" => "candidate_stale_payload",
        "candidate_stale_target" => "candidate_stale_target",
        "candidate_transition_invalid" => "candidate_transition_invalid",
        "candidate_target_unavailable" => "candidate_target_unavailable",
        "candidate_unavailable" => "candidate_unavailable",
        "candidate_user_required" => "candidate_user_required",
        "candidate_targets_invalid" => "candidate_targets_invalid",
        _ => "candidate_refused",
    };
    failure(code, reason)
}

async fn authorize(
    txn: &mut Transaction<'_, Postgres>,
    auth: &AuthorizationScope,
) -> Result<Uuid, CandidateFailure> {
    let workspace = confirm_token_repo::sole_workspace(auth)
        .map_err(|code| failure(code, "candidate_workspace_required"))?
        .0;
    confirm_token_repo::set_authorization_local(txn, auth)
        .await
        .map_err(|code| failure(code, "candidate_authorization"))?;
    sqlx::query("SELECT control.assert_write_scope($1,$2), set_config('humaux.candidate_workspace_id',$3,true)")
        .bind(auth.principal().0)
        .bind(workspace)
        .bind(workspace.to_string())
        .execute(&mut **txn)
        .await
        .map_err(db_error)?;
    Ok(workspace)
}

/// §11.6: capture the target revision pairs in the caller's transaction; never apply a Memory verb.
pub async fn propose_in_txn(
    txn: &mut Transaction<'_, Postgres>,
    auth: &AuthorizationScope,
    proposal: &Proposal,
) -> Result<Uuid, CandidateFailure> {
    let workspace = authorize(txn, auth).await?;
    sqlx::query_scalar("SELECT private.propose_curation_candidate($1,$2,$3,$4,$5,$6,$7)")
        .bind(auth.principal().0)
        .bind(workspace)
        .bind(&proposal.proposed_by)
        .bind(proposal.kind.wire())
        .bind(proposal.payload_hash.as_slice())
        .bind(proposal.score)
        .bind(&proposal.targets)
        .fetch_one(&mut **txn)
        .await
        .map_err(db_error)
}

/// §11.6: own a transaction for a standalone producer; shares the exact in-transaction door.
pub async fn propose(
    pool: &RuntimeDbPool,
    auth: &AuthorizationScope,
    proposal: &Proposal,
) -> Result<Uuid, CandidateFailure> {
    // dep: PostgreSQL(any) — commits only candidate and captured target rows
    let mut txn = pool.pool().begin().await.map_err(db_error)?;
    let id = propose_in_txn(&mut txn, auth, proposal).await?;
    txn.commit().await.map_err(db_error)?;
    Ok(id)
}

/// G-N09-2: only this isolated API lists candidates in the authenticated workspace.
pub async fn list(
    pool: &RuntimeDbPool,
    auth: &AuthorizationScope,
) -> Result<Vec<Candidate>, CandidateFailure> {
    // dep: PostgreSQL(any) — candidate-only read transaction with authenticated workspace
    let mut txn = pool.pool().begin().await.map_err(db_error)?;
    authorize(&mut txn, auth).await?;
    let rows = sqlx::query("SELECT candidate_id,proposed_by,kind,state,payload_hash,score FROM private.curation_candidates ORDER BY candidate_id")
        .fetch_all(&mut *txn).await.map_err(db_error)?;
    let mut candidates = Vec::with_capacity(rows.len());
    for row in rows {
        let candidate_id = row.try_get("candidate_id").map_err(db_error)?;
        candidates.push(Candidate {
            proposed_by: row.try_get("proposed_by").map_err(db_error)?,
            score: row.try_get("score").map_err(db_error)?,
            targets: target_revisions(&mut txn, candidate_id).await?,
            candidate_id,
            kind: CandidateKind::parse_wire(row.try_get("kind").map_err(db_error)?)
                .ok_or_else(|| failure(ErrorCode::Internal, "candidate_kind_invalid"))?,
            state: CandidateState::parse_wire(row.try_get("state").map_err(db_error)?)
                .ok_or_else(|| failure(ErrorCode::Internal, "candidate_state_invalid"))?,
            payload_hash: row.try_get("payload_hash").map_err(db_error)?,
        });
    }
    txn.commit().await.map_err(db_error)?;
    Ok(candidates)
}

/// §11.6: CAS confirms only the unchanged manifest; any mismatch rolls back without writes.
pub async fn decide(
    pool: &RuntimeDbPool,
    auth: &AuthorizationScope,
    candidate_id: Uuid,
    expected_payload_hash: &[u8; 32],
    state: CandidateState,
) -> Result<CandidateState, CandidateFailure> {
    // dep: PostgreSQL(any) — SQL door owns locks, revision comparison and terminal-state refusal
    let mut txn = pool.pool().begin().await.map_err(db_error)?;
    let workspace = authorize(&mut txn, auth).await?;
    let state: String =
        sqlx::query_scalar("SELECT private.decide_curation_candidate($1,$2,$3,$4,$5)")
            .bind(auth.principal().0)
            .bind(workspace)
            .bind(candidate_id)
            .bind(expected_payload_hash.as_slice())
            .bind(state.wire())
            .fetch_one(&mut *txn)
            .await
            .map_err(db_error)?;
    let state = CandidateState::parse_wire(&state)
        .ok_or_else(|| failure(ErrorCode::Internal, "candidate_state_invalid"))?;
    txn.commit().await.map_err(db_error)?;
    Ok(state)
}
