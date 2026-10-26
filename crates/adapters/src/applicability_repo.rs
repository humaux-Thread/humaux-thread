//! `adapters::applicability_repo` — applicability proposals and evidenced decisions through SQL doors.
//! Depends-on: crates=[humaux-domain, serde_json, sqlx, uuid]; services=[PostgreSQL(any) x=[private.propose_memory_applicability, private.decide_memory_applicability]]; env=[]; modules=[adapters::confirm_token_repo, adapters::postgres, domain::applicability, domain::error, domain::identity]
//! Called-by: [tests]
//! Invariants: [writes authenticate through 0188 inside the SQL door; proposals never approve; console is fail-closed]
//! Spec: Baseline §6.1.1; §78.2; ADR-0096 D-A/D-B.1

use humaux_domain::{
    applicability::{ApplicabilityScope, ApplicabilityStatus, AssignmentMethod},
    error::ErrorCode,
    identity::AuthorizationScope,
};
use uuid::Uuid;

use crate::{confirm_token_repo, postgres::RuntimeDbPool};

/// §52: an existing terminal ErrorCode plus a stable SQL sub-reason, never another error enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicabilityFailure {
    /// Existing terminal vocabulary (§52).
    pub code: ErrorCode,
    /// Stable refusal detail; no SQL text or credential material.
    pub reason: &'static str,
}

/// ADR-0096 D-A: proposal payload; the SQL CHECK owns closed qualifier validation.
pub struct Proposal {
    /// Memory version whose applicability is proposed.
    pub memory_id: Uuid,
    /// Closed applicability scope (§78.2).
    pub scope: ApplicabilityScope,
    /// Required only for PRODUCT_SPECIFIC.
    pub product_subject_id: Option<Uuid>,
    /// Required only for CHANNEL_GENERIC.
    pub channel_key: Option<String>,
    /// Closed v1 language qualifiers; empty means language independent.
    pub implementation_languages: Vec<String>,
    /// Closed v1 exclusions.
    pub exclusions: Vec<String>,
}

/// ADR-0096 D-B.1: a requested decision; the SQL door proves its provenance.
pub struct Decision {
    /// Existing applicability proposal.
    pub memory_id: Uuid,
    /// Missing Evidence must be refused by the same SQL door.
    pub decision_evidence_id: Option<Uuid>,
    /// Provenance method, never caller-supplied credential kind.
    pub assignment_method: AssignmentMethod,
    /// Only APPROVED or REJECTED is accepted by the decision door.
    pub status: ApplicabilityStatus,
}

fn failure(code: ErrorCode, reason: &'static str) -> ApplicabilityFailure {
    ApplicabilityFailure { code, reason }
}

fn db_error(error: sqlx::Error) -> ApplicabilityFailure {
    let sqlx::Error::Database(db) = error else {
        return failure(ErrorCode::DependencyUnavailable, "applicability_dependency");
    };
    let code = match db.code().as_deref() {
        Some("42501") => ErrorCode::Forbidden,
        Some("28000") => ErrorCode::Unauthorized,
        Some("22023" | "22P02" | "23514" | "23502") => ErrorCode::InvalidInput,
        Some("23503") => ErrorCode::TenantBoundary,
        Some("40001" | "40P01") => ErrorCode::Conflict,
        _ => ErrorCode::Internal,
    };
    let reason = match db.message() {
        "applicability_console_unavailable" => "applicability_console_unavailable",
        "applicability_owner_required" => "applicability_owner_required",
        "applicability_evidence_required" => "applicability_evidence_required",
        "applicability_proposal_required" => "applicability_proposal_required",
        "applicability_console_precedence" => "applicability_console_precedence",
        "applicability_memory_unavailable" => "applicability_memory_unavailable",
        "applicability_decision_invalid" => "applicability_decision_invalid",
        "applicability_product_invalid" => "applicability_product_invalid",
        _ => "applicability_refused",
    };
    failure(code, reason)
}

/// ADR-0096 D-B: every authorised writer can propose; SQL always stores PROPOSED.
pub async fn propose(
    pool: &RuntimeDbPool,
    auth: &AuthorizationScope,
    proposal: &Proposal,
) -> Result<ApplicabilityStatus, ApplicabilityFailure> {
    let workspace = confirm_token_repo::sole_workspace(auth)
        .map_err(|code| failure(code, "applicability_workspace_required"))?;
    // dep: PostgreSQL(any) — one proposal transaction; SQL reuses control.assert_write_scope
    let mut txn = pool.pool().begin().await.map_err(db_error)?;
    confirm_token_repo::set_authorization_local(&mut txn, auth)
        .await
        .map_err(|code| failure(code, "applicability_authorization"))?;
    let qualifiers = serde_json::json!({
        "implementation_languages": proposal.implementation_languages,
        "exclusions": proposal.exclusions,
    });
    let status: String =
        sqlx::query_scalar("SELECT private.propose_memory_applicability($1,$2,$3,$4,$5,$6,$7)")
            .bind(auth.principal().0)
            .bind(workspace.0)
            .bind(proposal.memory_id)
            .bind(proposal.scope.wire())
            .bind(proposal.product_subject_id)
            .bind(&proposal.channel_key)
            .bind(qualifiers)
            .fetch_one(&mut *txn)
            .await
            .map_err(db_error)?;
    let status = ApplicabilityStatus::parse_wire(&status)
        .ok_or_else(|| failure(ErrorCode::Internal, "applicability_status_invalid"))?;
    txn.commit().await.map_err(db_error)?;
    Ok(status)
}

/// ADR-0096 D-B.1: approve or reject only through the evidenced OWNER agent door.
pub async fn decide(
    pool: &RuntimeDbPool,
    auth: &AuthorizationScope,
    decision: &Decision,
) -> Result<ApplicabilityStatus, ApplicabilityFailure> {
    let workspace = confirm_token_repo::sole_workspace(auth)
        .map_err(|code| failure(code, "applicability_workspace_required"))?;
    // dep: PostgreSQL(any) — one decision transaction; refusal leaves the row unchanged
    let mut txn = pool.pool().begin().await.map_err(db_error)?;
    confirm_token_repo::set_authorization_local(&mut txn, auth)
        .await
        .map_err(|code| failure(code, "applicability_authorization"))?;
    let status: String =
        sqlx::query_scalar("SELECT private.decide_memory_applicability($1,$2,$3,$4,$5,$6)")
            .bind(auth.principal().0)
            .bind(workspace.0)
            .bind(decision.memory_id)
            .bind(decision.decision_evidence_id)
            .bind(decision.assignment_method.wire())
            .bind(decision.status.wire())
            .fetch_one(&mut *txn)
            .await
            .map_err(db_error)?;
    let status = ApplicabilityStatus::parse_wire(&status)
        .ok_or_else(|| failure(ErrorCode::Internal, "applicability_status_invalid"))?;
    txn.commit().await.map_err(db_error)?;
    Ok(status)
}
