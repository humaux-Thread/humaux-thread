//! `adapters::entitlement_repo` — the persisted entitlement projector: reads a tenant's grants through the owner door,
//!   runs `application::entitlement::project`, and stores the snapshot through the owner door. Also supplies
//!   the read-only commercial MCP entitlement decision for a batch of authorized tenant scopes.
//! Depends-on: crates=[humaux-application, humaux-domain, serde_json, sqlx, uuid];
//!   services=[PostgreSQL(role_maintenance) r=[control.entitlement_snapshots]
//!   x=[control.entitlement_grants_for_projection, control.write_entitlement_snapshot], PostgreSQL(role_gateway)]; env=[];
//!   modules=[adapters::postgres, adapters::request_guard_repo, application::entitlement, application::read_quota, domain::error, domain::identity, domain::ids, domain::plan]
//! Called-by: [adapters::billing_processor_repo, adapters::provisioning, tests]
//! Invariants: [the only writer of control.entitlement_snapshots besides control.renew_quota_period (§76): no table
//!   INSERT or UPDATE here, the write is the owner door; the raw grants are read only through
//!   control.entitlement_grants_for_projection, never from the table; a recompute takes the quota issuer's per-tenant
//!   advisory lock first, so it serializes with a renewal and never overwrites a period the renewal just advanced;
//!   recompute is deterministic from the grants and the stored period boundaries and idempotent: a second call with
//!   nothing changed writes nothing; a tenant with no grant row is left alone (NoGrants), never overwritten with an
//!   empty snapshot; batch admission reads every tenant under RLS at one observation time and snapshot]
//! Spec: Baseline §76; §72.2.1; §71.1; ADR-0137
//!
//! The clock is the database's (`clock_timestamp()`), the same one that stamps a grant's `valid_from`, so a grant written
//! a moment ago is never "not yet valid" because of clock skew between this process and PostgreSQL.

use std::{collections::HashMap, time::SystemTime};

use humaux_application::entitlement::{
    EntitlementGrant, GrantSource, carry_period_boundaries, project,
};
use humaux_application::read_quota::{
    BMO_ENTITLEMENT, McpEntitlement, QuotaPolicyFacts, quota_policy,
};
use humaux_domain::error::ErrorCode;
use humaux_domain::identity::{AuthorizationScope, BoundedSet};
use humaux_domain::ids::{TenantId, WorkspaceId};
use humaux_domain::plan::EntitlementKey;
use serde_json::Value;
use sqlx::Row;
use sqlx::types::time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    postgres::{MaintenanceDbPool, RuntimeDbPool},
    request_guard_repo::{self, read_scoped_entitlement, set_authorized_ids_local},
};

type Txn<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

/// Decide BMO admission once per tenant in a verified session's candidate batch.
/// Only the trusted candidate derivation may supply these scopes. An error aborts the entire read.
pub async fn mcp_entitlement_for_tenants(
    pool: &RuntimeDbPool,
    candidates: &[AuthorizationScope],
) -> Result<HashMap<TenantId, McpEntitlement>, ErrorCode> {
    let Some(first) = candidates.first() else {
        return Ok(HashMap::new());
    };
    if candidates.len() > BoundedSet::<WorkspaceId>::MAX_LEN {
        return Err(ErrorCode::InvalidInput);
    }
    let user = first.user_id().ok_or(ErrorCode::Forbidden)?;
    if candidates.iter().any(|scope| scope.user_id() != Some(user)) {
        return Err(ErrorCode::Forbidden);
    }

    // dep: PostgreSQL(role_gateway) — one MVCC snapshot, with the original RLS scope set for each read.
    let mut txn = pool
        .pool()
        .begin()
        .await
        .map_err(request_guard_repo::db_error)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *txn)
        .await
        .map_err(request_guard_repo::db_error)?;
    let observed_at = sqlx::query_scalar::<_, OffsetDateTime>("SELECT clock_timestamp()")
        .fetch_one(&mut *txn)
        .await
        .map_err(request_guard_repo::db_error)?;

    let mut decisions = HashMap::with_capacity(candidates.len());
    for scope in candidates {
        let tenant = scope.tenant_id();
        if decisions.contains_key(&tenant) {
            continue;
        }
        set_authorized_ids_local(&mut txn, tenant, Some(user)).await?;
        let result = read_scoped_entitlement(&mut txn, tenant, Some(observed_at))
            .await
            .and_then(|facts| {
                quota_policy(
                    &QuotaPolicyFacts {
                        effective: facts.effective,
                        computed_at: facts.computed_at,
                        observed_at: facts.observed_at,
                    },
                    BMO_ENTITLEMENT,
                )
            });
        let decision = match result {
            Ok(_) => McpEntitlement::Enabled,
            Err(ErrorCode::EntitlementRequired) => McpEntitlement::EntitlementRequired,
            Err(error) => return Err(error),
        };
        decisions.insert(tenant, decision);
    }
    txn.commit().await.map_err(request_guard_repo::db_error)?;
    Ok(decisions)
}

/// What one recompute did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecomputeOutcome {
    /// The snapshot was created or its `effective` changed.
    Written,
    /// The stored `effective` already equals the projection; nothing changed.
    Unchanged,
    /// The tenant has no grant row at all (a tenant onboarded before grants existed): the stored snapshot, if any, is
    /// untouched.
    NoGrants,
}

fn db_error(error: sqlx::Error) -> ErrorCode {
    match error {
        sqlx::Error::Database(ref db) => match db.code().as_deref() {
            Some("42501") => ErrorCode::Forbidden,
            Some("22023") => ErrorCode::InvalidInput,
            Some("23503") => ErrorCode::TenantBoundary,
            Some("23505" | "40001" | "40P01" | "55P03") => ErrorCode::Conflict,
            _ => ErrorCode::Internal,
        },
        sqlx::Error::RowNotFound => ErrorCode::NotFound,
        _ => ErrorCode::DependencyUnavailable,
    }
}

/// Recomputes `tenant`'s snapshot in its own transaction as role_maintenance (the door's only caller role).
pub async fn recompute(
    pool: &MaintenanceDbPool,
    tenant: TenantId,
) -> Result<RecomputeOutcome, ErrorCode> {
    if tenant.0.is_nil() {
        return Err(ErrorCode::InvalidInput);
    }
    // dep: PostgreSQL(role_maintenance) — one recompute, one transaction
    let mut txn = pool.pool().begin().await.map_err(db_error)?;
    sqlx::query("SELECT set_config('humaux.tenant_id', $1, true)")
        .bind(tenant.0.to_string())
        .execute(&mut *txn)
        .await
        .map_err(db_error)?;
    let outcome = recompute_in_txn(&mut txn, tenant).await?;
    txn.commit().await.map_err(db_error)?;
    Ok(outcome)
}

/// Recomputes `tenant`'s snapshot inside the caller's transaction (onboarding writes the PLAN grants and the snapshot
/// together). The transaction's `humaux.tenant_id` must already name `tenant`: both owner doors refuse otherwise.
pub async fn recompute_in_txn(
    txn: &mut Txn<'_>,
    tenant: TenantId,
) -> Result<RecomputeOutcome, ErrorCode> {
    // §72.2.1: the issuer's own lock key, so a renewal and this recompute for one tenant serialize.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!(
            "quota-window:{}:{}",
            tenant.0,
            EntitlementKey::PerPeriod.wire()
        ))
        .execute(&mut **txn)
        .await
        .map_err(db_error)?;
    let now: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **txn)
        .await
        .map_err(db_error)?;
    let rows = sqlx::query(
        "SELECT out_grant_id, out_source, out_feature, out_value, out_valid_from, out_valid_until, \
                out_priority, out_revoked_at \
           FROM control.entitlement_grants_for_projection($1)",
    )
    .bind(tenant.0)
    .fetch_all(&mut **txn)
    .await
    .map_err(db_error)?;
    if rows.is_empty() {
        return Ok(RecomputeOutcome::NoGrants);
    }
    let mut grants = Vec::with_capacity(rows.len());
    for row in &rows {
        let source: String = row.try_get("out_source").map_err(db_error)?;
        // An unknown source can only mean the CHECK and the enum drifted (§78.2): fail closed, write nothing.
        let source = GrantSource::from_db_str(&source).ok_or(ErrorCode::Internal)?;
        let grant_id: Uuid = row.try_get("out_grant_id").map_err(db_error)?;
        let valid_from: OffsetDateTime = row.try_get("out_valid_from").map_err(db_error)?;
        let valid_until: Option<OffsetDateTime> =
            row.try_get("out_valid_until").map_err(db_error)?;
        let revoked_at: Option<OffsetDateTime> = row.try_get("out_revoked_at").map_err(db_error)?;
        grants.push(EntitlementGrant {
            grant_id: grant_id.to_string(),
            tenant_id: tenant,
            source,
            feature: row.try_get("out_feature").map_err(db_error)?,
            value: row.try_get("out_value").map_err(db_error)?,
            valid_from: SystemTime::from(valid_from),
            valid_until: valid_until.map(SystemTime::from),
            priority: row.try_get("out_priority").map_err(db_error)?,
            revoked_at: revoked_at.map(SystemTime::from),
        });
    }
    let current: Option<Value> = sqlx::query_scalar(
        "SELECT effective FROM control.entitlement_snapshots WHERE tenant_id = $1",
    )
    .bind(tenant.0)
    .fetch_optional(&mut **txn)
    .await
    .map_err(db_error)?;
    let snapshot = carry_period_boundaries(
        project(tenant, &grants, SystemTime::from(now)),
        current.as_ref(),
    );
    let source_grant_ids = snapshot
        .source_grant_ids
        .iter()
        .map(|id| id.parse::<Uuid>().map_err(|_| ErrorCode::Internal))
        .collect::<Result<Vec<Uuid>, ErrorCode>>()?;
    let effective = serde_json::to_value(&snapshot.effective).map_err(|_| ErrorCode::Internal)?;
    let changed: bool =
        sqlx::query_scalar("SELECT control.write_entitlement_snapshot($1, $2, $3, $4)")
            .bind(tenant.0)
            .bind(effective)
            .bind(source_grant_ids)
            .bind(OffsetDateTime::from(snapshot.computed_at))
            .fetch_one(&mut **txn)
            .await
            .map_err(db_error)?;
    Ok(if changed {
        RecomputeOutcome::Written
    } else {
        RecomputeOutcome::Unchanged
    })
}
