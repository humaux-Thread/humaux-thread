//! `adapters::request_guard_repo` — PostgreSQL effective-entitlement reads and
//!   FORCE-RLS operational-audit writes.
//! Depends-on: crates=[humaux-domain, serde_json, sqlx]; services=[PostgreSQL(role_gateway)
//!   r=[control.entitlement_snapshots] x=[control.audit_event_insert]]; env=[]; modules=[adapters::postgres, domain::audit, domain::audit::write_view, domain::error, domain::identity, domain::ids]
//! Called-by: [adapters::audited_read_quota, adapters::confirm_token_repo, adapters::context_repo, adapters::distill_repo, adapters::independent_audit, adapters::memory_governance_repo, adapters::operation_receipt, tests]
//! Invariants: [this reads the effective entitlement snapshot (its staged successor
//!   once that is in force, ADR-0072 D-A); a missing entitlement is EntitlementRequired]
//! Spec: Baseline §72.2.1; §77; ADR-0072
//!
//! Policy belongs to the commercial application. This adapter supplies the effective snapshot
//! and the §77 audit writer for the caller's PostgreSQL transaction.

use humaux_domain::{
    audit::{AuditEventId, SYSTEM_TENANT_ID, write_view::AuditWriteSource},
    error::ErrorCode,
    identity::AuthorizationScope,
    ids::{TenantId, UserId},
};
use serde_json::Value;
use sqlx::types::time::OffsetDateTime;
use sqlx::{Row, types::Uuid};

use crate::postgres::RuntimeDbPool;

type Txn<'c> = sqlx::Transaction<'c, sqlx::Postgres>;

/// Read-only database facts from the sole effective-entitlement projection (§76).
///
/// This is intentionally not `application::entitlement::EntitlementSnapshot`: `project` is
/// that type's sole constructor. Read admission only needs the already-projected facts.
#[derive(Clone, Debug, PartialEq)]
pub struct EffectiveEntitlementFacts {
    pub effective: Value,
    pub source_grant_ids: Vec<Uuid>,
    pub computed_at: OffsetDateTime,
    pub observed_at: OffsetDateTime,
}

/// Closed tenant source for an audit event. Callers cannot pass an unverified UUID.
#[derive(Clone, Copy, Debug)]
pub enum AuditTenant<'a> {
    Authenticated(&'a AuthorizationScope),
    System,
}

impl AuditTenant<'_> {
    fn authorized_ids(self) -> Option<(TenantId, Option<UserId>)> {
        match self {
            Self::Authenticated(auth) => Some((auth.tenant_id(), auth.user_id())),
            Self::System => None,
        }
    }
}

pub(crate) fn db_error(error: sqlx::Error) -> ErrorCode {
    match error {
        sqlx::Error::RowNotFound => ErrorCode::NotFound,
        sqlx::Error::Database(ref db) => match db.code().as_deref() {
            Some("23503") => ErrorCode::TenantBoundary,
            Some("42501") => ErrorCode::Forbidden,
            Some("23505") | Some("40001") | Some("40P01") => ErrorCode::Conflict,
            Some("22023") | Some("22P02") | Some("23514") => ErrorCode::InvalidInput,
            _ => ErrorCode::Internal,
        },
        _ => ErrorCode::DependencyUnavailable,
    }
}

async fn set_authorization_local(
    txn: &mut Txn<'_>,
    authorization: &AuthorizationScope,
) -> Result<(), ErrorCode> {
    set_authorized_ids_local(txn, authorization.tenant_id(), authorization.user_id()).await
}

async fn set_authorized_ids_local(
    txn: &mut Txn<'_>,
    tenant_id: TenantId,
    user_id: Option<UserId>,
) -> Result<(), ErrorCode> {
    sqlx::query("SELECT set_config('humaux.tenant_id', $1, true)")
        .bind(tenant_id.0.to_string())
        .execute(&mut **txn)
        .await
        .map_err(db_error)?;
    sqlx::query("SELECT set_config('humaux.user_id', $1, true)")
        .bind(
            user_id
                .map(|id| id.0.to_string())
                .unwrap_or_else(|| Uuid::nil().to_string()),
        )
        .execute(&mut **txn)
        .await
        .map_err(db_error)?;
    Ok(())
}

async fn set_system_tenant_local(txn: &mut Txn<'_>) -> Result<(), ErrorCode> {
    sqlx::query(
        "SELECT set_config('humaux.tenant_id', $1, true), set_config('humaux.user_id', $2, true)",
    )
    .bind(SYSTEM_TENANT_ID.0.to_string())
    .bind(Uuid::nil().to_string())
    .execute(&mut **txn)
    .await
    .map_err(db_error)?;
    Ok(())
}

/// Reads only the projected §76 entitlement facts in a fresh tenant-scoped transaction.
///
/// No row is a real absence of entitlement, never a default plan. A non-object `effective`
/// payload is corrupt control data and fails closed rather than being interpreted loosely.
pub async fn read_effective_entitlements(
    pool: &RuntimeDbPool,
    authorization: &AuthorizationScope,
) -> Result<EffectiveEntitlementFacts, ErrorCode> {
    // dep: PostgreSQL(role_gateway) — transaction entry for `read_effective_entitlements`
    let mut txn = pool.pool().begin().await.map_err(db_error)?;
    set_authorization_local(&mut txn, authorization).await?;
    // ADR-0072 D-A: a staged successor is the effective object from its own start, read with the one clock value
    // the guard then checks the period against.
    let row = sqlx::query(
        "SELECT CASE WHEN s.successor_from <= c.observed_at THEN s.successor ELSE s.effective END AS effective, \
                s.source_grant_ids, s.computed_at, c.observed_at \
         FROM control.entitlement_snapshots s CROSS JOIN (SELECT clock_timestamp() AS observed_at) c \
         WHERE s.tenant_id = $1",
    )
    .bind(authorization.tenant_id().0)
    .fetch_optional(&mut *txn)
    .await
    .map_err(db_error)?;
    txn.commit().await.map_err(db_error)?;

    let Some(row) = row else {
        return Err(ErrorCode::EntitlementRequired);
    };
    let effective: Value = row.try_get("effective").map_err(|_| ErrorCode::Internal)?;
    if !effective.is_object() {
        return Err(ErrorCode::Internal);
    }
    Ok(EffectiveEntitlementFacts {
        effective,
        source_grant_ids: row
            .try_get("source_grant_ids")
            .map_err(|_| ErrorCode::Internal)?,
        computed_at: row
            .try_get("computed_at")
            .map_err(|_| ErrorCode::Internal)?,
        observed_at: row
            .try_get("observed_at")
            .map_err(|_| ErrorCode::Internal)?,
    })
}

/// Calls §77's only audit writer inside a fresh FORCE-RLS-scoped transaction.
///
/// `AuditTenant` fixes the tenant to an authenticated scope or the reserved system tenant;
/// the event's tenant must agree before the audit writer is invoked.
pub async fn audit_event_insert(
    pool: &RuntimeDbPool,
    tenant: AuditTenant<'_>,
    event: &(impl AuditWriteSource + Sync),
) -> Result<AuditEventId, ErrorCode> {
    insert_bound_audit(pool, tenant.authorized_ids(), event).await
}

/// §77: bind trusted scope IDs or the fixed system tenant for a fresh audit transaction.
pub(crate) async fn insert_bound_audit(
    pool: &RuntimeDbPool,
    authorized: Option<(TenantId, Option<UserId>)>,
    event: &(impl AuditWriteSource + Sync),
) -> Result<AuditEventId, ErrorCode> {
    // dep: PostgreSQL(role_gateway) — transaction entry for `audit_event_insert`
    let mut txn = pool.pool().begin().await.map_err(db_error)?;
    let id = insert_bound_audit_in_txn(&mut txn, authorized, event).await?;
    txn.commit().await.map_err(db_error)?;
    Ok(id)
}

/// The sole audit writer in an existing local business transaction; never commits it.
pub async fn audit_event_insert_in_txn(
    txn: &mut Txn<'_>,
    tenant: AuditTenant<'_>,
    event: &(impl AuditWriteSource + Sync),
) -> Result<AuditEventId, ErrorCode> {
    insert_bound_audit_in_txn(txn, tenant.authorized_ids(), event).await
}

async fn insert_bound_audit_in_txn(
    txn: &mut Txn<'_>,
    authorized: Option<(TenantId, Option<UserId>)>,
    event: &(impl AuditWriteSource + Sync),
) -> Result<AuditEventId, ErrorCode> {
    let event = event.audit_write_event();
    let expected_tenant = authorized.map_or(SYSTEM_TENANT_ID, |(tenant_id, _)| tenant_id);
    if event.tenant_id != expected_tenant {
        return Err(ErrorCode::TenantBoundary);
    }
    let client_ip = event
        .client_ip
        .parse::<std::net::IpAddr>()
        .map_err(|_| ErrorCode::InvalidInput)?;
    let metadata = Value::Object(
        event
            .metadata
            .iter()
            .map(|(key, value)| (key.to_owned(), Value::String(value.to_owned())))
            .collect(),
    );

    match authorized {
        Some((tenant_id, user_id)) => set_authorized_ids_local(txn, tenant_id, user_id).await?,
        None => set_system_tenant_local(txn).await?,
    }
    let event_id: Uuid = sqlx::query_scalar(
        "SELECT control.audit_event_insert( \
           $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::inet, $13, $14, $15, $16, $17)",
    )
    .bind(event.event_id.0)
    .bind(OffsetDateTime::from(event.ts))
    .bind(event.tenant_id.0)
    .bind(&event.actor_type)
    .bind(&event.actor_id)
    .bind(&event.action)
    .bind(&event.resource_type)
    .bind(&event.resource_id)
    .bind(&event.result)
    .bind(&event.request_id)
    .bind(&event.trace_id)
    .bind(client_ip.to_string())
    .bind(&event.user_agent_hash)
    .bind(&event.risk_tags)
    .bind(&event.before_fingerprint)
    .bind(&event.after_fingerprint)
    .bind(metadata)
    .fetch_one(&mut **txn)
    .await
    .map_err(|error| match db_error(error) {
        // Typed audit fields have already been checked. Internal SQL/constraint failures
        // cannot turn an otherwise valid request into a client-input error.
        ErrorCode::InvalidInput => ErrorCode::Internal,
        code => code,
    })?;
    Ok(AuditEventId(event_id))
}
