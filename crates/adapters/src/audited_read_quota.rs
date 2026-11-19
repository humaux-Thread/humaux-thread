//! `adapters::audited_read_quota` — PG binding for the commercial read port and its §77 audit envelope.
//! Depends-on: crates=[async-trait, humaux-application, humaux-domain, sqlx]; services=[PostgreSQL(role_gateway)]; env=[]; modules=[adapters::postgres, adapters::quota_repo, adapters::request_guard_repo, application::read_quota, domain::audit, domain::error, domain::identity]
//! Called-by: [gateway::bootstrap]
//! Invariants: [commits each quota transition and its success audits in one transaction]
//! Spec: Baseline §72.2.1; §77; ADR-0130 D2/D5

use crate::{
    postgres::RuntimeDbPool,
    quota_repo::{self, QuotaReservation, ReservationStatus, ReserveResult},
    request_guard_repo::{self, AuditTenant, audit_event_insert_in_txn, db_error},
};
use humaux_application::read_quota::{QuotaPolicyFacts, ReadQuotaStore, ReservationLease};
use humaux_domain::{
    audit::{AuditEvent, AuditEventId, McpAuditAction},
    error::ErrorCode,
    identity::AuthorizationScope,
};
use sqlx::types::{Uuid, time::OffsetDateTime};
use std::time::Duration;

/// Request-scoped access to the existing runtime pool.
pub struct PostgresReadQuota<'a>(&'a RuntimeDbPool);

impl<'a> PostgresReadQuota<'a> {
    /// Wire the runtime pool at bootstrap.
    pub fn new(pool: &'a RuntimeDbPool) -> Self {
        Self(pool)
    }
}

impl ReservationLease for QuotaReservation {
    fn valid_for(&self) -> Duration {
        self.valid_for()
    }
}

#[async_trait::async_trait]
impl ReadQuotaStore for PostgresReadQuota<'_> {
    type Audit = AuditEvent;
    type Reservation = QuotaReservation;

    async fn policy_facts(&self, auth: &AuthorizationScope) -> Result<QuotaPolicyFacts, ErrorCode> {
        let facts = request_guard_repo::read_effective_entitlements(self.0, auth).await?;
        Ok(QuotaPolicyFacts {
            effective: facts.effective,
            computed_at: facts.computed_at,
            observed_at: facts.observed_at,
        })
    }

    async fn reserve(
        &self,
        auth: &AuthorizationScope,
        operation: &str,
        fingerprint: &str,
        ttl: Duration,
        audit: &AuditEvent,
    ) -> Result<QuotaReservation, ErrorCode> {
        reserve_read_with_audit(self.0, auth, operation, fingerprint, ttl, audit).await
    }

    async fn settle(
        &self,
        auth: &AuthorizationScope,
        reservation: Option<&QuotaReservation>,
        consume: bool,
        audit: &AuditEvent,
    ) -> Result<bool, ErrorCode> {
        settle_read_with_audit(self.0, auth, reservation, consume, audit).await
    }
}

fn validate_request_audit(
    auth: &AuthorizationScope,
    event: &AuditEvent,
    action: McpAuditAction,
) -> Result<Uuid, ErrorCode> {
    if event.tenant_id != auth.tenant_id() || event.actor_id != auth.principal().0.to_string() {
        return Err(ErrorCode::TenantBoundary);
    }
    let request_id = Uuid::parse_str(&event.request_id).map_err(|_| ErrorCode::InvalidInput)?;
    if request_id.is_nil()
        || event.action != action.as_str()
        || event.resource_type != "MCP_OPERATION"
    {
        return Err(ErrorCode::InvalidInput);
    }
    Ok(request_id)
}

/// Reserve one read BMO and its audit atomically; a failed audit leaves no reservation.
async fn reserve_read_with_audit(
    pool: &RuntimeDbPool,
    auth: &AuthorizationScope,
    operation: &str,
    request_fingerprint: &str,
    ttl: std::time::Duration,
    reserved_audit: &AuditEvent,
) -> Result<QuotaReservation, ErrorCode> {
    let request_id =
        validate_request_audit(auth, reserved_audit, McpAuditAction::McpQuotaReserved)?;
    if reserved_audit.resource_id != operation || reserved_audit.result != "OK" {
        return Err(ErrorCode::InvalidInput);
    }
    // dep: PostgreSQL(role_gateway) — transaction entry for `reserve_read_with_audit`
    let mut txn = pool.pool().begin().await.map_err(db_error)?;
    let reservation = match quota_repo::reserve_bmo_in_txn(
        &mut txn,
        auth,
        request_id,
        operation,
        request_fingerprint,
        ttl,
    )
    .await?
    {
        ReserveResult::Created(reservation) => reservation,
        ReserveResult::Existing(_) => return Err(ErrorCode::Conflict),
    };
    audit_event_insert_in_txn(&mut txn, AuditTenant::Authenticated(auth), reserved_audit).await?;
    txn.commit().await.map_err(db_error)?;
    Ok(reservation)
}

/// Settle a local read with both quota and finished audits in the same transaction.
/// False means the read did not consume a BMO; the caller must withhold a success when
/// consumption was requested but its lease expired. A failed audit rolls back settlement.
async fn settle_read_with_audit(
    pool: &RuntimeDbPool,
    auth: &AuthorizationScope,
    reservation: Option<&QuotaReservation>,
    consume: bool,
    finished_audit: &AuditEvent,
) -> Result<bool, ErrorCode> {
    let request_id =
        validate_request_audit(auth, finished_audit, McpAuditAction::McpRequestFinished)?;
    if reservation.is_some_and(|r| r.request_id() != request_id) {
        return Err(ErrorCode::Conflict);
    }
    // dep: PostgreSQL(role_gateway) — transaction entry for `settle_read_with_audit`
    let mut txn = pool.pool().begin().await.map_err(db_error)?;
    let mut consumed = false;
    if let Some(reservation) = reservation {
        let status =
            quota_repo::finish_reservation_in_txn(&mut txn, auth, reservation, consume).await?;
        consumed = status == ReservationStatus::Consumed;
        let mut quota_audit = finished_audit.clone();
        quota_audit.event_id = AuditEventId::new();
        quota_audit.action = if consumed {
            McpAuditAction::McpQuotaConsumed
        } else {
            McpAuditAction::McpQuotaReleased
        }
        .as_str()
        .to_owned();
        audit_event_insert_in_txn(&mut txn, AuditTenant::Authenticated(auth), &quota_audit).await?;
    }
    let mut finished = finished_audit.clone();
    if consume && reservation.is_some() && !consumed {
        finished.result = ErrorCode::Conflict.as_str().to_owned();
    }
    audit_event_insert_in_txn(&mut txn, AuditTenant::Authenticated(auth), &finished).await?;
    if let Some(reservation) = reservation.filter(|_| consumed) {
        let now: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *txn)
            .await
            .map_err(db_error)?;
        if now >= reservation.expires_at() {
            return Err(ErrorCode::Conflict);
        }
    }
    txn.commit().await.map_err(db_error)?;
    Ok(consumed || reservation.is_none())
}
