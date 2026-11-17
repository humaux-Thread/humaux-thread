//! `adapters::audited_read_quota` — PG binding for the commercial read port and its §77 audit envelope.
//! Depends-on: crates=[async-trait, humaux-application, humaux-domain]; services=[]; env=[]; modules=[adapters::postgres, adapters::quota_repo, adapters::request_guard_repo, application::read_quota, domain::audit, domain::error, domain::identity]
//! Called-by: [gateway::bootstrap]
//! Invariants: [delegates both transitions to the original single-commit transaction doors]
//! Spec: Baseline §72.2.1; §77; ADR-0130 D2/D5

use crate::{postgres::RuntimeDbPool, quota_repo::QuotaReservation, request_guard_repo};
use humaux_application::read_quota::{QuotaPolicyFacts, ReadQuotaStore, ReservationLease};
use humaux_domain::{audit::AuditEvent, error::ErrorCode, identity::AuthorizationScope};
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
        request_guard_repo::reserve_read_with_audit(
            self.0,
            auth,
            operation,
            fingerprint,
            ttl,
            audit,
        )
        .await
    }

    async fn settle(
        &self,
        auth: &AuthorizationScope,
        reservation: Option<&QuotaReservation>,
        consume: bool,
        audit: &AuditEvent,
    ) -> Result<bool, ErrorCode> {
        request_guard_repo::settle_read_with_audit(self.0, auth, reservation, consume, audit).await
    }
}
