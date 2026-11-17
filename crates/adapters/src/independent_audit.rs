//! `adapters::independent_audit` — PostgreSQL implementation of the standalone operational audit port (Baseline §77).
//! Depends-on: crates=[async-trait, humaux-application, humaux-domain]; services=[]; env=[]; modules=[adapters::postgres, adapters::request_guard_repo, application::independent_audit, domain::audit, domain::error]
//! Called-by: [gateway::bootstrap, tests]
//! Invariants: [uses the same FORCE-RLS audit writer as the in-transaction door]
//! Spec: Baseline §77; ADR-0130 D2/D5

use humaux_application::independent_audit::{AuditIdentity, IndependentAuditStore};
use humaux_domain::{
    audit::{AuditEvent, AuditEventId},
    error::ErrorCode,
};

use crate::{postgres::RuntimeDbPool, request_guard_repo};

/// Binds the runtime PostgreSQL pool to the standalone audit use case.
pub struct PostgresIndependentAudit<'a> {
    pool: &'a RuntimeDbPool,
}

impl<'a> PostgresIndependentAudit<'a> {
    /// Reuse the gateway's existing runtime pool.
    pub fn new(pool: &'a RuntimeDbPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl IndependentAuditStore for PostgresIndependentAudit<'_> {
    async fn record(
        &self,
        identity: AuditIdentity,
        event: &AuditEvent,
    ) -> Result<AuditEventId, ErrorCode> {
        let authorized = match identity {
            AuditIdentity::Authorized { tenant_id, user_id } => Some((tenant_id, user_id)),
            AuditIdentity::System => None,
        };
        request_guard_repo::insert_bound_audit(self.pool, authorized, event).await
    }
}
