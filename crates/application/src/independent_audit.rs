//! `application::independent_audit` — Standalone operational audit use case and its persistence port (Baseline §77).
//! Depends-on: crates=[async-trait, humaux-domain]; services=[]; env=[]; modules=[domain::audit, domain::error, domain::ids]
//! Called-by: [adapters::independent_audit, gateway::bootstrap, gateway::guard, tests]
//! Invariants: [business transactions use their existing in-transaction audit door]
//! Spec: Baseline §77; ADR-0130 D2/D5

use humaux_domain::{
    audit::{AuditEvent, AuditEventId},
    error::ErrorCode,
    ids::{TenantId, UserId},
};

/// The tenant and user supplied by the trusted request identity layer (§6.1.1, §77).
#[derive(Clone, Copy, Debug)]
pub enum AuditIdentity {
    /// A request whose authorization scope supplies both IDs.
    Authorized {
        /// Tenant from the authorization scope.
        tenant_id: TenantId,
        /// On-behalf-of user, if the principal has one.
        user_id: Option<UserId>,
    },
    /// An unauthenticated request attributed to the reserved system tenant.
    System,
}

/// Persist a §77 audit event in its own transaction.
#[async_trait::async_trait]
pub trait IndependentAuditStore: Send + Sync {
    /// Bind the trusted identity independently of the event and return its committed ID.
    async fn record(
        &self,
        identity: AuditIdentity,
        event: &AuditEvent,
    ) -> Result<AuditEventId, ErrorCode>;
}

/// Record an operational audit whose outcome has no enclosing business transaction.
pub async fn record_independent_audit(
    store: &dyn IndependentAuditStore,
    identity: AuditIdentity,
    event: &AuditEvent,
) -> Result<AuditEventId, ErrorCode> {
    store.record(identity, event).await
}
