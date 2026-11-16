//! `application::public_dispatch` — bounded public admission, revocation and projection dispatch (§13/§14).
//! Depends-on: crates=[async-trait, humaux-domain]; services=[]; env=[]; modules=[domain::error, domain::ids]
//! Called-by: [public-pool::public_projection, public-worker::main]
//! Invariants: [the cloud port owns projection and complete database transactions; private facts never cross this port]
//! Spec: §13; §14; ADR-0130 D2/D7a; ADR-0112

use humaux_domain::{error::ErrorCode, ids::TenantId};

/// Bounded dispatch operations; implementations retain lease and revocation fences (§13/§14).
#[async_trait::async_trait]
pub trait PublicDispatchPort: Send + Sync {
    /// Drain tenant outbox events through the existing atomic dispatch door.
    async fn drain_outbox(&self, tenant_id: TenantId, limit: i64) -> Result<u64, ErrorCode>;
    /// Process one bounded tenant dispatch batch with its configured projector.
    async fn run_once(
        &self,
        tenant_id: TenantId,
        lease_owner: &str,
        limit: i64,
    ) -> Result<u64, ErrorCode>;
    /// Process globally leased anonymous work without a tenant or private-data capability.
    async fn run_anonymous_once(&self, lease_owner: &str, limit: i64) -> Result<u64, ErrorCode>;
}

/// Drain public events without exposing a database capability to the inbound use case.
pub async fn drain_outbox(
    port: &dyn PublicDispatchPort,
    tenant_id: TenantId,
    limit: i64,
) -> Result<u64, ErrorCode> {
    port.drain_outbox(tenant_id, limit).await
}

/// Run tenant dispatch through its transaction-owning cloud implementation.
pub async fn run_once(
    port: &dyn PublicDispatchPort,
    tenant_id: TenantId,
    lease_owner: &str,
    limit: i64,
) -> Result<u64, ErrorCode> {
    port.run_once(tenant_id, lease_owner, limit).await
}

/// Run anonymous admission, revocation and projection through the authorized cloud seam.
pub async fn run_anonymous_once(
    port: &dyn PublicDispatchPort,
    lease_owner: &str,
    limit: i64,
) -> Result<u64, ErrorCode> {
    port.run_anonymous_once(lease_owner, limit).await
}
