//! `application::coordination` — Task claim use case; the outbound port owns the complete lease transaction (§30.2; ADR-0130 D7a).
//! Depends-on: crates=[async-trait, humaux-domain, time]; services=[]; env=[]; modules=[domain::coordination, domain::error, domain::identity, domain::ids]
//! Called-by: [adapters::coord_repo, gateway::mcp_application]
//! Invariants: [one port call claims atomically using the database clock and fencing sequence]
//! Spec: §30.2; ADR-0130 D2/D7a

use humaux_domain::{
    coordination::{FencingToken, TaskRunId},
    error::ErrorCode,
    identity::AuthorizationScope,
    ids::TaskId,
};
use std::time::Duration;
use time::OffsetDateTime;

/// A lease opened by [`claim`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimedTaskRun {
    /// The new run.
    pub task_run_id: TaskRunId,
    /// §30.2 token for every later heartbeat, close or verification of this run.
    pub fencing_token: FencingToken,
    /// DB-clock expiry of the lease.
    pub lease_expires_at: OffsetDateTime,
}

/// Atomic lease acquisition; transaction handles never cross the application boundary.
#[async_trait::async_trait]
pub trait TaskClaimPort: Send + Sync {
    /// Claim one task with the authenticated principal and configured lease duration (§30.2).
    async fn claim_task(
        &self,
        scope: &AuthorizationScope,
        task_id: TaskId,
        lease_ttl: Duration,
    ) -> Result<ClaimedTaskRun, ErrorCode>;
}

/// Acquire a task lease through its transaction-owning adapter (§30.2).
pub async fn claim(
    port: &dyn TaskClaimPort,
    scope: &AuthorizationScope,
    task_id: TaskId,
    lease_ttl: Duration,
) -> Result<ClaimedTaskRun, ErrorCode> {
    port.claim_task(scope, task_id, lease_ttl).await
}
