//! `adapters::derived_job_lease` — Knowledge curation's PG-side settlement contract (ADR-0036/0058).
//! Depends-on: crates=[humaux-application, sqlx]; services=[]; env=[]; modules=[application::distill_execution]
//! Called-by: [adapters::consolidate_repo, adapters::distill_repo, adapters::jobs]
//! Invariants: [the caller owns COMMIT and rollback; settlement must use the caller's transaction]
//! Spec: ADR-0036; ADR-0058 D-E; ADR-0130 D7

use std::future::Future;

use humaux_application::distill_execution::{DistillLease, Finish};
use sqlx::{Postgres, Transaction, types::Uuid};

/// Exact consolidation claim fence used for heartbeat and same-transaction publication.
pub struct DerivedLease<'a> {
    /// Tenant of the claimed job.
    pub tenant_id: Uuid,
    /// Claimed job identity.
    pub job_id: Uuid,
    /// Owner returned by the claim.
    pub lease_owner: &'a str,
    /// Claim attempt. A stale token settles nothing.
    pub attempt: i32,
}

/// Generation-fenced Distill completion or release.
pub(crate) struct DistillLeaseSettlement<'a> {
    pub(crate) lease: &'a DistillLease<'a>,
    pub(crate) finish: Finish,
    pub(crate) error_class: Option<&'a str>,
    pub(crate) backoff_seconds: f64,
    pub(crate) park_seconds: f64,
}

/// Settle the exact claim inside a curation adapter's existing write transaction.
pub(crate) trait DerivedJobLeaseSettlementPort<Request>: Sync {
    /// `false` means the fence was lost and the caller must roll back.
    fn settle_in_txn(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        request: Request,
    ) -> impl Future<Output = Result<bool, sqlx::Error>> + Send;
}
