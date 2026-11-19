//! PostgreSQL quota port for lifecycle and receipt writes (§34.0.1, §36).
//! Depends-on: crates=[async-trait, humaux-domain, sqlx, time, uuid]; services=[]; env=[]; modules=[domain::error, domain::identity]
//! Called-by: [adapters::memory_governance_repo, gateway::bootstrap, tests]
//! Invariants: [the business write owns the transaction; reserve and consume never commit it]
//! Spec: Baseline §34.0.1; §36; ADR-0130 D5

use std::time::Duration;

use humaux_domain::{error::ErrorCode, identity::AuthorizationScope};
use time::OffsetDateTime;
use uuid::Uuid;

/// The transaction held by the business write for reserve and consume.
pub type QuotaTransaction<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

/// Reserves a BMO in the business write's transaction.
#[async_trait::async_trait]
pub trait QuotaReservationPort: Send + Sync {
    /// Returns a lease only for a newly created reservation. An existing reservation
    /// returns `None` and grants no authority to execute the write again.
    async fn reserve(
        &self,
        txn: &mut QuotaTransaction<'_>,
        auth: &AuthorizationScope,
        request_id: Uuid,
        operation: &str,
        fingerprint: &str,
        ttl: Duration,
    ) -> Result<Option<Box<dyn ReservedQuota>>, ErrorCode>;
}

/// A new reservation's settlement capability. The implementation retains the commercial
/// handle so the caller cannot settle by supplying an ID or a deadline.
#[async_trait::async_trait]
pub trait ReservedQuota: Send + Sync {
    /// Reservation ID recorded by the receipt writer.
    fn id(&self) -> Uuid;

    /// Database deadline checked before the caller commits the write.
    fn expires_at(&self) -> OffsetDateTime;

    /// Settles this lease in the caller's transaction; returns whether it is consumed.
    async fn consume(
        &self,
        txn: &mut QuotaTransaction<'_>,
        auth: &AuthorizationScope,
    ) -> Result<bool, ErrorCode>;
}
