//! `adapters::tests::support::quota_expiry` — PostgreSQL lease fault for receipt and governance writes (§34.0.1).
//! Depends-on: crates=[async-trait, humaux-adapters, humaux-domain, sqlx, time]; services=[]; env=[];
//!   modules=[adapters::postgres, adapters::quota_reservation_port, domain::error, domain::identity]
//! Called-by: [adapters::tests::governance_quota, adapters::tests::note_replace]
//! Invariants: [settles through the real commercial adapter and lets the original DB deadline elapse before commit]
//! Spec: Baseline §34.0.1; §36

use std::time::Duration;

use humaux_adapters::{
    postgres::commercial_write_quota,
    quota_reservation_port::{QuotaReservationPort, QuotaTransaction, ReservedQuota},
};
use humaux_domain::{error::ErrorCode, identity::AuthorizationScope};
use sqlx::types::Uuid;

// The real settlement succeeds before the database lease expires. Delay its return to
// exercise the final lease check after settlement and before the business commit.
pub struct ExpireSettledQuota;
struct ExpiringLease(Box<dyn ReservedQuota>);

#[async_trait::async_trait]
impl QuotaReservationPort for ExpireSettledQuota {
    async fn reserve(
        &self,
        txn: &mut QuotaTransaction<'_>,
        auth: &AuthorizationScope,
        request_id: Uuid,
        operation: &str,
        fingerprint: &str,
        ttl: Duration,
    ) -> Result<Option<Box<dyn ReservedQuota>>, ErrorCode> {
        let lease = commercial_write_quota()
            .reserve(txn, auth, request_id, operation, fingerprint, ttl)
            .await?;
        Ok(lease.map(|lease| Box::new(ExpiringLease(lease)) as Box<dyn ReservedQuota>))
    }
}

#[async_trait::async_trait]
impl ReservedQuota for ExpiringLease {
    fn id(&self) -> Uuid {
        self.0.id()
    }

    fn expires_at(&self) -> time::OffsetDateTime {
        self.0.expires_at()
    }

    async fn consume(
        &self,
        txn: &mut QuotaTransaction<'_>,
        auth: &AuthorizationScope,
    ) -> Result<bool, ErrorCode> {
        assert!(
            self.0.consume(txn, auth).await?,
            "native settlement before expiry"
        );
        sqlx::query(
            "SELECT pg_sleep(GREATEST(0, EXTRACT(EPOCH FROM $1::timestamptz - clock_timestamp())))",
        )
        .bind(self.expires_at())
        .execute(&mut **txn)
        .await
        .expect("wait for the actual database reservation deadline");
        Ok(true)
    }
}
