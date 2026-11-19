//! `adapters::public_outbox_port` — public contribution's transaction boundary for dispatch.
//! Depends-on: crates=[sqlx]; services=[]; env=[]; modules=[]
//! Called-by: [adapters::contribution_entry_repo, adapters::contribution_repo, adapters::postgres]
//! Invariants: [the producer's release and its outbox event commit together]
//! Spec: Baseline §12; §13

use sqlx::types::Uuid;

type Txn<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

/// M20's caller-transaction port for public outbox events.
pub(crate) trait PublicOutboxPort {
    /// Enqueues the event for the explicit release path.
    async fn enqueue_explicit_release(
        txn: &mut Txn<'_>,
        tenant: Uuid,
        seq: i64,
        release: Uuid,
    ) -> Result<(), sqlx::Error>;

    /// Enqueues the event for the confirmation path.
    async fn enqueue_confirmed_release(
        txn: &mut Txn<'_>,
        tenant: Uuid,
        seq: i64,
        release: Uuid,
        anonymous: Option<(Uuid, Vec<u8>)>,
    ) -> Result<(), sqlx::Error>;

    /// Enqueues the event for the revocation path.
    async fn enqueue_public_revoke(
        txn: &mut Txn<'_>,
        tenant: Uuid,
        seq: i64,
        release: Uuid,
        anonymous: Option<(Uuid, Vec<u8>)>,
    ) -> Result<(), sqlx::Error>;
}
