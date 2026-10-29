//! `adapters::billing_processor_repo` — maintenance-only 0300 doors (§71.3).
//! Depends-on: crates=[humaux-application, humaux-domain, serde_json, sqlx, uuid]; services=[PostgreSQL(role_maintenance) r=[control.tenants] x=[control.billing_inbox_claim, control.billing_inbox_settle, control.billing_apply_subscription]]; env=[];
//!   modules=[adapters::postgres, application::billing, domain::billing, domain::error, domain::ids]
//! Called-by: [billing-worker::process, tests]
//! Invariants: [no gateway caller; unchanged 0300 doors; C2 alone writes snapshots]
//! Spec: Baseline §71.3; §76
use crate::postgres::MaintenanceDbPool;
use humaux_application::billing::{ProviderSubscription, VerifiedBillingEvent};
use humaux_domain::{
    billing::{BillingProviderId, InboxStatus, SubscriptionState},
    error::ErrorCode,
    ids::TenantId,
};
use serde_json::Value;
use sqlx::{Acquire, Row};
use uuid::Uuid;
/// §71.3: caller-owned processor transaction; database access remains in this adapter.
pub type Txn<'a> = sqlx::Transaction<'a, sqlx::Postgres>;
fn db_error(error: sqlx::Error) -> ErrorCode {
    match error {
        sqlx::Error::Database(ref db) => match db.code().as_deref() {
            Some("42501") => ErrorCode::Forbidden,
            Some("22023" | "22P02" | "23502" | "23514") => ErrorCode::InvalidInput,
            _ => ErrorCode::Internal,
        },
        _ => ErrorCode::DependencyUnavailable,
    }
}

/// Begins a processor transaction as role_maintenance; claim locks last until its commit/rollback (§71.3).
pub async fn begin_processor(pool: &MaintenanceDbPool) -> Result<Txn<'_>, ErrorCode> {
    // dep: PostgreSQL(role_maintenance) — caller owns claim/apply/recompute/settle atomicity
    pool.pool().begin().await.map_err(db_error)
}

/// §71.3: failed effects roll back to this savepoint while the outer inbox claim stays locked.
pub async fn savepoint<'a>(txn: &'a mut Txn<'_>) -> Result<Txn<'a>, ErrorCode> {
    // dep: PostgreSQL(role_maintenance) — savepoint preserves the outer durable claim.
    txn.begin().await.map_err(db_error)
}
/// §71.3: unknown tenants fail before any subscription or entitlement effect.
pub async fn scope_tenant(txn: &mut Txn<'_>, tenant: TenantId) -> Result<(), ErrorCode> {
    sqlx::query("SELECT set_config('humaux.tenant_id',$1,true)")
        .bind(tenant.0.to_string())
        .execute(&mut **txn)
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    // dep: PostgreSQL(role_maintenance) — scoped existence check before any effect (§71.3).
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM control.tenants WHERE tenant_id=$1)")
            .bind(tenant.0)
            .fetch_one(&mut **txn)
            .await
            .map_err(|_| ErrorCode::DependencyUnavailable)?;
    exists.then_some(()).ok_or(ErrorCode::NotFound)
}
/// Claims oldest RECEIVED rows without waiting for another processor's locks (0300, §71.3).
pub async fn inbox_claim(
    txn: &mut Txn<'_>,
    limit: i32,
) -> Result<Vec<(VerifiedBillingEvent, Value)>, ErrorCode> {
    // dep: PostgreSQL(role_maintenance) — owner claim door, no table SELECT privilege
    let rows = sqlx::query("SELECT provider, event_id, event_type, object_id, payload FROM control.billing_inbox_claim($1)")
        .bind(limit).fetch_all(&mut **txn).await.map_err(db_error)?;
    rows.iter()
        .map(|row| {
            let provider: String = row.try_get("provider").map_err(db_error)?;
            Ok((
                VerifiedBillingEvent {
                    provider: BillingProviderId::parse_wire(&provider)
                        .ok_or(ErrorCode::Internal)?,
                    event_id: row.try_get("event_id").map_err(db_error)?,
                    event_type: row.try_get("event_type").map_err(db_error)?,
                    object_id: row.try_get("object_id").map_err(db_error)?,
                },
                row.try_get("payload").map_err(db_error)?,
            ))
        })
        .collect()
}

/// Settles only RECEIVED → PROCESSED/FAILED; any other transition is refused (§71.3).
pub async fn inbox_settle(
    txn: &mut Txn<'_>,
    event: &VerifiedBillingEvent,
    status: InboxStatus,
    error: Option<ErrorCode>,
) -> Result<bool, ErrorCode> {
    // dep: PostgreSQL(role_maintenance) — owner settlement door
    sqlx::query_scalar("SELECT control.billing_inbox_settle($1,$2,$3,$4)")
        .bind(event.provider.wire())
        .bind(&event.event_id)
        .bind(status.wire())
        .bind(error.map(|e| e.as_str()))
        .fetch_one(&mut **txn)
        .await
        .map_err(db_error)
}

/// Applies one provider event once; `tenant` must match the transaction GUC. The caller next invokes
/// `entitlement_repo::recompute_in_txn` before commit (§76 / M04 D13(h)); plan IDs come from configuration (§78.1).
pub async fn apply_subscription_in_txn(
    txn: &mut Txn<'_>,
    tenant: TenantId,
    event: &VerifiedBillingEvent,
    subscription: &ProviderSubscription,
    plan_version: Uuid,
    free_plan_version: Uuid,
    state: SubscriptionState,
) -> Result<bool, ErrorCode> {
    // dep: PostgreSQL(role_maintenance) — owner application door; provider fetch already normalized (§71.3)
    sqlx::query_scalar(
        "SELECT control.billing_apply_subscription($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp())",
    )
    .bind(tenant.0)
    .bind(event.provider.wire())
    .bind(&event.event_id)
    .bind(&subscription.reference.0)
    .bind(plan_version)
    .bind(free_plan_version)
    .bind(state.wire())
    .bind(subscription.current_period_start)
    .bind(subscription.current_period_end)
    .fetch_one(&mut **txn)
    .await
    .map_err(db_error)
}
