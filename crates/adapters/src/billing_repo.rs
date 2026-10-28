//! `adapters::billing_repo` — contract C4, the webhook inbox door of Baseline §71.3: `inbox_insert` stores one verified
//!   provider event once, keyed by (provider, event_id), as `role_gateway` with INSERT on the table and nothing else
//!   (module design M04 D7, G-M04-13).
//! Depends-on: crates=[humaux-application, humaux-domain, serde_json, sqlx, uuid]; services=[PostgreSQL(role_gateway) w=[control.billing_inbox], PostgreSQL(role_maintenance)
//!   x=[control.billing_inbox_claim, control.billing_inbox_settle, control.billing_apply_subscription]];
//!   env=[]; modules=[adapters::postgres, application::billing, domain::billing, domain::error, domain::ids]
//! Called-by: [gateway::billing_webhook, tests]
//! Invariants: [the insert is `ON CONFLICT DO NOTHING` with no conflict target and no RETURNING, so the primary key
//!   (provider, event_id) decides a duplicate and the gateway never needs SELECT on the inbox; a redelivery is the
//!   result `Duplicate`, never an error and never a second row; the first delivery's payload is kept; this module
//!   changes subscription facts only through 0300 owner doors; snapshots remain C2's (§76)]
//! Spec: Baseline §71.3; §6.2.2; §76
//!
//! A conflict target (`ON CONFLICT (provider, event_id)`) would make PostgreSQL ask for SELECT on those columns, and
//! `RETURNING` asks for SELECT on the returned ones; the rows-affected count says the same thing with INSERT alone
//! (G-M04-13: no runtime role reads raw billing tables, §76). Signature verification happens before this call, in the
//! webhook route (M04-10); this door stores whatever it is handed.

use humaux_application::billing::{ProviderSubscription, VerifiedBillingEvent};
use humaux_domain::billing::{BillingProviderId, InboxStatus, SubscriptionState};
use humaux_domain::error::ErrorCode;
use humaux_domain::ids::TenantId;
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;

use crate::postgres::{MaintenanceDbPool, RuntimeDbPool};

type Txn<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

/// What one [`inbox_insert`] did. A result, not an error: a redelivered event is the normal case (§71.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboxInsert {
    /// The event was new and is stored.
    Stored,
    /// The (provider, event_id) pair was already stored; nothing changed.
    Duplicate,
}

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

/// Stores one provider event in `control.billing_inbox` unless its (provider, event_id) is already there.
///
/// `payload` is the event body as received (JSON); `api_version` and `object_id` are the provider's own, when it sends
/// them. The row starts `RECEIVED`; the processor settles it later.
pub async fn inbox_insert(
    pool: &RuntimeDbPool,
    provider: BillingProviderId,
    event_id: &str,
    event_type: &str,
    api_version: Option<&str>,
    object_id: Option<&str>,
    payload: &Value,
) -> Result<InboxInsert, ErrorCode> {
    // dep: PostgreSQL(role_gateway) — the inbox INSERT, the only privilege the gateway holds on the table (G-M04-13)
    let stored = sqlx::query(
        "INSERT INTO control.billing_inbox (provider, event_id, event_type, api_version, object_id, payload) \
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
    )
    .bind(provider.wire())
    .bind(event_id)
    .bind(event_type)
    .bind(api_version)
    .bind(object_id)
    .bind(payload)
    .execute(pool.pool())
    .await
    .map_err(db_error)?;
    Ok(if stored.rows_affected() == 1 {
        InboxInsert::Stored
    } else {
        InboxInsert::Duplicate
    })
}

/// Begins a processor transaction as role_maintenance; claim locks last until its commit/rollback (§71.3).
pub async fn begin_processor(pool: &MaintenanceDbPool) -> Result<Txn<'_>, ErrorCode> {
    // dep: PostgreSQL(role_maintenance) — caller owns claim/apply/recompute/settle atomicity
    pool.pool().begin().await.map_err(db_error)
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
