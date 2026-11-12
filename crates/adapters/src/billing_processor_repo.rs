//! `adapters::billing_processor_repo` — maintenance-only 0300 doors (§71.3).
//! Depends-on: crates=[humaux-application, humaux-domain, serde_json, sqlx, time, uuid]; services=[PostgreSQL(role_maintenance) r=[control.tenants] x=[control.billing_inbox_claim, control.billing_inbox_settle, control.billing_apply_subscription, control.billing_append_payment, control.billing_slot_observe, control.billing_handover_subscription]]; env=[];
//!   modules=[adapters::postgres, application::billing, domain::billing, domain::error, domain::ids, domain::plan]
//! Called-by: [billing-worker::process, tests]
//! Invariants: [no gateway caller; 0300/0301/0305/0307 owner doors; C2 alone writes snapshots]
//! Spec: Baseline §71.3; §76
use crate::postgres::MaintenanceDbPool;
use humaux_application::billing::{
    ExternalSubscriptionRef, ProviderSubscription, VerifiedBillingEvent,
};
use humaux_domain::{
    billing::{BillingProviderId, InboxStatus, PaymentKind, SubscriptionState},
    error::ErrorCode,
    ids::TenantId,
    plan::Currency,
};
use serde_json::Value;
use sqlx::{Acquire, Row};
use time::OffsetDateTime;
use uuid::Uuid;
/// §71.3: caller-owned processor transaction; database access remains in this adapter.
pub type Txn<'a> = sqlx::Transaction<'a, sqlx::Postgres>;
fn db_error(error: sqlx::Error) -> ErrorCode {
    match error {
        sqlx::Error::Database(ref db) => match db.code().as_deref() {
            Some("55P03" | "57014" | "40P01") => ErrorCode::DependencyUnavailable,
            Some("42501") => ErrorCode::Forbidden,
            Some("23505") => ErrorCode::Conflict,
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

/// §71.3: serialize authoritative fetch through outer commit across events of one provider subscription.
pub async fn lock_subscription(
    txn: &mut Txn<'_>,
    provider: BillingProviderId,
    reference: &str,
) -> Result<(), ErrorCode> {
    // dep: PostgreSQL(role_maintenance) — transaction-scoped ordering; no table privileges (§71.3).
    sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))")
        .bind(format!(
            "billing-subscription:{}:{reference}",
            provider.wire()
        ))
        .execute(&mut **txn)
        .await
        .map_err(db_error)?;
    Ok(())
}
/// The currently occupied slot, read through the owner door.
pub struct SlotOccupant {
    pub id: Uuid,
    pub provider: BillingProviderId,
    pub reference: ExternalSubscriptionRef,
    pub state: SubscriptionState,
}

/// Replay and reversal facts must be checked before any external cancellation.
pub struct SlotObservation {
    pub replay: bool,
    pub old: Option<SlotOccupant>,
    pub reversed_b: bool,
}

/// Acquire the common event then quota locks before subscription locks or provider fetches.
pub async fn acquire_billing_scope_in_txn(
    txn: &mut Txn<'_>,
    tenant: TenantId,
    event: &VerifiedBillingEvent,
) -> Result<(), ErrorCode> {
    let scope: Option<String> =
        sqlx::query_scalar("SELECT NULLIF(current_setting('humaux.tenant_id', true), '')")
            .fetch_one(&mut **txn)
            .await
            .map_err(db_error)?;
    if tenant.0.is_nil() || scope.as_deref() != Some(tenant.0.to_string().as_str()) {
        return Err(ErrorCode::Forbidden);
    }
    for key in [
        format!("billing-event:{}:{}", event.provider.wire(), event.event_id),
        format!(
            "quota-window:{}:mcp.billable_operations.per_period",
            tenant.0
        ),
    ] {
        sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))")
            .bind(key)
            .execute(&mut **txn)
            .await
            .map_err(db_error)?;
    }
    Ok(())
}

/// Observe a slot after acquiring the scope locks and fetching the new subscription.
pub async fn prepare_slot_in_txn(
    txn: &mut Txn<'_>,
    tenant: TenantId,
    event: &VerifiedBillingEvent,
    new_ref: &ExternalSubscriptionRef,
    period: [OffsetDateTime; 2],
) -> Result<SlotObservation, ErrorCode> {
    let row = sqlx::query("SELECT * FROM control.billing_slot_observe($1,$2,$3,$4,$5,$6)")
        .bind(tenant.0)
        .bind(event.provider.wire())
        .bind(&event.event_id)
        .bind(&new_ref.0)
        .bind(period[0])
        .bind(period[1])
        .fetch_one(&mut **txn)
        .await
        .map_err(db_error)?;
    let id: Option<Uuid> = row.try_get("old_id").map_err(db_error)?;
    let old = match id {
        None => None,
        Some(id) => {
            let provider: String = row.try_get("old_provider").map_err(db_error)?;
            let state: String = row.try_get("old_state").map_err(db_error)?;
            Some(SlotOccupant {
                id,
                provider: BillingProviderId::parse_wire(&provider).ok_or(ErrorCode::Internal)?,
                reference: ExternalSubscriptionRef(row.try_get("old_ref").map_err(db_error)?),
                state: SubscriptionState::parse_wire(&state).ok_or(ErrorCode::Internal)?,
            })
        }
    };
    Ok(SlotObservation {
        replay: row.try_get("replay").map_err(db_error)?,
        old,
        reversed_b: row.try_get("reversed_b").map_err(db_error)?,
    })
}

/// End the eligible old slot and apply the new active subscription in one transaction.
#[allow(clippy::too_many_arguments)]
pub async fn handover_subscription_in_txn(
    txn: &mut Txn<'_>,
    tenant: TenantId,
    event: &VerifiedBillingEvent,
    old_id: Uuid,
    old_state: SubscriptionState,
    new: &ProviderSubscription,
    plan: Uuid,
    free: Uuid,
) -> Result<bool, ErrorCode> {
    sqlx::query_scalar("SELECT control.billing_handover_subscription($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,clock_timestamp())")
        .bind(tenant.0).bind(event.provider.wire()).bind(&event.event_id).bind(old_id)
        .bind(old_state.wire()).bind(&new.reference.0).bind(plan).bind(free)
        .bind(new.current_period_start).bind(new.current_period_end)
        .fetch_one(&mut **txn).await.map_err(db_error)
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

/// §71.3: caller must hold `lock_subscription` for this reference before the authoritative fetch.
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

/// §71.3: verified provider facts only; amounts are unsigned cents and refs identify each movement kind.
pub struct PaymentFacts<'a> {
    /// D13b: movement direction, independent of subscription state.
    pub kind: PaymentKind,
    /// §71.3: transaction, refund or dispute id (never the original charge id for reversals).
    pub reference: &'a str,
    /// D13a/b: charged, refunded or disputed cents respectively.
    pub amount: i64,
    /// §78.2: the closed USD-only currency set.
    pub currency: Currency,
    /// §71.3: provider period boundaries.
    pub period: [OffsetDateTime; 2],
    /// D13b: event creation time, not processing time.
    pub occurred_at: OffsetDateTime,
}
/// §71.3: caller must hold `lock_subscription` for this reference before the authoritative fetch.
/// §71.3 / §76: false means replay, without effects; caller scopes the tenant and recomputes before commit.
pub async fn append_payment_in_txn(
    txn: &mut Txn<'_>,
    tenant: TenantId,
    event: &VerifiedBillingEvent,
    subscription: &ProviderSubscription,
    plan_version: Uuid,
    free_plan: Uuid,
    payment: &PaymentFacts<'_>,
) -> Result<bool, ErrorCode> {
    // dep: PostgreSQL(role_maintenance) — 0301 owner payment door; no table privileges (§71.3).
    sqlx::query_scalar(
        "SELECT control.billing_append_payment($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
    )
    .bind(tenant.0)
    .bind(event.provider.wire())
    .bind(&event.event_id)
    .bind(&subscription.reference.0)
    .bind(plan_version)
    .bind(free_plan)
    .bind(payment.reference)
    .bind(payment.kind.wire())
    .bind(payment.amount)
    .bind(payment.currency.wire())
    .bind(payment.period[0])
    .bind(payment.period[1])
    .bind(subscription.current_period_start)
    .bind(subscription.current_period_end)
    .bind(payment.occurred_at)
    .fetch_one(&mut **txn)
    .await
    .map_err(db_error)
}

/// §71.3: lock, cancellation and deadlock SQLSTATEs remain retryable without a database.
#[cfg(test)]
#[test]
fn db_error_transient_sqlstates() {
    #[derive(Debug)]
    struct SqlState(&'static str);
    impl std::fmt::Display for SqlState {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }
    impl std::error::Error for SqlState {}
    impl sqlx::error::DatabaseError for SqlState {
        fn message(&self) -> &str {
            self.0
        }
        fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
            Some(self.0.into())
        }
        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }
    for code in ["55P03", "57014", "40P01"] {
        assert_eq!(
            db_error(sqlx::Error::Database(Box::new(SqlState(code)))),
            ErrorCode::DependencyUnavailable,
            "SQLSTATE {code}"
        );
    }
    for (code, expected) in [
        ("23505", ErrorCode::Conflict),
        ("23503", ErrorCode::Internal),
        ("XX000", ErrorCode::Internal),
        ("42501", ErrorCode::Forbidden),
        ("22023", ErrorCode::InvalidInput),
        ("22P02", ErrorCode::InvalidInput),
        ("23502", ErrorCode::InvalidInput),
        ("23514", ErrorCode::InvalidInput),
    ] {
        assert_eq!(
            db_error(sqlx::Error::Database(Box::new(SqlState(code)))),
            expected,
            "SQLSTATE {code}"
        );
    }
}
