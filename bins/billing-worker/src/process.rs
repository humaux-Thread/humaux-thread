//! `billing-worker::process` — one durable inbox task (§71.3, M04 D13h).
//! Depends-on: crates=[humaux-adapters, humaux-application, humaux-domain, serde_json, time, uuid];
//!   services=[]; env=[];
//!   modules=[adapters::billing_processor_repo, adapters::entitlement_repo, adapters::postgres, application::billing, billing-worker::normalize, domain::billing, domain::error, domain::ids]
//! Called-by: [tests]
//! Invariants: [ingress authenticates raw bytes; inbox identity checked; fetched state wins; C2 alone writes snapshots]
//! Spec: Baseline §71.3; §76; §52; §78.1
use crate::normalize::{self, EventKind, PaymentAmount};
use humaux_adapters::{
    billing_processor_repo as repo, entitlement_repo, postgres::MaintenanceDbPool,
};
use humaux_application::billing::{BillingProvider, ExternalSubscriptionRef, VerifiedBillingEvent};
use humaux_domain::{
    billing::{BillingFacts, InboxStatus, ObservedStatus, PaymentKind, project_state},
    error::ErrorCode,
    ids::TenantId,
};
use serde_json::Value;
use std::collections::BTreeMap;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
/// §78.1: provider products map to pinned plan versions supplied by the caller.
pub struct ProcessorConfig {
    /// §71: no tier names or prices in processor logic.
    pub plans: BTreeMap<String, Uuid>,
    /// D13h: configured Free template, never inferred from its name.
    pub free_plan_version: Uuid,
}

/// §71.3: returns false only for an empty inbox; unavailable dependencies roll back for the next poll.
pub async fn process_one(
    pool: &MaintenanceDbPool,
    provider: &dyn BillingProvider,
    config: &ProcessorConfig,
) -> Result<bool, ErrorCode> {
    let mut txn = repo::begin_processor(pool).await?;
    let rows = repo::inbox_claim(&mut txn, 1).await?;
    let Some((event, payload)) = rows.first() else {
        return Ok(false);
    };
    // §71.3: a failed apply/recompute must leave no partial effects, while retaining the outer claim lock.
    let mut effect = repo::savepoint(&mut txn).await?;
    let result = apply(&mut effect, provider, config, event, payload).await;
    let error = match result {
        Ok(()) => {
            effect
                .commit()
                .await
                .map_err(|_| ErrorCode::DependencyUnavailable)?;
            None
        }
        Err(ErrorCode::DependencyUnavailable) => return Err(ErrorCode::DependencyUnavailable),
        Err(error) => {
            effect
                .rollback()
                .await
                .map_err(|_| ErrorCode::DependencyUnavailable)?;
            Some(error)
        }
    };
    repo::inbox_settle(
        &mut txn,
        event,
        if error.is_some() {
            InboxStatus::Failed
        } else {
            InboxStatus::Processed
        },
        error,
    )
    .await?;
    txn.commit()
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    Ok(true)
}

async fn apply(
    txn: &mut repo::Txn<'_>,
    provider: &dyn BillingProvider,
    config: &ProcessorConfig,
    event: &VerifiedBillingEvent,
    payload: &Value,
) -> Result<(), ErrorCode> {
    // §71.3: inbox columns must agree with the authenticated envelope.
    if event.event_id.is_empty()
        || event.event_type.is_empty()
        || payload["id"].as_str() != Some(event.event_id.as_str())
        || payload["eventType"].as_str() != Some(event.event_type.as_str())
        || payload["object"]["id"].as_str() != event.object_id.as_deref()
        || payload["created_at"].as_i64().is_none_or(|n| n < 0)
    {
        return Err(ErrorCode::InvalidInput);
    }
    let normalized = normalize::normalize(
        &serde_json::to_vec(payload).map_err(|_| ErrorCode::InvalidInput)?,
        None,
    )?;
    if normalized.kind == EventKind::Ignored {
        return Err(ErrorCode::InvalidInput);
    }
    let object = &payload["object"];
    let tenant = object["metadata"]["tenant_id"]
        .as_str()
        .and_then(|id| Uuid::parse_str(id).ok())
        .filter(|id| !id.is_nil())
        .map(TenantId)
        .ok_or(ErrorCode::NotFound)?;
    repo::scope_tenant(txn, tenant).await?;
    let subscription = if matches!(
        normalized.kind,
        EventKind::Payment(PaymentKind::Refund | PaymentKind::Chargeback)
    ) {
        object
            .get("subscription")
            .unwrap_or(&object["transaction"]["subscription"])
    } else if event.event_type == "checkout.completed" {
        &object["subscription"]
    } else {
        object
    };
    let reference = subscription
        .as_str()
        .or_else(|| subscription["id"].as_str())
        .filter(|id| !id.is_empty())
        .ok_or(ErrorCode::InvalidInput)?;
    // §71.3: another event cannot fetch until this observation and its projection commit.
    repo::lock_subscription(txn, event.provider, reference).await?;
    let fetched = provider
        .fetch_subscription(&ExternalSubscriptionRef(reference.into()))
        .await?;
    if fetched.reference.0 != reference {
        return Err(ErrorCode::InvalidInput);
    }
    apply_fetched(txn, config, event, tenant, reference, &fetched, &normalized).await
}
async fn apply_fetched(
    txn: &mut repo::Txn<'_>,
    config: &ProcessorConfig,
    event: &VerifiedBillingEvent,
    tenant: TenantId,
    reference: &str,
    fetched: &humaux_application::billing::ProviderSubscription,
    normalized: &normalize::NormalizedEvent,
) -> Result<(), ErrorCode> {
    let plan = config
        .plans
        .get(&fetched.product)
        .ok_or(ErrorCode::NotFound)?;
    let payment_changed = if let EventKind::Payment(kind) = normalized.kind {
        let money = normalized.money.as_ref().ok_or(ErrorCode::InvalidInput)?;
        let amount = match money.amount {
            PaymentAmount::Charge { charged_amount } => charged_amount,
            PaymentAmount::Refund { refund_amount, .. } => refund_amount,
            PaymentAmount::Chargeback { disputed_amount } => disputed_amount,
        };
        let millis = |n| {
            OffsetDateTime::from_unix_timestamp_nanos(i128::from(n) * 1_000_000)
                .map_err(|_| ErrorCode::InvalidInput)
        };
        repo::append_payment_in_txn(
            txn,
            tenant,
            event,
            reference,
            config.free_plan_version,
            &repo::PaymentFacts {
                kind,
                reference: normalized
                    .provider_txn_ref
                    .as_deref()
                    .ok_or(ErrorCode::InvalidInput)?,
                amount,
                currency: money.currency,
                period: [millis(money.period_start)?, millis(money.period_end)?],
                occurred_at: millis(normalized.created_at)?,
            },
        )
        .await?
    } else {
        false
    };
    if matches!(
        normalized.kind,
        EventKind::Payment(PaymentKind::Refund | PaymentKind::Chargeback)
    ) {
        if payment_changed {
            entitlement_repo::recompute_in_txn(txn, tenant).await?;
        }
        return Ok(());
    }
    // D13h supersedes the domain's historical grace clock; the door revokes PAST_DUE immediately.
    let state = if matches!(
        fetched.status,
        ObservedStatus::PastDue | ObservedStatus::Unpaid
    ) {
        humaux_domain::billing::SubscriptionState::PastDue
    } else {
        project_state(
            fetched.status,
            &BillingFacts {
                now: OffsetDateTime::now_utc(),
                current_period_end: fetched.current_period_end,
                grace: Duration::ZERO,
                reversed: false,
            },
        )
    };
    if repo::apply_subscription_in_txn(
        txn,
        tenant,
        event,
        fetched,
        *plan,
        config.free_plan_version,
        state,
    )
    .await?
        || payment_changed
    {
        entitlement_repo::recompute_in_txn(txn, tenant).await?;
    }
    Ok(())
}
