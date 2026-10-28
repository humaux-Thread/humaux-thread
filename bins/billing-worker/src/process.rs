//! `billing-worker::process` — one durable inbox task (§71.3, M04 D13h).
//! Depends-on: crates=[humaux-adapters, humaux-application, humaux-domain, serde_json, time, uuid];
//!   services=[]; env=[];
//!   modules=[adapters::billing_processor_repo, adapters::entitlement_repo, adapters::postgres, application::billing, billing-worker::normalize, domain::billing, domain::error, domain::ids]
//! Called-by: [tests]
//! Invariants: [ingress authenticates raw bytes; inbox identity checked; fetched state wins; C2 alone writes snapshots]
//! Spec: Baseline §71.3; §76; §52; §78.1
use humaux_adapters::{
    billing_processor_repo as repo, entitlement_repo, postgres::MaintenanceDbPool,
};
use humaux_application::billing::{BillingProvider, ExternalSubscriptionRef, VerifiedBillingEvent};
use humaux_domain::{
    billing::{BillingFacts, InboxStatus, ObservedStatus, project_state},
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

/// §71.3: returns false only for an empty inbox; failures are durably settled with their closed error code.
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
    let raw = serde_json::to_vec(payload).map_err(|_| ErrorCode::InvalidInput)?;
    let normalized = crate::normalize::normalize(&raw, None)?;
    if normalized.id != event.event_id
        || normalized.event_type != event.event_type
        || payload["object"]["id"].as_str() != event.object_id.as_deref()
    {
        return Err(ErrorCode::InvalidInput);
    }
    if normalized.kind == crate::normalize::EventKind::Ignored {
        return Ok(());
    }
    // §71.3: refunds/disputes and their payment rows are M04-11b; never consume them prematurely.
    if matches!(
        event.event_type.as_str(),
        "refund.created" | "dispute.created"
    ) {
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
    let product = object["product"]
        .as_str()
        .or_else(|| object["product"]["id"].as_str())
        .ok_or(ErrorCode::InvalidInput)?;
    let plan = config.plans.get(product).ok_or(ErrorCode::NotFound)?;
    let subscription = if event.event_type == "checkout.completed" {
        &object["subscription"]
    } else {
        object
    };
    let reference = subscription
        .as_str()
        .or_else(|| subscription["id"].as_str())
        .filter(|id| !id.is_empty())
        .ok_or(ErrorCode::InvalidInput)?;
    // ponytail: no per-subscription ordering yet, M04-11a3 adds lock-before-fetch
    let fetched = provider
        .fetch_subscription(&ExternalSubscriptionRef(reference.into()))
        .await?;
    if fetched.reference.0 != reference {
        return Err(ErrorCode::InvalidInput);
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
        &fetched,
        *plan,
        config.free_plan_version,
        state,
    )
    .await?
    {
        entitlement_repo::recompute_in_txn(txn, tenant).await?;
    }
    Ok(())
}
