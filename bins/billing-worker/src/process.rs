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
    billing::{InboxStatus, ObservedStatus, PaymentKind, SubscriptionState},
    error::ErrorCode,
    ids::TenantId,
};
use serde_json::Value;
use std::{collections::BTreeMap, time::Duration};
use time::OffsetDateTime;
use tokio::time::{Instant, timeout_at};
use uuid::Uuid;
/// §78.1: provider products map to pinned plan versions supplied by the caller.
pub struct ProcessorConfig {
    /// §71: no tier names or prices in processor logic.
    pub plans: BTreeMap<String, Uuid>,
    /// D13h: configured Free template, never inferred from its name.
    pub free_plan_version: Uuid,
    /// One validated budget for the entire invocation.
    pub budget: ProcessorBudget,
}

/// Bounds local waits; a timed-out commit may nevertheless have committed.
#[derive(Clone, Copy)]
pub struct ProcessorBudget {
    pub invocation: Duration,
    pub acquire: Duration,
    pub provider: Duration,
    pub lock: Duration,
    pub statement: Duration,
    pub transaction: Duration,
}
impl Default for ProcessorBudget {
    fn default() -> Self {
        Self {
            invocation: Duration::from_secs(120),
            acquire: Duration::from_secs(5),
            provider: Duration::from_secs(20),
            lock: Duration::from_secs(5),
            statement: Duration::from_secs(15),
            transaction: Duration::from_secs(115),
        }
    }
}
impl ProcessorBudget {
    fn validate(self) -> Result<(), ErrorCode> {
        let values = [
            self.invocation,
            self.acquire,
            self.provider,
            self.lock,
            self.statement,
            self.transaction,
        ];
        if values.iter().any(|d| {
            d.as_millis() == 0
                || d.as_millis() > i32::MAX as u128
                || d.subsec_nanos() % 1_000_000 != 0
        }) || !(self.lock < self.statement && self.statement < self.transaction)
            || self
                .acquire
                .checked_add(self.transaction)
                .is_none_or(|d| d > self.invocation)
            || self
                .provider
                .checked_mul(5)
                .is_none_or(|d| d >= self.transaction)
        {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(())
    }
}
fn ensure_time(deadline: Instant) -> Result<(), ErrorCode> {
    if Instant::now() >= deadline {
        Err(ErrorCode::DependencyUnavailable)
    } else {
        Ok(())
    }
}

/// §71.3: returns false only for an empty inbox; unavailable dependencies roll back for the next poll.
pub async fn process_one(
    pool: &MaintenanceDbPool,
    provider: &dyn BillingProvider,
    config: &ProcessorConfig,
) -> Result<bool, ErrorCode> {
    config.budget.validate()?;
    let now = Instant::now();
    let deadline = now
        .checked_add(config.budget.invocation)
        .ok_or(ErrorCode::InvalidInput)?;
    let acquire_deadline = now
        .checked_add(config.budget.acquire)
        .ok_or(ErrorCode::InvalidInput)?;
    let mut txn = timeout_at(acquire_deadline, repo::begin_processor(pool))
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)??;
    ensure_time(deadline)?;
    let processed = timeout_at(
        deadline,
        process_in_txn(&mut txn, provider, config, deadline),
    )
    .await
    .map_err(|_| ErrorCode::DependencyUnavailable)??;
    if !processed {
        return Ok(false);
    }
    ensure_time(deadline)?;
    // If the COMMIT acknowledgement times out its outcome is unknown; durable inbox dedupe resolves replay.
    timeout_at(deadline, txn.commit())
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    Ok(true)
}

async fn process_in_txn(
    txn: &mut repo::Txn<'_>,
    provider: &dyn BillingProvider,
    config: &ProcessorConfig,
    deadline: Instant,
) -> Result<bool, ErrorCode> {
    repo::configure_processor_timeouts(
        txn,
        config.budget.lock,
        config.budget.statement,
        config.budget.transaction,
    )
    .await?;
    let rows = repo::inbox_claim(txn, 1).await?;
    let Some((event, payload)) = rows.first() else {
        return Ok(false);
    };
    // §71.3: a failed apply/recompute must leave no partial effects, while retaining the outer claim lock.
    let mut effect = repo::savepoint(txn).await?;
    let result = apply(&mut effect, provider, config, event, payload, deadline).await;
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
        txn,
        event,
        if error.is_some() {
            InboxStatus::Failed
        } else {
            InboxStatus::Processed
        },
        error,
    )
    .await?;
    Ok(true)
}

async fn apply(
    txn: &mut repo::Txn<'_>,
    provider: &dyn BillingProvider,
    config: &ProcessorConfig,
    event: &VerifiedBillingEvent,
    payload: &Value,
    deadline: Instant,
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
    let object = &payload["object"];
    let reversal = matches!(
        event.event_type.as_str(),
        "refund.created" | "dispute.created"
    );
    let tenant = event_tenant(object, reversal)?;
    repo::scope_tenant(txn, tenant).await?;
    let subscription = if reversal {
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
    repo::acquire_billing_scope_in_txn(txn, tenant, event).await?;
    repo::lock_subscription(txn, event.provider, reference).await?;
    ensure_time(deadline)?;
    let provider_deadline = deadline; // TEMPORARY FAULT for named causal red
    let fetched = timeout_at(
        provider_deadline,
        provider.fetch_subscription(&ExternalSubscriptionRef(reference.into())),
    )
    .await
    .map_err(|_| ErrorCode::DependencyUnavailable)??;
    if fetched.reference.0 != reference {
        return Err(ErrorCode::InvalidInput);
    }
    // §71.3: checkout orders omit periods; only the locked authoritative subscription supplies them.
    let fallback = if event.event_type == "checkout.completed" {
        Some(
            serde_json::json!({"id":normalize::transaction_source(payload)?.1,
            "period_start":fetched.current_period_start.unix_timestamp_nanos() / 1_000_000,
            "period_end":fetched.current_period_end.unix_timestamp_nanos() / 1_000_000}),
        )
    } else {
        None
    };
    let normalized = normalize::normalize(
        &serde_json::to_vec(payload).map_err(|_| ErrorCode::InvalidInput)?,
        fallback.as_ref(),
    )?;
    if normalized.kind == EventKind::Ignored {
        return Err(ErrorCode::InvalidInput);
    }
    apply_fetched(txn, config, event, tenant, &fetched, &normalized).await
}
async fn apply_fetched(
    txn: &mut repo::Txn<'_>,
    config: &ProcessorConfig,
    event: &VerifiedBillingEvent,
    tenant: TenantId,
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
            fetched,
            *plan,
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
    // §71.3 / D13h: the apply door overlays recorded reversal facts on every fetched observation.
    let state = match fetched.status {
        ObservedStatus::Incomplete => SubscriptionState::Incomplete,
        ObservedStatus::Trialing => SubscriptionState::Trialing,
        ObservedStatus::Active => SubscriptionState::Active,
        ObservedStatus::PastDue | ObservedStatus::Unpaid => SubscriptionState::PastDue,
        ObservedStatus::Paused => SubscriptionState::Paused,
        ObservedStatus::ScheduledCancel => SubscriptionState::CancelAtPeriodEnd,
        ObservedStatus::Canceled | ObservedStatus::Expired => SubscriptionState::Canceled,
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

fn event_tenant(object: &Value, reversal: bool) -> Result<TenantId, ErrorCode> {
    // §71.3: Creem v1 refund/dispute metadata belongs to subscription/checkout (docs 2026-10-29).
    let subscription = &object["subscription"]["metadata"]["tenant_id"];
    let checkout = &object["checkout"]["metadata"]["tenant_id"];
    if reversal && !subscription.is_null() && !checkout.is_null() && subscription != checkout {
        return Err(ErrorCode::TenantBoundary);
    }
    let value = if reversal {
        if subscription.is_null() {
            checkout
        } else {
            subscription
        }
    } else {
        &object["metadata"]["tenant_id"]
    };
    value
        .as_str()
        .and_then(|id| Uuid::parse_str(id).ok())
        .filter(|id| !id.is_nil())
        .map(TenantId)
        .ok_or(ErrorCode::NotFound)
}
