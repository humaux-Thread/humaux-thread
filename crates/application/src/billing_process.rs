//! `application::billing_process` — process one verified billing inbox event (§71.3).
//! Depends-on: crates=[async-trait, humaux-domain, time, uuid]; services=[]; env=[]; modules=[application::billing, domain::billing, domain::error, domain::ids, domain::plan]
//! Called-by: [adapters::billing_processor_repo, billing-worker::normalize, billing-worker::process]
//! Invariants: [claim through settlement is atomic; fetched state wins; dependency failure leaves RECEIVED]
//! Spec: Baseline §71.3; §76; ADR-0130 D2

use crate::billing::{
    BillingProvider, ExternalSubscriptionRef, ProviderSubscription, VerifiedBillingEvent,
};
use async_trait::async_trait;
use humaux_domain::{
    billing::{BillingProviderId, InboxStatus, ObservedStatus, PaymentKind, SubscriptionState},
    error::ErrorCode,
    ids::TenantId,
    plan::Currency,
};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

/// §78.1: provider products map to pinned plan versions supplied by the caller.
pub struct ProcessorConfig {
    /// §71: no tier names or prices in processor logic.
    pub plans: BTreeMap<String, Uuid>,
    /// D13h: configured Free template, never inferred from its name.
    pub free_plan_version: Uuid,
}

/// §71.3: non-payment events carry no invented payment facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// §71.3: append-only payment direction.
    Payment(PaymentKind),
    /// §71.3: requires an authoritative subscription re-fetch.
    SubscriptionChanged,
    /// §71.3: retained by the inbox, without billing effects.
    Ignored,
}

/// §71.3: integer cents and millisecond period bounds from payload/fetch only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Money {
    /// §71.3: M04-11 stores the explicitly named amount for each direction.
    pub amount: PaymentAmount,
    /// §78.2: the existing USD-only vocabulary.
    pub currency: Currency,
    /// §71.3: absent tax stays unknown.
    pub tax_amount: Option<i64>,
    /// §71.3: transaction period start in epoch milliseconds.
    pub period_start: i64,
    /// §71.3: transaction period end in epoch milliseconds.
    pub period_end: i64,
}

/// §71.3: M04-11 writes charged_amount, refund_amount or disputed_amount respectively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentAmount {
    /// §71.3: CHARGE stores gross tax-inclusive amount_paid (lead ruling 2026-10-29).
    Charge {
        /// §71.3: charged cents, never defaulted.
        charged_amount: i64,
    },
    /// §71.3: REFUND stores refund_amount, never original_transaction_amount.
    Refund {
        /// §71.3: event-specific reversal, not aggregate refunded_amount.
        refund_amount: i64,
        /// §71.3: original charge retained separately.
        original_transaction_amount: i64,
    },
    /// §71.3: CHARGEBACK stores disputed_amount from the dispute object.
    Chargeback {
        /// §71.3: disputed cents, independent of the original transaction amount.
        disputed_amount: i64,
    },
}

/// §71.3: normalization does not confer signature verification or deduplication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedEvent {
    /// §71.3: inbox deduplication key.
    pub id: String,
    /// §71.3: retained even for ignored events.
    pub event_type: String,
    /// §71.3: envelope epoch milliseconds, not a replay check.
    pub created_at: i64,
    /// §71.3: effect category independent of subscription status.
    pub kind: EventKind,
    /// §71.3: present exactly for payment events.
    pub money: Option<Money>,
    /// §71.3: M04-11 stores CHARGE transaction id, REFUND refund id, CHARGEBACK dispute id
    /// in the ledger UNIQUE key; absent on non-payments (M04 ledger-ref ruling).
    pub provider_txn_ref: Option<String>,
    /// §71.3: original transaction id for REFUND/CHARGEBACK linking only, never their ledger key.
    /// Absent on CHARGE and non-payments (M04 ledger-ref ruling).
    pub original_txn_ref: Option<String>,
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

/// Provider envelope decoded in stages without exposing its wire format to the use case.
pub trait BillingEventPayload: Send + Sync {
    /// Check the verified inbox identity and extract the tenant before scoping the claim.
    fn tenant(&self, event: &VerifiedBillingEvent) -> Result<TenantId, ErrorCode>;

    /// Resolve the subscription to lock before fetching authoritative state.
    fn subscription_ref(&self, event: &VerifiedBillingEvent) -> Result<&str, ErrorCode>;

    /// Normalize using the authoritative observation already fetched under the subscription lock.
    fn normalize(
        &self,
        event: &VerifiedBillingEvent,
        fetched: &ProviderSubscription,
    ) -> Result<NormalizedEvent, ErrorCode>;
}

/// Durable inbox access backed by a claim that retains its lock through settlement.
#[async_trait]
pub trait BillingInbox: Sync {
    /// Adapter-owned handle for the claimed inbox row.
    type Claim<'a>: BillingClaim
    where
        Self: 'a;
    /// Opaque stored provider envelope.
    type Payload: BillingEventPayload;

    /// Claim the oldest available verified event, or return an empty inbox.
    async fn claim(
        &self,
    ) -> Result<Option<(Self::Claim<'_>, VerifiedBillingEvent, Self::Payload)>, ErrorCode>;
}

/// An inbox claim whose settlement and effects share one outer commit.
#[async_trait]
pub trait BillingClaim: Send {
    /// Handle for the effects that may roll back while the outer claim stays locked.
    type Effects<'a>: BillingEffects
    where
        Self: 'a;

    /// Scope the effects to a savepoint inside this claim.
    async fn begin_effects(&mut self) -> Result<Self::Effects<'_>, ErrorCode>;

    /// Settle the inbox and commit the claim together with any released effects.
    async fn settle(
        self,
        event: &VerifiedBillingEvent,
        status: InboxStatus,
        error: Option<ErrorCode>,
    ) -> Result<(), ErrorCode>;
}

/// The business effects of a claimed billing event, scoped to its savepoint.
#[async_trait]
pub trait BillingEffects: Send {
    /// Scope the event to an existing tenant.
    async fn scope_tenant(&mut self, tenant: TenantId) -> Result<(), ErrorCode>;
    /// Serialize authoritative observations until the claim commits.
    async fn lock_subscription(
        &mut self,
        provider: BillingProviderId,
        reference: &str,
    ) -> Result<(), ErrorCode>;
    /// Append one verified payment movement, returning whether it is new.
    #[allow(clippy::too_many_arguments)] // Keep the owner door's inputs explicit.
    async fn append_payment(
        &mut self,
        tenant: TenantId,
        event: &VerifiedBillingEvent,
        fetched: &ProviderSubscription,
        plan: Uuid,
        free_plan: Uuid,
        payment: &PaymentFacts<'_>,
    ) -> Result<bool, ErrorCode>;
    /// Apply the current subscription and plan, returning whether the event is new.
    #[allow(clippy::too_many_arguments)] // Keep the owner door's inputs explicit.
    async fn apply_subscription(
        &mut self,
        tenant: TenantId,
        event: &VerifiedBillingEvent,
        fetched: &ProviderSubscription,
        plan: Uuid,
        free_plan: Uuid,
        state: SubscriptionState,
    ) -> Result<bool, ErrorCode>;
    /// Recompute C2 from the effects in the same claim.
    async fn recompute_entitlements(&mut self, tenant: TenantId) -> Result<(), ErrorCode>;
    /// Release the savepoint. Effects become durable only when the claim commits.
    async fn release(self) -> Result<(), ErrorCode>;
    /// Discard effects while retaining the claim for terminal failure settlement.
    async fn rollback(self) -> Result<(), ErrorCode>;
}

/// §71.3: returns false only for an empty inbox; unavailable dependencies roll back for the next poll.
pub async fn process_one(
    inbox: &impl BillingInbox,
    provider: &dyn BillingProvider,
    config: &ProcessorConfig,
) -> Result<bool, ErrorCode> {
    let Some((mut claim, event, payload)) = inbox.claim().await? else {
        return Ok(false);
    };
    // §71.3: failed apply/recompute leaves no partial effects while retaining the outer claim lock.
    let mut effect = claim.begin_effects().await?;
    let result = apply(&mut effect, provider, config, &event, &payload).await;
    let error = match result {
        Ok(()) => {
            effect.release().await?;
            None
        }
        Err(ErrorCode::DependencyUnavailable) => return Err(ErrorCode::DependencyUnavailable),
        Err(error) => {
            effect.rollback().await?;
            Some(error)
        }
    };
    claim
        .settle(
            &event,
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
    effect: &mut impl BillingEffects,
    provider: &dyn BillingProvider,
    config: &ProcessorConfig,
    event: &VerifiedBillingEvent,
    payload: &impl BillingEventPayload,
) -> Result<(), ErrorCode> {
    let tenant = payload.tenant(event)?;
    effect.scope_tenant(tenant).await?;
    let reference = payload.subscription_ref(event)?;
    // §71.3: another event cannot fetch until this observation and its projection commit.
    effect.lock_subscription(event.provider, reference).await?;
    let fetched = provider
        .fetch_subscription(&ExternalSubscriptionRef(reference.into()))
        .await?;
    if fetched.reference.0 != reference {
        return Err(ErrorCode::InvalidInput);
    }
    let normalized = payload.normalize(event, &fetched)?;
    if normalized.kind == EventKind::Ignored {
        return Err(ErrorCode::InvalidInput);
    }
    apply_fetched(effect, config, event, tenant, &fetched, &normalized).await
}

async fn apply_fetched(
    effect: &mut impl BillingEffects,
    config: &ProcessorConfig,
    event: &VerifiedBillingEvent,
    tenant: TenantId,
    fetched: &ProviderSubscription,
    normalized: &NormalizedEvent,
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
        effect
            .append_payment(
                tenant,
                event,
                fetched,
                *plan,
                config.free_plan_version,
                &PaymentFacts {
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
            effect.recompute_entitlements(tenant).await?;
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
    if effect
        .apply_subscription(
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
        effect.recompute_entitlements(tenant).await?;
    }
    Ok(())
}
