//! `application::billing` — contract C3, the `BillingProvider` port of Baseline §71.2: the one seam through which the
//!   core talks to a billing provider, so no provider type enters the core (module design M04 D7).
//! Depends-on: crates=[async-trait, humaux-domain, time, uuid]; services=[]; env=[];
//!   modules=[domain::billing, domain::error]
//! Called-by: [adapters::billing_processor_repo, billing-worker::creem, billing-worker::process, tests]
//! Invariants: [the port and its DTOs hold no provider type and no HTTP type: the application crate takes no `http`
//!   dependency, so headers cross as `&[(&str, &str)]`; every method fails with `ErrorCode` and nothing else (the
//!   two-error-enum rule of §52 overrides the §71.2 sketch's `BillingError`); the trait stays object-safe, so a worker
//!   holds it as `dyn BillingProvider`; this crate has no implementation and no test double — the Creem adapter and the
//!   fake Creem server are M04-9's]
//! Spec: Baseline §71.2; §71.3; §52.1; §78.3
//!
//! The success URL of a checkout is display-only: only a processed webhook grants an entitlement (M04 D7). A checkout
//! pairs to its tenant by the opaque [`TenantRef`] carried in the provider's checkout metadata, never by the buyer's
//! e-mail address. [`BillingProvider::verify_webhook`] is the only place a raw body becomes a [`VerifiedBillingEvent`],
//! and it takes the bytes the signature covers. Errors are `ErrorCode` with no bespoke port error type, the precedent of
//! `application::retrieval_embedding_port` (§52.1: two error enums, no third).

use async_trait::async_trait;
use humaux_domain::billing::{BillingProviderId, ObservedStatus};
use humaux_domain::error::ErrorCode;
use time::OffsetDateTime;
use uuid::Uuid;

/// An opaque reference to a tenant that the provider echoes back in checkout metadata; the processor pairs a paid
/// checkout to its tenant by it (M04 D7), so it carries no e-mail address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TenantRef(pub String);

/// The provider's identifier of a customer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExternalCustomerRef(pub String);

/// The provider's identifier of a subscription.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExternalSubscriptionRef(pub String);

/// What a checkout needs from the core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutRequest {
    /// Whom the checkout is for, echoed back in the provider's metadata.
    pub tenant_ref: TenantRef,
    /// The plan version being bought (`control.plan_versions.plan_version_id`).
    pub plan_version_id: Uuid,
    /// Where the provider sends the buyer afterwards. Display only: it grants nothing.
    pub success_url: String,
}

/// A checkout the provider created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutSession {
    /// The provider-hosted page the buyer is sent to.
    pub url: String,
    /// The provider's identifier of the checkout.
    pub provider_checkout_ref: String,
}

/// A provider-hosted billing portal session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalSession {
    /// The portal page the customer is sent to.
    pub url: String,
}

/// The authoritative subscription as the provider reports it, normalized by the adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSubscription {
    /// The provider's identifier of the subscription.
    pub reference: ExternalSubscriptionRef,
    /// The provider's identifier of its customer.
    pub customer: ExternalCustomerRef,
    /// §71.3: the fetched provider product pins the plan; webhook product state may be stale.
    pub product: String,
    /// The provider-neutral status, the input of `domain::billing::project_state`.
    pub status: ObservedStatus,
    /// The start of the current paid period.
    pub current_period_start: OffsetDateTime,
    /// The end of the current paid period.
    pub current_period_end: OffsetDateTime,
}

/// A webhook whose raw-body signature verified; provider event ID UNIQUE keys enforce replay protection (§71.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBillingEvent {
    /// The provider that sent it.
    pub provider: BillingProviderId,
    /// The provider's event identifier, the duplicate guard of `control.billing_inbox`.
    pub event_id: String,
    /// The provider's event type.
    pub event_type: String,
    /// The object the event is about (a subscription or a transaction), when it names one.
    pub object_id: Option<String>,
}

/// C3: a billing provider, behind the core. Calls may be slow and fail; every failure is an [`ErrorCode`].
#[async_trait]
pub trait BillingProvider: Send + Sync {
    /// Creates a hosted checkout for `request`.
    async fn create_checkout(&self, request: CheckoutRequest)
    -> Result<CheckoutSession, ErrorCode>;

    /// Creates a hosted billing-portal session for an existing customer.
    async fn create_portal(
        &self,
        customer: &ExternalCustomerRef,
    ) -> Result<PortalSession, ErrorCode>;

    /// Fetches the authoritative subscription: the processor re-reads it instead of trusting a webhook's body (§71.3).
    async fn fetch_subscription(
        &self,
        subscription: &ExternalSubscriptionRef,
    ) -> Result<ProviderSubscription, ErrorCode>;

    /// Verifies the raw-body signature; provider event ID UNIQUE keys enforce replay protection (§71.3).
    /// Creem documents no timestamp; no timestamp window is assumed (M04 lead ruling 2026-10-28).
    /// `headers` are the request's header name and value pairs; `raw_body` is the exact bytes received.
    async fn verify_webhook(
        &self,
        headers: &[(&str, &str)],
        raw_body: &[u8],
    ) -> Result<VerifiedBillingEvent, ErrorCode>;
}

// Compile-time assertion that the port is object-safe: it fails to build when a method breaks `dyn BillingProvider`.
const _: Option<&dyn BillingProvider> = None;
