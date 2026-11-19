//! `billing-worker::creem` — cloud provider boundary (§71.2).
//! Depends-on: crates=[async-trait, humaux-application, humaux-domain, serde_json, time, url]; services=[]; env=[]; modules=[application::billing, billing-worker::mode, billing-worker::normalize, domain::billing, domain::error]
//! Called-by: [billing-worker::creem_egress, tests]
//! Invariants: [explicit allowlist; authenticated raw bodies; no checkout-response money]
//! Spec: Baseline §71.2; §71.3; §52
use crate::{
    mode::BillingMode,
    normalize::{self, NormalizedEvent},
};
use async_trait::async_trait;
use humaux_application::billing::{
    BillingProvider, CheckoutRequest, CheckoutSession, ExternalCustomerRef,
    ExternalSubscriptionRef, PortalSession, ProviderSubscription, VerifiedBillingEvent,
};
use humaux_domain::{billing::BillingProviderId, error::ErrorCode};
use serde_json::Value;
use std::sync::Arc;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;

/// §71: provider transport and signature verification at the commercial boundary.
#[async_trait]
pub trait PaymentProviderClientPort: Send + Sync {
    /// Send a request to a destination selected by the commercial client.
    async fn send(
        &self,
        url: Url,
        method: &str,
        body: Vec<u8>,
        allowed_hosts: &[String],
    ) -> Result<Vec<u8>, ErrorCode>;

    /// Verify the provider signature over the original webhook bytes.
    async fn verify_webhook_signature(
        &self,
        header: Option<&str>,
        raw: &[u8],
    ) -> Result<(), ErrorCode>;
}

/// §71.2: Creem request and response contracts over an injected provider client.
pub struct CreemClient {
    base: Url,
    hosts: Vec<String>,
    provider: Arc<dyn PaymentProviderClientPort>,
}
impl CreemClient {
    /// §71.2: mode and configured origin constrain every outbound destination.
    pub fn new(
        base: &str,
        mode: &BillingMode,
        provider: Arc<dyn PaymentProviderClientPort>,
    ) -> Result<Self, ErrorCode> {
        let url = Url::parse(base).map_err(|_| ErrorCode::InvalidInput)?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(ErrorCode::InvalidInput);
        }
        let hosts = mode
            .allowed_hosts(Some(base))
            .map_err(|_| ErrorCode::Forbidden)?;
        if !hosts
            .iter()
            .any(|host| Some(host.as_str()) == url.host_str())
        {
            return Err(ErrorCode::Forbidden);
        }
        Ok(Self {
            base: url,
            hosts,
            provider,
        })
    }
    async fn get(&self, resource: &str, parameter: &str, id: &str) -> Result<Value, ErrorCode> {
        if id.is_empty() {
            return Err(ErrorCode::InvalidInput);
        }
        let mut url = self
            .base
            .join(resource)
            .map_err(|_| ErrorCode::InvalidInput)?;
        url.query_pairs_mut().append_pair(parameter, id);
        self.request(url, "GET", Vec::new(), id).await
    }
    async fn request(
        &self,
        url: Url,
        method: &str,
        body: Vec<u8>,
        id: &str,
    ) -> Result<Value, ErrorCode> {
        let body = self.provider.send(url, method, body, &self.hosts).await?;
        let value: Value = serde_json::from_slice(&body).map_err(|_| ErrorCode::InvalidInput)?;
        if text(&value, "id")? != id {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(value)
    }
    /// §71.3: authoritative money source; response identity must equal the requested reference.
    pub async fn fetch_transaction(&self, id: &str) -> Result<Value, ErrorCode> {
        self.get("v1/transactions", "transaction_id", id).await
    }
    /// §71.3: only verified payloads or their matching authoritative transaction supply money.
    pub async fn normalize_event(
        &self,
        headers: &[(&str, &str)],
        raw: &[u8],
    ) -> Result<NormalizedEvent, ErrorCode> {
        self.verify_webhook(headers, raw).await?;
        if let Ok(event) = normalize::normalize(raw, None) {
            return Ok(event);
        }
        let envelope: Value = serde_json::from_slice(raw).map_err(|_| ErrorCode::InvalidInput)?;
        let (_, reference) = normalize::transaction_source(&envelope)?;
        let transaction = self.fetch_transaction(reference).await?;
        normalize::normalize(raw, Some(&transaction))
    }
}
#[async_trait]
impl BillingProvider for CreemClient {
    async fn create_checkout(&self, _: CheckoutRequest) -> Result<CheckoutSession, ErrorCode> {
        // ponytail: §71.2 checkout creation belongs to M04-14.
        Err(ErrorCode::DependencyUnavailable)
    }
    async fn create_portal(&self, _: &ExternalCustomerRef) -> Result<PortalSession, ErrorCode> {
        // ponytail: §71.2 portal creation belongs to M04-14.
        Err(ErrorCode::DependencyUnavailable)
    }
    async fn fetch_subscription(
        &self,
        reference: &ExternalSubscriptionRef,
    ) -> Result<ProviderSubscription, ErrorCode> {
        let value = self
            .get("v1/subscriptions", "subscription_id", &reference.0)
            .await
            .map_err(|error| match error {
                ErrorCode::ProviderTransient | ErrorCode::ProviderRateLimited => {
                    ErrorCode::DependencyUnavailable
                }
                other => other,
            })?;
        parse_subscription(&value, reference)
    }
    async fn cancel_subscription_now(
        &self,
        reference: &ExternalSubscriptionRef,
    ) -> Result<ProviderSubscription, ErrorCode> {
        // Reject dot segments too: URL parsers normalize them rather than preserving identity.
        if reference.0.is_empty() || matches!(reference.0.as_str(), "." | "..") {
            return Err(ErrorCode::InvalidInput);
        }
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|_| ErrorCode::InvalidInput)?
            .extend(["v1", "subscriptions", reference.0.as_str(), "cancel"]);
        // Explicit immediate mode; neither this adapter nor HttpExternalCall retries a POST.
        let value = self
            .request(
                url,
                "POST",
                br#"{"mode":"immediate"}"#.to_vec(),
                &reference.0,
            )
            .await?;
        parse_subscription(&value, reference)
    }
    async fn verify_webhook(
        &self,
        headers: &[(&str, &str)],
        raw: &[u8],
    ) -> Result<VerifiedBillingEvent, ErrorCode> {
        let mut signatures = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("creem-signature"));
        let header = signatures.next().map(|(_, value)| *value);
        if signatures.next().is_some() {
            return Err(ErrorCode::Unauthorized);
        }
        self.provider.verify_webhook_signature(header, raw).await?;
        let value: Value = serde_json::from_slice(raw).map_err(|_| ErrorCode::InvalidInput)?;
        // §71.3: replay dedupe is the durable M04-11 inbox; Creem signs no timestamp component.
        Ok(VerifiedBillingEvent {
            provider: BillingProviderId::Creem,
            event_id: text(&value, "id")?.into(),
            event_type: text(&value, "eventType")?.into(),
            object_id: value["object"]["id"].as_str().map(str::to_owned),
        })
    }
}
fn parse_subscription(
    value: &Value,
    reference: &ExternalSubscriptionRef,
) -> Result<ProviderSubscription, ErrorCode> {
    let date = |key| {
        OffsetDateTime::parse(text(value, key)?, &Rfc3339).map_err(|_| ErrorCode::InvalidInput)
    };
    let start = date("current_period_start_date")?;
    let end = date("current_period_end_date")?;
    if end <= start {
        return Err(ErrorCode::InvalidInput);
    }
    let customer = value["customer"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(Ok)
        .unwrap_or_else(|| text(&value["customer"], "id"))?;
    Ok(ProviderSubscription {
        reference: reference.clone(),
        customer: ExternalCustomerRef(customer.into()),
        product: value["product"]
            .as_str()
            .filter(|id| !id.is_empty())
            .map(Ok)
            .unwrap_or_else(|| text(&value["product"], "id"))?
            .into(),
        status: normalize::status(text(value, "status")?)?,
        current_period_start: start,
        current_period_end: end,
    })
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, ErrorCode> {
    value[key]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or(ErrorCode::InvalidInput)
}
