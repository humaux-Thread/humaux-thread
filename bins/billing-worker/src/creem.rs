//! `billing-worker::creem` — cloud provider boundary (§71.2).
//! Depends-on: crates=[async-trait, humaux-application, humaux-domain, humaux-infra-egress, humaux-infra-network, serde_json, time]; services=[HTTP(provider)]; env=[]; modules=[application::billing, billing-worker::mode, billing-worker::normalize, billing-worker::signature, domain::billing, domain::dataclass, domain::egress, domain::error, domain::ids, infra-egress::http, humaux-infra-network]
//! Called-by: [tests]
//! Invariants: [explicit allowlist; authenticated raw bodies; no checkout-response money]
//! Spec: Baseline §71.2; §71.3; §52
use crate::{
    mode::BillingMode,
    normalize::{self, NormalizedEvent},
    signature,
};
use async_trait::async_trait;
use humaux_application::billing::{
    BillingProvider, CheckoutRequest, CheckoutSession, ExternalCustomerRef,
    ExternalSubscriptionRef, PortalSession, ProviderSubscription, VerifiedBillingEvent,
};
use humaux_domain::{
    billing::BillingProviderId,
    dataclass::DataClass,
    egress::{self, AuthorizedEgressPayload, ExternalCall, PrivateDataPurpose, ProcessorId},
    error::ErrorCode,
    ids::TenantId,
};
use humaux_infra_egress::http::{HttpEgressConfig, HttpExternalCall, RetrievalCredentialSource};
use humaux_infra_network::reqwest::{Method, Url, header::HeaderName};
use serde_json::Value;
use std::sync::Arc;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

/// §71.2: credentials are injected sources (production uses `EnvCredentialSource`), never URL components.
pub struct CreemClient {
    base: Url,
    hosts: Vec<String>,
    tenant: TenantId,
    processor: ProcessorId,
    config: HttpEgressConfig,
    api_key: Arc<dyn RetrievalCredentialSource>,
    webhook_secret: Arc<dyn RetrievalCredentialSource>,
}
impl CreemClient {
    /// §71.2: mode and configured origin constrain every outbound destination.
    pub fn new(
        base: &str,
        mode: &BillingMode,
        tenant: TenantId,
        processor: ProcessorId,
        config: HttpEgressConfig,
        api_key: Arc<dyn RetrievalCredentialSource>,
        webhook_secret: Arc<dyn RetrievalCredentialSource>,
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
            tenant,
            processor,
            config,
            api_key,
            webhook_secret,
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
        let call = HttpExternalCall::new(
            url.as_str(),
            self.processor,
            self.config,
            self.api_key.clone(),
            classify_status,
        )
        .map_err(|_| ErrorCode::InvalidInput)?
        .with_request_policy(
            Method::GET,
            HeaderName::from_static("x-api-key"),
            self.hosts.clone(),
        )?;
        let payload = AuthorizedEgressPayload::new(Vec::new());
        // §71 / external-egress-registry: BILLING is metadata; no private-data disclosure reservation.
        let permit = egress::authorize(
            self.tenant,
            self.processor,
            PrivateDataPurpose::BillingProvider,
            DataClass::Internal,
            &payload,
            self.config.request_timeout,
        )?;
        // dep: HTTP(provider) — §71.2 purpose-bound GET with transport-injected credential
        let body = call.call(&permit, &payload).await?;
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
            .await?;
        let date = |key| {
            OffsetDateTime::parse(text(&value, key)?, &Rfc3339).map_err(|_| ErrorCode::InvalidInput)
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
            status: normalize::status(text(&value, "status")?)?,
            current_period_start: start,
            current_period_end: end,
        })
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
        let secret = self.webhook_secret.credential().await?;
        signature::verify(header, raw, secret.expose().as_bytes())?;
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
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, ErrorCode> {
    value[key]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or(ErrorCode::InvalidInput)
}
fn classify_status(status: u16) -> ErrorCode {
    match status {
        401 => ErrorCode::Unauthorized,
        429 => ErrorCode::ProviderRateLimited,
        500..=599 => ErrorCode::ProviderTransient,
        _ => ErrorCode::ProviderPermanent,
    }
}
