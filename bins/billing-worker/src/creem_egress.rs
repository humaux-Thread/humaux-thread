//! `billing-worker::creem_egress` — purpose-bound Creem transport and credential adapter.
//! Depends-on: crates=[async-trait, humaux-domain, humaux-infra-egress, url]; services=[HTTP(provider)]; env=[]; modules=[billing-worker::creem, billing-worker::signature, domain::dataclass, domain::egress, domain::error, domain::ids, infra-egress::http]
//! Called-by: [tests]
//! Invariants: [authorize before transport; injected credentials; raw webhook signatures]
//! Spec: Baseline §30; §71.2; §71.3
use crate::{creem::PaymentProviderClientPort, signature};
use async_trait::async_trait;
use humaux_domain::{
    dataclass::DataClass,
    egress::{self, AuthorizedEgressPayload, ExternalCall, PrivateDataPurpose, ProcessorId},
    error::ErrorCode,
    ids::TenantId,
};
use humaux_infra_egress::http::{HttpEgressConfig, HttpExternalCall, RetrievalCredentialSource};
use std::sync::Arc;
use url::Url;

/// §71.2: binds the worker's egress identity, transport policy and credential sources.
pub struct CreemEgress {
    tenant: TenantId,
    processor: ProcessorId,
    config: HttpEgressConfig,
    api_key: Arc<dyn RetrievalCredentialSource>,
    webhook_secret: Arc<dyn RetrievalCredentialSource>,
}

impl CreemEgress {
    /// Credentials are resolved at use time and never form part of the URL.
    pub fn new(
        tenant: TenantId,
        processor: ProcessorId,
        config: HttpEgressConfig,
        api_key: Arc<dyn RetrievalCredentialSource>,
        webhook_secret: Arc<dyn RetrievalCredentialSource>,
    ) -> Self {
        Self {
            tenant,
            processor,
            config,
            api_key,
            webhook_secret,
        }
    }
}

#[async_trait]
impl PaymentProviderClientPort for CreemEgress {
    async fn send(
        &self,
        url: Url,
        method: &str,
        body: Vec<u8>,
        allowed_hosts: &[String],
    ) -> Result<Vec<u8>, ErrorCode> {
        let call = HttpExternalCall::new(
            url.as_str(),
            self.processor,
            self.config,
            self.api_key.clone(),
            classify_status,
        )
        .map_err(|_| ErrorCode::InvalidInput)?
        .with_request_policy(
            method.parse().map_err(|_| ErrorCode::InvalidInput)?,
            "x-api-key".parse().map_err(|_| ErrorCode::InvalidInput)?,
            allowed_hosts.to_vec(),
        )?;
        let payload = AuthorizedEgressPayload::new(body);
        // §71 / external-egress-registry: BILLING is metadata; no private-data disclosure reservation.
        let permit = egress::authorize(
            self.tenant,
            self.processor,
            PrivateDataPurpose::BillingProvider,
            DataClass::Internal,
            &payload,
            self.config.request_timeout,
        )?;
        // dep: HTTP(provider) — §71.2 purpose-bound provider call with transport-injected credential
        call.call(&permit, &payload).await
    }

    async fn verify_webhook_signature(
        &self,
        header: Option<&str>,
        raw: &[u8],
    ) -> Result<(), ErrorCode> {
        let secret = self.webhook_secret.credential().await?;
        signature::verify(header, raw, secret.expose().as_bytes())
    }
}

fn classify_status(status: u16) -> ErrorCode {
    match status {
        401 => ErrorCode::Unauthorized,
        429 => ErrorCode::ProviderRateLimited,
        500..=599 => ErrorCode::ProviderTransient,
        _ => ErrorCode::ProviderPermanent,
    }
}
