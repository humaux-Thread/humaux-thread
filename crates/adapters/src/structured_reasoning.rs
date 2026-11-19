//! `adapters::structured_reasoning` — Route admission contract and execution helpers for private structured provider calls.
//! Depends-on: crates=[humaux-application, humaux-domain, serde_json, sqlx, uuid]; services=[]; env=[]; modules=[adapters::byok, adapters::disclosure, adapters::model_call_ledger, application::private_reasoning, domain::egress, domain::error, domain::ids, domain::ledger, domain::reasoning_types]
//! Called-by: [adapters::consolidation_reasoner, adapters::contribution_entry_repo, adapters::contribution_reasoner, adapters::distill_reasoner, adapters::reasoning_route_admission]
//! Invariants: [only a matching admitted profile may dispatch; failure lines carry static classes]
//! Spec: §11.2; §11.8; ADR-0060 D-B

use crate::{
    byok::{
        CredentialRef, PrivateInferenceContext, ReasoningCapability, ReasoningDomainId,
        ReasoningProviderError, UserReasoningProvider,
    },
    disclosure::DeletionCapability,
    model_call_ledger::FinalizeCall,
};
use humaux_application::private_reasoning::PrivateReasoningError;
use humaux_domain::{
    egress::{EgressPermit, ProcessorId},
    error::ErrorCode,
    ids::{TenantId, UserId},
    ledger::ModelCallPurpose,
    reasoning_types::{
        PrivateReasoningDomainId, PrivateReasoningPurpose, ReasoningRouteBindingId,
        ReasoningRouteBindingVersion,
    },
};
use sqlx::types::time::OffsetDateTime;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

/// ADR-0060 D-B: the seam from one admitted route to the provider instance that serves it. The
/// reasoners call it only after the resolver admitted the locator (D-G), then compare the
/// instance with the route (`contribution_reasoner::provider_matches_admission`, D-C). The
/// private worker passes one closure over its per-Profile@version instances; tests pass closures
/// over stub providers. An `Err` is a static NOT_READY class (ADR-0058 D-H), never provider text.
pub type ProviderFor = dyn Fn(&ReasoningAdmissionLocator) -> Result<Arc<dyn UserReasoningProvider>, &'static str>
    + Send
    + Sync;

/// One fully admitted route. Every field comes from one resolver statement snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReasoningAdmissionLocator {
    pub tenant_id: Uuid,
    pub binding_id: ReasoningRouteBindingId,
    pub binding_version: ReasoningRouteBindingVersion,
    pub reasoning_domain_id: PrivateReasoningDomainId,
    pub purpose: PrivateReasoningPurpose,
    pub route_policy_id: Uuid,
    pub route_policy_version: i64,
    pub profile_id: Uuid,
    pub profile_version: i64,
    pub provider_account_id: Uuid,
    pub processor_id: String,
    pub processor_model_id: Uuid,
    pub provider_model_id: String,
    pub model_revision: Option<String>,
    pub provider_endpoint_id: Uuid,
    pub egress_processor_id: ProcessorId,
    pub endpoint_ref: String,
    pub region: String,
    pub service_tier: String,
    pub credential_ref: Uuid,
    pub billing_account_id: Option<Uuid>,
    pub billing_instrument_id: Option<Uuid>,
    pub provider_health_observation_id: i64,
    pub account_health_observation_id: i64,
    pub admitted_at: OffsetDateTime,
    /// §11.2 / ADR-0060 D-A: the capabilities the admitted Profile@version declares (never the
    /// catalog upper bound, never process configuration). Immutable per Profile@version (0128).
    pub capabilities: Vec<ReasoningCapability>,
    /// ADR-0060 research amendment 1: the admitted Profile@version's `request_extras` (vendor
    /// request fields as profile data, 0206 CHECK). Immutable per Profile@version (0128).
    pub request_extras: serde_json::Map<String, serde_json::Value>,
}

impl ReasoningAdmissionLocator {
    /// ADR-0060 D-M: the route fields every operator line about one call carries — provider and
    /// model as registered, Profile@version and Binding@version. Never `endpoint_ref`, never a
    /// key, never provider or user text.
    #[must_use]
    pub fn route_fields(&self) -> String {
        format!(
            "provider={} model={} profile={}@{} binding={}@{}",
            self.processor_id,
            self.provider_model_id,
            self.profile_id,
            self.profile_version,
            self.binding_id.0,
            self.binding_version.0
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasoningAdmissionError {
    Database,
    InvalidLocator,
}

impl std::fmt::Display for ReasoningAdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database => f.write_str("reasoning admission resolver unavailable"),
            Self::InvalidLocator => f.write_str("reasoning admission locator invalid"),
        }
    }
}

impl std::error::Error for ReasoningAdmissionError {}

/// Resolves admission using the caller's already scoped transaction and snapshot.
pub(crate) trait ReasoningAdmissionPort {
    fn resolve_user_reasoning_admission(
        &mut self,
        binding_id: ReasoningRouteBindingId,
        binding_version: ReasoningRouteBindingVersion,
        expected_reasoning_domain_id: PrivateReasoningDomainId,
        expected_purpose: PrivateReasoningPurpose,
    ) -> impl Future<Output = Result<Option<ReasoningAdmissionLocator>, ReasoningAdmissionError>> + Send;
}

/// Deployment-owned inputs for one contribution de-identification call.
///
/// No provider, model, recipient, region, credential, source bytes or fallback key appears here:
/// the admitted route names all of them, and the caller's [`ProviderFor`] maps that route to its
/// provider instance (ADR-0060 D-B/D-C). The deployment's deny-only recipient and region lists
/// live with that mapping, not here, so no config can select a recipient (§11.2.5).
pub struct ContributionReasonerConfig {
    pub permit_ttl: Duration,
    pub deletion_capability: DeletionCapability,
    pub system_prompt: String,
    pub json_schema: String,
    pub max_output_tokens: u32,
}

impl ContributionReasonerConfig {
    /// Rejects an incomplete deployment configuration before any private DB read or egress.
    pub fn validate(&self) -> Result<(), ErrorCode> {
        if self.permit_ttl.is_zero()
            || self.system_prompt.trim().is_empty()
            || self.json_schema.trim().is_empty()
            || self.max_output_tokens == 0
        {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(())
    }
}

/// §11.1 [`PrivateInferenceContext`] from one admitted route + the permit minted over the
/// exact wire bytes. Shared by the same three dispatch paths as
/// [`crate::contribution_reasoner::authorize_structured_egress`].
pub(crate) fn admitted_inference_context(
    tenant_id: Uuid,
    user_id: Uuid,
    reasoning_domain_id: Uuid,
    admission: &ReasoningAdmissionLocator,
    permit: EgressPermit,
    trace_id: String,
) -> Result<PrivateInferenceContext, crate::byok::InferenceContextError> {
    PrivateInferenceContext::new(
        TenantId(tenant_id),
        UserId(user_id),
        ReasoningDomainId(reasoning_domain_id),
        CredentialRef::new(admission.credential_ref),
        permit,
        admission.processor_id.clone(),
        admission.provider_model_id.clone(),
        admission.profile_version,
        trace_id,
    )
}

/// ADR-0058 D-N: the ONE operator line for a failed provider call, printed by every dispatch path
/// (contribution, distill, consolidation). It carries what the ledger row holds — the static
/// class, the latency and the `model_call_id` to join on — so a timeout (`RETRY_WAIT` with
/// latency ≈ the transport timeout), a 429/5xx (`RETRY_WAIT`, short) and a refusal
/// (`PROVIDER_PERMANENT`) are told apart without a SQL session. Never the provider message: it
/// may carry provider or user text. ADR-0060 D-M: it names the route of the call (provider,
/// model, Profile@version, Binding@version), so with several providers the line says which one.
pub(crate) fn provider_failure_line(
    purpose: ModelCallPurpose,
    route: &ReasoningAdmissionLocator,
    model_call_id: Uuid,
    finalize: &FinalizeCall,
    error: &ReasoningProviderError,
) -> String {
    let latency_ms = finalize
        .latency_ms
        .map_or_else(|| "-".to_owned(), |ms| ms.to_string());
    format!(
        "humaux-reasoning: provider call failed purpose={} tenant={} {} model_call_id={model_call_id} error_class={} latency_ms={latency_ms}",
        purpose.as_db_str(),
        route.tenant_id,
        route.route_fields(),
        error.class()
    )
}

/// ADR-0060 D-C: the class of an instance that is not the one its admitted route names — a seam
/// or cache bug, never a deployment choice.
pub const ROUTE_PROVIDER_MISMATCH: &str = "ROUTE_PROVIDER_MISMATCH";
/// ADR-0060 D-C: the admitted Profile@version does not declare `STRUCTURED_OUTPUT`.
pub const PROFILE_LACKS_STRUCTURED_OUTPUT: &str = "PROFILE_LACKS_STRUCTURED_OUTPUT";

/// ADR-0060 D-C: the instance that will send equals the admitted route on every axis it serves
/// (provider, model, revision, endpoint, capability SET, request extras), and the route's own Profile@version
/// declares structured output. The deployment's deny-only recipient / region lists are not here:
/// they belong to the one production source of instances (D-B), which can refuse a route but
/// never select one (§11.2.5).
pub(crate) fn provider_matches_admission(
    provider: &dyn UserReasoningProvider,
    admission: &ReasoningAdmissionLocator,
) -> Result<(), &'static str> {
    let descriptor = provider.descriptor();
    let declared: std::collections::BTreeSet<&str> =
        descriptor.capabilities.iter().map(|c| c.as_str()).collect();
    let admitted: std::collections::BTreeSet<&str> =
        admission.capabilities.iter().map(|c| c.as_str()).collect();
    if admission.processor_id != descriptor.provider_id
        || admission.provider_model_id != descriptor.model_id
        || provider.model_revision() != admission.model_revision.as_deref()
        || provider.endpoint_ref() != admission.endpoint_ref
        || declared != admitted
        || descriptor.request_extras != admission.request_extras
    {
        return Err(ROUTE_PROVIDER_MISMATCH);
    }
    if !admission
        .capabilities
        .contains(&ReasoningCapability::StructuredOutput)
    {
        return Err(PROFILE_LACKS_STRUCTURED_OUTPUT);
    }
    Ok(())
}

/// Every private-reasoning failure raised in this crate goes through here, so every one of them
/// carries a loggable static class (`PrivateReasoningError::class`) while `Display` stays
/// redacted. Card 16: without the class a permanently not-ready tenant's deferrals were
/// indistinguishable from a provider blip in any log.
pub(crate) fn fail(label: &'static str) -> PrivateReasoningError {
    PrivateReasoningError::classified(label)
}
