//! `private-worker::bootstrap` — Adapter construction and direct delegation for consumer ports (ADR-0130 D2).
//! Depends-on: crates=[humaux-adapters, humaux-application, humaux-domain, uuid]; services=[PostgreSQL(role_private_worker)]; env=[]; modules=[adapters::attribution_repo, adapters::byok::ssrf, adapters::consolidation_reasoner, adapters::contribution_execution_repo, adapters::contribution_reasoner, adapters::contribution_scan, adapters::disclosure, adapters::distill_repo, adapters::jobs, adapters::postgres, adapters::reasoning_route_admission, application::consolidate, application::contribution_execution, application::distill_execution, application::private_inference, domain::authority, domain::error, humaux-private-worker, private-worker::route_providers]
//! Called-by: [private-worker::inference_rpc, private-worker::main, private-worker::route_providers, tests]
//! Invariants: [no processing loop or business decisions; health observation is best effort and never changes settlement]
//! Spec: ADR-0130 D2; ADR-0060 E3

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use humaux_adapters::{
    byok::ssrf,
    consolidation_reasoner::{
        ConsolidationCallBinding, ConsolidationReasoner, consolidation_prompt_contract,
    },
    contribution_execution_repo::ContributionExecutionRepoError,
    contribution_reasoner::{self, ContributionReasoner, ContributionReasonerConfig},
    contribution_scan::ContributionScanner,
    disclosure::DeletionCapability,
    jobs::{self, JobStatus, JobsError},
    postgres::PrivateWorkerDbPool,
    reasoning_route_admission::{self, ProviderFor, ReasoningAdmissionLocator},
};
use humaux_application::consolidate::{
    ClaimedReasoningPort, ConsolidationInference, PrivateReasoningError, PrivateReasoningPort,
    PrivateReasoningResult, SealedPrivateReasoningRequest,
};
use humaux_application::contribution_execution::{
    ContributionClaim, ContributionExecutionFailure, ContributionExecutionRunnerConfig,
    ContributionExecutionUseCase, ContributionJobLease, ContributionRouteHealth,
    ContributionRunOnceReport,
};
use humaux_application::distill_execution::DistillDispatchConfig;
use humaux_application::private_inference::PrivateInferenceCallsPort;
use humaux_domain::{authority::AuthorityClass, error::ErrorCode};

use crate::route_providers::{self, EnvCredentialMap, RouteProviders};
use uuid::Uuid;

/// Failure of a bounded contribution run, preserving the claim and execution error classes.
#[derive(Debug)]
pub enum ContributionExecutionRunnerError {
    Jobs(JobsError),
    Repository(ContributionExecutionRepoError),
    Domain(ErrorCode),
    InvalidClaim(&'static str),
    Invariant(&'static str),
}

impl std::fmt::Display for ContributionExecutionRunnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Jobs(error) => write!(f, "contribution claim failed: {error}"),
            Self::Repository(error) => write!(f, "contribution repository failed: {error}"),
            Self::Domain(error) => write!(f, "contribution contract failed: {error}"),
            Self::InvalidClaim(message) => write!(f, "invalid contribution claim: {message}"),
            Self::Invariant(message) => write!(f, "contribution invariant failed: {message}"),
        }
    }
}

impl std::error::Error for ContributionExecutionRunnerError {}

impl From<JobsError> for ContributionExecutionRunnerError {
    fn from(value: JobsError) -> Self {
        Self::Jobs(value)
    }
}

impl From<ContributionExecutionRepoError> for ContributionExecutionRunnerError {
    fn from(value: ContributionExecutionRepoError) -> Self {
        Self::Repository(value)
    }
}

impl From<ErrorCode> for ContributionExecutionRunnerError {
    fn from(value: ErrorCode) -> Self {
        Self::Domain(value)
    }
}

impl From<ContributionExecutionFailure<ContributionExecutionRepoError>>
    for ContributionExecutionRunnerError
{
    fn from(failure: ContributionExecutionFailure<ContributionExecutionRepoError>) -> Self {
        match failure {
            ContributionExecutionFailure::Port(error) => Self::Repository(error),
            ContributionExecutionFailure::Domain(error) => Self::Domain(error),
            ContributionExecutionFailure::InvalidClaim(message) => Self::InvalidClaim(message),
            ContributionExecutionFailure::Invariant(message) => Self::Invariant(message),
        }
    }
}

/// Process-owned claim and adapter assembly; the application runs the claimed contribution.
pub struct ContributionExecutionRunner<'a, 'provider> {
    pool: &'a PrivateWorkerDbPool,
    reasoner: &'a ContributionReasoner<'provider>,
    scanner: &'a ContributionScanner,
    config: ContributionExecutionRunnerConfig,
}
impl<'a, 'provider> ContributionExecutionRunner<'a, 'provider> {
    /// Assemble the worker capabilities for the bounded contribution use case.
    pub fn new(
        pool: &'a PrivateWorkerDbPool,
        reasoner: &'a ContributionReasoner<'provider>,
        scanner: &'a ContributionScanner,
        config: ContributionExecutionRunnerConfig,
    ) -> Result<Self, ErrorCode> {
        config.validate()?;
        Ok(Self {
            pool,
            reasoner,
            scanner,
            config,
        })
    }
    /// Run one exact contribution job through the application use case.
    pub async fn run_once(
        &self,
        tenant_id: Uuid,
    ) -> Result<ContributionRunOnceReport, ContributionExecutionRunnerError> {
        let io = contribution_reasoner::contribution_execution_io(
            self.pool,
            self.reasoner,
            self.scanner,
        );
        ContributionExecutionUseCase::new(&io, self, self.config.clone())?
            .run_once(self, tenant_id)
            .await
    }
}

impl ContributionJobLease for ContributionExecutionRunner<'_, '_> {
    type Error = JobsError;

    async fn claim(
        &self,
        tenant_id: Uuid,
        lease_owner: &str,
        lease_seconds: f64,
        limit: i64,
    ) -> Result<Vec<ContributionClaim>, Self::Error> {
        Ok(
            jobs::private_claim(self.pool, tenant_id, lease_owner, lease_seconds, limit)
                .await?
                .into_iter()
                .map(|job| ContributionClaim {
                    job_id: job.job_id,
                    tenant_id: job.tenant_id,
                    job_type: job.job_type,
                    processing: job.status == JobStatus::Processing,
                    attempt: job.attempt,
                    lease_owner: job.lease_owner,
                    has_lease_expiry: job.lease_expires_at.is_some(),
                    has_stream_key: job.stream_key.is_some(),
                    has_stream_seq: job.stream_seq.is_some(),
                    payload: job.payload,
                })
                .collect(),
        )
    }
}

/// Ruling E3 (b): records the route health one routed call observed through the owner definer —
/// after a SUCCEEDED call a renewal (rate-limited by the definer), after a provider-refused key
/// (`credential_rejected`) one INVALID account row. Best effort: a failure is logged with a static
/// class and changes no settle — the next admission then sees the older observation (§11.2.5:
/// stale health parks, it never admits). The one call shape for distill, the consolidation RPC and the
/// contribution runner.
pub async fn observe_route_health(
    pool: &PrivateWorkerDbPool,
    tenant_id: Uuid,
    model_call_id: Uuid,
    credential_rejected: bool,
    valid_for_seconds: i64,
) {
    // dep: PostgreSQL(role_private_worker) — control.observe_reasoning_route_health (0206/0209, E3)
    let observation = reasoning_route_admission::observe_route_health(
        pool,
        tenant_id,
        model_call_id,
        credential_rejected,
        valid_for_seconds,
    )
    .await;
    crate::log_route_health(tenant_id, model_call_id, credential_rejected, observation);
}

impl ContributionRouteHealth for ContributionExecutionRunner<'_, '_> {
    async fn observe_route_health(&self, tenant: Uuid, call: Uuid, rejected: bool, seconds: i64) {
        observe_route_health(self.pool, tenant, call, rejected, seconds).await;
    }
}

/// Parse startup DNS pins and assemble the resolver shared by provider instances (§11.4).
pub fn dns_resolver(raw: &str) -> Result<(Arc<dyn ssrf::DnsResolver>, bool), String> {
    let pins = ssrf::PinnedDnsResolver::parse(raw)
        .map_err(|e| format!("invalid configuration: HUMAUX_PRIVATE_WORKER_DNS_PINS ({e:?})"))?;
    let dns_pins_configured = !pins.is_empty();
    Ok((Arc::new(pins), dns_pins_configured))
}

/// Assemble and validate the shared private reasoning config (ADR-0015 D2).
pub fn reasoner_config(permit_ttl: Duration) -> Result<ContributionReasonerConfig, String> {
    // Consolidate takes prompt/schema/budget from its own contract. These values must
    // satisfy ContributionReasonerConfig::validate (ADR-0058 D-O).
    let contract = consolidation_prompt_contract(AuthorityClass::ProjectConstraint);
    let config = ContributionReasonerConfig {
        permit_ttl,
        // ponytail: deletion semantics are unknown until a provider promises deletion;
        // move to per-recipient configuration when one is onboarded (ADR-0060 L7).
        deletion_capability: DeletionCapability::Unknown,
        system_prompt: contract.system_prompt,
        json_schema: contract.json_schema,
        max_output_tokens: contract.max_output_tokens,
    };
    config
        .validate()
        .map_err(|code| format!("invalid configuration: {code:?}"))?;
    Ok(config)
}

/// Bind each admitted locator to its provider instance (ADR-0060 D-B).
pub fn admitted_providers(
    credentials: EnvCredentialMap,
    recipients: BTreeMap<Uuid, Vec<String>>,
    regions: BTreeSet<String>,
    resolver: Arc<dyn ssrf::DnsResolver>,
    http_timeout: Duration,
) -> Box<ProviderFor> {
    let routes = Arc::new(RouteProviders::new(
        credentials,
        recipients,
        regions,
        resolver,
        http_timeout,
    ));
    Box::new(move |route: &ReasoningAdmissionLocator| routes.provider_for(route))
}

/// Shared private inference resources for the RPC and Distill modes.
pub struct InferenceRuntime {
    calls: PrivateWorkerDbPool,
    config: ContributionReasonerConfig,
    /// ADR-0060 D-E: resolve the admitted route without any provider identity from the wire.
    pub providers: Box<ProviderFor>,
    health_renew_seconds: i64,
}

impl InferenceRuntime {
    /// Bind the worker's already validated startup resources.
    pub fn new(
        calls: PrivateWorkerDbPool,
        config: ContributionReasonerConfig,
        providers: Box<ProviderFor>,
        health_renew_seconds: i64,
    ) -> Self {
        Self {
            calls,
            config,
            providers,
            health_renew_seconds,
        }
    }

    /// Claim and finish through the application lifecycle port.
    pub(crate) fn calls(&self) -> &impl PrivateInferenceCallsPort {
        &self.calls
    }

    /// Bind the Distill process to its outbound capabilities.
    pub fn distill_runtime<'a>(
        &'a self,
        dispatch: &'a DistillDispatchConfig,
    ) -> Result<
        humaux_adapters::distill_repo::DistillRuntime<
            'a,
            humaux_adapters::attribution_repo::AttributionLadder,
        >,
        ErrorCode,
    > {
        route_providers::distill_runtime(
            &self.calls,
            &*self.providers,
            clone_config(&self.config),
            dispatch,
        )
    }
}

impl ClaimedReasoningPort for InferenceRuntime {
    async fn consolidate(
        &self,
        tenant_id: Uuid,
        consolidation_run_id: Uuid,
        sealed: SealedPrivateReasoningRequest,
    ) -> Result<ConsolidationInference, &'static str> {
        let reasoner = ConsolidationReasoner::new(
            &self.calls,
            self.providers.as_ref(),
            clone_config(&self.config),
            ConsolidationCallBinding {
                tenant_id,
                consolidation_run_id,
            },
        )
        .map_err(|_| "INVALID_CONFIG")?;
        let result = reasoner.infer(sealed).await;
        Ok(ConsolidationInference {
            result,
            observed_call: reasoner.observed_call(),
            route: reasoner.route_fields().map(str::to_owned),
        })
    }

    async fn contribution(
        &self,
        sealed: SealedPrivateReasoningRequest,
    ) -> Result<Result<PrivateReasoningResult, PrivateReasoningError>, &'static str> {
        let reasoner = ContributionReasoner::new_for_execution(
            &self.calls,
            self.providers.as_ref(),
            clone_config(&self.config),
        )
        .map_err(|_| "INVALID_CONFIG")?;
        Ok(reasoner.infer(sealed).await)
    }

    async fn observe_health(
        &self,
        tenant_id: Uuid,
        model_call_id: Uuid,
        credential_rejected: bool,
    ) {
        observe_route_health(
            &self.calls,
            tenant_id,
            model_call_id,
            credential_rejected,
            self.health_renew_seconds,
        )
        .await;
    }
}

// The configuration is fixed for the process lifetime (ADR-0016).
fn clone_config(config: &ContributionReasonerConfig) -> ContributionReasonerConfig {
    ContributionReasonerConfig {
        permit_ttl: config.permit_ttl,
        deletion_capability: match config.deletion_capability {
            DeletionCapability::Supported => DeletionCapability::Supported,
            DeletionCapability::Unsupported => DeletionCapability::Unsupported,
            DeletionCapability::Unknown => DeletionCapability::Unknown,
        },
        system_prompt: config.system_prompt.clone(),
        json_schema: config.json_schema.clone(),
        max_output_tokens: config.max_output_tokens,
    }
}
