//! `humaux-private-worker` — Bounded Phase 9 private contribution worker orchestration.
//! Depends-on: crates=[humaux-adapters, humaux-application, humaux-domain, uuid]; services=[PostgreSQL(role_private_worker)]; env=[]; modules=[adapters::contribution_execution_repo, adapters::contribution_reasoner, adapters::contribution_scan, adapters::jobs, adapters::postgres, adapters::reasoning_route_admission, application::contribute, application::contribution_execution, domain::error]
//! Called-by: [crate(humaux-consolidation-worker), private-worker::inference_rpc, private-worker::route_providers, tests]
//! Invariants: [a routed call's health observation (ruling E3 (b)) is best effort: it is logged with a static class
//!   and never fails or re-settles a job]
//! Spec: ADR-0012; ADR-0016; ADR-0060 E3
//!
//! `pub mod inference_rpc` exists on this lib target (not only inside `src/main.rs`) for the
//! same reason `bins/retrieval-worker/src/lib.rs` exports its own ADR-0012 `rpc` module:
//! `bins/consolidation-worker/tests/consolidation_hop_e2e.rs` spawns the real handler
//! in-process against a temp UDS path rather than reimplementing (and drifting from) it.
//! `pub mod distill` (ADR-0016) is the Evidence → MemoryRecord hop the binary's
//! `--distill-once`/`--distill-serve` modes drive and `tests/distill_hop_e2e.rs` proves.
//! `pub mod route_providers` (ADR-0060 D-B) is the one production source of provider instances,
//! one per admitted Profile@version, shared by both modes.
//!
//! This library wires the bounded contribution application use case and exposes its existing process API.

pub mod distill;
pub mod dsn;
pub mod inference_rpc;
pub mod route_providers;

mod stages;

use humaux_adapters::{
    contribution_execution_repo::ContributionExecutionRepoError,
    contribution_reasoner::{self, ContributionReasoner},
    contribution_scan::ContributionScanner,
    jobs::{self, JobStatus, JobsError},
    postgres::PrivateWorkerDbPool,
    reasoning_route_admission,
};
pub use humaux_application::contribution_execution::{
    ContributionExecutionRunnerConfig, ContributionRunOnceReport,
};
use humaux_application::{
    contribute::ContributionPreparationInput,
    contribution_execution::{
        ContributionClaim, ContributionExecutionFailure, ContributionExecutionUseCase,
        ContributionRouteHealth, EnqueuedContributionExecution, ManualContributionPort,
        start_manual_contribution,
    },
};
use humaux_domain::error::ErrorCode;
use uuid::Uuid;
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

/// Process-owned claim and adapter assembly; the application runs the claimed contribution.
pub struct ContributionExecutionRunner<'a, 'provider> {
    pool: &'a PrivateWorkerDbPool,
    reasoner: &'a ContributionReasoner<'provider>,
    scanner: &'a ContributionScanner,
    config: ContributionExecutionRunnerConfig,
}
impl<'a, 'provider> ContributionExecutionRunner<'a, 'provider> {
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
    /// Claims at most one exact contribution job and runs only the state already persisted by
    /// migration 0131. `private_claim` is the sole claim surface used by this worker.
    pub async fn run_once(
        &self,
        tenant_id: Uuid,
    ) -> Result<ContributionRunOnceReport, ContributionExecutionRunnerError> {
        if tenant_id.is_nil() {
            return Err(ErrorCode::InvalidInput.into());
        }
        let mut claimed = jobs::private_claim(
            self.pool,
            tenant_id,
            &self.config.lease_owner,
            self.config.lease_seconds,
            1,
        )
        .await?;
        let Some(job) = claimed.pop() else {
            return Ok(ContributionRunOnceReport::Idle);
        };
        if !claimed.is_empty() {
            return Err(ContributionExecutionRunnerError::Invariant(
                "bounded claim returned more than one job",
            ));
        }
        let job = ContributionClaim {
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
        };
        let io = contribution_reasoner::contribution_execution_io(
            self.pool,
            self.reasoner,
            self.scanner,
        );
        ContributionExecutionUseCase::new(&io, self, self.config.clone())?
            .run_claimed(tenant_id, job)
            .await
            .map_err(|e| match e {
                ContributionExecutionFailure::Port(e) => {
                    ContributionExecutionRunnerError::Repository(e)
                }
                ContributionExecutionFailure::Domain(e) => {
                    ContributionExecutionRunnerError::Domain(e)
                }
                ContributionExecutionFailure::InvalidClaim(e) => {
                    ContributionExecutionRunnerError::InvalidClaim(e)
                }
                ContributionExecutionFailure::Invariant(e) => {
                    ContributionExecutionRunnerError::Invariant(e)
                }
            })
    }
}
/// Production-core MANUAL contribution command owned by the private-worker process.
///
/// Phase 15 may place an authenticated mTLS transport in front of this command. The command
/// itself accepts only the existing verified ID-free preparation input and a caller idempotency
/// key; it cannot receive rights, policy, source hashes, durable identities, or a fingerprint.
pub struct StartManualContributionCommand<'a> {
    ingress: &'a dyn ManualContributionPort,
}

impl<'a> StartManualContributionCommand<'a> {
    pub const fn new(ingress: &'a dyn ManualContributionPort) -> Self {
        Self { ingress }
    }

    pub async fn execute(
        &self,
        request: ContributionPreparationInput,
        idempotency_key: String,
    ) -> Result<EnqueuedContributionExecution, ErrorCode> {
        start_manual_contribution(self.ingress, request, idempotency_key).await
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
    match reasoning_route_admission::observe_route_health(
        pool,
        tenant_id,
        model_call_id,
        credential_rejected,
        valid_for_seconds,
    )
    .await
    {
        Ok((None, None)) => {}
        Ok((provider, account)) => eprintln!(
            "humaux-private-worker: route health observed tenant={tenant_id} model_call_id={model_call_id} credential_rejected={credential_rejected} provider_observation={} account_observation={}",
            provider.map_or_else(|| "-".to_owned(), |id| id.to_string()),
            account.map_or_else(|| "-".to_owned(), |id| id.to_string()),
        ),
        Err(_) => eprintln!(
            "humaux-private-worker: route health observe failed tenant={tenant_id} model_call_id={model_call_id} class=WORKER_DB_ERROR"
        ),
    }
}

impl ContributionRouteHealth for ContributionExecutionRunner<'_, '_> {
    async fn observe_route_health(&self, tenant: Uuid, call: Uuid, rejected: bool, seconds: i64) {
        observe_route_health(self.pool, tenant, call, rejected, seconds).await;
    }
}
