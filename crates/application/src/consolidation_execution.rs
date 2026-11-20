//! `application::consolidation_execution` — Run and dispatch consolidation (§11.7–§11.9, ADR-0036).
//! Depends-on: crates=[async-trait, humaux-domain, serde_json, uuid]; services=[]; env=[]; modules=[application::consolidate, domain::authority, domain::consolidate, domain::error]
//! Called-by: [adapters::consolidate_repo, adapters::jobs, consolidation-worker::bootstrap, tests]
//! Invariants: [bind inference after recording the run; commit a published rollup and job DONE under one lease fence]
//! Spec: §11.7; §11.8; §11.9; ADR-0036; ADR-0130

use crate::consolidate::{
    ContentSha256, NextStep, PrivateReasoningDomainId, PrivateReasoningError, PrivateReasoningPort,
    PrivateReasoningPurpose, PrivateReasoningResult, ReasoningRouteBindingId,
    ReasoningRouteBindingVersion, SealedPrivateReasoningRequest, next_step,
};
use humaux_domain::authority::{AuthorityClass, EvidenceId};
use humaux_domain::consolidate::AutoMutableMemoryId;
use humaux_domain::error::ErrorCode;
use serde_json::Value;
use uuid::Uuid;

/// One row materialization actually wrote to
/// `private.memory_consolidation_inputs` — the tuple §11.8's `input_manifest_hash` must be
/// computed over (memory_id, input_version, source_hash, ordinal), so the caller never has to
/// re-derive it from a bare id list.
#[derive(Debug, Clone)]
pub struct MaterializedInput {
    /// The auto-mutable memory selected by this run.
    pub memory_id: AutoMutableMemoryId,
    /// The version observed in the input snapshot.
    pub input_version: i64,
    /// Input fingerprint recorded in the manifest.
    pub source_hash: Vec<u8>,
    /// Position in the recorded manifest.
    pub ordinal: i32,
    /// §11.6 source closure: the input memory's own in-domain Evidence (PRIMARY preferred),
    /// resolved in the same snapshot SELECT so `publish_rollup`'s `(memory_id, evidence_id)`
    /// pairs come from the materialized inputs, not a second read.
    pub evidence_id: EvidenceId,
}

/// Outcome of [`ConsolidationStore::publish_rollup`] — the three terminal `ConsolidationRunState`s it can reach
/// (`SUCCEEDED` / `SUCCEEDED_NO_OUTPUT` / `STALE_INPUT`; `FAILED` is the caller's to set on an
/// inference error, before ever calling this function), plus `LostLease`, which reaches NO
/// terminal state because the whole transaction rolled back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    /// A rollup and its source closure committed.
    Published {
        /// The committed rollup identifier.
        rollup_id: Uuid,
    },
    /// The run had no eligible source output.
    NoOutput,
    /// The input snapshot changed before publication.
    StaleInput,
    /// The caller passed a lease fence and the job it names was already
    /// re-claimed by another worker (its `attempt` moved). NOTHING was written: the rollup, its
    /// closure rows, the ticket and the run's terminal status all rolled back with the fence
    /// check, so the worker that now holds the job publishes the one and only rollup.
    LostLease,
}

/// The consolidation snapshot, run state and atomic rollup publication (§11.7–§11.9).
#[async_trait::async_trait]
pub trait ConsolidationStore: Sync {
    /// Adapter failure with its original operator-facing description.
    type Error: std::fmt::Debug + std::fmt::Display;
    /// Opaque fencing proof carried from job discovery to publication.
    type Lease<'a>: Sync;

    /// Start a durable run before binding its inference client.
    async fn create_run(
        &self,
        tenant_id: Uuid,
        domain_id: Uuid,
        workspace_id: Option<Uuid>,
    ) -> Result<Uuid, Self::Error>;

    /// Record the selected inputs in the same snapshot that read them.
    async fn select_inputs(
        &self,
        run_id: Uuid,
        tenant_id: Uuid,
        domain_id: Uuid,
        workspace_id: Option<Uuid>,
        max_inputs: i64,
    ) -> Result<Vec<MaterializedInput>, Self::Error>;

    /// Turn a serialization conflict into a recorded stale run, or propagate the error.
    async fn recover_input_error(
        &self,
        tenant_id: Uuid,
        run_id: Uuid,
        error: Self::Error,
    ) -> Result<PublishOutcome, Self::Error>;

    /// Commit the rollup, sources, ticket, run status and fenced DONE together.
    #[allow(clippy::too_many_arguments)]
    async fn publish_rollup(
        &self,
        run_id: Uuid,
        tenant_id: Uuid,
        workspace_id: Option<Uuid>,
        content: Value,
        rollup_class: AuthorityClass,
        manifest_hash: Option<&[u8]>,
        sources: &[(AutoMutableMemoryId, EvidenceId)],
        fence: Option<&Self::Lease<'_>>,
    ) -> Result<PublishOutcome, Self::Error>;

    /// Look up the admitted binding for this tenant and private reasoning domain.
    async fn resolve_binding(
        &self,
        tenant_id: Uuid,
        domain_id: Uuid,
    ) -> Result<Option<(ReasoningRouteBindingId, ReasoningRouteBindingVersion)>, Self::Error>;

    /// Preserve the terminal class of a storage failure for dispatch metrics.
    fn error_class(error: &Self::Error) -> ErrorCode;
}

/// The §11.8 manifest and reply contract shared by both ends of the private inference hop.
pub trait RollupWire {
    /// Hash the exact recorded manifest before sealing the inference request.
    fn manifest_hash(&self, inputs: &[MaterializedInput]) -> ContentSha256;

    /// Decode the private reply against the source pairs selected for this run.
    fn decode_rollup(
        &self,
        inputs: &[MaterializedInput],
        result: &PrivateReasoningResult,
    ) -> Result<RollupParts, PrivateReasoningError>;
}

/// The consolidation fields of a claimed job, with the exact fence from that claim.
pub struct ConsolidationClaim<L> {
    /// Stable job identity, used in dispatch logs.
    pub job_id: Uuid,
    /// The tenant used for all subsequent private operations.
    pub tenant_id: Uuid,
    /// The claim attempt used for retry or park decisions.
    pub attempt: i32,
    /// The trigger payload with the reasoning domain.
    pub payload: Value,
    /// The lease used for heartbeat, publication and settlement.
    pub lease: L,
}

/// Settlement intent for a claimed consolidation job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobOutcome {
    /// Complete the no-output job.
    Done,
    /// Release the job with backoff.
    Retry,
    /// Park an exhausted job.
    Dead,
}

/// Cross-tenant discovery and tenant-scoped lease transitions (ADR-0036).
#[async_trait::async_trait]
pub trait ConsolidationJobPort: ConsolidationStore {
    /// Claim only derived consolidation jobs.
    async fn claim<'a>(
        &self,
        config: &'a DispatchConfig,
    ) -> Result<Vec<ConsolidationClaim<Self::Lease<'a>>>, Box<dyn std::error::Error + Send + Sync>>;

    /// Refresh the exact lease before starting the inference hop.
    async fn heartbeat(
        &self,
        lease: &Self::Lease<'_>,
        seconds: f64,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;

    /// Settle work that did not publish a fenced rollup.
    async fn settle(
        &self,
        lease: &Self::Lease<'_>,
        outcome: JobOutcome,
        seconds: f64,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;
}

/// The decoded rollup content, its class and its input-bound sources.
pub type RollupParts = (
    serde_json::Value,
    AuthorityClass,
    Vec<(AutoMutableMemoryId, EvidenceId)>,
);

/// `&dyn PrivateReasoningPort` viewed as an owned port, so [`run_once`] can reuse
/// [`run_once_bound`] for callers that have no per-run state to bind.
struct BorrowedPort<'a>(&'a dyn PrivateReasoningPort);

#[async_trait::async_trait]
impl PrivateReasoningPort for BorrowedPort<'_> {
    async fn infer(
        &self,
        req: SealedPrivateReasoningRequest,
    ) -> Result<PrivateReasoningResult, PrivateReasoningError> {
        self.0.infer(req).await
    }
}

/// [`run_once_bound`] for a port that carries no per-run state; the closure receives the
/// materialized ids only.
/// No `ops.jobs` fence: callers with no claimed job (the hop tests) settle nothing.
#[allow(clippy::too_many_arguments)]
pub async fn run_once<S: ConsolidationStore + RollupWire>(
    store: &S,
    port: &dyn PrivateReasoningPort,
    tenant_id: Uuid,
    reasoning_domain_id: Uuid,
    binding_id: ReasoningRouteBindingId,
    binding_version: ReasoningRouteBindingVersion,
    workspace_id: Option<Uuid>,
    max_inputs: i64,
    build_rollup: impl FnOnce(
        &[AutoMutableMemoryId],
        &PrivateReasoningResult,
    ) -> Result<RollupParts, PrivateReasoningError>,
) -> Result<PublishOutcome, RunOnceError<S::Error>> {
    run_once_bound(
        store,
        |_run_id| BorrowedPort(port),
        tenant_id,
        reasoning_domain_id,
        binding_id,
        binding_version,
        workspace_id,
        max_inputs,
        |inputs, result| {
            let ids: Vec<AutoMutableMemoryId> = inputs.iter().map(|m| m.memory_id).collect();
            build_rollup(&ids, result)
        },
        None,
    )
    .await
}

/// One consolidation run, start to finish: snapshot-bound selection (§11.7), then either skip
/// straight to `SUCCEEDED_NO_OUTPUT` (§11.7, empty input set) or call the sealed inference
/// port and publish. `bind_port` builds the port AFTER `create_run` so the port can carry the
/// run id (ADR-0015: `UdsInferenceClient` registers `consolidation_run_id` alongside the sealed
/// identifiers, since the sealed request itself — §11.8 — carries no run id); see module doc
/// for why the use case receives only the sealed inference port.
///
/// `binding_id` plus `binding_version` is the caller's exact immutable Phase 9 R3 authority.
/// This BYOK-capability-free worker only seals and forwards that pair; the private worker must
/// resolve and admit it immediately before private materialization or provider dispatch.
///
/// `build_rollup` receives the sealed result and this run's materialized inputs. The
/// `AutoMutableMemoryId` sources stay typestate-bound through the publish port (§11.8).
#[allow(clippy::too_many_arguments)]
pub async fn run_once_bound<P: PrivateReasoningPort, S: ConsolidationStore + RollupWire>(
    store: &S,
    bind_port: impl FnOnce(Uuid) -> P,
    tenant_id: Uuid,
    reasoning_domain_id: Uuid,
    binding_id: ReasoningRouteBindingId,
    binding_version: ReasoningRouteBindingVersion,
    workspace_id: Option<Uuid>,
    max_inputs: i64,
    build_rollup: impl FnOnce(
        &[MaterializedInput],
        &PrivateReasoningResult,
    ) -> Result<RollupParts, PrivateReasoningError>,
    fence: Option<&S::Lease<'_>>,
) -> Result<PublishOutcome, RunOnceError<S::Error>> {
    let run_id = store
        .create_run(tenant_id, reasoning_domain_id, workspace_id)
        .await
        .map_err(RunOnceError::Repo)?;
    let port = bind_port(run_id);

    let inputs = match store
        .select_inputs(
            run_id,
            tenant_id,
            reasoning_domain_id,
            workspace_id,
            max_inputs,
        )
        .await
    {
        Ok(inputs) => inputs,
        Err(error) => {
            return store
                .recover_input_error(tenant_id, run_id, error)
                .await
                .map_err(RunOnceError::Repo);
        }
    };
    let auto_ids: Vec<AutoMutableMemoryId> = inputs.iter().map(|m| m.memory_id).collect();

    match next_step(auto_ids.len()) {
        NextStep::SkipToNoOutput => {
            // §11.5.1: don't spend a BYOK inference call on a guaranteed-empty result.
            // `rollup_class` is unused on this branch (`publish_rollup` short-circuits on an
            // empty `sources` slice before its §11.9 ceiling check ever runs) — `PublicKnowledge`
            // is the lowest-ranked class, chosen only so the placeholder can never look like a
            // real classification decision if this branch's plumbing ever changes.
            store
                .publish_rollup(
                    run_id,
                    tenant_id,
                    workspace_id,
                    serde_json::Value::Null,
                    AuthorityClass::PublicKnowledge,
                    None,
                    &[],
                    fence,
                )
                .await
                .map_err(RunOnceError::Repo)
        }
        NextStep::RunInference => {
            // Reaching `port.infer` at all is the G11-R1 positive sentinel's real call site;
            // the fake-port version of that same call lives in
            // `humaux_application::consolidate`'s own unit tests (no network stack needed to
            // prove the trait boundary is usable), and `tests/run_once_e2e.rs` in this crate
            // drives this exact call site end to end against a real `ConsolidationDbPool`.
            let manifest_hash = store.manifest_hash(&inputs);
            let req = SealedPrivateReasoningRequest {
                reasoning_domain_id: PrivateReasoningDomainId(reasoning_domain_id),
                binding_id,
                binding_version,
                input_manifest_hash: manifest_hash,
                purpose: PrivateReasoningPurpose::Consolidate,
                contribution_attempt: None,
            };
            let inference = port.infer(req).await?;
            let (content, rollup_class, sources) = build_rollup(&inputs, &inference)?;
            store
                .publish_rollup(
                    run_id,
                    tenant_id,
                    workspace_id,
                    content,
                    rollup_class,
                    Some(&manifest_hash.0),
                    &sources,
                    fence,
                )
                .await
                .map_err(RunOnceError::Repo)
        }
    }
}

/// Deployment-owned inputs for one cross-tenant dispatch pass (ADR-0036, card 14). No tenant id
/// and no route-binding id: both come from the claimed job / the per-tenant resolver, which is
/// exactly what makes one process able to serve N tenants.
#[derive(Debug, Clone)]
pub struct DispatchConfig {
    /// Per-process lease owner; every terminal transition is fenced on it plus the claim's
    /// `attempt`, so two resident workers never both settle one job.
    pub lease_owner: String,
    /// Duration used for the claim, heartbeat and retry backoff.
    pub lease_seconds: f64,
    /// Max jobs one pass claims.
    pub batch: i64,
    /// §11.7 selection cap handed to `select_and_materialize_inputs`.
    pub max_inputs: i64,
    /// At or past this many attempts a repeatedly-failing job is parked `DEAD` instead of being
    /// released for another pass — otherwise a poison tenant burns every pass forever.
    pub max_attempts: i32,
}

impl DispatchConfig {
    /// Reject invalid deployment inputs before claiming any work.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.lease_owner.trim().is_empty() {
            return Err("lease_owner");
        }
        if !self.lease_seconds.is_finite() || self.lease_seconds <= 0.0 {
            return Err("lease_seconds");
        }
        if self.batch <= 0 {
            return Err("batch");
        }
        if self.max_inputs <= 0 {
            return Err("max_inputs");
        }
        if self.max_attempts <= 0 {
            return Err("max_attempts");
        }
        Ok(())
    }
}

/// What one [`dispatch_pass`] did. `claimed == 0` is the "no input" signal `--run-once` exits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DispatchReport {
    /// §39: original terminal class of the latest failed job in this pass.
    pub last_error: Option<ErrorCode>,
    /// Jobs discovered by this pass.
    pub claimed: u32,
    /// Rollups committed with their job fence.
    pub published: u32,
    /// Runs completed without a rollup.
    pub no_output: u32,
    /// Runs whose recorded input changed before publication.
    pub stale_input: u32,
    /// Jobs released back to PENDING after an environmental failure (no route binding yet,
    /// provider blip, DB blip). Released with a backoff (`adapters::jobs::retry_backoff_seconds`),
    /// not instantly re-claimable.
    pub deferred: u32,
    /// Jobs released because this tenant is NOT READY yet — its `PRIVATE_CONSOLIDATE` route
    /// binding has not been admitted. Counted apart from [`Self::deferred`] because it never
    /// spends the retry budget: a tenant onboarded before its binding is admitted must not lose
    /// its consolidation work to `DEAD` (ADR-0036 D5).
    pub not_ready: u32,
    /// Jobs parked DEAD after exhausting `max_attempts`.
    pub dead: u32,
    /// Jobs whose lease was already reclaimed by the time this worker tried to settle them —
    /// nothing of theirs was committed by this process.
    pub lost_lease: u32,
}

/// The `reasoning_domain_id` `migrations/0164_derived_work_dispatch.sql`'s
/// `derived_consolidate_work_enqueue` trigger writes into the job payload. A payload this worker
/// cannot read is a permanent defect of that row, not a transient one — it is parked, never
/// retried forever.
fn payload_reasoning_domain(payload: &serde_json::Value) -> Option<Uuid> {
    payload
        .get("reasoning_domain_id")?
        .as_str()?
        .parse::<Uuid>()
        .ok()
}

/// One cross-tenant dispatch pass (ADR-0036): claim up to `config.batch` `DERIVED_CONSOLIDATE`
/// jobs through the owner SECURITY DEFINER `ops.claim_derived_work`, then run each one's
/// consolidation under ITS OWN tenant's RLS context — `run_once_bound` and every repo it calls
/// install `humaux.tenant_id` from the claimed job, so a pass for tenant A can read nothing of
/// tenant B's even though the claim that found it was cross-tenant.
///
/// `bind_port` receives `(tenant_id, run_id)`: the inference client is sealed per tenant AND per
/// run (ADR-0015), so it cannot be built once for the process the way a single-tenant worker's
/// could.
pub async fn dispatch_pass<P: PrivateReasoningPort, S: ConsolidationJobPort + RollupWire>(
    store: &S,
    bind_port: impl Fn(Uuid, Uuid) -> P,
    config: &DispatchConfig,
) -> Result<DispatchReport, DispatchError> {
    config.validate().map_err(DispatchError::Config)?;
    let claimed = store.claim(config).await?;
    let mut report = DispatchReport {
        claimed: claimed.len() as u32,
        ..DispatchReport::default()
    };
    for job in claimed {
        // Refresh before the (potentially long) inference hop rather than after it — a heartbeat
        // taken once the work is already done proves nothing about the lease that protected it.
        if let Some(code) = lease_class(store.heartbeat(&job.lease, config.lease_seconds).await) {
            report.lost_lease += 1;
            report.last_error.get_or_insert(code);
            continue;
        }
        let outcome = run_claimed_job(store, &bind_port, config, &job).await;
        let settle = match &outcome {
            // Already settled DONE inside `publish_rollup`'s own transaction (the fence): the
            // rollup and the terminal transition committed together, so there is no second
            // settle to do and no window between them for the lease to lapse in.
            Ok(PublishOutcome::Published { .. }) => {
                report.published += 1;
                continue;
            }
            // The fence found the job re-claimed: this worker's transaction rolled back and
            // wrote NOTHING. The worker that now holds the job publishes the one rollup.
            Ok(PublishOutcome::LostLease) => {
                report.lost_lease += 1;
                report.last_error.get_or_insert(ErrorCode::Conflict);
                continue;
            }
            Ok(PublishOutcome::NoOutput) => {
                report.no_output += 1;
                JobOutcome::Done
            }
            // §11.7: a stale run publishes nothing and the next run redoes it — that is a
            // release, not a completion.
            Ok(PublishOutcome::StaleInput) => {
                report.stale_input += 1;
                retry_or_park(job.attempt >= config.max_attempts, &mut report, None)
            }
            // Not a failure of this job — the tenant is not provisioned yet. Release it with a
            // backoff and DO NOT spend an attempt: parking it `DEAD` would drop that memory's
            // consolidation permanently (the 0164 enqueue trigger's idempotency key is per
            // memory_id with ON CONFLICT DO NOTHING, so the job is never re-emitted).
            Err(RunOnceError::NotReady(reason)) => {
                eprintln!(
                    "humaux-consolidation-worker: job {} (tenant {}) not ready: {reason}",
                    job.job_id, job.tenant_id
                );
                report
                    .last_error
                    .get_or_insert(ErrorCode::DependencyUnavailable);
                report.not_ready += 1;
                JobOutcome::Retry
            }
            Err(error) => {
                let class = Some(match error {
                    RunOnceError::Repo(error) => S::error_class(error),
                    RunOnceError::NotReady(_) => ErrorCode::DependencyUnavailable,
                    RunOnceError::Reasoning(error) => reasoning_class(error),
                });
                // The pass keeps going: one tenant's environmental failure must not stop the
                // other tenants this cross-tenant pass claimed.
                //
                // Card 21 (card 16's lesson, applied to the second worker): `RunOnceError`'s
                // `Display` delegates to `PrivateReasoningError`'s, which is redacted by
                // construction — "PrivateReasoningPort error (redacted, fingerprint=abcd1234)".
                // For the whole Reasoning arm that was the end of the road for the only
                // information an operator needs (*why* a tenant never consolidates: e.g.
                // `configured provider does not match admitted route`). The distill side already
                // logs `PrivateReasoningError::class()`, the static, payload-free label the raise
                // site supplied; so does this one now. Non-reasoning arms keep their own Display,
                // which is not redacted.
                eprintln!(
                    "humaux-consolidation-worker: job {} (tenant {}) failed: {}",
                    job.job_id,
                    job.tenant_id,
                    error_class_for_log(error)
                );
                retry_or_park(job.attempt >= config.max_attempts, &mut report, class)
            }
        };
        if let Some(code) =
            lease_class(store.settle(&job.lease, settle, config.lease_seconds).await)
        {
            report.lost_lease += 1;
            report.last_error.get_or_insert(code);
        }
    }
    Ok(report)
}

fn lease_class(
    result: Result<bool, Box<dyn std::error::Error + Send + Sync>>,
) -> Option<ErrorCode> {
    match result {
        Ok(true) => None,
        Ok(false) => Some(ErrorCode::Conflict),
        Err(_) => Some(ErrorCode::DependencyUnavailable),
    }
}
/// Loggable description of a failed pass (card 21). The `Reasoning` arm carries a redacted
/// `Display`, so its static [`PrivateReasoningError::class`] is what goes to the log; every other
/// arm's `Display` already says something. `unclassified private reasoning failure` is the honest
/// answer when the raise site used `PrivateReasoningError::new` rather than `::classified` — it
/// says "no class", which is not the same as saying nothing.
fn reasoning_class(error: &PrivateReasoningError) -> ErrorCode {
    ErrorCode::ALL
        .into_iter()
        .find(|code| Some(code.as_str()) == error.class())
        .unwrap_or(ErrorCode::Internal)
}

fn error_class_for_log(error: &RunOnceError<impl std::fmt::Display>) -> String {
    match error {
        RunOnceError::Reasoning(e) => e
            .class()
            .unwrap_or("unclassified private reasoning failure")
            .to_owned(),
        other => other.to_string(),
    }
}

fn retry_or_park(
    exhausted: bool,
    report: &mut DispatchReport,
    class: Option<ErrorCode>,
) -> JobOutcome {
    if let Some(code) = class.or(exhausted.then_some(ErrorCode::Internal)) {
        report.last_error.get_or_insert(code);
    }
    if exhausted {
        report.dead += 1;
        JobOutcome::Dead
    } else {
        report.deferred += 1;
        JobOutcome::Retry
    }
}

async fn run_claimed_job<P: PrivateReasoningPort, S: ConsolidationJobPort + RollupWire>(
    store: &S,
    bind_port: &impl Fn(Uuid, Uuid) -> P,
    config: &DispatchConfig,
    job: &ConsolidationClaim<S::Lease<'_>>,
) -> Result<PublishOutcome, RunOnceError<S::Error>> {
    let Some(reasoning_domain_id) = payload_reasoning_domain(&job.payload) else {
        return Err(RunOnceError::Reasoning(PrivateReasoningError::new(
            "DERIVED_CONSOLIDATE payload carries no reasoning_domain_id",
        )));
    };
    // `consolidate_repo::resolve_consolidate_binding` calls this condition "environmental
    // (retryable)" itself: the tenant simply has no admitted route yet. It is NOT a defect of
    // this job, so it gets its own error class and never reaches `retry_or_park`.
    let (binding_id, binding_version) = store
        .resolve_binding(job.tenant_id, reasoning_domain_id)
        .await
        .map_err(RunOnceError::Repo)?
        .ok_or(RunOnceError::NotReady(
            "no admitted PRIVATE_CONSOLIDATE route binding for this tenant/domain",
        ))?;
    let tenant_id = job.tenant_id;
    run_once_bound(
        store,
        |run_id| bind_port(tenant_id, run_id),
        tenant_id,
        reasoning_domain_id,
        binding_id,
        binding_version,
        // Tenant-scope rollups. A workspace-scoped pass needs the workspace in the job payload,
        // which needs an enqueue site that knows one — not something this card's triggers see.
        None,
        config.max_inputs,
        |inputs, result| store.decode_rollup(inputs, result),
        Some(&job.lease),
    )
    .await
}

/// A dispatch pass could not claim work.
#[derive(Debug)]
pub enum DispatchError {
    /// Rejected deployment setting.
    Config(&'static str),
    /// The job adapter could not claim work.
    Jobs(Box<dyn std::error::Error + Send + Sync>),
}

impl From<Box<dyn std::error::Error + Send + Sync>> for DispatchError {
    fn from(e: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self::Jobs(e)
    }
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(field) => write!(f, "invalid dispatch configuration: {field}"),
            Self::Jobs(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DispatchError {}

/// A single consolidation run could not finish.
#[derive(Debug)]
pub enum RunOnceError<E> {
    /// Storage failed before or during publication.
    Repo(E),
    /// The private inference hop or its reply failed.
    Reasoning(PrivateReasoningError),
    /// The tenant is not provisioned for this hop yet (no admitted route binding). Retryable
    /// forever with a backoff — never parked `DEAD`, see [`dispatch_pass`].
    NotReady(&'static str),
}

impl<E> From<PrivateReasoningError> for RunOnceError<E> {
    fn from(e: PrivateReasoningError) -> Self {
        Self::Reasoning(e)
    }
}

impl<E: std::fmt::Display> std::fmt::Display for RunOnceError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Repo(e) => write!(f, "{e}"),
            Self::Reasoning(e) => write!(f, "{e}"),
            Self::NotReady(reason) => write!(f, "{reason}"),
        }
    }
}

#[cfg(test)]
mod error_log_tests {
    use super::{RunOnceError, error_class_for_log};
    use crate::consolidate::PrivateReasoningError;

    #[test]
    fn pass_outcome_release_or_park() {
        use super::{DispatchReport, JobOutcome as Outcome, retry_or_park};
        use humaux_domain::error::ErrorCode;
        let mut r = DispatchReport::default();
        assert_eq!(retry_or_park(false, &mut r, None), Outcome::Retry);
        assert_eq!(
            (r.last_error, r.published, r.dead, r.deferred),
            (None, 0, 0, 1)
        );
        assert_eq!(retry_or_park(true, &mut r, None), Outcome::Dead);
        assert_eq!((r.last_error, r.dead), (Some(ErrorCode::Internal), 1));
    }
    #[test]
    fn reasoning_classes_are_never_guessed() {
        use humaux_domain::error::ErrorCode;
        for code in ErrorCode::ALL {
            assert_eq!(
                super::reasoning_class(&PrivateReasoningError::classified(code.as_str())),
                code
            );
        }
        assert_eq!(
            super::reasoning_class(&PrivateReasoningError::new("unknown")),
            ErrorCode::Internal
        );
    }

    /// Card 21 (folded card-16 debt). The `Reasoning` arm's `Display` is redacted by
    /// construction, so logging `{error}` threw away the only thing an operator can act on.
    /// Fault injection: revert `error_class_for_log` to `error.to_string()` and this goes red
    /// on the first assertion — the log would say `fingerprint=…` instead of the class.
    #[test]
    fn a_reasoning_failure_logs_its_class_not_its_redacted_display() {
        const CLASS: &str = "configured provider does not match admitted route";
        let classified =
            RunOnceError::<String>::Reasoning(PrivateReasoningError::classified(CLASS));
        assert_eq!(error_class_for_log(&classified), CLASS);
        // The thing it used to print, for contrast.
        assert!(classified.to_string().contains("redacted"));
        assert!(!error_class_for_log(&classified).contains("redacted"));
    }

    /// An unclassified reasoning failure says so out loud rather than falling back to the
    /// redacted fingerprint — "no class" is information; a fingerprint is not.
    #[test]
    fn an_unclassified_reasoning_failure_says_so() {
        let plain = RunOnceError::<String>::Reasoning(PrivateReasoningError::new("boom"));
        assert_eq!(
            error_class_for_log(&plain),
            "unclassified private reasoning failure"
        );
    }

    /// Non-reasoning arms keep their own (unredacted) `Display`.
    #[test]
    fn other_arms_keep_their_display() {
        let not_ready = RunOnceError::<String>::NotReady("no admitted route binding");
        assert_eq!(error_class_for_log(&not_ready), "no admitted route binding");
    }
}
