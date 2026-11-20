//! `application::distill_execution` — Claimed-job Distill use case (§16.1.1; ADR-0058; ADR-0130 D2/D7a).
//! Depends-on: crates=[async-trait, humaux-domain, rand, serde_json, time, uuid]; services=[]; env=[]; modules=[application::consolidate, domain::affect, domain::authority, domain::error, domain::memory]
//! Called-by: [adapters::derived_job_lease, adapters::distill_reasoner, adapters::distill_repo, adapters::jobs, private-worker::bootstrap, private-worker::distill, private-worker::main, private-worker::route_providers, tests]
//! Invariants: [provider attempts are admitted before sending; result persistence owns one fenced transaction]
//! Spec: §16.1.1; ADR-0058; ADR-0130
use crate::consolidate::PrivateReasoningError;
use async_trait::async_trait;
use humaux_domain::{
    affect::AffectAnnotation,
    authority::{AuthorityClass, CandidateRejection},
    error::ErrorCode,
    memory::MemoryType,
};
use serde_json::Value;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use uuid::Uuid;
/// Generation-fenced claimed job coordinates (ADR-0058).
#[derive(Debug, Clone)]
pub struct DistillClaim {
    /// The claimed job.
    pub job_id: Uuid,
    /// Its tenant; every later read/write installs this tenant (§62).
    pub tenant_id: Uuid,
    /// ADR-0058 D-E fencing token of this claim.
    pub claim_generation: i32,
    /// Provider requests admitted so far (counted at `begin_call`, never at claim).
    pub attempt: i32,
    /// Claims that expired before any request was admitted (D-F pre-dispatch cap).
    pub abandoned_claims: i32,
    /// The 0164 enqueue payload (`reasoning_domain_id`, `evidence_id`).
    pub payload: serde_json::Value,
    /// Lease end as claimed.
    pub lease_expires_at: OffsetDateTime,
    /// End of this claim: the lease never passes it.
    pub hard_deadline: OffsetDateTime,
    /// Class of the previous settle, if any.
    pub last_error_class: Option<String>,
    /// Since when the job has been not ready (D-H park age), if it is.
    pub not_ready_since: Option<OffsetDateTime>,
    /// The ledger row of the claim's last admitted request — after a T6 re-queue, the call whose
    /// outcome stayed unknown.
    pub dispatch_model_call_id: Option<Uuid>,
}

/// The exact claim generation and owner, with no database capability.
#[derive(Debug, Clone, Copy)]
pub struct DistillLease<'a> {
    /// The claimed job.
    pub job_id: Uuid,
    /// Its tenant.
    pub tenant_id: Uuid,
    /// This process's `lease_owner`.
    pub lease_owner: &'a str,
    /// The generation the claim returned; a superseded one renews, dispatches and settles nothing.
    pub claim_generation: i32,
}

impl<'a> DistillLease<'a> {
    /// The lease exactly as the job adapter handed it back.
    pub fn of(claim: &DistillClaim, lease_owner: &'a str) -> Self {
        Self {
            job_id: claim.job_id,
            tenant_id: claim.tenant_id,
            lease_owner,
            claim_generation: claim.claim_generation,
        }
    }
}

/// Deployment-owned tenant call allowance (§72.3).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DistillCallBudget {
    /// Length of the sliding window, seconds (> 0).
    pub window_seconds: f64,
    /// Admitted requests of one tenant allowed inside the window (>= 1).
    pub max_calls: i32,
}

/// Attempt admission before the provider request can leave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallAdmission {
    /// The request may leave; the job's attempt count after counting it.
    Admitted(i32),
    /// The claim's fence refused it (owner, generation, lease, slot or deadline): no request.
    Refused,
    /// The tenant's §72.3 budget is spent for now: no request, nothing counted, no row written.
    OverBudget,
}

/// Parsed but unauthorized candidate; §10.1 is checked inside the write transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct DistillCandidate {
    /// Proposed memory text.
    pub content: String,
    /// Proposed closed memory kind.
    pub memory_type: MemoryType,
    /// Requested authority, checked against the Evidence ceiling.
    pub class: AuthorityClass,
    /// Parser-validated confidence.
    pub confidence: f32,
    /// ADR-0058 D-P: inferred `EMOTION`s of the authoring user (only when the menu was offered),
    /// already inside the inferred ceiling; written as `origin = 'DISTILL'` rows.
    pub affects: Vec<AffectAnnotation>,
}

/// Validated memories and the parser affect-drop signal.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DistillReply {
    /// The memory candidates, in reply order.
    pub memories: Vec<DistillCandidate>,
    /// ADR-0058 R1: some `affects` entry was outside the inferred menu, so every inferred affect
    /// of this reply was discarded; the memories stand.
    pub affects_dropped: bool,
}

/// Finalized provider output and its disclosure receipt.
#[derive(Clone, PartialEq, Eq)]
pub struct DistillInferenceResult {
    /// Provider response bytes, redacted by Debug.
    pub output_bytes: Vec<u8>,
    /// Finalized disclosure receipt.
    pub disclosure_id: Uuid,
    /// ADR-0058 R9: the tool-channel reply carried no tool call and these bytes are its `content`
    /// object (`StructuredReasoningResponse::channel_fallback`); the parser judges them the same.
    pub channel_fallback: bool,
}

impl std::fmt::Debug for DistillInferenceResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DistillInferenceResult")
            .field(
                "output_bytes",
                &format_args!("[REDACTED; {} bytes]", self.output_bytes.len()),
            )
            .field("disclosure_id", &self.disclosure_id)
            .field("channel_fallback", &self.channel_fallback)
            .finish()
    }
}

/// Deployment-owned inputs of the cross-tenant dispatcher (ADR-0036 / ADR-0058 D-K). No tenant
/// id and no reasoning domain: both come from each claimed `DERIVED_DISTILL` job. Every value is
/// a required `HUMAUX_PRIVATE_WORKER_*` key (§78.1: no code default).
#[derive(Debug, Clone)]
pub struct DistillDispatchConfig {
    /// Per-process lease owner of every claim and of the outbox row the job takes.
    pub lease_owner: String,
    /// Job lease; the heartbeat renews it every third of it.
    pub lease_seconds: f64,
    /// Seats of this process (ADR-0058 D-J), `1..=`[`PROVIDER_SLOTS`]. The four slot rows are the
    /// global bound; this is the in-process second line.
    pub in_flight: u32,
    /// End of one claim; the lease never passes it and only it frees a dispatched slot (D-G).
    pub hard_deadline_seconds: f64,
    /// The provider transport timeout (`HUMAUX_PRIVATE_WORKER_HTTP_TIMEOUT_SECS`): `ops.begin_call`
    /// admits a request only with `http_timeout + lease` left before `hard_deadline`.
    pub http_timeout_seconds: f64,
    /// How long a job may be not ready before it parks as `WAITING_KEY`, and the park interval.
    pub not_ready_park_seconds: f64,
    /// Admitted provider requests after which retryable failures are DEAD with their class.
    pub max_attempts: i32,
    /// §72.3 tenant distill budget every request passes before it may leave (ADR-0058 D-T).
    pub budget: DistillCallBudget,
    /// Ruling E3 (`HUMAUX_PRIVATE_WORKER_HEALTH_RENEW_SECS`): the validity of the health a
    /// SUCCEEDED call renews (only once less than half of it is left) and of the INVALID verdict
    /// a provider-rejected credential records.
    pub health_renew_seconds: i64,
    /// ADR-0066 D-P: `HUMAUX_PRIVATE_WORKER_DNS_PINS` names at least one host, so a TRANSPORT deferral counts
    /// `dns_pin_deferred_total`.
    pub dns_pins_configured: bool,
}

/// ADR-0058 R2: the `ops.provider_slots` rows `migrations/0190_distill_dispatch_v2.sql` seeds
/// (gate `four_slots`). A seat past them can never hold a slot, and the pool is sized for them.
pub const PROVIDER_SLOTS: u32 = 4;

impl DistillDispatchConfig {
    /// ADR-0058 D-K: `hard_deadline >= 2 × (http_timeout + lease)` — the first call and the one
    /// ADR-0048 re-ask each need `http_timeout + lease` (`ops.begin_call`'s `min_remaining`).
    pub fn validate(&self) -> Result<(), ErrorCode> {
        let positive = |v: f64| v.is_finite() && v > 0.0;
        if self.lease_owner.trim().is_empty()
            || !positive(self.lease_seconds)
            || !(1..=PROVIDER_SLOTS).contains(&self.in_flight)
            || self.max_attempts <= 0
            || !positive(self.not_ready_park_seconds)
            || !positive(self.http_timeout_seconds)
            || !self.hard_deadline_seconds.is_finite()
            || self.hard_deadline_seconds < 2.0 * self.min_remaining_seconds()
            || !positive(self.budget.window_seconds)
            || self.budget.max_calls < 1
            || self.health_renew_seconds < 1
        {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(())
    }

    /// The window `ops.begin_call` must still see before `hard_deadline`: the HTTP call plus one
    /// lease for the post-call legs (ADR-0058 D-J).
    // ponytail: post-call legs slower than one lease let T6 fire before a known answer is written
    // (ADR-0058 L14); upgrade: a fenced renew allowed past the HTTP window for a completed call.
    pub fn min_remaining_seconds(&self) -> f64 {
        self.http_timeout_seconds + self.lease_seconds
    }
}

/// ADR-0058 R5: why a `--distill-once` seat stopped — its claim came back empty because every
/// provider slot was bound (READY work may be left; another process holds the slots), or because a
/// slot was free and no READY job could be taken. Ordered so the pass reports the worse one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DrainStop {
    /// A slot was free and the claim found no READY job it could take.
    NoWork,
    /// Every provider slot was bound when the empty claim was read back.
    NoSlot,
}

impl DrainStop {
    /// The `stopped=` value of the summary line.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoWork => "no_work",
            Self::NoSlot => "no_slot",
        }
    }
}

/// What one dispatcher run did, summed over its seats. `claimed == 0` is the "no input" signal
/// `--distill-once` exits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DistillDispatchReport {
    /// `DERIVED_DISTILL` jobs claimed.
    pub claimed: u32,
    /// Jobs settled DONE with their outbox row DONE (memories written, or nothing memorable, or
    /// the Evidence was already settled).
    pub completed: u32,
    /// Jobs whose outbox row was settled FAILED (input-bound rejection, or DEAD).
    pub failed: u32,
    /// NOT_READY settles: nothing was dispatched (no usable binding, admission mismatch, domain
    /// mismatch, a refused first call). Backed off, never an attempt.
    pub not_ready: u32,
    /// Jobs settled `WAITING_KEY` (not ready past the park age, or a provider 401).
    pub parked: u32,
    /// RETRY settles after a counted failed call.
    pub deferred: u32,
    /// DEAD settles (attempts exhausted, abandoned claims, fail-closed refusals).
    pub dead: u32,
    /// Jobs whose take or settle was rejected by the generation fence (another claim owns them).
    /// Fence losses only (ADR-0058 R3).
    pub lost_lease: u32,
    /// Jobs an error escaped (a DB, reasoner or membership failure the job could not settle);
    /// the job line names its class (ADR-0058 R3).
    pub errors: u32,
    /// Jobs whose heartbeat found the lease gone while their work was still running.
    pub heartbeat_lost: u32,
    /// Provider requests admitted by `ops.begin_call` (each one an attempt).
    pub attempts: u32,
    /// Calls the HTTP cutoff ended with no answer (outcome unknown; reconciled by T5 → T6).
    pub unknown: u32,
    /// Memories written.
    pub memories: u32,
    /// §10.1 `memory_candidate_rejections_total` count (every reason).
    pub rejected: u32,
    /// ADR-0048: re-asks after a clean parse with zero candidates.
    pub empty_retries: u32,
    /// ADR-0048 addendum: re-asks after a reply the parser refused.
    pub malformed_retries: u32,
    /// ADR-0058 R1: written replies whose inferred affects were discarded as invalid.
    pub affects_dropped: u32,
    /// ADR-0058 R9: written replies the tool channel delivered in `content` (no tool call) and the
    /// parser accepted.
    pub channel_fallback: u32,
    /// ADR-0058 R5: why the drain stopped (`None` for `--distill-serve`, which never stops on an
    /// empty claim). Summed as the worse of the seats' reasons.
    pub stopped: Option<DrainStop>,
}

impl DistillDispatchReport {
    pub fn add(&mut self, other: DistillDispatchReport) {
        self.claimed += other.claimed;
        self.completed += other.completed;
        self.failed += other.failed;
        self.not_ready += other.not_ready;
        self.parked += other.parked;
        self.deferred += other.deferred;
        self.dead += other.dead;
        self.lost_lease += other.lost_lease;
        self.errors += other.errors;
        self.heartbeat_lost += other.heartbeat_lost;
        self.attempts += other.attempts;
        self.unknown += other.unknown;
        self.memories += other.memories;
        self.rejected += other.rejected;
        self.empty_retries += other.empty_retries;
        self.malformed_retries += other.malformed_retries;
        self.affects_dropped += other.affects_dropped;
        self.channel_fallback += other.channel_fallback;
        self.stopped = self.stopped.max(other.stopped);
    }

    /// The operator-facing summary line (`claimed=` = jobs claimed this run).
    pub fn summary_line(&self) -> String {
        format!(
            "humaux-private-worker: distill dispatch claimed={} completed={} failed={} not_ready={} parked={} deferred={} dead={} lost_lease={} errors={} heartbeat_lost={} attempts={} unknown={} memories={} rejected={} empty_retries={} malformed_retries={} affects_dropped={} channel_fallback={} stopped={}",
            self.claimed,
            self.completed,
            self.failed,
            self.not_ready,
            self.parked,
            self.deferred,
            self.dead,
            self.lost_lease,
            self.errors,
            self.heartbeat_lost,
            self.attempts,
            self.unknown,
            self.memories,
            self.rejected,
            self.empty_retries,
            self.malformed_retries,
            self.affects_dropped,
            self.channel_fallback,
            self.stopped.map_or("-", DrainStop::as_str),
        )
    }
}

/// Why a dispatcher run stopped early.
#[derive(Debug)]
pub enum DistillError<E = Box<dyn std::error::Error + Send + Sync>> {
    /// §37 / ADR-0092 D-C: forgotten input, terminal without another provider call.
    StaleInput,
    /// Original database error, opaque outside its adapter.
    Db(E),
    /// Existing private reasoning failure vocabulary.
    Reasoning(PrivateReasoningError),
    /// Existing terminal configuration code.
    Config(ErrorCode),
}

impl<E> DistillError<E> {
    /// Preserve the worker job error as an unclassified, redacted reasoning failure.
    pub fn job_reasoning_failure(message: String) -> Self {
        Self::Reasoning(PrivateReasoningError::new(message))
    }

    /// Static class for `last_error_class` and the job line — never DB or provider text.
    pub fn class(&self) -> &'static str {
        match self {
            Self::StaleInput => "STALE_INPUT",
            Self::Db(_) => "WORKER_DB_ERROR",
            Self::Reasoning(error) => error.class().unwrap_or("UNCLASSIFIED_REASONING_ERROR"),
            Self::Config(_) => "WORKER_CONFIG_ERROR",
        }
    }
}

impl<E: std::fmt::Display> std::fmt::Display for DistillError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StaleInput => f.write_str("stale distill input"),
            Self::Db(error) => write!(f, "distill database error: {error}"),
            Self::Reasoning(error) => write!(f, "distill reasoning error: {error}"),
            Self::Config(code) => write!(f, "distill configuration rejected: {code:?}"),
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for DistillError<E> {}

impl<E> From<E> for DistillError<E> {
    fn from(error: E) -> Self {
        Self::Db(error)
    }
}
impl<E: std::error::Error + Send + Sync + 'static> DistillError<E> {
    /// Preserve the error class and source while erasing the database implementation.
    pub fn erase(self) -> DistillError {
        match self {
            Self::StaleInput => DistillError::StaleInput,
            Self::Db(e) => DistillError::Db(Box::new(e)),
            Self::Reasoning(e) => DistillError::Reasoning(e),
            Self::Config(e) => DistillError::Config(e),
        }
    }
}
/// Map the existing static failure classes to stage telemetry (§53).
pub fn stage_class(class: &str) -> ErrorCode {
    ErrorCode::ALL
        .into_iter()
        .find(|c| c.as_str() == class)
        .unwrap_or(match class {
            "TRANSPORT" | "RETRY_WAIT" | EXECUTION_UNCERTAIN => ErrorCode::ProviderTransient,
            PROVIDER_BUDGET => ErrorCode::CostBudgetExceeded,
            FAILED_OUTPUT_SCHEMA | INVALID_JOB_PAYLOAD | DOMAIN_MISMATCH => ErrorCode::InvalidInput,
            "EGRESS_PERMIT_PAYLOAD_MISMATCH" | "ENDPOINT_REJECTED" => ErrorCode::Forbidden,
            _ => ErrorCode::DependencyUnavailable,
        })
}
/// Decode the job payload identity written by the enqueue trigger (ADR-0058 D-C).
pub fn payload_identity(payload: &Value) -> Option<(Uuid, Uuid)> {
    let field = |name: &str| payload.get(name)?.as_str()?.parse::<Uuid>().ok();
    Some((field("reasoning_domain_id")?, field("evidence_id")?))
}

/// ADR-0058 D-D: the Evidence names another reasoning domain than its job.
const DOMAIN_MISMATCH: &str = "DOMAIN_MISMATCH";
/// A job payload without the 0164 identity: no Evidence can ever be named for it.
const INVALID_JOB_PAYLOAD: &str = "INVALID_JOB_PAYLOAD";
/// ADR-0058 D-F: claimed with `attempt >= max_attempts` (after a T6 reconcile).
const ATTEMPTS_EXHAUSTED: &str = "ATTEMPTS_EXHAUSTED";
/// ADR-0058 D-F: claimed with `abandoned_claims >= max_attempts` (pre-dispatch crashes).
const PRE_DISPATCH_ABANDONED: &str = "PRE_DISPATCH_ABANDONED";
/// ADR-0048 D-D: the reply failed the parser (or the tool-call shape, ADR-0058 D-M) after its
/// re-ask budget.
const FAILED_OUTPUT_SCHEMA: &str = "FAILED_OUTPUT_SCHEMA";
/// The ADR-0058 T6 class the claim's sweep writes; seen again on the re-claim.
const EXECUTION_UNCERTAIN: &str = "EXECUTION_UNCERTAIN";
/// ADR-0058 D-T: the first request of a claim was refused by the tenant's §72.3 budget (NOT_READY,
/// no attempt spent).
const PROVIDER_BUDGET: &str = "PROVIDER_BUDGET";

// ADR-0048: one flat re-ask each per claim; a refused or exhausted one settles as its budget does.
const DISTILL_EMPTY_RETRY_BUDGET: u32 = 1;
const DISTILL_MALFORMED_RETRY_BUDGET: u32 = 1;

/// How one claimed job ended, as the job line names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobOutcome {
    /// Job DONE, outbox DONE.
    Done,
    /// Job DONE, outbox FAILED (input-bound).
    Failed,
    Retry,
    NotReady,
    Parked,
    Dead,
    /// The generation fence refused the take or the settle (ADR-0058 R3: nothing else).
    LeaseLost,
    /// An error escaped the job; the claim reconciles through the sweep (ADR-0058 R3).
    Error,
    /// The HTTP cutoff won: no settle, the claim reconciles through T5 → T6.
    Unknown,
}

impl JobOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Done => "DONE",
            Self::Failed => "FAILED",
            Self::Retry => "RETRY",
            Self::NotReady => "NOT_READY",
            Self::Parked => "PARKED",
            Self::Dead => "DEAD",
            Self::LeaseLost => "LEASE_LOST",
            Self::Error => "ERROR",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// One settled job, for the job line.
pub struct Settled {
    /// Preserved origin or lease-loss error.
    pub error: Option<ErrorCode>,
    /// Settled job outcome.
    pub outcome: JobOutcome,
    /// Static operational class, without provider payloads.
    pub class: Option<&'static str>,
    /// Existing retry or park delay.
    pub next_retry_seconds: Option<f64>,
    /// ADR-0058 R9: the written reply came from the tool channel's `content`.
    pub channel_fallback: bool,
}

impl Settled {
    /// Retain a more specific lease-loss classification.
    pub fn record_origin_error(&mut self, error: &DistillError) {
        // A refused settlement fence already identifies lease loss more precisely.
        self.error = self.error.or_else(|| {
            Some(match error {
                DistillError::Config(code) => *code,
                other => stage_class(other.class()),
            })
        });
    }

    /// Construct a settlement using the existing fence classification.
    pub fn new(outcome: JobOutcome, class: Option<&'static str>) -> Self {
        Self {
            error: matches!(outcome, JobOutcome::LeaseLost).then_some(ErrorCode::Conflict),
            outcome,
            class,
            next_retry_seconds: None,
            channel_fallback: false,
        }
    }
}

/// The job-finish policy, mapped exhaustively by the job adapter.
#[derive(Debug, Clone, Copy)]
pub enum Finish {
    /// Completed.
    Done,
    /// Retry a counted failure.
    Retry,
    /// No admitted call.
    NotReady,
    /// Credential refused.
    WaitingKey,
    /// Terminal exhaustion.
    Dead,
}
/// Taken outbox coordinates (not a transaction handle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimedEvidence {
    /// Outbox identity.
    pub outbox_id: Uuid,
    /// Evidence identity.
    pub evidence_id: Uuid,
    /// Commit coordinate carried by the taken row.
    pub commit_seq: i64,
    /// Stream coordinate carried by the taken row.
    pub stream_seq: i64,
}
/// Fenced take result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TakenOutbox {
    /// Fence refused.
    LeaseLost,
    /// Existing terminal outbox.
    AlreadySettled,
    /// Acquired this job's row.
    Taken(ClaimedEvidence),
}
/// Outbox completion policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxSettle {
    /// Completed.
    Done,
    /// Terminal failure.
    Failed,
    /// Retry later.
    Pending,
}
/// Admitted read snapshot. The transport/provider-bearing handle stays opaque.
pub struct Ready<H> {
    /// Adapter-owned read data.
    pub handle: H,
    /// Safe admitted route fields for the job line.
    pub route: String,
    /// Durable run identity.
    pub processing_run_id: Uuid,
    /// Fingerprinted affect menu.
    pub offer_affects: bool,
}
/// Read gate result before spending an attempt.
pub enum ReadLeg<H> {
    /// Ready to prepare one call.
    Ready(Box<Ready<H>>),
    /// Evidence unavailable.
    Unavailable,
    /// Explicit identity contract owns this Evidence.
    IdentityContract,
    /// Temporarily refused.
    NotReady(&'static str),
}
/// Reserved provider request, opaque until sent or abandoned.
pub struct Prepared<H> {
    /// Ledger reservation identity.
    pub model_call_id: Uuid,
    /// Provider/egress handle.
    pub handle: H,
}
/// Finalized call or deliberately unknown outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DistillCallOutcome {
    /// Successful round trip.
    Answered(DistillInferenceResult),
    /// A finalized failure, without any provider text.
    Failed {
        /// Static failure class.
        class: &'static str,
        /// Provider retry hint already bounded at the BYOK boundary.
        retry_after: Option<Duration>,
    },
    /// Deadline cut only the HTTP future.
    Unknown,
}
/// Job lease, slot and budget operations (ADR-0058).
#[async_trait(?Send)]
pub trait DistillJobPort {
    /// Claim through the existing four-slot scheduler.
    async fn claim(
        &self,
        config: &DistillDispatchConfig,
    ) -> Result<Option<DistillClaim>, DistillError>;
    /// Diagnose an empty drain claim.
    async fn all_slots_bound(&self) -> Result<bool, DistillError>;
    /// Renew the generation-fenced claim.
    async fn renew(
        &self,
        lease: &DistillLease<'_>,
        seconds: f64,
    ) -> Result<Option<()>, DistillError>;
    /// Reserve one admitted attempt before any bytes leave.
    async fn admit_call(
        &self,
        lease: &DistillLease<'_>,
        call: Uuid,
        remaining: f64,
        budget: DistillCallBudget,
    ) -> Result<CallAdmission, DistillError>;
    /// Existing retry policy, supplied by the job adapter.
    fn retry_backoff(&self, seconds: f64, attempt: i32) -> f64;
}
/// Provider boundary: admission/preparation handles never expose SDK types.
#[async_trait(?Send)]
pub trait DistillProviderPort {
    /// Admitted Evidence + provider route, owned by the adapter.
    type Admission;
    /// A reserved but unsent call.
    type Prepared;
    /// Prepare egress after the read run committed.
    async fn prepare(
        &self,
        ready: &Ready<Self::Admission>,
    ) -> Result<Prepared<Self::Prepared>, DistillError>;
    /// Finalize an unsent reservation.
    async fn abandon(&self, prepared: Self::Prepared) -> Result<(), DistillError>;
    /// Execute only the admitted request, cutting HTTP at the supplied deadline.
    async fn call(
        &self,
        prepared: Self::Prepared,
        cutoff: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    ) -> Result<DistillCallOutcome, DistillError>;
    /// Validate the provider output using the existing parser.
    fn parse(&self, bytes: &[u8], affects: bool) -> Result<DistillReply, &'static str>;
    /// Preserve route-health observation and its diagnostic-only failure handling.
    async fn observe_health(&self, tenant: Uuid, call: Uuid, rejected: bool, seconds: i64);
}
/// Read snapshots and complete fenced result/settlement transactions.
#[async_trait(?Send)]
pub trait DistillWorkStore: DistillProviderPort {
    /// Take only the claimed job's Evidence outbox.
    async fn take_outbox(
        &self,
        lease: &DistillLease<'_>,
        evidence: Uuid,
        deadline: OffsetDateTime,
    ) -> Result<TakenOutbox, DistillError>;
    /// Complete all read gates and commit the processing run before egress.
    async fn read(
        &self,
        tenant: Uuid,
        domain: Uuid,
        evidence: Uuid,
    ) -> Result<ReadLeg<Self::Admission>, DistillError>;
    /// Settle the job and optional outbox together, fenced first.
    async fn settle(
        &self,
        lease: &DistillLease<'_>,
        outbox: Option<(&ClaimedEvidence, OutboxSettle)>,
        finish: Finish,
        class: Option<&'static str>,
        backoff: f64,
        park: f64,
    ) -> Result<bool, DistillError>;
    /// Persist authorized results and the run/outbox/job in the same transaction.
    async fn write(
        &self,
        lease: &DistillLease<'_>,
        row: &ClaimedEvidence,
        ready: &Ready<Self::Admission>,
        inferred: &DistillInferenceResult,
        candidates: &[DistillCandidate],
    ) -> Result<Option<(u32, u32)>, DistillError>;
    /// Complete a successful empty attempt before its one permitted re-ask.
    async fn close_empty(
        &self,
        ready: &Ready<Self::Admission>,
        inferred: &DistillInferenceResult,
    ) -> Result<(), DistillError>;
}
/// The independently named capabilities needed by one Distill job.
pub trait DistillPorts: DistillJobPort + DistillWorkStore {}
impl<T: DistillJobPort + DistillWorkStore> DistillPorts for T {}
/// Use-case dependencies assembled by the binary.
pub struct Dispatcher<'a, R> {
    /// Purpose-specific outbound capabilities.
    pub runtime: &'a R,
    /// Monotonic deadline future supplied by the process executor.
    pub sleep_until: fn(Instant) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    /// Deployment policy, unchanged for the claim.
    pub dispatch: &'a DistillDispatchConfig,
}
struct EmptyAnswer<H> {
    inferred: DistillInferenceResult,
    ready: Ready<H>,
}
const AFFECT_INVALID_CLASS: &str = "affect_invalid";
const DISPATCH_REFUSED: &str = "DISPATCH_REFUSED";
async fn settle_as<R: DistillPorts>(
    dispatcher: &Dispatcher<'_, R>,
    lease: &DistillLease<'_>,
    outbox: Option<(&ClaimedEvidence, OutboxSettle)>,
    finish: Finish,
    class: Option<&'static str>,
    backoff_seconds: f64,
    outcome: JobOutcome,
) -> Result<Settled, DistillError> {
    if dispatcher
        .runtime
        .settle(
            lease,
            outbox,
            finish,
            class,
            backoff_seconds,
            dispatcher.dispatch.not_ready_park_seconds,
        )
        .await?
    {
        let next_retry_seconds = match finish {
            Finish::Retry | Finish::NotReady => Some(backoff_seconds),
            Finish::WaitingKey => Some(dispatcher.dispatch.not_ready_park_seconds),
            Finish::Done | Finish::Dead => None,
        };
        Ok(Settled {
            error: None,
            outcome,
            class,
            next_retry_seconds,
            channel_fallback: false,
        })
    } else {
        Ok(Settled::new(JobOutcome::LeaseLost, class))
    }
}

async fn settle_not_ready<R: DistillPorts>(
    dispatcher: &Dispatcher<'_, R>,
    claim: &DistillClaim,
    lease: &DistillLease<'_>,
    row: &ClaimedEvidence,
    class: &'static str,
) -> Result<Settled, DistillError> {
    let dispatch = dispatcher.dispatch;
    let claimed_at = claim.lease_expires_at - Duration::from_secs_f64(dispatch.lease_seconds);
    let parks = claim.not_ready_since.is_some_and(|since| {
        (claimed_at - since).as_seconds_f64() >= dispatch.not_ready_park_seconds
    });
    settle_as(
        dispatcher,
        lease,
        Some((row, OutboxSettle::Pending)),
        Finish::NotReady,
        Some(class),
        dispatcher
            .runtime
            .retry_backoff(dispatch.lease_seconds, claim.attempt),
        if parks {
            JobOutcome::Parked
        } else {
            JobOutcome::NotReady
        },
    )
    .await
}

async fn settle_failed_call<R: DistillPorts>(
    dispatcher: &Dispatcher<'_, R>,
    lease: &DistillLease<'_>,
    row: &ClaimedEvidence,
    attempt: i32,
    class: &'static str,
    retry_after: Option<Duration>,
) -> Result<Settled, DistillError> {
    let dispatch = dispatcher.dispatch;
    if attempt >= dispatch.max_attempts {
        return settle_as(
            dispatcher,
            lease,
            Some((row, OutboxSettle::Failed)),
            Finish::Dead,
            Some(class),
            0.0,
            JobOutcome::Dead,
        )
        .await;
    }
    let delay = retry_after.map_or_else(
        || {
            // ADR-0058 E1: spread retries across the same ±25% window as D1's T6 reconciliation.
            dispatcher
                .runtime
                .retry_backoff(dispatch.lease_seconds, attempt)
                * rand::random_range(0.75..1.25)
        },
        |hint| hint.as_secs_f64(),
    );
    settle_as(
        dispatcher,
        lease,
        Some((row, OutboxSettle::Pending)),
        Finish::Retry,
        Some(class),
        delay,
        JobOutcome::Retry,
    )
    .await
}

/// Execute one claimed job through the budget, provider and atomic result ports.
pub async fn work_job<R: DistillPorts>(
    dispatcher: &Dispatcher<'_, R>,
    claim: &DistillClaim,
    lease: &DistillLease<'_>,
    local_deadline: Instant,
    attempt: &mut i32,
    route: &mut String,
    report: &mut DistillDispatchReport,
) -> Result<Settled, DistillError> {
    let dispatch = dispatcher.dispatch;
    let Some((reasoning_domain_id, evidence_id)) = payload_identity(&claim.payload) else {
        return settle_as(
            dispatcher,
            lease,
            None,
            Finish::Dead,
            Some(INVALID_JOB_PAYLOAD),
            0.0,
            JobOutcome::Dead,
        )
        .await;
    };
    let row = match dispatcher
        .runtime
        .take_outbox(lease, evidence_id, claim.hard_deadline)
        .await?
    {
        TakenOutbox::LeaseLost => return Ok(Settled::new(JobOutcome::LeaseLost, None)),
        TakenOutbox::AlreadySettled => {
            return settle_as(
                dispatcher,
                lease,
                None,
                Finish::Done,
                None,
                0.0,
                JobOutcome::Done,
            )
            .await;
        }
        TakenOutbox::Taken(row) => row,
    };
    // ADR-0058 D-F: exhausted on claim — DEAD at once, no HTTP, outbox FAILED in the same txn.
    for (spent, class) in [
        (claim.attempt, ATTEMPTS_EXHAUSTED),
        (claim.abandoned_claims, PRE_DISPATCH_ABANDONED),
    ] {
        if spent >= dispatch.max_attempts {
            return settle_as(
                dispatcher,
                lease,
                Some((&row, OutboxSettle::Failed)),
                Finish::Dead,
                Some(class),
                0.0,
                JobOutcome::Dead,
            )
            .await;
        }
    }

    let mut calls = 0_u32;
    // ADR-0058 D-E: every error exit after the take settles here — one fenced settle in a fresh
    // transaction (NOT_READY before any admitted call, a failed counted call after one), so a job
    // whose outcome the worker already knows neither keeps its slot until hard_deadline nor comes
    // back as EXECUTION_UNCERTAIN.
    match call_loop(
        dispatcher,
        claim,
        lease,
        &row,
        reasoning_domain_id,
        local_deadline,
        attempt,
        route,
        &mut calls,
        report,
    )
    .await
    {
        Err(error) => {
            settle_after_error(dispatcher, claim, lease, &row, calls, *attempt, &error).await
        }
        settled => settled,
    }
}

#[allow(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    reason = "one claim's call loop (read → prepare → admit → call → parse → write, with the ADR-0048 re-asks) reads best in one place; ADR-0058 D-F"
)]
async fn call_loop<R: DistillPorts>(
    dispatcher: &Dispatcher<'_, R>,
    claim: &DistillClaim,
    lease: &DistillLease<'_>,
    row: &ClaimedEvidence,
    reasoning_domain_id: Uuid,
    local_deadline: Instant,
    attempt: &mut i32,
    route: &mut String,
    calls: &mut u32,
    report: &mut DistillDispatchReport,
) -> Result<Settled, DistillError> {
    let dispatch = dispatcher.dispatch;
    // The Evidence of the row this claim took (equal to the payload's by construction): the hop
    // works and settles exactly what it took.
    let evidence_id = row.evidence_id;
    let http_cutoff = local_deadline - Duration::from_secs_f64(dispatch.lease_seconds);
    let mut empty_retries = 0_u32;
    let mut malformed_retries = 0_u32;
    let mut empty_answer: Option<EmptyAnswer<R::Admission>> = None;
    loop {
        let ready = match dispatcher
            .runtime
            .read(claim.tenant_id, reasoning_domain_id, evidence_id)
            .await
        {
            Ok(ReadLeg::Ready(ready)) => *ready,
            Ok(ReadLeg::Unavailable) => {
                eprintln!(
                    "humaux-private-worker: distill evidence={evidence_id} failed: no_output"
                );
                return settle_as(
                    dispatcher,
                    lease,
                    Some((row, OutboxSettle::Failed)),
                    Finish::Done,
                    None,
                    0.0,
                    JobOutcome::Failed,
                )
                .await;
            }
            // ADR-0067 D-B: a job for a contracted Evidence is refused terminally — job DONE, outbox DONE, no call.
            Ok(ReadLeg::IdentityContract) => {
                eprintln!(
                    "humaux-private-worker: distill evidence={evidence_id} refused: identity_contract"
                );
                return settle_as(
                    dispatcher,
                    lease,
                    Some((row, OutboxSettle::Done)),
                    Finish::Done,
                    None,
                    0.0,
                    JobOutcome::Done,
                )
                .await;
            }
            Ok(ReadLeg::NotReady(class)) if *calls == 0 => {
                return settle_not_ready(dispatcher, claim, lease, row, class).await;
            }
            // Became unready between two calls of one claim: a counted call happened.
            Ok(ReadLeg::NotReady(class)) => {
                return settle_failed_call(dispatcher, lease, row, *attempt, class, None).await;
            }
            Err(error) => return Err(error),
        };
        *route = ready.route.clone();
        let prepared = dispatcher.runtime.prepare(&ready).await?;
        let admission = dispatcher
            .runtime
            .admit_call(
                lease,
                prepared.model_call_id,
                dispatch.min_remaining_seconds(),
                dispatch.budget,
            )
            .await?;
        let admitted_attempt = if let CallAdmission::Admitted(admitted) = admission {
            admitted
        } else {
            let refused = if admission == CallAdmission::OverBudget {
                PROVIDER_BUDGET
            } else {
                DISPATCH_REFUSED
            };
            dispatcher.runtime.abandon(prepared.handle).await?;
            if *calls == 0 {
                return settle_not_ready(dispatcher, claim, lease, row, refused).await;
            }
            // ADR-0048 D-D: a refused re-ask fails closed, never re-sends the prompt.
            if let Some(empty) = empty_answer.take() {
                return write_leg(
                    dispatcher,
                    lease,
                    row,
                    *attempt,
                    &empty.ready,
                    &empty.inferred,
                    &DistillReply::default(),
                    report,
                )
                .await;
            }
            return settle_as(
                dispatcher,
                lease,
                Some((row, OutboxSettle::Failed)),
                Finish::Dead,
                Some(FAILED_OUTPUT_SCHEMA),
                0.0,
                JobOutcome::Dead,
            )
            .await;
        };
        *calls += 1;
        *attempt = admitted_attempt;
        report.attempts += 1;
        let model_call_id = prepared.model_call_id;
        let outcome = dispatcher
            .runtime
            .call(prepared.handle, (dispatcher.sleep_until)(http_cutoff))
            .await;
        // Ruling E3 (b): traffic keeps a route's health alive; a rejected key denies the next
        // admission at once.
        match &outcome {
            Ok(DistillCallOutcome::Answered(_)) => {
                dispatcher
                    .runtime
                    .observe_health(
                        claim.tenant_id,
                        model_call_id,
                        false,
                        dispatcher.dispatch.health_renew_seconds,
                    )
                    .await;
            }
            Ok(DistillCallOutcome::Failed { class, .. }) if *class == "WAITING_KEY" => {
                dispatcher
                    .runtime
                    .observe_health(
                        claim.tenant_id,
                        model_call_id,
                        true,
                        dispatcher.dispatch.health_renew_seconds,
                    )
                    .await;
            }
            _ => {}
        }
        let answered = match outcome {
            Ok(DistillCallOutcome::Unknown) => {
                return Ok(Settled::new(JobOutcome::Unknown, Some(EXECUTION_UNCERTAIN)));
            }
            Ok(DistillCallOutcome::Failed {
                class: "WAITING_KEY",
                ..
            }) => {
                // §11: WAITING_KEY = known blocked, never DEAD, no retry count.
                *attempt = (*attempt - 1).max(0);
                return settle_as(
                    dispatcher,
                    lease,
                    Some((row, OutboxSettle::Pending)),
                    Finish::WaitingKey,
                    Some("WAITING_KEY"),
                    0.0,
                    JobOutcome::Parked,
                )
                .await;
            }
            // ADR-0058 D-M: a reply that broke the tool-call contract spends the malformed budget
            // exactly like one the parser refused (ADR-0048 D-D), never the provider-retry path.
            Ok(DistillCallOutcome::Failed {
                class: FAILED_OUTPUT_SCHEMA,
                ..
            }) => None,
            Ok(DistillCallOutcome::Failed { class, retry_after }) => {
                return settle_failed_call(dispatcher, lease, row, *attempt, class, retry_after)
                    .await;
            }
            Ok(DistillCallOutcome::Answered(inferred)) => Some(inferred),
            Err(error) => return Err(error),
        };
        let parsed = match answered {
            Some(inferred) => dispatcher
                .runtime
                .parse(&inferred.output_bytes, ready.offer_affects)
                .map(|reply| (inferred, reply)),
            None => Err("tool_call_shape"),
        };
        let (inferred, reply) = match parsed {
            Ok(parsed) => parsed,
            Err(reason) => {
                // Structural class only (`DistillParseError`), never payload text. The re-ask is
                // one more counted call (its own run / disclosure / ledger / distill_calls rows);
                // after the budget the job is DEAD and the outbox FAILED (ADR-0048 D-D).
                if malformed_retries < DISTILL_MALFORMED_RETRY_BUDGET {
                    malformed_retries += 1;
                    report.malformed_retries += 1;
                    empty_answer = None;
                    eprintln!(
                        "humaux-private-worker: distill evidence={evidence_id} malformed reply ({reason}), retry {malformed_retries}/{DISTILL_MALFORMED_RETRY_BUDGET}"
                    );
                    continue;
                }
                eprintln!(
                    "humaux-private-worker: distill evidence={evidence_id} failed: InvalidInput ({reason})"
                );
                return settle_as(
                    dispatcher,
                    lease,
                    Some((row, OutboxSettle::Failed)),
                    Finish::Dead,
                    Some(FAILED_OUTPUT_SCHEMA),
                    0.0,
                    JobOutcome::Dead,
                )
                .await;
            }
        };
        if !reply.memories.is_empty() || empty_retries >= DISTILL_EMPTY_RETRY_BUDGET {
            return write_leg(
                dispatcher, lease, row, *attempt, &ready, &inferred, &reply, report,
            )
            .await;
        }
        // ADR-0048 (card 24) backstop: a clean parse with ZERO candidates is re-asked once. The
        // abandoned attempt is a call that SUCCEEDED with nothing in it, so its run is closed
        // with its own digest and `output_count = 0` (not the ADR-0016 D4 failure marker).
        dispatcher.runtime.close_empty(&ready, &inferred).await?;
        empty_retries += 1;
        report.empty_retries += 1;
        eprintln!(
            "humaux-private-worker: distill evidence={evidence_id} returned zero candidates, retry {empty_retries}/{DISTILL_EMPTY_RETRY_BUDGET}"
        );
        empty_answer = Some(EmptyAnswer { inferred, ready });
    }
}

async fn settle_after_error<R: DistillPorts>(
    dispatcher: &Dispatcher<'_, R>,
    claim: &DistillClaim,
    lease: &DistillLease<'_>,
    row: &ClaimedEvidence,
    calls: u32,
    attempt: i32,
    error: &DistillError,
) -> Result<Settled, DistillError> {
    eprintln!(
        "humaux-private-worker: distill job={} evidence={} error: {error}",
        claim.job_id, row.evidence_id
    );
    let mut settled = if matches!(error, DistillError::StaleInput) {
        settle_stale_input(dispatcher, lease, row).await
    } else if calls == 0 {
        settle_not_ready(dispatcher, claim, lease, row, error.class()).await
    } else {
        // ponytail: ADR-0058 R8 (c) known limit — a transient DB error in the write leg AFTER a
        // succeeded provider call settles RETRY here, and the next claim calls the provider again
        // (one extra billed call, counted). Upgrade: retry the write leg in place with the parsed
        // reply, inside the claim's hard deadline.
        settle_failed_call(dispatcher, lease, row, attempt, error.class()).await
    }?;
    settled.record_origin_error(error);
    Ok(settled)
}

async fn settle_stale_input<R: DistillPorts>(
    dispatcher: &Dispatcher<'_, R>,
    lease: &DistillLease<'_>,
    row: &ClaimedEvidence,
) -> Result<Settled, DistillError> {
    settle_as(
        dispatcher,
        lease,
        Some((row, OutboxSettle::Done)),
        Finish::Done,
        Some("STALE_INPUT"),
        0.0,
        JobOutcome::Done,
    )
    .await
}

#[allow(
    clippy::too_many_arguments,
    reason = "the write leg's inputs are the job's lease, its row, its attempt and the one answered call"
)]
async fn write_leg<R: DistillPorts>(
    dispatcher: &Dispatcher<'_, R>,
    lease: &DistillLease<'_>,
    row: &ClaimedEvidence,
    attempt: i32,
    ready: &Ready<R::Admission>,
    inferred: &DistillInferenceResult,
    reply: &DistillReply,
    report: &mut DistillDispatchReport,
) -> Result<Settled, DistillError> {
    match dispatcher
        .runtime
        .write(lease, row, ready, inferred, &reply.memories)
        .await
    {
        Ok(Some((inserted, rejected))) => {
            report.memories += inserted;
            report.rejected += rejected;
            // ADR-0058 R1: the memories are written; the job line names why no inferred affect was.
            report.affects_dropped += u32::from(reply.affects_dropped);
            // ADR-0058 R9: counted only once the parser accepted it and it was written.
            report.channel_fallback += u32::from(inferred.channel_fallback);
            Ok(Settled {
                channel_fallback: inferred.channel_fallback,
                ..Settled::new(
                    JobOutcome::Done,
                    reply.affects_dropped.then_some(AFFECT_INVALID_CLASS),
                )
            })
        }
        Ok(None) => Ok(Settled::new(JobOutcome::LeaseLost, None)),
        Err(DistillError::StaleInput) => settle_stale_input(dispatcher, lease, row).await,
        Err(error) => {
            eprintln!(
                "humaux-private-worker: distill job={} write failed: {error}",
                lease.job_id
            );
            settle_failed_call(dispatcher, lease, row, attempt, error.class()).await
        }
    }
}

/// Existing Distill value projection (§10.1 / §16.1.1).
pub fn memory_content(text: &str) -> Value {
    serde_json::json!({
        "title": text.chars().take(80).collect::<String>(),
        "key_claim": text,
    })
}

/// Existing Distill value projection (§10.1 / §16.1.1).
pub fn rejection_reason(rejection: CandidateRejection) -> &'static str {
    // One mapping (§78.2): the domain enum owns the label; this is the metric-value view of the
    // same string `private.distill_candidates.rejection_reason` stores.
    rejection.as_db_str()
}
