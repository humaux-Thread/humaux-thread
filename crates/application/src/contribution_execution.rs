//! `application::contribution_execution` — Phase 9 R4 application contract for one durable two-stage contribution
//!   execution.
//! Depends-on: crates=[async-trait, humaux-domain, serde_json, sha2, uuid]; services=[]; env=[]; modules=[application::consolidate, application::contribute, domain::error, domain::evidence]
//! Called-by: [adapters::contribution_execution_ingress, adapters::contribution_execution_repo, adapters::contribution_reasoner, humaux-private-worker, private-worker::bootstrap, tests]
//! Invariants: [only newly reserved permits dispatch; exact late completion retries only a fresh-lease refusal; each durable transition remains one adapter transaction]
//! Spec: none
//!
//! PostgreSQL owns durable transitions and coupled writes. The bounded use case sequences
//! purpose-specific ports; it never mints ids, resolves routes, or owns provider wire DTOs.

use humaux_domain::{error::ErrorCode, evidence::EvidencePayloadSha256};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    consolidate::{ContentSha256, LogicalReasoningCallId, ProviderTraceRef, ReasoningIntentSha256},
    contribute::{
        ContributionCandidatePort, ContributionGate, PreparationSnapshot,
        PreparedAssessedContribution, PublicCoverageDigest,
    },
};

/// Stable workflow identity. It can only wrap a non-nil caller/repository supplied UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContributionExecutionId(Uuid);

impl ContributionExecutionId {
    pub fn try_from_uuid(value: Uuid) -> Result<Self, ErrorCode> {
        if value.is_nil() {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self(value))
    }

    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// The exact closed state set owned by migration 0131.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContributionExecutionState {
    ReadyA,
    AReserved,
    ReadyB,
    BReserved,
    ReadyCandidate,
    Done,
    NotContributable,
    RejectedSafety,
    FailedTerminal,
}

impl ContributionExecutionState {
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::ReadyA => "READY_A",
            Self::AReserved => "A_RESERVED",
            Self::ReadyB => "READY_B",
            Self::BReserved => "B_RESERVED",
            Self::ReadyCandidate => "READY_CANDIDATE",
            Self::Done => "DONE",
            Self::NotContributable => "NOT_CONTRIBUTABLE",
            Self::RejectedSafety => "REJECTED_SAFETY",
            Self::FailedTerminal => "FAILED_TERMINAL",
        }
    }

    pub fn try_from_db(value: &str) -> Result<Self, ErrorCode> {
        match value {
            "READY_A" => Ok(Self::ReadyA),
            "A_RESERVED" => Ok(Self::AReserved),
            "READY_B" => Ok(Self::ReadyB),
            "B_RESERVED" => Ok(Self::BReserved),
            "READY_CANDIDATE" => Ok(Self::ReadyCandidate),
            "DONE" => Ok(Self::Done),
            "NOT_CONTRIBUTABLE" => Ok(Self::NotContributable),
            "REJECTED_SAFETY" => Ok(Self::RejectedSafety),
            "FAILED_TERMINAL" => Ok(Self::FailedTerminal),
            _ => Err(ErrorCode::InvalidInput),
        }
    }
}

/// The two immutable execution stages. There is no generic/stringly call kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContributionExecutionStage {
    Coverage,
    Assessment,
}

/// Closed completion outcomes accepted by the 0131 A command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageCompletionOutcome {
    Usable,
    RejectedSafety,
    FailedTerminal,
}

impl CoverageCompletionOutcome {
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Usable => "USABLE",
            Self::RejectedSafety => "REJECTED_SAFETY",
            Self::FailedTerminal => "FAILED_TERMINAL",
        }
    }
}

/// Closed completion outcomes accepted by the 0131 B command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssessmentCompletionOutcome {
    ReadyCandidate,
    NotContributable,
    RejectedSafety,
    FailedTerminal,
}

impl AssessmentCompletionOutcome {
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::ReadyCandidate => "READY_CANDIDATE",
            Self::NotContributable => "NOT_CONTRIBUTABLE",
            Self::RejectedSafety => "REJECTED_SAFETY",
            Self::FailedTerminal => "FAILED_TERMINAL",
        }
    }
}

/// Caller-supplied logical A/B identities. Neither this type nor its users mint ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContributionLogicalCallIds {
    coverage: LogicalReasoningCallId,
    assessment: LogicalReasoningCallId,
}

impl ContributionLogicalCallIds {
    pub fn try_new(
        coverage: LogicalReasoningCallId,
        assessment: LogicalReasoningCallId,
    ) -> Result<Self, ErrorCode> {
        if coverage.0.is_nil() || assessment.0.is_nil() || coverage == assessment {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self {
            coverage,
            assessment,
        })
    }

    pub const fn coverage(self) -> LogicalReasoningCallId {
        self.coverage
    }

    pub const fn assessment(self) -> LogicalReasoningCallId {
        self.assessment
    }
}

/// Versioned immutable prompt contract persisted at enqueue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContributionPromptContract {
    version: i64,
    sha256: ContentSha256,
}

impl ContributionPromptContract {
    pub fn try_new(version: i64, sha256: ContentSha256) -> Result<Self, ErrorCode> {
        if version <= 0 {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self { version, sha256 })
    }

    pub const fn version(self) -> i64 {
        self.version
    }

    pub const fn sha256(self) -> ContentSha256 {
        self.sha256
    }
}

/// Immutable application value consumed by the authoritative enqueue SQL command.
pub struct ContributionExecutionEnqueueInput<Authorization> {
    idempotency_key: String,
    coverage_contract: ContributionPromptContract,
    assessment_contract: ContributionPromptContract,
    prepared: PreparedAssessedContribution<Authorization>,
}

impl<Authorization: Eq> ContributionExecutionEnqueueInput<Authorization> {
    pub fn try_new<C: ContributionCandidatePort<Authorization = Authorization> + ?Sized>(
        idempotency_key: String,
        coverage_contract: ContributionPromptContract,
        assessment_contract: ContributionPromptContract,
        prepared: PreparedAssessedContribution<Authorization>,
        candidates: &C,
    ) -> Result<Self, ErrorCode> {
        let preparation = prepared.preparation();
        if idempotency_key.trim().is_empty()
            || !candidates.has_user(&preparation.authorization)
            || preparation.sources.is_empty()
            || preparation.policy_version <= 0
            || preparation.reasoning.binding_version.0 <= 0
            || preparation.reasoning.input_manifest_hash != preparation.source_manifest_hash
            || preparation.reasoning.contribution_attempt.is_some()
        {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self {
            idempotency_key,
            coverage_contract,
            assessment_contract,
            prepared,
        })
    }

    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    pub const fn coverage_contract(&self) -> ContributionPromptContract {
        self.coverage_contract
    }

    pub const fn assessment_contract(&self) -> ContributionPromptContract {
        self.assessment_contract
    }

    pub const fn preparation(&self) -> &PreparationSnapshot<Authorization> {
        self.prepared.preparation()
    }

    pub const fn prepared(&self) -> &PreparedAssessedContribution<Authorization> {
        &self.prepared
    }
}

/// The six immutable axes which authorize one exact late completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExactContributionCallBinding {
    execution_id: ContributionExecutionId,
    stage: ContributionExecutionStage,
    model_call_id: Uuid,
    request_id: LogicalReasoningCallId,
    intent_sha256: ReasoningIntentSha256,
    disclosure_id: Uuid,
}

impl ExactContributionCallBinding {
    pub fn try_new(
        execution_id: ContributionExecutionId,
        stage: ContributionExecutionStage,
        model_call_id: Uuid,
        request_id: LogicalReasoningCallId,
        intent_sha256: ReasoningIntentSha256,
        disclosure_id: Uuid,
    ) -> Result<Self, ErrorCode> {
        if model_call_id.is_nil() || request_id.0.is_nil() || disclosure_id.is_nil() {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self {
            execution_id,
            stage,
            model_call_id,
            request_id,
            intent_sha256,
            disclosure_id,
        })
    }

    pub const fn execution_id(self) -> ContributionExecutionId {
        self.execution_id
    }

    pub const fn stage(self) -> ContributionExecutionStage {
        self.stage
    }

    pub const fn model_call_id(self) -> Uuid {
        self.model_call_id
    }

    pub const fn request_id(self) -> LogicalReasoningCallId {
        self.request_id
    }

    pub const fn intent_sha256(self) -> ReasoningIntentSha256 {
        self.intent_sha256
    }

    pub const fn disclosure_id(self) -> Uuid {
        self.disclosure_id
    }

    /// Fails closed on the first independently named mismatch axis.
    pub fn validate_completion(self, completion: Self) -> Result<(), ExactCompletionMismatch> {
        if self.execution_id != completion.execution_id {
            return Err(ExactCompletionMismatch::Execution);
        }
        if self.stage != completion.stage {
            return Err(ExactCompletionMismatch::Stage);
        }
        if self.model_call_id != completion.model_call_id {
            return Err(ExactCompletionMismatch::ModelCall);
        }
        if self.request_id != completion.request_id {
            return Err(ExactCompletionMismatch::Request);
        }
        if self.intent_sha256 != completion.intent_sha256 {
            return Err(ExactCompletionMismatch::Intent);
        }
        if self.disclosure_id != completion.disclosure_id {
            return Err(ExactCompletionMismatch::Disclosure);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExactCompletionMismatch {
    Execution,
    Stage,
    ModelCall,
    Request,
    Intent,
    Disclosure,
}

/// Trusted repository classification of a reservation lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistedReservationStatus {
    NewlyReserved,
    ExistingReserved,
}

/// Non-cloneable authority to perform the one provider dispatch created by a new reservation.
#[derive(Debug, PartialEq, Eq)]
pub struct ProviderDispatchPermit {
    reservation: ReservedContributionCall,
}

impl ProviderDispatchPermit {
    pub const fn binding(&self) -> ExactContributionCallBinding {
        self.reservation.binding
    }

    pub const fn reservation(&self) -> &ReservedContributionCall {
        &self.reservation
    }
}

/// Exact nine-column reserve result with the boolean translated into [`ReservationDecision`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedContributionCall {
    binding: ExactContributionCallBinding,
    processor_id: Option<String>,
    provider_model_id: Option<String>,
    model_revision: Option<String>,
    egress_processor_id: Option<Uuid>,
    credential_ref: Option<Uuid>,
}

impl ReservedContributionCall {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binding: ExactContributionCallBinding,
        processor_id: Option<String>,
        provider_model_id: Option<String>,
        model_revision: Option<String>,
        egress_processor_id: Option<Uuid>,
        credential_ref: Option<Uuid>,
    ) -> Self {
        Self {
            binding,
            processor_id,
            provider_model_id,
            model_revision,
            egress_processor_id,
            credential_ref,
        }
    }

    pub const fn binding(&self) -> ExactContributionCallBinding {
        self.binding
    }

    pub fn processor_id(&self) -> Option<&str> {
        self.processor_id.as_deref()
    }

    pub fn provider_model_id(&self) -> Option<&str> {
        self.provider_model_id.as_deref()
    }

    pub fn model_revision(&self) -> Option<&str> {
        self.model_revision.as_deref()
    }

    pub const fn egress_processor_id(&self) -> Option<Uuid> {
        self.egress_processor_id
    }

    pub const fn credential_ref(&self) -> Option<Uuid> {
        self.credential_ref
    }
}

/// Closed reservation result. An existing observation carries no dispatch authority.
#[derive(Debug, PartialEq, Eq)]
pub enum ReservationDecision {
    NewlyReserved(ProviderDispatchPermit),
    ExistingReserved(ReservedContributionCall),
}

impl ReservationDecision {
    /// Trusted conversion seam for the repository's closed persisted status.
    pub fn from_persisted(
        reservation: ReservedContributionCall,
        status: PersistedReservationStatus,
    ) -> Self {
        match status {
            PersistedReservationStatus::NewlyReserved => {
                Self::NewlyReserved(ProviderDispatchPermit { reservation })
            }
            PersistedReservationStatus::ExistingReserved => Self::ExistingReserved(reservation),
        }
    }

    pub fn dispatch_permit(self) -> Option<ProviderDispatchPermit> {
        match self {
            Self::NewlyReserved(permit) => Some(permit),
            Self::ExistingReserved(_) => None,
        }
    }

    pub const fn binding(&self) -> ExactContributionCallBinding {
        match self {
            Self::NewlyReserved(permit) => permit.reservation.binding,
            Self::ExistingReserved(reservation) => reservation.binding,
        }
    }
}

/// Exact scanner value carried to a coupled completion command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionScanReceipt {
    scan_receipt: serde_json::Value,
    scan_receipt_sha256: ContentSha256,
}

impl CompletionScanReceipt {
    pub fn try_new(
        scan_receipt: serde_json::Value,
        scan_receipt_sha256: ContentSha256,
    ) -> Result<Self, ErrorCode> {
        if !scan_receipt.is_object() {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self {
            scan_receipt,
            scan_receipt_sha256,
        })
    }

    pub const fn value(&self) -> &serde_json::Value {
        &self.scan_receipt
    }

    pub const fn sha256(&self) -> ContentSha256 {
        self.scan_receipt_sha256
    }
}

/// Successful A provider/scan receipt; B carries provider and candidate scan facts separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuccessfulCoverageReceipt {
    scan_receipt: CompletionScanReceipt,
    provider_trace: ProviderTraceRef,
    provider_request_id: Option<String>,
}

impl SuccessfulCoverageReceipt {
    pub fn try_new(
        scan_receipt: CompletionScanReceipt,
        provider_trace: ProviderTraceRef,
        provider_request_id: Option<String>,
    ) -> Result<Self, ErrorCode> {
        if provider_trace.0.trim().is_empty()
            || provider_request_id.as_deref().is_some_and(str::is_empty)
        {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self {
            scan_receipt,
            provider_trace,
            provider_request_id,
        })
    }

    pub const fn scan_receipt(&self) -> &CompletionScanReceipt {
        &self.scan_receipt
    }

    pub const fn provider_trace(&self) -> &ProviderTraceRef {
        &self.provider_trace
    }

    pub fn provider_request_id(&self) -> Option<&str> {
        self.provider_request_id.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefiniteProviderFailure {
    error_class: String,
    provider_request_id: Option<String>,
}

impl DefiniteProviderFailure {
    pub fn try_new(
        error_class: String,
        provider_request_id: Option<String>,
    ) -> Result<Self, ErrorCode> {
        if error_class.trim().is_empty()
            || provider_request_id.as_deref().is_some_and(str::is_empty)
        {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self {
            error_class,
            provider_request_id,
        })
    }

    pub fn error_class(&self) -> &str {
        &self.error_class
    }

    pub fn provider_request_id(&self) -> Option<&str> {
        self.provider_request_id.as_deref()
    }
}

/// Exact A completion payload; its variant fixes the SQL outcome string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverageCompletionValue {
    Usable {
        coverage_probe_sha256: EvidencePayloadSha256,
        coverage: PublicCoverageDigest,
        receipt: SuccessfulCoverageReceipt,
    },
    RejectedSafety(SuccessfulCoverageReceipt),
    FailedTerminal(DefiniteProviderFailure),
}

impl CoverageCompletionValue {
    pub const fn outcome(&self) -> CoverageCompletionOutcome {
        match self {
            Self::Usable { .. } => CoverageCompletionOutcome::Usable,
            Self::RejectedSafety(_) => CoverageCompletionOutcome::RejectedSafety,
            Self::FailedTerminal(_) => CoverageCompletionOutcome::FailedTerminal,
        }
    }
}

/// Immutable exact A completion command value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageCompletion {
    binding: ExactContributionCallBinding,
    value: CoverageCompletionValue,
}

impl CoverageCompletion {
    pub fn try_new(
        reserved: ExactContributionCallBinding,
        completion: ExactContributionCallBinding,
        value: CoverageCompletionValue,
    ) -> Result<Self, ExactCompletionMismatch> {
        reserved.validate_completion(completion)?;
        if completion.stage != ContributionExecutionStage::Coverage {
            return Err(ExactCompletionMismatch::Stage);
        }
        Ok(Self {
            binding: completion,
            value,
        })
    }

    pub const fn binding(&self) -> ExactContributionCallBinding {
        self.binding
    }

    pub const fn value(&self) -> &CoverageCompletionValue {
        &self.value
    }
}

/// Exact non-terminal B response, including its canonical bytes and raw four-gate result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssessmentCompletionEvidence {
    output_canonical: Vec<u8>,
    output_sha256: ContentSha256,
    novelty: ContributionGate,
    quality: ContributionGate,
    generality: ContributionGate,
    grounding: ContributionGate,
    provider_trace: ProviderTraceRef,
    provider_request_id: Option<String>,
}

impl AssessmentCompletionEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        output_canonical: Vec<u8>,
        output_sha256: ContentSha256,
        novelty: ContributionGate,
        quality: ContributionGate,
        generality: ContributionGate,
        grounding: ContributionGate,
        provider_trace: ProviderTraceRef,
        provider_request_id: Option<String>,
    ) -> Result<Self, ErrorCode> {
        if output_canonical.is_empty()
            || ContentSha256(Sha256::digest(&output_canonical).into()) != output_sha256
            || provider_trace.0.trim().is_empty()
            || provider_request_id.as_deref().is_some_and(str::is_empty)
        {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self {
            output_canonical,
            output_sha256,
            novelty,
            quality,
            generality,
            grounding,
            provider_trace,
            provider_request_id,
        })
    }

    pub fn output_canonical(&self) -> &[u8] {
        &self.output_canonical
    }

    pub const fn output_sha256(&self) -> ContentSha256 {
        self.output_sha256
    }

    pub const fn gates(&self) -> [ContributionGate; 4] {
        [self.novelty, self.quality, self.generality, self.grounding]
    }

    pub const fn provider_trace(&self) -> &ProviderTraceRef {
        &self.provider_trace
    }

    pub fn provider_request_id(&self) -> Option<&str> {
        self.provider_request_id.as_deref()
    }
}

/// Candidate/scan values present only for READY_CANDIDATE or REJECTED_SAFETY.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateCompletionEvidence {
    body: Vec<u8>,
    sha256: EvidencePayloadSha256,
    scan_receipt: CompletionScanReceipt,
}

impl CandidateCompletionEvidence {
    pub fn try_new(
        body: Vec<u8>,
        sha256: EvidencePayloadSha256,
        scan_receipt: CompletionScanReceipt,
    ) -> Result<Self, ErrorCode> {
        if body.is_empty() || humaux_domain::evidence::payload_sha256(&body) != sha256 {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self {
            body,
            sha256,
            scan_receipt,
        })
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub const fn sha256(&self) -> EvidencePayloadSha256 {
        self.sha256
    }

    pub const fn scan_receipt(&self) -> &CompletionScanReceipt {
        &self.scan_receipt
    }
}

/// Exact B completion payload; variants prevent impossible outcome/receipt combinations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssessmentCompletionValue {
    ReadyCandidate {
        assessment: AssessmentCompletionEvidence,
        candidate: CandidateCompletionEvidence,
    },
    NotContributable(AssessmentCompletionEvidence),
    RejectedSafety {
        assessment: AssessmentCompletionEvidence,
        candidate: CandidateCompletionEvidence,
    },
    FailedTerminal(DefiniteProviderFailure),
}

impl AssessmentCompletionValue {
    pub fn try_ready_candidate(
        assessment: AssessmentCompletionEvidence,
        candidate: CandidateCompletionEvidence,
    ) -> Result<Self, ErrorCode> {
        if assessment
            .gates()
            .iter()
            .any(|gate| *gate != ContributionGate::Pass)
        {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self::ReadyCandidate {
            assessment,
            candidate,
        })
    }

    pub fn try_not_contributable(
        assessment: AssessmentCompletionEvidence,
    ) -> Result<Self, ErrorCode> {
        if assessment
            .gates()
            .iter()
            .all(|gate| *gate == ContributionGate::Pass)
        {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self::NotContributable(assessment))
    }

    pub const fn outcome(&self) -> AssessmentCompletionOutcome {
        match self {
            Self::ReadyCandidate { .. } => AssessmentCompletionOutcome::ReadyCandidate,
            Self::NotContributable(_) => AssessmentCompletionOutcome::NotContributable,
            Self::RejectedSafety { .. } => AssessmentCompletionOutcome::RejectedSafety,
            Self::FailedTerminal(_) => AssessmentCompletionOutcome::FailedTerminal,
        }
    }
}

/// Immutable exact B completion command value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssessmentCompletion {
    binding: ExactContributionCallBinding,
    value: AssessmentCompletionValue,
}

impl AssessmentCompletion {
    pub fn try_new(
        reserved: ExactContributionCallBinding,
        completion: ExactContributionCallBinding,
        value: AssessmentCompletionValue,
    ) -> Result<Self, ExactCompletionMismatch> {
        reserved.validate_completion(completion)?;
        if completion.stage != ContributionExecutionStage::Assessment {
            return Err(ExactCompletionMismatch::Stage);
        }
        Ok(Self {
            binding: completion,
            value,
        })
    }

    pub const fn binding(&self) -> ExactContributionCallBinding {
        self.binding
    }

    pub const fn value(&self) -> &AssessmentCompletionValue {
        &self.value
    }
}

/// Durable enqueue receipt, without a database capability (ADR-0130 D2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnqueuedContributionExecution {
    pub execution_id: ContributionExecutionId,
    pub job_id: Uuid,
    pub logical_call_ids: ContributionLogicalCallIds,
    pub candidate_id: Uuid,
    pub created: bool,
}

/// Atomic MANUAL preparation and enqueue door; implementations own the whole transaction.
#[async_trait::async_trait]
pub trait ManualContributionPort: Send + Sync {
    /// Trusted scope accepted by the manual admission adapter.
    type Authorization: Send + Sync;

    /// Freeze trusted preparation and enqueue before any provider execution (ADR-0130 D7a).
    async fn start_manual(
        &self,
        request: crate::contribute::ContributionPreparationInput<Self::Authorization>,
        idempotency_key: String,
    ) -> Result<EnqueuedContributionExecution, ErrorCode>;
}

/// Admit an explicit contribution through the transaction-owning private boundary.
pub async fn start_manual_contribution<Authorization: Send + Sync>(
    port: &dyn ManualContributionPort<Authorization = Authorization>,
    request: crate::contribute::ContributionPreparationInput<Authorization>,
    idempotency_key: String,
) -> Result<EnqueuedContributionExecution, ErrorCode> {
    port.start_manual(request, idempotency_key).await
}

const CONTRIBUTION_JOB_TYPE: &str = "CONTRIBUTION_EXECUTE";
const CONTRIBUTION_JOB_SCHEMA_VERSION: u64 = 1;
const DEFINITE_PROVIDER_ERROR_CLASS: &str = "PROVIDER_PERMANENT";
/// Deployment-owned lease settings for one bounded claim.
#[derive(Debug, Clone, PartialEq)]
pub struct ContributionExecutionRunnerConfig {
    pub lease_owner: String,
    pub lease_seconds: f64,
    /// Ruling E3 (b): validity of a worker-observed health renewal
    /// (`HUMAUX_PRIVATE_WORKER_HEALTH_RENEW_SECS`, the same value distill and consolidation use).
    pub health_renew_seconds: i64,
}

impl ContributionExecutionRunnerConfig {
    pub fn validate(&self) -> Result<(), ErrorCode> {
        if self.lease_owner.trim().is_empty()
            || !self.lease_seconds.is_finite()
            || self.lease_seconds <= 0.0
            || self.health_renew_seconds <= 0
        {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(())
    }
}

/// Durable result of one bounded claim attempt. Provider-call counts are intentionally omitted:
/// the non-cloneable dispatch permit and recording-provider tests are the authority for that gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContributionRunOnceReport {
    Idle,
    Completed {
        execution_id: ContributionExecutionId,
        state: ContributionExecutionState,
    },
    LateCompleted {
        execution_id: ContributionExecutionId,
        state: ContributionExecutionState,
    },
    ReconciliationRequired {
        execution_id: ContributionExecutionId,
        state: ContributionExecutionState,
    },
}

/// Claimed contribution coordinates, without database capability (ADR-0130 D2).
#[derive(Debug, Clone)]
pub struct ContributionClaim {
    pub job_id: Uuid,
    pub tenant_id: Uuid,
    pub job_type: String,
    pub processing: bool,
    pub attempt: i32,
    pub lease_owner: Option<String>,
    pub has_lease_expiry: bool,
    pub has_stream_key: bool,
    pub has_stream_seq: bool,
    pub payload: serde_json::Value,
}
/// Only the persisted workflow identity/state crosses the use-case read boundary.
pub trait ContributionExecutionView {
    fn tenant_id(&self) -> Uuid;
    fn execution_id(&self) -> ContributionExecutionId;
    fn state(&self) -> ContributionExecutionState;
}
/// A finalized provider response exposes only its exact completion binding.
pub trait ContributionResponseView {
    fn binding(&self) -> ExactContributionCallBinding;
}
/// Dispatch classification; provider wire DTOs remain adapter-owned (ADR-0130 step 5).
pub enum ContributionDispatchResult<R> {
    Response(R),
    DefiniteTerminal {
        binding: ExactContributionCallBinding,
    },
    NonTerminal {
        binding: ExactContributionCallBinding,
        credential_rejected: bool,
    },
}
/// Existing worker failure classes, parameterized by the I/O boundary's preserved error.
#[derive(Debug)]
pub enum ContributionExecutionFailure<E> {
    Port(E),
    Domain(ErrorCode),
    InvalidClaim(&'static str),
    Invariant(&'static str),
}
impl<E> From<ErrorCode> for ContributionExecutionFailure<E> {
    fn from(error: ErrorCode) -> Self {
        Self::Domain(error)
    }
}
/// Contribution claim, admission, completion and recovery I/O (ADR-0130 D2/D7a).
/// Opaque associated values preserve sealed preparation, provider DTOs, and lease ownership.
#[async_trait::async_trait]
pub trait ContributionExecutionPort: Sync {
    type Error: Send;
    type Execution: ContributionExecutionView + Send + Sync;
    type Lease: Send + Sync;
    type Prepared: Send + Sync;
    type Response: ContributionResponseView + Send + Sync;
    fn lease(
        &self,
        job: Uuid,
        owner: String,
        attempt: i32,
    ) -> Result<Self::Lease, ContributionExecutionFailure<Self::Error>>;
    async fn load(
        &self,
        tenant: Uuid,
        id: ContributionExecutionId,
    ) -> Result<Option<Self::Execution>, ContributionExecutionFailure<Self::Error>>;
    async fn prepare_a(
        &self,
        execution: &Self::Execution,
    ) -> Result<Self::Prepared, ContributionExecutionFailure<Self::Error>>;
    async fn prepare_b(
        &self,
        execution: &Self::Execution,
    ) -> Result<Self::Prepared, ContributionExecutionFailure<Self::Error>>;
    async fn reserve_a_new(
        &self,
        tenant: Uuid,
        id: ContributionExecutionId,
        lease: &Self::Lease,
        prepared: &Self::Prepared,
    ) -> Result<ReservationDecision, ContributionExecutionFailure<Self::Error>>;
    async fn reserve_b_new(
        &self,
        tenant: Uuid,
        id: ContributionExecutionId,
        lease: &Self::Lease,
        prepared: &Self::Prepared,
    ) -> Result<ReservationDecision, ContributionExecutionFailure<Self::Error>>;
    async fn dispatch_prepared(
        &self,
        prepared: Self::Prepared,
        permit: ProviderDispatchPermit,
    ) -> Result<ContributionDispatchResult<Self::Response>, ContributionExecutionFailure<Self::Error>>;
    async fn coverage_value(
        &self,
        execution: &Self::Execution,
        response: &Self::Response,
    ) -> Result<CoverageCompletionValue, ContributionExecutionFailure<Self::Error>>;
    async fn assessment_value(
        &self,
        execution: &Self::Execution,
        response: &Self::Response,
    ) -> Result<AssessmentCompletionValue, ContributionExecutionFailure<Self::Error>>;
    async fn complete_a_exact(
        &self,
        tenant: Uuid,
        value: &CoverageCompletion,
        lease: Option<&Self::Lease>,
    ) -> Result<ContributionExecutionState, ContributionExecutionFailure<Self::Error>>;
    async fn complete_b_exact(
        &self,
        tenant: Uuid,
        value: &AssessmentCompletion,
        lease: Option<&Self::Lease>,
    ) -> Result<ContributionExecutionState, ContributionExecutionFailure<Self::Error>>;
    async fn commit_candidate(
        &self,
        tenant: Uuid,
        id: ContributionExecutionId,
        lease: &Self::Lease,
    ) -> Result<(), ContributionExecutionFailure<Self::Error>>;
    async fn settle_terminal_job(
        &self,
        tenant: Uuid,
        id: ContributionExecutionId,
        lease: &Self::Lease,
    ) -> Result<(), ContributionExecutionFailure<Self::Error>>;
    async fn mark_reconciliation_required(
        &self,
        tenant: Uuid,
        id: ContributionExecutionId,
        lease: &Self::Lease,
    ) -> Result<bool, ContributionExecutionFailure<Self::Error>>;
    fn is_fresh_lease_required(error: &ContributionExecutionFailure<Self::Error>) -> bool;
}
/// Claims the exact contribution job type from the process queue (ADR-0130 D2).
///
/// Completion and terminal settlement remain coupled to workflow writes in
/// `ContributionExecutionPort`. The contribution runner does not renew leases.
pub trait ContributionJobLease: Sync {
    /// Opaque queue failure for the process to translate.
    type Error: Send;

    /// Claim at most `limit` contribution jobs with the requested lease.
    fn claim(
        &self,
        tenant_id: Uuid,
        lease_owner: &str,
        lease_seconds: f64,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<ContributionClaim>, Self::Error>> + Send;
}

/// Consumer-owned health observation boundary; process assembly supplies its implementation.
pub trait ContributionRouteHealth: Sync {
    /// Best effort, after persistence; failure must never change job settlement (ADR-0060 E3).
    fn observe_route_health(
        &self,
        tenant: Uuid,
        call: Uuid,
        rejected: bool,
        seconds: i64,
    ) -> impl std::future::Future<Output = ()> + Send;
}
/// Bounded two-stage contribution use case; PostgreSQL still owns each state transition.
pub struct ContributionExecutionUseCase<'a, P, H> {
    port: &'a P,
    health: &'a H,
    config: ContributionExecutionRunnerConfig,
}
impl<'a, P: ContributionExecutionPort, H: ContributionRouteHealth>
    ContributionExecutionUseCase<'a, P, H>
{
    pub fn new(
        port: &'a P,
        health: &'a H,
        config: ContributionExecutionRunnerConfig,
    ) -> Result<Self, ErrorCode> {
        config.validate()?;
        Ok(Self {
            port,
            health,
            config,
        })
    }
    /// Claim at most one exact contribution job, then run its persisted workflow.
    pub async fn run_once<J, E>(
        &self,
        jobs: &J,
        tenant_id: Uuid,
    ) -> Result<ContributionRunOnceReport, E>
    where
        J: ContributionJobLease,
        E: From<J::Error> + From<ErrorCode> + From<ContributionExecutionFailure<P::Error>>,
    {
        if tenant_id.is_nil() {
            return Err(ErrorCode::InvalidInput.into());
        }
        let mut claimed = jobs
            .claim(
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
            return Err(ContributionExecutionFailure::<P::Error>::Invariant(
                "bounded claim returned more than one job",
            )
            .into());
        }
        self.run_claimed(tenant_id, job).await.map_err(E::from)
    }

    /// Runs the already claimed contribution while preserving the generation fence.
    pub async fn run_claimed(
        &self,
        tenant_id: Uuid,
        job: ContributionClaim,
    ) -> Result<ContributionRunOnceReport, ContributionExecutionFailure<P::Error>> {
        validate_claim(tenant_id, &self.config.lease_owner, &job)?;
        let execution_id = parse_execution_id(&job.payload)?;
        let lease = self.port.lease(
            job.job_id,
            job.lease_owner
                .ok_or(ContributionExecutionFailure::InvalidClaim(
                    "processing claim has no lease owner",
                ))?,
            job.attempt,
        )?;
        let repo = self.port;
        let execution = repo.load(tenant_id, execution_id).await?.ok_or(
            ContributionExecutionFailure::InvalidClaim("execution does not exist"),
        )?;
        if execution.tenant_id() != tenant_id || execution.execution_id() != execution_id {
            return Err(ContributionExecutionFailure::InvalidClaim(
                "job and execution identity mismatch",
            ));
        }
        self.run_execution(repo, execution, &lease).await
    }

    async fn run_execution(
        &self,
        repo: &P,
        execution: P::Execution,
        lease: &P::Lease,
    ) -> Result<ContributionRunOnceReport, ContributionExecutionFailure<P::Error>> {
        match execution.state() {
            ContributionExecutionState::ReadyA => self.run_a(repo, execution, lease).await,
            ContributionExecutionState::AReserved | ContributionExecutionState::BReserved => {
                self.reconcile(repo, &execution, lease).await
            }
            ContributionExecutionState::ReadyB => self.run_b(repo, execution, lease).await,
            ContributionExecutionState::ReadyCandidate => {
                repo.commit_candidate(execution.tenant_id(), execution.execution_id(), lease)
                    .await?;
                Ok(ContributionRunOnceReport::Completed {
                    execution_id: execution.execution_id(),
                    state: ContributionExecutionState::Done,
                })
            }
            state @ (ContributionExecutionState::NotContributable
            | ContributionExecutionState::RejectedSafety
            | ContributionExecutionState::FailedTerminal) => {
                repo.settle_terminal_job(execution.tenant_id(), execution.execution_id(), lease)
                    .await?;
                Ok(ContributionRunOnceReport::Completed {
                    execution_id: execution.execution_id(),
                    state,
                })
            }
            ContributionExecutionState::Done => Err(ContributionExecutionFailure::Invariant(
                "a PROCESSING claim cannot settle an already DONE execution",
            )),
        }
    }

    async fn run_a(
        &self,
        repo: &P,
        execution: P::Execution,
        lease: &P::Lease,
    ) -> Result<ContributionRunOnceReport, ContributionExecutionFailure<P::Error>> {
        let prepared = self.port.prepare_a(&execution).await?;

        let reservation = repo
            .reserve_a_new(
                execution.tenant_id(),
                execution.execution_id(),
                lease,
                &prepared,
            )
            .await?;
        let permit = match reservation {
            ReservationDecision::NewlyReserved(permit) => permit,
            ReservationDecision::ExistingReserved(_) => {
                return self.reconciliation_report(&execution);
            }
        };
        let reserved = permit.binding();
        let dispatched = match self.port.dispatch_prepared(prepared, permit).await {
            Ok(outcome) => outcome,
            Err(_) => return self.reconcile(repo, &execution, lease).await,
        };
        let (completion_binding, value) = match dispatched {
            ContributionDispatchResult::Response(response) => {
                let binding = response.binding();
                match self.port.coverage_value(&execution, &response).await {
                    Ok(value) => (binding, value),
                    Err(_) => return self.reconcile(repo, &execution, lease).await,
                }
            }
            ContributionDispatchResult::DefiniteTerminal { binding, .. } => {
                let failure = DefiniteProviderFailure::try_new(
                    DEFINITE_PROVIDER_ERROR_CLASS.to_owned(),
                    None,
                )?;
                let completion = CoverageCompletion::try_new(
                    reserved,
                    binding,
                    CoverageCompletionValue::FailedTerminal(failure),
                )
                .map_err(|_| ErrorCode::Conflict)?;
                return self
                    .complete_a(repo, &execution, lease, &completion, None)
                    .await;
            }
            ContributionDispatchResult::NonTerminal {
                binding,
                credential_rejected,
            } => {
                self.observe_rejected_key(&execution, binding.model_call_id(), credential_rejected)
                    .await;
                return self.reconcile(repo, &execution, lease).await;
            }
        };
        let completion = CoverageCompletion::try_new(reserved, completion_binding, value)
            .map_err(|_| ErrorCode::Conflict)?;
        self.complete_a(
            repo,
            &execution,
            lease,
            &completion,
            Some(completion_binding.model_call_id()),
        )
        .await
    }

    async fn complete_a(
        &self,
        repo: &P,
        execution: &P::Execution,
        lease: &P::Lease,
        completion: &CoverageCompletion,
        answered_call: Option<Uuid>,
    ) -> Result<ContributionRunOnceReport, ContributionExecutionFailure<P::Error>> {
        let (state, late) = self
            .complete_a_live_or_late(repo, execution.tenant_id(), completion, lease)
            .await?;
        self.observe_answered(execution, answered_call).await;
        if late {
            return Ok(ContributionRunOnceReport::LateCompleted {
                execution_id: execution.execution_id(),
                state,
            });
        }
        match state {
            ContributionExecutionState::ReadyB => {
                let next = repo
                    .load(execution.tenant_id(), execution.execution_id())
                    .await?
                    .ok_or(ContributionExecutionFailure::Invariant(
                        "A completion lost its execution",
                    ))?;
                self.run_b(repo, next, lease).await
            }
            ContributionExecutionState::RejectedSafety
            | ContributionExecutionState::FailedTerminal => {
                Ok(ContributionRunOnceReport::Completed {
                    execution_id: execution.execution_id(),
                    state,
                })
            }
            _ => Err(ContributionExecutionFailure::Invariant(
                "A completion returned an impossible state",
            )),
        }
    }

    async fn run_b(
        &self,
        repo: &P,
        execution: P::Execution,
        lease: &P::Lease,
    ) -> Result<ContributionRunOnceReport, ContributionExecutionFailure<P::Error>> {
        let prepared = self.port.prepare_b(&execution).await?;

        let reservation = repo
            .reserve_b_new(
                execution.tenant_id(),
                execution.execution_id(),
                lease,
                &prepared,
            )
            .await?;
        let permit = match reservation {
            ReservationDecision::NewlyReserved(permit) => permit,
            ReservationDecision::ExistingReserved(_) => {
                return self.reconciliation_report(&execution);
            }
        };
        let reserved = permit.binding();
        let dispatched = match self.port.dispatch_prepared(prepared, permit).await {
            Ok(outcome) => outcome,
            Err(_) => return self.reconcile(repo, &execution, lease).await,
        };
        let (completion_binding, value) = match dispatched {
            ContributionDispatchResult::Response(response) => {
                let binding = response.binding();
                match self.port.assessment_value(&execution, &response).await {
                    Ok(value) => (binding, value),
                    Err(_) => return self.reconcile(repo, &execution, lease).await,
                }
            }
            ContributionDispatchResult::DefiniteTerminal { binding, .. } => {
                let failure = DefiniteProviderFailure::try_new(
                    DEFINITE_PROVIDER_ERROR_CLASS.to_owned(),
                    None,
                )?;
                let completion = AssessmentCompletion::try_new(
                    reserved,
                    binding,
                    AssessmentCompletionValue::FailedTerminal(failure),
                )
                .map_err(|_| ErrorCode::Conflict)?;
                return self
                    .complete_b(repo, &execution, lease, &completion, None)
                    .await;
            }
            ContributionDispatchResult::NonTerminal {
                binding,
                credential_rejected,
            } => {
                self.observe_rejected_key(&execution, binding.model_call_id(), credential_rejected)
                    .await;
                return self.reconcile(repo, &execution, lease).await;
            }
        };
        let completion = AssessmentCompletion::try_new(reserved, completion_binding, value)
            .map_err(|_| ErrorCode::Conflict)?;
        self.complete_b(
            repo,
            &execution,
            lease,
            &completion,
            Some(completion_binding.model_call_id()),
        )
        .await
    }

    async fn complete_b(
        &self,
        repo: &P,
        execution: &P::Execution,
        lease: &P::Lease,
        completion: &AssessmentCompletion,
        answered_call: Option<Uuid>,
    ) -> Result<ContributionRunOnceReport, ContributionExecutionFailure<P::Error>> {
        let (state, late) = self
            .complete_b_live_or_late(repo, execution.tenant_id(), completion, lease)
            .await?;
        self.observe_answered(execution, answered_call).await;
        if late {
            return Ok(ContributionRunOnceReport::LateCompleted {
                execution_id: execution.execution_id(),
                state,
            });
        }
        match state {
            ContributionExecutionState::ReadyCandidate => {
                repo.commit_candidate(execution.tenant_id(), execution.execution_id(), lease)
                    .await?;
                Ok(ContributionRunOnceReport::Completed {
                    execution_id: execution.execution_id(),
                    state: ContributionExecutionState::Done,
                })
            }
            ContributionExecutionState::NotContributable
            | ContributionExecutionState::RejectedSafety
            | ContributionExecutionState::FailedTerminal => {
                Ok(ContributionRunOnceReport::Completed {
                    execution_id: execution.execution_id(),
                    state,
                })
            }
            _ => Err(ContributionExecutionFailure::Invariant(
                "B completion returned an impossible state",
            )),
        }
    }

    /// Ruling E3 (b): a call the provider answered (its row now SUCCEEDED) keeps its route's health
    /// alive, as distill and consolidation do.
    async fn observe_answered(&self, execution: &P::Execution, answered_call: Option<Uuid>) {
        if let Some(model_call_id) = answered_call {
            self.health
                .observe_route_health(
                    execution.tenant_id(),
                    model_call_id,
                    false,
                    self.config.health_renew_seconds,
                )
                .await;
        }
    }

    /// Ruling E3 (b): a key the provider refused (WAITING_KEY) denies the route's next admission
    /// at once; the row stays RESERVED for reconciliation (0131, observed there per 0209).
    async fn observe_rejected_key(
        &self,
        execution: &P::Execution,
        model_call_id: Uuid,
        credential_rejected: bool,
    ) {
        if credential_rejected {
            self.health
                .observe_route_health(
                    execution.tenant_id(),
                    model_call_id,
                    true,
                    self.config.health_renew_seconds,
                )
                .await;
        }
    }

    async fn reconcile(
        &self,
        repo: &P,
        execution: &P::Execution,
        lease: &P::Lease,
    ) -> Result<ContributionRunOnceReport, ContributionExecutionFailure<P::Error>> {
        if !repo
            .mark_reconciliation_required(execution.tenant_id(), execution.execution_id(), lease)
            .await?
        {
            return Err(ContributionExecutionFailure::Invariant(
                "reserved execution was not marked for reconciliation",
            ));
        }
        self.reconciliation_report(execution)
    }

    fn reconciliation_report(
        &self,
        execution: &P::Execution,
    ) -> Result<ContributionRunOnceReport, ContributionExecutionFailure<P::Error>> {
        if !matches!(
            execution.state(),
            ContributionExecutionState::AReserved | ContributionExecutionState::BReserved
        ) {
            // The in-memory read preceded reservation; only those two predecessor states are
            // legal here. Report the durable stage reached by that reservation explicitly.
            let state = match execution.state() {
                ContributionExecutionState::ReadyA => ContributionExecutionState::AReserved,
                ContributionExecutionState::ReadyB => ContributionExecutionState::BReserved,
                _ => {
                    return Err(ContributionExecutionFailure::Invariant(
                        "reconciliation requested outside a reservable state",
                    ));
                }
            };
            return Ok(ContributionRunOnceReport::ReconciliationRequired {
                execution_id: execution.execution_id(),
                state,
            });
        }
        Ok(ContributionRunOnceReport::ReconciliationRequired {
            execution_id: execution.execution_id(),
            state: execution.state(),
        })
    }

    async fn complete_a_live_or_late(
        &self,
        repo: &P,
        tenant_id: Uuid,
        completion: &CoverageCompletion,
        lease: &P::Lease,
    ) -> Result<(ContributionExecutionState, bool), ContributionExecutionFailure<P::Error>> {
        match repo
            .complete_a_exact(tenant_id, completion, Some(lease))
            .await
        {
            Ok(state) => Ok((state, false)),
            Err(error) if P::is_fresh_lease_required(&error) => repo
                .complete_a_exact(tenant_id, completion, None)
                .await
                .map(|state| (state, true)),
            Err(error) => Err(error),
        }
    }

    async fn complete_b_live_or_late(
        &self,
        repo: &P,
        tenant_id: Uuid,
        completion: &AssessmentCompletion,
        lease: &P::Lease,
    ) -> Result<(ContributionExecutionState, bool), ContributionExecutionFailure<P::Error>> {
        match repo
            .complete_b_exact(tenant_id, completion, Some(lease))
            .await
        {
            Ok(state) => Ok((state, false)),
            Err(error) if P::is_fresh_lease_required(&error) => repo
                .complete_b_exact(tenant_id, completion, None)
                .await
                .map(|state| (state, true)),
            Err(error) => Err(error),
        }
    }
}
fn validate_claim<E>(
    tenant_id: Uuid,
    lease_owner: &str,
    job: &ContributionClaim,
) -> Result<(), ContributionExecutionFailure<E>> {
    if job.tenant_id != tenant_id
        || job.job_type != CONTRIBUTION_JOB_TYPE
        || !job.processing
        || job.attempt <= 0
        || job.lease_owner.as_deref() != Some(lease_owner)
        || !job.has_lease_expiry
        || job.has_stream_key
        || job.has_stream_seq
    {
        return Err(ContributionExecutionFailure::InvalidClaim(
            "claim fields do not match the private contribution contract",
        ));
    }
    Ok(())
}

fn parse_execution_id<E>(
    payload: &serde_json::Value,
) -> Result<ContributionExecutionId, ContributionExecutionFailure<E>> {
    let object = payload
        .as_object()
        .filter(|object| object.len() == 2)
        .ok_or(ContributionExecutionFailure::InvalidClaim(
            "payload is not the exact contribution schema",
        ))?;
    if object
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        != Some(CONTRIBUTION_JOB_SCHEMA_VERSION)
    {
        return Err(ContributionExecutionFailure::InvalidClaim(
            "payload schema version is invalid",
        ));
    }
    let raw = object
        .get("execution_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(ContributionExecutionFailure::InvalidClaim(
            "payload execution id is invalid",
        ))?;
    let id = Uuid::parse_str(raw).map_err(|_| {
        ContributionExecutionFailure::InvalidClaim("payload execution id is invalid")
    })?;
    ContributionExecutionId::try_from_uuid(id).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    fn binding() -> ExactContributionCallBinding {
        ExactContributionCallBinding::try_new(
            ContributionExecutionId::try_from_uuid(id(1)).expect("execution"),
            ContributionExecutionStage::Coverage,
            id(2),
            LogicalReasoningCallId(id(3)),
            ReasoningIntentSha256([4; 32]),
            id(5),
        )
        .expect("binding")
    }

    fn reservation() -> ReservedContributionCall {
        ReservedContributionCall::new(binding(), None, None, None, None, None)
    }

    #[test]
    fn contribution_execution_requires_distinct_non_nil_logical_ids() {
        assert!(
            ContributionLogicalCallIds::try_new(
                LogicalReasoningCallId(Uuid::nil()),
                LogicalReasoningCallId(id(1)),
            )
            .is_err()
        );
        assert!(
            ContributionLogicalCallIds::try_new(
                LogicalReasoningCallId(id(1)),
                LogicalReasoningCallId(Uuid::nil()),
            )
            .is_err()
        );
        assert!(
            ContributionLogicalCallIds::try_new(
                LogicalReasoningCallId(id(1)),
                LogicalReasoningCallId(id(1)),
            )
            .is_err()
        );
        assert!(
            ContributionLogicalCallIds::try_new(
                LogicalReasoningCallId(id(1)),
                LogicalReasoningCallId(id(2)),
            )
            .is_ok()
        );
    }

    #[test]
    fn contribution_execution_permit_exists_only_for_new_reservation() {
        assert!(
            ReservationDecision::from_persisted(
                reservation(),
                PersistedReservationStatus::NewlyReserved
            )
            .dispatch_permit()
            .is_some()
        );
        assert!(
            ReservationDecision::from_persisted(
                reservation(),
                PersistedReservationStatus::ExistingReserved
            )
            .dispatch_permit()
            .is_none()
        );
    }

    #[test]
    fn contribution_execution_rejects_each_exact_completion_mismatch_axis() {
        let expected = binding();
        let cases = [
            (
                ExactContributionCallBinding::try_new(
                    ContributionExecutionId::try_from_uuid(id(9)).expect("execution"),
                    expected.stage,
                    expected.model_call_id,
                    expected.request_id,
                    expected.intent_sha256,
                    expected.disclosure_id,
                )
                .expect("binding"),
                ExactCompletionMismatch::Execution,
            ),
            (
                ExactContributionCallBinding::try_new(
                    expected.execution_id,
                    ContributionExecutionStage::Assessment,
                    expected.model_call_id,
                    expected.request_id,
                    expected.intent_sha256,
                    expected.disclosure_id,
                )
                .expect("binding"),
                ExactCompletionMismatch::Stage,
            ),
            (
                ExactContributionCallBinding::try_new(
                    expected.execution_id,
                    expected.stage,
                    id(9),
                    expected.request_id,
                    expected.intent_sha256,
                    expected.disclosure_id,
                )
                .expect("binding"),
                ExactCompletionMismatch::ModelCall,
            ),
            (
                ExactContributionCallBinding::try_new(
                    expected.execution_id,
                    expected.stage,
                    expected.model_call_id,
                    LogicalReasoningCallId(id(9)),
                    expected.intent_sha256,
                    expected.disclosure_id,
                )
                .expect("binding"),
                ExactCompletionMismatch::Request,
            ),
            (
                ExactContributionCallBinding::try_new(
                    expected.execution_id,
                    expected.stage,
                    expected.model_call_id,
                    expected.request_id,
                    ReasoningIntentSha256([9; 32]),
                    expected.disclosure_id,
                )
                .expect("binding"),
                ExactCompletionMismatch::Intent,
            ),
            (
                ExactContributionCallBinding::try_new(
                    expected.execution_id,
                    expected.stage,
                    expected.model_call_id,
                    expected.request_id,
                    expected.intent_sha256,
                    id(9),
                )
                .expect("binding"),
                ExactCompletionMismatch::Disclosure,
            ),
        ];

        for (actual, mismatch) in cases {
            assert_eq!(expected.validate_completion(actual), Err(mismatch));
        }
        assert_eq!(expected.validate_completion(expected), Ok(()));
    }
    #[test]
    fn config_and_payload_are_closed() {
        assert!(
            ContributionExecutionRunnerConfig {
                lease_owner: "worker-a".into(),
                lease_seconds: 30.0,
                health_renew_seconds: 1800,
            }
            .validate()
            .is_ok()
        );
        assert!(
            ContributionExecutionRunnerConfig {
                lease_owner: " ".into(),
                lease_seconds: 30.0,
                health_renew_seconds: 1800,
            }
            .validate()
            .is_err()
        );

        let id = Uuid::from_u128(1);
        let valid = serde_json::json!({"schema_version": 1, "execution_id": id.to_string()});
        assert_eq!(
            parse_execution_id::<()>(&valid)
                .expect("exact payload")
                .as_uuid(),
            id
        );
        for invalid in [
            serde_json::json!({"schema_version": 1, "execution_id": id.to_string(), "extra": true}),
            serde_json::json!({"schema_version": "1", "execution_id": id.to_string()}),
            serde_json::json!({"schema_version": 1, "execution_id": Uuid::nil().to_string()}),
        ] {
            assert!(parse_execution_id::<()>(&invalid).is_err());
        }
    }
}
