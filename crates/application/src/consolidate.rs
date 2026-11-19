//! `application::consolidate` — Phase 4 T4.6+T4.7: Consolidation worker orchestration (§11.6-11.9, G11-1/G80-29).
//! Depends-on: crates=[async-trait, humaux-domain, sha2, tokio, uuid]; services=[]; env=[]; modules=[application::private_inference, domain::authority]
//! Called-by: [adapters::consolidate_repo, adapters::consolidation_reasoner, adapters::contribution_entry_repo, adapters::contribution_execution_repo, adapters::contribution_reasoner, adapters::distill_reasoner, adapters::distill_repo, adapters::model_call_ledger, adapters::private_inference_rpc, adapters::reasoning_route_admission, adapters::reasoning_route_onboarding, application::consolidation_execution, application::contribute, application::contribution_execution, application::distill_execution, application::reasoning_route_admin, consolidation-worker::inference_client, private-worker::bootstrap, private-worker::inference_rpc, tests]
//! Invariants: []
//! Spec: §11.6; §3; §78.3; §11.2.1
//!
//! Pure logic only: DB SQL for `private.memory_consolidation_*`
//! lives in `adapters::consolidate_repo` (through `ConsolidationDbPool`, never a bare
//! `sqlx::PgPool` — G6-DB1/G80-40), and the `ConsolidationRunState`/`AutoMutableMemoryId`/
//! rollup-authority-ceiling invariants live in `humaux_domain::consolidate` (no I/O there
//! either, §3/§78.3). This module is the seam between the two: the `PrivateReasoningPort`
//! boundary the worker calls through, and the pure run-state decisions built on top of it.

pub use crate::private_reasoning::{
    ContributionReasoningAttempt, PrivateReasoningError, PrivateReasoningPort,
    PrivateReasoningResult, SealedPrivateReasoningRequest,
};
use humaux_domain::authority::{AuthorityClass, EvidenceId, MemoryId};
pub use humaux_domain::consolidate::{
    AutoMutableMemoryId, ClassifiedMemoryId, ConsolidationRunState, RollupAuthorityViolation,
    check_rollup_authority_ceiling, classify,
};
pub use humaux_domain::reasoning_types::{
    ContentSha256, ContributionReasoningCallKind, LogicalReasoningCallId, PrivateReasoningDomainId,
    PrivateReasoningPurpose, ProviderTraceRef, ReasoningIntentSha256, ReasoningRouteBindingId,
    ReasoningRouteBindingVersion, UserReasoningProfileVersion,
};
use sha2::{Digest, Sha256};

/// Frozen schema for the semantic contribution intent committed by `intent_sha256`.
pub const CONTRIBUTION_REASONING_INTENT_SCHEMA_VERSION: u32 = 1;

const fn prompt_contract_version(call_kind: ContributionReasoningCallKind) -> u32 {
    match call_kind {
        ContributionReasoningCallKind::CoverageProbe
        | ContributionReasoningCallKind::TypedAssessment => 1,
    }
}

impl SealedPrivateReasoningRequest {
    fn contribution_reasoning_intent_sha256(
        self,
        call_kind: ContributionReasoningCallKind,
        coverage_digest: Option<ContentSha256>,
        intent_schema_version: u32,
    ) -> ReasoningIntentSha256 {
        let mut canonical = b"humaux.phase9.contribution-reasoning-intent\0".to_vec();
        canonical.extend_from_slice(b"intent_schema_version\0");
        canonical.extend_from_slice(&intent_schema_version.to_be_bytes());
        canonical.extend_from_slice(call_kind.as_db_str().as_bytes());
        canonical.push(0);
        canonical.extend_from_slice(b"CONTRIBUTION_DEIDENTIFY\0");
        canonical.extend_from_slice(self.reasoning_domain_id.0.as_bytes());
        canonical.extend_from_slice(self.binding_id.0.as_bytes());
        canonical.extend_from_slice(&self.binding_version.0.to_be_bytes());
        canonical.extend_from_slice(&self.input_manifest_hash.0);
        canonical.extend_from_slice(&prompt_contract_version(call_kind).to_be_bytes());
        match coverage_digest {
            Some(digest) => {
                canonical.push(1);
                canonical.extend_from_slice(&digest.0);
            }
            None => canonical.push(0),
        }
        ReasoningIntentSha256(Sha256::digest(canonical).into())
    }

    /// Binds a caller-carried logical id to the canonical contribution intent. The hash commits to
    /// semantic inputs only, so retries remain stable across fresh health/admission timestamps.
    pub fn with_contribution_attempt(
        mut self,
        logical_call_id: LogicalReasoningCallId,
        call_kind: ContributionReasoningCallKind,
        coverage_digest: Option<ContentSha256>,
    ) -> Self {
        self.contribution_attempt = Some(ContributionReasoningAttempt {
            logical_call_id,
            call_kind,
            intent_schema_version: CONTRIBUTION_REASONING_INTENT_SCHEMA_VERSION,
            intent_sha256: self.contribution_reasoning_intent_sha256(
                call_kind,
                coverage_digest,
                CONTRIBUTION_REASONING_INTENT_SCHEMA_VERSION,
            ),
        });
        self
    }

    pub fn contribution_attempt_is_canonical(self, coverage_digest: Option<ContentSha256>) -> bool {
        let Some(attempt) = self.contribution_attempt else {
            return false;
        };
        if attempt.logical_call_id.0.is_nil()
            || attempt.intent_schema_version != CONTRIBUTION_REASONING_INTENT_SCHEMA_VERSION
            || !matches!(
                (attempt.call_kind, coverage_digest),
                (ContributionReasoningCallKind::CoverageProbe, None)
                    | (ContributionReasoningCallKind::TypedAssessment, Some(_))
            )
        {
            return false;
        }
        let mut base = self;
        base.contribution_attempt = None;
        base.with_contribution_attempt(attempt.logical_call_id, attempt.call_kind, coverage_digest)
            .contribution_attempt
            == Some(attempt)
    }
}

/// Concrete provider work and health observation for the claimed inference path (§11.8).
pub trait ClaimedReasoningPort: Sync {
    /// Execute the consolidation run and return the admitted route and health observation.
    fn consolidate(
        &self,
        tenant_id: uuid::Uuid,
        run_id: uuid::Uuid,
        request: SealedPrivateReasoningRequest,
    ) -> impl std::future::Future<Output = Result<ConsolidationInference, &'static str>> + Send;

    /// Execute one request on the existing contribution reasoner.
    fn contribution(
        &self,
        request: SealedPrivateReasoningRequest,
    ) -> impl std::future::Future<
        Output = Result<Result<PrivateReasoningResult, PrivateReasoningError>, &'static str>,
    > + Send;

    /// Record worker-observed route health (ADR-0060 E3).
    fn observe_health(
        &self,
        tenant_id: uuid::Uuid,
        model_call_id: uuid::Uuid,
        credential_rejected: bool,
    ) -> impl std::future::Future<Output = ()> + Send;
}

/// Consolidation execution evidence from the admitted reasoner.
pub struct ConsolidationInference {
    pub result: Result<PrivateReasoningResult, PrivateReasoningError>,
    pub route: Option<String>,
    pub observed_call: Option<(uuid::Uuid, bool)>,
}

/// §11.8: choose the reasoner using only the claimed registration.
pub async fn infer_claimed(
    reasoning: &impl ClaimedReasoningPort,
    registration: &crate::private_inference::ClaimedRegistration,
) -> Result<
    (
        Result<PrivateReasoningResult, PrivateReasoningError>,
        Option<String>,
    ),
    &'static str,
> {
    let purpose = match registration.purpose.as_str() {
        "Distill" => PrivateReasoningPurpose::Distill,
        "Consolidate" => PrivateReasoningPurpose::Consolidate,
        "Vision" => PrivateReasoningPurpose::Vision,
        "ContributionDeidentify" => PrivateReasoningPurpose::ContributionDeidentify,
        _ => return Err("INVALID_REGISTRATION"),
    };
    let input_manifest_hash = registration
        .input_manifest_hash
        .as_slice()
        .try_into()
        .map_err(|_| "INVALID_REGISTRATION")?;
    let sealed = SealedPrivateReasoningRequest {
        reasoning_domain_id: PrivateReasoningDomainId(registration.reasoning_domain_id),
        binding_id: ReasoningRouteBindingId(registration.binding_id),
        binding_version: ReasoningRouteBindingVersion(registration.binding_version),
        input_manifest_hash: ContentSha256(input_manifest_hash),
        purpose,
        contribution_attempt: None,
    };
    match purpose {
        PrivateReasoningPurpose::Consolidate => {
            let run_id = registration
                .consolidation_run_id
                .ok_or("INVALID_REGISTRATION")?;
            let execution = reasoning
                .consolidate(registration.tenant_id, run_id, sealed)
                .await?;
            if let Some((model_call_id, credential_rejected)) = execution.observed_call {
                reasoning
                    .observe_health(registration.tenant_id, model_call_id, credential_rejected)
                    .await;
            }
            Ok((execution.result, execution.route))
        }
        PrivateReasoningPurpose::Distill
        | PrivateReasoningPurpose::Vision
        | PrivateReasoningPurpose::ContributionDeidentify => {
            Ok((reasoning.contribution(sealed).await?, None))
        }
    }
}

/// §11.7 Run State: what a caller who just finished [`adapters::consolidate_repo::
/// select_and_materialize_inputs`][select] should do next, given whether the snapshot
/// produced any candidates. Pure decision, no I/O — the actual `RUNNING`/`SUCCEEDED_NO_OUTPUT`
/// DB writes are the repo's job; this is the piece of logic a worker's control loop can unit
/// test without a database.
///
/// [select]: ../../humaux_adapters/consolidate_repo/fn.select_and_materialize_inputs.html
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextStep {
    /// Non-empty input set: call [`PrivateReasoningPort::infer`] next.
    RunInference,
    /// Empty input set: skip inference entirely and publish `SUCCEEDED_NO_OUTPUT` directly —
    /// §11.7 "健康终态，不得与 FAILED 混在一起", and there is nothing to send a `Distill`/
    /// `Consolidate` request about, so calling the port at all would just burn a BYOK request
    /// for a guaranteed-empty result (§11.5.1 "全自动不等于偷偷烧用户 BYOK").
    SkipToNoOutput,
}

pub fn next_step(input_count: usize) -> NextStep {
    if input_count == 0 {
        NextStep::SkipToNoOutput
    } else {
        NextStep::RunInference
    }
}

/// One source Memory's Authority, as the caller (which already holds each source's Authority
/// row for other reasons — it just read them to build the rollup content) reports it — used
/// only for [`validate_rollup_before_publish`]'s ceiling check, never persisted by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceAuthority {
    pub memory_id: MemoryId,
    pub evidence_id: EvidenceId,
    pub class: AuthorityClass,
}

/// §11.9 pre-publish gate: reject a rollup whose proposed class would outrank every source it
/// closes over, before `adapters::consolidate_repo::publish_rollup` ever runs — the repo layer
/// enforces the FK-based source closure (§11.6), this enforces the Authority ceiling (§11.9),
/// and the two checks are independent (see `RollupAuthorityViolation::NoSourceClosure`, which
/// this function surfaces for an empty `sources` too, though callers should already have
/// routed empty-sources runs to [`NextStep::SkipToNoOutput`] upstream).
pub fn validate_rollup_before_publish(
    rollup_class: AuthorityClass,
    sources: &[SourceAuthority],
) -> Result<(), RollupAuthorityViolation> {
    let classes: Vec<AuthorityClass> = sources.iter().map(|s| s.class).collect();
    check_rollup_authority_ceiling(rollup_class, &classes)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakePort {
        reply: Result<PrivateReasoningResult, PrivateReasoningError>,
    }

    #[async_trait::async_trait]
    impl PrivateReasoningPort for FakePort {
        async fn infer(
            &self,
            _req: SealedPrivateReasoningRequest,
        ) -> Result<PrivateReasoningResult, PrivateReasoningError> {
            self.reply.clone()
        }
    }

    /// G11-R1 positive sentinel (§11.8): `consolidation -> PrivateReasoningPort.infer() ->
    /// valid result`.
    #[tokio::test]
    async fn private_reasoning_port_positive_sentinel() {
        let port = FakePort {
            reply: Ok(PrivateReasoningResult {
                output_bytes: b"rollup text".to_vec(),
                output_sha256: ContentSha256([7u8; 32]),
                provider_trace: ProviderTraceRef("trace-1".into()),
                model_call_id: uuid::Uuid::from_u128(7),
                binding_id: ReasoningRouteBindingId(uuid::Uuid::from_u128(1)),
                binding_version: ReasoningRouteBindingVersion(1),
            }),
        };
        let req = SealedPrivateReasoningRequest {
            reasoning_domain_id: PrivateReasoningDomainId(uuid::Uuid::nil()),
            binding_id: ReasoningRouteBindingId(uuid::Uuid::from_u128(1)),
            binding_version: ReasoningRouteBindingVersion(1),
            input_manifest_hash: ContentSha256([1u8; 32]),
            purpose: PrivateReasoningPurpose::Consolidate,
            contribution_attempt: None,
        };
        let result = port.infer(req).await.expect("fake port succeeds");
        assert_eq!(result.output_bytes, b"rollup text");
    }

    #[test]
    fn contribution_attempt_shape_is_closed_and_a_b_intents_are_distinct() {
        let base = SealedPrivateReasoningRequest {
            reasoning_domain_id: PrivateReasoningDomainId(uuid::Uuid::from_u128(1)),
            binding_id: ReasoningRouteBindingId(uuid::Uuid::from_u128(2)),
            binding_version: ReasoningRouteBindingVersion(3),
            input_manifest_hash: ContentSha256([4; 32]),
            purpose: PrivateReasoningPurpose::ContributionDeidentify,
            contribution_attempt: None,
        };
        let coverage_id = LogicalReasoningCallId(uuid::Uuid::from_u128(5));
        let assessment_id = LogicalReasoningCallId(uuid::Uuid::from_u128(6));
        let coverage = base.with_contribution_attempt(
            coverage_id,
            ContributionReasoningCallKind::CoverageProbe,
            None,
        );
        let assessment = base.with_contribution_attempt(
            assessment_id,
            ContributionReasoningCallKind::TypedAssessment,
            Some(ContentSha256([7; 32])),
        );
        assert!(coverage.contribution_attempt_is_canonical(None));
        assert!(assessment.contribution_attempt_is_canonical(Some(ContentSha256([7; 32]))));
        assert_eq!(
            coverage
                .contribution_attempt
                .expect("coverage attempt")
                .intent_schema_version,
            CONTRIBUTION_REASONING_INTENT_SCHEMA_VERSION
        );
        assert_ne!(
            base.contribution_reasoning_intent_sha256(
                ContributionReasoningCallKind::CoverageProbe,
                None,
                CONTRIBUTION_REASONING_INTENT_SCHEMA_VERSION,
            ),
            base.contribution_reasoning_intent_sha256(
                ContributionReasoningCallKind::CoverageProbe,
                None,
                CONTRIBUTION_REASONING_INTENT_SCHEMA_VERSION + 1,
            )
        );
        assert_ne!(
            coverage
                .contribution_attempt
                .expect("coverage attempt")
                .logical_call_id,
            assessment
                .contribution_attempt
                .expect("assessment attempt")
                .logical_call_id
        );
        assert_ne!(
            coverage
                .contribution_attempt
                .expect("coverage attempt")
                .intent_sha256,
            assessment
                .contribution_attempt
                .expect("assessment attempt")
                .intent_sha256
        );
        assert!(!coverage.contribution_attempt_is_canonical(Some(ContentSha256([7; 32]))));
        assert!(!assessment.contribution_attempt_is_canonical(None));
        let nil_call = base.with_contribution_attempt(
            LogicalReasoningCallId(uuid::Uuid::nil()),
            ContributionReasoningCallKind::CoverageProbe,
            None,
        );
        assert!(!nil_call.contribution_attempt_is_canonical(None));
        let mut wrong_schema = coverage;
        wrong_schema
            .contribution_attempt
            .as_mut()
            .expect("coverage attempt")
            .intent_schema_version += 1;
        assert!(!wrong_schema.contribution_attempt_is_canonical(None));
    }

    #[test]
    fn next_step_empty_input_skips_inference() {
        assert_eq!(next_step(0), NextStep::SkipToNoOutput);
        assert_eq!(next_step(1), NextStep::RunInference);
        assert_eq!(next_step(160), NextStep::RunInference);
    }

    #[test]
    fn validate_rollup_before_publish_rejects_ceiling_violation() {
        let sources = [SourceAuthority {
            memory_id: MemoryId::new(),
            evidence_id: EvidenceId::new(),
            class: AuthorityClass::UserPreference,
        }];
        let err = validate_rollup_before_publish(AuthorityClass::ProjectConstraint, &sources)
            .unwrap_err();
        assert_eq!(
            err,
            RollupAuthorityViolation::ExceedsSource {
                rollup_class: AuthorityClass::ProjectConstraint,
                max_source_class: AuthorityClass::UserPreference,
            }
        );
    }

    #[test]
    fn validate_rollup_before_publish_accepts_ceiling_respected() {
        let sources = [SourceAuthority {
            memory_id: MemoryId::new(),
            evidence_id: EvidenceId::new(),
            class: AuthorityClass::ProjectDecision,
        }];
        assert!(validate_rollup_before_publish(AuthorityClass::UserPreference, &sources).is_ok());
    }
}
