//! `public-pool::bootstrap` — Wire the operations-owned claim evaluator to the public repository.
//! Depends-on: crates=[async-trait, humaux-adapters, humaux-domain]; services=[]; env=[]; modules=[adapters::mechanism_observation, adapters::postgres, domain::error, domain::identity, public-pool::public_repo]
//! Called-by: [tests]
//! Invariants: [one public repository evaluation per port call; return the original error unchanged]
//! Spec: Baseline §12.6; ADR-0130 D2

use humaux_adapters::{
    mechanism_observation::{EvaluateClaim, EvaluationResult, PublicClaimEvaluator},
    postgres::PublicWorkerDbPool,
};
use humaux_domain::{error::ErrorCode, identity::AuthorizationScope};

use crate::public_repo;

/// Public repository implementation of the operations claim-evaluation port.
#[derive(Clone, Copy, Debug, Default)]
pub struct PublicRepoEvaluator;

#[async_trait::async_trait]
impl PublicClaimEvaluator for PublicRepoEvaluator {
    type Authorization = AuthorizationScope;

    async fn evaluate_claim(
        &self,
        pool: &PublicWorkerDbPool,
        authorization: &AuthorizationScope,
        input: &EvaluateClaim<'_>,
    ) -> Result<EvaluationResult, ErrorCode> {
        let request = public_repo::EvaluateClaim {
            claim_id: input.claim_id,
            expected_revision: input.expected_revision,
            expected_body_sha256: input.expected_body_sha256,
            policy_version: input.policy_version,
            rationale: input.rationale,
            target_state: input.target_state,
        };
        let result = public_repo::evaluate_claim(pool, authorization, &request).await?;
        Ok(EvaluationResult {
            evaluation_id: result.evaluation_id,
            object_revision: result.object_revision,
            moderation_state: result.moderation_state,
        })
    }
}
