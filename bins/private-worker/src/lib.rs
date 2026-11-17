//! `humaux-private-worker` — Bounded Phase 9 private contribution worker orchestration.
//! Depends-on: crates=[humaux-application, humaux-domain]; services=[]; env=[]; modules=[application::contribute, application::contribution_execution, domain::error]
//! Called-by: [crate(humaux-consolidation-worker), tests]
//! Invariants: [the manual contribution command accepts the verified preparation and a caller idempotency key]
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
//! This library exposes the bounded contribution process API.

pub mod distill;
pub mod dsn;
pub mod inference_rpc;
pub mod route_providers;

mod bootstrap;
mod stages;

pub use bootstrap::{
    ContributionExecutionRunner, ContributionExecutionRunnerError, observe_route_health,
};
pub use humaux_application::contribution_execution::{
    ContributionExecutionRunnerConfig, ContributionRunOnceReport,
};
use humaux_application::{
    contribute::ContributionPreparationInput,
    contribution_execution::{
        EnqueuedContributionExecution, ManualContributionPort, start_manual_contribution,
    },
};
use humaux_domain::error::ErrorCode;

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
