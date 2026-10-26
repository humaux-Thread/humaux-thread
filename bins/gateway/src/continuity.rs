//! `gateway::continuity` — Native `continuity.get` and `continuity.publish` application handlers.
//! Depends-on: crates=[humaux-adapters, humaux-application, humaux-domain,
//!   serde_json]; services=[]; env=[]; modules=[adapters::continuity_read, adapters::continuity_repo,
//!   adapters::postgres, application::continuity, domain::context, domain::continuity, domain::error,
//!   domain::identity, domain::ids]
//! Called-by: [gateway::mcp_application]
//! Invariants: [an unknown or unpublished continuity project yields the application-layer NotFound error, never a
//!   partial facet list; a publish hands the adapter's own in-transaction slot read to the compare-and-set and never
//!   a caller version (ADR-0094 D-C)]
//! Spec: Baseline §25.3.1; ADR-0094

use std::sync::Arc;

use humaux_adapters::{
    continuity_read::PostgresContinuityReadPort,
    continuity_repo::{
        self, ContinuityEvidenceSource, ContinuityMemorySource, PublishContinuityFacet,
        PublishFacetOutcome,
    },
    postgres::RuntimeDbPool,
};
use humaux_application::continuity::{ContinuityResult, read_project_continuity};
use humaux_domain::{
    context::ContextBudget,
    continuity::{ContinuityFacetKind, ContinuityPublishResult, ContinuityPublishState, ProjectId},
    error::{ConflictReason, ErrorCode},
    identity::AuthorizationScope,
    ids::WorkspaceId,
};
use serde_json::Value;

/// One validated `continuity.publish` input. The expected slot version is not a field: the
/// adapter reads it inside the write transaction (ADR-0094 D-C).
#[derive(Debug, Clone)]
pub struct PublishFacetCommand {
    pub project_id: ProjectId,
    pub workspace_id: WorkspaceId,
    pub facet_kind: ContinuityFacetKind,
    pub body: Value,
    pub memories: Vec<ContinuityMemorySource>,
    pub evidence: Vec<ContinuityEvidenceSource>,
    pub removals: Vec<String>,
}

/// The published immutable version together with the facet it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedFacet {
    pub project_id: ProjectId,
    pub facet_kind: ContinuityFacetKind,
    pub result: ContinuityPublishResult,
}

/// §52 D-B: a lost compare-and-set is a success-shaped `CONFLICT` with a typed sub-reason, the
/// same shape `memory.restore` refuses with (the frozen `ErrorCode` set carries no reason).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishOutcome {
    Published(PublishedFacet),
    Conflict {
        reason: ConflictReason,
        current_slot_version: i64,
    },
}

pub async fn get<T>(
    pool: Arc<RuntimeDbPool>,
    authorization: AuthorizationScope,
    project_id: ProjectId,
    requested_workspace: Option<WorkspaceId>,
    budget: ContextBudget,
    accept: impl FnOnce(ContinuityResult) -> Result<T, ErrorCode>,
) -> Result<T, ErrorCode> {
    let adapter = PostgresContinuityReadPort::new(pool);
    let result = read_project_continuity(
        &adapter,
        &authorization,
        project_id,
        requested_workspace,
        budget,
    )
    .await?;
    accept(result)
}

pub async fn publish(
    pool: Arc<RuntimeDbPool>,
    authorization: AuthorizationScope,
    command: PublishFacetCommand,
) -> Result<PublishOutcome, ErrorCode> {
    let repository_command = PublishContinuityFacet {
        workspace_id: command.workspace_id,
        project_id: command.project_id,
        facet_kind: command.facet_kind,
        published_state: ContinuityPublishState::Current,
        body: &command.body,
        memories: &command.memories,
        evidence: &command.evidence,
        removals: &command.removals,
    };
    let outcome =
        continuity_repo::publish_facet(&pool, &authorization, &repository_command).await?;
    Ok(match outcome {
        PublishFacetOutcome::Published(result) => PublishOutcome::Published(PublishedFacet {
            project_id: command.project_id,
            facet_kind: command.facet_kind,
            result,
        }),
        PublishFacetOutcome::Conflict {
            reason,
            current_slot_version,
        } => PublishOutcome::Conflict {
            reason,
            current_slot_version,
        },
    })
}
