//! `application::operator_provisioning` — Operator provisioning inputs, receipts and I/O ports (ADR-0130 D2, SLICE-15c).
//! Depends-on: crates=[async-trait, hex, humaux-domain, serde, serde_json, sha2, time, uuid]; services=[]; env=[]; modules=[application::membership_admin, domain::identity, domain::ticket_family]
//! Called-by: [adapters::provisioning, application::reasoning_route_admin, maintenance::bootstrap, maintenance::main]
//! Invariants: [the wire API key stays in the CLI; persistence and SQLSTATE handling stay in the adapter]
//! Spec: ADR-0053; ADR-0058; ADR-0060; ADR-0130 D2

use async_trait::async_trait;
use humaux_domain::identity::MembershipRole;
use humaux_domain::ticket_family::TicketFamily;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::membership_admin::AdminAction;

/// Failure categories of the operator commands (ADR-0053 D-F).
#[derive(Debug)]
pub enum ProvisioningError {
    /// Definite refusal, reported on stdout.
    Refused(String),
    /// Invalid input with the original detail.
    InvalidInput(String),
    /// Infrastructure failure with the original diagnostic text.
    Infrastructure(String),
}

impl ProvisioningError {
    /// Process exit code of this failure.
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Refused(_) => 3,
            Self::InvalidInput(_) => 2,
            Self::Infrastructure(_) => 1,
        }
    }
}

impl std::fmt::Display for ProvisioningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(reason) => write!(f, "refused: {reason}"),
            Self::InvalidInput(reason) => write!(f, "invalid input: {reason}"),
            Self::Infrastructure(detail) => f.write_str(detail),
        }
    }
}

impl std::error::Error for ProvisioningError {}

type Result<T> = std::result::Result<T, ProvisioningError>;

/// §11.2 "能力至少" closed set. `==` the capability CHECKs of `control.user_reasoning_profiles`,
/// `control.processor_models` and `control.reasoning_profiles` (last widened by
/// `migrations/0206_reasoning_route_runtime.sql`) — [`ReasoningCapability::as_str`] /
/// [`ReasoningCapability::parse`] are the §78.2 contract-test surface for those columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReasoningCapability {
    Text,
    Vision,
    StructuredOutput,
    TokenUsage,
    /// ADR-0058 D-M: the endpoint answers through one declared `tools` function (`tool_calls`).
    ToolCalls,
    /// ADR-0058 D-M: the endpoint accepts `"reasoning_split": true` and keeps its reasoning out of
    /// the answer. Superseded by the Profile's `request_extras` (ADR-0060 research amendment 1):
    /// it selects no request field any more and stays in the closed set for the rows that already
    /// declare it.
    ReasoningSplit,
    /// ADR-0060 research amendment 2: the endpoint answers `response_format: {"type":"json_object"}`.
    JsonObject,
}

impl ReasoningCapability {
    /// Every variant, in the order of the 0206 CHECK arrays.
    pub const ALL: [ReasoningCapability; 7] = [
        ReasoningCapability::Text,
        ReasoningCapability::Vision,
        ReasoningCapability::StructuredOutput,
        ReasoningCapability::TokenUsage,
        ReasoningCapability::ToolCalls,
        ReasoningCapability::ReasoningSplit,
        ReasoningCapability::JsonObject,
    ];

    /// The wire / DB value.
    pub const fn as_str(self) -> &'static str {
        match self {
            ReasoningCapability::Text => "TEXT",
            ReasoningCapability::Vision => "VISION",
            ReasoningCapability::StructuredOutput => "STRUCTURED_OUTPUT",
            ReasoningCapability::TokenUsage => "TOKEN_USAGE",
            ReasoningCapability::ToolCalls => "TOOL_CALLS",
            ReasoningCapability::ReasoningSplit => "REASONING_SPLIT",
            ReasoningCapability::JsonObject => "JSON_OBJECT",
        }
    }

    /// Inverse of [`Self::as_str`]; `None` for any value outside the closed set.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

impl std::fmt::Display for ReasoningCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One active 0117 admission-limit row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TierReceipt {
    /// `GLOBAL` | `REGION` | `TENANT` | `PURPOSE`.
    pub tier: &'static str,
    pub provider_id: String,
    pub region: Option<String>,
    pub purpose: Option<String>,
    pub tpm_limit: i64,
    pub rpm_limit: i64,
    /// Set only by the call that attempted the insert (`deploy-init`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<bool>,
}

/// `deploy-init`.
#[derive(Debug, Clone, Serialize)]
pub struct DeployInitReceipt {
    pub outcome: &'static str,
    pub tiers: Vec<TierReceipt>,
    pub audit_event_id: Option<Uuid>,
}

/// An API key as the receipt may show it: never the wire key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiKeyReceipt {
    pub api_key_id: Uuid,
    pub prefix: String,
    /// `edge::api_key_log_fingerprint` — prefix plus the first four hash bytes.
    pub fingerprint: String,
    pub created: bool,
}

/// The §17.3 placement row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlacementReceipt {
    pub projection_family: String,
    pub collection_name: String,
    pub created: bool,
}

/// The Qdrant collection a tenant's family points live in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CollectionReceipt {
    pub name: String,
    pub created: bool,
    pub dimension: u32,
    pub payload_indexes: Vec<String>,
    pub generation: String,
}

/// `onboard tenant`'s transactional part (T1).
#[derive(Debug, Clone, Serialize)]
pub struct TenantReceipt {
    pub outcome: &'static str,
    pub tenant_id: Uuid,
    pub tenant_name: String,
    pub owner_user_id: Uuid,
    pub owner_user_created: bool,
    pub workspace_id: Uuid,
    pub workspace_name: String,
    pub reasoning_domain_id: Uuid,
    pub api_key: Option<ApiKeyReceipt>,
    pub admission_tiers: Vec<TierReceipt>,
    pub placements: Vec<PlacementReceipt>,
    pub audit_event_id: Option<Uuid>,
}

/// `onboard workspace`'s transactional part.
#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceReceipt {
    pub outcome: &'static str,
    pub tenant_id: Uuid,
    pub workspace_id: Uuid,
    pub workspace_name: String,
    pub audit_event_id: Option<Uuid>,
}

/// One family's activation (ADR-0053 D-D).
#[derive(Debug, Clone, Serialize)]
pub struct ActivationReceipt {
    pub domain: &'static str,
    pub projection_kind: &'static str,
    pub projection_version: &'static str,
    /// `activated` | `existing` | `refused`.
    pub outcome: &'static str,
    pub reason: Option<String>,
    pub evidence: &'static str,
    pub collection: Option<String>,
    pub generation: Option<String>,
    pub probe_id: Option<Uuid>,
    pub probe_visible: Option<u64>,
    /// `GET /collections/{c}` + the exact count, milliseconds.
    pub probe_latency_ms: Option<u64>,
    /// The short activation transaction including the generation re-read, milliseconds.
    pub activation_txn_ms: Option<u64>,
    pub audit_event_id: Option<Uuid>,
}

/// `activate` over one workspace.
#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceActivation {
    pub tenant_id: Uuid,
    pub workspace_id: Uuid,
    pub activations: Vec<ActivationReceipt>,
    pub lifecycle: String,
}

impl WorkspaceActivation {
    /// The first refusal's reason, if any family was refused.
    pub fn refusal(&self) -> Option<&str> {
        self.activations
            .iter()
            .find(|a| a.outcome == "refused")
            .map(|a| a.reason.as_deref().unwrap_or("refused"))
    }

    /// Whether this operation activated a family.
    pub fn created(&self) -> bool {
        self.activations
            .iter()
            .any(|family| family.outcome == "activated")
    }
}

/// `apikey revoke`.
#[derive(Debug, Clone, Serialize)]
pub struct RevokeReceipt {
    pub outcome: &'static str,
    pub api_key_id: Uuid,
    pub prefix: String,
    pub changed: bool,
    pub audit_event_id: Option<Uuid>,
}

/// `onboard user`.
#[derive(Debug, Clone, Serialize)]
pub struct UserReceipt {
    pub outcome: &'static str,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub user_created: bool,
    pub membership_state: String,
    pub membership_role: String,
    pub workspace_id: Option<Uuid>,
}

/// A caller-minted API key: `prefix`, the §73.5 keyed hash of `"<prefix>.<secret>"`, and the log
/// fingerprint. The wire key itself never enters this module.
#[derive(Debug, Clone)]
pub struct NewApiKey {
    pub prefix: String,
    pub key_hash: Vec<u8>,
    pub fingerprint: String,
}

/// `"hx"` + the first 12 hex digits of `sha256(tenant_id ‖ 0x00 ‖ key_name)`: deterministic per
/// (tenant, key name), so re-running `apikey issue` / `onboard tenant` finds the same prefix and
/// answers `existing` instead of minting a second key.
pub fn api_key_prefix(tenant_id: Uuid, key_name: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(tenant_id.as_bytes());
    digest.update([0u8]);
    digest.update(key_name.as_bytes());
    let hex = hex::encode(digest.finalize());
    format!("hx{}", &hex[..12])
}

/// Everything `onboard tenant` writes in PostgreSQL besides the quota window and the activation.
#[derive(Debug, Clone)]
pub struct TenantRequest<'a> {
    pub name: &'a str,
    pub owner_email: &'a str,
    pub workspace_name: &'a str,
    pub reasoning_domain_name: &'a str,
    /// The plan the tenant is granted (`control.plans.plan_key`); the version must be offered (§71.1).
    pub plan_key: &'a str,
    /// The pinned version of [`Self::plan_key`].
    pub plan_version: i32,
    pub period_start: OffsetDateTime,
    pub period_end: OffsetDateTime,
    pub provider_id: &'a str,
    pub region: &'a str,
    pub tenant_tpm: i64,
    pub tenant_rpm: i64,
    pub scopes: &'a [String],
    /// The Qdrant collection the tenant's placement names.
    pub collection: &'a str,
}

/// Which DEAD `DERIVED_DISTILL` jobs of one tenant `jobs requeue-dead` re-arms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequeueTarget<'a> {
    /// Exactly this job; anything but a DEAD job of the tenant is refused.
    Job(Uuid),
    /// Every DEAD job of the tenant whose `last_error_class` equals this one exactly (the class a
    /// worker stored; ADR-0058 R4: chosen after the cause was fixed).
    ErrorClass(&'a str),
}

/// One job `jobs requeue-dead` re-armed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequeuedJob {
    pub job_id: Uuid,
    pub evidence_id: Uuid,
    /// Kept on the re-armed row (plan v2 OPS-3).
    pub last_error_class: Option<String>,
    /// The counted provider requests the job had spent when it died (reset to 0).
    pub attempt_spent: i32,
}

/// Why class-mode `jobs requeue-dead` left a matching DEAD job DEAD (ADR-0058 ruling 2026-10-02
/// 20:30: the skip is reported, never silent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequeueSkipReason {
    /// The Evidence has no outbox row: a re-armed job could only die again.
    EvidenceGone,
    /// The Evidence's outbox row is already DONE.
    OutboxSettled,
}

/// One matching DEAD job class-mode `jobs requeue-dead` left DEAD.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkippedJob {
    pub job_id: Uuid,
    /// `None` when the job's payload names no Evidence.
    pub evidence_id: Option<Uuid>,
    pub last_error_class: Option<String>,
    pub attempt_spent: i32,
    pub reason: RequeueSkipReason,
}

/// `jobs requeue-dead`.
#[derive(Debug, Clone, Serialize)]
pub struct RequeueReceipt {
    /// `requeued`, or `nothing_requeued` when every matching DEAD job was skipped.
    pub outcome: &'static str,
    pub tenant_id: Uuid,
    pub requeued: Vec<RequeuedJob>,
    /// Class mode only (job mode refuses instead): the matching DEAD jobs left DEAD, with why.
    pub skipped: Vec<SkippedJob>,
    pub audit_event_id: Uuid,
}

/// PostgreSQL provisioning commands. One port call preserves one existing adapter operation.
#[async_trait]
pub trait ProvisioningPort: Sync {
    /// Executes `deploy_init` through its existing persistence boundary.
    async fn deploy_init(
        &self,
        provider_id: &str,
        region: &str,
        tpm: i64,
        rpm: i64,
        admin: &AdminAction<'_>,
    ) -> Result<DeployInitReceipt>;

    /// Executes `onboard_tenant` through its existing persistence boundary.
    async fn onboard_tenant(
        &self,
        request: &TenantRequest<'_>,
        mint: &mut (dyn FnMut(Uuid) -> NewApiKey + Send),
        admin: &AdminAction<'_>,
    ) -> Result<TenantReceipt>;

    /// Executes `onboard_workspace` through its existing persistence boundary.
    async fn onboard_workspace(
        &self,
        tenant_id: Uuid,
        name: &str,
        owner_user_id: Uuid,
        admin: &AdminAction<'_>,
    ) -> Result<WorkspaceReceipt>;

    /// Executes `issue_api_key` through its existing persistence boundary.
    async fn issue_api_key(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        workspace_id: Uuid,
        key: &NewApiKey,
        scopes: &[String],
        admin: &AdminAction<'_>,
    ) -> Result<ApiKeyReceipt>;

    /// Executes `revoke_api_key` through its existing persistence boundary.
    async fn revoke_api_key(
        &self,
        tenant_id: Uuid,
        prefix: &str,
        admin: &AdminAction<'_>,
    ) -> Result<RevokeReceipt>;

    /// Executes `ensure_placement` through its existing persistence boundary.
    async fn ensure_placement(
        &self,
        tenant_id: Uuid,
        collection: &str,
        admin: &AdminAction<'_>,
    ) -> Result<Vec<PlacementReceipt>>;

    /// Executes `onboard_user` through its existing persistence boundary.
    async fn onboard_user(
        &self,
        tenant_id: Uuid,
        email: &str,
        role: MembershipRole,
        workspace_id: Option<Uuid>,
        admin: &AdminAction<'_>,
    ) -> Result<UserReceipt>;

    /// Executes `requeue_dead_distill` through its existing persistence boundary.
    async fn requeue_dead_distill(
        &self,
        tenant_id: Uuid,
        target: RequeueTarget<'_>,
        admin: &AdminAction<'_>,
    ) -> Result<RequeueReceipt>;

    /// Executes `status` through its existing persistence boundary.
    async fn status(&self, tenant_id: Uuid) -> Result<Value>;
}

/// Collection provisioning uses the configured same-cell Qdrant face.
#[async_trait]
pub trait CollectionProvisioningPort: Sync {
    /// Ensures the configured collection exists.
    async fn ensure_collection(
        &self,
        collection: &str,
        dimension: u32,
    ) -> Result<CollectionReceipt>;
}

/// Workspace activation observes the projection before crossing its existing PG write boundary.
#[async_trait]
pub trait WorkspaceActivationPort: Sync {
    /// Activates the selected family or all families for a workspace.
    async fn activate_workspace(
        &self,
        tenant_id: Uuid,
        workspace_id: Uuid,
        dimension: u32,
        only: Option<TicketFamily>,
        admin: &AdminAction<'_>,
    ) -> Result<WorkspaceActivation>;
}

/// Creates or finds the tenant and initial workspace in the existing onboarding transaction.
pub async fn onboard_tenant(
    port: &impl ProvisioningPort,
    request: &TenantRequest<'_>,
    mint: &mut (dyn FnMut(Uuid) -> NewApiKey + Send),
    admin: &AdminAction<'_>,
) -> Result<TenantReceipt> {
    port.onboard_tenant(request, mint, admin).await
}

/// Issues the key without passing its wire secret through persistence.
pub async fn issue_api_key(
    port: &impl ProvisioningPort,
    tenant_id: Uuid,
    user_id: Uuid,
    workspace_id: Uuid,
    key: &NewApiKey,
    scopes: &[String],
    admin: &AdminAction<'_>,
) -> Result<ApiKeyReceipt> {
    port.issue_api_key(tenant_id, user_id, workspace_id, key, scopes, admin)
        .await
}

/// Re-arms only the DEAD jobs selected by the operator.
pub async fn requeue_dead_distill(
    port: &impl ProvisioningPort,
    tenant_id: Uuid,
    target: RequeueTarget<'_>,
    admin: &AdminAction<'_>,
) -> Result<RequeueReceipt> {
    port.requeue_dead_distill(tenant_id, target, admin).await
}

/// Ensures the collection through its configured same-cell port.
pub async fn ensure_collection(
    port: &impl CollectionProvisioningPort,
    collection: &str,
    dimension: u32,
) -> Result<CollectionReceipt> {
    port.ensure_collection(collection, dimension).await
}

/// Activates the selected workspace families through the PG and Qdrant boundary.
pub async fn activate_workspace(
    port: &impl WorkspaceActivationPort,
    tenant_id: Uuid,
    workspace_id: Uuid,
    dimension: u32,
    only: Option<TicketFamily>,
    admin: &AdminAction<'_>,
) -> Result<WorkspaceActivation> {
    port.activate_workspace(tenant_id, workspace_id, dimension, only, admin)
        .await
}
