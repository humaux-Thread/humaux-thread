//! `application::reasoning_route_admin` — Operator reasoning route commands and persistence port (ADR-0130 D2, SLICE-15c).
//! Depends-on: crates=[async-trait, serde, serde_json, uuid]; services=[]; env=[]; modules=[application::consolidate, application::membership_admin, application::operator_provisioning]
//! Called-by: [adapters::reasoning_route_admission, adapters::reasoning_route_onboarding, maintenance::main]
//! Invariants: [profile extras are opaque to application; the route door and success audit share a transaction]
//! Spec: ADR-0060 D-H; ADR-0130 D2

use async_trait::async_trait;
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use crate::consolidate::PrivateReasoningPurpose;
use crate::membership_admin::AdminAction;
use crate::operator_provisioning::{ProvisioningError, ReasoningCapability};

/// Failure from a reasoning-route administrative operation.
#[derive(Debug)]
pub enum ReasoningRouteError {
    /// Definite refusal, reported on stdout.
    Refused(String),
    /// Input rejected by the route adapter.
    InvalidInput(String),
    /// The adapter diagnostic with its original prefix.
    Infrastructure(String),
}

impl From<ReasoningRouteError> for ProvisioningError {
    fn from(error: ReasoningRouteError) -> Self {
        match error {
            ReasoningRouteError::Refused(reason) => Self::Refused(reason),
            ReasoningRouteError::InvalidInput(reason) => Self::InvalidInput(reason),
            ReasoningRouteError::Infrastructure(detail) => Self::Infrastructure(detail),
        }
    }
}

type Result<T> = std::result::Result<T, ReasoningRouteError>;

/// Parses a §11.2.3 purpose wire value over the closed [`PrivateReasoningPurpose`] set (the 0208
/// bind door, not this parser, decides which purposes are bindable: ADR-0060 D-H 2).
pub fn parse_purpose(wire: &str) -> Option<PrivateReasoningPurpose> {
    [
        PrivateReasoningPurpose::Distill,
        PrivateReasoningPurpose::Consolidate,
        PrivateReasoningPurpose::Vision,
        PrivateReasoningPurpose::ContributionDeidentify,
    ]
    .into_iter()
    .find(|p| purpose_db_value(*p) == wire)
}

/// §11.2.3 spelling shared by the operator CLI and the persistence adapter.
pub fn purpose_db_value(purpose: PrivateReasoningPurpose) -> &'static str {
    match purpose {
        PrivateReasoningPurpose::Distill => "PRIVATE_DISTILL_TEXT",
        PrivateReasoningPurpose::Consolidate => "PRIVATE_CONSOLIDATE",
        PrivateReasoningPurpose::Vision => "PRIVATE_DISTILL_VISION",
        PrivateReasoningPurpose::ContributionDeidentify => "CONTRIBUTION_DEIDENTIFY",
    }
}

/// One `reasoning register` request (ADR-0060 D-H 1).
#[derive(Debug, Clone)]
pub struct RegisterProfile<'a, Extras: ?Sized> {
    pub tenant_id: Uuid,
    pub owner_user_id: Uuid,
    pub processor_id: &'a str,
    pub provider_model_id: &'a str,
    /// Catalog label (ruling E5), never sent on the wire; `None` = the unlabelled catalog row.
    pub model_revision: Option<&'a str>,
    pub capabilities: &'a [ReasoningCapability],
    /// Research amendment 1: vendor request fields, refused by the 0206 CHECK if adapter-owned.
    pub request_extras: &'a Extras,
    /// The vendor account reference; only its sha256 is stored (ADR-0060 D-J).
    pub account_ref: &'a str,
    pub endpoint_ref: &'a str,
    pub region: &'a str,
    pub service_tier: &'a str,
    /// ADR-0060 D-L: the recipient uuid of this vendor/region, listed with its hosts in the worker env.
    pub egress_processor_id: Uuid,
    /// `None` mints a credential reference (its secret is the worker's env map entry, D-J).
    pub credential_ref: Option<Uuid>,
    /// `Some(profile_id)` registers the next version of that profile (a model switch, D-H).
    pub successor_of: Option<Uuid>,
}

/// `reasoning register` receipt.
#[derive(Debug, Clone, Serialize)]
pub struct RegisterReceipt {
    /// `created` or `existing`.
    pub outcome: String,
    pub tenant_id: Uuid,
    pub profile_id: Uuid,
    pub profile_version: i64,
    pub credential_ref: Uuid,
    pub provider_account_id: Uuid,
    pub endpoint_id: Uuid,
    pub processor_model_id: Uuid,
    /// The line to add to `HUMAUX_PRIVATE_WORKER_CREDENTIALS`; the operator names the variable.
    pub credential_map_entry: String,
    pub audit_event_id: Uuid,
}

/// `reasoning bind` receipt.
#[derive(Debug, Clone, Serialize)]
pub struct BindReceipt {
    /// `created`, `rebound` or `existing`.
    pub outcome: String,
    pub tenant_id: Uuid,
    pub reasoning_domain_id: Uuid,
    pub purpose: &'static str,
    pub binding_id: Uuid,
    pub binding_version: i64,
    pub route_policy_id: Uuid,
    /// The Binding@version a rebind closed.
    pub closed_binding_version: Option<i64>,
    pub audit_event_id: Uuid,
}

/// `reasoning attest-health` receipt.
#[derive(Debug, Clone, Serialize)]
pub struct AttestReceipt {
    pub outcome: &'static str,
    pub tenant_id: Uuid,
    pub profile_id: Uuid,
    pub profile_version: i64,
    pub provider_observation_id: i64,
    pub account_observation_id: i64,
    pub valid_until: String,
    pub audit_event_id: Uuid,
}

/// `reasoning profile-state` receipt.
#[derive(Debug, Clone, Serialize)]
pub struct ProfileStateReceipt {
    /// `updated` or `existing`.
    pub outcome: String,
    pub tenant_id: Uuid,
    pub profile_id: Uuid,
    pub profile_version: i64,
    pub enabled: bool,
    pub audit_event_id: Uuid,
}

/// Persistence boundary for the reasoning route operator doors.
#[async_trait]
pub trait ReasoningRoutePort: Sync {
    /// Adapter-owned request extras, forwarded untouched.
    type Extras: Sync + ?Sized;

    /// Executes `register_profile` through its existing persistence boundary.
    async fn register_profile(
        &self,
        request: &RegisterProfile<'_, Self::Extras>,
        admin: &AdminAction<'_>,
    ) -> Result<RegisterReceipt>;

    /// Executes `bind_domain` through its existing persistence boundary.
    async fn bind_domain(
        &self,
        tenant_id: Uuid,
        reasoning_domain_id: Uuid,
        purpose: PrivateReasoningPurpose,
        profile: (Uuid, i64),
        admin: &AdminAction<'_>,
    ) -> Result<BindReceipt>;

    /// Executes `attest_health` through its existing persistence boundary.
    async fn attest_health(
        &self,
        tenant_id: Uuid,
        profile: (Uuid, i64),
        valid_for_secs: i64,
        admin: &AdminAction<'_>,
    ) -> Result<AttestReceipt>;

    /// Executes `set_profile_enabled` through its existing persistence boundary.
    async fn set_profile_enabled(
        &self,
        tenant_id: Uuid,
        profile: (Uuid, i64),
        enabled: bool,
        admin: &AdminAction<'_>,
    ) -> Result<ProfileStateReceipt>;

    /// Executes `route_status` through its existing persistence boundary.
    async fn route_status(&self, tenant_id: Uuid) -> Result<Value>;
}

/// Registers the operator route profile and its success audit in one operation.
pub async fn register_profile<P: ReasoningRoutePort>(
    port: &P,
    request: &RegisterProfile<'_, P::Extras>,
    admin: &AdminAction<'_>,
) -> Result<RegisterReceipt> {
    port.register_profile(request, admin).await
}
