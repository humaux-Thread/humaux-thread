//! `application::membership_admin` — one operator membership request and its audited outcome.
//! Depends-on: crates=[async-trait, humaux-domain, uuid]; services=[]; env=[]; modules=[domain::identity, domain::ids]
//! Called-by: [adapters::membership_repo, maintenance::member]
//! Invariants: [membership changes, epoch bumps and audit are delegated as one operation]
//! Spec: §6.3; §77; ADR-0033

use humaux_domain::identity::{MembershipMutation, MembershipRole, MembershipState};
use humaux_domain::ids::{TenantId, UserId};
use uuid::Uuid;

/// What the admin path may ask for: create a new `INVITED` row, or move an existing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipRequest {
    /// `INSERT ... state='INVITED'` with this role. The user row must already exist (users
    /// are minted by the §74 identity path, never here).
    Invite(MembershipRole),
    /// A §6.3 transition on the existing row.
    Mutate(MembershipMutation),
}

/// §77 "Sensitive Admin Action 必须包含" — the operator-supplied half of the audit row: who
/// acts, why, under which request/ticket, correlated to which trace, and what step-up
/// authentication gated the action. The admin path has no principal of its own, so none of
/// these can be derived; each must be non-empty (an empty reason is a missing reason, §78.1
/// forbids inventing a default). The other half (subject tenant/user, before/after) the repo
/// takes from the row it locks.
///
/// Not `domain::audit::SensitiveAdminAction`: that type carries the *finished* record
/// (subject + before/after `AuditMetadata`, whose closed key allowlist is `plan` /
/// `previous_role` / `role` and lives outside this card's files), not the operator input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminAction<'a> {
    pub actor: &'a str,
    pub reason: &'a str,
    /// Request/ticket reference — written as the row's `request_id`.
    pub ticket: &'a str,
    /// Correlation id for the operator's run; `xtask member` accepts one or mints one per
    /// invocation and prints it, so a refused attempt and its retry can be tied together.
    pub trace_id: &'a str,
    /// Opaque evidence of the step-up authentication that gated this action (§77 / §73).
    pub step_up_auth_context: &'a str,
}

/// The committed result of one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipOutcome {
    pub membership_id: Uuid,
    pub state: MembershipState,
    pub role: MembershipRole,
    /// The user's `security_epoch` after this request — `Some` only when the request bumped
    /// it (§6.3: suspend / remove / role change).
    pub user_security_epoch: Option<i64>,
    /// The §77 audit row appended in the same transaction.
    pub audit_event_id: Uuid,
}

/// Executes the membership transition and records its audit result.
#[async_trait::async_trait(?Send)]
pub trait MembershipAdminPort {
    /// Preserves the operator-facing refusal and trace.
    type Error;

    /// Apply a request to a single tenant and user.
    async fn apply_member(
        &self,
        tenant: TenantId,
        user: UserId,
        request: MembershipRequest,
        admin: AdminAction<'_>,
    ) -> Result<MembershipOutcome, Self::Error>;
}

/// Apply a membership request through the audited outbound port.
///
/// # Errors
/// Returns the adapter refusal or infrastructure error.
pub async fn apply<P: MembershipAdminPort>(
    port: &P,
    tenant: TenantId,
    user: UserId,
    request: MembershipRequest,
    admin: AdminAction<'_>,
) -> Result<MembershipOutcome, P::Error> {
    port.apply_member(tenant, user, request, admin).await
}
