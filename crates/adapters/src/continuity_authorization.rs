//! `adapters::continuity_authorization` — trusted authorization bindings for the two Project Continuity PostgreSQL ports.
//! Depends-on: crates=[async-trait, humaux-domain, sqlx, uuid]; services=[]; env=[]; modules=[adapters::applicability_repo, adapters::confirm_token_repo, adapters::continuity_read, domain::error, domain::identity, domain::ids]
//! Called-by: []
//! Invariants: [scope decisions stay with identity and the canonical confirm-token helpers]
//! Spec: Baseline §6.1.1; ADR-0054 D-B; ADR-0131

use humaux_domain::{
    error::ErrorCode,
    identity::AuthorizationScope,
    ids::{TenantId, UserId, WorkspaceId},
};
use uuid::Uuid;

use crate::{
    applicability_repo::{ApplicabilityAuthorization, sealed},
    confirm_token_repo,
    continuity_read::ContinuityReadAuthorization,
};

impl sealed::Sealed for AuthorizationScope {}

#[async_trait::async_trait]
impl ApplicabilityAuthorization for AuthorizationScope {
    fn sole_workspace(&self) -> Result<WorkspaceId, ErrorCode> {
        confirm_token_repo::sole_workspace(self)
    }

    fn principal_id(&self) -> Uuid {
        self.principal().0
    }

    async fn install_in_txn(
        &self,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<(), ErrorCode> {
        confirm_token_repo::set_authorization_local(txn, self).await
    }
}

impl ContinuityReadAuthorization for AuthorizationScope {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id()
    }

    fn principal_id(&self) -> Uuid {
        self.principal().0
    }

    fn user_id(&self) -> Option<UserId> {
        self.user_id()
    }

    fn allowed_workspaces(&self) -> Vec<Uuid> {
        self.allowed_workspace_ids().iter().map(|id| id.0).collect()
    }

    fn narrow(&self, workspace: WorkspaceId) -> Result<Self, ErrorCode> {
        self.narrow(workspace)
    }
}
