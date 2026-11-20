//! `public-pool::public_repo::moderator_authorization` — Bind the moderation port to the authenticated identity scope (§12.6).
//! Depends-on: crates=[humaux-domain]; services=[]; env=[]; modules=[domain::identity, domain::ids, public-pool::public_repo]
//! Called-by: []
//! Invariants: [only the authenticated scope supplies the tenant and moderator identity]
//! Spec: Baseline §12.6; ADR-0131

use humaux_domain::{
    identity::AuthorizationScope,
    ids::{TenantId, UserId},
};

use super::{ModeratorAuthorization, sealed};

impl sealed::Sealed for AuthorizationScope {}

impl ModeratorAuthorization for AuthorizationScope {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id()
    }

    fn user_id(&self) -> Option<UserId> {
        self.user_id()
    }
}
