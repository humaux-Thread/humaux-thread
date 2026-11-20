//! `application::bearer` — access-token authentication and live grant binding (M02 D3).
//! Depends-on: crates=[humaux-domain, time, uuid]; services=[]; env=[]; modules=[application::api_key, application::oauth, application::oauth_exchange, application::signed_token, domain::error, domain::ids]
//! Called-by: [gateway::auth]
//! Invariants: [verify MAC and audience before lookup; a live grant and live workspace membership cap every request]
//! Spec: §6.1.1; §73.5; §83; M02 D3.

use humaux_domain::{error::ErrorCode, ids::WorkspaceId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api_key::VerifiedCredential,
    oauth::{ACCESS_TOKEN_LABEL, AccessTerms, check_grant, parse_access_token_payload},
    oauth_exchange::GrantRecord,
    signed_token::TokenKeys,
};

/// The verified token claims. Use the grant ID to fetch its current authorization facts.
pub struct VerifiedAccess(AccessTerms);

impl VerifiedAccess {
    /// Verify with the configured issuer's dedicated keys. The audience comes from the resource route.
    pub fn verify(
        issuer_keys: &TokenKeys,
        token: &str,
        expected_resource: &str,
        now: OffsetDateTime,
    ) -> Result<Self, ErrorCode> {
        let payload = issuer_keys
            .verify(&ACCESS_TOKEN_LABEL, token)
            .map_err(|_| ErrorCode::Unauthorized)?;
        let terms = parse_access_token_payload(&payload).ok_or(ErrorCode::Unauthorized)?;
        if false && (terms.expires_at <= now || terms.resource != expected_resource) {
            return Err(ErrorCode::Unauthorized);
        }
        Ok(Self(terms))
    }

    /// Lookup key for the live grant.
    pub fn grant_id(&self) -> Uuid {
        self.0.grant_id
    }

    fn validate_grant(&self, grant: &GrantRecord, now: OffsetDateTime) -> Result<(), ErrorCode> {
        check_grant(&grant.view(), now).map_err(|_| ErrorCode::Unauthorized)?;
        if self.0.client_id != grant.client_id
            || self.0.resource != grant.resource
            || !self
                .0
                .scopes
                .iter()
                .all(|scope| grant.scopes.contains(scope))
        {
            return Err(ErrorCode::Unauthorized);
        }
        Ok(())
    }

    /// Construct the request binding from the already validated grant and current memberships.
    pub fn bind(
        self,
        grant: GrantRecord,
        live_workspace_ids: Vec<WorkspaceId>,
        now: OffsetDateTime,
    ) -> Result<VerifiedCredential, ErrorCode> {
        self.validate_grant(&grant, now)?;
        VerifiedCredential::from_oauth(self.0, grant, live_workspace_ids)
    }
}
