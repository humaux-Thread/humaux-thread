//! `application::bearer` — access-token authentication and live grant binding (M02 D3).
//! Depends-on: crates=[humaux-domain, time, uuid]; services=[]; env=[]; modules=[application::oauth, application::oauth_exchange, application::signed_token, domain::error]
//! Called-by: [application::api_key, gateway::auth, tests]
//! Invariants: [verify MAC and audience before lookup; a live grant and live workspace membership cap every request]
//! Spec: §6.1.1; §73.5; §83; M02 D3.

use humaux_domain::error::ErrorCode;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
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
        if terms.expires_at <= now || terms.resource != expected_resource {
            return Err(ErrorCode::Unauthorized);
        }
        Ok(Self(terms))
    }

    /// Lookup key for the live grant.
    pub fn grant_id(&self) -> Uuid {
        self.0.grant_id
    }

    pub(crate) fn into_live_terms(
        self,
        grant: &GrantRecord,
        now: OffsetDateTime,
    ) -> Result<AccessTerms, ErrorCode> {
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
        Ok(self.0)
    }
}
