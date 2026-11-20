//! `application::login` — M02 D2 passwordless login challenge: the closed purpose set, the uniform start response and the
//!   verify outcome. Use cases own no SQL, mail transport, or clock.
//! Depends-on: crates=[async-trait, humaux-domain]; services=[]; env=[]; modules=[application::session, domain::error, domain::ids]
//! Called-by: [gateway::auth_pages, gateway::bootstrap, gateway::oauth_http, adapters::login_repo, adapters::session_repo, tests]
//! Invariants: [every start, whatever became of the mailbox, is answered with LoginStartResponse::UNIFORM; a verify is
//!   Accepted only for the one row the settle door consumed, and every other fate is the same Rejected]
//! Spec: §74.2; §74.3; §52; §78.1; §78.2
//!
//! Code generation, the keyed hash and the constant-time compare live in `application::auth`
//! (`generate_verification_code`, `CodeHash::verify`); TTL, attempt cap and resend cooldown are
//! `AuthConfig::login_challenge`. The adapter owns the transaction and the doors.

use humaux_domain::ids::UserId;

/// `control.email_challenges.purpose` — mirrors the CHECK list of migration 0266, both directions (§78.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengePurpose {
    /// §74.2 signup email verification.
    Signup,
    /// Passwordless sign-in (M02 D2).
    Login,
}

impl ChallengePurpose {
    /// Every variant, in CHECK order.
    pub const ALL: [ChallengePurpose; 2] = [Self::Signup, Self::Login];

    /// SQL CHECK spelling, verbatim.
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Signup => "SIGNUP",
            Self::Login => "LOGIN",
        }
    }
}

/// What a start request answers the caller, whatever happened to the mailbox (§74.3: no account
/// enumeration, in status or in body).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginStartResponse {
    /// HTTP status the route replies with.
    pub http_status: u16,
    /// Response body, byte for byte.
    pub body: &'static str,
}

impl LoginStartResponse {
    /// The only response a start request has.
    pub const UNIFORM: LoginStartResponse = LoginStartResponse {
        http_status: 202,
        body: r#"{"status":"code_requested"}"#,
    };
}

/// What a start request did, for the caller's own logs and metrics. Never reflected in the response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartDisposition {
    /// A code was stored and its mail enqueued.
    Issued,
    /// The mailbox is inside its resend cooldown; nothing was stored or enqueued.
    Throttled,
    /// No loginable account owns the mailbox; nothing was stored or enqueued.
    UnknownAccount,
    /// A code was stored but the outbox did not queue it (suppressed address, allowlist or replayed key).
    MailNotQueued,
}

/// A start request's answer plus its internal fate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginStartReceipt {
    /// Always [`LoginStartResponse::UNIFORM`].
    pub response: LoginStartResponse,
    /// Internal only.
    pub disposition: StartDisposition,
}

/// Result of one verify attempt. A wrong code, an unknown mailbox, an expired, consumed or exhausted
/// challenge are all the same `Rejected`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginVerifyOutcome {
    /// The code matched and consumed a live challenge of this user.
    Accepted(UserId),
    /// Anything else.
    Rejected,
}

/// A session issued after a consumed login challenge (§73.6); no verifier leaves the adapter.
#[derive(Debug)]
pub struct LoginSession {
    /// Secret delivered once in the session cookie.
    pub secret: crate::session::SessionSecret,
}

/// Passwordless login persistence boundary (ADR-0130 D5/D7a).
/// Each operation retains the existing adapter-owned transaction boundaries.
#[async_trait::async_trait]
pub trait PasswordlessLoginPort: Send + Sync {
    /// Issue a challenge and enqueue its mail in the same transaction.
    async fn start(
        &self,
        canonical_email: &str,
    ) -> Result<LoginStartReceipt, humaux_domain::error::ErrorCode>;
    /// Consume a challenge, then issue a session using the existing separate doors.
    async fn verify_session(
        &self,
        canonical_email: &str,
        candidate: &str,
    ) -> Result<Option<LoginSession>, humaux_domain::error::ErrorCode>;
    /// Resolve a live session and record its use with the database clock.
    async fn authenticate(
        &self,
        secret: &crate::session::SessionSecret,
    ) -> Result<Option<crate::session::VerifiedSession>, humaux_domain::error::ErrorCode>;
    /// Revoke a session after the inbound CSRF check.
    async fn revoke(
        &self,
        session_id: crate::session::SessionId,
    ) -> Result<bool, humaux_domain::error::ErrorCode>;
}

/// Start passwordless login; the receipt disposition remains internal (§74.3).
pub async fn start(
    port: &dyn PasswordlessLoginPort,
    canonical_email: &str,
) -> Result<LoginStartReceipt, humaux_domain::error::ErrorCode> {
    port.start(canonical_email).await
}

/// Verify once and mint a session only on the accepted outcome (§74.2).
pub async fn verify_session(
    port: &dyn PasswordlessLoginPort,
    canonical_email: &str,
    candidate: &str,
) -> Result<Option<LoginSession>, humaux_domain::error::ErrorCode> {
    port.verify_session(canonical_email, candidate).await
}

/// Resolve the live session before the inbound CSRF decision (§73.6).
pub async fn authenticate_session(
    port: &dyn PasswordlessLoginPort,
    secret: &crate::session::SessionSecret,
) -> Result<Option<crate::session::VerifiedSession>, humaux_domain::error::ErrorCode> {
    port.authenticate(secret).await
}

/// Revoke only the session selected by authenticated transport context (§73.6).
pub async fn revoke_session(
    port: &dyn PasswordlessLoginPort,
    session_id: crate::session::SessionId,
) -> Result<bool, humaux_domain::error::ErrorCode> {
    port.revoke(session_id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purposes_are_the_two_check_values_in_order() {
        let wire: Vec<&str> = ChallengePurpose::ALL
            .iter()
            .map(|p| p.as_db_str())
            .collect();
        assert_eq!(wire, vec!["SIGNUP", "LOGIN"]);
    }

    #[test]
    fn uniform_response_is_a_202_with_one_fixed_body() {
        assert_eq!(LoginStartResponse::UNIFORM.http_status, 202);
        assert_eq!(
            LoginStartResponse::UNIFORM.body,
            r#"{"status":"code_requested"}"#
        );
    }
}
