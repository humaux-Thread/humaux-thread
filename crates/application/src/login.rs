//! `application::login` — M02 D2 passwordless login challenge: the closed purpose set, the uniform start response and the
//!   verify outcome. Pure: no SQL, no mail, no clock.
//! Depends-on: crates=[humaux-domain]; services=[]; env=[]; modules=[domain::ids]
//! Called-by: [adapters::login_repo, tests]
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
