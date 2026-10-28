//! `application::oauth` — M02 OAuth 2.1 authorization-server state machine: authorize-request validation, code issuance
//!   terms, code-exchange validation, refresh-rotation decisions and grant lifetime/epoch checks. Pure: no SQL, no clock,
//!   no randomness; `now`, row snapshots and every lifetime come in as arguments.
//! Depends-on: crates=[base64, humaux-domain, sha2, time, uuid]; services=[]; env=[]; modules=[application::signed_token, domain::error, domain::ids]
//! Called-by: [gateway::oauth_http, tests]
//! Invariants: [PKCE is S256 only; a redirect URI is accepted only when it is exactly registered and is https, loopback
//!   http or a private-use scheme; `resource` is mandatory and allowlisted; a reused refresh token yields a decision that
//!   revokes its family and grant; a grant is live only before its ceiling and while both epoch snapshots equal the live
//!   epochs; every refusal is an `ErrorCode` plus one row of `OAUTH_REASONS`, never a third error enum]
//! Spec: §6.2.1; §73.5; §52; §78.1; M02 D3; M02 D4; RFC 7636; RFC 8252 §7.3; RFC 8707
//!
//! The mirrors below (`ClientView`, `GrantView`, `RotationFact`, `CodeTerms`, `GrantTerms`) exist because
//! `adapters::oauth_repo` depends on this crate, not the reverse; the M02-10 HTTP layer converts between them field for
//! field. OAuth wire error strings live only in [`OAUTH_REASONS`]; the HTTP layer renders them.

use std::time::Duration;

use crate::signed_token::{FIELD_SEP, TokenLabel};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use humaux_domain::error::ErrorCode;
use humaux_domain::ids::{TenantId, UserId, WorkspaceId};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

/// Baseline recommended OAuth scopes: one application table (M02 §14).
pub const SUPPORTED_SCOPES: [&str; 5] = [
    "context:read",
    "memory:write",
    "artifact:manage",
    "code:manage",
    "coordination:manage",
];
/// M02 D3 domain separation; kid label follows the page-token convention.
pub const ACCESS_TOKEN_LABEL: TokenLabel = TokenLabel::new(b"oauth-at@1", b"oauth-at.kid@1");

/// M02 D3 claims; client is last so splitn(5) preserves every byte of its identifier.
pub fn access_token_payload(access: &AccessTerms) -> String {
    format!(
        "{}{FIELD_SEP}{}{FIELD_SEP}{}{FIELD_SEP}{}{FIELD_SEP}{}",
        access.grant_id,
        access.expires_at.unix_timestamp(),
        access.resource,
        access.scopes.join(" "),
        access.client_id
    )
}

/// Decodes claims only after the caller verifies the MAC (M02-12); validity still requires the live grant.
pub fn parse_access_token_payload(payload: &str) -> Option<AccessTerms> {
    let mut fields = payload.splitn(5, FIELD_SEP);
    Some(AccessTerms {
        grant_id: fields.next()?.parse().ok()?,
        expires_at: OffsetDateTime::from_unix_timestamp(fields.next()?.parse().ok()?).ok()?,
        resource: fields.next()?.to_owned(),
        scopes: fields
            .next()?
            .split_whitespace()
            .map(str::to_owned)
            .collect(),
        client_id: fields.next()?.to_owned(),
    })
}

/// RFC 7636 §4.1: a code verifier is 43..=128 unreserved characters.
const VERIFIER_LEN: std::ops::RangeInclusive<usize> = 43..=128;
/// RFC 7636 §4.2: an S256 challenge is the 43-character unpadded base64url of a 32-byte digest.
const S256_CHALLENGE_LEN: usize = 43;
/// The only `code_challenge_method` this server accepts (§73.5).
const PKCE_METHOD_S256: &str = "S256";
/// The only `response_type` this server accepts.
const RESPONSE_TYPE_CODE: &str = "code";
/// The only token-endpoint grant type that creates a grant.
const GRANT_TYPE_AUTHORIZATION_CODE: &str = "authorization_code";
/// RFC 8252 §7.3: the hosts for which a plain-http redirect is permitted.
const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "::1", "localhost"];
/// Schemes that must never be a redirect target, registered or not.
const FORBIDDEN_REDIRECT_SCHEMES: [&str; 6] =
    ["javascript", "data", "vbscript", "file", "blob", "about"];

/// A sub-reason attached to an [`ErrorCode`], same shape as `domain::error::ConflictReason` (§52 D-B): a frozen numeric
/// code, resolved through [`OAUTH_REASONS`]. The 20xx block is authorize, 21xx code exchange, 22xx refresh and grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OAuthReason(pub u16);

impl OAuthReason {
    /// Unknown, disabled or unrecognised client; never redirected.
    pub const CLIENT_UNKNOWN: Self = Self(2001);
    /// No `redirect_uri` in the authorize request.
    pub const REDIRECT_URI_MISSING: Self = Self(2002);
    /// Malformed redirect URI, one with a fragment or userinfo, or a forbidden scheme.
    pub const REDIRECT_URI_INVALID: Self = Self(2003);
    /// `http://` redirect whose host is not loopback (RFC 8252 §7.3).
    pub const REDIRECT_URI_INSECURE: Self = Self(2004);
    /// Redirect URI is not exactly one of the client's registered URIs.
    pub const REDIRECT_URI_MISMATCH: Self = Self(2005);
    /// `response_type` absent or not `code`.
    pub const RESPONSE_TYPE_UNSUPPORTED: Self = Self(2006);
    /// No `code_challenge`.
    pub const PKCE_REQUIRED: Self = Self(2007);
    /// `code_challenge_method` absent or not `S256` (`plain` is refused).
    pub const PKCE_METHOD_UNSUPPORTED: Self = Self(2008);
    /// `code_challenge` is not a 43-character base64url string.
    pub const PKCE_CHALLENGE_MALFORMED: Self = Self(2009);
    /// No `resource` (RFC 8707).
    pub const RESOURCE_REQUIRED: Self = Self(2010);
    /// `resource` is not on the allowlist.
    pub const RESOURCE_UNKNOWN: Self = Self(2011);
    /// No scope requested.
    pub const SCOPE_REQUIRED: Self = Self(2012);
    /// A requested scope is not supported.
    pub const SCOPE_UNSUPPORTED: Self = Self(2013);
    /// Token request `grant_type` is not `authorization_code`.
    pub const GRANT_TYPE_UNSUPPORTED: Self = Self(2101);
    /// Code unknown, already used or expired (the door consumed nothing).
    pub const CODE_INVALID: Self = Self(2102);
    /// Token request `client_id` differs from the code's.
    pub const CODE_CLIENT_MISMATCH: Self = Self(2103);
    /// Token request `redirect_uri` is absent or differs from the code's.
    pub const CODE_REDIRECT_MISMATCH: Self = Self(2104);
    /// No `code_verifier`.
    pub const VERIFIER_MISSING: Self = Self(2105);
    /// `code_verifier` violates RFC 7636 §4.1.
    pub const VERIFIER_MALFORMED: Self = Self(2106);
    /// `S256(code_verifier)` differs from the stored challenge.
    pub const VERIFIER_MISMATCH: Self = Self(2107);
    /// Token request `resource` differs from the code's.
    pub const CODE_RESOURCE_MISMATCH: Self = Self(2108);
    /// Refresh token unknown, expired or revoked.
    pub const REFRESH_REJECTED: Self = Self(2201);
    /// A rotated refresh token was presented again.
    pub const REFRESH_REUSED: Self = Self(2202);
    /// Grant revoked, or in a status this build does not know.
    pub const GRANT_CLOSED: Self = Self(2203);
    /// Grant is past `grant_max_expires_at`.
    pub const GRANT_EXPIRED: Self = Self(2204);
    /// A security epoch moved past the grant's snapshot.
    pub const GRANT_EPOCH_STALE: Self = Self(2205);
    /// Refresh request `client_id` differs from the grant's.
    pub const REFRESH_CLIENT_MISMATCH: Self = Self(2206);
    /// Refresh request `resource` differs from the grant's.
    pub const REFRESH_RESOURCE_MISMATCH: Self = Self(2207);

    /// The raw numeric reason.
    pub const fn code(self) -> u16 {
        self.0
    }

    /// The table row of this reason; `None` for a number no row defines.
    pub fn row(self) -> Option<&'static ReasonRow> {
        OAUTH_REASONS.iter().find(|row| row.reason == self)
    }
}

/// One row of [`OAUTH_REASONS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReasonRow {
    /// The sub-reason.
    pub reason: OAuthReason,
    /// SCREAMING_SNAKE label, as `ConflictReason::label`.
    pub label: &'static str,
    /// RFC 6749 §5.2 / RFC 8707 `error` value the HTTP layer renders (M02-10 owns the response shape).
    pub wire_error: &'static str,
    /// The terminal `ErrorCode` this reason travels under.
    pub code: ErrorCode,
}

const fn row(
    reason: OAuthReason,
    label: &'static str,
    wire_error: &'static str,
    code: ErrorCode,
) -> ReasonRow {
    ReasonRow {
        reason,
        label,
        wire_error,
        code,
    }
}

/// The one table mapping every [`OAuthReason`] to its label, OAuth wire `error` string and `ErrorCode`.
pub const OAUTH_REASONS: [ReasonRow; 28] = [
    row(
        OAuthReason::CLIENT_UNKNOWN,
        "CLIENT_UNKNOWN",
        "invalid_request",
        ErrorCode::InvalidInput,
    ),
    row(
        OAuthReason::REDIRECT_URI_MISSING,
        "REDIRECT_URI_MISSING",
        "invalid_request",
        ErrorCode::InvalidInput,
    ),
    row(
        OAuthReason::REDIRECT_URI_INVALID,
        "REDIRECT_URI_INVALID",
        "invalid_request",
        ErrorCode::InvalidInput,
    ),
    row(
        OAuthReason::REDIRECT_URI_INSECURE,
        "REDIRECT_URI_INSECURE",
        "invalid_request",
        ErrorCode::InvalidInput,
    ),
    row(
        OAuthReason::REDIRECT_URI_MISMATCH,
        "REDIRECT_URI_MISMATCH",
        "invalid_request",
        ErrorCode::InvalidInput,
    ),
    row(
        OAuthReason::RESPONSE_TYPE_UNSUPPORTED,
        "RESPONSE_TYPE_UNSUPPORTED",
        "unsupported_response_type",
        ErrorCode::InvalidInput,
    ),
    row(
        OAuthReason::PKCE_REQUIRED,
        "PKCE_REQUIRED",
        "invalid_request",
        ErrorCode::InvalidInput,
    ),
    row(
        OAuthReason::PKCE_METHOD_UNSUPPORTED,
        "PKCE_METHOD_UNSUPPORTED",
        "invalid_request",
        ErrorCode::InvalidInput,
    ),
    row(
        OAuthReason::PKCE_CHALLENGE_MALFORMED,
        "PKCE_CHALLENGE_MALFORMED",
        "invalid_request",
        ErrorCode::InvalidInput,
    ),
    row(
        OAuthReason::RESOURCE_REQUIRED,
        "RESOURCE_REQUIRED",
        "invalid_request",
        ErrorCode::InvalidInput,
    ),
    row(
        OAuthReason::RESOURCE_UNKNOWN,
        "RESOURCE_UNKNOWN",
        "invalid_target",
        ErrorCode::InvalidInput,
    ),
    row(
        OAuthReason::SCOPE_REQUIRED,
        "SCOPE_REQUIRED",
        "invalid_scope",
        ErrorCode::InvalidInput,
    ),
    row(
        OAuthReason::SCOPE_UNSUPPORTED,
        "SCOPE_UNSUPPORTED",
        "invalid_scope",
        ErrorCode::InvalidInput,
    ),
    row(
        OAuthReason::GRANT_TYPE_UNSUPPORTED,
        "GRANT_TYPE_UNSUPPORTED",
        "unsupported_grant_type",
        ErrorCode::InvalidInput,
    ),
    row(
        OAuthReason::CODE_INVALID,
        "CODE_INVALID",
        "invalid_grant",
        ErrorCode::InvalidInput,
    ),
    row(
        OAuthReason::CODE_CLIENT_MISMATCH,
        "CODE_CLIENT_MISMATCH",
        "invalid_grant",
        ErrorCode::InvalidInput,
    ),
    row(
        OAuthReason::CODE_REDIRECT_MISMATCH,
        "CODE_REDIRECT_MISMATCH",
        "invalid_grant",
        ErrorCode::InvalidInput,
    ),
    row(
        OAuthReason::VERIFIER_MISSING,
        "VERIFIER_MISSING",
        "invalid_request",
        ErrorCode::InvalidInput,
    ),
    row(
        OAuthReason::VERIFIER_MALFORMED,
        "VERIFIER_MALFORMED",
        "invalid_grant",
        ErrorCode::InvalidInput,
    ),
    row(
        OAuthReason::VERIFIER_MISMATCH,
        "VERIFIER_MISMATCH",
        "invalid_grant",
        ErrorCode::InvalidInput,
    ),
    row(
        OAuthReason::CODE_RESOURCE_MISMATCH,
        "CODE_RESOURCE_MISMATCH",
        "invalid_target",
        ErrorCode::InvalidInput,
    ),
    row(
        OAuthReason::REFRESH_REJECTED,
        "REFRESH_REJECTED",
        "invalid_grant",
        ErrorCode::Unauthorized,
    ),
    row(
        OAuthReason::REFRESH_REUSED,
        "REFRESH_REUSED",
        "invalid_grant",
        ErrorCode::Unauthorized,
    ),
    row(
        OAuthReason::GRANT_CLOSED,
        "GRANT_CLOSED",
        "invalid_grant",
        ErrorCode::Unauthorized,
    ),
    row(
        OAuthReason::GRANT_EXPIRED,
        "GRANT_EXPIRED",
        "invalid_grant",
        ErrorCode::Unauthorized,
    ),
    row(
        OAuthReason::GRANT_EPOCH_STALE,
        "GRANT_EPOCH_STALE",
        "invalid_grant",
        ErrorCode::Unauthorized,
    ),
    row(
        OAuthReason::REFRESH_CLIENT_MISMATCH,
        "REFRESH_CLIENT_MISMATCH",
        "invalid_grant",
        ErrorCode::Unauthorized,
    ),
    row(
        OAuthReason::REFRESH_RESOURCE_MISMATCH,
        "REFRESH_RESOURCE_MISMATCH",
        "invalid_target",
        ErrorCode::Unauthorized,
    ),
];

/// A refusal: the terminal [`ErrorCode`] and the [`OAuthReason`] under it (§52 D-B shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OAuthRefusal {
    /// Terminal error class.
    pub code: ErrorCode,
    /// Sub-reason; resolves through [`OAUTH_REASONS`].
    pub reason: OAuthReason,
}

impl OAuthRefusal {
    /// The refusal of `reason`, with the `ErrorCode` its table row names (`Internal` for a number no row defines).
    pub fn of(reason: OAuthReason) -> Self {
        let code = reason.row().map_or(ErrorCode::Internal, |row| row.code);
        Self { code, reason }
    }
}

/// §78.1 policy values; every lifetime and allowlist is the caller's configuration, never a constant here.
#[derive(Debug, Clone, Copy)]
pub struct OAuthPolicy<'a> {
    /// Authorization-code lifetime.
    pub code_ttl: Duration,
    /// Access-token lifetime (M02 D3), capped by the grant ceiling.
    pub access_ttl: Duration,
    /// Refresh-token lifetime (M02 D4).
    pub refresh_ttl: Duration,
    /// Grant lifetime (M02 D4), after which a browser sign-in is required.
    pub grant_max_ttl: Duration,
    /// Resources (audiences) this server issues for.
    pub allowed_resources: &'a [String],
    /// Scopes this server issues.
    pub supported_scopes: &'a [String],
}

/// What the registry says about the requesting client; mirrors `adapters::oauth_repo::ClientRecord`.
#[derive(Debug, Clone, Copy)]
pub struct ClientView<'a> {
    /// Exact-match redirect URIs.
    pub redirect_uris: &'a [String],
    /// `kind` is a spelling this build knows (`ClientRecord::kind.is_some()`).
    pub kind_recognized: bool,
    /// `disabled_at` is set.
    pub disabled: bool,
}

/// Query parameters of an authorize request, as received.
#[derive(Debug, Clone, Copy)]
pub struct AuthorizeRequest<'a> {
    /// `response_type`.
    pub response_type: Option<&'a str>,
    /// `client_id`.
    pub client_id: &'a str,
    /// `redirect_uri`.
    pub redirect_uri: Option<&'a str>,
    /// `code_challenge`.
    pub code_challenge: Option<&'a str>,
    /// `code_challenge_method`.
    pub code_challenge_method: Option<&'a str>,
    /// `resource` (RFC 8707).
    pub resource: Option<&'a str>,
    /// Space-separated `scope`.
    pub scope: Option<&'a str>,
    /// `state`, opaque to us.
    pub state: Option<&'a str>,
}

/// An authorize request that passed every check; consent may now be asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAuthorize {
    /// Client.
    pub client_id: String,
    /// The exactly-registered redirect URI.
    pub redirect_uri: String,
    /// S256 challenge.
    pub pkce_challenge: String,
    /// Allowlisted resource.
    pub resource: String,
    /// Requested scopes, deduplicated in request order.
    pub scopes: Vec<String>,
    /// `state`, passed through unchanged to the redirect.
    pub state: Option<String>,
}

/// A refused authorize request plus where the refusal may be delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeRefusal {
    /// What was refused.
    pub refusal: OAuthRefusal,
    /// `Some(redirect_uri)` only once client and redirect URI are validated; before that the error is shown, never
    /// redirected (RFC 6749 §4.1.2.1).
    pub redirect_to: Option<String>,
    /// `state` to echo on that redirect.
    pub state: Option<String>,
}

fn refuse_before_redirect(reason: OAuthReason) -> AuthorizeRefusal {
    AuthorizeRefusal {
        refusal: OAuthRefusal::of(reason),
        redirect_to: None,
        state: None,
    }
}

/// Scheme and host of a redirect URI after the shape rules.
struct RedirectShape {
    scheme: String,
    host: Option<String>,
}

fn parse_redirect(uri: &str) -> Result<RedirectShape, OAuthReason> {
    let invalid = OAuthReason::REDIRECT_URI_INVALID;
    if uri.is_empty()
        || uri.contains('#')
        || uri.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(invalid);
    }
    let (scheme, rest) = uri.split_once(':').ok_or(invalid)?;
    let mut scheme_chars = scheme.chars();
    let scheme_ok = scheme_chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && scheme_chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    if !scheme_ok {
        return Err(invalid);
    }
    let scheme = scheme.to_ascii_lowercase();
    let Some(after_slashes) = rest.strip_prefix("//") else {
        return Ok(RedirectShape { scheme, host: None });
    };
    let authority = after_slashes.split(['/', '?']).next().unwrap_or_default();
    if authority.contains('@') {
        return Err(invalid);
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, tail) = bracketed.split_once(']').ok_or(invalid)?;
        let port = match tail {
            "" => None,
            _ => Some(tail.strip_prefix(':').ok_or(invalid)?),
        };
        (host, port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() || port.is_some_and(|p| p.parse::<u16>().is_err()) {
        return Err(invalid);
    }
    Ok(RedirectShape {
        scheme,
        host: Some(host.to_ascii_lowercase()),
    })
}

fn check_redirect_policy(uri: &str) -> Result<(), OAuthReason> {
    let shape = parse_redirect(uri)?;
    match (shape.scheme.as_str(), shape.host.as_deref()) {
        ("https", Some(_)) => Ok(()),
        ("https", None) | ("http", None) => Err(OAuthReason::REDIRECT_URI_INVALID),
        ("http", Some(host)) if LOOPBACK_HOSTS.contains(&host) => Ok(()),
        ("http", Some(_)) => Err(OAuthReason::REDIRECT_URI_INSECURE),
        (other, _) if FORBIDDEN_REDIRECT_SCHEMES.contains(&other) => {
            Err(OAuthReason::REDIRECT_URI_INVALID)
        }
        // ponytail: any other scheme is a private-use scheme accepted once exactly registered, with no reverse-domain
        // rule (RFC 8252 §7.1); tighten when DCR registrations are screened (M02-10).
        _ => Ok(()),
    }
}

fn is_base64url_challenge(value: &str) -> bool {
    value.len() == S256_CHALLENGE_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// Validates an authorize request against the client registry and `policy` (G-M02-6).
///
/// Order: client, redirect URI (shape, then exact registration), then — now redirectable — response type, PKCE,
/// resource, scope. The first failure wins.
pub fn authorize_request(
    request: &AuthorizeRequest<'_>,
    client: Option<&ClientView<'_>>,
    policy: &OAuthPolicy<'_>,
) -> Result<ValidatedAuthorize, AuthorizeRefusal> {
    let client = client
        .filter(|c| c.kind_recognized && !c.disabled)
        .ok_or_else(|| refuse_before_redirect(OAuthReason::CLIENT_UNKNOWN))?;
    let redirect_uri = request
        .redirect_uri
        .ok_or_else(|| refuse_before_redirect(OAuthReason::REDIRECT_URI_MISSING))?;
    check_redirect_policy(redirect_uri).map_err(refuse_before_redirect)?;
    if !client
        .redirect_uris
        .iter()
        .any(|registered| registered == redirect_uri)
    {
        return Err(refuse_before_redirect(OAuthReason::REDIRECT_URI_MISMATCH));
    }

    let state = request.state.map(str::to_owned);
    let deliverable = |reason: OAuthReason| AuthorizeRefusal {
        refusal: OAuthRefusal::of(reason),
        redirect_to: Some(redirect_uri.to_owned()),
        state: state.clone(),
    };

    if request.response_type != Some(RESPONSE_TYPE_CODE) {
        return Err(deliverable(OAuthReason::RESPONSE_TYPE_UNSUPPORTED));
    }
    let challenge = request
        .code_challenge
        .ok_or_else(|| deliverable(OAuthReason::PKCE_REQUIRED))?;
    if request.code_challenge_method != Some(PKCE_METHOD_S256) {
        return Err(deliverable(OAuthReason::PKCE_METHOD_UNSUPPORTED));
    }
    if !is_base64url_challenge(challenge) {
        return Err(deliverable(OAuthReason::PKCE_CHALLENGE_MALFORMED));
    }
    let resource = request
        .resource
        .filter(|r| !r.is_empty())
        .ok_or_else(|| deliverable(OAuthReason::RESOURCE_REQUIRED))?;
    if !policy
        .allowed_resources
        .iter()
        .any(|allowed| allowed == resource)
    {
        return Err(deliverable(OAuthReason::RESOURCE_UNKNOWN));
    }
    let mut scopes: Vec<String> = Vec::new();
    for scope in request.scope.unwrap_or_default().split_ascii_whitespace() {
        if !policy.supported_scopes.iter().any(|s| s == scope) {
            return Err(deliverable(OAuthReason::SCOPE_UNSUPPORTED));
        }
        if !scopes.iter().any(|s| s == scope) {
            scopes.push(scope.to_owned());
        }
    }
    if scopes.is_empty() {
        return Err(deliverable(OAuthReason::SCOPE_REQUIRED));
    }

    Ok(ValidatedAuthorize {
        client_id: request.client_id.to_owned(),
        redirect_uri: redirect_uri.to_owned(),
        pkce_challenge: challenge.to_owned(),
        resource: resource.to_owned(),
        scopes,
        state,
    })
}

/// The consenting subject, from the console session (M02 D6).
#[derive(Debug, Clone, Copy)]
pub struct ConsentSubject {
    /// Consenting user.
    pub user_id: UserId,
    /// Tenant the grant will act in.
    pub tenant_id: TenantId,
    /// Workspace narrowing, if any.
    pub workspace_id: Option<WorkspaceId>,
}

/// What to store for an authorization code; mirrors `adapters::oauth_repo::CodeIssue` minus the caller-hashed code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeTerms {
    /// Client the code is bound to.
    pub client_id: String,
    /// Redirect URI the code is bound to.
    pub redirect_uri: String,
    /// PKCE challenge the exchange must satisfy.
    pub pkce_challenge: String,
    /// Resource the grant will be bound to.
    pub resource: String,
    /// Consenting user.
    pub user_id: UserId,
    /// Tenant.
    pub tenant_id: TenantId,
    /// Workspace narrowing, if any.
    pub workspace_id: Option<WorkspaceId>,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// Code lifetime (§78.1).
    pub ttl: Duration,
}

/// Terms of the code issued after consent. The caller generates the code, hashes it and stores it with these terms.
/// `Internal` when the configured `code_ttl` is zero.
pub fn issue_code(
    validated: &ValidatedAuthorize,
    subject: &ConsentSubject,
    policy: &OAuthPolicy<'_>,
) -> Result<CodeTerms, ErrorCode> {
    if policy.code_ttl.is_zero() {
        return Err(ErrorCode::Internal);
    }
    Ok(CodeTerms {
        client_id: validated.client_id.clone(),
        redirect_uri: validated.redirect_uri.clone(),
        pkce_challenge: validated.pkce_challenge.clone(),
        resource: validated.resource.clone(),
        user_id: subject.user_id,
        tenant_id: subject.tenant_id,
        workspace_id: subject.workspace_id,
        scopes: validated.scopes.clone(),
        ttl: policy.code_ttl,
    })
}

/// Token-endpoint parameters of an `authorization_code` request, as received.
#[derive(Debug, Clone, Copy)]
pub struct CodeExchangeRequest<'a> {
    /// `grant_type`.
    pub grant_type: Option<&'a str>,
    /// `client_id`.
    pub client_id: &'a str,
    /// `redirect_uri`.
    pub redirect_uri: Option<&'a str>,
    /// `code_verifier`.
    pub code_verifier: Option<&'a str>,
    /// `resource`; optional on the token request, but when present it must match the code's.
    pub resource: Option<&'a str>,
}

/// Checks that need no stored code; run them BEFORE the consume door so a malformed request does not burn a code.
pub fn precheck_code_exchange(request: &CodeExchangeRequest<'_>) -> Result<(), OAuthRefusal> {
    if request.grant_type != Some(GRANT_TYPE_AUTHORIZATION_CODE) {
        return Err(OAuthRefusal::of(OAuthReason::GRANT_TYPE_UNSUPPORTED));
    }
    let verifier = request
        .code_verifier
        .ok_or_else(|| OAuthRefusal::of(OAuthReason::VERIFIER_MISSING))?;
    let unreserved = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~');
    if !VERIFIER_LEN.contains(&verifier.len()) || !verifier.chars().all(unreserved) {
        return Err(OAuthRefusal::of(OAuthReason::VERIFIER_MALFORMED));
    }
    Ok(())
}

/// The facts a consumed code carries; mirrors `adapters::oauth_repo::ConsumedCode`.
#[derive(Debug, Clone, Copy)]
pub struct ConsumedCodeView<'a> {
    /// Client the code was bound to.
    pub client_id: &'a str,
    /// Redirect URI the code was bound to.
    pub redirect_uri: &'a str,
    /// PKCE challenge to satisfy.
    pub pkce_challenge: &'a str,
    /// Resource the code was bound to.
    pub resource: &'a str,
    /// Consenting user.
    pub user_id: UserId,
    /// Tenant.
    pub tenant_id: TenantId,
    /// Workspace narrowing, if any.
    pub workspace_id: Option<WorkspaceId>,
    /// Granted scopes.
    pub scopes: &'a [String],
}

/// What to store for a new grant; mirrors `adapters::oauth_repo::GrantIssue` minus the caller-hashed refresh token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantTerms {
    /// Consenting user.
    pub user_id: UserId,
    /// Tenant.
    pub tenant_id: TenantId,
    /// Workspace narrowing, if any.
    pub workspace_id: Option<WorkspaceId>,
    /// Client.
    pub client_id: String,
    /// Resource the grant is bound to.
    pub resource: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// Refresh lifetime (§78.1).
    pub refresh_ttl: Duration,
    /// Grant lifetime (§78.1).
    pub grant_max_ttl: Duration,
}

/// Whether `verifier` satisfies the S256 `challenge` (RFC 7636 §4.6), compared without early exit.
fn s256_matches(verifier: &str, challenge: &str) -> bool {
    let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let (a, b) = (computed.as_bytes(), challenge.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Compares an exchange against the consumed code and yields the grant to create. The code is already spent whatever
/// this returns (the consume door's contract), so every `Err` is final for that code.
pub fn exchange_code(
    request: &CodeExchangeRequest<'_>,
    consumed: &ConsumedCodeView<'_>,
    policy: &OAuthPolicy<'_>,
) -> Result<GrantTerms, OAuthRefusal> {
    precheck_code_exchange(request)?;
    if request.client_id != consumed.client_id {
        return Err(OAuthRefusal::of(OAuthReason::CODE_CLIENT_MISMATCH));
    }
    if request.redirect_uri != Some(consumed.redirect_uri) {
        return Err(OAuthRefusal::of(OAuthReason::CODE_REDIRECT_MISMATCH));
    }
    if request.resource.is_some_and(|r| r != consumed.resource) {
        return Err(OAuthRefusal::of(OAuthReason::CODE_RESOURCE_MISMATCH));
    }
    let verifier = request.code_verifier.unwrap_or_default();
    if !s256_matches(verifier, consumed.pkce_challenge) {
        return Err(OAuthRefusal::of(OAuthReason::VERIFIER_MISMATCH));
    }
    Ok(GrantTerms {
        user_id: consumed.user_id,
        tenant_id: consumed.tenant_id,
        workspace_id: consumed.workspace_id,
        client_id: consumed.client_id.to_owned(),
        resource: consumed.resource.to_owned(),
        scopes: consumed.scopes.to_vec(),
        refresh_ttl: policy.refresh_ttl,
        grant_max_ttl: policy.grant_max_ttl,
    })
}

/// A grant and the live epochs; mirrors `adapters::oauth_repo::GrantRecord`.
#[derive(Debug, Clone, Copy)]
pub struct GrantView<'a> {
    /// Client the grant was issued to.
    pub client_id: &'a str,
    /// Resource the grant is bound to.
    pub resource: &'a str,
    /// Granted scopes.
    pub scopes: &'a [String],
    /// `status == Some(GrantStatus::Active)`; an unknown status spelling is `false`.
    pub active: bool,
    /// Set once revoked.
    pub revoked_at: Option<OffsetDateTime>,
    /// Ceiling after which the grant is dead whatever its refresh tokens say.
    pub grant_max_expires_at: OffsetDateTime,
    /// User epoch at issuance.
    pub user_epoch_snapshot: i64,
    /// Tenant epoch at issuance.
    pub tenant_epoch_snapshot: i64,
    /// User epoch now.
    pub live_user_epoch: i64,
    /// Tenant epoch now.
    pub live_tenant_epoch: i64,
}

/// Why a grant must be closed by the caller; maps onto `adapters::oauth_repo::RevokeReason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeCause {
    /// The user or tenant security epoch moved past the grant's snapshot.
    SecurityEpoch,
    /// A rotated refresh token was presented again (M02 D4).
    RefreshReuse,
}

/// A grant that fails its lifetime or epoch check, and whether the caller must also close it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantFailure {
    /// What was refused.
    pub refusal: OAuthRefusal,
    /// `Some` when the grant must be revoked rather than merely refused.
    pub revoke: Option<RevokeCause>,
}

/// The grant lifetime and epoch verdict, shared by refresh and the bearer path (G-M02-9): live only while active,
/// before its ceiling, and with both epoch snapshots equal to the live epochs (M02 D3).
pub fn check_grant(grant: &GrantView<'_>, now: OffsetDateTime) -> Result<(), GrantFailure> {
    let refuse = |reason, revoke| GrantFailure {
        refusal: OAuthRefusal::of(reason),
        revoke,
    };
    if !grant.active || grant.revoked_at.is_some() {
        return Err(refuse(OAuthReason::GRANT_CLOSED, None));
    }
    if now >= grant.grant_max_expires_at {
        return Err(refuse(OAuthReason::GRANT_EXPIRED, None));
    }
    if grant.user_epoch_snapshot != grant.live_user_epoch
        || grant.tenant_epoch_snapshot != grant.live_tenant_epoch
    {
        return Err(refuse(
            OAuthReason::GRANT_EPOCH_STALE,
            Some(RevokeCause::SecurityEpoch),
        ));
    }
    Ok(())
}

/// What the rotate door reported; mirrors `adapters::oauth_repo::RotateOutcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationFact {
    /// The presented token was rotated and its successor stored.
    Rotated {
        /// Grant the family belongs to.
        grant_id: Uuid,
        /// Family of both tokens.
        family_id: Uuid,
        /// Expiry of the successor, as capped by the door.
        expires_at: OffsetDateTime,
    },
    /// The presented token had already been rotated.
    ReuseDetected {
        /// Grant the door revoked.
        grant_id: Uuid,
        /// Family the door revoked.
        family_id: Uuid,
    },
    /// Unknown, expired or revoked token, or a closed grant.
    Rejected,
}

/// Refresh-request parameters that are compared with the grant.
#[derive(Debug, Clone, Copy)]
pub struct RefreshRequest<'a> {
    /// `client_id`.
    pub client_id: &'a str,
    /// `resource`; optional, but when present it must equal the grant's.
    pub resource: Option<&'a str>,
}

/// The claims of an access token to sign (M02 D3), bound to the grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessTerms {
    /// Grant the token is read against on every call.
    pub grant_id: Uuid,
    /// Client.
    pub client_id: String,
    /// Audience.
    pub resource: String,
    /// Scopes.
    pub scopes: Vec<String>,
    /// `min(now + access_ttl, grant ceiling)`.
    pub expires_at: OffsetDateTime,
}

/// Access-token claims for `grant_id`; the token never outlives the grant ceiling.
pub fn access_terms(
    grant_id: Uuid,
    grant: &GrantView<'_>,
    now: OffsetDateTime,
    policy: &OAuthPolicy<'_>,
) -> AccessTerms {
    AccessTerms {
        grant_id,
        client_id: grant.client_id.to_owned(),
        resource: grant.resource.to_owned(),
        scopes: grant.scopes.to_vec(),
        expires_at: (now + policy.access_ttl).min(grant.grant_max_expires_at),
    }
}

/// The closing action the caller executes through the revoke doors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revocation {
    /// Grant to close.
    pub grant_id: Uuid,
    /// Refresh family to close with it, when known.
    pub family_id: Option<Uuid>,
    /// Why.
    pub cause: RevokeCause,
}

/// Verdict of one refresh attempt, executed by the M02-10 HTTP layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshDecision {
    /// Rotation stands: sign `access`, hand out the successor refresh token (expiring `refresh_expires_at`), commit.
    Issue {
        /// Family of the rotated pair.
        family_id: Uuid,
        /// Expiry of the successor refresh token.
        refresh_expires_at: OffsetDateTime,
        /// Access token to sign.
        access: AccessTerms,
    },
    /// Refuse. With `revoke: Some` the revocation must be executed and the transaction committed; with `None` roll the
    /// transaction back so a refused rotation does not consume the token.
    Deny {
        /// What to answer.
        refusal: OAuthRefusal,
        /// Revocation to execute before commit.
        revoke: Option<Revocation>,
    },
}

/// Decides a refresh from the rotate door's outcome and the grant row read after it (M02 D4). Reuse revokes the family
/// and the grant; a grant past its ceiling or behind an epoch is refused (and, for an epoch, revoked).
pub fn decide_refresh(
    fact: RotationFact,
    grant: Option<&GrantView<'_>>,
    request: &RefreshRequest<'_>,
    now: OffsetDateTime,
    policy: &OAuthPolicy<'_>,
) -> RefreshDecision {
    let deny = |reason, revoke| RefreshDecision::Deny {
        refusal: OAuthRefusal::of(reason),
        revoke,
    };
    let (grant_id, family_id, expires_at) = match fact {
        RotationFact::Rejected => return deny(OAuthReason::REFRESH_REJECTED, None),
        RotationFact::ReuseDetected {
            grant_id,
            family_id,
        } => {
            return deny(
                OAuthReason::REFRESH_REUSED,
                Some(Revocation {
                    grant_id,
                    family_id: Some(family_id),
                    cause: RevokeCause::RefreshReuse,
                }),
            );
        }
        RotationFact::Rotated {
            grant_id,
            family_id,
            expires_at,
        } => (grant_id, family_id, expires_at),
    };
    let Some(grant) = grant else {
        return deny(OAuthReason::GRANT_CLOSED, None);
    };
    if let Err(failure) = check_grant(grant, now) {
        let revoke = failure.revoke.map(|cause| Revocation {
            grant_id,
            family_id: Some(family_id),
            cause,
        });
        return RefreshDecision::Deny {
            refusal: failure.refusal,
            revoke,
        };
    }
    if request.client_id != grant.client_id {
        return deny(OAuthReason::REFRESH_CLIENT_MISMATCH, None);
    }
    if request.resource.is_some_and(|r| r != grant.resource) {
        return deny(OAuthReason::REFRESH_RESOURCE_MISMATCH, None);
    }
    RefreshDecision::Issue {
        family_id,
        refresh_expires_at: expires_at,
        access: access_terms(grant_id, grant, now, policy),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_token_payload_round_trip_preserves_client_separator() {
        let access = AccessTerms {
            grant_id: Uuid::from_u128(1),
            client_id: "client\u{1}suffix".to_owned(),
            resource: "https://resource.example.test/mcp".to_owned(),
            scopes: vec!["context:read".to_owned()],
            expires_at: OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
        };
        assert_eq!(
            parse_access_token_payload(&access_token_payload(&access)),
            Some(access)
        );
    }

    /// RFC 7636 Appendix B vector.
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const CLIENT: &str = "client-1";
    const RESOURCE: &str = "https://mcp.example.test/mcp";
    const HTTPS_CB: &str = "https://app.example.test/cb";
    const LOOPBACK_CB: &str = "http://127.0.0.1:8123/cb";
    const HTTP_CB: &str = "http://app.example.test/cb";

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn at(n: u64) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + secs(n)
    }

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    struct Fixture {
        registered: Vec<String>,
        resources: Vec<String>,
        scopes: Vec<String>,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                registered: strings(&[
                    HTTPS_CB,
                    LOOPBACK_CB,
                    HTTP_CB,
                    "http://[::1]:9/cb",
                    "http://localhost/cb",
                    "http://localhost.evil.test/cb",
                    "com.example.app:/cb",
                    "javascript://x/cb",
                ]),
                resources: strings(&[RESOURCE]),
                scopes: strings(&["memory.read", "memory.write"]),
            }
        }

        fn policy(&self) -> OAuthPolicy<'_> {
            OAuthPolicy {
                code_ttl: secs(300),
                access_ttl: secs(3600),
                refresh_ttl: secs(30 * 86_400),
                grant_max_ttl: secs(90 * 86_400),
                allowed_resources: &self.resources,
                supported_scopes: &self.scopes,
            }
        }

        fn client(&self) -> ClientView<'_> {
            ClientView {
                redirect_uris: &self.registered,
                kind_recognized: true,
                disabled: false,
            }
        }
    }

    fn good_request() -> AuthorizeRequest<'static> {
        AuthorizeRequest {
            response_type: Some("code"),
            client_id: CLIENT,
            redirect_uri: Some(HTTPS_CB),
            code_challenge: Some(CHALLENGE),
            code_challenge_method: Some("S256"),
            resource: Some(RESOURCE),
            scope: Some("memory.read memory.write"),
            state: Some("xyz"),
        }
    }

    #[test]
    fn reason_table_is_closed_unique_and_total() {
        assert_eq!(OAUTH_REASONS.len(), 28);
        let mut codes = std::collections::HashSet::new();
        let mut labels = std::collections::HashSet::new();
        for row in OAUTH_REASONS {
            assert!(codes.insert(row.reason.code()), "dup code {}", row.reason.0);
            assert!(labels.insert(row.label), "dup label {}", row.label);
            assert_eq!(row.reason.row(), Some(&row));
            assert!(matches!(
                row.code,
                ErrorCode::InvalidInput | ErrorCode::Unauthorized
            ));
        }
        assert_eq!(OAuthReason(1).row(), None);
        assert_eq!(OAuthRefusal::of(OAuthReason(1)).code, ErrorCode::Internal);
    }

    #[test]
    fn good_authorize_request_passes_state_through() {
        let fx = Fixture::new();
        let validated = authorize_request(&good_request(), Some(&fx.client()), &fx.policy())
            .expect("valid request");
        assert_eq!(
            validated,
            ValidatedAuthorize {
                client_id: CLIENT.to_owned(),
                redirect_uri: HTTPS_CB.to_owned(),
                pkce_challenge: CHALLENGE.to_owned(),
                resource: RESOURCE.to_owned(),
                scopes: strings(&["memory.read", "memory.write"]),
                state: Some("xyz".to_owned()),
            }
        );
        let mut req = good_request();
        req.state = None;
        assert_eq!(
            authorize_request(&req, Some(&fx.client()), &fx.policy())
                .expect("valid")
                .state,
            None
        );
    }

    #[test]
    fn loopback_http_redirects_are_accepted() {
        let fx = Fixture::new();
        for uri in [LOOPBACK_CB, "http://[::1]:9/cb", "http://localhost/cb"] {
            let mut req = good_request();
            req.redirect_uri = Some(uri);
            let validated = authorize_request(&req, Some(&fx.client()), &fx.policy())
                .unwrap_or_else(|e| panic!("{uri} refused: {e:?}"));
            assert_eq!(validated.redirect_uri, uri);
        }
        let mut req = good_request();
        req.redirect_uri = Some("com.example.app:/cb");
        assert!(authorize_request(&req, Some(&fx.client()), &fx.policy()).is_ok());
    }

    /// One row per refusal: the mutation of an otherwise valid request, the exact reason, and whether the refusal may
    /// be redirected back to the client.
    #[test]
    #[allow(clippy::too_many_lines)] // one exhaustive table of authorize refusals, rustfmt expands each row
    fn authorize_refusals_are_exact() {
        type Mutate = fn(&mut AuthorizeRequest<'static>);
        let table: [(&str, Mutate, OAuthReason, bool); 18] = [
            (
                "response_type token",
                |r| r.response_type = Some("token"),
                OAuthReason::RESPONSE_TYPE_UNSUPPORTED,
                true,
            ),
            (
                "response_type missing",
                |r| r.response_type = None,
                OAuthReason::RESPONSE_TYPE_UNSUPPORTED,
                true,
            ),
            (
                "pkce plain",
                |r| r.code_challenge_method = Some("plain"),
                OAuthReason::PKCE_METHOD_UNSUPPORTED,
                true,
            ),
            (
                "pkce lowercase s256",
                |r| r.code_challenge_method = Some("s256"),
                OAuthReason::PKCE_METHOD_UNSUPPORTED,
                true,
            ),
            (
                "pkce method missing",
                |r| r.code_challenge_method = None,
                OAuthReason::PKCE_METHOD_UNSUPPORTED,
                true,
            ),
            (
                "pkce challenge missing",
                |r| r.code_challenge = None,
                OAuthReason::PKCE_REQUIRED,
                true,
            ),
            (
                "pkce challenge short",
                |r| r.code_challenge = Some("abc"),
                OAuthReason::PKCE_CHALLENGE_MALFORMED,
                true,
            ),
            (
                "resource missing",
                |r| r.resource = None,
                OAuthReason::RESOURCE_REQUIRED,
                true,
            ),
            (
                "resource empty",
                |r| r.resource = Some(""),
                OAuthReason::RESOURCE_REQUIRED,
                true,
            ),
            (
                "resource unknown",
                |r| r.resource = Some("https://other.example.test/"),
                OAuthReason::RESOURCE_UNKNOWN,
                true,
            ),
            (
                "scope missing",
                |r| r.scope = None,
                OAuthReason::SCOPE_REQUIRED,
                true,
            ),
            (
                "scope unsupported",
                |r| r.scope = Some("memory.read admin"),
                OAuthReason::SCOPE_UNSUPPORTED,
                true,
            ),
            (
                "redirect missing",
                |r| r.redirect_uri = None,
                OAuthReason::REDIRECT_URI_MISSING,
                false,
            ),
            (
                "redirect not registered",
                |r| r.redirect_uri = Some("https://evil.example.test/cb"),
                OAuthReason::REDIRECT_URI_MISMATCH,
                false,
            ),
            (
                "redirect differs by path",
                |r| r.redirect_uri = Some("https://app.example.test/cb/"),
                OAuthReason::REDIRECT_URI_MISMATCH,
                false,
            ),
            (
                "redirect http non-loopback",
                |r| r.redirect_uri = Some(HTTP_CB),
                OAuthReason::REDIRECT_URI_INSECURE,
                false,
            ),
            (
                "redirect http lookalike host",
                |r| r.redirect_uri = Some("http://localhost.evil.test/cb"),
                OAuthReason::REDIRECT_URI_INSECURE,
                false,
            ),
            (
                "redirect forbidden scheme",
                |r| r.redirect_uri = Some("javascript://x/cb"),
                OAuthReason::REDIRECT_URI_INVALID,
                false,
            ),
        ];
        assert_eq!(table.len(), 18);
        let fx = Fixture::new();
        for (name, mutate, reason, redirectable) in table {
            let mut req = good_request();
            mutate(&mut req);
            let refusal =
                authorize_request(&req, Some(&fx.client()), &fx.policy()).expect_err(name);
            assert_eq!(refusal.refusal, OAuthRefusal::of(reason), "{name}");
            assert_eq!(refusal.refusal.code, ErrorCode::InvalidInput, "{name}");
            if redirectable {
                assert_eq!(refusal.redirect_to.as_deref(), Some(HTTPS_CB), "{name}");
                assert_eq!(refusal.state.as_deref(), Some("xyz"), "{name}");
            } else {
                assert_eq!(refusal.redirect_to, None, "{name}");
                assert_eq!(refusal.state, None, "{name}");
            }
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one exhaustive table of redirect-shape refusals, rustfmt expands each row
    fn redirect_shape_refusals_are_exact() {
        for (uri, reason) in [
            (
                "https://app.example.test/cb#frag",
                OAuthReason::REDIRECT_URI_INVALID,
            ),
            (
                "https://user@app.example.test/cb",
                OAuthReason::REDIRECT_URI_INVALID,
            ),
            (
                "http://127.0.0.1@evil.test/cb",
                OAuthReason::REDIRECT_URI_INVALID,
            ),
            ("https:///cb", OAuthReason::REDIRECT_URI_INVALID),
            (
                "http://127.0.0.1:99999/cb",
                OAuthReason::REDIRECT_URI_INVALID,
            ),
            ("http://[::1/cb", OAuthReason::REDIRECT_URI_INVALID),
            ("not a uri", OAuthReason::REDIRECT_URI_INVALID),
            ("/relative", OAuthReason::REDIRECT_URI_INVALID),
            ("http://127.0.0.2/cb", OAuthReason::REDIRECT_URI_INSECURE),
            ("HTTP://example.test/cb", OAuthReason::REDIRECT_URI_INSECURE),
            ("data:text/html,x", OAuthReason::REDIRECT_URI_INVALID),
        ] {
            assert_eq!(check_redirect_policy(uri), Err(reason), "{uri}");
        }
        for uri in [
            "HTTP://LOCALHOST:1/cb",
            "https://app.example.test",
            "cursor://auth/cb",
        ] {
            assert_eq!(check_redirect_policy(uri), Ok(()), "{uri}");
        }
    }

    #[test]
    fn unknown_disabled_or_unrecognised_client_is_never_redirected() {
        let fx = Fixture::new();
        let mut disabled = fx.client();
        disabled.disabled = true;
        let mut unrecognised = fx.client();
        unrecognised.kind_recognized = false;
        for client in [None, Some(&disabled), Some(&unrecognised)] {
            let refusal =
                authorize_request(&good_request(), client, &fx.policy()).expect_err("refused");
            assert_eq!(
                refusal.refusal,
                OAuthRefusal::of(OAuthReason::CLIENT_UNKNOWN)
            );
            assert_eq!(refusal.redirect_to, None);
        }
    }

    #[test]
    fn scopes_are_deduplicated_in_request_order() {
        let fx = Fixture::new();
        let mut req = good_request();
        req.scope = Some("memory.write  memory.read memory.write");
        let validated = authorize_request(&req, Some(&fx.client()), &fx.policy()).expect("ok");
        assert_eq!(validated.scopes, strings(&["memory.write", "memory.read"]));
    }

    fn validated(fx: &Fixture) -> ValidatedAuthorize {
        authorize_request(&good_request(), Some(&fx.client()), &fx.policy()).expect("valid")
    }

    fn subject() -> ConsentSubject {
        ConsentSubject {
            user_id: UserId(id(1)),
            tenant_id: TenantId(id(2)),
            workspace_id: Some(WorkspaceId(id(3))),
        }
    }

    #[test]
    fn issue_code_carries_request_facts_and_configured_ttl() {
        let fx = Fixture::new();
        let terms = issue_code(&validated(&fx), &subject(), &fx.policy()).expect("terms");
        assert_eq!(
            terms,
            CodeTerms {
                client_id: CLIENT.to_owned(),
                redirect_uri: HTTPS_CB.to_owned(),
                pkce_challenge: CHALLENGE.to_owned(),
                resource: RESOURCE.to_owned(),
                user_id: UserId(id(1)),
                tenant_id: TenantId(id(2)),
                workspace_id: Some(WorkspaceId(id(3))),
                scopes: strings(&["memory.read", "memory.write"]),
                ttl: secs(300),
            }
        );
        let mut policy = fx.policy();
        policy.code_ttl = Duration::ZERO;
        assert_eq!(
            issue_code(&validated(&fx), &subject(), &policy),
            Err(ErrorCode::Internal)
        );
    }

    fn exchange_request() -> CodeExchangeRequest<'static> {
        CodeExchangeRequest {
            grant_type: Some("authorization_code"),
            client_id: CLIENT,
            redirect_uri: Some(HTTPS_CB),
            code_verifier: Some(VERIFIER),
            resource: Some(RESOURCE),
        }
    }

    fn consumed(scopes: &[String]) -> ConsumedCodeView<'_> {
        ConsumedCodeView {
            client_id: CLIENT,
            redirect_uri: HTTPS_CB,
            pkce_challenge: CHALLENGE,
            resource: RESOURCE,
            user_id: UserId(id(1)),
            tenant_id: TenantId(id(2)),
            workspace_id: None,
            scopes,
        }
    }

    #[test]
    fn code_exchange_succeeds_with_the_rfc7636_vector() {
        let fx = Fixture::new();
        let scopes = strings(&["memory.read"]);
        let terms =
            exchange_code(&exchange_request(), &consumed(&scopes), &fx.policy()).expect("exchange");
        assert_eq!(terms.refresh_ttl, secs(30 * 86_400));
        assert_eq!(terms.grant_max_ttl, secs(90 * 86_400));
        assert_eq!(terms.scopes, scopes);
        let mut req = exchange_request();
        req.resource = None;
        assert!(exchange_code(&req, &consumed(&scopes), &fx.policy()).is_ok());
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one exhaustive table of exchange refusals, rustfmt expands each row
    fn code_exchange_refusals_are_exact() {
        type Mutate = fn(&mut CodeExchangeRequest<'static>);
        let table: [(&str, Mutate, OAuthReason); 8] = [
            (
                "grant_type",
                |r| r.grant_type = Some("password"),
                OAuthReason::GRANT_TYPE_UNSUPPORTED,
            ),
            (
                "verifier missing",
                |r| r.code_verifier = None,
                OAuthReason::VERIFIER_MISSING,
            ),
            (
                "verifier short",
                |r| r.code_verifier = Some("short"),
                OAuthReason::VERIFIER_MALFORMED,
            ),
            (
                "verifier bad char",
                |r| r.code_verifier = Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX!"),
                OAuthReason::VERIFIER_MALFORMED,
            ),
            (
                "verifier wrong",
                |r| r.code_verifier = Some("aBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
                OAuthReason::VERIFIER_MISMATCH,
            ),
            (
                "client",
                |r| r.client_id = "other",
                OAuthReason::CODE_CLIENT_MISMATCH,
            ),
            (
                "redirect",
                |r| r.redirect_uri = Some("https://app.example.test/other"),
                OAuthReason::CODE_REDIRECT_MISMATCH,
            ),
            (
                "resource",
                |r| r.resource = Some("https://other.example.test/"),
                OAuthReason::CODE_RESOURCE_MISMATCH,
            ),
        ];
        assert_eq!(table.len(), 8);
        let fx = Fixture::new();
        let scopes = strings(&["memory.read"]);
        for (name, mutate, reason) in table {
            let mut req = exchange_request();
            mutate(&mut req);
            assert_eq!(
                exchange_code(&req, &consumed(&scopes), &fx.policy()),
                Err(OAuthRefusal::of(reason)),
                "{name}"
            );
        }
        let mut req = exchange_request();
        req.redirect_uri = None;
        assert_eq!(
            exchange_code(&req, &consumed(&scopes), &fx.policy()),
            Err(OAuthRefusal::of(OAuthReason::CODE_REDIRECT_MISMATCH))
        );
    }

    #[test]
    fn precheck_runs_without_a_code() {
        assert_eq!(precheck_code_exchange(&exchange_request()), Ok(()));
        let mut req = exchange_request();
        req.grant_type = Some("refresh_token");
        assert_eq!(
            precheck_code_exchange(&req),
            Err(OAuthRefusal::of(OAuthReason::GRANT_TYPE_UNSUPPORTED))
        );
    }

    fn grant(scopes: &[String]) -> GrantView<'_> {
        GrantView {
            client_id: CLIENT,
            resource: RESOURCE,
            scopes,
            active: true,
            revoked_at: None,
            grant_max_expires_at: at(1_000_000),
            user_epoch_snapshot: 4,
            tenant_epoch_snapshot: 7,
            live_user_epoch: 4,
            live_tenant_epoch: 7,
        }
    }

    fn refresh_request() -> RefreshRequest<'static> {
        RefreshRequest {
            client_id: CLIENT,
            resource: None,
        }
    }

    fn rotated() -> RotationFact {
        RotationFact::Rotated {
            grant_id: id(10),
            family_id: id(11),
            expires_at: at(5_000),
        }
    }

    #[test]
    fn grant_checks_are_exact() {
        let scopes = strings(&["memory.read"]);
        assert_eq!(check_grant(&grant(&scopes), at(1)), Ok(()));
        assert_eq!(check_grant(&grant(&scopes), at(999_999)), Ok(()));

        let fail = |reason, revoke| {
            Err(GrantFailure {
                refusal: OAuthRefusal::of(reason),
                revoke,
            })
        };
        assert_eq!(
            check_grant(&grant(&scopes), at(1_000_000)),
            fail(OAuthReason::GRANT_EXPIRED, None)
        );
        let mut g = grant(&scopes);
        g.active = false;
        assert_eq!(
            check_grant(&g, at(1)),
            fail(OAuthReason::GRANT_CLOSED, None)
        );
        let mut g = grant(&scopes);
        g.revoked_at = Some(at(0));
        assert_eq!(
            check_grant(&g, at(1)),
            fail(OAuthReason::GRANT_CLOSED, None)
        );
        let mut g = grant(&scopes);
        g.live_user_epoch = 5;
        assert_eq!(
            check_grant(&g, at(1)),
            fail(
                OAuthReason::GRANT_EPOCH_STALE,
                Some(RevokeCause::SecurityEpoch)
            )
        );
        let mut g = grant(&scopes);
        g.live_tenant_epoch = 8;
        assert_eq!(
            check_grant(&g, at(1)),
            fail(
                OAuthReason::GRANT_EPOCH_STALE,
                Some(RevokeCause::SecurityEpoch)
            )
        );
    }

    #[test]
    fn refresh_issue_caps_access_at_the_grant_ceiling() {
        let fx = Fixture::new();
        let scopes = strings(&["memory.read"]);
        let decision = decide_refresh(
            rotated(),
            Some(&grant(&scopes)),
            &refresh_request(),
            at(100),
            &fx.policy(),
        );
        assert_eq!(
            decision,
            RefreshDecision::Issue {
                family_id: id(11),
                refresh_expires_at: at(5_000),
                access: AccessTerms {
                    grant_id: id(10),
                    client_id: CLIENT.to_owned(),
                    resource: RESOURCE.to_owned(),
                    scopes: scopes.clone(),
                    expires_at: at(100 + 3600),
                },
            }
        );
        let RefreshDecision::Issue { access, .. } = decide_refresh(
            rotated(),
            Some(&grant(&scopes)),
            &refresh_request(),
            at(999_000),
            &fx.policy(),
        ) else {
            panic!("expected Issue");
        };
        assert_eq!(access.expires_at, at(1_000_000));
    }

    #[test]
    fn refresh_reuse_revokes_family_and_grant() {
        let fx = Fixture::new();
        let scopes = strings(&["memory.read"]);
        let fact = RotationFact::ReuseDetected {
            grant_id: id(10),
            family_id: id(11),
        };
        // The grant row is irrelevant to the verdict: reuse revokes even when the grant looks healthy.
        for grant_row in [Some(grant(&scopes)), None] {
            assert_eq!(
                decide_refresh(
                    fact,
                    grant_row.as_ref(),
                    &refresh_request(),
                    at(1),
                    &fx.policy()
                ),
                RefreshDecision::Deny {
                    refusal: OAuthRefusal::of(OAuthReason::REFRESH_REUSED),
                    revoke: Some(Revocation {
                        grant_id: id(10),
                        family_id: Some(id(11)),
                        cause: RevokeCause::RefreshReuse,
                    }),
                }
            );
        }
    }

    #[test]
    fn refresh_denials_are_exact() {
        let fx = Fixture::new();
        let scopes = strings(&["memory.read"]);
        let deny = |reason, revoke| RefreshDecision::Deny {
            refusal: OAuthRefusal::of(reason),
            revoke,
        };

        assert_eq!(
            decide_refresh(
                RotationFact::Rejected,
                Some(&grant(&scopes)),
                &refresh_request(),
                at(1),
                &fx.policy()
            ),
            deny(OAuthReason::REFRESH_REJECTED, None)
        );
        assert_eq!(
            decide_refresh(rotated(), None, &refresh_request(), at(1), &fx.policy()),
            deny(OAuthReason::GRANT_CLOSED, None)
        );
        assert_eq!(
            decide_refresh(
                rotated(),
                Some(&grant(&scopes)),
                &refresh_request(),
                at(1_000_000),
                &fx.policy()
            ),
            deny(OAuthReason::GRANT_EXPIRED, None)
        );
        let mut stale = grant(&scopes);
        stale.live_user_epoch = 9;
        assert_eq!(
            decide_refresh(
                rotated(),
                Some(&stale),
                &refresh_request(),
                at(1),
                &fx.policy()
            ),
            deny(
                OAuthReason::GRANT_EPOCH_STALE,
                Some(Revocation {
                    grant_id: id(10),
                    family_id: Some(id(11)),
                    cause: RevokeCause::SecurityEpoch,
                })
            )
        );
        let other_client = RefreshRequest {
            client_id: "other",
            resource: None,
        };
        assert_eq!(
            decide_refresh(
                rotated(),
                Some(&grant(&scopes)),
                &other_client,
                at(1),
                &fx.policy()
            ),
            deny(OAuthReason::REFRESH_CLIENT_MISMATCH, None)
        );
        let other_resource = RefreshRequest {
            client_id: CLIENT,
            resource: Some("https://other.example.test/"),
        };
        assert_eq!(
            decide_refresh(
                rotated(),
                Some(&grant(&scopes)),
                &other_resource,
                at(1),
                &fx.policy()
            ),
            deny(OAuthReason::REFRESH_RESOURCE_MISMATCH, None)
        );
    }
}
