//! `gateway::auth_pages` — M02 D1/D2 `/auth/*` SSR pages: email → code → console session, and logout (ADR-0125).
//! Depends-on: crates=[axum, humaux-adapters, humaux-application, humaux-domain, humaux-protocol, serde, uuid];
//!   services=[]; env=[]; modules=[adapters::email, adapters::login_repo, adapters::postgres, adapters::session_repo,
//!   application::auth, application::session, application::signed_token, domain::error,
//!   gateway::guard, protocol::edge]
//! Called-by: [gateway::bootstrap, gateway::main, tests]
//! Invariants: [every /auth/* request passes the pre-auth guard entry exactly once before any handler runs and every
//!   response the pages produce, refusals included, carries the hardening headers; a POST is acted on only when its
//!   Origin (Referer when Origin is absent) is the configured public origin, checked before any form field is acted
//!   on or any row is written (admission has already buffered the body by then); a start
//!   answers one byte-identical redirect whether the mailbox is unknown, in cooldown or issued; every failed code
//!   attempt answers one rejection page; the mailbox rides between the two steps only in a signed, expiring,
//!   HttpOnly cookie, never in a URL and never in HTML; logout revokes only on a session-bound CSRF token]
//! Spec: Baseline §73.6; §74.2; §74.3; §83; M02 D1; M02 D2; M02 D6; ADR-0125
//!
//! The pages are functional placeholders: semantic HTML, no script, no stylesheet, no dynamic text (nothing is echoed,
//! so there is nothing to escape). The email, session and CSRF doors are the merged M02-5/M02-6 ones; this file only
//! moves bytes between them and a browser.
//!
//! ponytail: unstyled forms, visual layer lands with the console design-system card (audit-first).
//! ponytail: English copy only; i18n arrives with the console card's message catalogue.
//! ponytail: the start path answers a statement faster for an unknown mailbox (login_repo::start's own ponytail);
//! a fixed latency floor is its upgrade path.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Form, Router,
    body::Body,
    extract::{ConnectInfo, Request, State, rejection::FormRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use humaux_adapters::email::RecipientAllowlist;
use humaux_adapters::login_repo::{self, LoginMail};
use humaux_adapters::postgres::RuntimeDbPool;
use humaux_adapters::session_repo;
use humaux_application::auth::{AuthConfig, canonicalize_email};
use humaux_application::session::{SessionPolicy, SessionSecret, csrf_token};
use humaux_application::signed_token::{FIELD_SEP, TokenKeys, TokenLabel};
use humaux_domain::error::ErrorCode;
use humaux_protocol::edge::{
    CSRF_HEADER_NAME, FETCH_SITE_HEADER_NAME, FetchSite, SESSION_COOKIE_NAME, SameSitePolicy,
    session_cookie_attributes, verify_csrf,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::guard::GatewayGuard;

const LOGIN_PATH: &str = "/auth/login";
const CODE_PATH: &str = "/auth/code";
const LOGOUT_PATH: &str = "/auth/logout";
// ponytail: console mounts at "/" until the M26 console card names its root; upgrade = that card's constant
const CONSOLE_ROOT: &str = "/";

/// The `resource_id` of the audit row a refused `/auth/*` request leaves (the `/mcp` twin writes `protocol`).
const AUDIT_SURFACE: &str = "auth";
/// Cookie that carries the canonical mailbox from the email step to the code step.
const PENDING_COOKIE_NAME: &str = "__Host-humaux_login";
/// MAC and kid domains of the pending-login value; distinct from every other token kind under the auth key. `pub` so the
/// forged-cookie test signs with the production label and fails on the expiry check, not on a label mismatch.
pub const PENDING_LABEL: TokenLabel =
    TokenLabel::new(b"humaux.login_pending.v1", b"humaux.login_pending.kid.v1");
const LOGIN_MAIL_SUBJECT: &str = "Your Humaux sign-in code";
/// RFC 5321 §4.5.3.1.3 path limit; a longer mailbox cannot exist.
const MAX_MAILBOX_BYTES: usize = 254;
/// A longer candidate cannot be a login code; it is refused without a database round trip.
const MAX_CODE_BYTES: usize = 32;

/// ADR-0125 ruling 5, on every `/auth/*` response.
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
/// ADR-0125 ruling 5 (amended): `same-origin`, not `no-referrer`. Under `no-referrer` browsers serialize the `Origin` of
/// a form POST as `null` (Fetch, "append a request `Origin` header"), which the Origin check must refuse, so no user
/// could sign in. `same-origin` sends nothing to any other origin, which is what the header is for.
const REFERRER_POLICY: &str = "same-origin";

/// One static page: the same shell for every route, so nothing but `$body` can differ between two answers.
macro_rules! document {
    ($title:literal, $body:literal) => {
        concat!(
            "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n",
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n",
            "<title>",
            $title,
            "</title>\n</head>\n<body>\n<main>\n",
            $body,
            "</main>\n</body>\n</html>\n"
        )
    };
}

// The forms carry no `action`: a form without one posts to the URL it was served from, so the routes live only in
// the constants above.
const LOGIN_PAGE: &str = document!(
    "Sign in",
    r#"<h1>Sign in</h1>
<form method="post">
<p><label for="email">Email address</label></p>
<p><input id="email" name="email" type="email" autocomplete="email" required></p>
<p><button type="submit">Email me a sign-in code</button></p>
</form>
"#
);

const CODE_PAGE: &str = document!(
    "Enter your code",
    r#"<h1>Enter your code</h1>
<p>If that address can sign in, a code is on its way.</p>
<form method="post">
<p><label for="code">Sign-in code</label></p>
<p><input id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]*" required></p>
<p><button type="submit">Sign in</button></p>
</form>
<p><a href="login">Use a different address</a></p>
"#
);

const REJECTED_PAGE: &str = document!(
    "Code not accepted",
    r#"<h1>Code not accepted</h1>
<p>That code is not valid or has expired.</p>
<p><a href="login">Request a new code</a></p>
"#
);

const FORBIDDEN_PAGE: &str = document!(
    "Request refused",
    r#"<h1>Request refused</h1>
<p>This request could not be verified. Reload the page and try again.</p>
"#
);

const BAD_REQUEST_PAGE: &str = document!(
    "Request not understood",
    r#"<h1>Request not understood</h1>
<p>Check what you entered and try again.</p>
"#
);

const BUSY_PAGE: &str = document!(
    "Try again shortly",
    r#"<h1>Try again shortly</h1>
<p>The service is busy or unavailable.</p>
"#
);

/// Everything the pages need from bootstrap. Secrets stay inside; the type has no `Debug`.
pub struct AuthPagesConfig {
    /// `HUMAUX_GATEWAY_AUTH_HMAC_KEY`: signs the pending-login value and the session-bound CSRF token (M02 D3).
    pub keys: TokenKeys,
    /// `HUMAUX_GATEWAY_PUBLIC_BASE_URL` as `scheme://host[:port]`, lowercase: the one origin a POST may come from.
    pub public_origin: String,
    /// `HUMAUX_GATEWAY_LOGIN_MAIL_FROM`.
    pub mail_from: String,
    /// `HUMAUX_GATEWAY_LOGIN_CODE_PEPPER`: the keyed-hash key of login codes, shared with no other credential.
    pub code_pepper: Vec<u8>,
    /// `HUMAUX_GATEWAY_EMAIL_RECIPIENT_ALLOWLIST`; blank allows every recipient at enqueue.
    pub allowlist: RecipientAllowlist,
    /// §78.1 challenge and session lifetimes, from the `HUMAUX_GATEWAY_AUTH_*` lifetime keys (ADR-0125 8e).
    pub auth: AuthConfig,
}

struct Pages {
    guard: Arc<GatewayGuard>,
    pool: Arc<RuntimeDbPool>,
    session: SessionPolicy,
    config: AuthPagesConfig,
}

type Shared = Arc<Pages>;

/// The `/auth/*` routes. Merge the result into the router `main` serves so the admission layer wraps both.
pub fn router(guard: Arc<GatewayGuard>, config: AuthPagesConfig) -> Router {
    let pages = Arc::new(Pages {
        pool: guard.runtime_pool(),
        session: SessionPolicy::from(&config.auth),
        guard,
        config,
    });
    Router::new()
        .route(LOGIN_PATH, get(login_form).post(login_submit))
        .route(CODE_PATH, get(code_form).post(code_submit))
        .route(LOGOUT_PATH, post(logout))
        .layer(middleware::from_fn_with_state(Arc::clone(&pages), gate))
        .with_state(pages)
}

/// Pre-auth guard exactly once per request, then the handler; hardening headers on whatever comes back.
async fn gate(
    State(pages): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    guarded(&pages.guard, AUDIT_SURFACE, peer, request, next).await
}

/// ADR-0125 D3: shared pre-auth tier, exactly once, before a surface handler; harden every answer.
pub(crate) async fn guarded(
    guard: &GatewayGuard,
    surface: &'static str,
    peer: SocketAddr,
    request: Request,
    next: Next,
) -> Response {
    let Ok(forwarded) = single_header(request.headers(), "forwarded") else {
        return harden(page(StatusCode::BAD_REQUEST, BAD_REQUEST_PAGE));
    };
    let admitted = guard
        .preflight_peer(
            Uuid::now_v7(),
            peer.ip(),
            forwarded.as_deref(),
            surface,
            None,
        )
        .await;
    harden(match admitted {
        Ok(()) => next.run(request).await,
        Err(code) => denial(code),
    })
}

/// ADR-0125 D7: hardening is shared by every auth and OAuth response.
pub(crate) fn harden(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static(REFERRER_POLICY),
    );
    response
}

async fn login_form() -> Response {
    page(StatusCode::OK, LOGIN_PAGE)
}

#[derive(Deserialize)]
struct LoginForm {
    email: String,
}

async fn login_submit(
    State(pages): State<Shared>,
    headers: HeaderMap,
    form: Result<Form<LoginForm>, FormRejection>,
) -> Response {
    if !same_origin(&headers, &pages.config.public_origin) {
        return forbidden();
    }
    let Ok(Form(form)) = form else {
        return page(StatusCode::BAD_REQUEST, BAD_REQUEST_PAGE);
    };
    let Some(canonical) = mailbox(&form.email) else {
        return page(StatusCode::BAD_REQUEST, BAD_REQUEST_PAGE);
    };
    let mail = LoginMail {
        from_email: &pages.config.mail_from,
        subject: LOGIN_MAIL_SUBJECT,
    };
    let started = login_repo::start(
        &pages.pool,
        &pages.config.code_pepper,
        pages.config.auth.login_challenge,
        &mail,
        &pages.config.allowlist,
        &canonical,
    )
    .await;
    // The receipt's disposition is for logs only (login_repo::start); the answer never depends on it.
    if started.is_err() {
        return denial(ErrorCode::DependencyUnavailable);
    }
    let ttl = pages.config.auth.login_challenge.ttl.as_secs();
    let payload = format!("{}{FIELD_SEP}{canonical}", unix_now().saturating_add(ttl));
    let pending = pages.config.keys.sign(&PENDING_LABEL, &payload);
    redirect(CODE_PATH, [cookie(PENDING_COOKIE_NAME, &pending, ttl)])
}

async fn code_form(State(pages): State<Shared>, headers: HeaderMap) -> Response {
    if pending_mailbox(&pages, &headers).is_none() {
        return redirect(LOGIN_PATH, []);
    }
    page(StatusCode::OK, CODE_PAGE)
}

#[derive(Deserialize)]
struct CodeForm {
    code: String,
}

async fn code_submit(
    State(pages): State<Shared>,
    headers: HeaderMap,
    form: Result<Form<CodeForm>, FormRejection>,
) -> Response {
    if !same_origin(&headers, &pages.config.public_origin) {
        return forbidden();
    }
    let (Ok(Form(form)), Some(address)) = (form, pending_mailbox(&pages, &headers)) else {
        return rejected();
    };
    let candidate = form.code.trim();
    if candidate.is_empty() || candidate.len() > MAX_CODE_BYTES {
        return rejected();
    }
    let Ok(outcome) =
        login_repo::verify_code(&pages.pool, &pages.config.code_pepper, &address, candidate).await
    else {
        return denial(ErrorCode::DependencyUnavailable);
    };
    let issued = match session_repo::issue(&pages.pool, &pages.session, outcome).await {
        Ok(Some(issued)) => issued,
        Ok(None) => return rejected(),
        Err(_) => return denial(ErrorCode::DependencyUnavailable),
    };
    let session = cookie(
        SESSION_COOKIE_NAME,
        &issued.secret.cookie_value(),
        pages.session.absolute_ttl.as_secs(),
    );
    redirect(CONSOLE_ROOT, [session, cookie(PENDING_COOKIE_NAME, "", 0)])
}

/// Revokes the caller's session when, and only when, the request carries the CSRF token minted for that session.
async fn logout(State(pages): State<Shared>, headers: HeaderMap) -> Response {
    if !same_origin(&headers, &pages.config.public_origin) {
        return forbidden();
    }
    let Some(secret) =
        cookie_value(&headers, SESSION_COOKIE_NAME).and_then(SessionSecret::from_cookie_value)
    else {
        return forbidden();
    };
    let verified = match session_repo::authenticate(&pages.pool, &pages.session, &secret).await {
        Ok(Some(verified)) => verified,
        Ok(None) => return forbidden(),
        Err(_) => return denial(ErrorCode::DependencyUnavailable),
    };
    let allowed = verify_csrf(
        "POST",
        FetchSite::from_header(header_str(&headers, FETCH_SITE_HEADER_NAME)),
        header_str(&headers, CSRF_HEADER_NAME),
        &csrf_token(&pages.config.keys, verified.session_id),
    );
    if !allowed {
        return forbidden();
    }
    match session_repo::revoke(&pages.pool, verified.session_id).await {
        Ok(_) => redirect(LOGIN_PATH, [cookie(SESSION_COOKIE_NAME, "", 0)]),
        Err(_) => denial(ErrorCode::DependencyUnavailable),
    }
}

/// ADR-0125 ruling 4: the request's `Origin` (its `Referer` when `Origin` is absent) must be the public origin. Anything
/// else, `Origin: null` and a repeated `Origin` included, fails closed.
fn same_origin(headers: &HeaderMap, public_origin: &str) -> bool {
    let mut origins = headers.get_all(header::ORIGIN).iter();
    match (origins.next(), origins.next()) {
        (Some(origin), None) => origin.to_str().is_ok_and(|origin| origin == public_origin),
        (None, _) => header_str(headers, "referer").is_some_and(|referer| {
            referer
                .strip_prefix(public_origin)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        }),
        _ => false,
    }
}

/// The canonical mailbox of a form field, or `None` for anything that cannot be an address.
fn mailbox(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let clean =
        raw.len() <= MAX_MAILBOX_BYTES && !raw.chars().any(|c| c.is_control() || c.is_whitespace());
    if !clean {
        return None;
    }
    canonicalize_email(raw).ok().map(|(_, canonical)| canonical)
}

/// The mailbox of a live pending-login cookie: MAC-verified under the auth key and not past its expiry.
fn pending_mailbox(pages: &Pages, headers: &HeaderMap) -> Option<String> {
    let token = cookie_value(headers, PENDING_COOKIE_NAME)?;
    let payload = pages.config.keys.verify(&PENDING_LABEL, token).ok()?;
    let (expires, address) = payload.split_once(FIELD_SEP)?;
    (expires.parse::<u64>().ok()? > unix_now()).then(|| address.to_owned())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// `Set-Cookie` value with the §73.6 attributes; `Max-Age=0` and an empty value clear it.
fn cookie(name: &str, value: &str, max_age_seconds: u64) -> String {
    format!(
        "{name}={value}; Max-Age={max_age_seconds}; {}",
        session_cookie_attributes(SameSitePolicy::Lax)
    )
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// The one value of a header that may appear at most once; a repeat or a non-text value is `Err`.
fn single_header(headers: &HeaderMap, name: &str) -> Result<Option<String>, ()> {
    let mut values = headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (None, _) => Ok(None),
        (Some(value), None) => value
            .to_str()
            .map(|text| Some(text.to_owned()))
            .map_err(|_| ()),
        _ => Err(()),
    }
}

fn page(status: StatusCode, body: &'static str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

/// `303 See Other` with an empty body; the same bytes for every caller of the same route.
fn redirect<const N: usize>(to: &'static str, cookies: [String; N]) -> Response {
    let mut response = axum::http::Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, to);
    for value in cookies {
        response = response.header(header::SET_COOKIE, value);
    }
    response
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn forbidden() -> Response {
    page(StatusCode::FORBIDDEN, FORBIDDEN_PAGE)
}

/// ADR-0125 ruling 3: the one answer to every failed code attempt, whatever failed.
fn rejected() -> Response {
    page(StatusCode::BAD_REQUEST, REJECTED_PAGE)
}

/// A guard or dependency refusal as a page; the status is the only detail.
fn denial(code: ErrorCode) -> Response {
    match code {
        ErrorCode::Forbidden => forbidden(),
        ErrorCode::RateLimited => page(StatusCode::TOO_MANY_REQUESTS, BUSY_PAGE),
        _ => page(StatusCode::SERVICE_UNAVAILABLE, BUSY_PAGE),
    }
}
