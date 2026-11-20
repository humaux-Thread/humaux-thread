//! `gateway::oauth_http` — M02 browser authorization, token exchange, revocation and AS metadata.
//! Depends-on: crates=[axum, humaux-adapters, humaux-application, humaux-domain, humaux-protocol, serde, serde_json, time, url, uuid]; services=[]; env=[]; modules=[adapters::postgres, application::login, application::oauth, application::oauth_exchange, application::read_quota, application::session, application::signed_token, domain::error, domain::identity, gateway::auth_pages, gateway::bootstrap, gateway::guard, protocol::edge]
//! Called-by: [gateway::bootstrap, gateway::main, tests]
//! Invariants: [refusals render only OAUTH_REASONS strings; precheck precedes consume; spent codes and revoking denies
//!   commit, other denies roll back; no raw code or refresh token is logged or stored]
//! Spec: §73.5; §78.1; M02 D3; M02 D4; M02 D9; RFC 8414; RFC 8707; RFC 6749 §5; MCP 2026-07-28

use crate::{auth_pages, guard::GatewayGuard};
use axum::{
    Form, Json, Router,
    extract::{ConnectInfo, RawQuery, Request, State, rejection::FormRejection},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use humaux_adapters::postgres::RuntimeDbPool;
use humaux_application::{
    login::{self, PasswordlessLoginPort},
    oauth::{
        self, ACCESS_TOKEN_LABEL, AccessTerms, AuthorizeRequest, ClientView, CodeExchangeRequest,
        ConsentSubject, OAuthPolicy, OAuthReason, RefreshRequest, SUPPORTED_SCOPES,
        ValidatedAuthorize,
    },
    oauth_exchange::{self, ExchangeStore},
    read_quota::{self, BMO_ENTITLEMENT},
    session::{SessionSecret, VerifiedSession, csrf_token},
    signed_token::{FIELD_SEP, TokenKeys, TokenLabel},
};
use humaux_domain::{
    error::ErrorCode,
    identity::{AuthorizationScope, BoundedSet, PrincipalId},
};
use humaux_protocol::edge::{FETCH_SITE_HEADER_NAME, FetchSite, SESSION_COOKIE_NAME, verify_csrf};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use time::OffsetDateTime;
use url::{Url, form_urlencoded};

const AUTHORIZE: &str = "/oauth/authorize";
const REVOKE: &str = "/oauth/revoke";
const CONSENT_LABEL: TokenLabel = TokenLabel::new(b"oauth-consent@1", b"oauth-consent.kid@1");
// A signed, hex-encoded return value must fit in the browser's 4 KiB cookie.
const MAX_AUTH_QUERY: usize = 1750;

const SERVER_ERROR: &str = "server_error";

/// M02 D3/D4 policy and auth MAC keys; constructed only while the auth surface is enabled (§78.1).
pub struct OAuthHttpConfig {
    /// Dedicated auth key pair.
    pub keys: TokenKeys,
    /// Normalized public origin, identical to the metadata issuer (RFC 8414 §3.3).
    pub issuer: String,
    /// Exact permitted resource URI (RFC 8707).
    pub resource: String,
    /// Same lifetime as the interactive login challenge.
    pub login_return_ttl: Duration,
    /// Authorization-code lifetime.
    pub code_ttl: Duration,
    /// Access-token lifetime.
    pub access_ttl: Duration,
    /// Refresh-token lifetime.
    pub refresh_ttl: Duration,
    /// Absolute grant lifetime.
    pub grant_max_ttl: Duration,
}

impl OAuthHttpConfig {
    fn policy(&self) -> OAuthPolicy<'_> {
        OAuthPolicy {
            code_ttl: self.code_ttl,
            access_ttl: self.access_ttl,
            refresh_ttl: self.refresh_ttl,
            grant_max_ttl: self.grant_max_ttl,
            // Token exchange checks the resource in the code or grant, not the current authorize allowlist.
            allowed_resources: &[],
            supported_scopes: &[],
        }
    }
}

struct HttpState {
    guard: Arc<GatewayGuard>,
    pool: Arc<RuntimeDbPool>,
    config: OAuthHttpConfig,
    login: Arc<dyn PasswordlessLoginPort>,
    scopes: [String; SUPPORTED_SCOPES.len()],
}

/// The M02 OAuth routes, inside admission and the one pre-auth layer (ADR-0125 D1/D3).
pub fn router(
    guard: Arc<GatewayGuard>,
    config: OAuthHttpConfig,
    login: Arc<dyn PasswordlessLoginPort>,
) -> Router {
    let state = Arc::new(HttpState {
        pool: guard.runtime_pool(),
        guard,
        config,
        login,
        scopes: SUPPORTED_SCOPES.map(str::to_owned),
    });
    Router::new()
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route("/oauth/token", post(token))
        .route(AUTHORIZE, get(authorize).post(consent))
        .route(REVOKE, post(revoke))
        .layer(middleware::from_fn_with_state(Arc::clone(&state), gate))
        .with_state(state)
}

async fn gate(
    State(state): State<Arc<HttpState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    auth_pages::guarded(&state.guard, "oauth", peer, request, next).await
}

#[derive(Serialize)]
struct Metadata<'a> {
    issuer: &'a str,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
    revocation_endpoint_auth_methods_supported: [&'static str; 1],
    response_types_supported: [&'static str; 1],
    grant_types_supported: [&'static str; 2],
    code_challenge_methods_supported: [&'static str; 1],
    token_endpoint_auth_methods_supported: [&'static str; 1],
    scopes_supported: [&'static str; 5],
    authorization_response_iss_parameter_supported: bool,
}

/// Compact, ordered RFC 8414 document; capabilities outside M02-10 are not advertised.
pub fn metadata_document(issuer: &str) -> String {
    serde_json::to_string(&Metadata {
        issuer,
        authorization_endpoint: format!("{issuer}/oauth/authorize"),
        token_endpoint: format!("{issuer}/oauth/token"),
        revocation_endpoint: format!("{issuer}{REVOKE}"),
        revocation_endpoint_auth_methods_supported: ["none"],
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
        scopes_supported: SUPPORTED_SCOPES,
        authorization_response_iss_parameter_supported: true,
    })
    .expect("metadata contains only strings and a bool")
}

async fn metadata(State(state): State<Arc<HttpState>>) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        metadata_document(&state.config.issuer),
    )
        .into_response()
}

struct Params(Vec<(String, String)>);
impl Params {
    // RFC 6749 §3.2: a repeated parameter is absent, even when both values are identical.
    fn get(&self, key: &str) -> Option<&str> {
        let mut values = self
            .0
            .iter()
            .filter(|(name, _)| name == key)
            .map(|(_, value)| value.as_str());
        let value = values.next()?;
        values.next().is_none().then_some(value)
    }
    fn authorize_request(&self) -> AuthorizeRequest<'_> {
        AuthorizeRequest {
            client_id: self.get("client_id").unwrap_or_default(),
            redirect_uri: self.get("redirect_uri"),
            response_type: self.get("response_type"),
            code_challenge: self.get("code_challenge"),
            code_challenge_method: self.get("code_challenge_method"),
            resource: self.get("resource"),
            scope: self.get("scope"),
            state: self.get("state"),
        }
    }

    fn code_request(&self) -> CodeExchangeRequest<'_> {
        CodeExchangeRequest {
            grant_type: self.get("grant_type"),
            client_id: self.get("client_id").unwrap_or_default(),
            redirect_uri: self.get("redirect_uri"),
            code_verifier: self.get("code_verifier"),
            resource: self.get("resource"),
        }
    }
}

async fn live_session(
    state: &HttpState,
    headers: &HeaderMap,
) -> Result<Option<VerifiedSession>, ErrorCode> {
    let Some(secret) = auth_pages::cookie_value(headers, SESSION_COOKIE_NAME)
        .and_then(SessionSecret::from_cookie_value)
    else {
        return Ok(None);
    };
    login::authenticate_session(state.login.as_ref(), &secret).await
}

async fn validate(state: &HttpState, query: &str) -> Result<ValidatedAuthorize, Response> {
    let params = Params(
        form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect(),
    );
    let request = params.authorize_request();
    let mut txn = state.pool.begin_exchange().await.map_err(server_failure)?;
    let client = txn
        .lookup_client(request.client_id)
        .await
        .map_err(server_failure)?;
    let client = client.as_ref().map(|c| ClientView {
        redirect_uris: &c.redirect_uris,
        kind_recognized: c.kind.is_some(),
        disabled: c.disabled_at.is_some(),
    });
    let policy = OAuthPolicy {
        allowed_resources: std::slice::from_ref(&state.config.resource),
        supported_scopes: &state.scopes,
        ..state.config.policy()
    };
    let result = oauth::authorize_request(&request, client.as_ref(), &policy);
    match result {
        Ok(validated) if valid_callback(&validated.redirect_uri) => Ok(validated),
        Ok(_) => Err(refusal(OAuthReason::REDIRECT_URI_INVALID)),
        Err(denied) => Err(authorize_refusal(state, &denied)),
    }
}

fn valid_callback(target: &str) -> bool {
    Url::parse(target).is_ok_and(|url| {
        !url.query_pairs()
            .any(|(key, _)| matches!(key.as_ref(), "code" | "state" | "error" | "iss"))
    })
}

fn callback(
    state: &HttpState,
    target: &str,
    echo: Option<&str>,
    key: &str,
    value: &str,
) -> Response {
    let mut pairs = form_urlencoded::Serializer::new(String::new());
    pairs
        .append_pair(key, value)
        .append_pair("iss", &state.config.issuer);
    if let Some(echo) = echo {
        pairs.append_pair("state", echo);
    }
    let separator = if target.contains('?') { '&' } else { '?' };
    auth_pages::redirect(&format!("{target}{separator}{}", pairs.finish()), [])
}

fn authorize_refusal(state: &HttpState, denied: &oauth::AuthorizeRefusal) -> Response {
    if let Some(target) = denied
        .redirect_to
        .as_deref()
        .filter(|uri| valid_callback(uri))
        && let Some(row) = denied.refusal.reason.row()
    {
        return callback(
            state,
            target,
            denied.state.as_deref(),
            "error",
            row.wire_error,
        );
    }
    refusal(denied.refusal.reason)
}

async fn sole_tenant(
    state: &HttpState,
    session: VerifiedSession,
) -> Result<AuthorizationScope, ErrorCode> {
    let mut txn = state.pool.begin_exchange().await?;
    let tenants = txn.consent_tenants(session.user_id).await?;
    let [tenant] = tenants.as_slice() else {
        return Err(ErrorCode::Forbidden);
    };
    txn.commit().await?;
    let scope = AuthorizationScope::new(
        *tenant,
        PrincipalId(session.user_id.0),
        Some(session.user_id),
        BoundedSet::new([])?,
    );
    read_quota::charge_policy_for(
        &crate::bootstrap::read_quota_store(state.pool.as_ref()),
        &scope,
        BMO_ENTITLEMENT,
    )
    .await?;
    Ok(scope)
}

fn consent_failure(code: ErrorCode) -> Response {
    match code {
        ErrorCode::Forbidden | ErrorCode::EntitlementRequired => auth_pages::forbidden(),
        _ => server_failure(code),
    }
}

async fn authorize(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let query = query.unwrap_or_default();
    if query.len() > MAX_AUTH_QUERY {
        return refusal(OAuthReason::CLIENT_UNKNOWN);
    }
    let validated = match validate(&state, &query).await {
        Ok(validated) => validated,
        Err(response) => return response,
    };
    let session = match live_session(&state, &headers).await {
        Ok(Some(session)) => session,
        Ok(None) => return request_login(&state, &query),
        Err(code) => return server_failure(code),
    };
    let tenant = match sole_tenant(&state, session).await {
        Ok(tenant) => tenant,
        Err(code) => return consent_failure(code),
    };
    show_consent(&state, &validated, session, tenant.tenant_id().0, &query)
}

fn request_login(state: &HttpState, query: &str) -> Response {
    auth_pages::oauth_login_redirect(
        &state.config.keys,
        query,
        state.config.login_return_ttl.as_secs(),
    )
}

fn html_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn show_consent(
    state: &HttpState,
    validated: &ValidatedAuthorize,
    session: VerifiedSession,
    tenant: uuid::Uuid,
    query: &str,
) -> Response {
    let ttl = state.config.code_ttl.as_secs();
    let expires = auth_pages::unix_now().saturating_add(ttl);
    let csrf = csrf_token(&state.config.keys, session.session_id);
    let ticket = state.config.keys.sign(
        &CONSENT_LABEL,
        &format!(
            "{expires}{FIELD_SEP}{}{FIELD_SEP}{}{FIELD_SEP}{query}",
            session.session_id.0, tenant
        ),
    );
    let client = html_text(&validated.client_id);
    let resource = html_text(&validated.resource);
    let scopes = html_text(&validated.scopes.join(", "));
    Html(format!(
        r#"<!doctype html><html lang="en"><meta charset="utf-8"><title>Authorize client</title>
<main><h1>Authorize client</h1><p>{client} requests {scopes} on {resource} for tenant {}.</p>
<form action="{AUTHORIZE}" method="post"><input type="hidden" name="ticket" value="{ticket}">
<input type="hidden" name="csrf" value="{csrf}">
<button type="submit" name="decision" value="allow">Allow</button>
<button type="submit" name="decision" value="deny">Deny</button></form></main></html>"#,
        tenant
    ))
    .into_response()
}

#[derive(Deserialize)]
struct ConsentForm {
    ticket: String,
    csrf: String,
    decision: String,
}

fn consent_ticket(
    config: &OAuthHttpConfig,
    ticket: &str,
    session: VerifiedSession,
) -> Option<(uuid::Uuid, String)> {
    let payload = config.keys.verify(&CONSENT_LABEL, ticket).ok()?;
    let mut parts = payload.splitn(4, FIELD_SEP);
    let expiry = parts.next()?.parse::<u64>().ok()?;
    let session_id = parts.next()?.parse::<uuid::Uuid>().ok()?;
    let tenant = parts.next()?.parse().ok()?;
    let query = parts.next()?;
    (expiry > auth_pages::unix_now() && session_id == session.session_id.0)
        .then(|| (tenant, query.to_owned()))
}

async fn consent(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
    form: Result<Form<ConsentForm>, FormRejection>,
) -> Response {
    if !auth_pages::same_origin(&headers, &state.config.issuer) {
        return auth_pages::forbidden();
    }
    let Ok(Form(form)) = form else {
        return auth_pages::forbidden();
    };
    let session = match live_session(&state, &headers).await {
        Ok(Some(session)) => session,
        Ok(None) => return auth_pages::forbidden(),
        Err(code) => return server_failure(code),
    };
    if !verify_csrf(
        "POST",
        FetchSite::from_header(auth_pages::header_str(&headers, FETCH_SITE_HEADER_NAME)),
        Some(&form.csrf),
        &csrf_token(&state.config.keys, session.session_id),
    ) {
        return auth_pages::forbidden();
    }
    let Some((tenant, query)) = consent_ticket(&state.config, &form.ticket, session) else {
        return auth_pages::forbidden();
    };
    let request = match validate(&state, &query).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    match form.decision.as_str() {
        "deny" => authorize_refusal(
            &state,
            &oauth::AuthorizeRefusal {
                refusal: oauth::OAuthRefusal::of(OAuthReason::CONSENT_DENIED),
                redirect_to: Some(request.redirect_uri),
                state: request.state,
            },
        ),
        "allow" => allow_consent(&state, session, tenant, &request).await,
        _ => auth_pages::forbidden(),
    }
}

async fn allow_consent(
    state: &HttpState,
    session: VerifiedSession,
    tenant: uuid::Uuid,
    request: &ValidatedAuthorize,
) -> Response {
    let tenant = match sole_tenant(state, session).await {
        Ok(current) if current.tenant_id().0 == tenant => current.tenant_id(),
        Ok(_) => return auth_pages::forbidden(),
        Err(code) => return consent_failure(code),
    };
    let subject = ConsentSubject {
        user_id: session.user_id,
        tenant_id: tenant,
        workspace_id: None,
    };
    let terms = match oauth::issue_code(request, &subject, &state.config.policy()) {
        Ok(terms) => terms,
        Err(code) => return server_failure(code),
    };
    match oauth_exchange::persist_consent_code(state.pool.as_ref(), &terms).await {
        Ok(Some(code)) => callback(
            state,
            &request.redirect_uri,
            request.state.as_deref(),
            "code",
            &code,
        ),
        Ok(None) => auth_pages::forbidden(),
        Err(code) => server_failure(code),
    }
}

async fn revoke(
    State(state): State<Arc<HttpState>>,
    form: Result<Form<Vec<(String, String)>>, FormRejection>,
) -> Response {
    let Ok(Form(values)) = form else {
        return refusal(OAuthReason::CLIENT_UNKNOWN);
    };
    let params = Params(values);
    let (Some(client), Some(token)) = (params.get("client_id"), params.get("token")) else {
        return refusal(OAuthReason::CLIENT_UNKNOWN);
    };
    if client.is_empty() || token.is_empty() {
        return refusal(OAuthReason::CLIENT_UNKNOWN);
    }
    match oauth_exchange::revoke_refresh(state.pool.as_ref(), client, token).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(code) => server_failure(code),
    }
}

async fn token(
    State(state): State<Arc<HttpState>>,
    form: Result<Form<Vec<(String, String)>>, FormRejection>,
) -> Response {
    let params = Params(form.map_or_else(|_| vec![], |Form(values)| values));
    let result = match params.get("grant_type") {
        Some("refresh_token") => {
            oauth_exchange::refresh_token(
                state.pool.as_ref(),
                &state.config.policy(),
                RefreshRequest {
                    client_id: params.get("client_id").unwrap_or_default(),
                    resource: params.get("resource"),
                },
                params.get("refresh_token"),
            )
            .await
        }
        _ => {
            oauth_exchange::exchange_code(
                state.pool.as_ref(),
                &state.config.policy(),
                params.code_request(),
                params.get("code"),
            )
            .await
        }
    };
    match result {
        Ok(Ok(tokens)) => success(
            &state.config,
            &tokens.access,
            &tokens.refresh,
            tokens.observed_at,
        ),
        Ok(Err(reason)) => refusal(reason),
        Err(code) => server_failure(code),
    }
}

fn refusal(reason: OAuthReason) -> Response {
    let Some(row) = reason.row() else {
        return server_failure(ErrorCode::Internal);
    };
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": row.wire_error})),
    )
        .into_response()
}

fn server_failure(code: ErrorCode) -> Response {
    let status = if code == ErrorCode::DependencyUnavailable {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    (status, Json(serde_json::json!({"error": SERVER_ERROR}))).into_response()
}

fn success(
    config: &OAuthHttpConfig,
    access: &AccessTerms,
    refresh: &str,
    now: OffsetDateTime,
) -> Response {
    Json(serde_json::json!({"access_token": config.keys.sign(&ACCESS_TOKEN_LABEL, &oauth::access_token_payload(access)),
        "token_type": "Bearer", "expires_in": (access.expires_at - now).whole_seconds().max(1),
        "refresh_token": refresh, "scope": access.scopes.join(" ")})).into_response()
}
