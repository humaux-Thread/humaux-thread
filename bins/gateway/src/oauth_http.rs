//! `gateway::oauth_http` — M02 token exchange and authorization-server metadata.
//! Depends-on: crates=[axum, hex, humaux-adapters, humaux-application, humaux-domain, rand, serde, serde_json, time];
//!   services=[]; env=[]; modules=[adapters::oauth_repo, adapters::postgres, application::oauth,
//!   application::signed_token, domain::error, gateway::auth_pages, gateway::guard]
//! Called-by: [gateway::bootstrap, gateway::main, tests]
//! Invariants: [refusals render only OAUTH_REASONS strings; precheck precedes consume; spent codes and revoking denies
//!   commit, other denies roll back; no raw code or refresh token is logged or stored]
//! Spec: §73.5; §78.1; M02 D3; M02 D4; M02 D9; RFC 8414; RFC 8707; RFC 6749 §5; MCP 2026-07-28

use crate::{auth_pages, guard::GatewayGuard};
use axum::{
    Form, Json, Router,
    extract::{ConnectInfo, Request, State, rejection::FormRejection},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use humaux_adapters::{
    oauth_repo::{
        self, GrantIssue, GrantRecord, GrantStatus, OAuthTxn, RevokeReason, RotateOutcome,
        SecretHash,
    },
    postgres::RuntimeDbPool,
};
use humaux_application::{
    oauth::{
        self, ACCESS_TOKEN_LABEL, AccessTerms, CodeExchangeRequest, ConsumedCodeView, GrantView,
        OAuthPolicy, OAuthReason, OAuthRefusal, RefreshDecision, RefreshRequest, RevokeCause,
        RotationFact, SUPPORTED_SCOPES,
    },
    signed_token::TokenKeys,
};
use humaux_domain::error::ErrorCode;
use rand::{TryRngCore as _, rngs::OsRng};
use serde::Serialize;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use time::OffsetDateTime;

const SERVER_ERROR: &str = "server_error";

/// M02 D3/D4 policy and auth MAC keys; constructed only while the auth surface is enabled (§78.1).
pub struct OAuthHttpConfig {
    /// Dedicated auth key pair.
    pub keys: TokenKeys,
    /// Normalized public origin, identical to the metadata issuer (RFC 8414 §3.3).
    pub issuer: String,
    /// Authorization-code lifetime, consumed by M02-10b.
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
            // token endpoint never consults the allowlist; code and grant carry the resource validated at authorize (M02-10b adds the key)
            allowed_resources: &[],
            supported_scopes: &[],
        }
    }
}

struct HttpState {
    guard: Arc<GatewayGuard>,
    pool: Arc<RuntimeDbPool>,
    config: OAuthHttpConfig,
}

/// The two M02-10 routes, inside admission and the one pre-auth layer (ADR-0125 D1/D3).
pub fn router(guard: Arc<GatewayGuard>, config: OAuthHttpConfig) -> Router {
    let state = Arc::new(HttpState {
        pool: guard.runtime_pool(),
        guard,
        config,
    });
    Router::new()
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route("/oauth/token", post(token))
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

async fn token(
    State(state): State<Arc<HttpState>>,
    form: Result<Form<Vec<(String, String)>>, FormRejection>,
) -> Response {
    let params = Params(form.map_or_else(|_| vec![], |Form(values)| values));
    let result = match params.get("grant_type") {
        Some("refresh_token") => refresh(&state, &params).await,
        _ => code(&state, &params).await,
    };
    result.unwrap_or_else(server_failure)
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

fn secret() -> Result<String, ErrorCode> {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| ErrorCode::Internal)?;
    Ok(hex::encode(bytes))
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

async fn spent(txn: OAuthTxn, reason: OAuthReason) -> Result<Response, ErrorCode> {
    txn.commit().await?;
    Ok(refusal(reason))
}

async fn code(state: &HttpState, params: &Params) -> Result<Response, ErrorCode> {
    let request = params.code_request();
    if let Err(error) = oauth::precheck_code_exchange(&request) {
        return Ok(refusal(error.reason));
    }
    let Some(presented) = params.get("code") else {
        return Ok(refusal(OAuthReason::CODE_INVALID));
    };
    let mut txn = oauth_repo::begin(&state.pool).await?;
    let Some(consumed) = txn.consume_code(&SecretHash::of_secret(presented)).await? else {
        return Ok(refusal(OAuthReason::CODE_INVALID));
    };
    // ponytail: tokens issued from a replayed code are not revoked (no code→grant link in 0268); add the link + revoke in a migration card (RFC 6749 §4.1.2 SHOULD)
    let view = ConsumedCodeView {
        client_id: &consumed.client_id,
        redirect_uri: &consumed.redirect_uri,
        pkce_challenge: &consumed.pkce_challenge,
        resource: &consumed.resource,
        user_id: consumed.user_id,
        tenant_id: consumed.tenant_id,
        workspace_id: consumed.workspace_id,
        scopes: &consumed.scopes,
    };
    let terms = match oauth::exchange_code(&request, &view, &state.config.policy()) {
        Ok(terms) => terms,
        Err(error) => return spent(txn, error.reason).await,
    };
    let refresh = secret()?;
    let hash = SecretHash::of_secret(&refresh);
    let issued = txn
        .issue_grant(&GrantIssue {
            user_id: terms.user_id,
            tenant_id: terms.tenant_id,
            workspace_id: terms.workspace_id,
            client_id: &terms.client_id,
            resource: &terms.resource,
            scopes: &terms.scopes,
            refresh_hash: &hash,
            refresh_ttl: terms.refresh_ttl,
            grant_max_ttl: terms.grant_max_ttl,
        })
        .await?;
    let Some(issued) = issued else {
        return spent(txn, OAuthReason::GRANT_CLOSED).await;
    };
    let grant = txn
        .lookup_grant(issued.grant_id)
        .await?
        .ok_or(ErrorCode::Internal)?;
    let now = OffsetDateTime::now_utc();
    let access = oauth::access_terms(
        issued.grant_id,
        &grant_view(&grant),
        now,
        &state.config.policy(),
    );
    let response = success(&state.config, &access, &refresh, now);
    txn.commit().await?;
    Ok(response)
}

fn grant_view(grant: &GrantRecord) -> GrantView<'_> {
    GrantView {
        client_id: &grant.client_id,
        resource: &grant.resource,
        scopes: &grant.scopes,
        active: grant.status == Some(GrantStatus::Active),
        revoked_at: grant.revoked_at,
        grant_max_expires_at: grant.grant_max_expires_at,
        user_epoch_snapshot: grant.user_epoch_snapshot,
        tenant_epoch_snapshot: grant.tenant_epoch_snapshot,
        live_user_epoch: grant.live_user_epoch,
        live_tenant_epoch: grant.live_tenant_epoch,
    }
}

fn rotation_fact(outcome: RotateOutcome) -> RotationFact {
    match outcome {
        RotateOutcome::Rotated {
            grant_id,
            family_id,
            expires_at,
        } => RotationFact::Rotated {
            grant_id,
            family_id,
            expires_at,
        },
        RotateOutcome::ReuseDetected {
            grant_id,
            family_id,
        } => RotationFact::ReuseDetected {
            grant_id,
            family_id,
        },
        RotateOutcome::Rejected => RotationFact::Rejected,
    }
}

async fn refresh(state: &HttpState, params: &Params) -> Result<Response, ErrorCode> {
    let Some(presented) = params.get("refresh_token") else {
        return Ok(refusal(OAuthReason::REFRESH_REJECTED));
    };
    let successor = secret()?;
    let mut txn = oauth_repo::begin(&state.pool).await?;
    let fact = rotation_fact(
        txn.rotate_refresh(
            &SecretHash::of_secret(presented),
            &SecretHash::of_secret(&successor),
            state.config.refresh_ttl,
        )
        .await?,
    );
    let grant = match fact {
        RotationFact::Rotated { grant_id, .. } => txn.lookup_grant(grant_id).await?,
        _ => None,
    };
    let view = grant.as_ref().map(grant_view);
    let request = RefreshRequest {
        client_id: params.get("client_id").unwrap_or_default(),
        resource: params.get("resource"),
    };
    let now = OffsetDateTime::now_utc();
    // RFC 6749 §6 / OPEN-5: requested scope is ignored; only the stored grant's scopes are returned.
    match oauth::decide_refresh(fact, view.as_ref(), &request, now, &state.config.policy()) {
        RefreshDecision::Issue { access, .. } => {
            let response = success(&state.config, &access, &successor, now);
            txn.commit().await?;
            Ok(response)
        }
        RefreshDecision::Deny {
            refusal: OAuthRefusal { reason, .. },
            revoke,
        } => {
            if let Some(revoke) = revoke {
                let cause = match revoke.cause {
                    RevokeCause::RefreshReuse => RevokeReason::RefreshReuse,
                    RevokeCause::SecurityEpoch => RevokeReason::SecurityEpoch,
                };
                if let Some(family) = revoke.family_id {
                    txn.revoke_family(family, cause).await?;
                } else {
                    txn.revoke_grant(revoke.grant_id, cause).await?;
                }
                return spent(txn, reason).await;
            }
            Ok(refusal(reason))
        }
    }
}
