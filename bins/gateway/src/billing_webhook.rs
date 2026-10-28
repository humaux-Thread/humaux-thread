//! `gateway::billing_webhook` — verified inbox ingress only (§71.3); M04-11 owns processing.
//! Depends-on: crates=[axum, humaux-adapters, humaux-application, humaux-domain, serde_json]; services=[]; env=[];
//!   modules=[adapters::billing_repo, application::signed_token, domain::billing, domain::error, gateway::admission, gateway::auth_pages, gateway::guard]
//! Called-by: [gateway::bootstrap, gateway::main, tests]
//! Invariants: [admission buffers first; provider, cap and MAC precede parsing; no secret Debug; duplicates acknowledge]
//! Spec: §71.3; §52; §78.1; M04 D7

use axum::{
    Router,
    body::to_bytes,
    extract::{ConnectInfo, Path, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    routing::post,
};
use humaux_adapters::billing_repo;
use humaux_application::signed_token::verify_hmac_sha256_hex;
use humaux_domain::{billing::BillingProviderId, error::ErrorCode};
use serde_json::Value;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use crate::{
    admission::{self, Admission},
    auth_pages,
    guard::GatewayGuard,
};

/// §71.3: one provider's unlabelled HMAC-SHA256-hex ingress contract; never exposes secret bytes through Debug.
pub struct BillingWebhookConfig {
    /// §78.2: the inbox's closed provider vocabulary.
    pub provider: BillingProviderId,
    /// §71.3: exactly one signature header is accepted.
    pub signature_header: String,
    /// §71.3: non-empty signing secret, checked at boot.
    pub secret: Vec<u8>,
    /// §71.3: pointer into the verified envelope for its stable delivery key.
    pub event_id_pointer: String,
    /// §71.3: pointer into the verified envelope for its event kind.
    pub event_type_pointer: String,
    /// §78.1: per-provider cap after admission's global buffering.
    pub body_max_bytes: usize,
}

struct WebhookState {
    guard: Arc<GatewayGuard>,
    providers: HashMap<String, BillingWebhookConfig>,
}

/// §71.3: merged inside admission, independently of the auth-pages switch.
pub fn router(
    guard: Arc<GatewayGuard>,
    providers: HashMap<String, BillingWebhookConfig>,
) -> Router {
    let state = Arc::new(WebhookState { guard, providers });
    Router::new()
        .route("/v1/billing/webhooks/{provider}", post(ingress))
        .layer(middleware::from_fn_with_state(Arc::clone(&state), gate))
        .with_state(state)
}

/// §71.3 / ADR-0065 D-C: production and tests share the webhook's admission boundary.
pub fn compose(
    routes: Router,
    supervision: Router,
    admission: Arc<Admission>,
    guard: Arc<GatewayGuard>,
    providers: Option<HashMap<String, BillingWebhookConfig>>,
) -> Router {
    let webhook = providers.map(|p| router(guard, p)).unwrap_or_default();
    admission::wrap(routes.merge(webhook), supervision, admission)
}

// §71.3: jsonb cannot represent U+0000 in either object keys or string values.
fn jsonb_storable(value: &Value) -> bool {
    match value {
        Value::String(s) => !s.contains('\0'),
        Value::Array(values) => values.iter().all(jsonb_storable),
        Value::Object(fields) => fields
            .iter()
            .all(|(k, v)| !k.contains('\0') && jsonb_storable(v)),
        _ => true,
    }
}

async fn gate(
    State(state): State<Arc<WebhookState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    auth_pages::guarded(&state.guard, "billing_webhook", peer, request, next).await
}

async fn ingress(
    State(state): State<Arc<WebhookState>>,
    Path(provider): Path<String>,
    request: Request,
) -> StatusCode {
    let Some(config) = state.providers.get(&provider) else {
        return StatusCode::NOT_FOUND;
    };
    let (headers, body) = request.into_parts();
    let Ok(body) = to_bytes(body, config.body_max_bytes).await else {
        return StatusCode::PAYLOAD_TOO_LARGE;
    };
    let mut signatures = headers
        .headers
        .get_all(config.signature_header.as_str())
        .iter();
    let signature = signatures.next().and_then(|v| v.to_str().ok());
    if signatures.next().is_some()
        || !signature.is_some_and(|s| verify_hmac_sha256_hex(&config.secret, &body, s))
    {
        return StatusCode::UNAUTHORIZED;
    }
    let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
        return StatusCode::BAD_REQUEST;
    };
    if !jsonb_storable(&payload) {
        return StatusCode::BAD_REQUEST;
    }
    let (Some(id), Some(kind)) = (
        payload
            .pointer(&config.event_id_pointer)
            .and_then(Value::as_str),
        payload
            .pointer(&config.event_type_pointer)
            .and_then(Value::as_str),
    ) else {
        return StatusCode::BAD_REQUEST;
    };
    match billing_repo::inbox_insert(
        &state.guard.runtime_pool(),
        config.provider,
        id,
        kind,
        None,
        None,
        &payload,
    )
    .await
    {
        Ok(_) => StatusCode::OK,
        Err(ErrorCode::DependencyUnavailable) => StatusCode::SERVICE_UNAVAILABLE,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
