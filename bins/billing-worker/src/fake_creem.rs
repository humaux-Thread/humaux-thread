//! `billing-worker::fake_creem` — test-only HTTP double (§71.2).
//! Depends-on: crates=[async-trait, axum, hex, hmac, humaux-domain, humaux-infra-egress, serde_json, sha2, tokio]; services=[HTTP(loopback)]; env=[]; modules=[domain::error, infra-egress::http]
//! Called-by: [billing-worker::tests::fetch]
//! Invariants: [loopback only; exact query identities; no M04-10 dependency]
//! Spec: Baseline §71.2; §71.3; §79.4
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::get,
};
use hmac::{Hmac, KeyInit, Mac};
use humaux_domain::error::ErrorCode;
use humaux_infra_egress::http::{EgressSecret, RetrievalCredentialSource};
use serde_json::Value;
use sha2::Sha256;
use std::collections::BTreeMap;

/// §79.4: public fixture token, not an API credential.
pub const TEST_KEY: &str = "public-fixture-api-token";
/// §79.4: injectable test source, never reads a real key.
pub struct FixtureCredential(
    /// §79.4: public fixture material only.
    pub &'static str,
);
#[async_trait::async_trait]
impl RetrievalCredentialSource for FixtureCredential {
    async fn credential(&self) -> Result<EgressSecret, ErrorCode> {
        Ok(EgressSecret::new(self.0.into()))
    }
}
/// §71.3: signature covers the exact supplied bytes, without serializing again.
pub fn sign(raw: &[u8], secret: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret).unwrap();
    mac.update(raw);
    hex::encode(mac.finalize().into_bytes())
}
/// §71.2: caller owns shutdown through the returned task handle.
pub async fn start(
    subscription: Value,
    transaction: Value,
) -> (String, tokio::task::JoinHandle<()>) {
    let router = Router::new()
        .route("/v1/subscriptions", get(read))
        .route("/v1/transactions", get(read))
        .with_state([subscription, transaction]);
    // dep: HTTP(loopback) — §79.4 isolated provider double; no external network.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    (
        base,
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        }),
    )
}
async fn read(
    State(objects): State<[Value; 2]>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    if headers.get("x-api-key").and_then(|v| v.to_str().ok()) != Some(TEST_KEY) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let (index, parameter) = if uri.path() == "/v1/subscriptions" {
        (0, "subscription_id")
    } else {
        (1, "transaction_id")
    };
    if query.len() != 1 || query.get(parameter).map(String::as_str) != objects[index]["id"].as_str()
    {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(Json(objects[index].clone()))
}
