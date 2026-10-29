//! `billing-worker::tests::fetch` — authoritative reads through HTTP (§71.3).
//! Depends-on: crates=[humaux-application, humaux-domain, humaux-infra-egress, serde_json, tokio, uuid]; services=[HTTP(loopback)]; env=[]; modules=[application::billing, billing-worker::creem, billing-worker::fake_creem, billing-worker::mode, billing-worker::normalize, domain::billing, domain::egress, domain::error, domain::ids, infra-egress::http]
//! Called-by: [cargo-test]
//! Invariants: [no external calls; wrong credentials and altered bodies fail closed]
//! Spec: Baseline §71.2; §71.3; §79.5
#[path = "../src/fake_creem.rs"]
mod fake_creem;
use fake_creem::{FixtureCredential, TEST_KEY};
use humaux_application::billing::{BillingProvider, ExternalSubscriptionRef};
use humaux_billing_worker::{creem::CreemClient, mode::BillingMode, normalize::PaymentAmount};
use humaux_domain::{
    billing::ObservedStatus, egress::ProcessorId, error::ErrorCode, ids::TenantId,
};
use humaux_infra_egress::http::HttpEgressConfig;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;
// §79.4: fixed public fixture bytes, not a credential; test-only source.
/// Webhook signing secret, random per test run and shared by the fake signer and the client (no literal key).
fn test_secret() -> &'static str {
    static SECRET: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SECRET.get_or_init(|| Uuid::new_v4().to_string())
}
fn client(base: &str, key: &'static str) -> CreemClient {
    CreemClient::new(
        base,
        &BillingMode::parse(Some("fake"), None).unwrap(),
        TenantId::new(),
        ProcessorId(Uuid::new_v4()),
        HttpEgressConfig::default(),
        Arc::new(FixtureCredential(key)),
        Arc::new(FixtureCredential(test_secret())),
    )
    .unwrap()
}
#[tokio::test]
async fn authoritative_fetch_and_authentication() {
    let transaction = json!({"id":"txn_fixture","amount":500,"currency":"USD","tax_amount":50,"period_start":1000,"period_end":2000});
    let subscription = json!({"id":"sub_fixture","customer":{"id":"cust_fixture"},"product":{"id":"prod_fixture"},"status":"past_due","current_period_start_date":"2026-10-01T00:00:00Z","current_period_end_date":"2026-11-01T00:00:00Z"});
    // dep: HTTP(loopback) — §79.4 isolated provider double; no external network.
    let (base, server) = fake_creem::start(subscription, transaction.clone()).await;
    let provider = client(&base, TEST_KEY);
    assert_eq!(
        provider.fetch_transaction("txn_fixture").await,
        Ok(transaction)
    );
    let fetched = provider
        .fetch_subscription(&ExternalSubscriptionRef("sub_fixture".into()))
        .await
        .unwrap();
    assert_eq!(
        (
            fetched.reference.0.as_str(),
            fetched.customer.0.as_str(),
            fetched.status
        ),
        ("sub_fixture", "cust_fixture", ObservedStatus::PastDue)
    );
    assert_eq!(fetched.product, "prod_fixture");
    assert_eq!(
        (
            fetched.current_period_start.unix_timestamp(),
            fetched.current_period_end.unix_timestamp()
        ),
        (1790812800, 1793491200)
    );
    let raw = serde_json::to_vec(&json!({"id":"evt_fixture","eventType":"subscription.paid","created_at":3000,"object":{"id":"sub_fixture","last_transaction":{"id":"txn_fixture"}}})).unwrap();
    let signed = fake_creem::sign(&raw, test_secret().as_bytes());
    let headers = [("creem-signature", signed.as_str())];
    let normalized = provider.normalize_event(&headers, &raw).await.unwrap();
    assert_eq!(normalized.provider_txn_ref.as_deref(), Some("txn_fixture"));
    assert_eq!(
        normalized.money.unwrap().amount,
        PaymentAmount::Charge {
            charged_amount: 500
        }
    );
    assert_eq!(
        client(&base, "wrong-fixture-token")
            .fetch_transaction("txn_fixture")
            .await,
        Err(ErrorCode::Unauthorized)
    );
    assert_eq!(
        provider.fetch_transaction("missing").await,
        Err(ErrorCode::ProviderPermanent)
    );
    assert_eq!(
        provider.verify_webhook(&[], &raw).await,
        Err(ErrorCode::Unauthorized)
    );
    assert_eq!(
        provider.verify_webhook(&headers, b"{}").await,
        Err(ErrorCode::Unauthorized)
    );
    assert_eq!(
        provider
            .verify_webhook(&headers, &raw)
            .await
            .unwrap()
            .event_id,
        "evt_fixture"
    );
    server.abort();
}
