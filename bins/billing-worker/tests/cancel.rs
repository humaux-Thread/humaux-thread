//! `billing-worker::tests::cancel` — immediate cancellation HTTP contract (M04 D13h).
//! Depends-on: crates=[humaux-application, humaux-billing-worker, humaux-domain, humaux-infra-egress, serde_json, tokio, uuid]; services=[HTTP(loopback)]; env=[]; modules=[application::billing, billing-worker::creem, billing-worker::fake_creem, billing-worker::mode, domain::billing, domain::egress, domain::error, domain::ids, infra-egress::http]
//! Called-by: [cargo-test]
//! Invariants: [fixture credentials only; raw wire assertions; no automatic cancellation retry]
//! Spec: Baseline §71.2; §71.3; §79.4; M04 D13(h)
#[allow(dead_code)]
#[path = "../src/fake_creem.rs"]
mod fake_creem;
use fake_creem::{FixtureCredential, TEST_KEY};
use humaux_application::billing::{BillingProvider, ExternalSubscriptionRef};
use humaux_billing_worker::{creem::CreemClient, mode::BillingMode};
use humaux_domain::{
    billing::ObservedStatus, egress::ProcessorId, error::ErrorCode, ids::TenantId,
};
use humaux_infra_egress::http::HttpEgressConfig;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
fn client(base: &str, key: &'static str) -> CreemClient {
    CreemClient::new(
        base,
        &BillingMode::parse(Some("fake"), None).unwrap(),
        TenantId::new(),
        ProcessorId(Uuid::new_v4()),
        HttpEgressConfig::default(),
        Arc::new(FixtureCredential(key)),
        Arc::new(FixtureCredential(TEST_KEY)),
    )
    .unwrap()
}
fn subscription(id: &str) -> Value {
    json!({"id":id,"customer":{"id":"cust_fixture"},"product":"prod_fixture","status":"canceled",
        "current_period_start_date":"2026-10-01T00:00:00Z","current_period_end_date":"2026-11-01T00:00:00Z"})
}
#[tokio::test]
async fn cancel_wire_contract_and_typed_observation() {
    let id = "sub/a ?#%";
    let (base, server, requests) = fake_creem::start_cancel(subscription(id), 200).await;
    let provider: Box<dyn BillingProvider> = Box::new(client(&base, TEST_KEY));
    let observed = provider
        .cancel_subscription_now(&ExternalSubscriptionRef(id.into()))
        .await
        .unwrap();
    assert_eq!(observed.reference.0, id);
    assert_eq!(observed.customer.0, "cust_fixture");
    assert_eq!(observed.product, "prod_fixture");
    assert_eq!(observed.status, ObservedStatus::Canceled);
    assert!(observed.current_period_end > observed.current_period_start);
    let captured = requests.lock().unwrap();
    assert_eq!(captured.len(), 1);
    let (method, path, headers, body) = &captured[0];
    assert_eq!(method, "POST");
    assert_eq!(path, "/v1/subscriptions/sub%2Fa%20%3F%23%25/cancel");
    assert_eq!(headers["x-api-key"], TEST_KEY);
    assert_eq!(headers["content-type"], "application/json");
    assert_eq!(
        serde_json::from_slice::<Value>(body).unwrap(),
        json!({"mode":"immediate"})
    );
    server.abort();
}
#[tokio::test]
async fn cancel_rejects_wrong_identity_and_malformed_subscription() {
    let mut cases = vec![
        subscription("wrong"),
        json!({}),
        subscription("sub_fixture"),
    ];
    cases[2]["status"] = json!("unknown");
    let mut bad_period = subscription("sub_fixture");
    bad_period["current_period_end_date"] = json!("invalid");
    cases.push(bad_period);
    for response in cases {
        let (base, server, requests) = fake_creem::start_cancel(response, 200).await;
        assert_eq!(
            client(&base, TEST_KEY)
                .cancel_subscription_now(&ExternalSubscriptionRef("sub_fixture".into()))
                .await,
            Err(ErrorCode::InvalidInput)
        );
        assert_eq!(requests.lock().unwrap().len(), 1);
        server.abort();
    }
}
#[tokio::test]
async fn cancel_errors_are_classified_without_post_retries() {
    for (status, key, error) in [
        (429, TEST_KEY, ErrorCode::ProviderRateLimited),
        (503, TEST_KEY, ErrorCode::ProviderTransient),
        (400, TEST_KEY, ErrorCode::ProviderPermanent),
        (200, "wrong-fixture-token", ErrorCode::Unauthorized),
    ] {
        let (base, server, requests) =
            fake_creem::start_cancel(subscription("sub_fixture"), status).await;
        assert_eq!(
            client(&base, key)
                .cancel_subscription_now(&ExternalSubscriptionRef("sub_fixture".into()))
                .await,
            Err(error)
        );
        assert_eq!(
            requests.lock().unwrap().len(),
            1,
            "POST must not retry on {status}"
        );
        server.abort();
    }
}
#[tokio::test]
async fn cancel_transport_failure_is_unknown_and_not_retried() {
    // dep: HTTP(loopback) — deliberately close the connection after receiving a POST.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let provider = client(&base, TEST_KEY);
    let call = tokio::spawn(async move {
        provider
            .cancel_subscription_now(&ExternalSubscriptionRef("sub_fixture".into()))
            .await
    });
    let (stream, _) = listener.accept().await.unwrap();
    let mut bytes = [0; 4096];
    stream.readable().await.unwrap();
    assert!(stream.try_read(&mut bytes).unwrap() > 0);
    drop(stream);
    assert_eq!(call.await.unwrap(), Err(ErrorCode::ProviderTransient));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
}
#[tokio::test]
async fn cancel_invalid_reference_never_sends() {
    let (base, server, requests) = fake_creem::start_cancel(subscription("sub_fixture"), 200).await;
    for id in ["", ".", ".."] {
        assert_eq!(
            client(&base, TEST_KEY)
                .cancel_subscription_now(&ExternalSubscriptionRef(id.into()))
                .await,
            Err(ErrorCode::InvalidInput)
        );
    }
    assert!(requests.lock().unwrap().is_empty());
    server.abort();
}
