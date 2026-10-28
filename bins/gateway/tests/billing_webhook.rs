//! `gateway::tests::billing_webhook` — G-M04-10 route half, real HTTP and the runtime inbox grant.
//! Depends-on: crates=[axum, humaux-adapters, humaux-domain, humaux-protocol, humaux-testkit, postgres,
//!   serde_json, sha2, tokio, uuid]; services=[HTTP(loopback), PostgreSQL(any) w=[control.billing_inbox],
//!   PostgreSQL(role_gateway)]; env=[CI, HUMAUX_TEST_PG_DSN]; modules=[adapters::postgres, domain::billing,
//!   gateway::admission, gateway::billing_webhook, gateway::guard, gateway::limiter, humaux-testkit, protocol::edge]
//! Called-by: [cargo-test]
//! Invariants: [unique fixture payloads are cleaned; missing CI input fails; exact row counts include changed keys]
//! Spec: §71.3; §79.2; M04 D7; G-M04-10

use humaux_adapters::postgres::RuntimeDbPool;
use humaux_domain::billing::BillingProviderId;
use humaux_gateway::{
    admission::{Admission, AdmissionSettings},
    billing_webhook::{self, BillingWebhookConfig},
    guard::{GatewayGuard, GuardRatePolicies, GuardSettings},
    limiter::RatePolicy,
};
use humaux_protocol::edge::TrustedProxyConfig;
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use uuid::Uuid;

fn providers() -> HashMap<String, BillingWebhookConfig> {
    HashMap::from([(
        "creem".into(),
        BillingWebhookConfig {
            provider: BillingProviderId::Creem,
            signature_header: "creem-signature".into(),
            secret: b"Jefe".to_vec(),
            event_id_pointer: "/id".into(),
            event_type_pointer: "/eventType".into(),
            body_max_bytes: 1024,
        },
    )])
}
fn settings() -> GuardSettings {
    let rate = || RatePolicy::new(10_000, 10_000).expect("positive");
    GuardSettings {
        credential_pepper: vec![9; 32],
        credential_pepper_previous: None,
        trusted_proxies: TrustedProxyConfig {
            trusted_proxy_cidrs: vec![],
            max_forwarded_hops: 1,
        },
        global_denylist: vec![],
        global_emergency_allowlist: vec![],
        tenant_network: BTreeMap::new(),
        rate_max_subjects: [50_000; 5],
        rates: GuardRatePolicies {
            preauth_ip: rate(),
            credential: rate(),
            user: rate(),
            tenant: rate(),
            operation: rate(),
            lock_timeout: Duration::from_secs(2),
            preauth_ipv6_prefix_bits: 64,
        },
        reservation_ttl: Duration::from_secs(30),
        handler_timeout: Duration::from_secs(5),
        finalize_timeout: Duration::from_secs(2),
        replay_ttl: Duration::from_secs(60),
    }
}
struct Handle {
    rt: tokio::runtime::Runtime,
    admin: Client,
    address: SocketAddr,
    empty: SocketAddr,
    admission: Arc<Admission>,
    id: String,
}
impl Drop for Handle {
    fn drop(&mut self) {
        self.admin
            .execute(
                "DELETE FROM control.billing_inbox WHERE payload->>'id'=$1",
                &[&self.id],
            )
            .expect("cleanup");
    }
}
struct Fixture;
impl DbIntegrationFixture for Fixture {
    type Handle = Handle;
    fn isolate() -> Result<Handle, DbFixtureSkipReason> {
        let dsn = match std::env::var("HUMAUX_TEST_PG_DSN") {
            Ok(dsn) => dsn,
            Err(_) => {
                assert!(
                    std::env::var_os("CI").is_none(),
                    "CI missing HUMAUX_TEST_PG_DSN"
                );
                return Err(DbFixtureSkipReason::NoDatabaseUrl);
            }
        };
        // dep: PostgreSQL(any) — fixture inspection and cleanup only (§79.2).
        let admin = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        let sep = if dsn.contains('?') { '&' } else { '?' };
        // dep: PostgreSQL(role_gateway) — exercises the 0288 INSERT-only grant.
        let pool = rt
            .block_on(RuntimeDbPool::connect(&format!(
                "{dsn}{sep}options=-c%20role%3Drole_gateway"
            )))
            .expect("runtime pool");
        let guard = Arc::new(GatewayGuard::new(pool, settings()).expect("guard"));
        let admission = Arc::new(Admission::new(AdmissionSettings {
            concurrency: 1,
            queue_depth: 0,
            max_wait: Duration::from_millis(50),
            per_key_limit: 1,
            body_read_timeout: Duration::from_secs(2),
            max_request_body_bytes: 2048,
        }));
        let composed = |providers| {
            billing_webhook::compose(
                axum::Router::new(),
                axum::Router::new(),
                Arc::clone(&admission),
                Arc::clone(&guard),
                Some(providers),
            )
        };
        let address = rt.block_on(serve(composed(providers())));
        let empty = rt.block_on(serve(composed(HashMap::new())));
        Ok(Handle {
            rt,
            admin,
            address,
            empty,
            admission,
            id: Uuid::now_v7().to_string(),
        })
    }
}
async fn serve(router: axum::Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("serve");
    });
    address
}
// §71.3: independent HMAC oracle for the fixture's short key (RFC 2104, SHA-256 block = 64 bytes).
fn signature(body: &str) -> String {
    let mut key = [0; 64];
    key[..4].copy_from_slice(b"Jefe");
    let inner = Sha256::new()
        .chain_update(key.map(|b| b ^ 0x36))
        .chain_update(body)
        .finalize();
    let digest = Sha256::new()
        .chain_update(key.map(|b| b ^ 0x5c))
        .chain_update(inner)
        .finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
async fn http(address: SocketAddr, provider: &str, body: &str, headers: &str) -> u16 {
    // dep: HTTP(loopback) — production router and shared pre-auth gate, without an MCP credential.
    let mut stream = TcpStream::connect(address).await.expect("connect");
    let raw = format!(
        "POST /v1/billing/webhooks/{provider} HTTP/1.1\r\nHost: webhook.example.test\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len()
    );
    stream.write_all(raw.as_bytes()).await.expect("write");
    let mut reply = String::new();
    stream.read_to_string(&mut reply).await.expect("read");
    reply
        .split_whitespace()
        .nth(1)
        .expect("status")
        .parse()
        .expect("status code")
}
fn rows(h: &mut Handle) -> Vec<Value> {
    h.admin
        .query(
            "SELECT payload FROM control.billing_inbox WHERE payload->>'id'=$1",
            &[&h.id],
        )
        .expect("inspect inbox")
        .into_iter()
        .map(|r| r.get(0))
        .collect()
}
fn body(h: &Handle) -> String {
    json!({"id":h.id,"eventType":"paid"}).to_string()
}
#[test]
fn g_m04_10_valid_and_replay() {
    run_db_fixture::<Fixture, _>("G-M04-10 valid/replay", |mut h| {
        let body = body(&h);
        let header = format!("creem-signature: {}\r\n", signature(&body));
        assert_eq!(h.rt.block_on(http(h.address, "creem", &body, &header)), 200);
        assert_eq!(
            rows(&mut h),
            vec![serde_json::from_str::<Value>(&body).unwrap()]
        );
        assert_eq!(h.rt.block_on(http(h.address, "creem", &body, &header)), 200);
        assert_eq!(rows(&mut h).len(), 1, "replay rows == 1");
    });
}
#[test]
fn g_m04_10_tampered_and_refusals() {
    run_db_fixture::<Fixture, _>("G-M04-10 tampered/refusals", |mut h| {
        let body = body(&h);
        let header = format!("creem-signature: {}\r\n", signature(&body));
        let tampered = body.replace("paid", "fail");
        let status = h.rt.block_on(http(h.address, "creem", &tampered, &header));
        assert_eq!(
            (status, rows(&mut h).len()),
            (401, 0),
            "tampered status and rows"
        );
        for headers in [
            String::new(),
            header.repeat(2),
            "creem-signature: zz\r\n".into(),
        ] {
            let status = h.rt.block_on(http(h.address, "creem", &body, &headers));
            assert_eq!((status, rows(&mut h).len()), (401, 0));
        }
        for (address, provider, payload, headers, expected) in [
            (h.address, "unknown", body.clone(), header.clone(), 404),
            (h.empty, "creem", body.clone(), header.clone(), 404),
            (h.address, "creem", "x".repeat(1025), header.clone(), 413),
            (
                h.address,
                "creem",
                "not json".into(),
                format!("creem-signature: {}\r\n", signature("not json")),
                400,
            ),
        ] {
            assert_eq!(
                h.rt.block_on(http(address, provider, &payload, &headers)),
                expected
            );
            assert_eq!(rows(&mut h).len(), 0);
        }
    });
}

#[test]
fn webhook_composition_keeps_admission() {
    run_db_fixture::<Fixture, _>("M04-P2-438 admission", |mut h| {
        let payload = body(&h);
        let headers = format!("creem-signature: {}\r\n", signature(&payload));
        let ticket =
            h.rt.block_on(h.admission.enter(0))
                .expect("occupy admission");
        let status = h.rt.block_on(http(h.address, "creem", &payload, &headers));
        assert_eq!(
            (status, rows(&mut h).len()),
            (503, 0),
            "webhook must enter admission"
        );
        drop(ticket);
        assert_eq!(
            h.rt.block_on(http(h.address, "creem", &payload, &headers)),
            200
        );
        assert_eq!(
            rows(&mut h),
            vec![serde_json::from_str::<Value>(&payload).unwrap()]
        );
    });
}

#[test]
fn webhook_unstorable_signed_payload_is_bad_request() {
    run_db_fixture::<Fixture, _>("M04-P2-438 jsonb", |mut h| {
        for extra in [json!({"nested": ["\0"]}), json!({"bad\0key": "ok"})] {
            let mut payload = json!({"id":h.id, "eventType":"paid"});
            payload["extra"] = extra;
            let payload = payload.to_string();
            let headers = format!("creem-signature: {}\r\n", signature(&payload));
            let status = h.rt.block_on(http(h.address, "creem", &payload, &headers));
            assert_eq!(
                (status, rows(&mut h).len()),
                (400, 0),
                "unstorable signed payload"
            );
        }
        let payload =
            json!({"id":h.id, "eventType":"paid", "extra": [null, true, 1, "\\u0000"]}).to_string();
        let headers = format!("creem-signature: {}\r\n", signature(&payload));
        assert_eq!(
            h.rt.block_on(http(h.address, "creem", &payload, &headers)),
            200
        );
        assert_eq!(
            rows(&mut h),
            vec![serde_json::from_str::<Value>(&payload).unwrap()]
        );
    });
}
