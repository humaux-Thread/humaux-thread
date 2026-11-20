//! `gateway::tests::route_cache` — G-M03-4 and G-M03-5 through the MCP HTTP guard.
//! Depends-on: crates=[async-trait, axum, humaux-adapters, humaux-application, humaux-domain, humaux-protocol, humaux-testkit, tokio, uuid];
//!   services=[HTTP(gateway)]; env=[]; modules=[adapters::postgres, adapters::tests::support::operation_receipt_fixture, application::api_key, domain::error, domain::ids, gateway::guard, gateway::limiter, gateway::route_cache, humaux-testkit, protocol::edge, protocol::mcp, protocol::mcp_catalog]
//! Called-by: [cargo-test]
//! Invariants: [one real gateway-login pool and isolated fixture tenant per gate; use the transport and guard for every request]
//! Spec: Baseline §73.5.1; §79.2; ADR-0133; G-M03-4; G-M03-5

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use humaux_adapters::postgres::RuntimeDbPool;
use humaux_application::api_key::compute_api_key_hash;
use humaux_domain::{error::ErrorCode, ids::TenantId};
use humaux_gateway::{
    guard::{GatewayGuard, GuardRatePolicies, GuardSettings},
    limiter::RatePolicy,
    route_cache::CredentialRouteCache,
};
use humaux_protocol::{
    edge::TrustedProxyConfig,
    mcp::{
        McpAdapter, McpApplication, McpHttpConfig, McpHttpContext, McpOperation, McpToolArguments,
        ToolName, ToolOutput,
    },
    mcp_catalog::CanonicalCatalog,
};
use humaux_testkit::run_db_fixture;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use uuid::Uuid;

#[allow(dead_code)]
#[path = "../../../crates/adapters/tests/support/operation_receipt_fixture.rs"]
mod operation_receipt_fixture;
use operation_receipt_fixture::{
    Fixture, Handle, SYNTHETIC_CREDENTIAL_PEPPER, SyntheticCredentialScopes,
    SyntheticServiceCredential,
};

const INTERVAL: Duration = Duration::from_secs(60);

// The real protocol path calls the production GatewayGuard, with no business tool fixture needed.
struct ProtocolGate(GatewayGuard);

#[async_trait::async_trait]
impl McpApplication for ProtocolGate {
    async fn check_access(
        &self,
        context: &McpHttpContext,
        operation: McpOperation,
    ) -> Result<(), ErrorCode> {
        self.0.protocol(context, operation).await
    }

    async fn invoke(
        &self,
        _: &McpHttpContext,
        _: ToolName,
        _: McpToolArguments<'_>,
    ) -> Result<ToolOutput, ErrorCode> {
        Err(ErrorCode::Internal)
    }
}

async fn start(
    pool: RuntimeDbPool,
    cache: Arc<CredentialRouteCache>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let rate = || RatePolicy::new(1_000, 1_000).unwrap();
    let guard = GatewayGuard::new(
        pool,
        GuardSettings {
            credential_pepper: SYNTHETIC_CREDENTIAL_PEPPER.to_vec(),
            credential_pepper_previous: None,
            trusted_proxies: TrustedProxyConfig {
                trusted_proxy_cidrs: vec![],
                max_forwarded_hops: 1,
            },
            global_denylist: vec![],
            global_emergency_allowlist: vec![],
            tenant_network: Default::default(),
            rate_max_subjects: [1_000; 5],
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
            replay_ttl: INTERVAL,
        },
    )
    .unwrap()
    .with_credential_route_cache(cache)
    .with_batched_credential_touch(INTERVAL)
    .unwrap();
    let adapter = McpAdapter::new(
        Arc::new(ProtocolGate(guard)),
        CanonicalCatalog::load().unwrap().trusted_catalog().unwrap(),
        McpHttpConfig::new(
            vec!["mcp.test".into()],
            vec!["https://mcp.test".into()],
            4096,
        )
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            adapter
                .router()
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("serve loopback");
    });
    (address, server)
}

fn seed(handle: &mut Handle) -> SyntheticServiceCredential {
    let prefix = format!("route_fixture_{}", Uuid::new_v4().simple());
    let wire = format!("{prefix}.synthetic_fixture_{}", Uuid::new_v4().simple());
    let hash = compute_api_key_hash(SYNTHETIC_CREDENTIAL_PEPPER, &wire);
    handle.seed_synthetic_service_credential(
        SyntheticCredentialScopes::ContextRead,
        &prefix,
        &wire,
        &hash,
    )
}

async fn catalog_request(address: SocketAddr, credential: &SyntheticServiceCredential) -> u16 {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{
        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientInfo":{"name":"route-cache-acceptance","version":"1"},
        "io.modelcontextprotocol/clientCapabilities":{}
    }}}"#;
    let request = format!(
        "POST /mcp HTTP/1.1\r\nHost: mcp.test\r\nOrigin: https://mcp.test\r\nConnection: close\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/list\r\nAuthorization: {}\r\nContent-Length: {}\r\n\r\n{body}",
        credential.bearer,
        body.len()
    );
    // dep: HTTP(gateway) — dial only the fixture's loopback listener
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    std::str::from_utf8(&response)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn g_m03_4_revoke_and_wrong_tenant_candidates_fail_on_http_entry() {
    run_db_fixture::<Fixture, _>("G-M03-4 HTTP revoke and tenant route", |mut fixture| {
        let credential = seed(&mut fixture);
        let cache = Arc::new(CredentialRouteCache::new(
            SYNTHETIC_CREDENTIAL_PEPPER,
            4096,
            INTERVAL,
        ));
        let key = cache.key(credential.bearer.strip_prefix("Bearer ").unwrap());
        let rt = fixture.rt.handle().clone();
        rt.block_on(async {
            let pool = fixture.fresh_runtime().await.unwrap();
            let (address, server) = start(pool, Arc::clone(&cache)).await;
            assert!(cache.lookup(&key).await.is_none());
            assert_eq!(catalog_request(address, &credential).await, 200);
            let mut wrong = cache
                .lookup(&key)
                .await
                .expect("HTTP request populated the hint");
            wrong.tenant_id = TenantId(Uuid::new_v4());
            cache.insert(key, wrong).await;
            assert_eq!(
                catalog_request(address, &credential).await,
                401,
                "foreign candidate must be refused"
            );
            assert!(
                cache.lookup(&key).await.is_none(),
                "foreign candidate must be evicted"
            );
            assert_eq!(
                catalog_request(address, &credential).await,
                200,
                "fresh lookup rebuilds the correct route"
            );
            assert!(
                cache.lookup(&key).await.is_some(),
                "revocation case must begin with a hit"
            );
            tokio::task::block_in_place(|| fixture.revoke_service_credential(&credential));
            assert_eq!(
                catalog_request(address, &credential).await,
                401,
                "the next warm request must check the live row"
            );
            assert!(
                cache.lookup(&key).await.is_none(),
                "revocation must evict the warm route"
            );
            server.abort();
        });
    });
}

#[test]
fn g_m03_5_http_calls_change_the_activity_row_once_per_window() {
    run_db_fixture::<Fixture, _>("G-M03-5 HTTP activity writes", |mut fixture| {
        let credential = seed(&mut fixture);
        let cache = Arc::new(CredentialRouteCache::new(
            SYNTHETIC_CREDENTIAL_PEPPER,
            4096,
            INTERVAL,
        ));
        let rt = fixture.rt.handle().clone();
        rt.block_on(async {
            let pool = fixture.fresh_runtime().await.unwrap();
            let (address, server) = start(pool, cache).await;
            let mut previous =
                tokio::task::block_in_place(|| fixture.credential_activity(&credential));
            assert!(!previous.1);
            let start = Instant::now();
            let mut updates = 0;
            for _ in 0..100 {
                assert_eq!(catalog_request(address, &credential).await, 200);
                let next = tokio::task::block_in_place(|| fixture.credential_activity(&credential));
                updates += usize::from(next.0 != previous.0);
                previous = next;
            }
            assert!(
                start.elapsed() < INTERVAL,
                "100 requests must fit one test window"
            );
            assert!(previous.1, "the gateway must actually stamp the credential");
            assert_eq!(
                updates, 1,
                "count committed updates from row transaction IDs"
            );
            server.abort();
        });
    });
}
