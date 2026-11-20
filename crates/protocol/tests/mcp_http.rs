//! `protocol::tests::mcp_http` — integration test: spins up `protocol::mcp`'s Axum router on a real loopback TCP listener and drives it as an HTTP client, covering dual-output raw arguments, stateless transport, legacy/malformed request rejection, and authorization-error status codes.
//! Depends-on: crates=[async-trait, axum, humaux-domain, serde_json, tokio, uuid]; services=[HTTP(loopback)]; env=[];
//!   modules=[domain::error, protocol::mcp, protocol::mcp_catalog]
//! Called-by: [cargo-test]
//! Invariants: [drives protocol::mcp's router over a real loopback listener: malformed/legacy transport is rejected
//!   before invoke and authorization errors set the HTTP status before dispatch]
//! Spec: none
//!
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use humaux_domain::error::ErrorCode;
use humaux_protocol::mcp::{
    McpAdapter, McpApplication, McpHttpConfig, McpHttpContext, McpOperation, McpResourceRoute,
    McpToolArguments, McpToolSchema, ToolName, ToolOutput, TrustedMcpCatalog,
};
use humaux_protocol::mcp_catalog::CanonicalCatalog;
use serde_json::{Map, Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[derive(Default)]
struct MockApplication {
    /// Refuses only the pre-parse `Preflight` access check.
    denied: Mutex<Option<ErrorCode>>,
    preflight_budget: Option<usize>,
    /// Refuses every later per-operation access check (`authorize`), the second 503 source of `protocol::mcp`.
    operation_denied: Mutex<Option<ErrorCode>>,
    invoke_denied: Mutex<Option<ErrorCode>>,
    scope_catalog: Option<CanonicalCatalog>,
    operations: Mutex<Vec<McpOperation>>,
    invocations: Mutex<Vec<(ToolName, String, String)>>,
    request_ids: Mutex<Vec<uuid::Uuid>>,
    expected_resources: Mutex<Vec<Option<String>>>,
}

#[async_trait]
impl McpApplication for MockApplication {
    async fn check_access(
        &self,
        context: &McpHttpContext,
        operation: McpOperation,
    ) -> Result<(), ErrorCode> {
        let stage = if operation == McpOperation::Preflight {
            &self.denied
        } else {
            &self.operation_denied
        };
        let mut operations = self.operations.lock().expect("operations");
        operations.push(operation);
        if operation == McpOperation::Preflight
            && self
                .preflight_budget
                .is_some_and(|budget| operations.len() > budget)
        {
            return Err(ErrorCode::RateLimited);
        }
        drop(operations);
        self.request_ids
            .lock()
            .expect("request ids")
            .push(context.request_id());
        self.expected_resources
            .lock()
            .expect("expected resources")
            .push(context.expected_resource().map(str::to_owned));
        stage
            .lock()
            .expect("denied")
            .as_ref()
            .copied()
            .map_or(Ok(()), Err)
    }

    async fn invoke(
        &self,
        context: &McpHttpContext,
        tool: ToolName,
        arguments: McpToolArguments<'_>,
    ) -> Result<ToolOutput, ErrorCode> {
        if let Some(code) = *self.invoke_denied.lock().expect("invoke denied") {
            if let Some(catalog) = self
                .scope_catalog
                .as_ref()
                .filter(|_| code == ErrorCode::Forbidden)
            {
                let operation = catalog
                    .validate(tool, &Value::Object(arguments.decoded().clone()))
                    .expect("canonical MCP operation");
                context.mark_insufficient_scope(operation.required_scope());
            }
            return Err(code);
        }
        self.invocations.lock().expect("invocations").push((
            tool,
            arguments.raw_json().unwrap_or("").to_owned(),
            serde_json::to_string(arguments.decoded()).expect("decoded arguments"),
        ));
        Ok(ToolOutput {
            text: "\u{feff}line\r\n".to_owned(),
            structured_content: json!({"kind":"mock","ok":true}),
            is_error: false,
        })
    }
}

fn catalog() -> TrustedMcpCatalog {
    TrustedMcpCatalog::new(catalog_items()).expect("closed trusted catalog")
}

fn catalog_items() -> Vec<McpToolSchema> {
    [
        ToolName::Remember,
        ToolName::Recall,
        ToolName::Memory,
        ToolName::Context,
        ToolName::Continuity,
        ToolName::Artifact,
        ToolName::Code,
        ToolName::Coordinate,
    ]
    .into_iter()
    .map(|name| McpToolSchema {
        name,
        title: Some(name.as_str().to_owned()),
        description: format!("{} tool", name.as_str()),
        input_schema: Map::new(),
        output_schema: Some(Map::new()),
    })
    .collect()
}

#[test]
fn trusted_catalog_rejects_duplicate_schema_names() {
    let mut items = catalog_items();
    items.push(items[0].clone());
    assert_eq!(
        TrustedMcpCatalog::new(items).expect_err("duplicate must not overwrite trusted schema"),
        ErrorCode::InvalidInput
    );
}

async fn start(app: Arc<MockApplication>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    start_router(app, McpAdapter::router).await
}

async fn start_router(
    app: Arc<MockApplication>,
    router: fn(&McpAdapter) -> axum::Router,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    start_with_oauth(app, router, None, false).await
}

async fn start_with_oauth(
    app: Arc<MockApplication>,
    router: fn(&McpAdapter) -> axum::Router,
    issuer: Option<&str>,
    legacy_enabled: bool,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let mut config = McpHttpConfig::new(
        vec!["mcp.test".to_owned()],
        vec!["https://mcp.test".to_owned()],
        64 * 1024,
    )
    .expect("safe config")
    .with_legacy_enabled(legacy_enabled);
    if let Some(issuer) = issuer {
        config = config.with_oauth_issuer(issuer.to_owned());
    }
    let adapter = McpAdapter::new(app, catalog(), config);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let address = listener.local_addr().expect("loopback address");
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            router(&adapter).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("loopback server");
    });
    (address, handle)
}

async fn request(
    address: SocketAddr,
    method: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, String, BTreeMap<String, String>) {
    request_at(address, "/mcp", method, headers, body).await
}

async fn request_at(
    address: SocketAddr,
    path: &str,
    method: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, String, BTreeMap<String, String>) {
    // dep: HTTP(loopback) — connects to the Axum router this test just started on a real TCP listener.
    let mut stream = TcpStream::connect(address).await.expect("connect loopback");
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body.len(),
    );
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("host"))
    {
        request.push_str("Host: mcp.test\r\n");
    }
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("origin"))
    {
        request.push_str("Origin: https://mcp.test\r\n");
    }
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("accept"))
    {
        request.push_str("Accept: application/json, text/event-stream\r\n");
    }
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    let response = String::from_utf8(response).expect("HTTP response UTF-8");
    let (head, body) = response
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("HTTP separator: {response:?}"));
    let mut lines = head.lines();
    let status = lines
        .next()
        .expect("status line")
        .split_whitespace()
        .nth(1)
        .expect("status")
        .parse()
        .expect("numeric status");
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    (status, body.to_owned(), headers)
}

fn modern_headers(method: &str) -> [(&str, &str); 3] {
    [
        ("MCP-Protocol-Version", "2026-07-28"),
        ("Mcp-Method", method),
        ("Authorization", "Bearer accepted"),
    ]
}

fn tool_call_headers() -> [(&'static str, &'static str); 4] {
    [
        ("MCP-Protocol-Version", "2026-07-28"),
        ("Mcp-Method", "tools/call"),
        ("Mcp-Name", "remember"),
        ("Authorization", "Bearer accepted"),
    ]
}

const MODERN_META: &str = r#""_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}"#;

fn modern_params(prefix: &str) -> String {
    if prefix.is_empty() {
        format!("{{{MODERN_META}}}")
    } else {
        format!("{{{prefix},{MODERN_META}}}")
    }
}

#[tokio::test]
async fn native_list_and_call_keep_dual_output_raw_arguments_and_stateless_transport() {
    let app = Arc::new(MockApplication::default());
    let (address, server) = start(app.clone()).await;

    let list = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}}"#,
        modern_params("")
    );
    let (status, body, headers) =
        request(address, "POST", &modern_headers("tools/list"), &list).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(headers.get("mcp-session-id"), None);
    let listed: Value = serde_json::from_str(&body)
        .unwrap_or_else(|error| panic!("list JSON-RPC response {error}: {body:?}"));
    assert_eq!(
        listed["result"]["tools"].as_array().expect("tools").len(),
        8
    );
    assert!(body.contains("\"remember\""));

    let call = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{}}}"#,
        modern_params(r#""name":"remember","arguments":{ "content" : "a\r\n" }"#)
    );
    let (status, body, _) = request(address, "POST", &tool_call_headers(), &call).await;
    assert_eq!(status, 200, "{body}");
    let called: Value = serde_json::from_str(&body).expect("call JSON-RPC response");
    assert_eq!(
        called["result"]["content"][0]["text"], "\u{feff}line\r\n",
        "{body}"
    );
    assert_eq!(called["result"]["structuredContent"]["kind"], "mock");
    let invocations = app.invocations.lock().expect("invocations");
    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0].1, r#"{ "content" : "a\r\n" }"#);
    drop(invocations);
    let request_ids = app.request_ids.lock().expect("request ids");
    let distinct = request_ids
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(distinct.len(), 2, "one server-minted id per HTTP request");
    server.abort();
}

#[tokio::test]
async fn malformed_or_legacy_transport_is_rejected_before_invoke() {
    let app = Arc::new(MockApplication::default());
    let (address, server) = start(app.clone()).await;
    let valid_call = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}}"#,
        modern_params(r#""name":"remember","arguments":{}"#)
    );

    let old_headers = [
        ("MCP-Protocol-Version", "2025-11-25"),
        ("Mcp-Method", "tools/call"),
        ("Authorization", "Bearer accepted"),
    ];
    assert_eq!(
        request(address, "POST", &old_headers, &valid_call).await.0,
        400
    );

    let missing_capability = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"remember","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#;
    assert_eq!(
        request(address, "POST", &tool_call_headers(), missing_capability)
            .await
            .0,
        400
    );
    assert_eq!(
        request(address, "POST", &tool_call_headers(), "{").await.0,
        200,
        "rmcp owns JSON-RPC parse errors; this request must still be preflighted"
    );

    let duplicate_auth = [
        ("MCP-Protocol-Version", "2026-07-28"),
        ("Mcp-Method", "tools/call"),
        ("Authorization", "Bearer first"),
        ("Authorization", "Bearer second"),
    ];
    assert_eq!(
        request(address, "POST", &duplicate_auth, &valid_call)
            .await
            .0,
        400
    );
    let invalid_origin = [
        ("MCP-Protocol-Version", "2026-07-28"),
        ("Mcp-Method", "tools/call"),
        ("Authorization", "Bearer accepted"),
        ("Origin", "https://wrong.test"),
    ];
    assert_eq!(
        request(address, "POST", &invalid_origin, &valid_call)
            .await
            .0,
        403
    );
    assert_eq!(request(address, "GET", &[], "").await.0, 405);
    assert_eq!(request(address, "DELETE", &[], "").await.0, 405);
    assert!(app.invocations.lock().expect("invocations").is_empty());
    assert!(
        app.operations
            .lock()
            .expect("operations")
            .contains(&McpOperation::Preflight),
        "invalid JSON must still reach the one pre-auth IP-rate callback"
    );
    server.abort();
}

#[tokio::test]
async fn authorization_errors_change_the_http_status_before_dispatch() {
    let app = Arc::new(MockApplication::default());
    let (address, server) = start(app.clone()).await;
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}}"#,
        modern_params(r#""name":"remember","arguments":{}"#)
    );
    *app.invoke_denied.lock().expect("invoke denied") = Some(ErrorCode::Unauthorized);
    let (status, _body, _) = request(address, "POST", &tool_call_headers(), &body).await;
    assert_eq!(status, 401);
    assert!(app.invocations.lock().expect("invocations").is_empty());
    *app.invoke_denied.lock().expect("invoke denied") = Some(ErrorCode::Forbidden);
    let (status, _body, _) = request(address, "POST", &tool_call_headers(), &body).await;
    assert_eq!(status, 403);
    server.abort();
}

// The transport Host is deliberately different from the deployment origin.
const DISCOVERY_ISSUER: &str = "https://mcp-edge.example.test:8443";
const DISCOVERY_PRM: &str = "/.well-known/oauth-protected-resource/mcp";
const DISCOVERY_RESOURCE: &str = "https://mcp-edge.example.test:8443/mcp";
const DISCOVERY_CHALLENGE: &str = r#"Bearer resource_metadata="https://mcp-edge.example.test:8443/.well-known/oauth-protected-resource/mcp""#;

#[tokio::test]
async fn discovery_publishes_only_the_native_resource_and_its_exact_metadata() {
    let app = Arc::new(MockApplication::default());
    let (address, server) = start_with_oauth(
        app.clone(),
        McpAdapter::router,
        Some(DISCOVERY_ISSUER),
        false,
    )
    .await;
    for path in [DISCOVERY_PRM, "/.well-known/oauth-protected-resource"] {
        let (status, body, headers) = request_at(address, path, "GET", &[], "").await;
        assert_eq!(status, 200);
        assert_eq!(headers["content-type"], "application/json");
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap(),
            json!({
                "resource": DISCOVERY_RESOURCE,
                "authorization_servers": [DISCOVERY_ISSUER],
                "scopes_supported": ["context:read", "memory:write", "artifact:manage",
                                     "code:manage", "coordination:manage"],
                "bearer_methods_supported": ["header"]
            }),
        );
    }
    for path in [
        "/.well-known/oauth-protected-resource/mcp/legacy",
        "/mcp/legacy",
    ] {
        assert_eq!(request_at(address, path, "GET", &[], "").await.0, 404);
    }
    assert!(app.operations.lock().unwrap().is_empty());
    assert_eq!(
        McpResourceRoute::Legacy.resource(DISCOVERY_ISSUER),
        "https://mcp-edge.example.test:8443/mcp/legacy"
    );
    server.abort();
}

#[tokio::test]
async fn legacy_mount_publishes_its_own_metadata() {
    let app = Arc::new(MockApplication::default());
    let (address, server) = start_with_oauth(
        app.clone(),
        McpAdapter::router,
        Some(DISCOVERY_ISSUER),
        true,
    )
    .await;
    for (path, resource) in [
        (
            "/.well-known/oauth-protected-resource/mcp/legacy",
            "https://mcp-edge.example.test:8443/mcp/legacy",
        ),
        (DISCOVERY_PRM, DISCOVERY_RESOURCE),
        ("/.well-known/oauth-protected-resource", DISCOVERY_RESOURCE),
    ] {
        let (status, body, headers) = request_at(address, path, "GET", &[], "").await;
        assert_eq!(status, 200, "{path}");
        assert_eq!(headers["content-type"], "application/json");
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap(),
            json!({
                "resource": resource,
                "authorization_servers": [DISCOVERY_ISSUER],
                "scopes_supported": ["context:read", "memory:write", "artifact:manage",
                                     "code:manage", "coordination:manage"],
                "bearer_methods_supported": ["header"]
            }),
        );
    }
    assert!(app.operations.lock().unwrap().is_empty());
    server.abort();
}

#[tokio::test]
async fn discovery_challenges_unauthenticated_mcp_with_the_same_resource() {
    let app = Arc::new(MockApplication {
        operation_denied: Mutex::new(Some(ErrorCode::Unauthorized)),
        ..MockApplication::default()
    });
    let (address, server) = start_with_oauth(
        app.clone(),
        McpAdapter::router,
        Some(DISCOVERY_ISSUER),
        false,
    )
    .await;
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{}}}"#,
        modern_params("")
    );
    let headers = modern_headers("server/discover");
    let (status, _, response) = request(address, "POST", &headers[..2], &body).await;
    assert_eq!(status, 401);
    assert_eq!(response["www-authenticate"], DISCOVERY_CHALLENGE);
    let (status, _, response) = request(address, "POST", &headers, &body).await;
    assert_eq!(status, 401);
    assert_eq!(
        response["www-authenticate"],
        format!(r#"{DISCOVERY_CHALLENGE}, error="invalid_token""#)
    );
    assert_eq!(
        app.expected_resources.lock().unwrap().as_slice(),
        vec![Some(DISCOVERY_RESOURCE.to_owned()); 4].as_slice()
    );
    server.abort();
}

#[tokio::test]
async fn discovery_challenges_only_the_403_for_an_exact_catalog_scope() {
    let app = Arc::new(MockApplication {
        invoke_denied: Mutex::new(Some(ErrorCode::Forbidden)),
        operation_denied: Mutex::new(Some(ErrorCode::Forbidden)),
        scope_catalog: Some(CanonicalCatalog::load().expect("canonical MCP catalog")),
        ..MockApplication::default()
    });
    let (address, server) =
        start_with_oauth(app, McpAdapter::router, Some(DISCOVERY_ISSUER), false).await;
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}}"#,
        modern_params(
            r#""name":"remember","arguments":{"operation":"put","source":{"kind":"AgentNote","object_key":"entry"},"content":"test","idempotency_key":"entry"}"#
        )
    );
    let (status, _, response) = request(address, "POST", &tool_call_headers(), &body).await;
    assert_eq!(status, 403);
    assert_eq!(
        response["www-authenticate"],
        format!(r#"{DISCOVERY_CHALLENGE}, error="insufficient_scope", scope="memory:write""#)
    );
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}}"#,
        modern_params("")
    );
    let (status, _, response) =
        request(address, "POST", &modern_headers("tools/list"), &body).await;
    assert_eq!(status, 403);
    assert_eq!(response.get("www-authenticate"), None);
    server.abort();
}

#[tokio::test]
async fn non_capacity_503_has_no_retry_after() {
    let app = Arc::new(MockApplication::default());
    let (address, server) = start(app.clone()).await;
    let call = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}}"#,
        modern_params(r#""name":"remember","arguments":{}"#)
    );
    let list = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}}"#,
        modern_params("")
    );
    for code in [
        ErrorCode::DependencyUnavailable,
        ErrorCode::CannotEstablishCompleteness,
    ] {
        // Both 503 sources of §67.2: the pre-parse preflight and a later per-operation access check.
        for preflight in [true, false] {
            *app.denied.lock().unwrap() = preflight.then_some(code);
            *app.operation_denied.lock().unwrap() = (!preflight).then_some(code);
            let (status, response, headers) = if preflight {
                request(address, "POST", &tool_call_headers(), &call).await
            } else {
                request(address, "POST", &modern_headers("tools/list"), &list).await
            };
            assert_eq!(status, 503, "{code:?} preflight={preflight}: {response}");
            assert_eq!(
                headers.get("retry-after"),
                None,
                "non-capacity {code:?} preflight={preflight}"
            );
        }
    }
    assert_eq!(app.invocations.lock().unwrap().len(), 0);
    server.abort();
}

const LEGACY_PATH: &str = "/mcp/legacy";
const LEGACY_HEADER: (&str, &str) = ("MCP-Protocol-Version", "2025-06-18");

fn qwen_sample() -> Value {
    serde_json::from_str(include_str!("fixtures/qwen_legacy_http.json")).expect("Qwen fixture")
}

async fn start_legacy(app: Arc<MockApplication>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    start_router(app, McpAdapter::legacy_router).await
}

#[tokio::test]
async fn legacy_qwen_initialize_negotiates_one_version() {
    let (address, server) = start_legacy(Arc::new(MockApplication::default())).await;
    let sample = qwen_sample();
    let (status, body, headers) = request_at(
        address,
        LEGACY_PATH,
        "POST",
        &[("Accept", sample["accept"].as_str().unwrap())],
        &sample["initialize"].to_string(),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(headers.get("mcp-session-id"), None);
    assert_eq!(headers["content-type"], "application/json");
    let reply: Value = serde_json::from_str(&body).unwrap();
    let expected = &sample["initialize_response"];
    assert_eq!(reply["id"], expected["id"]);
    assert_eq!(
        reply["result"]["protocolVersion"],
        expected["result"]["protocolVersion"]
    );
    assert_eq!(
        reply["result"]["capabilities"],
        expected["result"]["capabilities"]
    );
    assert_eq!(reply["result"]["serverInfo"]["name"], "humaux-thread");
    server.abort();
}

#[tokio::test]
async fn legacy_qwen_notification_is_empty() {
    let app = Arc::new(MockApplication::default());
    let (address, server) = start_legacy(app.clone()).await;
    let (status, body, headers) = request_at(
        address,
        LEGACY_PATH,
        "POST",
        &[LEGACY_HEADER],
        &qwen_sample()["initialized"].to_string(),
    )
    .await;
    assert_eq!(status, 202);
    assert!(body.is_empty());
    assert_eq!(headers.get("mcp-session-id"), None);
    server.abort();
    assert!(app.invocations.lock().unwrap().is_empty());
}

#[tokio::test]
async fn legacy_qwen_get_probe_is_405() {
    let app = Arc::new(MockApplication::default());
    let (address, server) = start_legacy(app.clone()).await;
    for method in ["GET", "DELETE"] {
        let (status, body, headers) = request_at(
            address,
            LEGACY_PATH,
            method,
            &[LEGACY_HEADER, ("Accept", "text/event-stream")],
            "",
        )
        .await;
        assert_eq!(status, 405);
        assert_eq!(headers["allow"], "POST");
        assert!(body.is_empty());
    }
    assert!(app.operations.lock().unwrap().is_empty());
    server.abort();
}

#[tokio::test]
async fn legacy_mount_replays_qwen_with_native_catalog_and_one_dispatch() {
    let app = Arc::new(MockApplication::default());
    let (address, server) = start_with_oauth(app.clone(), McpAdapter::router, None, true).await;
    let sample = qwen_sample();
    for (key, headers, expected) in [
        ("initialize", &[][..], 200),
        ("initialized", &[LEGACY_HEADER][..], 202),
    ] {
        assert_eq!(
            request_at(
                address,
                LEGACY_PATH,
                "POST",
                headers,
                &sample[key].to_string()
            )
            .await
            .0,
            expected
        );
    }
    assert_eq!(
        request_at(
            address,
            LEGACY_PATH,
            "GET",
            &[LEGACY_HEADER, ("Accept", "text/event-stream")],
            ""
        )
        .await
        .0,
        405
    );
    let (status, legacy_list, headers) = request_at(
        address,
        LEGACY_PATH,
        "POST",
        &[LEGACY_HEADER],
        &sample["list"].to_string(),
    )
    .await;
    assert_eq!(status, 200, "{legacy_list}");
    assert_eq!(headers.get("mcp-session-id"), None);
    let native_list = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}}"#,
        modern_params("")
    );
    let (status, native_list, _) =
        request(address, "POST", &modern_headers("tools/list"), &native_list).await;
    assert_eq!(status, 200, "{native_list}");
    let legacy_list: Value = serde_json::from_str(&legacy_list).unwrap();
    let native_list: Value = serde_json::from_str(&native_list).unwrap();
    assert_eq!(legacy_list["id"], sample["list"]["id"]);
    assert_eq!(
        legacy_list["result"]["tools"],
        native_list["result"]["tools"]
    );
    assert_eq!(legacy_list["result"].as_object().unwrap().len(), 1);

    let call = sample["call"].to_string().replace(
        r#""name":"echo""#,
        r#""name":"recall","arguments":{ "query" : "test" }"#,
    );
    let (status, body, headers) =
        request_at(address, LEGACY_PATH, "POST", &[LEGACY_HEADER], &call).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(headers.get("mcp-session-id"), None);
    let reply: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(reply["id"], sample["call_response"]["id"]);
    assert_eq!(reply["result"]["content"][0]["text"], "\u{feff}line\r\n");
    assert_eq!(
        reply["result"]["structuredContent"],
        json!({"kind":"mock","ok":true})
    );
    assert!(reply["result"].get("resultType").is_none());
    assert_eq!(
        *app.invocations.lock().unwrap(),
        [(
            ToolName::Recall,
            r#"{ "query" : "test" }"#.to_owned(),
            r#"{"query":"test"}"#.to_owned()
        )]
    );
    assert_eq!(
        *app.operations.lock().unwrap(),
        [
            McpOperation::Preflight,
            McpOperation::Initialize,
            McpOperation::Preflight,
            McpOperation::Preflight,
            McpOperation::Catalog,
            McpOperation::Preflight,
            McpOperation::Catalog,
            McpOperation::Preflight
        ]
    );
    server.abort();
}

#[tokio::test]
async fn opposite_protocol_versions_never_dispatch() {
    let app = Arc::new(MockApplication::default());
    let (address, server) = start_legacy(app.clone()).await;
    let (native, native_server) = start(app.clone()).await;
    let sample = qwen_sample();
    assert_eq!(
        request(native, "POST", &[], &sample["initialize"].to_string())
            .await
            .0,
        400
    );
    assert_eq!(
        request(
            native,
            "POST",
            &[LEGACY_HEADER],
            &sample["list"].to_string()
        )
        .await
        .0,
        400
    );
    let modern = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{}}}"#,
        modern_params("")
    );
    let mut modern_init = sample["initialize"].clone();
    modern_init["params"]["protocolVersion"] = json!("2026-07-28");
    let mut invalid_init = sample["initialize"].clone();
    invalid_init["params"]
        .as_object_mut()
        .unwrap()
        .remove("protocolVersion");
    for (headers, body) in [
        (&modern_headers("server/discover")[..], modern.clone()),
        (&[LEGACY_HEADER][..], modern),
        (&[LEGACY_HEADER][..], invalid_init.to_string()),
        (&[][..], modern_init.to_string()),
        (
            &[("MCP-Protocol-Version", "2025-11-25")][..],
            sample["list"].to_string(),
        ),
        (&[][..], sample["list"].to_string()),
        (
            &[LEGACY_HEADER, LEGACY_HEADER][..],
            sample["list"].to_string(),
        ),
        (&[LEGACY_HEADER][..], sample["initialize"].to_string()),
    ] {
        assert_eq!(
            request_at(address, LEGACY_PATH, "POST", headers, &body)
                .await
                .0,
            400,
            "{body}"
        );
    }
    assert_eq!(
        *app.operations.lock().unwrap(),
        [McpOperation::Preflight; 7]
    );
    assert!(app.invocations.lock().unwrap().is_empty());
    server.abort();
    native_server.abort();
}

#[tokio::test]
async fn malformed_posts_consume_preflight_budget_before_decoding() {
    let native_headers = tool_call_headers();
    for (router, path, headers, parse_status) in [
        (
            McpAdapter::router as fn(&McpAdapter) -> axum::Router,
            "/mcp",
            &native_headers[..],
            200,
        ),
        (
            McpAdapter::legacy_router,
            LEGACY_PATH,
            &[LEGACY_HEADER][..],
            400,
        ),
    ] {
        let app = Arc::new(MockApplication {
            preflight_budget: Some(2),
            ..MockApplication::default()
        });
        let (address, server) = start_router(app.clone(), router).await;
        let mut preflight_counts = Vec::new();
        for expected_status in [parse_status, parse_status, 429] {
            let (status, body, _) = request_at(address, path, "POST", headers, "{").await;
            assert_eq!(
                status,
                expected_status,
                "{path}, request {}",
                preflight_counts.len() + 1
            );
            let operations = app.operations.lock().unwrap();
            assert!(operations.iter().all(|op| *op == McpOperation::Preflight));
            preflight_counts.push(operations.len());
            assert!(app.invocations.lock().unwrap().is_empty());
            if status == 429 {
                assert_eq!(body, ErrorCode::RateLimited.as_str());
            }
        }
        assert_eq!(preflight_counts, [1, 2, 3], "{path}");
        server.abort();
    }
}

#[tokio::test]
async fn legacy_rejects_batches_oversize_bodies_and_unknown_methods() {
    let app = Arc::new(MockApplication::default());
    let (address, server) = start_legacy(app.clone()).await;
    let batch = json!([qwen_sample()["call"]]).to_string();
    let oversized = " ".repeat(64 * 1024 + 1);
    for (body, expected) in [(&batch, 400), (&oversized, 413)] {
        let (status, _, _) = request_at(address, LEGACY_PATH, "POST", &[LEGACY_HEADER], body).await;
        assert_eq!(status, expected);
        assert!(app.invocations.lock().unwrap().is_empty());
        assert_eq!(*app.operations.lock().unwrap(), [McpOperation::Preflight]);
    }
    let unknown = r#"{"jsonrpc":"2.0","id":7,"method":"server/discover"}"#;
    let (status, body, _) =
        request_at(address, LEGACY_PATH, "POST", &[LEGACY_HEADER], unknown).await;
    assert_eq!(status, 200);
    let reply: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(reply["id"], 7);
    assert_eq!(reply["error"]["code"], -32601);
    assert!(app.invocations.lock().unwrap().is_empty());
    assert_eq!(
        *app.operations.lock().unwrap(),
        [McpOperation::Preflight; 2]
    );
    server.abort();
}
