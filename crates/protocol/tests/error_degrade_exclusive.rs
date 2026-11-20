//! G52-4 exercises the production MCP adapter at the HTTP wire boundary.
//! Depends-on: crates=[async-trait, axum, humaux-domain, serde_json, tokio]; services=[HTTP(loopback)]; env=[];
//!   modules=[domain::error, protocol::mcp, protocol::mcp_catalog]
//! Called-by: [cargo-test]
//! Invariants: [terminal wire responses carry no degradation markers]
//! Spec: Baseline §52.4 G52-4

use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use humaux_domain::error::ErrorCode;
use humaux_protocol::{
    mcp::{
        McpAdapter, McpApplication, McpHttpConfig, McpHttpContext, McpOperation, McpToolArguments,
        ToolName, ToolOutput,
    },
    mcp_catalog,
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

struct FixtureApplication;

#[async_trait]
impl McpApplication for FixtureApplication {
    async fn check_access(&self, _: &McpHttpContext, _: McpOperation) -> Result<(), ErrorCode> {
        Ok(())
    }

    async fn invoke(
        &self,
        _: &McpHttpContext,
        _: ToolName,
        arguments: McpToolArguments<'_>,
    ) -> Result<ToolOutput, ErrorCode> {
        match arguments.decoded()["case"].as_str() {
            Some("tool_error") => Err(ErrorCode::ProjectionLag),
            Some("protocol_error") => Err(ErrorCode::InvalidInput),
            Some("degraded") => {
                let structured_content = json!({
                    "items": ["stale-result"],
                    "completeness": {"degradations": ["PROJECTION_LAG"]}
                });
                Ok(ToolOutput {
                    text: structured_content.to_string(),
                    structured_content,
                    is_error: false,
                })
            }
            _ => panic!("unknown G52-4 fixture case"),
        }
    }
}

async fn call(address: SocketAddr, case: &str) -> Value {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "recall",
            "arguments": {"case": case},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientInfo": {"name": "g52-4", "version": "1"},
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }
    })
    .to_string();
    // dep: HTTP(loopback) — the listener is owned by this test.
    let mut stream = TcpStream::connect(address).await.expect("connect loopback");
    let request = format!(
        "POST /mcp HTTP/1.1\r\nHost: mcp.test\r\nOrigin: https://mcp.test\r\n\
         Connection: close\r\nAccept: application/json, text/event-stream\r\n\
         Content-Type: application/json\r\nMCP-Protocol-Version: 2026-07-28\r\n\
         Mcp-Method: tools/call\r\nMcp-Name: recall\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write MCP call");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .expect("read MCP response");
    let (_, wire) = response
        .split_once("\r\n\r\n")
        .expect("HTTP header separator");
    serde_json::from_str(wire).unwrap_or_else(|error| panic!("MCP {case}: {error}: {response}"))
}

#[tokio::test]
async fn wire_error_and_degrade_are_exclusive() {
    let adapter = McpAdapter::new(
        Arc::new(FixtureApplication),
        mcp_catalog::trusted_catalog().expect("trusted catalog"),
        McpHttpConfig::new(
            vec!["mcp.test".into()],
            vec!["https://mcp.test".into()],
            64 * 1024,
        )
        .expect("safe config"),
    );
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let address = listener.local_addr().expect("loopback address");
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            adapter
                .router()
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("loopback server");
    });

    let degraded = call(address, "degraded").await;
    assert!(degraded.get("error").is_none(), "{degraded}");
    assert_ne!(degraded["result"]["isError"], true, "{degraded}");
    assert_eq!(
        degraded["result"]["structuredContent"]["items"],
        json!(["stale-result"])
    );
    assert_eq!(
        degraded["result"]["structuredContent"]["completeness"]["degradations"],
        json!(["PROJECTION_LAG"])
    );

    let terminal = call(address, "tool_error").await;
    assert_eq!(terminal["result"]["isError"], true, "{terminal}");
    assert_eq!(
        terminal["result"]["structuredContent"]["code"],
        "PROJECTION_LAG"
    );

    let protocol_error = call(address, "protocol_error").await;
    assert_eq!(protocol_error["error"]["data"]["code"], "INVALID_INPUT");
    assert!(protocol_error.get("result").is_none(), "{protocol_error}");
    for wire in [terminal, protocol_error] {
        for path in [
            "/degradations",
            "/error/degradations",
            "/error/data/degradations",
            "/result/degradations",
            "/result/structuredContent/degradations",
            "/result/structuredContent/completeness/degradations",
        ] {
            assert!(
                wire.pointer(path)
                    .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty)),
                "G52-4: terminal response carries degradations at {path}: {wire}"
            );
        }
    }
    server.abort();
}
