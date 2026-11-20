//! `protocol::mcp_legacy` — Stateless legacy Streamable HTTP codec.
//! Depends-on: crates=[axum, rmcp, serde_json]; services=[]; env=[]; modules=[protocol::mcp]
//! Called-by: [protocol::mcp]
//! Invariants: [2025-06-18 is the sole negotiated revision; one POST yields at most one tool dispatch]
//! Spec: Baseline §33.6; ADR-0136

use axum::{
    Extension,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use rmcp::model::{
    ClientJsonRpcMessage, ClientRequest, ErrorData, GetMeta, Implementation, InitializeResult,
    ProtocolVersion, ServerCapabilities, ServerJsonRpcMessage, ServerResult,
};

use crate::mcp::{HandlerState, McpHttpContext, McpOperation, McpRequestState};

const LEGACY_PROTOCOL: ProtocolVersion = ProtocolVersion::V_2025_06_18;

pub(crate) fn decode(headers: &HeaderMap, body: &[u8]) -> Result<ClientJsonRpcMessage, StatusCode> {
    if !headers.get(header::CONTENT_TYPE).is_some_and(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
        })
    }) {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let version = headers
        .get("mcp-protocol-version")
        .map(|value| value.to_str())
        .transpose()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let message: ClientJsonRpcMessage =
        serde_json::from_slice(body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if let ClientJsonRpcMessage::Request(request) = &message {
        if request.request.method() == "initialize" {
            let ClientRequest::InitializeRequest(init) = &request.request else {
                return Err(StatusCode::BAD_REQUEST);
            };
            let proposed = &init.params.protocol_version;
            return if ProtocolVersion::KNOWN_VERSIONS.contains(proposed)
                && proposed.has_initialize()
                && version.is_none_or(|value| value == proposed.as_str())
                && request
                    .request
                    .get_meta()
                    .protocol_version()
                    .is_none_or(|value| &value == proposed)
            {
                Ok(message)
            } else {
                Err(StatusCode::BAD_REQUEST)
            };
        }
        if request
            .request
            .get_meta()
            .protocol_version()
            .is_some_and(|value| value != LEGACY_PROTOCOL)
        {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    if version != Some(LEGACY_PROTOCOL.as_str())
        || !matches!(
            message,
            ClientJsonRpcMessage::Request(_) | ClientJsonRpcMessage::Notification(_)
        )
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(message)
}

pub(crate) async fn dispatch(
    State(handler): State<HandlerState>,
    Extension(message): Extension<ClientJsonRpcMessage>,
    Extension(state): Extension<McpRequestState>,
    Extension(context): Extension<McpHttpContext>,
) -> Response {
    let ClientJsonRpcMessage::Request(message) = message else {
        return StatusCode::ACCEPTED.into_response();
    };
    let result = match message.request {
        ClientRequest::InitializeRequest(_) => handler
            .check(&context, &state, McpOperation::Initialize)
            .await
            .map(|()| {
                ServerResult::InitializeResult(
                    InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
                        .with_protocol_version(LEGACY_PROTOCOL)
                        .with_server_info(Implementation::new(
                            "humaux-thread",
                            env!("CARGO_PKG_VERSION"),
                        )),
                )
            }),
        ClientRequest::PingRequest(_) => handler
            .check(&context, &state, McpOperation::Ping)
            .await
            .map(|()| ServerResult::empty(())),
        ClientRequest::ListToolsRequest(_) => handler
            .check(&context, &state, McpOperation::Catalog)
            .await
            .map(|()| ServerResult::ListToolsResult(handler.list())),
        ClientRequest::CallToolRequest(call) => handler
            .call(call.params, &context, &state)
            .await
            .map(ServerResult::CallToolResult),
        request => Err(ErrorData::new(
            rmcp::model::ErrorCode::METHOD_NOT_FOUND,
            format!("Method not found: {}", request.method()),
            None,
        )),
    };
    let response = match result {
        Ok(mut result) => {
            result.strip_result_type_for_legacy_peer();
            ServerJsonRpcMessage::response(result, message.id)
        }
        Err(error) => ServerJsonRpcMessage::error(error, Some(message.id)),
    };
    match serde_json::to_vec(&response) {
        Ok(body) => ([(header::CONTENT_TYPE, "application/json")], body).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
