//! `consolidation-worker::inference_client` — §11.8 `UdsInferenceClient` — `humaux-consolidation-worker`'s
//!   [`PrivateReasoningPort`] implementation: registers a call row on [`ConsolidationDbPool`]
//!   (`role_consolidation_worker`), then RPCs `humaux-private-worker` over the ADR-0012 Unix domain socket.
//! Depends-on: crates=[async-trait, hex, humaux-adapters, humaux-application, humaux-domain, humaux-infra-cell, serde, serde_json, sha2, tokio, uuid];
//!   services=[UDS(private-worker)]; env=[]; modules=[adapters::postgres, adapters::private_inference_rpc,
//!   application::consolidate, domain::error, infra-cell::uds]
//! Called-by: [consolidation-worker::main, tests]
//! Invariants: [one fresh UDS connection per call to the private worker's inference socket; a dial/IO/parse failure
//!   is TRANSPORT/INVALID_RESPONSE mapped to PrivateReasoningError, never a local fallback inference]
//! Spec: none
//!
//! Mirrors
//! `bins/gateway/src/retrieval_embedding_client.rs::GatewayRetrievalEmbeddingClient` verbatim
//! in transport shape (§决定1: hand-rolled HTTP/1.1 framing over a fresh UDS connection per
//! call, no generic RPC framework) — see that module's doc for the full reasoning this one
//! does not repeat.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use humaux_adapters::postgres::ConsolidationDbPool;
use humaux_adapters::private_inference_rpc::{ConsolidationRegistrations, RegisterCall};
use humaux_application::consolidate::{
    PrivateReasoningError, PrivateReasoningPort, PrivateReasoningResult, ProviderTraceRef,
    SealedPrivateReasoningRequest,
};
use humaux_domain::error::ErrorCode;
use humaux_infra_cell::uds::{UdsError, connect_verified};

const SCHEMA_VERSION: u16 = 1;
/// Same cap `retrieval_embedding_client`'s `MAX_RESPONSE_BYTES` documents: private-worker's
/// `Json` response body is always a fully materialized `Content-Length` body of modest size
/// (hex-encoded rollup content plus a few identifiers) — anything past this is a misbehaving
/// peer or a protocol bug, never a legitimate reply.
const MAX_RESPONSE_BYTES: usize = 8 << 20;

#[derive(Debug, Serialize)]
struct PrivateInferenceRpcRequest {
    schema_version: u16,
    call_id: Uuid,
    tenant_hint: Uuid,
}

#[derive(Debug, Deserialize)]
struct PrivateInferenceRpcEnvelope {
    #[allow(dead_code)]
    schema_version: u16,
    call_id: Uuid,
    outcome: String,
    output_bytes_hex: Option<String>,
    output_sha256_hex: Option<String>,
    provider_trace: Option<String>,
    model_call_id: Option<Uuid>,
    failure_message: Option<String>,
}

pub struct UdsInferenceClient<'a> {
    pool: &'a ConsolidationDbPool,
    socket_path: String,
    /// ADR-0066 D-L: `HUMAUX_CONSOLIDATION_WORKER_RPC_SERVER_UID` — the dial refuses any other serving uid.
    expected_server_uid: u32,
    tenant_id: Uuid,
    call_ttl: Duration,
    dial_timeout: Duration,
    /// ADR-0015: bound at construction (`run_once_bound`'s `bind_port` runs after
    /// `create_run`) and registered next to the sealed identifiers so the private worker can
    /// locate this run's inputs — the sealed request itself (§11.8) carries no run id.
    consolidation_run_id: Uuid,
}

impl<'a> UdsInferenceClient<'a> {
    /// `expected_server_uid` is the private worker's uid (ADR-0066 D-L); every dial verifies it first.
    pub fn new(
        pool: &'a ConsolidationDbPool,
        socket_path: impl Into<String>,
        expected_server_uid: u32,
        tenant_id: Uuid,
        call_ttl: Duration,
        dial_timeout: Duration,
        consolidation_run_id: Uuid,
    ) -> Self {
        Self {
            pool,
            socket_path: socket_path.into(),
            expected_server_uid,
            tenant_id,
            call_ttl,
            dial_timeout,
            consolidation_run_id,
        }
    }

    async fn dial(
        &self,
        wire: &PrivateInferenceRpcRequest,
    ) -> Result<PrivateInferenceRpcEnvelope, String> {
        tokio::time::timeout(self.dial_timeout, self.dial_inner(wire))
            .await
            .unwrap_or_else(|_| Err("TRANSPORT_TIMEOUT".to_owned()))
    }

    async fn dial_inner(
        &self,
        wire: &PrivateInferenceRpcRequest,
    ) -> Result<PrivateInferenceRpcEnvelope, String> {
        let body = serde_json::to_vec(wire).map_err(|_| "INVALID_RESPONSE".to_owned())?;
        parse_http_response(&post_infer(&self.socket_path, self.expected_server_uid, &body).await?)
    }
}

/// One `POST /internal/v1/private/infer` over a fresh verified connection; returns the raw response capped at
/// [`MAX_RESPONSE_BYTES`]. Nothing is written before the serving uid is the expected one (ADR-0066 D-L); a wrong
/// uid is a TRANSPORT failure naming `inference rpc peer uid`.
async fn post_infer(
    socket_path: &str,
    expected_server_uid: u32,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    // dep: UDS(private-worker) — dials the private worker's inference RPC socket (ADR-0012)
    let mut stream = connect_verified(socket_path, expected_server_uid)
        .await
        .map_err(|e| match e {
            UdsError::PeerUid { got, expected } => {
                format!("TRANSPORT: inference rpc peer uid {got}, expected {expected}")
            }
            _ => "TRANSPORT".to_owned(),
        })?;
    let head = format!(
        "POST /internal/v1/private/infer HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .await
        .map_err(|_| "TRANSPORT".to_owned())?;
    stream
        .write_all(body)
        .await
        .map_err(|_| "TRANSPORT".to_owned())?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|_| "TRANSPORT".to_owned())?;
        if n == 0 {
            break;
        }
        if raw.len() + n > MAX_RESPONSE_BYTES {
            return Err("TRANSPORT_OVERSIZED_RESPONSE".to_owned());
        }
        raw.extend_from_slice(&chunk[..n]);
    }
    Ok(raw)
}

fn parse_http_response(raw: &[u8]) -> Result<PrivateInferenceRpcEnvelope, String> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "TRANSPORT".to_owned())?;
    let head = std::str::from_utf8(&raw[..header_end]).map_err(|_| "TRANSPORT".to_owned())?;
    let status_line = head.lines().next().ok_or_else(|| "TRANSPORT".to_owned())?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| "TRANSPORT".to_owned())?;
    if status != 200 {
        return Err(format!("TRANSPORT_HTTP_{status}"));
    }
    let body = &raw[header_end + 4..];
    serde_json::from_slice(body).map_err(|_| "INVALID_RESPONSE".to_owned())
}

fn rpc_failure(reason: &str) -> PrivateReasoningError {
    let code = match reason {
        "INVALID_RESPONSE" | "RESPONSE_DIGEST_MISMATCH" => ErrorCode::ProviderPermanent,
        reason if reason.starts_with("TRANSPORT") => ErrorCode::ProviderTransient,
        _ => ErrorCode::ALL
            .into_iter()
            .find(|code| code.as_str() == reason)
            .unwrap_or(ErrorCode::Internal),
    };
    PrivateReasoningError::classified(code.as_str())
}

#[async_trait::async_trait]
impl PrivateReasoningPort for UdsInferenceClient<'_> {
    async fn infer(
        &self,
        req: SealedPrivateReasoningRequest,
    ) -> Result<PrivateReasoningResult, PrivateReasoningError> {
        let call_id = Uuid::now_v7();
        let purpose = humaux_adapters::private_inference_rpc::purpose_db_str(req.purpose);
        ConsolidationRegistrations::new(self.pool)
            .register(&RegisterCall {
                call_id,
                tenant_id: self.tenant_id,
                reasoning_domain_id: req.reasoning_domain_id.0,
                binding_id: req.binding_id.0,
                binding_version: req.binding_version.0,
                purpose,
                input_manifest_hash: req.input_manifest_hash.0,
                consolidation_run_id: Some(self.consolidation_run_id),
                ttl: self.call_ttl,
            })
            .await
            .map_err(|_| {
                PrivateReasoningError::classified(ErrorCode::DependencyUnavailable.as_str())
            })?;

        let wire = PrivateInferenceRpcRequest {
            schema_version: SCHEMA_VERSION,
            call_id,
            tenant_hint: self.tenant_id,
        };
        let envelope = match self.dial(&wire).await {
            Ok(envelope) if envelope.call_id == call_id => envelope,
            Ok(_) => {
                return Err(rpc_failure("INVALID_RESPONSE"));
            }
            Err(reason) => return Err(rpc_failure(&reason)),
        };
        if envelope.outcome != "COMPLETED" {
            return Err(rpc_failure(
                envelope.failure_message.as_deref().unwrap_or("UNKNOWN"),
            ));
        }
        let (Some(output_hex), Some(sha_hex), Some(trace), Some(model_call_id)) = (
            envelope.output_bytes_hex,
            envelope.output_sha256_hex,
            envelope.provider_trace,
            envelope.model_call_id,
        ) else {
            return Err(rpc_failure("INVALID_RESPONSE"));
        };
        let output_bytes = hex::decode(&output_hex).map_err(|_| rpc_failure("INVALID_RESPONSE"))?;
        let sha_bytes = hex::decode(&sha_hex).map_err(|_| rpc_failure("INVALID_RESPONSE"))?;
        let output_sha256: [u8; 32] = sha_bytes
            .try_into()
            .map_err(|_| rpc_failure("INVALID_RESPONSE"))?;
        // §11.8: proves the wire body's `output_bytes` is the actual referent of
        // `output_sha256`, not a mismatched pair a compromised/buggy peer sent — the same
        // integrity discipline `retrieval_embedding_rpc`'s `query_sha256` check applies at the
        // registration boundary, applied here at the response boundary instead.
        let computed: [u8; 32] = Sha256::digest(&output_bytes).into();
        if computed != output_sha256 {
            return Err(rpc_failure("RESPONSE_DIGEST_MISMATCH"));
        }
        Ok(PrivateReasoningResult {
            output_bytes,
            output_sha256: humaux_application::consolidate::ContentSha256(output_sha256),
            provider_trace: ProviderTraceRef(trace),
            model_call_id,
            binding_id: req.binding_id,
            binding_version: req.binding_version,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::post_infer;
    use humaux_infra_cell::uds::{bind_guarded, own_uid};
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    /// ADR-0066 D-L: a socket served by any uid but the registered private-worker uid is refused before a byte is
    /// written. Fault: dial without the peer-uid check ⇒ the request is written ⇒ red.
    #[tokio::test]
    async fn wrong_server_uid_is_refused() {
        // Short `/tmp` path: a macOS temp dir plus a name overflows `sockaddr_un`.
        let dir = std::path::PathBuf::from(format!("/tmp/hq-cwpeer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).expect("create the socket dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let path = dir.join("i.sock");
        let listener = bind_guarded(&path).expect("bind the stand-in private worker socket");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept the dial");
            let mut buf = [0u8; 64];
            match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                Ok(Ok(n)) => n,
                _ => usize::MAX,
            }
        });
        let wrong = own_uid().expect("own uid").wrapping_add(1);
        let dial = tokio::time::timeout(
            Duration::from_secs(5),
            post_infer(path.to_str().expect("utf-8 path"), wrong, b"{}"),
        )
        .await;
        let written = server.await.expect("the stand-in worker task");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            written, 0,
            "the consolidation worker wrote to an unverified peer"
        );
        let err = dial
            .expect("the dial returned")
            .expect_err("a wrong server uid must fail");
        assert!(
            err.starts_with("TRANSPORT") && err.contains("inference rpc peer uid"),
            "{err}"
        );
    }
}
