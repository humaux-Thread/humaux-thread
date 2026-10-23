//! `gateway::rerank_client` — the gateway's client of the retrieval worker's local rerank RPC (ADR-0084 D-B): the
//!   [`RerankPort`] the recall path calls, its UDS implementation, and the [`RerankLane`] (port plus the deployment
//!   model pin) the runtime carries.
//! Depends-on: crates=[async-trait, humaux-infra-cell, humaux-retrieval, serde, serde_json, uuid]; services=[];
//!   env=[]; modules=[gateway::retrieval_embedding_client, infra-cell::permit, infra-cell::resource, retrieval::rerank]
//! Called-by: [gateway::bootstrap, gateway::recall, tests]
//! Invariants: [the call flows through the one closed IntraCellResource::RETRIEVAL_EMBEDDING_RPC registry/permit and
//!   the same verified UDS dial as the embedding RPC (ADR-0084 U6); every failure of the dial or of the reply is
//!   `RerankAnswer::Failed` with a short class and never carries the query, a document or driver text; a reply is
//!   `Scored` only with outcome `scored`, the request's call id, exactly one finite score per document and a
//!   well-formed model identity]
//! Spec: Baseline §2; §41.4; ADR-0012; ADR-0084 D-B; ADR-0084 D-C; ADR-0084 D-D
//!
//! The wait for the answer is not here: [`crate::recall`] bounds the whole call with the registered
//! `rerank_timeout_ms` (ADR-0084 D-E, U7), so one place owns the timeout whichever port is behind it.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use humaux_infra_cell::{IntraCellResource, IntraCellResourceRegistry, authorize_cell_access};
use humaux_retrieval::rerank::ModelIdentity;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::retrieval_embedding_client::{exchange_on, split_http_response};

/// The worker's rerank wire version (`bins/retrieval-worker/src/rpc.rs`).
const SCHEMA_VERSION: u16 = 1;
/// ADR-0084 D-B: the rerank route on the worker's serve socket.
const RERANK_PATH: &str = "/v1/rerank";

/// One rerank call: the query and the documents to score against it, in-Cell text that is never sealed and never
/// logged.
pub struct RerankCall<'a> {
    /// Names the call in the worker's counts and timings.
    pub call_id: Uuid,
    /// The query exactly as the caller sent it.
    pub query: &'a str,
    /// One document per hydrated, visible Memory (ADR-0084 D-C 3).
    pub documents: &'a [String],
    /// The registered `rerank_max_len`: the token cap of one (query, document) pair.
    pub max_len: u32,
}

/// What a port answered.
#[derive(Debug, Clone, PartialEq)]
pub enum RerankAnswer {
    /// Every document scored: one raw logit per document in request order, and the identity the worker reported.
    Scored {
        /// One raw logit per document.
        scores: Vec<f32>,
        /// The model identity the worker reported.
        model: ModelIdentity,
    },
    /// No usable scores. `class` is a short machine-stable tag for the operator line.
    Failed {
        /// Why: `permit`, `encode`, `transport`, `non_2xx`, `malformed`, `not_scored` or `count_mismatch`.
        class: &'static str,
    },
}

/// The seam the recall path scores through; the production implementation is [`GatewayRerankClient`].
#[async_trait]
pub trait RerankPort: Send + Sync {
    /// Scores every document of `call` against its query, or says why not. All or nothing.
    async fn rerank(&self, call: RerankCall<'_>) -> RerankAnswer;
}

/// The rerank lane of a [`crate::recall::SemanticRecallRuntime`]: the port and the deployment model pin (ADR-0084 D-E)
/// the identity each reply reports is compared with.
#[derive(Clone)]
pub struct RerankLane {
    port: Arc<dyn RerankPort>,
    pin: ModelIdentity,
}

impl RerankLane {
    /// A lane over `port` that accepts only scores of the model `pin` names.
    #[must_use]
    pub fn new(port: Arc<dyn RerankPort>, pin: ModelIdentity) -> Self {
        Self { port, pin }
    }

    /// The port to score through.
    #[must_use]
    pub fn port(&self) -> &dyn RerankPort {
        self.port.as_ref()
    }

    /// The pinned model identity.
    #[must_use]
    pub fn pin(&self) -> &ModelIdentity {
        &self.pin
    }
}

/// `POST /v1/rerank` request body (`deny_unknown_fields` on the worker's side: these are exactly its fields).
#[derive(Serialize)]
struct RerankWireRequest<'a> {
    schema_version: u16,
    call_id: Uuid,
    query: &'a str,
    documents: &'a [String],
    max_len: u32,
}

/// The identity the worker reports on a reply.
#[derive(Deserialize)]
struct WireModel {
    repo: String,
    revision: String,
    recipe: String,
    onnx_sha256: String,
    tokenizer_sha256: String,
}

/// The worker's reply; unknown fields (`schema_version`) are ignored.
#[derive(Deserialize)]
struct RerankWireReply {
    call_id: Uuid,
    outcome: String,
    scores: Option<Vec<f32>>,
    model: Option<WireModel>,
}

/// The UDS client of the worker's rerank RPC. It dials like [`crate::retrieval_embedding_client`] does: the same
/// verified socket, the same permit entry, the same peer-credential gate on the worker's side.
pub struct GatewayRerankClient {
    socket_path: String,
    /// ADR-0066 D-L: the dial refuses any other serving uid.
    expected_server_uid: u32,
    cell_registry: IntraCellResourceRegistry,
    permit_ttl: Duration,
}

impl GatewayRerankClient {
    /// A client of the worker serving `socket_path` as `expected_server_uid`.
    #[must_use]
    pub fn new(
        socket_path: impl Into<String>,
        expected_server_uid: u32,
        cell_registry: IntraCellResourceRegistry,
        permit_ttl: Duration,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            expected_server_uid,
            cell_registry,
            permit_ttl,
        }
    }
}

#[async_trait]
impl RerankPort for GatewayRerankClient {
    async fn rerank(&self, call: RerankCall<'_>) -> RerankAnswer {
        // ADR-0084 U6: rerank is served on the embedding RPC's socket behind the same gate, so it shares that entry.
        let Ok(_permit) = authorize_cell_access(
            &self.cell_registry,
            IntraCellResource::RETRIEVAL_EMBEDDING_RPC,
            self.permit_ttl,
        ) else {
            return failed("permit");
        };
        let Ok(body) = serde_json::to_vec(&RerankWireRequest {
            schema_version: SCHEMA_VERSION,
            call_id: call.call_id,
            query: call.query,
            documents: call.documents,
            max_len: call.max_len,
        }) else {
            return failed("encode");
        };
        match exchange_on(
            &self.socket_path,
            self.expected_server_uid,
            "POST",
            RERANK_PATH,
            &body,
        )
        .await
        {
            Ok(raw) => interpret(&raw, &call),
            Err(_) => failed("transport"),
        }
    }
}

fn failed(class: &'static str) -> RerankAnswer {
    RerankAnswer::Failed { class }
}

/// The answer a raw `HTTP/1.1` reply to `call` stands for. Pure over the bytes, so every refusal is a unit test.
fn interpret(raw: &[u8], call: &RerankCall<'_>) -> RerankAnswer {
    let Ok((status, body)) = split_http_response(raw) else {
        return failed("transport");
    };
    if status != 200 {
        return failed("non_2xx");
    }
    let Ok(reply) = serde_json::from_slice::<RerankWireReply>(body) else {
        return failed("malformed");
    };
    if reply.call_id != call.call_id || reply.outcome != "scored" {
        return failed("not_scored");
    }
    let (Some(scores), Some(model)) = (reply.scores, reply.model) else {
        return failed("malformed");
    };
    if scores.len() != call.documents.len() || scores.iter().any(|score| !score.is_finite()) {
        return failed("count_mismatch");
    }
    let Some(model) = ModelIdentity::new(
        &model.repo,
        &model.revision,
        &model.recipe,
        &model.onnx_sha256,
        &model.tokenizer_sha256,
    ) else {
        return failed("malformed");
    };
    RerankAnswer::Scored { scores, model }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn http(status: u16, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn reply(call_id: Uuid, outcome: &str, scores: &str, model: &str) -> String {
        format!(
            r#"{{"schema_version":1,"call_id":"{call_id}","outcome":"{outcome}","scores":{scores},"model":{model}}}"#
        )
    }

    fn model_json() -> String {
        format!(
            r#"{{"repo":"org/model","revision":"rev","recipe":"recipe","onnx_sha256":"{HASH}","tokenizer_sha256":"{HASH}"}}"#
        )
    }

    /// The reply of a scoring worker is read as `Scored` only when it fits the call: outcome, call id, one finite score
    /// per document and a well-formed identity; every other shape is a `Failed` with its class.
    /// Fault: accept a reply with the wrong score count, or another call's id ⇒ red.
    #[test]
    fn a_reply_is_scored_only_when_it_fits_the_call() {
        let call_id = Uuid::from_u128(7);
        let documents = vec!["a".to_owned(), "b".to_owned()];
        let call = RerankCall {
            call_id,
            query: "q",
            documents: &documents,
            max_len: 256,
        };
        let model = model_json();
        let good = http(200, &reply(call_id, "scored", "[1.5,-0.25]", &model));
        match interpret(&good, &call) {
            RerankAnswer::Scored { scores, model } => {
                assert_eq!(scores, [1.5, -0.25]);
                assert_eq!(
                    model,
                    ModelIdentity::new("org/model", "rev", "recipe", HASH, HASH).expect("valid")
                );
            }
            other => panic!("expected a scored answer, got {other:?}"),
        }
        let failed_with = |raw: Vec<u8>| match interpret(&raw, &call) {
            RerankAnswer::Failed { class } => class,
            RerankAnswer::Scored { .. } => "scored",
        };
        assert_eq!(failed_with(http(500, "{}")), "non_2xx");
        assert_eq!(failed_with(http(200, "not json")), "malformed");
        assert_eq!(failed_with(b"garbage".to_vec()), "transport");
        for outcome in ["disabled", "invalid_request", "failed"] {
            assert_eq!(
                failed_with(http(200, &reply(call_id, outcome, "null", "null"))),
                "not_scored",
                "{outcome}"
            );
        }
        assert_eq!(
            failed_with(http(
                200,
                &reply(Uuid::from_u128(8), "scored", "[1.0,2.0]", &model)
            )),
            "not_scored",
            "another call's reply"
        );
        assert_eq!(
            failed_with(http(200, &reply(call_id, "scored", "[1.0]", &model))),
            "count_mismatch",
            "one score for two documents"
        );
        assert_eq!(
            failed_with(http(200, &reply(call_id, "scored", "[1.0,2.0]", "null"))),
            "malformed",
            "no identity"
        );
        let bad_model = model.replace("org/model", "org model");
        assert_eq!(
            failed_with(http(
                200,
                &reply(call_id, "scored", "[1.0,2.0]", &bad_model)
            )),
            "malformed",
            "an identity that cannot be told apart"
        );
    }
}
