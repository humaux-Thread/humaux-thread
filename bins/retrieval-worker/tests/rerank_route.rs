//! `retrieval-worker::tests::rerank_route` — ADR-0084 D-B: the wire contract of `POST /v1/rerank` on a worker whose
//!   rerank lane is off, served by the real `rpc::rerank_router` on a loopback port: the `disabled` outcome, every
//!   bound answering `invalid_request`, an unknown field refused, and no request text ever echoed.
//! Depends-on: crates=[axum, serde_json, tokio]; services=[HTTP(loopback)]; env=[]; modules=[retrieval-worker::rerank,
//!   retrieval-worker::rpc]
//! Called-by: [cargo-test]
//! Invariants: [the server binds 127.0.0.1 on a port the OS picked and lives as long as the test process; no model,
//!   database or artifact is touched, so the test runs in every lane]
//! Spec: Baseline §79.2; ADR-0084 D-B
//!
//! The peer-credential layer is not under test here: it is `router_with_rerank`'s one outer layer, the same one the
//! embedding route sits behind (`rpc_readyz` covers its 403).

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};

use humaux_retrieval_worker::rerank::RerankLane;
use humaux_retrieval_worker::rpc::{RERANK_ROUTE, rerank_router};
use serde_json::{Value, json};

/// Serves the rerank route (lane off) on a free loopback port and returns the address.
fn serve() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    listener
        .set_nonblocking(true)
        .expect("non-blocking listener");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
            axum::serve(listener, rerank_router::<()>(RerankLane::disabled()))
                .await
                .expect("serve");
        });
    });
    addr
}

/// POSTs `body` to the rerank route and returns the status code and the response body.
fn post(addr: SocketAddr, body: &Value) -> (u16, String) {
    let payload = body.to_string();
    // dep: HTTP(loopback) — the rerank route served by this test on 127.0.0.1
    let mut stream = TcpStream::connect(addr).expect("connect");
    write!(
        stream,
        "POST {RERANK_ROUTE} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    )
    .expect("send");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    let status = response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status line");
    let body = response
        .split_once("\r\n\r\n")
        .map_or(String::new(), |(_, body)| body.to_owned());
    (status, body)
}

fn request(documents: &[&str], max_len: u64) -> Value {
    json!({
        "schema_version": 1,
        "call_id": "00000000-0000-7000-8000-000000000001",
        "query": "needle-query-text",
        "documents": documents,
        "max_len": max_len,
    })
}

/// ADR-0084 D-B: a well-formed request to a worker with the lane off answers `disabled` with the call id, no
/// `scores` and no `model`, and the reply never contains the query or a document.
#[test]
fn a_disabled_lane_answers_disabled_without_scores_or_model() {
    let addr = serve();
    let (status, body) = post(addr, &request(&["needle-document-text"], 256));
    assert_eq!(status, 200, "{body}");
    let reply: Value = serde_json::from_str(&body).expect("json reply");
    assert_eq!(reply["outcome"], "disabled", "{body}");
    assert_eq!(reply["schema_version"], 1, "{body}");
    assert_eq!(reply["call_id"], "00000000-0000-7000-8000-000000000001");
    assert!(
        reply.get("scores").is_none() && reply.get("model").is_none(),
        "{body}"
    );
    assert!(
        !body.contains("needle"),
        "the reply echoed request text: {body}"
    );
}

/// ADR-0084 D-B: every bound of the request is `invalid_request` (not a transport error): the schema version, 0 and
/// more than `RETRIEVAL_CANDIDATE_CAP` documents, and `max_len` under the special-token floor or over 512; the edges
/// themselves are accepted. Fault: drop one bound from `rerank_reply` => its row is red.
#[test]
fn every_bound_of_the_request_is_invalid_request() {
    let addr = serve();
    let outcome = |body: &Value| -> String {
        let (status, text) = post(addr, body);
        assert_eq!(status, 200, "{text}");
        serde_json::from_str::<Value>(&text).expect("json reply")["outcome"]
            .as_str()
            .expect("outcome")
            .to_owned()
    };
    let docs = |n: usize| vec!["d"; n];
    let mut wrong_schema = request(&["d"], 256);
    wrong_schema["schema_version"] = json!(2);
    for (label, body, expected) in [
        ("wrong schema version", wrong_schema, "invalid_request"),
        ("no documents", request(&[], 256), "invalid_request"),
        ("201 documents", request(&docs(201), 256), "invalid_request"),
        ("max_len 4", request(&["d"], 4), "invalid_request"),
        ("max_len 513", request(&["d"], 513), "invalid_request"),
        ("200 documents", request(&docs(200), 256), "disabled"),
        ("max_len 5", request(&["d"], 5), "disabled"),
        ("max_len 512", request(&["d"], 512), "disabled"),
    ] {
        assert_eq!(outcome(&body), expected, "{label}");
    }
}

/// ADR-0084 D-B: the request is `deny_unknown_fields`: a body with an extra field is refused by the extractor
/// (422), never scored or answered `disabled`. Fault: drop `deny_unknown_fields` => red.
#[test]
fn an_unknown_request_field_is_refused() {
    let addr = serve();
    let mut body = request(&["d"], 256);
    body["tenant_hint"] = json!("00000000-0000-7000-8000-000000000002");
    let (status, text) = post(addr, &body);
    assert_eq!(status, 422, "{text}");
}
