//! Policy/capacity HTTP contracts (§67.2; §72.3; ADR-0100).
//! Depends-on: crates=[axum, humaux-domain, humaux-gateway, humaux-protocol, tokio, uuid];
//!   services=[HTTP(loopback)]; env=[]; modules=[gateway::admission, gateway::limiter, protocol::error_map]
//! Called-by: [cargo-test]
//! Invariants: [G-M03-9 uses production admission middleware and policy error mapping; no quota path is entered]
//! Spec: Baseline §67.2; §72.3; §79; §80.1; ADR-0100

use axum::{Router, http::StatusCode, routing::post};
use humaux_domain::error::ErrorCode;
use humaux_gateway::{
    admission::{self, Admission, AdmissionSettings},
    limiter::{Limiter, RatePolicy, Subject},
};
use humaux_protocol::error_map;
use std::{
    future::IntoFuture,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

async fn request(addr: std::net::SocketAddr) -> (u16, Vec<String>, String) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).await.unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap();
    (
        head.split_whitespace().nth(1).unwrap().parse().unwrap(),
        head.lines().skip(1).map(str::to_lowercase).collect(),
        body.to_owned(),
    )
}

#[tokio::test]
async fn g_m03_9_policy_429_capacity_503_retry_after_and_zero_handler_calls() {
    let policy = RatePolicy::new(1, 1).unwrap();
    let limiter = Arc::new(Limiter::new([policy; 5], 100).unwrap());
    let subject = Subject::Account(Uuid::now_v7());
    limiter.check(std::slice::from_ref(&subject)).unwrap();
    let called = Arc::new(AtomicUsize::new(0));
    let count = called.clone();
    let mcp = Router::new().route(
        "/",
        post(move || async move {
            count.fetch_add(1, Ordering::SeqCst);
            let code = limiter.check(&[subject]).unwrap_err().code;
            assert_eq!(code, ErrorCode::RateLimited);
            (
                StatusCode::from_u16(error_map::lookup(code).http_status).unwrap(),
                code.as_str(),
            )
        }),
    );
    let admission = Arc::new(Admission::new(AdmissionSettings {
        concurrency: 1,
        queue_depth: 0,
        max_wait: Duration::from_millis(5),
        per_key_limit: 1,
        body_read_timeout: Duration::from_secs(1),
        max_request_body_bytes: 1024,
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(
        axum::serve(
            listener,
            admission::wrap(mcp, Router::new(), admission.clone()),
        )
        .into_future(),
    );
    let (status, headers, body) = request(addr).await;
    assert_eq!(
        (status, body.as_str()),
        (429, "RATE_LIMITED"),
        "G-M03-9 policy refusal"
    );
    assert_eq!(
        headers
            .iter()
            .filter(|h| h.starts_with("retry-after:"))
            .count(),
        0
    );
    assert_eq!(called.load(Ordering::SeqCst), 1);
    let ticket = admission.enter(0).await.unwrap();
    let (status, headers, body) = request(addr).await;
    assert_eq!(
        (status, body.as_str()),
        (503, "RATE_LIMITED"),
        "G-M03-9 capacity refusal"
    );
    let retry: Vec<_> = headers
        .iter()
        .filter_map(|h| h.strip_prefix("retry-after: "))
        .collect();
    assert_eq!(retry.len(), 1);
    assert!((1..=30).contains(&retry[0].parse::<u64>().unwrap()));
    assert_eq!(
        called.load(Ordering::SeqCst),
        1,
        "capacity refusal never reaches quota/handler"
    );
    drop(ticket);
    task.abort();
}
