//! `gateway::tests::guard_limiter` — Real MCP guard wiring and subject-cap refusals (§72.3; ADR-0100).
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-protocol, humaux-testkit, serde_json, tokio, uuid];
//!   services=[PostgreSQL(role_gateway), HTTP(loopback)]; env=[]; modules=[gateway::guard, gateway::limiter]
//! Called-by: [tests]
//! Invariants: [each case isolates one production guard tier; frozen time prevents refill during DB I/O]
//! Spec: Baseline §72.3; §79; §80.1; ADR-0065 W-10; ADR-0100

use super::*;

fn seed(handle: &mut Handle) -> SyntheticServiceCredential {
    let prefix = format!("rate{}", Uuid::now_v7().simple());
    let wire = format!("{prefix}.{}", "r".repeat(32));
    handle.seed_synthetic_service_credential(
        SyntheticCredentialScopes::RememberWriteAndContextRead,
        &prefix,
        &wire,
        &compute_api_key_hash(SYNTHETIC_CREDENTIAL_PEPPER, &wire),
    )
}

fn configured(
    handle: &Handle,
    settings: GuardSettings,
) -> (GatewayMcpApplication, Arc<GatewayGuard>) {
    let rt = handle.rt.handle().clone();
    rt.block_on(async {
        let pool = handle.fresh_runtime().await.expect("checked runtime");
        let guard = Arc::new(GatewayGuard::new(pool, settings).unwrap());
        let app = application_with_guard(
            handle,
            guard.clone(),
            ContextBudget::new(2048, 1024).unwrap(),
        );
        (app, guard)
    })
}

fn frozen() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap()
}

// §79: runnable work prevents Tokio auto-advancing the paused limiter clock while PG is busy.
async fn hold_clock() {
    loop {
        tokio::task::yield_now().await;
    }
}

async fn wire(addr: SocketAddr, bearer: Option<&str>) -> (u16, Vec<String>, String) {
    let body = rpc(1, "tools/list", json!({"_meta": metadata()}));
    // dep: HTTP(loopback) — production MCP boundary and GatewayGuard (§83)
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let auth = bearer.map_or(String::new(), |b| format!("Authorization: {b}\r\n"));
    let raw = format!(
        "POST /mcp HTTP/1.1\r\nHost: {HOST}\r\nOrigin: {ORIGIN}\r\nConnection: close\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/list\r\n{auth}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(raw.as_bytes()).await.unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).await.unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap();
    (
        head.split_whitespace().nth(1).unwrap().parse().unwrap(),
        head.lines().skip(1).map(str::to_lowercase).collect(),
        body.to_owned(),
    )
}

fn assert_rate_metrics(guard: &GatewayGuard, rejected: &str) {
    let mut rendered = String::new();
    guard.metrics().render(&mut rendered);
    let actual: BTreeSet<_> = rendered
        .lines()
        .filter(|l| l.starts_with("rate_limit_rejected_total{"))
        .map(str::to_owned)
        .collect();
    let expected: BTreeSet<_> = [
        "ip",
        "credential",
        "user",
        "tenant",
        "operation",
        "capacity",
    ]
    .map(|scope| {
        format!(
            "rate_limit_rejected_total{{scope=\"{scope}\"}} {}",
            u8::from(scope == rejected)
        )
    })
    .into_iter()
    .collect();
    assert_eq!(actual.len(), 6);
    assert_eq!(
        actual, expected,
        "one refusal in precisely the configured tier"
    );
}

async fn policy_case(
    app: GatewayMcpApplication,
    guard: Arc<GatewayGuard>,
    bearer: &str,
    tier: &str,
) {
    let clock = tokio::spawn(hold_clock());
    let (addr, server) = start(app).await;
    let mut statuses = Vec::new();
    for _ in 0..2 {
        statuses.push(wire(addr, Some(bearer)).await.0);
    }
    let (status, headers, body) = wire(addr, (tier != "ip").then_some(bearer)).await;
    statuses.push(status);
    assert_eq!(
        statuses,
        [200, 200, 429],
        "G-M03-1 guard {tier} exact burst"
    );
    let code = if tier == "ip" {
        body
    } else {
        serde_json::from_str::<Value>(&body).unwrap()["error"]["message"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert_eq!(code, "RATE_LIMITED");
    assert_eq!(
        headers
            .iter()
            .filter(|h| h.starts_with("retry-after:"))
            .count(),
        0
    );
    assert_rate_metrics(&guard, tier);
    server.abort();
    clock.abort();
}

#[test]
fn g_m03_1_guard_wiring_all_five_tiers() {
    run_db_fixture::<Fixture, _>("g_m03_1_guard_wiring", |mut handle| {
        let credential = seed(&mut handle);
        for tier in ["ip", "credential", "user", "tenant", "operation"] {
            let mut settings = guard_settings();
            let rates = &mut settings.rates;
            let selected = match tier {
                "ip" => &mut rates.preauth_ip,
                "credential" => &mut rates.credential,
                "user" => &mut rates.user,
                "tenant" => &mut rates.tenant,
                "operation" => &mut rates.operation,
                _ => unreachable!(),
            };
            *selected = RatePolicy::new(2, 2).unwrap();
            let (app, guard) = configured(&handle, settings);
            frozen().block_on(policy_case(app, guard, &credential.bearer, tier));
        }
    });
}

#[test]
fn g_m03_9_real_guard_subject_capacity_has_retry_after_and_metric() {
    run_db_fixture::<Fixture, _>("g_m03_9_guard_subject_capacity", |mut handle| {
        let a = seed(&mut handle);
        let b = seed(&mut handle);
        let mut settings = guard_settings();
        settings.rate_max_subjects[1] = 1;
        let (app, guard) = configured(&handle, settings);
        frozen().block_on(async {
            let clock = tokio::spawn(hold_clock());
            let (addr, server) = start(app).await;
            assert_eq!(wire(addr, Some(&a.bearer)).await.0, 200);
            let (status, headers, body) = wire(addr, Some(&b.bearer)).await;
            assert_eq!(status, 503, "G-M03-9 real postauth subject capacity");
            let error: Value = serde_json::from_str(&body).unwrap();
            assert_eq!(error["error"]["message"], "DEPENDENCY_UNAVAILABLE");
            assert_eq!(
                headers
                    .iter()
                    .filter(|h| h.starts_with("retry-after:"))
                    .collect::<Vec<_>>(),
                vec!["retry-after: 1"]
            );
            assert_rate_metrics(&guard, "capacity");
            server.abort();
            clock.abort();
        });
    });
}
