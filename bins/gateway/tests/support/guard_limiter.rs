//! `gateway::tests::support::guard_limiter` — Real MCP guard wiring and subject-cap refusals (§72.3; ADR-0100).
//! Depends-on: crates=[serde_json, tokio];
//!   services=[HTTP(loopback)]; env=[]; modules=[gateway::tests::mcp_gateway]
//! Called-by: [gateway::tests::mcp_gateway]
//! Invariants: [each case isolates one production guard tier; frozen time prevents refill during DB I/O; the global
//!   denylist refuses before authentication, beats the emergency allowlist, and the emergency allowlist beats the
//!   tenant's own deny (§73.3); a policy refusal moves no rate counter]
//! Spec: Baseline §72.3; §73.3; §79; §80.1; ADR-0065 W-10; ADR-0100

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
    wire_from(addr, bearer, "").await
}

async fn wire_from(
    addr: SocketAddr,
    bearer: Option<&str>,
    forwarded: &str,
) -> (u16, Vec<String>, String) {
    let body = rpc(1, "tools/list", json!({"_meta": metadata()}));
    // dep: HTTP(loopback) — production MCP boundary and GatewayGuard (§83)
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let auth = bearer.map_or(String::new(), |b| format!("Authorization: {b}\r\n"));
    let raw = format!(
        "POST /mcp HTTP/1.1\r\nHost: {HOST}\r\nOrigin: {ORIGIN}\r\nConnection: close\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/list\r\n{auth}{forwarded}Content-Length: {}\r\n\r\n{body}",
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

#[test]
fn g_m03_1_real_guard_ip_capacity_keeps_authenticated_room() {
    run_db_fixture::<Fixture, _>("g_m03_1_guard_tier_capacity", |mut handle| {
        let credential = seed(&mut handle);
        let mut settings = guard_settings();
        settings.rate_max_subjects[0] = 1;
        let (app, guard) = configured(&handle, settings);
        frozen().block_on(async {
            let clock = tokio::spawn(hold_clock());
            let (addr, server) = start(app).await;
            // §72.3: unauthenticated traffic fills the only IP slot before any postauth slot exists.
            let statuses = [
                wire(addr, None).await.0,
                wire(addr, Some(&credential.bearer)).await.0,
            ];
            assert_eq!(
                statuses,
                [401, 200],
                "IP capacity must leave all four authenticated tiers available"
            );
            assert_rate_metrics(&guard, "");
            server.abort();
            clock.abort();
        });
    });
}

#[test]
fn g_m03_9_preflight_ip_capacity_has_retry_after_and_metric() {
    run_db_fixture::<Fixture, _>("g_m03_9_preflight_capacity", |mut handle| {
        let credential = seed(&mut handle);
        let mut settings = guard_settings();
        settings.rate_max_subjects[0] = 1;
        settings.trusted_proxies.trusted_proxy_cidrs = vec!["127.0.0.0/8".parse().unwrap()];
        let (app, guard) = configured(&handle, settings);
        frozen().block_on(async {
            let clock = tokio::spawn(hold_clock());
            let (addr, server) = start(app).await;
            assert_eq!(
                wire_from(addr, Some(&credential.bearer), "Forwarded: 203.0.113.1\r\n")
                    .await
                    .0,
                200
            );
            let (status, headers, body) =
                wire_from(addr, Some(&credential.bearer), "Forwarded: 203.0.113.2\r\n").await;
            assert_eq!(status, 503, "G-M03-9 new IP at preflight capacity");
            assert_eq!(body, "DEPENDENCY_UNAVAILABLE");
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

/// §73.3: a documentation range (never routable) that the G-M03-13 cases deny; `DENIED_IP` sits inside it.
const DENIED_NET: &str = "203.0.113.0/24";
const DENIED_IP: &str = "203.0.113.7";
const OTHER_IP: &str = "198.51.100.1";

/// Guard settings whose client IP comes from `Forwarded:`, because the loopback peer is a trusted proxy (§73.3).
fn proxied_settings() -> GuardSettings {
    let mut settings = guard_settings();
    settings.trusted_proxies.trusted_proxy_cidrs = vec!["127.0.0.0/8".parse().unwrap()];
    settings
}

/// One `tools/list` per `(bearer, client ip)` probe, in order, through a real guard built from `settings`.
/// A policy refusal is not a rate refusal (§73.3 against §72.3): no probe may move `rate_limit_rejected_total`.
fn probe(handle: &Handle, settings: GuardSettings, probes: &[(&str, &str)]) -> Vec<(u16, String)> {
    let (app, guard) = configured(handle, settings);
    frozen().block_on(async {
        let clock = tokio::spawn(hold_clock());
        let (addr, server) = start(app).await;
        let mut replies = Vec::new();
        for &(bearer, ip) in probes {
            let (status, _, body) =
                wire_from(addr, Some(bearer), &format!("Forwarded: {ip}\r\n")).await;
            replies.push((status, body));
        }
        assert_rate_metrics(&guard, "");
        server.abort();
        clock.abort();
        replies
    })
}

#[test]
fn g_m03_13_global_denylist_is_preauth_and_is_not_a_rate_refusal() {
    run_db_fixture::<Fixture, _>("g_m03_13_global_denylist", |mut handle| {
        let credential = seed(&mut handle);
        let invalid = format!("Bearer nope.{}", "x".repeat(32));
        let mut settings = proxied_settings();
        settings.global_denylist = vec![DENIED_NET.parse().unwrap()];
        // One token per client: a deny that charged the pre-auth bucket would make the second DENIED_IP probe a 429.
        settings.rates.preauth_ip = RatePolicy::new(1, 1).unwrap();
        let got = probe(
            &handle,
            settings,
            &[
                (invalid.as_str(), DENIED_IP),
                (credential.bearer.as_str(), DENIED_IP),
                (credential.bearer.as_str(), OTHER_IP),
            ],
        );
        let denied: (u16, String) = (403, "FORBIDDEN".to_owned());
        assert_eq!(
            got[0], denied,
            "G-M03-13 an invalid bearer from a denied client is a 403, not a 401: the deny is pre-auth"
        );
        assert_eq!(
            got[1], denied,
            "G-M03-13 a valid bearer from a denied client is a 403"
        );
        assert_eq!(
            got[2].0, 200,
            "G-M03-13 the same bearer from another client is served"
        );
    });
}

#[test]
fn g_m03_13_global_denylist_beats_the_emergency_allowlist() {
    run_db_fixture::<Fixture, _>("g_m03_13_deny_beats_emergency_allow", |mut handle| {
        let credential = seed(&mut handle);
        let mut settings = proxied_settings();
        settings.global_denylist = vec!["203.0.113.7/32".parse().unwrap()];
        settings.global_emergency_allowlist = vec!["203.0.113.7/32".parse().unwrap()];
        let got = probe(
            &handle,
            settings,
            &[(credential.bearer.as_str(), DENIED_IP)],
        );
        let denied: (u16, String) = (403, "FORBIDDEN".to_owned());
        assert_eq!(
            got[0], denied,
            "G-M03-13 an IP on both lists stays denied (edge.rs evaluate_ip_policy)"
        );
    });
}

#[test]
fn g_m03_13_emergency_allowlist_beats_the_tenants_own_deny_postauth() {
    run_db_fixture::<Fixture, _>("g_m03_13_emergency_beats_tenant_deny", |mut handle| {
        let credential = seed(&mut handle);
        // `seed` inserts the key under `Handle::tenant_id` (operation_receipt_fixture.rs, control.api_keys.tenant_id),
        // the tenant the post-auth tier looks the policy up by.
        let tenant = handle.tenant_id;
        let settings_for = |emergency: bool| {
            let mut settings = proxied_settings();
            settings.tenant_network = BTreeMap::from([(
                tenant,
                TenantNetworkPolicy {
                    denylist: vec![DENIED_NET.parse().unwrap()],
                    allowlist: vec![],
                },
            )]);
            if emergency {
                settings.global_emergency_allowlist = vec!["203.0.113.7/32".parse().unwrap()];
            }
            settings
        };
        let probes = [(credential.bearer.as_str(), DENIED_IP)];
        let refused = probe(&handle, settings_for(false), &probes);
        // Post-auth: the handler answers, so the code is the JSON-RPC error message, not the pre-auth plain body.
        let error: Value = serde_json::from_str(&refused[0].1).unwrap();
        assert_eq!(
            refused[0].0, 403,
            "G-M03-13 the tenant's own deny refuses without an emergency allow"
        );
        assert_eq!(error["error"]["message"], "FORBIDDEN");
        let allowed = probe(&handle, settings_for(true), &probes);
        assert_eq!(
            allowed[0].0, 200,
            "G-M03-13 the emergency allow beats the tenant's own deny"
        );
    });
}
