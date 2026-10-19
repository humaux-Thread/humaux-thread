//! `gateway::tests::coordinate_task` — G-T04b-1..3 (M29 T04b): `coordinate.task_submit` / `task_claim` /
//!   `task_heartbeat` / `task_complete` / `task_fail` through the real MCP surface against real PostgreSQL.
//! Depends-on: crates=[async-trait, axum, humaux-adapters, humaux-contracts, humaux-domain, humaux-protocol,
//!   humaux-testkit, postgres, serde_json, tokio, uuid]; services=[HTTP(gateway), PostgreSQL(owner)
//!   r=[control.quota_windows, coord.task_runs, coord.tasks] w=[control.api_keys, coord.task_runs],
//!   PostgreSQL(role_gateway)]; env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::postgres, adapters::quota_repo,
//!   adapters::tests::support::operation_receipt_fixture, contracts::retrieval_config, domain::context,
//!   domain::dataclass, domain::identity, gateway::context, gateway::guard, gateway::mcp_application,
//!   gateway::remember, humaux-testkit, protocol::edge, protocol::mcp, protocol::mcp_catalog]
//! Called-by: [cargo-test]
//! Invariants: [every call travels the in-process gateway over loopback MCP as a real service credential holding only
//!   `coordination:manage`; a lease is expired by SQL (`clock_timestamp() - interval '1 second'`), never by sleeping;
//!   a refusal is asserted by the tool error code AND by the rows the refused call must not have changed; BMO usage
//!   is the sum of `control.quota_windows.consumed` for the fixture tenant and is compared with `==`]
//! Spec: Baseline §30.1; §30.2; §33; §52; §80.1; ADR-0078 Q10
//!
//! Faults these gates are built for: the gateway or repository accepting a stale holder's token (G-T04b-2), a run that
//! belongs to another task (G-T04b-3), and `coordinate.task_heartbeat` being charged one BMO (G-T04b-1).

use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, time::Duration};

use humaux_adapters::{postgres::RuntimeDbPool, quota_repo::RatePolicy};
use humaux_domain::{context::ContextBudget, dataclass::DataClass, identity::VisibilityClass};
use humaux_gateway::{
    context::ContextBootstrap,
    guard::{GatewayGuard, GuardRatePolicies, GuardSettings},
    mcp_application::GatewayMcpApplication,
    remember::{ProcessFamily, RememberEventKind, RememberPolicy},
};
use humaux_protocol::{
    edge::{TrustedProxyConfig, compute_api_key_hash},
    mcp::{McpAdapter, McpHttpConfig},
    mcp_catalog::CanonicalCatalog,
};
use humaux_testkit::run_db_fixture;
use serde_json::{Value, json};
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
};

const HOST: &str = "mcp.test";
const ORIGIN: &str = "https://mcp.test";

// ----------------------------------------------------------------------------------------------
// One in-process gateway
// ----------------------------------------------------------------------------------------------

fn rate() -> RatePolicy {
    RatePolicy::new(100, 100).expect("explicit fixture rate")
}

fn guard(runtime: RuntimeDbPool) -> Arc<GatewayGuard> {
    Arc::new(
        GatewayGuard::new(
            runtime,
            GuardSettings {
                credential_pepper: SYNTHETIC_CREDENTIAL_PEPPER.to_vec(),
                credential_pepper_previous: None,
                trusted_proxies: TrustedProxyConfig {
                    trusted_proxy_cidrs: vec![],
                    max_forwarded_hops: 1,
                },
                global_denylist: vec![],
                global_emergency_allowlist: vec![],
                tenant_network: BTreeMap::new(),
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
                replay_ttl: Duration::from_secs(60),
            },
        )
        .expect("explicit guard settings"),
    )
}

fn application(handle: &Handle) -> GatewayMcpApplication {
    let policy = RememberPolicy::new(
        ProcessFamily::new("workspace", "knowledge", "ingest", "v1").expect("trusted family"),
        handle.reasoning_domain_id,
        Duration::from_secs(60),
        DataClass::Internal,
        VisibilityClass::WorkspaceShared,
    )
    .expect("trusted fixture remember policy");
    let bootstrap = ContextBootstrap::new(
        ContextBudget::new(2_048, 1_024).expect("trusted budget"),
        humaux_contracts::retrieval_config::resolve_registered_retrieval_profile(
            &Default::default(),
        )
        .expect("registered profile"),
        &policy,
        Duration::from_secs(60),
    )
    .expect("actual executable identity");
    let runtime = handle
        .rt
        .block_on(handle.fresh_runtime())
        .expect("fresh Gateway runtime");
    GatewayMcpApplication::new(
        CanonicalCatalog::load().expect("closed canonical MCP catalog"),
        guard(runtime),
        policy,
        RememberEventKind::UserMessage,
        bootstrap,
    )
    .with_task_lease_ttl(Duration::from_secs(300))
    .expect("positive task lease TTL")
}

async fn start(application: GatewayMcpApplication) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let catalog = CanonicalCatalog::load()
        .expect("catalog")
        .trusted_catalog()
        .expect("trusted catalog");
    let adapter = McpAdapter::new(
        Arc::new(application),
        catalog,
        McpHttpConfig::new(vec![HOST.into()], vec![ORIGIN.into()], 64 * 1024)
            .expect("explicit listener configuration"),
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
        .expect("serve loopback MCP");
    });
    (address, server)
}

/// One `tools/call` to `coordinate`: the HTTP status and the JSON body.
async fn call_coordinate(address: SocketAddr, bearer: &str, arguments: Value) -> (u16, Value) {
    let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
    "name": "coordinate", "arguments": arguments, "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "coordinate-task", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }}})
    .to_string();
    // dep: HTTP(gateway) — the test dials the in-process gateway's loopback listener
    let mut stream = TcpStream::connect(address).await.expect("connect gateway");
    let request = format!(
        "POST /mcp HTTP/1.1\r\nConnection: close\r\nAccept: application/json, text/event-stream\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nHost: {HOST}\r\nOrigin: {ORIGIN}\r\n\
         MCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: coordinate\r\n\
         Authorization: {bearer}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("read");
    let response = String::from_utf8(response).expect("utf8");
    let (head, body) = response.split_once("\r\n\r\n").expect("http body");
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("HTTP status line");
    let body = if body.starts_with("event:") {
        body.lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap_or(body)
    } else {
        body
    };
    (
        status,
        serde_json::from_str(body).unwrap_or_else(|_| json!({"raw": body})),
    )
}

/// The gateway under test plus the credential that reaches it.
struct Rig {
    address: SocketAddr,
    bearer: String,
    _server: tokio::task::JoinHandle<()>,
}

impl Rig {
    fn new(handle: &mut Handle) -> Self {
        let prefix = format!("ct{}", &Uuid::now_v7().simple().to_string()[..12]);
        let wire = format!("{prefix}.{}", "c".repeat(32));
        let credential = handle.seed_synthetic_service_credential_and_window(
            SyntheticCredentialScopes::RememberWrite,
            &prefix,
            &wire,
            &compute_api_key_hash(SYNTHETIC_CREDENTIAL_PEPPER, &wire),
            400,
        );
        // The fixture's closed scope sets carry no coordination scope; the owner swaps in the one this tool needs.
        let updated = handle
            .admin
            .execute(
                "UPDATE control.api_keys SET scopes = ARRAY['coordination:manage'] WHERE api_key_id = $1",
                &[&credential.api_key_id],
            )
            .expect("owner grants the coordination scope");
        assert_eq!(updated, 1, "exactly the fixture credential is re-scoped");
        let application = application(handle);
        let (address, server) = handle.rt.block_on(start(application));
        Self {
            address,
            bearer: credential.bearer,
            _server: server,
        }
    }

    fn call(&self, handle: &Handle, arguments: Value) -> (u16, Value) {
        handle
            .rt
            .block_on(call_coordinate(self.address, &self.bearer, arguments))
    }
}

// ----------------------------------------------------------------------------------------------
// Wire helpers
// ----------------------------------------------------------------------------------------------

#[track_caller]
fn structured(response: &(u16, Value)) -> &Value {
    assert_eq!(response.0, 200, "{}", response.1);
    assert_ne!(response.1["result"]["isError"], true, "{}", response.1);
    &response.1["result"]["structuredContent"]
}

#[track_caller]
fn assert_refused(response: &(u16, Value), code: &str, label: &str) {
    let result = &response.1["result"];
    assert_eq!(
        result["isError"], true,
        "{label}: expected {code}: {}",
        response.1
    );
    assert_eq!(
        result["structuredContent"]["code"], code,
        "{label}: {}",
        response.1
    );
}

#[track_caller]
fn uuid_field(value: &Value, field: &str) -> Uuid {
    Uuid::parse_str(
        value[field]
            .as_str()
            .unwrap_or_else(|| panic!("{field}: {value}")),
    )
    .unwrap_or_else(|_| panic!("{field} is a uuid: {value}"))
}

struct Claim {
    run: Uuid,
    token: i64,
}

fn submit(rig: &Rig, handle: &Handle, title: &str, description: &str) -> Uuid {
    let response = rig.call(
        handle,
        json!({"action":"task_submit","title":title,"description":description}),
    );
    uuid_field(structured(&response), "task_id")
}

fn claim(rig: &Rig, handle: &Handle, task: Uuid) -> Claim {
    let response = rig.call(handle, json!({"action":"task_claim","task_id":task}));
    let result = structured(&response);
    assert!(
        result["lease_expires_at"].as_str().is_some(),
        "claim answers the lease expiry: {result}"
    );
    Claim {
        run: uuid_field(result, "task_run_id"),
        token: result["fencing_token"].as_i64().expect("fencing_token"),
    }
}

fn heartbeat(rig: &Rig, handle: &Handle, task: Uuid, run: Uuid, token: i64) -> (u16, Value) {
    rig.call(
        handle,
        json!({"action":"task_heartbeat","task_id":task,"task_run_id":run,"fencing_token":token}),
    )
}

fn close(
    rig: &Rig,
    handle: &Handle,
    action: &str,
    task: Uuid,
    run: Uuid,
    token: i64,
    summary: &str,
) -> (u16, Value) {
    rig.call(
        handle,
        json!({"action":action,"task_id":task,"task_run_id":run,"fencing_token":token,"summary":summary}),
    )
}

// ----------------------------------------------------------------------------------------------
// Database probes (owner role; the request path never uses these)
// ----------------------------------------------------------------------------------------------

/// The tenant's total consumed BMO across its quota windows.
fn consumed(handle: &mut Handle) -> i64 {
    handle
        .admin
        .query_one(
            "SELECT COALESCE(sum(consumed), 0)::bigint FROM control.quota_windows WHERE tenant_id = $1",
            &[&handle.tenant_id],
        )
        .expect("owner reads consumed BMO")
        .get(0)
}

fn expire_lease(handle: &mut Handle, run: Uuid) {
    let updated = handle
        .admin
        .execute(
            "UPDATE coord.task_runs SET lease_expires_at = clock_timestamp() - interval '1 second' \
             WHERE task_run_id = $1",
            &[&run],
        )
        .expect("owner expires the lease");
    assert_eq!(updated, 1, "exactly the named run is expired");
}

fn task_state(handle: &mut Handle, task: Uuid) -> String {
    handle
        .admin
        .query_one("SELECT state FROM coord.tasks WHERE task_id = $1", &[&task])
        .expect("owner reads the task")
        .get(0)
}

/// `(finished, outcome_summary)` of one run.
fn run_outcome(handle: &mut Handle, run: Uuid) -> (bool, Option<String>) {
    let row = handle
        .admin
        .query_one(
            "SELECT finished_at IS NOT NULL, outcome_summary FROM coord.task_runs WHERE task_run_id = $1",
            &[&run],
        )
        .expect("owner reads the run");
    (row.get(0), row.get(1))
}

// ----------------------------------------------------------------------------------------------
// Gates
// ----------------------------------------------------------------------------------------------

/// G-T04b-1: submit -> claim (run id + token) -> heartbeat OK -> lease expires -> heartbeat and complete with the same
/// token are `CONFLICT`. Metering rides the contract: claim adds exactly one BMO, heartbeat none.
#[test]
fn g_t04b_1_end_to_end_then_expiry_refuses_with_bmo_per_contract() {
    run_db_fixture::<Fixture, _>("coordinate_task_g1", |mut handle| {
        let rig = Rig::new(&mut handle);

        let before_submit = consumed(&mut handle);
        let task = submit(&rig, &handle, "g1 task", "g1 description");
        assert_eq!(
            consumed(&mut handle),
            before_submit + 1,
            "task_submit is ordinary1"
        );
        let stored: Option<String> = handle
            .admin
            .query_one(
                "SELECT description FROM coord.tasks WHERE task_id = $1",
                &[&task],
            )
            .expect("owner reads the task")
            .get(0);
        assert_eq!(stored.as_deref(), Some("g1 description"));

        let before_claim = consumed(&mut handle);
        let claimed = claim(&rig, &handle, task);
        assert_eq!(
            claimed.token, 1,
            "the first claim of a task carries token 1"
        );
        assert_eq!(
            consumed(&mut handle),
            before_claim + 1,
            "task_claim is ordinary1: exactly one BMO"
        );

        let before_heartbeat = consumed(&mut handle);
        let renewed = heartbeat(&rig, &handle, task, claimed.run, claimed.token);
        assert!(
            structured(&renewed)["lease_expires_at"].as_str().is_some(),
            "heartbeat answers the renewed expiry: {}",
            renewed.1
        );
        assert_eq!(
            consumed(&mut handle),
            before_heartbeat,
            "task_heartbeat is zeroControl: no BMO"
        );
        assert_eq!(task_state(&mut handle, task), "WORKING");

        expire_lease(&mut handle, claimed.run);
        assert_refused(
            &heartbeat(&rig, &handle, task, claimed.run, claimed.token),
            "CONFLICT",
            "heartbeat after expiry",
        );
        assert_refused(
            &close(
                &rig,
                &handle,
                "task_complete",
                task,
                claimed.run,
                claimed.token,
                "too late",
            ),
            "CONFLICT",
            "complete after expiry",
        );
        assert_eq!(
            task_state(&mut handle, task),
            "WORKING",
            "the refused complete changed nothing"
        );
        assert_eq!(run_outcome(&mut handle, claimed.run), (false, None));
    });
}

/// G-T04b-2: a token from before a re-claim is `CONFLICT` on heartbeat and complete — against its own run and against
/// the new run alike — while the new token works; complete stores the sent summary and leaves the task `COMPLETED`.
#[test]
fn g_t04b_2_stale_token_on_the_wire_is_refused_and_the_new_one_completes() {
    run_db_fixture::<Fixture, _>("coordinate_task_g2", |mut handle| {
        let rig = Rig::new(&mut handle);
        let task = submit(&rig, &handle, "g2 task", "g2 description");

        let first = claim(&rig, &handle, task);
        expire_lease(&mut handle, first.run);
        let second = claim(&rig, &handle, task);
        assert_eq!(second.token, first.token + 1, "a re-claim bumps the token");
        assert_ne!(second.run, first.run);

        for (label, run, token) in [
            ("first run, first token", first.run, first.token),
            ("second run, first token", second.run, first.token),
        ] {
            assert_refused(
                &heartbeat(&rig, &handle, task, run, token),
                "CONFLICT",
                &format!("heartbeat: {label}"),
            );
            assert_refused(
                &close(&rig, &handle, "task_complete", task, run, token, "stale"),
                "CONFLICT",
                &format!("complete: {label}"),
            );
            assert_refused(
                &close(&rig, &handle, "task_fail", task, run, token, "stale"),
                "CONFLICT",
                &format!("fail: {label}"),
            );
        }
        assert_eq!(task_state(&mut handle, task), "CLAIMED");
        assert_eq!(run_outcome(&mut handle, second.run), (false, None));

        structured(&heartbeat(&rig, &handle, task, second.run, second.token));
        let done = close(
            &rig,
            &handle,
            "task_complete",
            task,
            second.run,
            second.token,
            "g2 finished",
        );
        assert_eq!(structured(&done)["state"], "COMPLETED", "{}", done.1);
        assert_eq!(task_state(&mut handle, task), "COMPLETED");
        assert_eq!(
            run_outcome(&mut handle, second.run),
            (true, Some("g2 finished".to_owned())),
            "outcome_summary equals the sent summary"
        );
        assert_eq!(
            run_outcome(&mut handle, first.run),
            (true, None),
            "the superseded run closed by the re-claim carries no summary"
        );
    });
}

/// G-T04b-3: run A's id and token under task B's `task_id` is `NOT_FOUND` on heartbeat, complete and fail, and changes
/// neither run nor task; the same ids under their own task work, `task_fail` included.
#[test]
fn g_t04b_3_run_that_is_not_of_the_named_task_is_not_found() {
    run_db_fixture::<Fixture, _>("coordinate_task_g3", |mut handle| {
        let rig = Rig::new(&mut handle);
        let task_a = submit(&rig, &handle, "g3 task a", "g3 description a");
        let task_b = submit(&rig, &handle, "g3 task b", "g3 description b");
        let run_a = claim(&rig, &handle, task_a);
        let run_b = claim(&rig, &handle, task_b);

        assert_refused(
            &heartbeat(&rig, &handle, task_b, run_a.run, run_a.token),
            "NOT_FOUND",
            "heartbeat: run A under task B",
        );
        for action in ["task_complete", "task_fail"] {
            assert_refused(
                &close(
                    &rig,
                    &handle,
                    action,
                    task_b,
                    run_a.run,
                    run_a.token,
                    "mismatch",
                ),
                "NOT_FOUND",
                &format!("{action}: run A under task B"),
            );
        }
        assert_eq!(task_state(&mut handle, task_a), "CLAIMED");
        assert_eq!(task_state(&mut handle, task_b), "CLAIMED");
        assert_eq!(run_outcome(&mut handle, run_a.run), (false, None));

        structured(&heartbeat(&rig, &handle, task_a, run_a.run, run_a.token));
        let failed = close(
            &rig,
            &handle,
            "task_fail",
            task_b,
            run_b.run,
            run_b.token,
            "g3 broke",
        );
        assert_eq!(structured(&failed)["state"], "FAILED", "{}", failed.1);
        assert_eq!(task_state(&mut handle, task_b), "FAILED");
        assert_eq!(
            run_outcome(&mut handle, run_b.run),
            (true, Some("g3 broke".to_owned()))
        );
    });
}
