//! `gateway::tests::mcp_forget` — G-M19-2/G-M19-3 over real loopback MCP (§33.10; §37.2).
//! Depends-on: crates=[axum, humaux-adapters, humaux-application, humaux-contracts, humaux-domain, humaux-protocol,
//!   humaux-testkit, postgres, serde_json, tokio, uuid]; services=[HTTP(gateway), PostgreSQL(owner)
//!   r=[control.confirm_tokens, control.deletion_requests, ops.memory_lifecycle_events, private.memory_evidence, private.memory_records, projection.stream_log]
//!   w=[control.api_keys, control.confirm_tokens, control.deletion_requests, control.deletion_targets, ops.deletion_plan_steps, ops.memory_lifecycle_events, private.memory_evidence, projection.stream_checkpoints], PostgreSQL(role_gateway)]; env=[HUMAUX_TEST_PG_DSN];
//!   modules=[adapters::postgres, adapters::tests::support::operation_receipt_fixture, application::forget, contracts::retrieval_config,
//!   domain::context, domain::dataclass, domain::identity, gateway::context, gateway::guard, gateway::limiter,
//!   gateway::mcp_application, gateway::remember, humaux-testkit, protocol::edge, protocol::mcp, protocol::mcp_catalog, testkit::disposable]
//! Called-by: [cargo-test]
//! Invariants: [only disposable CI databases; each refusal asserts its wire code and unchanged deletion footprint;
//!   round one never consumes or revokes; no path mints and accepts in one call]
//! Spec: Baseline §33.10; §37.2; §52.1; §80.1; ADR-0092 D-B/D-C

use humaux_gateway::limiter::RatePolicy;
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, time::Duration};

use humaux_adapters::postgres::RuntimeDbPool;
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

use operation_receipt_fixture::{Handle, SYNTHETIC_CREDENTIAL_PEPPER, SyntheticCredentialScopes};

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
                rate_max_subjects: [50_000; 5],
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
    .with_confirm_token_ttl(Duration::from_secs(300))
    .expect("positive confirmation TTL")
    .with_enumeration(Duration::from_secs(300), 100)
    .expect("bounded enumeration")
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

/// §33.10: exercise the Memory tool through its HTTP wire contract.
async fn call_memory(address: SocketAddr, bearer: &str, arguments: Value) -> (u16, Value) {
    let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
    "name": "memory", "arguments": arguments, "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "mcp-forget", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }}})
    .to_string();
    // dep: HTTP(gateway) — the test dials the in-process gateway's loopback listener
    let mut stream = TcpStream::connect(address).await.expect("connect gateway");
    let request = format!(
        "POST /mcp HTTP/1.1\r\nConnection: close\r\nAccept: application/json, text/event-stream\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nHost: {HOST}\r\nOrigin: {ORIGIN}\r\n\
         MCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: memory\r\n\
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
        let updated = handle.admin.execute(
            "UPDATE control.api_keys SET scopes = ARRAY['memory:write','context:read'] WHERE api_key_id = $1",
            &[&credential.api_key_id],
        ).expect("owner grants fixture scopes");
        assert_eq!(updated, 1);
        // ADR-0031 / ADR-0054 D-A: governance writes admit a (tenant, workspace) pair only through its serving `v1`
        // checkpoint, so the fixture pair is provisioned the way ops does (mcp_gateway.rs `provision_stream_pair`);
        // unprovisioned, every round reads DEPENDENCY_UNAVAILABLE. The fixture teardown deletes these rows.
        for statement in [
            "INSERT INTO projection.stream_checkpoints \
               (tenant_id,scope_kind,scope_id,domain,projection_kind,projection_version) \
             VALUES($1,'workspace',$2,'knowledge','ingest','v1') ON CONFLICT DO NOTHING",
            "UPDATE projection.stream_checkpoints SET serving=true \
             WHERE tenant_id=$1 AND scope_kind='workspace' AND scope_id=$2 \
               AND domain='knowledge' AND projection_kind='ingest' AND projection_version='v1' \
               AND NOT EXISTS (SELECT 1 FROM projection.stream_checkpoints \
                               WHERE tenant_id=$1 AND scope_kind='workspace' AND scope_id=$2 \
                                 AND domain='knowledge' AND projection_kind='ingest' AND serving)",
        ] {
            handle
                .admin
                .execute(statement, &[&handle.tenant_id, &handle.workspace_id])
                .expect("owner provisions the fixture stream pair");
        }
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
            .block_on(call_memory(self.address, &self.bearer, arguments))
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self._server.abort();
    }
}

struct Fixture;
struct TestHandle(Handle);
impl std::ops::Deref for TestHandle {
    type Target = Handle;
    fn deref(&self) -> &Handle {
        &self.0
    }
}
impl std::ops::DerefMut for TestHandle {
    fn deref_mut(&mut self) -> &mut Handle {
        &mut self.0
    }
}
impl humaux_testkit::DbIntegrationFixture for Fixture {
    type Handle = TestHandle;
    fn isolate() -> Result<TestHandle, humaux_testkit::DbFixtureSkipReason> {
        let dsn = std::env::var("HUMAUX_TEST_PG_DSN")
            .map_err(|_| humaux_testkit::DbFixtureSkipReason::NoDatabaseUrl)?;
        // dep: PostgreSQL(owner) — §37 disposable check precedes fixture writes
        let mut client = postgres::Client::connect(&dsn, postgres::NoTls)
            .map_err(|e| humaux_testkit::DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        humaux_testkit::disposable::require_disposable(&mut client).expect("disposable database");
        Ok(TestHandle(operation_receipt_fixture::Fixture::isolate()?))
    }
}
impl Drop for TestHandle {
    fn drop(&mut self) {
        let tenant = self.tenant_id;
        for sql in [
            "DELETE FROM ops.deletion_plan_steps WHERE tenant_id=$1",
            "DELETE FROM control.deletion_targets WHERE tenant_id=$1",
            "DELETE FROM control.deletion_requests WHERE tenant_id=$1",
            "DELETE FROM control.confirm_tokens WHERE tenant_id=$1",
            "DELETE FROM ops.memory_lifecycle_events WHERE tenant_id=$1",
        ] {
            self.admin
                .execute(sql, &[&tenant])
                .expect("cleanup own deletion fixture");
        }
    }
}

#[track_caller]
fn structured(response: &(u16, Value)) -> &Value {
    assert_eq!(response.0, 200, "{}", response.1);
    assert_ne!(response.1["result"]["isError"], true, "{}", response.1);
    assert_eq!(response.1.get("error"), None, "{}", response.1);
    &response.1["result"]["structuredContent"]
}

#[track_caller]
fn refused(response: &(u16, Value), code: &str) {
    assert_eq!(response.1["result"]["isError"], true, "{}", response.1);
    assert_eq!(response.1["result"]["structuredContent"]["code"], code);
}

fn seed(h: &mut Handle, title: &str) -> Uuid {
    let content = json!({"title":title, "key_claim":title});
    h.seed_workspace_visible_context_record_with_content(&content)
        .memory_id
}

fn prepare(rig: &Rig, h: &Handle, roots: Value) -> (Uuid, String) {
    let response = rig.call(h, roots);
    let value = structured(&response);
    assert_eq!(value["confirmation_required"], true);
    assert_eq!(value["operation"], "memory.forget");
    assert_eq!(value["preview"]["restore_supported"], false);
    (
        Uuid::parse_str(
            value["target"]["deletion_request_id"]
                .as_str()
                .expect("request id"),
        )
        .expect("uuid"),
        value["confirm_token"].as_str().expect("token").to_owned(),
    )
}

fn accept(rig: &Rig, h: &Handle, request: Uuid, token: &str) -> (u16, Value) {
    rig.call(
        h,
        json!({"action":"forget", "request_id":request, "confirm_token":token}),
    )
}

fn footprint(h: &mut Handle) -> (i64, i64, i64, i64, i64) {
    let tenant = h.tenant_id;
    let row = h.admin.query_one(
        "SELECT (SELECT count(*) FROM control.confirm_tokens WHERE tenant_id=$1 AND consumed_at IS NOT NULL), \
         (SELECT count(*) FROM control.deletion_requests WHERE tenant_id=$1 AND logical_deleted_at IS NOT NULL), \
         (SELECT count(*) FROM ops.memory_lifecycle_events WHERE tenant_id=$1), \
         (SELECT count(*) FROM private.memory_records WHERE tenant_id=$1 AND status='revoked'), \
         (SELECT count(*) FROM projection.stream_log WHERE tenant_id=$1 AND state='TOMBSTONED')", &[&tenant]
    ).expect("deletion footprint");
    (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4))
}

fn get(rig: &Rig, h: &Handle, memory: Uuid) -> (u16, Value) {
    rig.call(h, json!({"action":"get", "memory_id":memory}))
}

#[test]
fn g_m19_2_wire_round_one_previews_and_forgets_nothing() {
    run_db_fixture::<Fixture, _>(
        "g_m19_2_wire_round_one_previews_and_forgets_nothing",
        |mut h| {
            let memory = seed(&mut h, "m19wirepreview");
            let rig = Rig::new(&mut h);
            let response = rig.call(&h, json!({"action":"forget", "memory_id":memory}));
            let value = structured(&response);
            assert_eq!(
                value["preview"],
                json!({"scope":"memory", "memory_count":1, "evidence_count":0,
            "memory_titles":["m19wirepreview"], "memory_titles_omitted":0, "multi_person_evidence":[],
            "multi_person_evidence_omitted":0, "source_retained":true, "restore_supported":false})
            );
            assert_eq!(value["preview"].get("manifest_hash"), None);
            let request =
                Uuid::parse_str(value["target"]["deletion_request_id"].as_str().expect("id"))
                    .expect("uuid");
            let tenant = h.tenant_id;
            let rows = h.admin.query("SELECT state, logical_deleted_at IS NULL, manifest_hash FROM control.deletion_requests WHERE tenant_id=$1 AND deletion_request_id=$2", &[&tenant,&request]).expect("request");
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].get::<_, String>(0), "REQUESTED");
            assert!(rows[0].get::<_, bool>(1));
            let manifest: Vec<u8> = rows[0].get(2);
            let intent = humaux_application::forget::confirmation_digest(
                humaux_application::forget::DeletionScopeKind::Memory,
                &manifest.try_into().expect("32-byte hash"),
            );
            let tokens = h.admin.query("SELECT request_sha256 FROM control.confirm_tokens WHERE tenant_id=$1 AND target_id=$2", &[&tenant,&request]).expect("tokens");
            assert_eq!(tokens.len(), 1);
            assert_eq!(tokens[0].get::<_, Vec<u8>>(0), intent);
            assert_eq!(footprint(&mut h), (0, 0, 0, 0, 0));
            assert_eq!(
                structured(&get(&rig, &h, memory))["content"]["items"]
                    .as_array()
                    .expect("items")
                    .len(),
                1
            );
            let (again, _) = prepare(&rig, &h, json!({"action":"forget", "memory_id":memory}));
            assert_eq!(again, request);
            let count: i64 = h
                .admin
                .query_one(
                    "SELECT count(*) FROM control.deletion_requests WHERE tenant_id=$1",
                    &[&tenant],
                )
                .expect("count")
                .get(0);
            assert_eq!(count, 1);
        },
    );
}

#[test]
fn g_m19_2_wire_round_two_without_token_is_invalid_input() {
    run_db_fixture::<Fixture, _>(
        "g_m19_2_wire_round_two_without_token_is_invalid_input",
        |mut h| {
            let memory = seed(&mut h, "m19wirenotoken");
            let rig = Rig::new(&mut h);
            let (request, _) = prepare(&rig, &h, json!({"action":"forget", "memory_id":memory}));
            let result = rig.call(&h, json!({"action":"forget", "request_id":request}));
            assert_eq!(result.1["error"]["code"], -32602);
            assert_eq!(footprint(&mut h), (0, 0, 0, 0, 0));
        },
    );
}

#[test]
fn g_m19_2_wire_foreign_token_is_conflict() {
    run_db_fixture::<Fixture, _>("g_m19_2_wire_foreign_token_is_conflict", |mut h| {
        let memory = seed(&mut h, "m19wireforeign");
        let rig = Rig::new(&mut h);
        let (request, _) = prepare(&rig, &h, json!({"action":"forget", "memory_id":memory}));
        let pin = rig.call(&h, json!({"action":"pin", "memory_id":memory}));
        let token = structured(&pin)["confirm_token"]
            .as_str()
            .expect("pin token");
        refused(&accept(&rig, &h, request, token), "CONFLICT");
        assert_eq!(footprint(&mut h), (0, 0, 0, 0, 0));
    });
}

#[test]
fn g_m19_2_wire_closure_grew_is_conflict() {
    run_db_fixture::<Fixture, _>("g_m19_2_wire_closure_grew_is_conflict", |mut h| {
        let memory = seed(&mut h, "m19wireclosure");
        let other = seed(&mut h, "m19wirelate");
        let root: Uuid = h.admin.query_one("SELECT evidence_id FROM private.memory_evidence WHERE memory_id=$1 AND role='PRIMARY'", &[&memory]).expect("root").get(0);
        let rig = Rig::new(&mut h);
        let (request, token) = prepare(&rig, &h, json!({"action":"forget", "evidence_ids":[root]}));
        h.admin.execute("INSERT INTO private.memory_evidence (memory_id,evidence_id,role,grounding_mode) VALUES ($1,$2,'SUPPORTING','SNAPSHOT')", &[&other,&root]).expect("closure grows");
        refused(&accept(&rig, &h, request, &token), "CONFLICT");
        assert_eq!(footprint(&mut h), (0, 0, 0, 0, 0));
        for id in [memory, other] {
            assert_eq!(
                structured(&get(&rig, &h, id))["content"]["items"]
                    .as_array()
                    .expect("items")
                    .len(),
                1
            );
        }
    });
}

#[test]
fn g_m19_2_wire_other_workspace_memory_is_not_found() {
    run_db_fixture::<Fixture, _>(
        "g_m19_2_wire_other_workspace_memory_is_not_found",
        |mut h| {
            let other_ws = Uuid::new_v4();
            let workspace = h.seed_workspace_with_id(other_ws);
            assert_eq!(workspace, other_ws);
            let original = h.workspace_id;
            h.workspace_id = other_ws;
            let memory = seed(&mut h, "m19wireotherworkspace");
            h.workspace_id = original;
            let rig = Rig::new(&mut h);
            refused(
                &rig.call(&h, json!({"action":"forget", "memory_id":memory})),
                "NOT_FOUND",
            );
            let tenant = h.tenant_id;
            let count: i64 = h
                .admin
                .query_one(
                    "SELECT count(*) FROM control.deletion_requests WHERE tenant_id=$1",
                    &[&tenant],
                )
                .expect("requests")
                .get(0);
            assert_eq!(count, 0);
            assert_eq!(footprint(&mut h), (0, 0, 0, 0, 0));
        },
    );
}

#[test]
fn g_m19_3_wire_accept_hides_memory_from_get_grep_enumerate() {
    run_db_fixture::<Fixture, _>(
        "g_m19_3_wire_accept_hides_memory_from_get_grep_enumerate",
        |mut h| {
            let memory = seed(&mut h, "m19wireuniquehidden");
            let rig = Rig::new(&mut h);
            let (request, token) =
                prepare(&rig, &h, json!({"action":"forget", "memory_id":memory}));
            let response = accept(&rig, &h, request, &token);
            assert_eq!(
                structured(&response),
                &json!({"forgotten":true,"deletion_request_id":request,"restore_supported":false})
            );
            refused(&get(&rig, &h, memory), "NOT_FOUND");
            let grep = rig.call(
                &h,
                json!({"action":"grep", "pattern":"m19wireuniquehidden"}),
            );
            assert_eq!(structured(&grep)["items"], json!([]));
            assert_eq!(structured(&grep)["total"], 0);
            let enumeration = rig.call(&h, json!({"action":"enumerate"}));
            assert_eq!(structured(&enumeration)["content"]["items"], json!([]));
            refused(&accept(&rig, &h, request, &token), "CONFLICT");
            assert_eq!(footprint(&mut h), (1, 1, 1, 1, 0));
        },
    );
}
