//! `gateway::tests::cross_tenant_canary` — G-M08-3 (DOD-023): another tenant's real ids, sent through the gateway on
//!   every read op, answer exactly as ids that exist nowhere do, and report totals of zero.
//! Depends-on: crates=[async-trait, axum, humaux-adapters, humaux-application, humaux-contracts, humaux-domain,
//!   humaux-infra-cell, humaux-protocol, humaux-testkit, postgres, serde_json, tokio, uuid];
//!   services=[HTTP(gateway), PostgreSQL(owner) w=[coord.tasks, private.continuity_projects, private.evidence_objects,
//!   private.memory_records, projection.stream_checkpoints], PostgreSQL(role_gateway)]; env=[HUMAUX_TEST_QDRANT_PORT];
//!   modules=[adapters::postgres, adapters::quota_repo, adapters::tests::support::operation_receipt_fixture,
//!   application::retrieval_embedding_port, contracts::retrieval_config, domain::context, domain::dataclass,
//!   domain::error, domain::identity, gateway::context, gateway::guard, gateway::mcp_application, gateway::recall,
//!   gateway::remember, humaux-testkit, infra-cell::resource, infra-cell::transport, protocol::edge, protocol::mcp,
//!   protocol::mcp_catalog]
//! Called-by: [cargo-test]
//! Invariants: [two real fixture tenants, the foreign one owning a memory, a workspace, a task and a continuity
//!   project that the caller's tenant then names; the caller is a real service credential of its own tenant through
//!   one in-process gateway over loopback MCP; "identical" is a byte comparison of status and body after the probed
//!   ids are masked, against a request naming ids that exist in no tenant; the caller's own data is the positive
//!   control, so an op that returns nothing cannot pass]
//! Spec: Baseline §6.1.1; §6.1.2; §6.2.3; DOD-023
//!
//! Fault this gate is built for (module design M08 §8 G-M08-3): a read SQL that stops binding the caller's tenant
//! answers a foreign id differently from an absent one. RLS stays behind every such predicate (defense in depth,
//! migration 0012), so the fault is only visible where RLS is not in the path or is also absent.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use humaux_adapters::{postgres::RuntimeDbPool, quota_repo::RatePolicy};
use humaux_application::retrieval_embedding_port::{
    RetrievalEmbeddingInput, RetrievalEmbeddingOutcome, RetrievalEmbeddingPort,
};
use humaux_domain::{
    context::ContextBudget, dataclass::DataClass, error::ErrorCode, identity::VisibilityClass,
};
use humaux_gateway::{
    context::ContextBootstrap,
    guard::{GatewayGuard, GuardRatePolicies, GuardSettings},
    mcp_application::GatewayMcpApplication,
    recall::{SemanticRecallRuntime, SemanticRecallVersions},
    remember::{ProcessFamily, RememberEventKind, RememberPolicy},
};
use humaux_infra_cell::{
    CallerId, CellId, DEFAULT_MAX_RESPONSE_BYTES, HttpIntraCellTransport, IntraCellResource,
    IntraCellResourceRegistry, ResourceEntry,
};
use humaux_protocol::{
    edge::{TrustedProxyConfig, compute_api_key_hash},
    mcp::{McpAdapter, McpHttpConfig},
    mcp_catalog::CanonicalCatalog,
};
use humaux_testkit::run_db_fixture;
use postgres::{Client, GenericClient};
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
const DIMENSION: u32 = 4;
/// Only the foreign tenant's memory carries this text; no response to the caller may.
const FOREIGN_LITERAL: &str = "foreign-canary-text-3b7e";
/// Only the caller's own memory carries this text.
const OWN_LITERAL: &str = "own-canary-text-81c2";

// ----------------------------------------------------------------------------------------------
// One in-process gateway (the read_decoupling harness, with the semantic lane wired but never reached)
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

/// The embedding seam; the caller's family is unserved, so recall must never reach it.
struct CountingPort {
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl RetrievalEmbeddingPort for CountingPort {
    async fn embed_query(
        &self,
        _input: RetrievalEmbeddingInput<'_>,
    ) -> Result<RetrievalEmbeddingOutcome, ErrorCode> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(RetrievalEmbeddingOutcome::Embedded {
            vector: vec![0.5; DIMENSION as usize],
            provider_id: "cross-tenant-canary".to_owned(),
            model_id: "counting-port".to_owned(),
            model_revision: "v1".to_owned(),
            dimension: DIMENSION,
        })
    }
}

fn qdrant_registry() -> IntraCellResourceRegistry {
    let cell = CellId(Uuid::now_v7());
    let caller = CallerId("gateway-cross-tenant-canary".to_owned());
    let port = std::env::var("HUMAUX_TEST_QDRANT_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6333);
    let mut entries = BTreeMap::new();
    entries.insert(
        IntraCellResource::QDRANT_REST,
        ResourceEntry::new(
            "127.0.0.1",
            port,
            cell,
            vec!["127.0.0.1/32".parse().expect("loopback CIDR")],
            BTreeSet::from([caller.clone()]),
            false,
        )
        .expect("loopback Qdrant resource"),
    );
    IntraCellResourceRegistry::new(entries, cell, caller)
}

fn application(handle: &Handle) -> (GatewayMcpApplication, Arc<CountingPort>) {
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
    let registry = qdrant_registry();
    let transport = Arc::new(
        HttpIntraCellTransport::new(
            registry.clone(),
            Duration::from_secs(10),
            DEFAULT_MAX_RESPONSE_BYTES,
        )
        .expect("Qdrant transport"),
    );
    let port = Arc::new(CountingPort {
        calls: AtomicUsize::new(0),
    });
    let semantic = SemanticRecallRuntime::new(
        port.clone(),
        transport,
        registry,
        SemanticRecallVersions {
            embedding_version: "embed-v1".to_owned(),
            dimension: DIMENSION,
        },
        Duration::from_secs(10),
    )
    .expect("semantic runtime");
    let app = GatewayMcpApplication::new(
        CanonicalCatalog::load().expect("closed canonical MCP catalog"),
        guard(runtime),
        policy,
        RememberEventKind::UserMessage,
        bootstrap,
    )
    .with_confirm_token_ttl(Duration::from_secs(300))
    .expect("positive confirm-token TTL")
    .with_undo_window(Duration::from_secs(86_400))
    .expect("positive undo window")
    .with_mood_half_life(Duration::from_secs(21_600))
    .expect("positive mood half-life")
    .with_enumeration(Duration::from_secs(900), 1000)
    .expect("positive enumeration policy")
    .with_semantic_recall(semantic);
    (app, port)
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

/// One `tools/call`: the HTTP status and the JSON body (the raw text when it is not JSON).
async fn call(address: SocketAddr, tool: &str, bearer: &str, arguments: Value) -> (u16, Value) {
    let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
    "name": tool, "arguments": arguments, "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "cross-tenant-canary", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }}})
    .to_string();
    // dep: HTTP(gateway) — the test dials the in-process gateway's loopback listener
    let mut stream = TcpStream::connect(address).await.expect("connect gateway");
    let request = format!(
        "POST /mcp HTTP/1.1\r\nConnection: close\r\nAccept: application/json, text/event-stream\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nHost: {HOST}\r\nOrigin: {ORIGIN}\r\n\
         MCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: {tool}\r\n\
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

// ----------------------------------------------------------------------------------------------
// Seeds
// ----------------------------------------------------------------------------------------------

fn set_context(
    client: &mut impl GenericClient,
    tenant: Uuid,
    workspace: Uuid,
    principal: Uuid,
    user: Uuid,
) {
    client
        .query_one(
            "SELECT set_config('humaux.tenant_id',$1,true), set_config('humaux.workspace_id',$2,true), \
                    set_config('humaux.principal_id',$3,true), set_config('humaux.user_id',$4,true)",
            &[
                &tenant.to_string(),
                &workspace.to_string(),
                &principal.to_string(),
                &user.to_string(),
            ],
        )
        .expect("set continuity context");
}

/// Registers `project` for the handle's tenant through the production function, as a real gateway login.
fn register_project(handle: &Handle, project: Uuid) {
    let mut client: Client = handle.gateway_client().expect("role_gateway login");
    client.batch_execute("BEGIN").expect("begin");
    set_context(
        &mut client,
        handle.tenant_id,
        handle.workspace_id,
        handle.principal_id,
        handle.user_id,
    );
    client
        .query_one(
            "SELECT private.register_continuity_project($1,$2,$3,$4,$5,'canary')",
            &[
                &handle.tenant_id,
                &handle.workspace_id,
                &project,
                &handle.principal_id,
                &Some(handle.user_id),
            ],
        )
        .expect("register continuity project");
    client.batch_execute("COMMIT").expect("commit");
}

/// Publishes a GOAL facet sourced from `memory`, so the project reads as a real, populated continuity.
fn publish_goal(handle: &mut Handle, project: Uuid, memory: Uuid) {
    let hash: Vec<u8> = handle
        .admin
        .query_one(
            "SELECT sha256(convert_to(content::text,'UTF8')) FROM private.memory_records \
             WHERE tenant_id=$1 AND memory_id=$2",
            &[&handle.tenant_id, &memory],
        )
        .expect("memory content hash")
        .get(0);
    let mut client: Client = handle.gateway_client().expect("role_gateway login");
    client.batch_execute("BEGIN").expect("begin");
    set_context(
        &mut client,
        handle.tenant_id,
        handle.workspace_id,
        handle.principal_id,
        handle.user_id,
    );
    client
        .query_one(
            "SELECT facet_version_id FROM private.publish_continuity_facet(\
               $1,$2,$3,$4,$5,'GOAL',0,'CURRENT',$6,$7,$8,$9,$10)",
            &[
                &handle.tenant_id,
                &handle.workspace_id,
                &project,
                &handle.principal_id,
                &Some(handle.user_id),
                &json!({"goal":"canary continuity"}),
                &vec![memory],
                &vec![hash],
                &Vec::<Uuid>::new(),
                &Vec::<Vec<u8>>::new(),
            ],
        )
        .expect("publish goal facet");
    client.batch_execute("COMMIT").expect("commit");
}

fn set_text(handle: &mut Handle, memory_id: Uuid, text: &str) {
    handle
        .admin
        .execute(
            "UPDATE private.memory_records SET content = $2 WHERE memory_id = $1",
            &[&memory_id, &json!({"title": text, "key_claim": text})],
        )
        .expect("owner sets the fixture memory text");
}

/// What the foreign tenant owns and the caller will name.
struct Foreign {
    memory: Uuid,
    workspace: Uuid,
    task: Uuid,
    project: Uuid,
}

fn seed_foreign(foreign: &mut Handle) -> Foreign {
    let memory = foreign.seed_workspace_visible_context_record().memory_id;
    set_text(foreign, memory, FOREIGN_LITERAL);
    let task: Uuid = foreign
        .admin
        .query_one(
            "INSERT INTO coord.tasks(tenant_id,title) VALUES($1,'foreign canary task') RETURNING task_id",
            &[&foreign.tenant_id],
        )
        .expect("owner seeds the foreign task")
        .get(0);
    let project = Uuid::now_v7();
    register_project(foreign, project);
    Foreign {
        memory,
        workspace: foreign.workspace_id,
        task,
        project,
    }
}

/// What the caller owns: the positive controls.
struct Own {
    memory: Uuid,
    workspace: Uuid,
    project: Uuid,
    bearer: String,
}

fn seed_own(handle: &mut Handle) -> Own {
    handle
        .admin
        .execute(
            "INSERT INTO projection.stream_checkpoints \
               (tenant_id,scope_kind,scope_id,domain,projection_kind,projection_version,serving) \
             VALUES($1,'workspace',$2,'knowledge','ingest','v1',false)",
            &[&handle.tenant_id, &handle.workspace_id],
        )
        .expect("owner seeds the caller's family checkpoint");
    let prefix = format!("xt{}", &Uuid::now_v7().simple().to_string()[..12]);
    let wire = format!("{prefix}.{}", "c".repeat(32));
    let credential = handle.seed_synthetic_service_credential_and_window(
        SyntheticCredentialScopes::RememberWriteAndContextRead,
        &prefix,
        &wire,
        &compute_api_key_hash(SYNTHETIC_CREDENTIAL_PEPPER, &wire),
        400,
    );
    let memory = handle.seed_workspace_visible_context_record().memory_id;
    set_text(handle, memory, OWN_LITERAL);
    let project = Uuid::now_v7();
    register_project(handle, project);
    publish_goal(handle, project, memory);
    Own {
        memory,
        workspace: handle.workspace_id,
        project,
        bearer: credential.bearer,
    }
}

// ----------------------------------------------------------------------------------------------
// Assertions
// ----------------------------------------------------------------------------------------------

/// Status and body with every probed id masked, so only the shape of the answer is compared.
fn masked(response: &(u16, Value), ids: &[Uuid]) -> (u16, String) {
    let mut wire = response.1.to_string();
    for id in ids {
        wire = wire.replace(&id.to_string(), "<id>");
    }
    (response.0, wire)
}

fn tool_error_code(response: &(u16, Value)) -> Option<&str> {
    let result = &response.1["result"];
    (result["isError"] == true)
        .then(|| result["structuredContent"]["code"].as_str())
        .flatten()
}

/// The caller names `foreign_args` (another tenant's real id) and `absent_args` (an id that exists nowhere); the two
/// answers must be the same status and the same body, must not carry anything the foreign tenant owns, and must be
/// the refusal `expected_status`/`expected_code` names.
#[allow(clippy::too_many_arguments)] // one comparison: the call, both argument sets, the masked ids and the expected refusal
async fn assert_foreign_is_absent(
    address: SocketAddr,
    bearer: &str,
    tool: &str,
    label: &str,
    foreign_args: Value,
    absent_args: Value,
    probed: &[Uuid],
    expected_status: u16,
    expected_code: Option<&str>,
) {
    let foreign = call(address, tool, bearer, foreign_args).await;
    let absent = call(address, tool, bearer, absent_args).await;
    assert_eq!(
        foreign.0, expected_status,
        "{label}: foreign status: {}",
        foreign.1
    );
    assert_eq!(
        masked(&foreign, probed),
        masked(&absent, probed),
        "{label}: a foreign id must answer exactly as an absent one"
    );
    if let Some(code) = expected_code {
        assert_eq!(
            tool_error_code(&foreign),
            Some(code),
            "{label}: {}",
            foreign.1
        );
    }
    let wire = foreign.1.to_string();
    assert!(
        !wire.contains(FOREIGN_LITERAL),
        "{label}: the foreign tenant's text reached the caller: {wire}"
    );
}

fn structured(response: &(u16, Value)) -> &Value {
    assert_eq!(response.0, 200, "{}", response.1);
    assert_ne!(response.1["result"]["isError"], true, "{}", response.1);
    &response.1["result"]["structuredContent"]
}

#[test]
#[allow(clippy::too_many_lines)] // one seeded pair of tenants, every read op against it
fn foreign_tenant_ids_answer_like_absent_ones_on_every_read_op_and_totals_are_zero() {
    run_db_fixture::<Fixture, _>("cross_tenant_canary_foreign", |mut foreign_handle| {
        let foreign = seed_foreign(&mut foreign_handle);
        run_db_fixture::<Fixture, _>("cross_tenant_canary", |mut handle| {
            let own = seed_own(&mut handle);
            let (app, embedding) = application(&handle);
            let absent_memory = Uuid::now_v7();
            let absent_workspace = Uuid::now_v7();
            let absent_task = Uuid::now_v7();
            let absent_project = Uuid::now_v7();
            let probed = [
                foreign.memory,
                foreign.workspace,
                foreign.task,
                foreign.project,
                absent_memory,
                absent_workspace,
                absent_task,
                absent_project,
            ];
            handle.rt.block_on(async {
                let (address, server) = start(app).await;
                let bearer = own.bearer.as_str();

                // Positive controls first: every op answers the caller's own data, so a refusal below is not an op
                // that is broken for everyone.
                let got = call(
                    address,
                    "memory",
                    bearer,
                    json!({"action":"get","memory_id":own.memory,"workspace_id":own.workspace}),
                )
                .await;
                assert_eq!(
                    structured(&got)["items"][0]["memory_id"],
                    own.memory.to_string(),
                    "control memory.get: {}",
                    got.1
                );
                let enumerated = call(
                    address,
                    "memory",
                    bearer,
                    json!({"action":"enumerate","workspace_id":own.workspace,"limit":100}),
                )
                .await;
                let wire = enumerated.1.to_string();
                assert_eq!(enumerated.0, 200, "control memory.enumerate: {wire}");
                assert!(
                    wire.contains(&own.memory.to_string()),
                    "control memory.enumerate lists the caller's memory: {wire}"
                );
                let own_grep = call(
                    address,
                    "memory",
                    bearer,
                    json!({"action":"grep","pattern":OWN_LITERAL,"workspace_id":own.workspace}),
                )
                .await;
                assert_eq!(
                    structured(&own_grep)["total_memories"], 1,
                    "control memory.grep finds the caller's text: {}",
                    own_grep.1
                );
                let context = call(
                    address,
                    "context",
                    bearer,
                    json!({"workspace_id":own.workspace}),
                )
                .await;
                assert_eq!(context.0, 200, "control context.assemble: {}", context.1);
                assert!(
                    context.1.to_string().contains(&own.memory.to_string()),
                    "control context.assemble carries the caller's memory: {}",
                    context.1
                );
                let continuity = call(
                    address,
                    "continuity",
                    bearer,
                    json!({"project_id":own.project}),
                )
                .await;
                assert_ne!(
                    continuity.1["result"]["isError"], true,
                    "control continuity.get: {}",
                    continuity.1
                );

                // The canary: the foreign tenant's real ids against the caller's own workspace (object ops) or by
                // workspace (scope ops), each against an id that exists nowhere.
                assert_foreign_is_absent(
                    address,
                    bearer,
                    "memory",
                    "memory.get foreign memory id",
                    json!({"action":"get","memory_id":foreign.memory,"workspace_id":own.workspace}),
                    json!({"action":"get","memory_id":absent_memory,"workspace_id":own.workspace}),
                    &probed,
                    200,
                    Some("NOT_FOUND"),
                )
                .await;
                assert_foreign_is_absent(
                    address,
                    bearer,
                    "memory",
                    "memory.get foreign workspace",
                    json!({"action":"get","memory_id":foreign.memory,"workspace_id":foreign.workspace}),
                    json!({"action":"get","memory_id":absent_memory,"workspace_id":absent_workspace}),
                    &probed,
                    403,
                    None,
                )
                .await;
                assert_foreign_is_absent(
                    address,
                    bearer,
                    "memory",
                    "memory.enumerate foreign workspace",
                    json!({"action":"enumerate","workspace_id":foreign.workspace,"limit":100}),
                    json!({"action":"enumerate","workspace_id":absent_workspace,"limit":100}),
                    &probed,
                    403,
                    None,
                )
                .await;
                assert_foreign_is_absent(
                    address,
                    bearer,
                    "memory",
                    "memory.grep foreign workspace",
                    json!({"action":"grep","pattern":FOREIGN_LITERAL,"workspace_id":foreign.workspace}),
                    json!({"action":"grep","pattern":FOREIGN_LITERAL,"workspace_id":absent_workspace}),
                    &probed,
                    403,
                    None,
                )
                .await;
                assert_foreign_is_absent(
                    address,
                    bearer,
                    "recall",
                    "recall foreign workspace",
                    json!({"query":FOREIGN_LITERAL,"workspace_id":foreign.workspace,"mode":"semantic"}),
                    json!({"query":FOREIGN_LITERAL,"workspace_id":absent_workspace,"mode":"semantic"}),
                    &probed,
                    403,
                    None,
                )
                .await;
                assert_foreign_is_absent(
                    address,
                    bearer,
                    "context",
                    "context.assemble foreign workspace",
                    json!({"workspace_id":foreign.workspace}),
                    json!({"workspace_id":absent_workspace}),
                    &probed,
                    403,
                    None,
                )
                .await;
                assert_foreign_is_absent(
                    address,
                    bearer,
                    "context",
                    "context.assemble foreign task id",
                    json!({"workspace_id":own.workspace,"task_id":foreign.task}),
                    json!({"workspace_id":own.workspace,"task_id":absent_task}),
                    &probed,
                    200,
                    Some("NOT_FOUND"),
                )
                .await;
                assert_foreign_is_absent(
                    address,
                    bearer,
                    "continuity",
                    "continuity.get foreign project id",
                    json!({"project_id":foreign.project}),
                    json!({"project_id":absent_project}),
                    &probed,
                    200,
                    Some("NOT_FOUND"),
                )
                .await;
                assert_foreign_is_absent(
                    address,
                    bearer,
                    "continuity",
                    "continuity.get foreign project in its own workspace",
                    json!({"project_id":foreign.project,"workspace_id":foreign.workspace}),
                    json!({"project_id":absent_project,"workspace_id":absent_workspace}),
                    &probed,
                    200,
                    Some("NOT_FOUND"),
                )
                .await;

                // Totals: the caller's own workspace never counts or lists the foreign tenant's data.
                let foreign_grep = call(
                    address,
                    "memory",
                    bearer,
                    json!({"action":"grep","pattern":FOREIGN_LITERAL,"workspace_id":own.workspace}),
                )
                .await;
                let page = structured(&foreign_grep);
                assert_eq!(page["total_matching_lines"], 0, "{}", foreign_grep.1);
                assert_eq!(page["total_memories"], 0, "{}", foreign_grep.1);
                assert_eq!(page["items"], json!([]), "{}", foreign_grep.1);
                let wire = enumerated.1.to_string();
                for owned in [
                    foreign.memory.to_string(),
                    foreign.workspace.to_string(),
                    FOREIGN_LITERAL.to_owned(),
                ] {
                    assert!(
                        !wire.contains(&owned),
                        "memory.enumerate leaked a foreign value {owned}: {wire}"
                    );
                    assert!(
                        !context.1.to_string().contains(&owned),
                        "context.assemble leaked a foreign value {owned}"
                    );
                }
                let recalled = call(
                    address,
                    "recall",
                    bearer,
                    json!({"query":FOREIGN_LITERAL,"workspace_id":own.workspace,"mode":"semantic"}),
                )
                .await;
                assert_eq!(recalled.0, 200, "{}", recalled.1);
                assert!(
                    !recalled.1.to_string().contains(FOREIGN_LITERAL),
                    "recall leaked the foreign text: {}",
                    recalled.1
                );
                assert_eq!(
                    recalled.1["result"]["structuredContent"]["items"],
                    json!([]),
                    "recall of another tenant's text lists nothing: {}",
                    recalled.1
                );
                assert_eq!(
                    embedding.calls.load(Ordering::SeqCst),
                    0,
                    "an unserved family never embeds"
                );
                server.abort();
            });
        });
    });
}
