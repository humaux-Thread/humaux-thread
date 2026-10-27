//! `gateway::tests::memory_get_frontier` — M13-2 / ADR-0110 D-A: `memory.get` reports the ledger frontier from the
//!   `stream_checkpoints` row alone (G-M13-1, G-M13-2).
//! Depends-on: crates=[async-trait, axum, humaux-adapters, humaux-application, humaux-contracts, humaux-domain,
//!   humaux-infra-cell, humaux-projection, humaux-protocol, humaux-testkit, postgres, serde_json, tokio, uuid];
//!   services=[HTTP(gateway), PostgreSQL(owner) r=[ops.commit_seq_seq]
//!   w=[control.memberships, control.private_reasoning_domains, control.tenants, control.users,
//!   control.workspace_memberships, control.workspaces, private.evidence_objects, private.memory_evidence,
//!   private.memory_records, projection.stream_checkpoints, projection.stream_log, projection.tenant_placements]
//!   x=[projection.stream_point_ledger], PostgreSQL(role_gateway), Qdrant(*)]; env=[HUMAUX_TEST_PG_DSN, HUMAUX_TEST_QDRANT_PORT];
//!   modules=[adapters::postgres, adapters::read_gate, adapters::stream_repo,
//!   adapters::tests::support::operation_receipt_fixture, adapters::tests::support::throwaway_db,
//!   application::retrieval_embedding_port, contracts::retrieval_config, domain::authority, domain::context,
//!   domain::dataclass, domain::error, domain::identity, domain::ids, gateway::context, gateway::guard,
//!   gateway::limiter, gateway::mcp_application, gateway::recall, gateway::remember, humaux-testkit,
//!   infra-cell::permit, infra-cell::resource, infra-cell::transport, projection::serving, projection::stream,
//!   protocol::edge, protocol::mcp, protocol::mcp_catalog]
//! Called-by: [cargo-test]
//! Invariants: [the door tests run in their own throwaway database because they REVOKE every right of role_gateway on
//!   `projection.stream_log` and EXECUTE on `projection.stream_point_ledger`: a `memory.get` that closed the ledger
//!   would fail with permission denied, which proves the O(1) claim by construction (the closure door, run first as a
//!   control and again after the revoke, has teeth); the MCP tests run against the isolated operation-receipt fixture
//!   tenant with a counting Qdrant transport, so "no Qdrant count" is an observed zero and a positive control (a recall
//!   on the same app) proves the spy sees traffic; no DSN or unreachable DB is a visible SKIP]
//! Spec: Baseline §15.5; §23.1; §23.3; §79.2; ADR-0110 D-A
//!
//! G-M13-1: get succeeds with `stream_log` unreadable, returns the frontier block, and takes no Qdrant count.
//! G-M13-2: a stream with no checkpoint row is `projection: null` with `projection_reason: "no_checkpoint"`, never a
//! zero frontier. Recall's `pipeline.projection` stays the closure block.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use humaux_adapters::{
    postgres::RuntimeDbPool,
    read_gate::{
        MaterializedMemory, MemoryGetTarget, frontier_pipeline_block,
        materialize_memory_get_frontier_target, materialize_memory_get_target,
    },
    stream_repo::Frontier,
};
use humaux_application::retrieval_embedding_port::{
    RetrievalEmbeddingInput, RetrievalEmbeddingOutcome, RetrievalEmbeddingPort,
};
use humaux_domain::{
    authority::MemoryId,
    context::ContextBudget,
    dataclass::DataClass,
    error::ErrorCode,
    identity::{AuthorizationScope, BoundedSet, PrincipalId, VisibilityClass},
    ids::{Scope, TenantId, UserId, WorkspaceId},
};
use humaux_gateway::{
    context::ContextBootstrap,
    guard::{GatewayGuard, GuardRatePolicies, GuardSettings},
    limiter::RatePolicy,
    mcp_application::GatewayMcpApplication,
    recall::{SemanticRecallRuntime, SemanticRecallVersions},
    remember::{ProcessFamily, RememberEventKind, RememberPolicy},
};
use humaux_infra_cell::{
    CallerId, CellAccessPermit, CellId, DEFAULT_MAX_RESPONSE_BYTES, HttpIntraCellTransport,
    IntraCellError, IntraCellHttpTransport, IntraCellRequest, IntraCellResource,
    IntraCellResourceRegistry, IntraCellResponse, ResourceEntry,
};
use humaux_projection::{serving::StreamFamily, stream::StreamKey};
use humaux_protocol::{
    edge::{TrustedProxyConfig, compute_api_key_hash},
    mcp::{McpAdapter, McpHttpConfig, ToolName},
    mcp_catalog::CanonicalCatalog,
};
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use uuid::Uuid;

#[allow(dead_code)]
#[path = "../../../crates/adapters/tests/support/throwaway_db.rs"]
mod throwaway_db;
use throwaway_db::ThrowawayDb;

#[allow(dead_code)]
#[path = "../../../crates/adapters/tests/support/operation_receipt_fixture.rs"]
mod operation_receipt_fixture;
use operation_receipt_fixture::{
    Fixture, Handle, SYNTHETIC_CREDENTIAL_PEPPER, SyntheticCredentialScopes,
};

const HOST: &str = "mcp.test";
const ORIGIN: &str = "https://mcp.test";
const DIMENSION: u32 = 4;
const QUERY: &str = "frontier reading scoped context";

// ----------------------------------------------------------------------------------------------
// Door level: a throwaway database, role_gateway, stream_log revoked
// ----------------------------------------------------------------------------------------------

/// The identities of the one seeded tenant tree.
struct Ids {
    tenant: Uuid,
    user: Uuid,
    workspace: Uuid,
    domain: Uuid,
    memory: Uuid,
}

struct DoorHandle {
    rt: tokio::runtime::Runtime,
    gateway: RuntimeDbPool,
    admin: Client,
    ids: Ids,
    /// Dropped last: it drops the whole database.
    _db: ThrowawayDb,
}

struct DoorFixture;

impl DbIntegrationFixture for DoorFixture {
    type Handle = DoorHandle;

    fn isolate() -> Result<DoorHandle, DbFixtureSkipReason> {
        let db = throwaway_db::create("m13_get_frontier")?;
        let dsn = db.dsn();
        // dep: PostgreSQL(owner) — test opens a direct PG connection for setup/verification
        let mut admin = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        let mut ids = Ids {
            tenant: Uuid::new_v4(),
            user: Uuid::new_v4(),
            workspace: Uuid::new_v4(),
            domain: Uuid::new_v4(),
            memory: Uuid::nil(),
        };
        ids.memory = seed_memory_tree(&mut admin, &ids)
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        let sep = if dsn.contains('?') { '&' } else { '?' };
        let gateway = rt
            // dep: PostgreSQL(role_gateway) — the role `memory.get` runs as
            .block_on(RuntimeDbPool::connect(&format!(
                "{dsn}{sep}options=-c%20role%3Drole_gateway"
            )))
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        Ok(DoorHandle {
            rt,
            gateway,
            admin,
            ids,
            _db: db,
        })
    }
}

/// One tenant, user, workspace (user is a member), reasoning domain and one WORKSPACE_SHARED Memory with its evidence;
/// the same rows the shared operation-receipt fixture plants. Deliberately no checkpoint row: each test decides.
fn seed_memory_tree(admin: &mut Client, ids: &Ids) -> Result<Uuid, postgres::Error> {
    let mut txn = admin.transaction()?;
    txn.execute(
        "INSERT INTO control.tenants(tenant_id,name,state) VALUES($1,'m13-2 get frontier','ACTIVE')",
        &[&ids.tenant],
    )?;
    txn.execute(
        "INSERT INTO control.users(user_id,state) VALUES($1,'ACTIVE')",
        &[&ids.user],
    )?;
    txn.execute(
        "INSERT INTO control.memberships(tenant_id,user_id,role,state) VALUES($1,$2,'member','ACTIVE')",
        &[&ids.tenant, &ids.user],
    )?;
    txn.execute(
        "INSERT INTO control.workspaces(workspace_id,tenant_id,name) VALUES($1,$2,'m13-2 workspace')",
        &[&ids.workspace, &ids.tenant],
    )?;
    txn.execute(
        "INSERT INTO control.workspace_memberships(tenant_id,workspace_id,user_id,role,state) \
         VALUES($1,$2,$3,'MEMBER','ACTIVE')",
        &[&ids.tenant, &ids.workspace, &ids.user],
    )?;
    txn.execute(
        "INSERT INTO control.private_reasoning_domains(reasoning_domain_id,tenant_id,name) VALUES($1,$2,'default')",
        &[&ids.domain, &ids.tenant],
    )?;
    let evidence_id: Uuid = txn
        .query_one(
            "INSERT INTO private.evidence_objects \
               (tenant_id,evidence_kind,payload_sha256,data_class,origin_class,visibility_class, \
                visibility_workspace_id,reasoning_domain_id) \
             VALUES($1,'EVENT',$2,'INTERNAL','DirectUserInput','WORKSPACE_SHARED',$3,$4) \
             RETURNING evidence_id",
            &[&ids.tenant, &vec![3_u8; 32], &ids.workspace, &ids.domain],
        )?
        .get(0);
    let confidence: f32 = 0.9;
    let memory_id: Uuid = txn
        .query_one(
            "INSERT INTO private.memory_records \
               (tenant_id,memory_type,content,visibility_class,visibility_workspace_id,authority_class, \
                confidence,status,asserted_at) \
             VALUES($1,'NOTE',$2,'WORKSPACE_SHARED',$3,'ProjectConstraint',$4,'active',clock_timestamp()) \
             RETURNING memory_id",
            &[
                &ids.tenant,
                &json!({"fixture": "m13-2 frontier reading"}),
                &ids.workspace,
                &confidence,
            ],
        )?
        .get(0);
    txn.execute(
        "INSERT INTO private.memory_evidence(memory_id,evidence_id,role,grounding_mode) \
         VALUES($1,$2,'PRIMARY','SNAPSHOT')",
        &[&memory_id, &evidence_id],
    )?;
    txn.commit()?;
    Ok(memory_id)
}

/// Three `DONE` tickets and one `ISSUED` under a checkpoint that issued four with a stored prefix of two, serving: the
/// frontier (4, 2, true) and the closure's own count (4 expected) are both readable from it, and `behind` (2) differs
/// from every number it is derived from.
fn seed_stream(admin: &mut Client, ids: &Ids) {
    admin
        .execute(
            "INSERT INTO projection.stream_checkpoints \
               (tenant_id,scope_kind,scope_id,domain,projection_kind,projection_version, \
                issued_highwater,projection_highwater,serving) \
             VALUES($1,'workspace',$2,'knowledge','ingest','v1',4,2,true)",
            &[&ids.tenant, &ids.workspace],
        )
        .expect("seed the stream_checkpoints row");
    for seq in 1..=3_i64 {
        admin
            .execute(
                "INSERT INTO projection.stream_log \
                   (tenant_id,scope_kind,scope_id,domain,projection_kind,projection_version, \
                    stream_seq,commit_seq,state,settled_at) \
                 VALUES($1,'workspace',$2,'knowledge','ingest','v1',$3,$3,'DONE',clock_timestamp())",
                &[&ids.tenant, &ids.workspace, &seq],
            )
            .expect("seed a DONE stream_log row");
    }
    admin
        .execute(
            "INSERT INTO projection.stream_log \
               (tenant_id,scope_kind,scope_id,domain,projection_kind,projection_version, \
                stream_seq,commit_seq,state) \
             VALUES($1,'workspace',$2,'knowledge','ingest','v1',4,4,'ISSUED')",
            &[&ids.tenant, &ids.workspace],
        )
        .expect("seed the ISSUED stream_log row");
}

/// Takes every right on the O(stream) closure's two sources away from `role_gateway` and proves it took.
fn revoke_closure_sources(admin: &mut Client) {
    admin
        .batch_execute(
            "REVOKE ALL ON projection.stream_log FROM role_gateway; \
             REVOKE EXECUTE ON FUNCTION \
               projection.stream_point_ledger(uuid,text,uuid,text,text,text,text,uuid[]) \
             FROM role_gateway",
        )
        .expect("revoke stream_log and stream_point_ledger from role_gateway");
    let table_revoked: bool = admin
        .query_one(
            "SELECT NOT has_any_column_privilege('role_gateway', 'projection.stream_log', 'SELECT')",
            &[],
        )
        .expect("privilege probe")
        .get(0);
    assert!(
        table_revoked,
        "precondition: role_gateway cannot read stream_log any more"
    );
    let function_revoked: bool = admin
        .query_one(
            "SELECT NOT has_function_privilege('role_gateway', \
               'projection.stream_point_ledger(uuid,text,uuid,text,text,text,text,uuid[])', 'EXECUTE')",
            &[],
        )
        .expect("function privilege probe")
        .get(0);
    assert!(
        function_revoked,
        "precondition: role_gateway cannot execute stream_point_ledger any more"
    );
}

impl DoorHandle {
    fn auth(&self) -> AuthorizationScope {
        AuthorizationScope::new(
            TenantId(self.ids.tenant),
            PrincipalId(self.ids.user),
            Some(UserId(self.ids.user)),
            BoundedSet::new([WorkspaceId(self.ids.workspace)]).expect("one workspace"),
        )
    }

    fn scope(&self) -> Scope {
        Scope {
            tenant_id: TenantId(self.ids.tenant),
            user_id: Some(UserId(self.ids.user)),
            workspace_id: Some(WorkspaceId(self.ids.workspace)),
            repository_id: None,
            task_id: None,
            run_id: None,
            agent_id: None,
        }
    }

    fn family(&self) -> StreamFamily {
        StreamFamily::new(
            TenantId(self.ids.tenant),
            "workspace",
            self.ids.workspace,
            "knowledge",
            "ingest",
        )
    }

    fn key(&self) -> StreamKey {
        self.family().with_version("v1")
    }

    /// The door `memory.get` uses (ADR-0110 D-A).
    fn frontier_read(&self) -> Result<MaterializedMemory<Option<Frontier>>, ErrorCode> {
        self.rt.block_on(materialize_memory_get_frontier_target(
            &self.gateway,
            &self.auth(),
            &self.scope(),
            &self.family(),
            &self.key(),
            MemoryGetTarget::Memory(MemoryId(self.ids.memory)),
            false,
        ))
    }

    /// The pre-ADR-0110 door: the same snapshot plus the O(stream) closure.
    fn closure_read(&self) -> Result<MaterializedMemory, ErrorCode> {
        self.rt.block_on(materialize_memory_get_target(
            &self.gateway,
            &self.auth(),
            &self.scope(),
            &self.family(),
            &self.key(),
            MemoryGetTarget::Memory(MemoryId(self.ids.memory)),
            false,
        ))
    }
}

/// The wire form of the `pipeline` a frontier read becomes.
fn pipeline_json(frontier: Option<Frontier>) -> Value {
    let pipeline = frontier_pipeline_block(frontier).expect("pipeline block");
    serde_json::to_value(pipeline).expect("pipeline serializes")
}

/// G-M13-1: with every right on `stream_log` and the point ledger revoked from `role_gateway`, the closure door is
/// denied while the frontier door still returns the Memory and the checkpoint's numbers; `behind` follows the row.
#[test]
fn get_frontier_door_needs_neither_stream_log_nor_the_point_ledger() {
    run_db_fixture::<DoorFixture, _>(
        "get_frontier_door_needs_neither_stream_log_nor_the_point_ledger",
        |mut h| {
            seed_stream(&mut h.admin, &h.ids);
            // Control: before the revoke the closure door works, and counts the four tickets.
            let before = h.closure_read().expect("closure door before the revoke");
            assert_eq!(before.ledger.counts().expected(), 4);

            revoke_closure_sources(&mut h.admin);
            let denied = h.closure_read();
            assert!(
                matches!(denied, Err(ErrorCode::DependencyUnavailable)),
                "the closure needs stream_log, so the revoke has teeth: {:?}",
                denied.as_ref().err()
            );

            let read = h
                .frontier_read()
                .expect("the frontier door must not need stream_log or stream_point_ledger");
            assert_eq!(read.bodies.items.len(), 1, "the Memory is still returned");
            let frontier = read.ledger.expect("the checkpoint row exists");
            assert_eq!(
                (frontier.issued_hw, frontier.projection_hw, frontier.serving),
                (4, 2, true)
            );
            let pipeline = pipeline_json(Some(frontier));
            let projection = &pipeline["projection"];
            assert_eq!(projection["mode"], "frontier", "{pipeline}");
            assert_eq!(projection["issued"], 4, "{pipeline}");
            assert_eq!(projection["settled_prefix"], 2, "{pipeline}");
            assert_eq!(
                projection["behind"], 2,
                "behind = issued - prefix: {pipeline}"
            );
            assert_eq!(projection["serving"], true, "{pipeline}");
            assert_eq!(pipeline["projection_reason"], Value::Null, "{pipeline}");

            // `behind` is derived from the row, not a constant: three DONE tickets settled the prefix to 3.
            h.admin
                .execute(
                    "UPDATE projection.stream_checkpoints SET projection_highwater = 3 \
                     WHERE tenant_id = $1 AND scope_id = $2",
                    &[&h.ids.tenant, &h.ids.workspace],
                )
                .expect("advance the stored prefix");
            let advanced = h.frontier_read().expect("frontier after the advance");
            let pipeline = pipeline_json(advanced.ledger);
            assert_eq!(pipeline["projection"]["settled_prefix"], 3, "{pipeline}");
            assert_eq!(pipeline["projection"]["behind"], 1, "{pipeline}");
        },
    );
}

/// G-M13-2: a stream that never issued a ticket has no checkpoint row. The door answers `None` and the pipeline says
/// `projection: null` with `no_checkpoint`; the same Memory read after a row exists carries a frontier and no reason.
#[test]
fn a_row_less_stream_is_null_with_no_checkpoint_never_a_zero_frontier() {
    run_db_fixture::<DoorFixture, _>(
        "a_row_less_stream_is_null_with_no_checkpoint_never_a_zero_frontier",
        |mut h| {
            let read = h.frontier_read().expect("a get on a row-less stream");
            assert_eq!(read.bodies.items.len(), 1, "the Memory is still returned");
            assert_eq!(read.ledger, None, "no checkpoint row, no frontier");
            let pipeline = pipeline_json(read.ledger);
            assert_eq!(pipeline["projection"], Value::Null, "{pipeline}");
            assert_eq!(pipeline["projection_reason"], "no_checkpoint", "{pipeline}");

            // Positive control: a row flips both fields, so the null above is the absence and not a fixed shape.
            seed_stream(&mut h.admin, &h.ids);
            let with_row = h.frontier_read().expect("a get once the row exists");
            let pipeline = pipeline_json(with_row.ledger);
            assert_eq!(pipeline["projection"]["mode"], "frontier", "{pipeline}");
            assert_eq!(pipeline["projection_reason"], Value::Null, "{pipeline}");
        },
    );
}

// ----------------------------------------------------------------------------------------------
// MCP level: one in-process gateway over the shared operation-receipt fixture
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

/// The embedding seam: a fixed vector, so a recall can reach the Qdrant transport.
struct FixedPort;

#[async_trait::async_trait]
impl RetrievalEmbeddingPort for FixedPort {
    async fn embed_query(
        &self,
        _input: RetrievalEmbeddingInput<'_>,
    ) -> Result<RetrievalEmbeddingOutcome, ErrorCode> {
        Ok(RetrievalEmbeddingOutcome::Embedded {
            vector: vec![0.5; DIMENSION as usize],
            provider_id: "memory-get-frontier-test".to_owned(),
            model_id: "fixed-port".to_owned(),
            model_revision: "v1".to_owned(),
            dimension: DIMENSION,
        })
    }
}

/// The Qdrant seam, counted: every call that reaches the inner transport is one Qdrant request. It increments before
/// the inner call, so the count does not depend on a Qdrant being up.
struct CountingTransport {
    inner: HttpIntraCellTransport,
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl IntraCellHttpTransport for CountingTransport {
    async fn execute(
        &self,
        permit: &CellAccessPermit,
        request: IntraCellRequest,
    ) -> Result<IntraCellResponse, IntraCellError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.execute(permit, request).await
    }
}

fn qdrant_registry() -> IntraCellResourceRegistry {
    let cell = CellId(Uuid::now_v7());
    let caller = CallerId("gateway-memory-get-frontier".to_owned());
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

struct Gateway {
    spy: Arc<CountingTransport>,
    app: GatewayMcpApplication,
}

fn gateway(handle: &Handle) -> Gateway {
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
    let spy = Arc::new(CountingTransport {
        inner: HttpIntraCellTransport::new(
            registry.clone(),
            Duration::from_secs(10),
            DEFAULT_MAX_RESPONSE_BYTES,
        )
        .expect("Qdrant transport"),
        calls: AtomicUsize::new(0),
    });
    let semantic = SemanticRecallRuntime::new(
        Arc::new(FixedPort),
        spy.clone(),
        registry,
        SemanticRecallVersions {
            embedding_version: "embed-v1".to_owned(),
            dimension: DIMENSION,
        },
        Duration::from_secs(10),
        None,
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
    Gateway { spy, app }
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

async fn tool_call(address: SocketAddr, tool: &str, bearer: &str, arguments: Value) -> Value {
    let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
    "name": tool, "arguments": arguments, "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "memory-get-frontier", "version": "1"},
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
    assert!(head.starts_with("HTTP/1.1 200"), "{head}\n{body}");
    serde_json::from_str(body).expect("json-rpc body")
}

/// The tool succeeded; its structured content satisfies the advertised schema.
fn ok_content(response: &Value, tool: ToolName) -> Value {
    let result = &response["result"];
    assert_ne!(result["isError"], true, "expected success: {response}");
    let value = result["structuredContent"].clone();
    CanonicalCatalog::load()
        .expect("catalog")
        .validate_output(tool, &value)
        .expect("response satisfies its advertised schema");
    value
}

/// How a seeded workspace's `(knowledge, ingest)` family looks.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    /// Checkpoint row, no serving version.
    Unserved,
    /// Checkpoint row serving `v1` (a READY family).
    Serving,
}

struct Pair {
    workspace_id: Uuid,
    bearer: String,
    memory_id: Uuid,
}

/// A second workspace of the fixture tenant with its own credential, one WORKSPACE_SHARED memory with its mandatory
/// binding, and the family's checkpoint row in `family`'s state.
fn seed_pair(handle: &mut Handle, tag: &str, family: Family) -> Pair {
    let workspace_id = handle.seed_workspace();
    let own = std::mem::replace(&mut handle.workspace_id, workspace_id);
    let prefix = format!("{tag}{}", &Uuid::now_v7().simple().to_string()[..12]);
    let wire = format!("{prefix}.{}", tag.repeat(32));
    let credential = handle.seed_synthetic_service_credential(
        SyntheticCredentialScopes::RememberWriteAndContextRead,
        &prefix,
        &wire,
        &compute_api_key_hash(SYNTHETIC_CREDENTIAL_PEPPER, &wire),
    );
    let memory_id = handle.seed_workspace_visible_context_record().memory_id;
    handle
        .admin
        .execute(
            "INSERT INTO projection.stream_checkpoints \
               (tenant_id,scope_kind,scope_id,domain,projection_kind,projection_version,serving) \
             VALUES($1,'workspace',$2,'knowledge','ingest','v1',$3)",
            &[
                &handle.tenant_id,
                &workspace_id,
                &(family == Family::Serving),
            ],
        )
        .expect("owner seeds the family checkpoint");
    handle.workspace_id = own;
    Pair {
        workspace_id,
        bearer: credential.bearer,
        memory_id,
    }
}

fn seed_placement(handle: &mut Handle, collection: &str) {
    handle
        .admin
        .execute(
            "INSERT INTO projection.tenant_placements \
               (tenant_id,projection_family,collection_name,shard_key,placement_class, \
                point_count,bytes_estimate,promotion_state) \
             VALUES ($1,'private_memory_v1',$2,NULL,'SHARED_FALLBACK',0,0,'STABLE')",
            &[&handle.tenant_id, &collection],
        )
        .expect("owner seeds the tenant placement");
}

/// Three settled tickets and one pending under the pair's checkpoint: issued 4, prefix 3, so `behind` is 1.
fn seed_issued_stream(handle: &mut Handle, pair: &Pair) {
    for seq in 1..=4_i64 {
        let commit_seq: i64 = handle
            .admin
            .query_one("SELECT nextval('ops.commit_seq_seq')", &[])
            .expect("commit sequence")
            .get(0);
        let (state, settled) = if seq < 4 {
            ("'DONE'", ",clock_timestamp()")
        } else {
            ("'ISSUED'", ",NULL")
        };
        let insert = format!(
            "INSERT INTO projection.stream_log \
               (tenant_id,scope_kind,scope_id,domain,projection_kind,projection_version, \
                stream_seq,commit_seq,state,settled_at) \
             VALUES($1,'workspace',$2,'knowledge','ingest','v1',$3,$4,{state}{settled})"
        );
        handle
            .admin
            .execute(
                insert.as_str(),
                &[&handle.tenant_id, &pair.workspace_id, &seq, &commit_seq],
            )
            .expect("seed a stream_log row");
    }
    handle
        .admin
        .execute(
            "UPDATE projection.stream_checkpoints SET issued_highwater = 4, projection_highwater = 3 \
             WHERE tenant_id = $1 AND scope_id = $2",
            &[&handle.tenant_id, &pair.workspace_id],
        )
        .expect("owner sets the checkpoint highwaters");
}

fn get_args(pair: &Pair) -> Value {
    json!({"action":"get","memory_id":pair.memory_id,"workspace_id":pair.workspace_id})
}

fn recall_args(pair: &Pair) -> Value {
    json!({"query":QUERY,"workspace_id":pair.workspace_id,"mode":"semantic"})
}

/// G-M13-1 over MCP: the frontier is exactly the checkpoint row's reading, and the same app that answers a get without
/// one Qdrant request makes one for a recall (the spy sees traffic).
#[test]
fn memory_get_over_mcp_reports_the_frontier_and_makes_no_qdrant_request() {
    run_db_fixture::<Fixture, _>(
        "memory_get_over_mcp_reports_the_frontier_and_makes_no_qdrant_request",
        |mut handle| {
            handle.seed_current_entitlement_and_window(100);
            // A placement and a serving family are what made the old get reach Qdrant for a count.
            seed_placement(&mut handle, &format!("m13_2_{}", Uuid::now_v7().simple()));
            let pair = seed_pair(&mut handle, "f", Family::Serving);
            seed_issued_stream(&mut handle, &pair);
            let gw = gateway(&handle);
            let spy = gw.spy.clone();
            handle.rt.block_on(async {
                let (address, server) = start(gw.app).await;
                let response = tool_call(address, "memory", &pair.bearer, get_args(&pair)).await;
                let content = ok_content(&response, ToolName::Memory);
                assert_eq!(
                    content["items"][0]["memory_id"],
                    pair.memory_id.to_string(),
                    "{content}"
                );
                let projection = content["pipeline"]["projection"]
                    .as_object()
                    .expect("a frontier object");
                let mut keys: Vec<&str> = projection.keys().map(String::as_str).collect();
                keys.sort_unstable();
                assert_eq!(
                    keys,
                    [
                        "behind",
                        "issued",
                        "mode",
                        "observed_at",
                        "serving",
                        "settled_prefix"
                    ],
                    "no visible, ratio or count: {content}"
                );
                assert_eq!(projection["mode"], "frontier");
                assert_eq!(projection["issued"], 4);
                assert_eq!(projection["settled_prefix"], 3);
                assert_eq!(projection["behind"], 1, "behind = issued - prefix");
                assert_eq!(projection["serving"], true);
                assert!(projection["observed_at"].is_string(), "{content}");
                assert_eq!(content["pipeline"]["projection_reason"], Value::Null);
                assert_eq!(content["completeness"]["class"], "cannot_establish");
                assert_eq!(content["completeness"]["reason"], "count_unknown");
                assert_eq!(
                    spy.calls.load(Ordering::SeqCst),
                    0,
                    "memory.get must not take a Qdrant count (ADR-0110 D-A)"
                );

                // Control: a recall on the same app does reach the transport, so the zero above is observed.
                tool_call(address, "recall", &pair.bearer, recall_args(&pair)).await;
                assert!(
                    spy.calls.load(Ordering::SeqCst) >= 1,
                    "positive control: the spy counts a recall's Qdrant request"
                );
                server.abort();
            });
        },
    );
}

/// Recall keeps the closure block: the A1/A2 keys are there and the frontier's `mode` and `behind` are not. The
/// unserved family is the deterministic B path, so no Qdrant is needed.
#[test]
fn recall_projection_stays_the_closure_block() {
    run_db_fixture::<Fixture, _>("recall_projection_stays_the_closure_block", |mut handle| {
        handle.seed_current_entitlement_and_window(100);
        seed_placement(&mut handle, "m13_2_never_dialled");
        let pair = seed_pair(&mut handle, "r", Family::Unserved);
        let gw = gateway(&handle);
        handle.rt.block_on(async {
            let (address, server) = start(gw.app).await;
            let response = tool_call(address, "recall", &pair.bearer, recall_args(&pair)).await;
            let content = ok_content(&response, ToolName::Recall);
            let projection = content["pipeline"]["projection"]
                .as_object()
                .expect("a closure object");
            for key in [
                "expected",
                "done",
                "visible",
                "completeness_ratio",
                "current",
            ] {
                assert!(projection.contains_key(key), "closure key {key}: {content}");
            }
            for key in ["mode", "behind", "settled_prefix"] {
                assert!(
                    !projection.contains_key(key),
                    "frontier key {key}: {content}"
                );
            }
            assert!(
                content["pipeline"].get("projection_reason").is_none(),
                "projection_reason is memory.get's, not recall's: {content}"
            );
            server.abort();
        });
    });
}
