//! `gateway::tests::semantic_recall_wiring` — ADR-0012/ADR-0014 gateway semantic-recall wiring acceptance.
//! Depends-on: crates=[async-trait, axum, humaux-adapters, humaux-application, humaux-contracts, humaux-domain,
//!   humaux-infra-cell, humaux-local-secret-scan, humaux-projection, humaux-protocol, humaux-retrieval-provider,
//!   humaux-retrieval-worker, humaux-testkit, postgres, serde_json, time, tokio, uuid];
//!   services=[PostgreSQL(role_gateway) r=[private.memory_records] w=[ops.retrieval_embedding_rpc_calls,
//!   ops.retrieval_query_log, projection.private_memory_points, projection.stream_checkpoints, projection.tenant_placements],
//!   PostgreSQL(role_retrieval_worker), Qdrant(*),
//!   UDS(retrieval-worker), UDS(serve)]; env=[CARGO_MANIFEST_DIR, HUMAUX_GATEWAY_PG_DSN,
//!   HUMAUX_RETRIEVAL_WORKER_PG_DSN, HUMAUX_TEST_GITLEAKS_BIN, HUMAUX_TEST_GITLEAKS_SHA256,
//!   HUMAUX_TEST_GITLEAKS_VERSION, HUMAUX_TEST_QDRANT_PORT]; modules=[adapters::postgres, adapters::qdrant,
//!   adapters::retrieve,
//!   adapters::tests::support::operation_receipt_fixture, application::retrieval_embedding_port,
//!   contracts::retrieval_config, domain::authority, domain::context, domain::dataclass, domain::error,
//!   domain::identity, domain::ids, domain::memory, gateway::context, gateway::recall, gateway::remember,
//!   gateway::retrieval_embedding_client, humaux-local-secret-scan, humaux-testkit, infra-cell::permit,
//!   infra-cell::resource, infra-cell::transport, projection::card, protocol::mcp,
//!   protocol::mcp_catalog,
//!   retrieval-provider::adapters, retrieval-provider::contract, retrieval-worker::rpc]
//! Called-by: [cargo-test]
//! Invariants: [each test wires its own PostgreSQL/Qdrant/UDS fixtures; a missing fixture fails the test rather than skipping it]
//! Spec: ADR-0012; ADR-0014; ADR-0055; ADR-0065; ADR-0081
//!
//! Drives `humaux_gateway::recall::search` directly (no HTTP/MCP layer — that surface is
//! already covered by `tests/mcp_gateway.rs`'s native MCP acceptance tests) against a real
//! `role_gateway` PostgreSQL pool, a real disposable Qdrant collection, and — for the happy
//! path — a real in-process `humaux-retrieval-worker` RPC app (mirrors
//! `tests/query_embedding_rpc.rs`'s own in-process-worker pattern). Proves: (1) the bootstrap
//! wiring card's per-tenant placement resolution actually hits; (2) a tenant with no placement
//! row degrades closed, never onto another tenant's collection; (3) a dead RPC socket degrades
//! closed without hanging or panicking; (4) `HttpIntraCellTransport` really denies a write under
//! a `QdrantReadOnly` permit (ADR-0014); (5) a wrong-dimension vector from the embedding port
//! never gets hydrated; (6) `bootstrap.rs` wires `with_semantic_recall` exactly once; (8) a
//! transient query-embedding failure fails fast after one worker call (ADR-0065 D-G); (9) the query-hash log
//! `ops.retrieval_query_log` (T-RET-1b, ADR-0081 D-A): one row per answered recall, the query only as a keyed per-tenant
//! HMAC, insert-only and tenant-isolated for `role_gateway`, and a failing insert never fails the recall.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use postgres::Client;
use uuid::Uuid;

// This test file only needs a slice of the shared fixture's surface (tenant/workspace setup,
// context-record seeding, teardown) — the rest is real, used by `tests/mcp_gateway.rs`'s own
// inclusion of the identical file, just not by this one.
#[allow(dead_code)]
#[path = "../../../crates/adapters/tests/support/operation_receipt_fixture.rs"]
mod operation_receipt_fixture;
use operation_receipt_fixture::{Fixture, Handle};

use humaux_adapters::{
    postgres::RetrievalWorkerDbPool,
    qdrant::{
        Distance, PointId, QdrantOperation, QdrantPointPayload, ShardingMethod,
        create_collection_body, ha_profile_for, tenant_index_body, upsert,
    },
};
use humaux_application::retrieval_embedding_port::{
    RetrievalEmbeddingInput, RetrievalEmbeddingOutcome, RetrievalEmbeddingPort,
};
use humaux_domain::{
    authority::{AuthorityClass, AuthorityStatus},
    dataclass::DataClass,
    error::ErrorCode,
    identity::VisibilityClass,
    ids::{TenantId, WorkspaceId},
    memory::MemoryType,
};
use humaux_gateway::{
    context::ContextBootstrap,
    recall::{self, RecallSearchRequest, SemanticRecallRuntime, SemanticRecallVersions},
    remember::{ProcessFamily, RememberPolicy},
    retrieval_embedding_client::GatewayRetrievalEmbeddingClient,
};
use humaux_infra_cell::{
    CallerId, CellAccessMode, CellAccessPermit, CellId, HttpIntraCellTransport, IntraCellError,
    IntraCellHttpTransport, IntraCellMethod, IntraCellRequest, IntraCellResource,
    IntraCellResourceRegistry, IntraCellResponse, ResourceEntry, authorize_cell_access,
};
use humaux_local_secret_scan::{LocalSecretScanner, LocalSecretScannerConfig};
use humaux_projection::card::EgressDisposition;
use humaux_protocol::mcp_catalog::CanonicalCatalog;
use humaux_retrieval_provider::{
    adapters::TestDoubleProvider,
    contract::{
        CalibrationProfileId, EmbeddingModelDescriptor, ModelId, RerankModelDescriptor,
        RerankScoreSemantics,
    },
};
use humaux_testkit::{DbIntegrationFixture, run_db_fixture};

const DIMENSION: u32 = 4;
const EMBEDDING_VERSION: &str = "embed-v1";

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing required test env {name}"))
}

fn temp_socket_path(tag: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/tmp/hsr-{tag}-{}.sock", Uuid::now_v7().simple()))
}

/// Mirrors `tests/query_embedding_rpc.rs`'s identical helper (separate test binary).
async fn own_uid() -> u32 {
    let path = temp_socket_path("uid-probe");
    // dep: UDS(serve) — test binds a probe socket to read the peer uid
    let listener = tokio::net::UnixListener::bind(&path).expect("bind uid probe socket");
    // dep: UDS(retrieval-worker) — test dials the probe socket as the retrieval-worker client would
    let client = tokio::net::UnixStream::connect(&path)
        .await
        .expect("connect uid probe");
    let (server_side, _) = listener.accept().await.expect("accept uid probe");
    let uid = server_side.peer_cred().expect("peer credential").uid();
    drop(client);
    drop(server_side);
    let _ = std::fs::remove_file(&path);
    uid
}

fn embedding_model() -> EmbeddingModelDescriptor {
    EmbeddingModelDescriptor {
        model_id: ModelId("wiring-test-embedding".to_owned()),
        model_revision: "v1".to_owned(),
        dimension_options: vec![DIMENSION],
        max_input_tokens: 4_096,
        max_batch_items: std::num::NonZeroU32::new(10).expect("non-zero cap"),
        batch_supported: true,
        dense_supported: true,
        sparse_supported: false,
    }
}

fn rerank_model() -> RerankModelDescriptor {
    RerankModelDescriptor {
        model_id: ModelId("wiring-test-unused-reranker".to_owned()),
        model_revision: "unused-v1".to_owned(),
        max_documents: 5,
        max_input_tokens: 4_096,
        score_semantics: RerankScoreSemantics::RawLogit,
        calibration_profile: CalibrationProfileId("unused-v1".to_owned()),
    }
}

fn scanner() -> Arc<LocalSecretScanner> {
    Arc::new(
        LocalSecretScanner::new(LocalSecretScannerConfig {
            executable: required("HUMAUX_TEST_GITLEAKS_BIN").into(),
            expected_version: required("HUMAUX_TEST_GITLEAKS_VERSION"),
            expected_executable_sha256: required("HUMAUX_TEST_GITLEAKS_SHA256"),
            timeout: Duration::from_secs(5),
            max_payload_bytes: 64 * 1024,
            finding_exit_code: 1,
        })
        .expect("pinned wiring-test scanner"),
    )
}

/// Spawns the real `humaux-retrieval-worker` RPC app in-process on a temporary UDS — mirrors
/// `tests/query_embedding_rpc.rs`'s `spawn_worker`.
async fn spawn_worker(expected_gateway_uid: u32) -> String {
    let socket_path = temp_socket_path("worker");
    // dep: PostgreSQL(role_retrieval_worker) — test fixture pool for the semantic recall wiring suite
    let calls = RetrievalWorkerDbPool::connect(&required("HUMAUX_RETRIEVAL_WORKER_PG_DSN"))
        .await
        .expect("retrieval worker db pool");
    let state = Arc::new(humaux_retrieval_worker::rpc::RpcState {
        expected_gateway_uid,
        calls,
        pg_dsn: required("HUMAUX_RETRIEVAL_WORKER_PG_DSN"),
        scanner: scanner(),
        embedder: Arc::new(TestDoubleProvider::new(embedding_model(), rerank_model())),
        dimension: DIMENSION,
        provider_id: "wiring-test-provider".to_owned(),
    });
    // dep: UDS(serve) — test serves the real retrieval-worker RPC router on a temp socket
    let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind worker rpc socket");
    // ADR-0066 D-L: the gateway's dial refuses a socket with `other` bits; a server socket is 0660.
    std::fs::set_permissions(
        &socket_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o660),
    )
    .expect("chmod the worker rpc socket");
    let app = humaux_retrieval_worker::rpc::router(state);
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<humaux_retrieval_worker::rpc::PeerIdentity>(),
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    socket_path.to_string_lossy().into_owned()
}

fn qdrant_port() -> u16 {
    std::env::var("HUMAUX_TEST_QDRANT_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(6333)
}

/// The one registry both `IntraCellResource::QDRANT_REST` (`QdrantReadOnly`, ADR-0014) and
/// `IntraCellResource::RETRIEVAL_EMBEDDING_RPC` share — the same shape `bootstrap.rs`'s
/// `build_semantic_recall_runtime` constructs in production.
fn cell_registry(cell: CellId, caller: CallerId) -> IntraCellResourceRegistry {
    let mut entries = BTreeMap::new();
    entries.insert(
        IntraCellResource::QDRANT_REST,
        ResourceEntry::new(
            "127.0.0.1",
            qdrant_port(),
            cell,
            vec!["127.0.0.1/32".parse().expect("loopback CIDR")],
            BTreeSet::from([caller.clone()]),
            false,
        )
        .expect("loopback Qdrant resource")
        .with_access_mode(CellAccessMode::QdrantReadOnly),
    );
    entries.insert(
        IntraCellResource::RETRIEVAL_EMBEDDING_RPC,
        ResourceEntry::new(
            "unix-socket",
            0,
            cell,
            vec![],
            BTreeSet::from([caller.clone()]),
            false,
        )
        .expect("valid RPC resource entry"),
    );
    IntraCellResourceRegistry::new(entries, cell, caller)
}

/// Counts every call that reaches the inner transport — proves "zero Qdrant calls" for the
/// no-placement test rather than merely asserting the final `Err`.
struct CountingTransport {
    inner: Arc<HttpIntraCellTransport>,
    calls: AtomicUsize,
}

#[async_trait]
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

/// An in-process `RetrievalEmbeddingPort` double that always returns the same fixed outcome —
/// used where the test cares about `recall::search`'s reaction to a specific outcome
/// (`Unavailable`, or a wrong-dimension `Embedded`) rather than a real worker round-trip.
/// `calls` lets a test prove the port was actually reached (i.e. placement resolution
/// succeeded) rather than the assertion passing vacuously because `recall::search` degraded
/// earlier, at the placement step.
struct FixedOutcomePort {
    outcome: RetrievalEmbeddingOutcome,
    calls: AtomicUsize,
}

impl FixedOutcomePort {
    fn new(outcome: RetrievalEmbeddingOutcome) -> Self {
        Self {
            outcome,
            calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl RetrievalEmbeddingPort for FixedOutcomePort {
    async fn embed_query(
        &self,
        _input: RetrievalEmbeddingInput<'_>,
    ) -> Result<RetrievalEmbeddingOutcome, ErrorCode> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.outcome.clone())
    }
}

fn qdrant_transport(registry: &IntraCellResourceRegistry) -> Arc<HttpIntraCellTransport> {
    Arc::new(
        HttpIntraCellTransport::new(
            registry.clone(),
            Duration::from_secs(10),
            humaux_infra_cell::DEFAULT_MAX_RESPONSE_BYTES,
        )
        .expect("Qdrant transport"),
    )
}

async fn create_collection(
    transport: &HttpIntraCellTransport,
    registry: &IntraCellResourceRegistry,
    collection: &str,
) {
    let permit = authorize_cell_access(
        registry,
        IntraCellResource::QDRANT_REST,
        Duration::from_secs(60),
    )
    .expect(
        "real Qdrant setup needs a permit that predates ADR-0014 (setup runs GET/PUT \
             directly against the real transport, never through a QdrantReadOnly permit)",
    );
    for (path, body) in [
        (
            format!("/collections/{collection}"),
            create_collection_body(
                DIMENSION.into(),
                Distance::Cosine,
                1,
                1,
                1,
                ShardingMethod::Auto,
            ),
        ),
        (
            format!("/collections/{collection}/index"),
            tenant_index_body(),
        ),
    ] {
        let response = transport
            .execute(
                &permit,
                // dep: Qdrant(*) — test issues a Qdrant REST request against the fixture collection
                IntraCellRequest {
                    method: IntraCellMethod::Put,
                    path,
                    json_body: Some(body),
                    headers: Vec::new(),
                },
            )
            .await
            .expect("real Qdrant setup request");
        assert!(
            (200..300).contains(&response.status),
            "real Qdrant setup returned {}",
            response.status
        );
    }
}

async fn delete_collection(
    transport: &HttpIntraCellTransport,
    registry: &IntraCellResourceRegistry,
    collection: &str,
) {
    let permit = authorize_cell_access(
        registry,
        IntraCellResource::QDRANT_REST,
        Duration::from_secs(60),
    )
    .expect("real Qdrant cleanup permit");
    let _ = transport
        .execute(
            &permit,
            // dep: Qdrant(*) — test issues a Qdrant REST request against the fixture collection
            IntraCellRequest {
                method: IntraCellMethod::Delete,
                path: format!("/collections/{collection}"),
                json_body: None,
                headers: Vec::new(),
            },
        )
        .await;
}

/// A setup permit that predates ADR-0014's read-only enforcement — this test file's own setup
/// deliberately dials with a plain `ReadWrite` registry (mirrors `tests/mcp_gateway.rs`'s
/// `semantic_qdrant_registry`), since seeding a collection needs `PUT`. Production gateway code
/// never constructs this; only `bins/gateway/src/bootstrap.rs` may (ADR-0014, enforced by
/// `xtask architecture-check`).
fn setup_registry(cell: CellId, caller: CallerId) -> IntraCellResourceRegistry {
    let mut entries = BTreeMap::new();
    entries.insert(
        IntraCellResource::QDRANT_REST,
        ResourceEntry::new(
            "127.0.0.1",
            qdrant_port(),
            cell,
            vec!["127.0.0.1/32".parse().expect("loopback CIDR")],
            BTreeSet::from([caller.clone()]),
            false,
        )
        .expect("loopback Qdrant resource"),
    );
    IntraCellResourceRegistry::new(entries, cell, caller)
}

fn seed_tenant_placement(admin: &mut Client, tenant_id: Uuid, collection: &str) {
    admin
        .execute(
            "INSERT INTO projection.tenant_placements \
               (tenant_id,projection_family,collection_name,shard_key,placement_class, \
                point_count,bytes_estimate,promotion_state) \
             VALUES ($1,'private_memory_v1',$2,NULL,'SHARED_FALLBACK',1,0,'STABLE')",
            &[&tenant_id, &collection],
        )
        .expect("owner seeds tenant placement row");
}

fn seed_registry_row(
    admin: &mut Client,
    tenant_id: Uuid,
    workspace_id: Uuid,
    memory_id: Uuid,
    point_id: Uuid,
) {
    admin
        .execute(
            "INSERT INTO projection.private_memory_points \
               (point_id,tenant_id,scope_kind,scope_id,domain,projection_kind, \
                projection_version,embedding_version,memory_id,source_updated_at,body_sha256) \
             SELECT $1,$2,'workspace',$3,'knowledge','ingest','v1',$4,memory_id, \
                    updated_at,sha256(convert_to(content::text,'UTF8')) \
             FROM private.memory_records WHERE tenant_id=$2 AND memory_id=$5",
            &[
                &point_id,
                &tenant_id,
                &workspace_id,
                &EMBEDDING_VERSION,
                &memory_id,
            ],
        )
        .expect("owner registers opaque Qdrant point identity");
}

fn seed_checkpoint(admin: &mut Client, tenant_id: Uuid, workspace_id: Uuid) {
    admin
        .execute(
            "INSERT INTO projection.stream_checkpoints \
               (tenant_id,scope_kind,scope_id,domain,projection_kind,projection_version, \
                issued_highwater,evidence_highwater,knowledge_highwater,projection_highwater,serving) \
             VALUES($1,'workspace',$2,'knowledge','ingest','v1',0,0,0,0,true)",
            &[&tenant_id, &workspace_id],
        )
        .expect("owner seeds the trusted serving version");
}

fn payload(
    tenant_id: Uuid,
    workspace_id: Uuid,
    source_updated_at: time::OffsetDateTime,
) -> humaux_adapters::qdrant::IndexablePayload {
    QdrantPointPayload {
        memory_id: humaux_domain::authority::MemoryId::new(),
        tenant_id: TenantId(tenant_id),
        workspace_id: WorkspaceId(workspace_id),
        visibility_class: VisibilityClass::WorkspaceShared,
        visibility_user_id: None,
        visibility_workspace_id: Some(WorkspaceId(workspace_id)),
        object_type: "memory_record".to_owned(),
        memory_type: MemoryType::Note,
        status: AuthorityStatus::Active,
        authority: AuthorityClass::ProjectConstraint,
        created_at: source_updated_at,
        effective_at: source_updated_at,
        embedding_version: EMBEDDING_VERSION.to_owned(),
        projection_version: "v1".to_owned(),
        source_stream_seq: 0,
        data_class: DataClass::Internal,
        egress_disposition: EgressDisposition::Allowed,
    }
    .into_indexable()
    .expect("non-secret wiring-test fixture payload")
}

fn fixed_vector(text: &str) -> Vec<f32> {
    let mut vector = vec![0.0; DIMENSION as usize];
    for (index, byte) in text.bytes().enumerate() {
        vector[index % DIMENSION as usize] += f32::from(byte) / 255.0;
    }
    vector
}

fn context_bootstrap(handle: &Handle) -> ContextBootstrap {
    let policy = RememberPolicy::new(
        // ADR-0054 D-D: the family only — no default (tenant, workspace) pair.
        ProcessFamily::new("workspace", "knowledge", "ingest", "v1").expect("trusted family"),
        handle.reasoning_domain_id,
        Duration::from_secs(60),
        DataClass::Internal,
        VisibilityClass::WorkspaceShared,
    )
    .expect("trusted wiring-test remember policy");
    ContextBootstrap::new(
        humaux_domain::context::ContextBudget::new(2_048, 1_024).expect("trusted budget"),
        humaux_contracts::retrieval_config::resolve_registered_retrieval_profile(
            &Default::default(),
        )
        .expect("registered default profile"),
        &policy,
        std::time::Duration::from_secs(60),
    )
    .expect("actual executable identity")
}

fn recall_request(query: &str, workspace_id: Uuid) -> RecallSearchRequest {
    RecallSearchRequest {
        query: query.to_owned(),
        workspace_id: WorkspaceId(workspace_id),
        consistency_token: None,
        mode: Some("semantic".to_owned()),
        completeness_request: None,
        limit: None,
        subject_ids: Vec::new(),
        affect: None,
        mood_congruence: None,
    }
}

/// (1) Bootstrap from test envs + seeded tenant placement + seeded point ⇒ recall.search hit.
#[allow(clippy::too_many_lines)]
// one end-to-end scenario: bootstrap → placement → point → recall hit; splitting it would hide the sequence the test exists to prove.
#[test]
fn happy_path_placement_and_point_hit() {
    run_db_fixture::<Fixture, _>("semantic_recall_wiring_happy_path", |mut handle| {
        handle.assert_gateway_login();
        let context_row = handle.seed_workspace_visible_context_record();
        let point_id = Uuid::new_v4();

        let rt = handle.rt.handle().clone();
        // `owner_client()` (`postgres::Client::connect`) is blocking and spins its own Tokio
        // runtime internally — calling it from inside `rt.block_on`'s future body panics with
        // "Cannot start a runtime from within a runtime". Do the blocking seeding on the plain
        // test thread, outside any `block_on`, same as the rest of this fixture's usage.
        let mut admin = handle.owner_client().expect("owner client for setup");
        seed_registry_row(
            &mut admin,
            handle.tenant_id,
            handle.workspace_id,
            context_row.memory_id,
            point_id,
        );
        seed_checkpoint(&mut admin, handle.tenant_id, handle.workspace_id);
        let source_updated_at = time::OffsetDateTime::now_utc();

        let collection = format!("wiring_happy_{}", Uuid::now_v7().simple());
        let cell = CellId(Uuid::now_v7());
        let caller = CallerId("gateway-wiring-test".to_owned());
        let setup_registry = setup_registry(cell, caller.clone());
        let setup_transport = qdrant_transport(&setup_registry);
        let registry = cell_registry(cell, caller);
        let transport = qdrant_transport(&registry);

        let mut admin = handle.owner_client().expect("owner client for placement");
        seed_tenant_placement(&mut admin, handle.tenant_id, &collection);

        rt.block_on(async {
            create_collection(&setup_transport, &setup_registry, &collection).await;
            let permit = authorize_cell_access(
                &setup_registry,
                IntraCellResource::QDRANT_REST,
                Duration::from_secs(60),
            )
            .expect("setup upsert permit");
            let vector = fixed_vector("operation receipt scoped context");
            let point_payload = payload(handle.tenant_id, handle.workspace_id, source_updated_at);
            upsert(
                setup_transport.as_ref(),
                &permit,
                &collection,
                &[(PointId::Uuid(point_id), &point_payload, vector)],
                ha_profile_for(QdrantOperation::NormalImmutableUpsert),
            )
            .await
            .expect("real Qdrant upsert");

            let gateway_uid = own_uid().await;
            let socket_path = spawn_worker(gateway_uid).await;
            let pool = Arc::new(
                // dep: PostgreSQL(role_gateway) — test fixture pool for the semantic recall wiring suite
                humaux_adapters::postgres::RuntimeDbPool::connect(&required(
                    "HUMAUX_GATEWAY_PG_DSN",
                ))
                .await
                .expect("real role_gateway pool"),
            );
            let embedding_port: Arc<dyn RetrievalEmbeddingPort> =
                Arc::new(GatewayRetrievalEmbeddingClient::new(
                    pool.clone(),
                    socket_path,
                    own_uid().await,
                    registry.clone(),
                    Duration::from_secs(30),
                ));
            let runtime = Arc::new(
                SemanticRecallRuntime::new(
                    embedding_port,
                    transport,
                    registry,
                    SemanticRecallVersions {
                        embedding_version: EMBEDDING_VERSION.to_owned(),
                        dimension: DIMENSION,
                    },
                    Duration::from_secs(10),
                )
                .expect("trusted semantic runtime"),
            );
            let catalog = Arc::new(CanonicalCatalog::load().expect("catalog"));
            let result = recall::search(
                pool,
                runtime,
                catalog,
                handle.auth.clone(),
                Uuid::now_v7(),
                context_bootstrap(&handle),
                recall_request("operation receipt scoped context", handle.workspace_id),
            )
            .await;
            let output = result.expect("semantic recall hit").finish();
            let items = output.structured_content["items"]
                .as_array()
                .expect("items array");
            assert!(
                items.iter().any(
                    |item| item["memory_id"] == context_row.memory_id.to_string()
                        || item["memory_id"] == serde_json::json!(context_row.memory_id)
                ),
                "expected the seeded memory in the hit: {items:?}"
            );

            delete_collection(&setup_transport, &setup_registry, &collection).await;
        });
        // `tenant_placements_tenant_id_fkey` references `control.tenants` — the fixture's own
        // teardown (`Handle::Drop`) deletes that tenant row and panics on the FK violation if a
        // seeded placement row outlives it.
        admin
            .execute(
                "DELETE FROM projection.tenant_placements WHERE tenant_id=$1",
                &[&handle.tenant_id],
            )
            .expect("cleanup seeded tenant placement row");
    });
}

/// (2) Tenant B has no placement row ⇒ `DependencyUnavailable`, and zero Qdrant calls (proves
/// the "no placement = not indexed" path returns before ever dialing Qdrant, never falling back
/// onto some other tenant's collection).
#[test]
fn tenant_with_no_placement_degrades_closed_without_calling_qdrant() {
    run_db_fixture::<Fixture, _>("semantic_recall_wiring_no_placement", |handle| {
        handle.assert_gateway_login();
        let rt = handle.rt.handle().clone();
        let cell = CellId(Uuid::now_v7());
        let caller = CallerId("gateway-wiring-test".to_owned());
        let registry = cell_registry(cell, caller);
        let inner = qdrant_transport(&registry);
        let counting = Arc::new(CountingTransport {
            inner,
            calls: AtomicUsize::new(0),
        });

        rt.block_on(async {
            let pool = Arc::new(
                // dep: PostgreSQL(role_gateway) — test fixture pool for the semantic recall wiring suite
                humaux_adapters::postgres::RuntimeDbPool::connect(&required(
                    "HUMAUX_GATEWAY_PG_DSN",
                ))
                .await
                .expect("real role_gateway pool"),
            );
            let embedding_port: Arc<dyn RetrievalEmbeddingPort> =
                Arc::new(FixedOutcomePort::new(RetrievalEmbeddingOutcome::Embedded {
                    vector: fixed_vector("no placement query"),
                    provider_id: "wiring-test-provider".to_owned(),
                    model_id: "wiring-test-embedding".to_owned(),
                    model_revision: "v1".to_owned(),
                    dimension: DIMENSION,
                }));
            let runtime = Arc::new(
                SemanticRecallRuntime::new(
                    embedding_port,
                    counting.clone(),
                    registry,
                    SemanticRecallVersions {
                        embedding_version: EMBEDDING_VERSION.to_owned(),
                        dimension: DIMENSION,
                    },
                    Duration::from_secs(10),
                )
                .expect("trusted semantic runtime"),
            );
            let catalog = Arc::new(CanonicalCatalog::load().expect("catalog"));
            let result = recall::search(
                pool,
                runtime,
                catalog,
                handle.auth.clone(),
                Uuid::now_v7(),
                context_bootstrap(&handle),
                recall_request("no placement seeded for this tenant", handle.workspace_id),
            )
            .await;
            assert_eq!(result.err(), Some(ErrorCode::DependencyUnavailable));
            assert_eq!(
                counting.calls.load(Ordering::SeqCst),
                0,
                "no placement must short-circuit before ever calling Qdrant"
            );
        });
    });
}

/// (3) A socket path pointing nowhere ⇒ `DependencyUnavailable`, no panic, and the call
/// completes well inside the configured handler timeout (a hung dial would time out the test
/// harness itself long before any test assertion could fail it).
#[tokio::test]
async fn dead_socket_path_degrades_closed_without_hanging() {
    let cell = CellId(Uuid::now_v7());
    let caller = CallerId("gateway-wiring-test".to_owned());
    let registry = cell_registry(cell, caller);
    let transport = qdrant_transport(&registry);
    let pool = Arc::new(
        // dep: PostgreSQL(role_gateway) — test fixture pool for the semantic recall wiring suite
        humaux_adapters::postgres::RuntimeDbPool::connect(&required("HUMAUX_GATEWAY_PG_DSN"))
            .await
            .expect("real role_gateway pool"),
    );
    let embedding_port: Arc<dyn RetrievalEmbeddingPort> =
        Arc::new(GatewayRetrievalEmbeddingClient::new(
            pool,
            temp_socket_path("nowhere").to_string_lossy().into_owned(),
            own_uid().await,
            registry,
            Duration::from_secs(5),
        ));
    let deadline_unix_ms = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
        + 5_000;
    let auth = humaux_domain::identity::AuthorizationScope::new(
        TenantId::new(),
        humaux_domain::identity::PrincipalId::new(),
        Some(humaux_domain::ids::UserId::new()),
        humaux_domain::identity::BoundedSet::new([WorkspaceId::new()]).unwrap(),
    );
    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        embedding_port.embed_query(RetrievalEmbeddingInput {
            authorization: &auth,
            workspace_id: *auth.allowed_workspace_ids().iter().next().unwrap(),
            request_id: Uuid::now_v7(),
            logical_call_id: Uuid::now_v7(),
            attempt_no: 1,
            profile_fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000",
            dimension: DIMENSION,
            query: "dead socket",
            deadline_unix_ms,
        }),
    )
    .await
    .expect("dead-socket dial must not hang the whole call");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "dial to a dead socket must fail fast"
    );
    // `embed_query` registers the call (a real INSERT) before ever dialing the socket
    // (ADR-0012 §决定2's idempotency-anchor ordering) — with this test's unseeded synthetic
    // tenant that registration itself fails closed (`Err(DependencyUnavailable)`) before the
    // dead-socket dial is ever attempted; a seeded tenant would instead reach the dial and come
    // back `Ok(Unavailable{reason: "TRANSPORT"})`. Both are the same outward
    // `ErrorCode::DependencyUnavailable` this test's name asserts — `recall::search`'s own
    // `runtime.port.embed_query(..).await?` propagates either shape identically via `?`.
    match outcome {
        Err(ErrorCode::DependencyUnavailable) => {}
        Ok(RetrievalEmbeddingOutcome::Unavailable { .. }) => {}
        other => panic!("expected a degrade-closed outcome, got {other:?}"),
    }
    let _ = transport; // constructed to mirror the real wiring shape; unused on this path.
}

/// (4) The gateway transport denies a write under a `QdrantReadOnly` permit (ADR-0014) — the
/// same registry/permit shape `SemanticRecallRuntime` mints for `recall.search`, proven against
/// a real Qdrant connection (the request never leaves in the first place, so no live collection
/// is needed).
#[tokio::test]
async fn gateway_transport_denies_a_write_under_the_read_only_permit() {
    let cell = CellId(Uuid::now_v7());
    let caller = CallerId("gateway-wiring-test".to_owned());
    let registry = cell_registry(cell, caller);
    let transport = qdrant_transport(&registry);
    let permit = authorize_cell_access(
        &registry,
        IntraCellResource::QDRANT_REST,
        Duration::from_secs(30),
    )
    .expect("read-only permit mints fine — ADR-0014 denies at execute(), not at mint time");
    let result = transport
        .execute(
            &permit,
            // dep: Qdrant(*) — test issues a Qdrant REST request against the fixture collection
            IntraCellRequest {
                method: IntraCellMethod::Put,
                path: "/collections/whatever-tenant-forgot-to-check/points".to_owned(),
                json_body: Some(serde_json::json!({"points": []})),
                headers: Vec::new(),
            },
        )
        .await;
    assert_eq!(result, Err(IntraCellError::WriteDenied));
}

/// (5) A wrong-dimension vector from the embedding port never gets hydrated — `recall.search`
/// returns `DependencyUnavailable` before touching Qdrant or PostgreSQL hydration at all.
#[test]
fn wrong_dimension_vector_from_port_is_never_hydrated() {
    run_db_fixture::<Fixture, _>("semantic_recall_wiring_wrong_dimension", |handle| {
        handle.assert_gateway_login();
        let rt = handle.rt.handle().clone();
        let cell = CellId(Uuid::now_v7());
        let caller = CallerId("gateway-wiring-test".to_owned());
        let registry = cell_registry(cell, caller);
        let inner = qdrant_transport(&registry);
        let counting = Arc::new(CountingTransport {
            inner,
            calls: AtomicUsize::new(0),
        });
        // A placement row and a serving family must exist, or `recall::search` degrades at the
        // placement step or (ADR-0053 D-E: the serving read now runs BEFORE the query embedding)
        // at the family read — before ever calling the embedding port — and the assertions
        // below would pass vacuously without ever exercising the dimension guard this test
        // targets.
        let collection = format!("wiring_wrong_dim_{}", Uuid::now_v7().simple());
        let mut admin = handle.owner_client().expect("owner client for placement");
        seed_tenant_placement(&mut admin, handle.tenant_id, &collection);
        seed_checkpoint(&mut admin, handle.tenant_id, handle.workspace_id);

        rt.block_on(async {
            let pool = Arc::new(
                // dep: PostgreSQL(role_gateway) — test fixture pool for the semantic recall wiring suite
                humaux_adapters::postgres::RuntimeDbPool::connect(&required(
                    "HUMAUX_GATEWAY_PG_DSN",
                ))
                .await
                .expect("real role_gateway pool"),
            );
            // Configured dimension is 4; the port double returns 3 — a real worker could never
            // legitimately do this for a fixed model, but a misconfigured/rogue one could, and
            // `recall.search` must never truncate or pad to fit.
            let port = Arc::new(FixedOutcomePort::new(RetrievalEmbeddingOutcome::Embedded {
                vector: vec![0.1, 0.2, 0.3],
                provider_id: "wiring-test-provider".to_owned(),
                model_id: "wiring-test-embedding".to_owned(),
                model_revision: "v1".to_owned(),
                dimension: 3,
            }));
            let embedding_port: Arc<dyn RetrievalEmbeddingPort> = port.clone();
            let runtime = Arc::new(
                SemanticRecallRuntime::new(
                    embedding_port,
                    counting.clone(),
                    registry,
                    SemanticRecallVersions {
                        embedding_version: EMBEDDING_VERSION.to_owned(),
                        dimension: DIMENSION,
                    },
                    Duration::from_secs(10),
                )
                .expect("trusted semantic runtime"),
            );
            let catalog = Arc::new(CanonicalCatalog::load().expect("catalog"));
            let result = recall::search(
                pool,
                runtime,
                catalog,
                handle.auth.clone(),
                Uuid::now_v7(),
                context_bootstrap(&handle),
                recall_request("mismatched dimension query", handle.workspace_id),
            )
            .await;
            assert_eq!(result.err(), Some(ErrorCode::DependencyUnavailable));
            assert_eq!(
                port.calls.load(Ordering::SeqCst),
                1,
                "placement resolved fine — the embedding port must actually have been called \
                 for the dimension guard below it to mean anything"
            );
            assert_eq!(
                counting.calls.load(Ordering::SeqCst),
                0,
                "a dimension mismatch must be caught before ever calling Qdrant"
            );
        });
        // See the happy-path test's identical cleanup comment: `control.tenants` teardown
        // would otherwise fail on the `tenant_placements_tenant_id_fkey` FK.
        admin
            .execute(
                "DELETE FROM projection.tenant_placements WHERE tenant_id=$1",
                &[&handle.tenant_id],
            )
            .expect("cleanup seeded tenant placement row");
    });
}

/// A [`FixedOutcomePort`] that sleeps before answering — makes the `embed` stage observably
/// slow, so a `.await` left outside every stage lap would show up as missing wall time.
struct DelayedPort {
    delay: Duration,
    outcome: RetrievalEmbeddingOutcome,
}

#[async_trait]
impl RetrievalEmbeddingPort for DelayedPort {
    async fn embed_query(
        &self,
        _input: RetrievalEmbeddingInput<'_>,
    ) -> Result<RetrievalEmbeddingOutcome, ErrorCode> {
        tokio::time::sleep(self.delay).await;
        Ok(self.outcome.clone())
    }
}

/// (7) ADR-0055 D-E: `provenance.stage_ms` partitions `recall::search` exhaustively — the eight
/// stages sum to at least 90% of the in-process wall time around the call, `total` never
/// exceeds it, and the port's injected 200 ms lands in `embed`. Fault: move one `.await` (e.g.
/// the embedding call) outside every lap ⇒ the sum loses ≥ 200 ms ⇒ red.
#[test]
#[allow(clippy::too_many_lines)] // one fixture: placement → point → timed search → stage arithmetic.
fn recall_stage_ms_cover_at_least_ninety_percent_of_in_process_search_time() {
    run_db_fixture::<Fixture, _>("semantic_recall_wiring_stage_ms", |mut handle| {
        handle.assert_gateway_login();
        let context_row = handle.seed_workspace_visible_context_record();
        let point_id = Uuid::new_v4();
        let rt = handle.rt.handle().clone();
        let mut admin = handle.owner_client().expect("owner client for setup");
        seed_registry_row(
            &mut admin,
            handle.tenant_id,
            handle.workspace_id,
            context_row.memory_id,
            point_id,
        );
        seed_checkpoint(&mut admin, handle.tenant_id, handle.workspace_id);
        let source_updated_at = time::OffsetDateTime::now_utc();
        let collection = format!("c30_wiring_stage_{}", Uuid::now_v7().simple());
        let cell = CellId(Uuid::now_v7());
        let caller = CallerId("gateway-wiring-test".to_owned());
        let setup_registry = setup_registry(cell, caller.clone());
        let setup_transport = qdrant_transport(&setup_registry);
        let registry = cell_registry(cell, caller);
        let transport = qdrant_transport(&registry);
        seed_tenant_placement(&mut admin, handle.tenant_id, &collection);
        let query = "operation receipt scoped context";
        let delay = Duration::from_millis(200);

        rt.block_on(async {
            create_collection(&setup_transport, &setup_registry, &collection).await;
            let permit = authorize_cell_access(
                &setup_registry,
                IntraCellResource::QDRANT_REST,
                Duration::from_secs(60),
            )
            .expect("setup upsert permit");
            let point_payload = payload(handle.tenant_id, handle.workspace_id, source_updated_at);
            upsert(
                setup_transport.as_ref(),
                &permit,
                &collection,
                &[(PointId::Uuid(point_id), &point_payload, fixed_vector(query))],
                ha_profile_for(QdrantOperation::NormalImmutableUpsert),
            )
            .await
            .expect("real Qdrant upsert");
            let pool = Arc::new(
                // dep: PostgreSQL(role_gateway) — test fixture pool for the semantic recall wiring suite
                humaux_adapters::postgres::RuntimeDbPool::connect(&required(
                    "HUMAUX_GATEWAY_PG_DSN",
                ))
                .await
                .expect("real role_gateway pool"),
            );
            let embedding_port: Arc<dyn RetrievalEmbeddingPort> = Arc::new(DelayedPort {
                delay,
                outcome: RetrievalEmbeddingOutcome::Embedded {
                    vector: fixed_vector(query),
                    provider_id: "wiring-test-provider".to_owned(),
                    model_id: "wiring-test-embedding".to_owned(),
                    model_revision: "v1".to_owned(),
                    dimension: DIMENSION,
                },
            });
            let runtime = Arc::new(
                SemanticRecallRuntime::new(
                    embedding_port,
                    transport,
                    registry,
                    SemanticRecallVersions {
                        embedding_version: EMBEDDING_VERSION.to_owned(),
                        dimension: DIMENSION,
                    },
                    Duration::from_secs(10),
                )
                .expect("trusted semantic runtime"),
            );
            let catalog = Arc::new(CanonicalCatalog::load().expect("catalog"));
            let bootstrap = context_bootstrap(&handle);
            let started = std::time::Instant::now();
            let result = recall::search(
                pool,
                runtime,
                catalog,
                handle.auth.clone(),
                Uuid::now_v7(),
                bootstrap,
                recall_request(query, handle.workspace_id),
            )
            .await;
            let wall_ms = started.elapsed().as_secs_f64() * 1_000.0;
            let output = result.expect("semantic recall answers").finish();
            let stage_ms = &output.structured_content["provenance"]["stage_ms"];
            let stage = |name: &str| {
                stage_ms[name]
                    .as_f64()
                    .unwrap_or_else(|| panic!("stage_ms.{name} missing: {stage_ms}"))
            };
            let names = [
                "route", "planner", "scan", "embed", "qdrant", "hydrate", "rerank", "assemble",
            ];
            let sum: f64 = names.iter().map(|name| stage(name)).sum();
            eprintln!("stage_ms={stage_ms} sum={sum:.1} wall={wall_ms:.1}");
            assert!(
                stage("embed") >= 200.0,
                "the injected 200 ms must land in `embed`: {stage_ms}"
            );
            assert!(
                stage("total") <= wall_ms + 0.1,
                "total {} exceeds the wall time {wall_ms}",
                stage("total")
            );
            assert!(
                sum >= 0.9 * wall_ms,
                "stages cover {sum:.1} of {wall_ms:.1} ms — an .await sits outside every stage"
            );
            delete_collection(&setup_transport, &setup_registry, &collection).await;
        });
        admin
            .execute(
                "DELETE FROM projection.tenant_placements WHERE tenant_id=$1",
                &[&handle.tenant_id],
            )
            .expect("cleanup seeded tenant placement row");
    });
}

/// (6) `bootstrap.rs` wires `with_semantic_recall` exactly once — a second call site would
/// mean two competing semantic-recall configurations racing to be `GatewayMcpApplication`'s
/// last write.
#[test]
fn bootstrap_wires_semantic_recall_exactly_once() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bootstrap.rs"))
        .expect("read bootstrap.rs");
    let count = source.matches("with_semantic_recall(").count();
    assert_eq!(
        count, 1,
        "bootstrap.rs must call with_semantic_recall exactly once, found {count}"
    );
}

/// A stub of the retrieval-worker RPC (ADR-0012 wire shape): the first call answers a transient
/// provider failure, every later call a fixed-vector `EMBEDDED`; `calls` counts what reached it.
async fn spawn_flaky_worker(calls: Arc<AtomicUsize>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let socket_path = temp_socket_path("flaky");
    // dep: UDS(serve) — test serves a stub retrieval-worker RPC on a temp socket
    let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind stub rpc socket");
    // ADR-0066 D-L: the gateway's dial refuses a socket with `other` bits; a server socket is 0660.
    std::fs::set_permissions(
        &socket_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o660),
    )
    .expect("chmod the stub rpc socket");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let calls = calls.clone();
            tokio::spawn(async move {
                let mut raw = Vec::new();
                let mut chunk = [0u8; 4096];
                let body = loop {
                    let n = stream.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    raw.extend_from_slice(&chunk[..n]);
                    let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    if raw.len() >= end + 4 + len {
                        break raw[end + 4..end + 4 + len].to_vec();
                    }
                };
                let wire: serde_json::Value =
                    serde_json::from_slice(&body).expect("stub rpc request json");
                let envelope = if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    serde_json::json!({"schema_version": 1, "call_id": wire["call_id"],
                        "outcome": "UNAVAILABLE", "failure_code": "PROVIDER_TRANSIENT"})
                } else {
                    serde_json::json!({"schema_version": 1, "call_id": wire["call_id"],
                        "outcome": "EMBEDDED",
                        "vector": fixed_vector(wire["query"].as_str().unwrap_or_default()),
                        "provider_id": "wiring-test-provider", "model_id": "wiring-test-embedding",
                        "model_revision": "v1", "dimension": DIMENSION})
                }
                .to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{envelope}",
                    envelope.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    socket_path.to_string_lossy().into_owned()
}

/// (8) ADR-0065 D-G (Debt A): a transient query-embedding failure fails fast — the recall is
/// `DependencyUnavailable` well inside its handler deadline after exactly ONE worker call, so the
/// admission permit it holds is released at once; the next recall answers. Fault: a retry loop in
/// `retrieval_embedding_client` ⇒ the stub sees 2 calls and the first recall answers ⇒ red.
#[test]
#[allow(clippy::too_many_lines)] // one fixture: placement → point → failing recall → answering recall.
fn a_transient_query_embedding_failure_fails_fast_with_one_worker_call() {
    run_db_fixture::<Fixture, _>("semantic_recall_wiring_fail_fast", |mut handle| {
        handle.assert_gateway_login();
        let context_row = handle.seed_workspace_visible_context_record();
        let point_id = Uuid::new_v4();
        let rt = handle.rt.handle().clone();
        let mut admin = handle.owner_client().expect("owner client for setup");
        seed_registry_row(
            &mut admin,
            handle.tenant_id,
            handle.workspace_id,
            context_row.memory_id,
            point_id,
        );
        seed_checkpoint(&mut admin, handle.tenant_id, handle.workspace_id);
        let source_updated_at = time::OffsetDateTime::now_utc();
        let collection = format!("wiring_fail_fast_{}", Uuid::now_v7().simple());
        let cell = CellId(Uuid::now_v7());
        let caller = CallerId("gateway-wiring-test".to_owned());
        let setup_registry = setup_registry(cell, caller.clone());
        let setup_transport = qdrant_transport(&setup_registry);
        let registry = cell_registry(cell, caller);
        let transport = qdrant_transport(&registry);
        seed_tenant_placement(&mut admin, handle.tenant_id, &collection);
        let query = "operation receipt scoped context";
        let handler_timeout = Duration::from_secs(10);
        let calls = Arc::new(AtomicUsize::new(0));

        rt.block_on(async {
            create_collection(&setup_transport, &setup_registry, &collection).await;
            let permit = authorize_cell_access(
                &setup_registry,
                IntraCellResource::QDRANT_REST,
                Duration::from_secs(60),
            )
            .expect("setup upsert permit");
            let point_payload = payload(handle.tenant_id, handle.workspace_id, source_updated_at);
            upsert(
                setup_transport.as_ref(),
                &permit,
                &collection,
                &[(PointId::Uuid(point_id), &point_payload, fixed_vector(query))],
                ha_profile_for(QdrantOperation::NormalImmutableUpsert),
            )
            .await
            .expect("real Qdrant upsert");

            let socket_path = spawn_flaky_worker(calls.clone()).await;
            let stub_socket = socket_path.clone();
            let pool = Arc::new(
                // dep: PostgreSQL(role_gateway) — test fixture pool for the semantic recall wiring suite
                humaux_adapters::postgres::RuntimeDbPool::connect(&required(
                    "HUMAUX_GATEWAY_PG_DSN",
                ))
                .await
                .expect("real role_gateway pool"),
            );
            let embedding_port: Arc<dyn RetrievalEmbeddingPort> =
                Arc::new(GatewayRetrievalEmbeddingClient::new(
                    pool.clone(),
                    socket_path,
                    own_uid().await,
                    registry.clone(),
                    Duration::from_secs(30),
                ));
            let runtime = Arc::new(
                SemanticRecallRuntime::new(
                    embedding_port,
                    transport,
                    registry,
                    SemanticRecallVersions {
                        embedding_version: EMBEDDING_VERSION.to_owned(),
                        dimension: DIMENSION,
                    },
                    handler_timeout,
                )
                .expect("trusted semantic runtime"),
            );
            let catalog = Arc::new(CanonicalCatalog::load().expect("catalog"));
            let search = || {
                recall::search(
                    pool.clone(),
                    runtime.clone(),
                    catalog.clone(),
                    handle.auth.clone(),
                    Uuid::now_v7(),
                    context_bootstrap(&handle),
                    recall_request(query, handle.workspace_id),
                )
            };

            let started = std::time::Instant::now();
            let first = search().await;
            let first_elapsed = started.elapsed();
            assert_eq!(
                first.err(),
                Some(ErrorCode::DependencyUnavailable),
                "ADR-0065 D-G: a transient embedding failure must fail fast, not be retried"
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "ADR-0065 D-G: the failing recall must reach the worker exactly once"
            );
            assert!(
                first_elapsed < handler_timeout / 2,
                "the failing recall must return well inside its handler deadline (held its \
                 permit {first_elapsed:?})"
            );

            let started = std::time::Instant::now();
            let second = search().await.expect("the next recall answers").finish();
            // Evidence line for ADR-0065 Debt A (the first recall also pays the cold pool's connects).
            eprintln!(
                "fail-fast recall {first_elapsed:?}; answering recall {:?}",
                started.elapsed()
            );
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            let items = second.structured_content["items"]
                .as_array()
                .expect("items array");
            assert!(
                items.iter().any(
                    |item| item["memory_id"] == context_row.memory_id.to_string()
                        || item["memory_id"] == serde_json::json!(context_row.memory_id)
                ),
                "expected the seeded memory in the second recall: {items:?}"
            );
            delete_collection(&setup_transport, &setup_registry, &collection).await;
            let _ = std::fs::remove_file(&stub_socket);
        });
        // Same FK cleanup as the happy path; the stub never claims the registrations, so they
        // are removed here instead of waiting out their TTL.
        for sql in [
            "DELETE FROM projection.tenant_placements WHERE tenant_id=$1",
            "DELETE FROM ops.retrieval_embedding_rpc_calls WHERE tenant_id=$1",
        ] {
            admin
                .execute(sql, &[&handle.tenant_id])
                .expect("cleanup seeded fail-fast rows");
        }
    });
}

// ============================================================================
// T-RET-1b (ADR-0081 D-A): the query-hash log `ops.retrieval_query_log`, written by `recall::search` once per
// recall that answers Ok. Every recall below embeds to the one seeded point's vector, so each answered recall finds
// the one seeded Memory (candidates = returned = 1) over a real Qdrant collection and a real `role_gateway` pool.
// ============================================================================

/// The text whose vector the seeded point carries; the stub embedding port answers it for every query.
const LOG_SEED_TEXT: &str = "operation receipt scoped context";

/// One fixture tenant's answerable recall environment: placement, serving checkpoint, one seeded point in a disposable
/// Qdrant collection, and a stub embedding port (no worker, no provider).
struct LogEnv {
    pool: Arc<humaux_adapters::postgres::RuntimeDbPool>,
    catalog: Arc<CanonicalCatalog>,
    collection: String,
    setup_registry: IntraCellResourceRegistry,
    setup_transport: Arc<HttpIntraCellTransport>,
    registry: IntraCellResourceRegistry,
    transport: Arc<HttpIntraCellTransport>,
}

impl LogEnv {
    fn seed(handle: &mut Handle) -> Self {
        let context_row = handle.seed_workspace_visible_context_record();
        let point_id = Uuid::new_v4();
        let mut admin = handle.owner_client().expect("owner client for setup");
        seed_registry_row(
            &mut admin,
            handle.tenant_id,
            handle.workspace_id,
            context_row.memory_id,
            point_id,
        );
        seed_checkpoint(&mut admin, handle.tenant_id, handle.workspace_id);
        let collection = format!("t_ret_1b_{}", Uuid::now_v7().simple());
        seed_tenant_placement(&mut admin, handle.tenant_id, &collection);
        let cell = CellId(Uuid::now_v7());
        let caller = CallerId("gateway-wiring-test".to_owned());
        let setup_registry = setup_registry(cell, caller.clone());
        let setup_transport = qdrant_transport(&setup_registry);
        let registry = cell_registry(cell, caller);
        let transport = qdrant_transport(&registry);
        let (tenant_id, workspace_id) = (handle.tenant_id, handle.workspace_id);
        let pool = handle.rt.block_on(async {
            create_collection(&setup_transport, &setup_registry, &collection).await;
            let permit = authorize_cell_access(
                &setup_registry,
                IntraCellResource::QDRANT_REST,
                Duration::from_secs(60),
            )
            .expect("setup upsert permit");
            let point_payload = payload(tenant_id, workspace_id, time::OffsetDateTime::now_utc());
            upsert(
                setup_transport.as_ref(),
                &permit,
                &collection,
                &[(
                    PointId::Uuid(point_id),
                    &point_payload,
                    fixed_vector(LOG_SEED_TEXT),
                )],
                ha_profile_for(QdrantOperation::NormalImmutableUpsert),
            )
            .await
            .expect("real Qdrant upsert");
            Arc::new(
                // dep: PostgreSQL(role_gateway) — test fixture pool for the semantic recall wiring suite
                humaux_adapters::postgres::RuntimeDbPool::connect(&required(
                    "HUMAUX_GATEWAY_PG_DSN",
                ))
                .await
                .expect("real role_gateway pool"),
            )
        });
        Self {
            pool,
            catalog: Arc::new(CanonicalCatalog::load().expect("catalog")),
            collection,
            setup_registry,
            setup_transport,
            registry,
            transport,
        }
    }

    fn runtime(&self) -> Arc<SemanticRecallRuntime> {
        let port: Arc<dyn RetrievalEmbeddingPort> =
            Arc::new(FixedOutcomePort::new(RetrievalEmbeddingOutcome::Embedded {
                vector: fixed_vector(LOG_SEED_TEXT),
                provider_id: "wiring-test-provider".to_owned(),
                model_id: "wiring-test-embedding".to_owned(),
                model_revision: "v1".to_owned(),
                dimension: DIMENSION,
            }));
        Arc::new(
            SemanticRecallRuntime::new(
                port,
                self.transport.clone(),
                self.registry.clone(),
                SemanticRecallVersions {
                    embedding_version: EMBEDDING_VERSION.to_owned(),
                    dimension: DIMENSION,
                },
                Duration::from_secs(10),
            )
            .expect("trusted semantic runtime"),
        )
    }

    /// One `recall::search` over `pool`, finished the way the MCP layer finishes it.
    fn recall_on(
        &self,
        pool: &Arc<humaux_adapters::postgres::RuntimeDbPool>,
        handle: &Handle,
        request: RecallSearchRequest,
    ) -> Result<humaux_protocol::mcp::ToolOutput, ErrorCode> {
        handle
            .rt
            .block_on(recall::search(
                Arc::clone(pool),
                self.runtime(),
                Arc::clone(&self.catalog),
                handle.auth.clone(),
                Uuid::now_v7(),
                context_bootstrap(handle),
                request,
            ))
            .map(|pending| pending.finish())
    }

    fn recall(
        &self,
        handle: &Handle,
        query: &str,
    ) -> Result<humaux_protocol::mcp::ToolOutput, ErrorCode> {
        self.recall_on(
            &self.pool,
            handle,
            recall_request(query, handle.workspace_id),
        )
    }

    fn teardown(&self, handle: &Handle) {
        handle.rt.block_on(delete_collection(
            &self.setup_transport,
            &self.setup_registry,
            &self.collection,
        ));
        let mut admin = handle.owner_client().expect("owner client for cleanup");
        admin
            .execute(
                "DELETE FROM projection.tenant_placements WHERE tenant_id=$1",
                &[&handle.tenant_id],
            )
            .expect("cleanup seeded tenant placement row");
    }
}

/// A second fixture tenant on the same database (the fixture's serial lock is already held by the caller).
fn second_tenant() -> Handle {
    let Ok(handle) = Fixture::isolate() else {
        panic!("missing object: a second operation_receipt fixture tenant (T-RET-1b)");
    };
    handle
}

/// One `ops.retrieval_query_log` row as the owner reads it, plus the row cast to text (`t::text`).
struct LogRow {
    tenant_id: Uuid,
    workspace_id: Uuid,
    user_id: Option<Uuid>,
    query_hmac: Vec<u8>,
    key_id: String,
    cand_k: i32,
    candidates: i32,
    visible: Option<i32>,
    returned: i32,
    stage_ms: Option<serde_json::Value>,
    as_text: String,
}

/// The tenant's log rows, oldest first. Read under the tenant binding, so FORCE RLS admits the owner too.
fn log_rows(admin: &mut Client, tenant_id: Uuid) -> Vec<LogRow> {
    let mut txn = admin.transaction().expect("begin log read");
    txn.execute(
        "SELECT set_config('humaux.tenant_id', $1, true)",
        &[&tenant_id.to_string()],
    )
    .expect("bind the tenant");
    let rows = txn
        .query(
            "SELECT tenant_id, workspace_id, user_id, query_hmac, key_id, cand_k, candidates, visible, returned, \
                    stage_ms::text, t::text \
               FROM ops.retrieval_query_log t WHERE tenant_id = $1 ORDER BY called_at, log_id",
            &[&tenant_id],
        )
        .expect("read the query log");
    rows.iter()
        .map(|row| LogRow {
            tenant_id: row.get(0),
            workspace_id: row.get(1),
            user_id: row.get(2),
            query_hmac: row.get(3),
            key_id: row.get(4),
            cand_k: row.get(5),
            candidates: row.get(6),
            visible: row.get(7),
            returned: row.get(8),
            stage_ms: row
                .get::<_, Option<String>>(9)
                .map(|text| serde_json::from_str(&text).expect("stage_ms is JSON")),
            as_text: row.get(10),
        })
        .collect()
}

/// A JSON value with every leaf replaced by its type name: a response keeps its shape whatever its numbers and ids.
fn shape(value: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            Value::Object(map.iter().map(|(k, v)| (k.clone(), shape(v))).collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(shape).collect()),
        Value::Null => Value::from("null"),
        Value::Bool(_) => Value::from("bool"),
        Value::Number(_) => Value::from("number"),
        Value::String(_) => Value::from("string"),
    }
}

/// T-RET-1b L1 (ADR-0081 D-A D5): one log row per recall that answers Ok — a repeated query and a second tenant each
/// count — and none for a refused recall (an undelivered `mode`, `limit` 0). The rows carry the scope's tenant,
/// workspace and user, the envelope's counts and its `provenance.stage_ms`.
/// Fault: skip the insert for the repeated query, or insert twice ⇒ the row count moves ⇒ red.
#[test]
#[allow(clippy::too_many_lines)] // one scenario: two tenants, four answers, two refusals, then every row
fn query_log_has_one_row_per_answered_recall_and_none_for_a_refused_one() {
    run_db_fixture::<Fixture, _>("semantic_recall_wiring_query_log_rows", |mut ha| {
        ha.assert_gateway_login();
        let mut hb = second_tenant();
        let (ea, eb) = (LogEnv::seed(&mut ha), LogEnv::seed(&mut hb));
        let repeated = "t-ret-1b repeated query";
        let answers: Vec<_> = [repeated, repeated, "t-ret-1b another query"]
            .iter()
            .map(|query| ea.recall(&ha, query).expect("tenant A's recall answers"))
            .collect();
        eb.recall(&hb, repeated).expect("tenant B's recall answers");
        let mut undelivered = recall_request(repeated, ha.workspace_id);
        undelivered.mode = Some("keyword".to_owned());
        assert_eq!(
            ea.recall_on(&ea.pool, &ha, undelivered).err(),
            Some(ErrorCode::DependencyUnavailable)
        );
        let mut limit_zero = recall_request(repeated, ha.workspace_id);
        limit_zero.limit = Some(0);
        assert_eq!(
            ea.recall_on(&ea.pool, &ha, limit_zero).err(),
            Some(ErrorCode::InvalidInput)
        );

        let mut admin = ha.owner_client().expect("owner client");
        let (rows_a, rows_b) = (
            log_rows(&mut admin, ha.tenant_id),
            log_rows(&mut admin, hb.tenant_id),
        );
        assert_eq!(
            (rows_a.len(), rows_b.len()),
            (3, 1),
            "one row per answered recall, none for the two refused ones"
        );
        for (row, handle) in rows_a
            .iter()
            .map(|row| (row, &ha))
            .chain(rows_b.iter().map(|row| (row, &hb)))
        {
            assert_eq!(
                (row.tenant_id, row.workspace_id, row.user_id),
                (handle.tenant_id, handle.workspace_id, Some(handle.user_id)),
                "the scope's tenant, workspace and user"
            );
        }
        for row in rows_a.iter().chain(&rows_b) {
            // One seeded point: the live index count is 1 and the one candidate is the one Memory.
            assert_eq!(
                (row.visible, row.candidates),
                (Some(1), 1),
                "a healthy projection states a real count (§23.1②)"
            );
        }
        let (row, envelope) = (&rows_a[2], &answers[2].structured_content);
        assert_eq!(
            (row.cand_k, row.candidates, row.returned),
            (
                i32::try_from(
                    envelope["provenance"]["profile"]["cand_k"]
                        .as_i64()
                        .unwrap()
                )
                .unwrap(),
                i32::try_from(
                    envelope["completeness"]["candidate_count"]
                        .as_i64()
                        .unwrap()
                )
                .unwrap(),
                i32::try_from(envelope["completeness"]["returned"].as_i64().unwrap()).unwrap(),
            ),
            "the counts are the envelope's own"
        );
        assert_eq!(
            row.visible.map(i64::from),
            envelope["pipeline"]["projection"]["visible"].as_i64(),
            "visible is the envelope's own (NULL = not established)"
        );
        assert_eq!(
            row.stage_ms.as_ref(),
            Some(&envelope["provenance"]["stage_ms"]),
            "stage_ms is the object the answer carried"
        );
        ea.teardown(&ha);
        eb.teardown(&hb);
    });
}

/// T-RET-1b L2 (ADR-0081 D-A D3): the log row, cast to text, holds neither the query, nor its UTF-8 hex, nor its
/// unkeyed `sha256` hex, and the table has no text column but the 8-hex `key_id`.
/// Fault: store the unkeyed `sha256(query)` ⇒ its hex is in the row ⇒ red.
#[test]
fn query_log_row_holds_no_plaintext_hex_or_unkeyed_digest_of_the_query() {
    run_db_fixture::<Fixture, _>(
        "semantic_recall_wiring_query_log_no_plaintext",
        |mut handle| {
            handle.assert_gateway_login();
            let env = LogEnv::seed(&mut handle);
            let query = format!("t-ret-1b distinctive query {}", Uuid::now_v7().simple());
            env.recall(&handle, &query).expect("the recall answers");
            let mut admin = handle.owner_client().expect("owner client");
            let rows = log_rows(&mut admin, handle.tenant_id);
            assert_eq!(rows.len(), 1, "one answered recall, one row");
            let probe = admin
                .query_one(
                    "SELECT encode(convert_to($1::text, 'UTF8'), 'hex'), \
                        encode(sha256(convert_to($1::text, 'UTF8')), 'hex')",
                    &[&query],
                )
                .expect("hex and digest of the query");
            let (query_hex, digest_hex): (String, String) = (probe.get(0), probe.get(1));
            for (what, needle) in [
                ("the query", query.as_str()),
                ("its UTF-8 hex", query_hex.as_str()),
                ("its unkeyed sha256 hex", digest_hex.as_str()),
            ] {
                assert!(
                    !rows[0].as_text.contains(needle),
                    "{what} appears in the log row: {}",
                    rows[0].as_text
                );
            }
            let text_columns: Vec<String> = admin
                .query(
                    "SELECT column_name::text FROM information_schema.columns \
                  WHERE table_schema = 'ops' AND table_name = 'retrieval_query_log' \
                    AND data_type IN ('text', 'character varying', 'character') ORDER BY 1",
                    &[],
                )
                .expect("text columns of the log")
                .iter()
                .map(|row| row.get(0))
                .collect();
            assert_eq!(text_columns, ["key_id"], "no column could hold the query");
            env.teardown(&handle);
        },
    );
}

/// T-RET-1b L3 (ADR-0081 D-A D2): the digest is repeatable for one tenant, different for another tenant, never the
/// plain `sha256(query)`, equals the keyed derivation under the installed token key, and `key_id` is that key's kid.
/// Fault: drop the tenant from the derivation ⇒ the two tenants' digests are equal ⇒ red.
#[test]
fn query_hmac_is_keyed_tenant_separated_and_tagged_with_the_installed_kid() {
    run_db_fixture::<Fixture, _>("semantic_recall_wiring_query_log_keyed", |mut ha| {
        ha.assert_gateway_login();
        let mut hb = second_tenant();
        let (ea, eb) = (LogEnv::seed(&mut ha), LogEnv::seed(&mut hb));
        let query = "t-ret-1b keyed query";
        ea.recall(&ha, query).expect("tenant A answers");
        ea.recall(&ha, query).expect("tenant A answers again");
        eb.recall(&hb, query).expect("tenant B answers");
        let mut admin = ha.owner_client().expect("owner client");
        let (rows_a, rows_b) = (
            log_rows(&mut admin, ha.tenant_id),
            log_rows(&mut admin, hb.tenant_id),
        );
        assert_eq!((rows_a.len(), rows_b.len()), (2, 1));
        assert_eq!(
            rows_a[0].query_hmac, rows_a[1].query_hmac,
            "the same query in the same tenant gives the same digest"
        );
        assert_ne!(
            rows_a[0].query_hmac, rows_b[0].query_hmac,
            "the same query in another tenant gives another digest"
        );
        let plain: Vec<u8> = admin
            .query_one("SELECT sha256(convert_to($1::text, 'UTF8'))", &[&query])
            .expect("plain digest")
            .get(0);
        for row in [&rows_a[0], &rows_b[0]] {
            assert_ne!(
                row.query_hmac, plain,
                "the digest is keyed, not sha256(query)"
            );
            assert_eq!(row.query_hmac.len(), 32);
        }
        for (row, handle) in [(&rows_a[0], &ha), (&rows_b[0], &hb)] {
            let expected =
                humaux_adapters::retrieve::query_hmac(TenantId(handle.tenant_id), query.as_bytes())
                    .expect("the fixture installed the token key set");
            assert_eq!(row.query_hmac, expected.mac(), "the card's derivation");
            assert_eq!(row.key_id, expected.key_id(), "the installed kid");
        }
        ea.teardown(&ha);
        eb.teardown(&hb);
    });
}

/// T-RET-1b L4 (ADR-0081 D-A D4): under the runtime role, an INSERT for another tenant is refused by RLS (the control
/// insert for its own tenant is not), and SELECT, UPDATE and DELETE are refused outright.
/// Fault: drop the policy's WITH CHECK clause or the policy itself ⇒ the cross-tenant insert lands, or the control
/// insert is refused ⇒ red.
#[test]
fn query_log_is_insert_only_and_tenant_isolated_for_the_gateway_role() {
    use postgres::error::SqlState;
    run_db_fixture::<Fixture, _>("semantic_recall_wiring_query_log_isolation", |ha| {
        ha.assert_gateway_login();
        let hb = second_tenant();
        let mut gateway = ha.gateway_client().expect("role_gateway login");
        let insert = "INSERT INTO ops.retrieval_query_log \
                        (tenant_id, workspace_id, query_hmac, key_id, cand_k, candidates, returned) \
                      VALUES ($1, $2, decode(repeat('00', 32), 'hex'), '00000000', 0, 0, 0)";
        let bind = "SELECT set_config('humaux.tenant_id', $1, true)";
        let tenant_a = ha.tenant_id.to_string();
        let mut txn = gateway.transaction().expect("begin");
        txn.execute(bind, &[&tenant_a]).expect("bind tenant A");
        assert_eq!(
            txn.execute(insert, &[&ha.tenant_id, &ha.workspace_id])
                .expect("the gateway inserts its own tenant's row"),
            1
        );
        txn.rollback().expect("roll the control row back");
        let mut txn = gateway.transaction().expect("begin");
        txn.execute(bind, &[&tenant_a]).expect("bind tenant A");
        let refused = txn
            .execute(insert, &[&hb.tenant_id, &hb.workspace_id])
            .expect_err("a cross-tenant insert is refused");
        assert_eq!(
            refused.code(),
            Some(&SqlState::INSUFFICIENT_PRIVILEGE),
            "{refused}"
        );
        assert!(
            refused
                .as_db_error()
                .is_some_and(|e| e.message().contains("row-level security")),
            "the refusal is the policy's: {refused}"
        );
        drop(txn);
        for (verb, sql) in [
            ("SELECT", "SELECT count(*) FROM ops.retrieval_query_log"),
            ("UPDATE", "UPDATE ops.retrieval_query_log SET cand_k = 0"),
            ("DELETE", "DELETE FROM ops.retrieval_query_log"),
        ] {
            let denied = gateway
                .execute(sql, &[])
                .expect_err("the runtime role holds INSERT and nothing else");
            assert_eq!(
                denied.code(),
                Some(&SqlState::INSUFFICIENT_PRIVILEGE),
                "{verb}: {denied}"
            );
        }
    });
}

/// T-RET-1b L5 (ADR-0081 D-A D5): with the log INSERT failing (every session of this pool starts read-only, so the
/// recall's reads succeed and only the INSERT raises 25006) the recall still answers Ok, with the shape of a passing
/// run, and no row is written.
/// Fault: let the insert error propagate as the recall's error ⇒ the recall is refused ⇒ red.
#[test]
fn a_failing_log_insert_does_not_fail_the_recall() {
    run_db_fixture::<Fixture, _>(
        "semantic_recall_wiring_query_log_insert_failure",
        |mut handle| {
            handle.assert_gateway_login();
            let env = LogEnv::seed(&mut handle);
            let query = "t-ret-1b insert failure";
            let passing = env.recall(&handle, query).expect("a passing run answers");
            let mut admin = handle.owner_client().expect("owner client");
            assert_eq!(log_rows(&mut admin, handle.tenant_id).len(), 1);
            let read_only_dsn = format!(
                "{}?options=-c%20default_transaction_read_only%3Don",
                handle.gateway_dsn_for_process()
            );
            let read_only = handle.rt.block_on(async {
                Arc::new(
                    // dep: PostgreSQL(role_gateway) — test fixture pool whose sessions default to read-only
                    humaux_adapters::postgres::RuntimeDbPool::connect(&read_only_dsn)
                        .await
                        .expect("read-only role_gateway pool"),
                )
            });
            let degraded = env
                .recall_on(
                    &read_only,
                    &handle,
                    recall_request(query, handle.workspace_id),
                )
                .expect("the recall still answers when its log insert fails");
            assert_eq!(
                log_rows(&mut admin, handle.tenant_id).len(),
                1,
                "the failed insert left no row"
            );
            assert_eq!(
                shape(&degraded.structured_content),
                shape(&passing.structured_content),
                "the response keeps the shape of a passing run"
            );
            env.teardown(&handle);
        },
    );
}
