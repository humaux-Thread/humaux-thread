//! `gateway::tests::recall_embedding_cache` — M12 gates G-M12-6 and G-M12-7: the gateway's `CachedEmbeddingPort` in
//!   front of the real ADR-0012 query-embedding client and an in-process `humaux-retrieval-worker` RPC app.
//! Depends-on: crates=[async-trait, axum, humaux-adapters, humaux-application, humaux-cache, humaux-domain,
//!   humaux-infra-cell, humaux-local-secret-scan, humaux-retrieval-provider, humaux-retrieval-worker,
//!   sqlx, tokio, uuid];
//!   services=[PostgreSQL(role_gateway) r=[ops.retrieval_embedding_rpc_calls], PostgreSQL(role_retrieval_worker),
//!   UDS(retrieval-worker), UDS(serve)]; env=[HUMAUX_GATEWAY_PG_DSN, HUMAUX_RETRIEVAL_WORKER_PG_DSN,
//!   HUMAUX_TEST_GITLEAKS_BIN, HUMAUX_TEST_GITLEAKS_SHA256, HUMAUX_TEST_GITLEAKS_VERSION]; modules=[adapters::postgres,
//!   application::retrieval_embedding_port, cache::bounded, domain::error, domain::identity, domain::ids,
//!   gateway::cached_embedding, gateway::retrieval_embedding_client, humaux-local-secret-scan, infra-cell::permit,
//!   infra-cell::resource,
//!   retrieval-provider::adapters, retrieval-provider::contract, retrieval-worker::rpc]
//! Called-by: [cargo-test]
//! Invariants: [a missing PostgreSQL DSN or gitleaks pin fails the test, it never skips (ADR-0050); each test uses a
//!   fresh tenant, so registration counts are its own]
//! Spec: Baseline §51; ADR-0012; ADR-0076
//!
//! G-M12-6 counts `ops.retrieval_embedding_rpc_calls` rows, the registration every uncached recall writes before it
//! dials the worker: a hit writes none. It drives the port `recall.search` calls, not the Qdrant / PostgreSQL stages
//! behind it, which the cache does not touch. Fault: bypass the decorator (call the inner port directly) ⇒ the second
//! identical call registers a second row ⇒ red. G-M12-7 uses an in-process port stub. Fault: insert regardless of
//! the stamp ⇒ the second call after a foreign stamp is a hit ⇒ red. The W2 tests pin that the cache never answers
//! a call the inner client refuses. Fault: drop the guard in front of the cache lookup ⇒ a hit is served for a workspace
//! outside the scope, and a service principal's call is cached ⇒ red.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tokio::net::{UnixListener, UnixStream};
use uuid::Uuid;

use humaux_adapters::postgres::{RetrievalWorkerDbPool, RuntimeDbPool};
use humaux_application::retrieval_embedding_port::{
    RetrievalEmbeddingInput, RetrievalEmbeddingOutcome, RetrievalEmbeddingPort,
};
use humaux_cache::CacheConfig;
use humaux_domain::error::ErrorCode;
use humaux_domain::identity::{AuthorizationScope, BoundedSet, PrincipalId};
use humaux_domain::ids::{TenantId, UserId, WorkspaceId};
use humaux_gateway::cached_embedding::{CachedEmbeddingPort, GenerationStamp};
use humaux_gateway::retrieval_embedding_client::GatewayRetrievalEmbeddingClient;
use humaux_infra_cell::{
    CallerId, CellId, IntraCellResource, IntraCellResourceRegistry, ResourceEntry,
};
use humaux_local_secret_scan::{LocalSecretScanner, LocalSecretScannerConfig};
use humaux_retrieval_provider::adapters::TestDoubleProvider;
use humaux_retrieval_provider::contract::{
    CalibrationProfileId, EmbeddingModelDescriptor, ModelId, RerankModelDescriptor,
    RerankScoreSemantics,
};
use humaux_retrieval_worker::rpc::{PeerIdentity, RpcState, router};

const DIMENSION: u32 = 4;
const PROVIDER_ID: &str = "cache-test-provider";
const MODEL_ID: &str = "cache-test-embedding";
const MODEL_REVISION: &str = "v1";

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing required test env {name}"))
}

/// `/tmp` directly: a macOS temp dir plus a name overflows `sockaddr_un`'s path limit.
fn temp_socket_path(tag: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/tmp/hc-{tag}-{}.sock", Uuid::now_v7().simple()))
}

/// Mirrors `tests/query_embedding_rpc.rs`'s helper (separate test binary).
async fn own_uid() -> u32 {
    let path = temp_socket_path("uid");
    // dep: UDS(serve) — test binds a probe socket to read the peer uid
    let listener = UnixListener::bind(&path).expect("bind uid probe socket");
    // dep: UDS(retrieval-worker) — test dials the probe socket as the retrieval-worker client would
    let client = UnixStream::connect(&path).await.expect("connect uid probe");
    let (server_side, _) = listener.accept().await.expect("accept uid probe");
    let uid = server_side.peer_cred().expect("peer credential").uid();
    drop(client);
    drop(server_side);
    let _ = std::fs::remove_file(&path);
    uid
}

fn embedding_model() -> EmbeddingModelDescriptor {
    EmbeddingModelDescriptor {
        model_id: ModelId(MODEL_ID.to_owned()),
        model_revision: MODEL_REVISION.to_owned(),
        dimension_options: vec![DIMENSION],
        max_input_tokens: 1_000,
        max_batch_items: std::num::NonZeroU32::new(10).expect("non-zero cap"),
        batch_supported: true,
        dense_supported: true,
        sparse_supported: false,
    }
}

fn rerank_model() -> RerankModelDescriptor {
    RerankModelDescriptor {
        model_id: ModelId("unused-rerank-model".to_owned()),
        model_revision: "v1".to_owned(),
        max_documents: 10,
        max_input_tokens: 1_000,
        score_semantics: RerankScoreSemantics::RawLogit,
        calibration_profile: CalibrationProfileId("unused".to_owned()),
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
        .expect("valid scanner config"),
    )
}

/// The real retrieval-worker RPC app on a temporary socket (mirrors `tests/query_embedding_rpc.rs`).
async fn spawn_worker(expected_gateway_uid: u32) -> String {
    let socket_path = temp_socket_path("worker");
    // dep: PostgreSQL(role_retrieval_worker) — the worker claims and finishes each registered call
    let calls = RetrievalWorkerDbPool::connect(&required("HUMAUX_RETRIEVAL_WORKER_PG_DSN"))
        .await
        .expect("retrieval worker db pool");
    let state = Arc::new(RpcState {
        expected_gateway_uid,
        calls,
        pg_dsn: required("HUMAUX_RETRIEVAL_WORKER_PG_DSN"),
        scanner: scanner(),
        embedder: Arc::new(TestDoubleProvider::new(embedding_model(), rerank_model())),
        dimension: DIMENSION,
        provider_id: PROVIDER_ID.to_owned(),
    });
    // dep: UDS(serve) — test serves the real retrieval-worker RPC router on a temp socket
    let listener = UnixListener::bind(&socket_path).expect("bind worker rpc socket");
    // ADR-0066 D-L: the gateway's dial refuses a socket with `other` bits; a server socket is 0660.
    std::fs::set_permissions(
        &socket_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o660),
    )
    .expect("chmod the worker rpc socket");
    let app = router(state);
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<PeerIdentity>(),
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    socket_path.to_string_lossy().into_owned()
}

fn cell_registry() -> IntraCellResourceRegistry {
    let cell_id = CellId(Uuid::now_v7());
    let caller = CallerId("gateway-cache-test".to_owned());
    let mut entries = BTreeMap::new();
    entries.insert(
        IntraCellResource::RETRIEVAL_EMBEDDING_RPC,
        ResourceEntry::new(
            "unix-socket",
            0,
            cell_id,
            vec![],
            BTreeSet::from([caller.clone()]),
            false,
        )
        .expect("valid resource entry"),
    );
    IntraCellResourceRegistry::new(entries, cell_id, caller)
}

fn stamp() -> GenerationStamp {
    GenerationStamp {
        embedding_version: "embed-v1".to_owned(),
        provider_id: PROVIDER_ID.to_owned(),
        model_id: MODEL_ID.to_owned(),
        model_revision: MODEL_REVISION.to_owned(),
        dimension: DIMENSION,
    }
}

fn cache_config() -> CacheConfig {
    CacheConfig {
        capacity_bytes: 1 << 20,
        per_tenant_bytes: 1 << 20,
        ttl: Duration::from_secs(600),
        enabled: true,
    }
}

fn scope(tenant: TenantId, user: Option<UserId>, workspace_id: WorkspaceId) -> AuthorizationScope {
    AuthorizationScope::new(
        tenant,
        PrincipalId::new(),
        user,
        BoundedSet::new([workspace_id]).expect("bounded workspace set"),
    )
}

fn user_scope(tenant: TenantId, workspace_id: WorkspaceId) -> AuthorizationScope {
    scope(tenant, Some(UserId::new()), workspace_id)
}

fn deadline_unix_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_millis(),
    )
    .expect("deadline fits i64")
        + 30_000
}

/// One embedding as `recall.search` asks for it: fresh request and logical call ids every time.
async fn recall_embed(
    port: &dyn RetrievalEmbeddingPort,
    scope: &AuthorizationScope,
    workspace_id: WorkspaceId,
    query: &str,
) -> RetrievalEmbeddingOutcome {
    embed(port, scope, workspace_id, query)
        .await
        .expect("typed outcome")
}

/// [`recall_embed`] without unwrapping the port's `ErrorCode`.
async fn embed(
    port: &dyn RetrievalEmbeddingPort,
    scope: &AuthorizationScope,
    workspace_id: WorkspaceId,
    query: &str,
) -> Result<RetrievalEmbeddingOutcome, ErrorCode> {
    let request_id = Uuid::now_v7();
    let profile_fingerprint = format!("sha256:{}", "a".repeat(64));
    port.embed_query(RetrievalEmbeddingInput {
        authorization: scope,
        workspace_id,
        request_id,
        logical_call_id: request_id,
        attempt_no: 1,
        profile_fingerprint: &profile_fingerprint,
        dimension: DIMENSION,
        query,
        deadline_unix_ms: deadline_unix_ms(),
    })
    .await
}

/// The outcome's variant only: failure messages never print a vector, a stamp or anything of the caller's scope.
fn kind(outcome: &RetrievalEmbeddingOutcome) -> &'static str {
    match outcome {
        RetrievalEmbeddingOutcome::Embedded { .. } => "Embedded",
        RetrievalEmbeddingOutcome::Skipped => "Skipped",
        RetrievalEmbeddingOutcome::Unavailable { .. } => "Unavailable",
    }
}

/// Registration rows of `tenant`, read as `role_gateway` under that tenant's RLS context.
async fn registered_calls(pool: &sqlx::PgPool, tenant: TenantId) -> i64 {
    // dep: PostgreSQL(role_gateway) — one read transaction carrying the tenant RLS context
    let mut tx = pool.begin().await.expect("begin count transaction");
    sqlx::query("SELECT set_config('humaux.tenant_id', $1, true)")
        .bind(tenant.0.to_string())
        .execute(&mut *tx)
        .await
        .expect("set tenant context");
    let n: i64 = sqlx::query_scalar(
        "SELECT count(call_id) FROM ops.retrieval_embedding_rpc_calls WHERE tenant_id = $1",
    )
    .bind(tenant.0)
    .fetch_one(&mut *tx)
    .await
    .expect("count registrations");
    tx.rollback().await.expect("end count transaction");
    n
}

/// The decorator over the real client and worker, and a `role_gateway` pool to count registrations with.
async fn real_port() -> (CachedEmbeddingPort, sqlx::PgPool) {
    let socket_path = spawn_worker(own_uid().await).await;
    // dep: PostgreSQL(role_gateway) — the gateway's registration pool behind the real client
    let gateway_pool = RuntimeDbPool::connect(&required("HUMAUX_GATEWAY_PG_DSN"))
        .await
        .expect("runtime db pool");
    let client = GatewayRetrievalEmbeddingClient::new(
        Arc::new(gateway_pool),
        socket_path,
        own_uid().await,
        cell_registry(),
        Duration::from_secs(30),
    );
    let port = CachedEmbeddingPort::new(Arc::new(client), stamp(), cache_config());
    // dep: PostgreSQL(role_gateway) — reads the registration rows this test's tenant wrote
    let count_pool = sqlx::PgPool::connect(&required("HUMAUX_GATEWAY_PG_DSN"))
        .await
        .expect("role_gateway count pool");
    (port, count_pool)
}

/// G-M12-6: two identical recalls by one user register one RPC call, not two, and get the same vector; the same
/// text from another user of the same tenant is its own namespace (M12 D3) and registers one more.
#[tokio::test]
async fn identical_recall_by_one_user_registers_one_call_and_another_user_one_more() {
    let (port, count_pool) = real_port().await;

    let tenant = TenantId::new();
    let workspace_id = WorkspaceId::new();
    let alice = user_scope(tenant, workspace_id);
    let bob = user_scope(tenant, workspace_id);
    let query = "which contract froze the retrieval profile?";
    assert_eq!(registered_calls(&count_pool, tenant).await, 0);

    let first = recall_embed(&port, &alice, workspace_id, query).await;
    assert!(
        matches!(first, RetrievalEmbeddingOutcome::Embedded { .. }),
        "the first recall embeds through the worker, got {}",
        kind(&first)
    );
    assert_eq!(registered_calls(&count_pool, tenant).await, 1);

    let second = recall_embed(&port, &alice, workspace_id, query).await;
    assert_eq!(
        registered_calls(&count_pool, tenant).await,
        1,
        "G-M12-6: an identical recall by the same user must be a hit, not a second RPC registration"
    );
    assert!(second == first, "a hit returns the identical outcome");

    let other_user = recall_embed(&port, &bob, workspace_id, query).await;
    assert_eq!(
        registered_calls(&count_pool, tenant).await,
        2,
        "G-M12-6: another user's identical recall is its own namespace and registers one more call"
    );
    assert!(
        other_user == first,
        "same text, same generation, same vector"
    );
}

/// Answers every call with one fixed outcome and counts the calls.
struct StubPort {
    outcome: RetrievalEmbeddingOutcome,
    calls: AtomicUsize,
}

#[async_trait]
impl RetrievalEmbeddingPort for StubPort {
    async fn embed_query(
        &self,
        _input: RetrievalEmbeddingInput<'_>,
    ) -> Result<RetrievalEmbeddingOutcome, ErrorCode> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.outcome.clone())
    }
}

/// Inner calls made by two identical recalls through a fresh cache over a stub answering with `model_id`, the stub's
/// outcome, and what the two recalls returned.
async fn inner_calls_for_two_recalls(
    model_id: &str,
) -> (
    usize,
    RetrievalEmbeddingOutcome,
    Vec<RetrievalEmbeddingOutcome>,
) {
    let outcome = RetrievalEmbeddingOutcome::Embedded {
        vector: vec![0.25; DIMENSION as usize],
        provider_id: PROVIDER_ID.to_owned(),
        model_id: model_id.to_owned(),
        model_revision: MODEL_REVISION.to_owned(),
        dimension: DIMENSION,
    };
    let stub = Arc::new(StubPort {
        outcome: outcome.clone(),
        calls: AtomicUsize::new(0),
    });
    let port = CachedEmbeddingPort::new(stub.clone(), stamp(), cache_config());
    let workspace_id = WorkspaceId::new();
    let scope = user_scope(TenantId::new(), workspace_id);
    let mut got = Vec::new();
    for _ in 0..2 {
        got.push(recall_embed(&port, &scope, workspace_id, "same query twice").await);
    }
    (stub.calls.load(Ordering::SeqCst), outcome, got)
}

/// G-M12-7: a worker answering with another model's stamp is passed through but never cached, so the next identical
/// call misses (M12 D4). The matching-stamp control proves this cache does store, so the assertion cannot pass
/// vacuously on a cache that stores nothing.
#[tokio::test]
async fn incompatible_stamp_not_cached() {
    let (calls, outcome, got) = inner_calls_for_two_recalls("another-embedding-model").await;
    assert_eq!(
        calls, 2,
        "G-M12-7: an incompatible stamp must not be cached; the next identical call must miss"
    );
    assert!(
        got == [outcome.clone(), outcome],
        "a foreign stamp passes through unchanged"
    );
    let (control, outcome, got) = inner_calls_for_two_recalls(MODEL_ID).await;
    assert_eq!(control, 1, "control: the generation's own stamp is cached");
    assert!(
        got == [outcome.clone(), outcome],
        "a hit returns the stored outcome"
    );
}

/// W2: an entry alice populated in workspace A is not served to alice's scope once A is outside its allowed set; the
/// inner client's Forbidden comes back and no registration is written. A service principal (no user) gets the inner
/// Unauthorized. The recall caller narrows the workspace first today; this pins that the cache does not rely on it.
#[tokio::test]
async fn cache_never_answers_a_call_the_inner_client_refuses() {
    let (port, count_pool) = real_port().await;
    let tenant = TenantId::new();
    let (workspace_a, workspace_b) = (WorkspaceId::new(), WorkspaceId::new());
    let alice = UserId::new();
    let query = "what did the access review decide?";

    let populated = recall_embed(
        &port,
        &scope(tenant, Some(alice), workspace_a),
        workspace_a,
        query,
    )
    .await;
    assert!(
        matches!(populated, RetrievalEmbeddingOutcome::Embedded { .. }),
        "the populating recall embeds through the worker, got {}",
        kind(&populated)
    );
    assert_eq!(registered_calls(&count_pool, tenant).await, 1);

    let outside = embed(
        &port,
        &scope(tenant, Some(alice), workspace_b),
        workspace_a,
        query,
    )
    .await;
    assert!(
        outside == Err(ErrorCode::Forbidden),
        "W2: a workspace outside the scope's allowed set must get the inner Forbidden, never a cached vector"
    );
    let service = embed(&port, &scope(tenant, None, workspace_a), workspace_a, query).await;
    assert!(
        service == Err(ErrorCode::Unauthorized),
        "W2: a scope without a user must get the inner Unauthorized"
    );
    assert_eq!(
        registered_calls(&count_pool, tenant).await,
        1,
        "refused calls register nothing"
    );
}

/// W2: a service principal's call reaches the inner port every time, even one that answers it, so it is never cached.
#[tokio::test]
async fn service_principal_call_is_never_cached() {
    let stub = Arc::new(StubPort {
        outcome: RetrievalEmbeddingOutcome::Embedded {
            vector: vec![0.5; DIMENSION as usize],
            provider_id: PROVIDER_ID.to_owned(),
            model_id: MODEL_ID.to_owned(),
            model_revision: MODEL_REVISION.to_owned(),
            dimension: DIMENSION,
        },
        calls: AtomicUsize::new(0),
    });
    let port = CachedEmbeddingPort::new(stub.clone(), stamp(), cache_config());
    let workspace_id = WorkspaceId::new();
    let service = scope(TenantId::new(), None, workspace_id);
    for _ in 0..2 {
        recall_embed(&port, &service, workspace_id, "service principal query").await;
    }
    assert_eq!(
        stub.calls.load(Ordering::SeqCst),
        2,
        "W2: a scope without a user must bypass the cache"
    );
}
