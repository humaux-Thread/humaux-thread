//! `gateway::recall` — Native authenticated semantic recall wiring.
//! Depends-on: crates=[async-trait, humaux-adapters, humaux-application, humaux-domain, humaux-infra-cell,
//!   humaux-contracts, humaux-projection, humaux-protocol, humaux-retrieval, serde_json, time, tokio, uuid]; services=[]; env=[]; modules=[adapters::affect_repo, adapters::memory_repo, adapters::placement_repo, adapters::postgres, adapters::projection_worker, adapters::qdrant, adapters::read_materialize, adapters::retrieval_query_log, adapters::retrieve, adapters::serving_repo, application::affect, application::retrieval_embedding_port, application::retrieve, contracts::retrieval_config, domain::affect, domain::error, domain::identity, domain::ids, domain::subject, gateway::context, gateway::rerank_client, infra-cell::permit, infra-cell::resource, infra-cell::transport, projection::dense, projection::note_chunks, projection::sparse, projection::stream, protocol::mcp, protocol::mcp_catalog, retrieval::completeness, retrieval::envelope, retrieval::planner, retrieval::request, retrieval::rerank]
//! Called-by: [gateway::bootstrap, gateway::context, gateway::mcp_application, tests]
//! Invariants: [this module owns no alternate search or body fallback path; a Qdrant or provider failure surfaces as the typed retrieval error, never a degraded silent result; Qdrant is asked for leg_depth Memories per leg for this request's workspace stream only, the dense and the sparse leg concurrently with one filter (ADR-0083 D-C), and the memory-level RRF of the two legs is cut to cand_k before the PG gate, which runs on that fused list unchanged; the sparse leg alone is bounded by the registered sparse_timeout_ms and its elapse is a sparse failure; a sparse-leg failure answers from the dense leg through retrieval::envelope::sparse_lane_unavailable (emitted in accepted_output, never before the hydrate gate) and never fails the recall, a dense-leg failure is the typed error as before; memory items are cut to top_k after the PG gate, the mood rerank permutes only that visible set (ADR-0030 D-D), then limit shortens it; every planner class is answered by dense (LANE_SUBSTITUTED unless the caller named a mode), only an explicit undelivered mode refuses; stage_ms partitions answer() exhaustively and is reported only when every lap followed LAP_SEQUENCE, with qdrant_sparse as a sub-timing contained in qdrant (present only when the sparse leg ran); search() hands the query-hash log row to a bounded, supervised spawn after answer() returns, once per answered recall, and never awaits the insert, so no lap, no LAP_SEQUENCE entry, no response byte and no handler deadline depends on it, and a failed or dropped insert never fails the recall (ADR-0081 D-A); when the profile turns the local rerank lane on and tenant policy allows in-Cell text processing, the texts of the lane are read by the hydrate transaction for the Memories that passed its gate and for no others, only those are sent to the worker, the rerank is order only (retrieval::rerank), and a timeout, a failure or another model's answer keeps the fused order and reports RERANK_PROVIDER_TIMEOUT / RERANK_MODEL_MISMATCH from accepted_output with a cannot_establish rerank_model_id (ADR-0084 D-C, D-D)]
//! Spec: Baseline §17.3; §17.6; §19.1; §23.3; §33; §48.1; §55.1; §78.1; ADR-0029; ADR-0031; ADR-0055; ADR-0056; ADR-0081; ADR-0083; ADR-0084
//!
//! This module composes the existing request builder, the retrieval-worker query embedding
//! (which alone seals the query, ADR-0056 D-C), same-Cell Qdrant candidate lookup, and the sole
//! PostgreSQL final hydration boundary. It owns no alternate search or body fallback.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{Arc, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use humaux_adapters::{
    affect_repo,
    memory_repo::MemoryText,
    placement_repo::tenant_placement,
    postgres::RuntimeDbPool,
    projection_worker::in_cell_text_processing_allowed,
    qdrant::{
        DenseCandidate, DenseQuery, DenseQueryVersions, PointId, QdrantOperation,
        QdrantTransportError, RetrievalFamily, ha_profile_for, query_dense,
        query_dense_groups_bounded, query_sparse_groups,
    },
    read_materialize::MaterializedItem,
    retrieval_query_log::QueryLogCounts,
    retrieve::{
        GatedTexts, IndexFace, MaterializedPrivateReadServing, PointSlots, QueryHmac,
        RetrieveError, grouped_recall, materialize_private_read_serving_about, query_hmac,
        query_log_limits, record_recall_query, tombstoned_source_seqs, visible_index_count,
    },
    serving_repo::{UnservedLedger, family_read_state},
};
use tokio::sync::Semaphore;

use humaux_application::affect::rerank_by_mood;
use humaux_application::{
    retrieval_embedding_port::{
        RetrievalEmbeddingInput, RetrievalEmbeddingOutcome, RetrievalEmbeddingPort,
    },
    retrieve::{RetrievalIntent, prepare_request},
};
use humaux_contracts::retrieval_config::RETRIEVAL_GROUP_QUERY_MAX_CALLS;
use humaux_domain::{
    affect::{AffectFilter, MoodPoint},
    error::ErrorCode,
    identity::AuthorizationScope,
    ids::{TenantId, WorkspaceId},
    subject::SubjectId,
};
use humaux_infra_cell::{
    CellAccessPermit, IntraCellHttpTransport, IntraCellResource, IntraCellResourceRegistry,
    authorize_cell_access,
};
use humaux_projection::{
    dense::DenseQueryFilter,
    note_chunks::rerank_document,
    sparse::{SparseLane, build_sparse_lane},
    stream::StreamKey,
};
use humaux_protocol::{
    mcp::{ToolName, ToolOutput},
    mcp_catalog::CanonicalCatalog,
};
use humaux_retrieval::{
    completeness::{CensusResult, FreshnessClass, LedgerClosure},
    envelope::{
        CompletenessBlock, CompletenessInputs, Envelope, FreshnessBlock, LaneStatus,
        MandatoryReport, PendingEnvelope, PinnedReport, PipelineBlock, ProfileBlock,
        ProvenanceBlock, ProvenanceValue, build_projection_block, dense_lane_outcome_block,
        dense_lane_substitution, no_serving_projection_envelope, sparse_lane_unavailable,
    },
    planner::QueryClass,
    rerank::{Executor, RerankFailure, degradations, not_run, settle, unavailable},
};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ContextBootstrap;
use crate::rerank_client::{RerankAnswer, RerankCall, RerankLane};

/// Bootstrap-owned components for the one native private-memory dense lane.
///
/// Holds no [`TenantPlacementRow`](humaux_adapters::qdrant::TenantPlacementRow) — an earlier
/// shape baked in exactly one tenant's placement at construction time, which made every other
/// tenant's `recall.search` call assert against it and fail closed. [`search`] resolves a
/// placement per request instead, through [`tenant_placement`], so this runtime carries no
/// single-tenant assumption at all (ADR-0012 gateway wiring card).
///
/// Holds `port: Arc<dyn RetrievalEmbeddingPort>`, not a provider trait object — §4.2:
/// the gateway process must never hold a provider descriptor/credential; the real
/// implementation (`crate::retrieval_embedding_client::GatewayRetrievalEmbeddingClient`) RPCs
/// `humaux-retrieval-worker`, which alone calls the real provider.
pub struct SemanticRecallRuntime {
    port: Arc<dyn RetrievalEmbeddingPort>,
    qdrant: Arc<dyn IntraCellHttpTransport>,
    cell_registry: IntraCellResourceRegistry,
    embedding_version: String,
    dimension: u32,
    /// Bounds [`RetrievalEmbeddingInput::deadline_unix_ms`] — the gateway's own configured
    /// handler timeout (`bins/gateway/src/guard.rs::GuardSettings::handler_timeout`), not a
    /// literal (§78.1).
    handler_timeout: Duration,
    /// ADR-0081 D-A D5: the query-hash log's in-flight writes and their deadline, derived from the pool on first use.
    query_log_gate: OnceLock<(Arc<Semaphore>, Duration)>,
    /// ADR-0084 D-B: the local rerank lane (the worker client and the deployment model pin); `None` when no worker
    /// serves rerank, which a profile that turns the lane on does not allow (bootstrap refuses it).
    rerank: Option<RerankLane>,
    /// ADR-0084 D-B Policy / ADR-0083 U4: the one in-Cell text-processing decision per tenant, read once per request
    /// for both the sparse leg and the rerank branch. Production leaves the default, `in_cell_text_processing_allowed`;
    /// a test sets another through [`SemanticRecallRuntime::with_text_processing_policy`].
    text_processing_allowed: fn(TenantId) -> bool,
}

/// `ContextBootstrap` derives `Debug` and now carries an optional handle to this runtime, so
/// the runtime needs one. Deliberately opaque: every field here is either a credential-adjacent
/// handle (embedding port, Qdrant transport, Cell registry) or a version string already
/// reported in `provenance`. Formatting them would put transport/permit detail into any operator
/// line that `{:?}`s a bootstrap.
impl std::fmt::Debug for SemanticRecallRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SemanticRecallRuntime")
    }
}

pub struct SemanticRecallVersions {
    pub embedding_version: String,
    pub dimension: u32,
}

impl SemanticRecallRuntime {
    pub fn new(
        port: Arc<dyn RetrievalEmbeddingPort>,
        qdrant: Arc<dyn IntraCellHttpTransport>,
        cell_registry: IntraCellResourceRegistry,
        versions: SemanticRecallVersions,
        handler_timeout: Duration,
        rerank: Option<RerankLane>,
    ) -> Result<Self, ErrorCode> {
        let SemanticRecallVersions {
            embedding_version,
            dimension,
        } = versions;
        if embedding_version.trim().is_empty() || dimension == 0 || handler_timeout.is_zero() {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self {
            port,
            qdrant,
            cell_registry,
            embedding_version,
            dimension,
            handler_timeout,
            query_log_gate: OnceLock::new(),
            rerank,
            text_processing_allowed: in_cell_text_processing_allowed,
        })
    }

    /// A runtime that reads `policy` instead of `in_cell_text_processing_allowed` for every tenant. The production
    /// function is a stub that always allows (its `ponytail`), so a test that must see a tenant whose policy forbids
    /// in-Cell text processing sets it here; bootstrap never does.
    #[must_use]
    pub fn with_text_processing_policy(mut self, policy: fn(TenantId) -> bool) -> Self {
        self.text_processing_allowed = policy;
        self
    }

    /// At most a quarter of the pool (minimum one) writes log rows at once, so the log can never take the answer path's
    /// connections, and a write lives no longer than the pool's own acquire timeout. Both derive from the pool's
    /// registered settings (§78.1: no new key).
    fn query_log_gate(&self, pool: &RuntimeDbPool) -> &(Arc<Semaphore>, Duration) {
        self.query_log_gate.get_or_init(|| {
            let (max_connections, acquire_timeout) = query_log_limits(pool);
            let permits = usize::try_from(max_connections / 4)
                .unwrap_or(usize::MAX)
                .max(1);
            (Arc::new(Semaphore::new(permits)), acquire_timeout)
        })
    }

    /// §23.1② live `visible` for the two PG-only read routes (`memory.*`, `context.assemble`),
    /// which hold no Qdrant transport of their own. They reach this through
    /// [`crate::context::ContextBootstrap::visible_index_count`]; `recall.search` skips it and
    /// calls `humaux_adapters::retrieve::visible_index_count` directly, because it has already
    /// resolved the placement and the permit for its own dense query and must not pay for a
    /// second placement round trip. The counting rules themselves live in exactly one place —
    /// that adapter function — not here.
    pub(crate) async fn visible_index_count(
        &self,
        pool: &RuntimeDbPool,
        authorization: &AuthorizationScope,
        key: &StreamKey,
        serving_version: Option<&str>,
        ledger: &LedgerClosure,
    ) -> Option<u64> {
        let placement = tenant_placement(
            pool,
            authorization.tenant_id(),
            RetrievalFamily::PrivateMemoryV1,
        )
        .await
        .ok()??;
        let permit = self.qdrant_permit().ok()?;
        visible_index_count(
            pool,
            authorization,
            IndexFace {
                transport: self.qdrant.as_ref(),
                permit: &permit,
                collection: &placement.collection_name,
            },
            key,
            serving_version,
            ledger,
        )
        .await
    }

    fn qdrant_permit(&self) -> Result<CellAccessPermit, ErrorCode> {
        authorize_cell_access(
            &self.cell_registry,
            IntraCellResource::QDRANT_REST,
            Duration::from_secs(30),
        )
        .map_err(|_| ErrorCode::DependencyUnavailable)
    }

    fn deadline_unix_ms(&self) -> Result<i64, ErrorCode> {
        let deadline = SystemTime::now() + self.handler_timeout;
        i64::try_from(
            deadline
                .duration_since(UNIX_EPOCH)
                .map_err(|_| ErrorCode::Internal)?
                .as_millis(),
        )
        .map_err(|_| ErrorCode::Internal)
    }
}

pub struct RecallSearchRequest {
    pub query: String,
    pub workspace_id: WorkspaceId,
    pub consistency_token: Option<String>,
    pub mode: Option<String>,
    pub completeness_request: Option<String>,
    pub limit: Option<u32>,
    /// §6.1.3 / ADR-0029 D-A: any-of subject narrowing (`recall.search.subject_ids`). Empty =
    /// unscoped. Applied twice by design — as a Qdrant payload prefilter
    /// (`DenseQuery::with_subject_ids`) and re-checked at the PG hydrate gate
    /// (`materialize_private_read_serving_about`); the prefilter is never the authority.
    pub subject_ids: Vec<SubjectId>,
    /// §8.5.1 / ADR-0030 D-D: the explicit affect query (`recall.search.affect`). Same double
    /// application as `subject_ids`: Qdrant structured-payload prefilter (flat affect arrays,
    /// ANDed inside the same filter) + PG hydrate re-check per annotation on the read-time
    /// effective intensity. `None` = unscoped.
    pub affect: Option<AffectFilter>,
    /// §8.5.1 / ADR-0030 D-D: optional mood-congruent late rerank — a bounded permutation of the
    /// already-visible set (never widens it), applied after the hydrate gate.
    pub mood_congruence: Option<MoodPoint>,
}

/// ADR-0055 D-E: the fixed, exhaustive partition of [`answer`] reported as
/// `provenance.stage_ms` — every `.await` belongs to exactly one stage, so the stage sum accounts
/// for the request's own wall time (RQ-5 attribution).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// narrow + placement + `family_read_state`.
    Route,
    /// intent + `prepare_request` + the `limit` check.
    Planner,
    /// `trusted_query()` only: since ADR-0056 D-C the gateway does not scan (the worker's one
    /// seal is inside `embed`), so this reads about 0 ms.
    // ponytail: key kept at ~0 ms so xtask soak.rs RECALL_STAGES still parses every recall; drop
    // it together with that list when a card owns xtask.
    Scan,
    /// the `embed_query` RPC (worker scan + provider + ledger).
    Embed,
    /// tombstoned-seq read + the chunk policy read + the dense and the sparse leg (concurrently, ADR-0083 D-C) + their
    /// memory-level RRF.
    Qdrant,
    /// `materialize_private_read_serving_about` (the PG gate).
    Hydrate,
    /// the local rerank RPC when the lane is selected (ADR-0084 D-C), truncation to `top_k` + `mood_rerank` + truncation
    /// to `limit`.
    Rerank,
    /// `visible_index_count` + envelope build.
    Assemble,
}

const STAGE_NAMES: [&str; 8] = [
    "route", "planner", "scan", "embed", "qdrant", "hydrate", "rerank", "assemble",
];

/// The one lap order [`answer`] takes on its success path (route is entered twice: before and
/// after the planner). A lap is attributed "time since the previous lap", so a dropped or moved
/// lap would silently fold its stage into the next one and keep the sum whole; [`StageClock`]
/// therefore checks every lap against this sequence.
const LAP_SEQUENCE: [Stage; 9] = [
    Stage::Route,
    Stage::Planner,
    Stage::Route,
    Stage::Scan,
    Stage::Embed,
    Stage::Qdrant,
    Stage::Hydrate,
    Stage::Rerank,
    Stage::Assemble,
];

/// ADR-0083 U7: the sparse leg's own wall time, reported beside the eight stages. It is a sub-timing CONTAINED in
/// `qdrant` (the two legs run concurrently, so no lap can own it), not a ninth stage: it joins no sum of the stages and
/// is present only when the leg ran.
const SPARSE_SUB_TIMING: &str = "qdrant_sparse";

/// Monotonic lap clock over [`Stage`]; a stage entered twice (route) accumulates.
struct StageClock {
    start: Instant,
    last: Instant,
    ms: [f64; 8],
    /// Laps taken so far, or `None` once a lap broke [`LAP_SEQUENCE`].
    laps: Option<usize>,
    /// The sparse leg's own duration (ms), when it ran.
    sparse_ms: Option<f64>,
}

impl StageClock {
    fn start() -> Self {
        let now = Instant::now();
        Self {
            start: now,
            last: now,
            ms: [0.0; 8],
            laps: Some(0),
            sparse_ms: None,
        }
    }

    /// Records how long the sparse leg took on its own (ADR-0083 U7); it never moves a lap.
    fn note_sparse(&mut self, elapsed: Duration) {
        self.sparse_ms = Some(elapsed.as_secs_f64() * 1_000.0);
    }

    /// Wall time since the request entered `answer` (ADR-0084 U7: the handler budget the rerank wait may still use).
    fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    fn lap(&mut self, stage: Stage) {
        let now = Instant::now();
        self.ms[stage as usize] += now.duration_since(self.last).as_secs_f64() * 1_000.0;
        self.last = now;
        self.laps = self
            .laps
            .filter(|&n| LAP_SEQUENCE.get(n) == Some(&stage))
            .map(|n| n + 1);
    }

    /// `{route, …, assemble, total}` (plus [`SPARSE_SUB_TIMING`] when the sparse leg ran) in ms at 0.1 ms resolution;
    /// `total` = entry → now.
    /// A clock whose laps did not follow [`LAP_SEQUENCE`] exactly reports `total` only: its
    /// per-stage split would misattribute time, and a missing key is what the stage tests and
    /// the soak's `recall.stage.*` sampler refuse (no fake zeros).
    fn to_json(&self) -> Value {
        let round = |ms: f64| (ms * 10.0).round() / 10.0;
        let mut map = serde_json::Map::with_capacity(9);
        if self.laps == Some(LAP_SEQUENCE.len()) {
            for (name, ms) in STAGE_NAMES.iter().zip(self.ms) {
                map.insert((*name).to_owned(), json!(round(ms)));
            }
            if let Some(ms) = self.sparse_ms {
                map.insert(SPARSE_SUB_TIMING.to_owned(), json!(round(ms)));
            }
        } else {
            eprintln!(
                "humaux-gateway: recall stage_clock_out_of_sequence laps={:?}",
                self.laps
            );
        }
        map.insert(
            "total".to_owned(),
            json!(round(self.start.elapsed().as_secs_f64() * 1_000.0)),
        );
        Value::Object(map)
    }
}

/// Answers one `recall.search`, then hands its query-hash log row off (ADR-0081 D-A, T-RET-1b).
///
/// The row is handed off after `answer` has produced the envelope and is never awaited here, so the stage clock,
/// `LAP_SEQUENCE`, the response bytes and the handler's `execution_limit` (`guard.rs`) are exactly what they were
/// without the log: a slow log (a lock wait, a connection acquire, a slow COMMIT) cannot push an answered recall past
/// its deadline. A failed insert never fails the recall: partitions have no DEFAULT leaf, so a missed
/// `retention create-partitions` makes every insert raise 23514 (Baseline §48.1), and an answered recall must not turn
/// into an error for that.
// ponytail: no metric for a missed row; reconcile `ops.retrieval_query_log` row counts against
// `humaux_retrieval_requests_total`. A counter is the upgrade if the gap ever needs an alert.
pub async fn search(
    pool: Arc<RuntimeDbPool>,
    runtime: Arc<SemanticRecallRuntime>,
    catalog: Arc<CanonicalCatalog>,
    authorization: AuthorizationScope,
    request_id: Uuid,
    bootstrap: ContextBootstrap,
    input: RecallSearchRequest,
) -> Result<PendingEnvelope<ToolOutput>, ErrorCode> {
    // Everything the row needs is computed here, on the trusted scope and the request, before the hand-off: the bytes
    // the query-embedding cache keys on (ADR-0081 D-A D1) are hashed before `answer` consumes the request, and no query
    // text and no authorization object leave this function.
    let digest = query_hmac(authorization.tenant_id(), input.query.as_bytes());
    let (tenant_id, user_id) = (
        authorization.tenant_id(),
        authorization.user_id().map(|user| user.0),
    );
    let workspace_id = input.workspace_id;
    let (log_pool, log_runtime) = (Arc::clone(&pool), Arc::clone(&runtime));
    let (pending, counts) = answer(
        pool,
        runtime,
        catalog,
        authorization,
        request_id,
        bootstrap,
        input,
    )
    .await?;
    match digest {
        Ok(digest) => hand_off_query_log(
            &log_pool,
            &log_runtime,
            request_id,
            QueryLogJob {
                tenant_id,
                workspace_id,
                user_id,
                digest,
                counts,
            },
        ),
        Err(error) => report_query_log_failure(request_id, &query_log_failure_reason(&error)),
    }
    Ok(pending)
}

/// One query-hash log row, complete: scope ids, the keyed digest and the counts. Holds no query text.
struct QueryLogJob {
    tenant_id: TenantId,
    workspace_id: WorkspaceId,
    user_id: Option<Uuid>,
    digest: QueryHmac,
    counts: QueryLogCounts,
}

/// Spawns the insert when a permit is free, drops the row (reported) when not. The task is bounded by the pool's acquire
/// timeout and releases its permit when it ends, so a stuck log can neither linger nor starve the pool.
fn hand_off_query_log(
    pool: &Arc<RuntimeDbPool>,
    runtime: &SemanticRecallRuntime,
    request_id: Uuid,
    job: QueryLogJob,
) {
    let (gate, deadline) = runtime.query_log_gate(pool);
    let deadline = *deadline;
    let Ok(permit) = Arc::clone(gate).try_acquire_owned() else {
        report_query_log_failure(request_id, "dropped_backpressure");
        return;
    };
    let pool = Arc::clone(pool);
    // ponytail: rows in flight at shutdown are lost; observability only
    tokio::spawn(async move {
        let _permit = permit;
        let QueryLogJob {
            tenant_id,
            workspace_id,
            user_id,
            digest,
            counts,
        } = job;
        let logged = tokio::time::timeout(
            deadline,
            record_recall_query(&pool, tenant_id, workspace_id, user_id, &digest, &counts),
        )
        .await;
        match logged {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                report_query_log_failure(request_id, &query_log_failure_reason(&error));
            }
            Err(_elapsed) => report_query_log_failure(request_id, "timeout"),
        }
    });
}

/// The SQLSTATE or the key-set class only, never driver text or any part of the query.
fn query_log_failure_reason(error: &RetrieveError) -> String {
    match error {
        RetrieveError::TokenKeysUnset => "token_keys_unset".to_owned(),
        other => other.sqlstate().unwrap_or_else(|| "unknown".to_owned()),
    }
}

fn report_query_log_failure(request_id: Uuid, reason: &str) {
    eprintln!("humaux-gateway: recall request_id={request_id} query_log_failed reason={reason}");
}

#[allow(clippy::too_many_lines)] // Keep the one native semantic-recall request/response chain together.
async fn answer(
    pool: Arc<RuntimeDbPool>,
    runtime: Arc<SemanticRecallRuntime>,
    catalog: Arc<CanonicalCatalog>,
    authorization: AuthorizationScope,
    request_id: Uuid,
    bootstrap: ContextBootstrap,
    input: RecallSearchRequest,
) -> Result<(PendingEnvelope<ToolOutput>, QueryLogCounts), ErrorCode> {
    let mut clock = StageClock::start();
    if input.mode.as_deref().is_some_and(|mode| mode != "semantic")
        || input.completeness_request.as_deref() == Some("required")
    {
        return Err(ErrorCode::DependencyUnavailable);
    }
    // Membership narrowing (`Forbidden` outside the credential's workspaces) already happened
    // in the guard's `credential.authorize` on the wire path; this `narrow` is defense in depth
    // for in-process callers. The stream family below is derived per request (ADR-0031 D-A);
    // an unprovisioned pair fails closed at the placement / serving-projection reads that
    // follow — the same serving read the PG read routes run in `read_scope` / `assemble`.
    let authorization = authorization.narrow(input.workspace_id)?;
    // §17.3 per-tenant placement, resolved fresh every request — `None` means "not indexed
    // yet for this tenant", never a fallback onto another tenant's collection.
    let placement = tenant_placement(
        &pool,
        authorization.tenant_id(),
        RetrievalFamily::PrivateMemoryV1,
    )
    .await
    .map_err(|_| {
        eprintln!("humaux-gateway: recall request_id={request_id} placement_lookup_failed");
        ErrorCode::DependencyUnavailable
    })?
    .ok_or_else(|| {
        eprintln!("humaux-gateway: recall request_id={request_id} placement_missing");
        ErrorCode::DependencyUnavailable
    })?;
    let (family, key) = bootstrap.request_stream(authorization.tenant_id(), input.workspace_id);
    clock.lap(Stage::Route);
    let intent = RetrievalIntent::new(input.query, Vec::new(), BTreeSet::new(), BTreeSet::new())
        .map_err(|_| ErrorCode::InvalidInput)?;
    let retrieval = prepare_request(intent, &bootstrap.profile).map_err(|_| ErrorCode::Internal)?;
    // ADR-0055 D-C (amends §33 / ADR-0044 D-A): the planner decision is recorded
    // (`provenance.planner_class`), never a refusal — while dense is the only delivered lane it
    // answers every class; `accepted_output` adds `LANE_SUBSTITUTED` when no `mode` was sent.
    // Only an explicit undelivered `mode` refuses (DEPENDENCY_UNAVAILABLE, above).
    //
    // §55.1: candidate depth (`cand_k`) and `top_k` come only from the registered profile.
    // ADR-0055 D-D (amends ADR-0044 D-B): a `limit` in 1..=top_k only shortens the returned
    // list (§33.5's bounded output); above `top_k` stays INVALID_INPUT. Refusing it *silently*
    // is what card 16's soak paid for — its replay sent `limit = <live point count>` and the
    // refusal was misread for a day as an embedding fault — so the operator line carries both
    // numbers, never the query.
    if let Some(limit) = input.limit
        && (limit == 0 || limit > retrieval.top_k())
    {
        eprintln!(
            "humaux-gateway: recall request_id={request_id} limit_not_profile_top_k \
             limit={limit} profile_top_k={}",
            retrieval.top_k()
        );
        return Err(ErrorCode::InvalidInput);
    }
    clock.lap(Stage::Planner);
    // ADR-0053 D-E: the serving read comes BEFORE the query embedding — an unactivated family
    // cannot use a vector, so it pays no provider egress and no provider budget. Uninitialised
    // key ⇒ DEPENDENCY_UNAVAILABLE (unchanged); initialised but unserved ⇒ the B-shaped read.
    let state = family_read_state(&pool, &authorization, &key, UnservedLedger::Read)
        .await
        .map_err(|_| {
            eprintln!("humaux-gateway: recall request_id={request_id} projection_selector_failed");
            ErrorCode::DependencyUnavailable
        })?;
    if !state.initialized {
        eprintln!("humaux-gateway: recall request_id={request_id} stream_uninitialized");
        return Err(ErrorCode::DependencyUnavailable);
    }
    let projection_version = match (state.serving, state.unserved) {
        (Some(version), _) => version,
        (None, Some((ledger, pipeline))) => {
            eprintln!("humaux-gateway: recall request_id={request_id} no_serving_projection");
            let (evidence, knowledge) = pipeline.blocks();
            // No dense lane ran: nothing was a candidate, visible or returned, and the answer carries no stage_ms.
            return no_serving_projection_envelope(
                &retrieval,
                &bootstrap.binary_build,
                vec!["dense".to_owned()],
                &ledger,
                evidence,
                knowledge,
                |envelope: Envelope<Value>| {
                    let value = serde_json::to_value(envelope).map_err(|_| ErrorCode::Internal)?;
                    catalog.validate_output(ToolName::Recall, &value)?;
                    let text = serde_json::to_string(&value).map_err(|_| ErrorCode::Internal)?;
                    Ok(ToolOutput {
                        text,
                        structured_content: value,
                        is_error: false,
                    })
                },
            )
            .map(|pending| {
                let counts = QueryLogCounts {
                    cand_k: retrieval.cand_k(),
                    candidates: 0,
                    visible: None,
                    returned: 0,
                    stage_ms: None,
                };
                (pending, counts)
            });
        }
        (None, None) => {
            eprintln!("humaux-gateway: recall request_id={request_id} no_serving_projection");
            return Err(ErrorCode::DependencyUnavailable);
        }
    };
    clock.lap(Stage::Route);
    // ADR-0056 D-C / ADR-0012 §2: raw query text crosses the same-entity UDS; the worker's
    // `seal_query` is the one egress seal, and its gitleaks verdict comes back as SCAN_REJECTED.
    let trusted_query = retrieval.trusted_query().ok_or(ErrorCode::Internal)?;
    clock.lap(Stage::Scan);
    let embedding_input = RetrievalEmbeddingInput {
        authorization: &authorization,
        workspace_id: input.workspace_id,
        request_id,
        logical_call_id: request_id,
        attempt_no: 1,
        profile_fingerprint: retrieval.profile_fingerprint_identity().as_str(),
        dimension: runtime.dimension,
        query: trusted_query.text(),
        deadline_unix_ms: runtime.deadline_unix_ms()?,
    };
    let (vector, embedding_model_id) = match runtime.port.embed_query(embedding_input).await? {
        RetrievalEmbeddingOutcome::Embedded {
            vector,
            dimension,
            model_id,
            ..
        } if dimension == runtime.dimension && vector.len() == runtime.dimension as usize => {
            (vector, model_id)
        }
        // Three different failures, three different operator lines. One collapsed
        // `query_embedding_unusable` covered all of them and cost card 16's soak a day of
        // diagnosis: "the provider declined" (Skipped), "the worker could not be reached or
        // failed" (Unavailable) and "the vector came back the wrong shape" (dimension
        // mismatch) have disjoint fixes, and a log line that cannot tell them apart forces
        // the reader to guess which one they are looking at.
        //
        // A wrong-dimension vector is never truncated/padded to fit — ADR-0012 gateway wiring
        // card: "mismatch ⇒ DependencyUnavailable, never truncate". Only the two lengths are
        // logged, never an element of the vector.
        RetrievalEmbeddingOutcome::Embedded {
            vector, dimension, ..
        } => {
            eprintln!(
                "humaux-gateway: recall request_id={request_id} query_embedding_dimension_mismatch \
                 reported={dimension} vector_len={} expected={}",
                vector.len(),
                runtime.dimension
            );
            return Err(ErrorCode::DependencyUnavailable);
        }
        RetrievalEmbeddingOutcome::Skipped => {
            eprintln!("humaux-gateway: recall request_id={request_id} query_embedding_skipped");
            return Err(ErrorCode::DependencyUnavailable);
        }
        // §7.5 C / §52: a gitleaks finding on the query is the caller's FORBIDDEN, as it was
        // when the gateway sealed it itself (ADR-0056 D-C); only the request id is logged.
        RetrievalEmbeddingOutcome::Unavailable { reason } if reason == "SCAN_REJECTED" => {
            eprintln!("humaux-gateway: recall request_id={request_id} query_scan_rejected");
            return Err(ErrorCode::Forbidden);
        }
        // `reason` is the worker's closed failure code (or this client's own transport class),
        // never provider text and never any part of the query — ADR-0014 operator-signal rule.
        RetrievalEmbeddingOutcome::Unavailable { reason } => {
            eprintln!(
                "humaux-gateway: recall request_id={request_id} query_embedding_unavailable \
                 reason={reason}"
            );
            return Err(ErrorCode::DependencyUnavailable);
        }
    };
    clock.lap(Stage::Embed);
    // ADR-0055 D-B / §37: TOMBSTONED seqs of the serving stream reach the Qdrant overlay, so a
    // tombstoned point cannot occupy a candidate slot (the PG gate re-checks by Evidence). The
    // seqs are this workspace stream's, so the candidate set is scoped to it as well.
    let serving_key = family.with_version(projection_version.clone());
    let tombstoned_seqs = tombstoned_source_seqs(&pool, &authorization, &serving_key)
        .await
        .map_err(|_| {
            eprintln!("humaux-gateway: recall request_id={request_id} tombstone_read_failed");
            ErrorCode::DependencyUnavailable
        })?;
    // §23.3 / ADR-0055 D-A: the candidate pool is `cand_k`, not `top_k` — the PG gate below drops
    // archived/superseded/secret/tombstoned rows, and truncation to the returned depth happens
    // only after it and the mood rerank. ADR-0083 D-C: each leg asks Qdrant for `leg_depth` Memories and the fused list
    // is cut to `cand_k` (below), so the fusion sees the depth the experiments measured.
    //
    // ADR-0083 D-C: the sparse leg runs only when the profile enables it and tenant policy allows in-Cell text
    // processing (`build_sparse_lane`, the one SKIPPED_BY_POLICY decision); otherwise its lane is `not_required` (U5)
    // and nothing is sent. Decided before the dense query is built: without a sparse leg there is nothing to fuse with,
    // so the dense leg asks for `cand_k` Memories as before and a grouped refill is not spent on a depth nobody reads.
    let text_processing_allowed = (runtime.text_processing_allowed)(authorization.tenant_id());
    let sparse_corpus = sparse_corpus_filter(
        bootstrap.profile.sparse_leg_enabled(),
        text_processing_allowed,
        &authorization,
    );
    // ADR-0084 D-D row 1: the rerank branch is selected only when the profile turns the lane on AND tenant policy allows
    // in-Cell text processing (the same decision as the sparse leg); otherwise no text is read and no call is made.
    let rerank_selected =
        rerank_branch_selected(bootstrap.profile.rerank_enabled(), text_processing_allowed);
    let leg_limit = if sparse_corpus.is_some() {
        bootstrap.profile.leg_depth()
    } else {
        retrieval.cand_k()
    };
    let dense = DenseQuery::new(
        &authorization,
        &placement,
        DenseQueryVersions {
            projection: &projection_version,
            embedding: &runtime.embedding_version,
        },
        vector,
        leg_limit,
        Vec::new(),
        ha_profile_for(QdrantOperation::ReadYourWriteStrict),
    )
    .map_err(|_| {
        eprintln!("humaux-gateway: recall request_id={request_id} dense_query_build_failed");
        ErrorCode::DependencyUnavailable
    })?
    .with_subject_ids(&input.subject_ids)
    .with_affect_filter(input.affect.as_ref())
    .in_workspace_stream(input.workspace_id, tombstoned_seqs);
    // ADR-0068 D-E: a projection whose policy chunks long notes is queried grouped by Memory, so `cand_k` counts
    // Memories and one note's chunks cannot fill it; the registry check in materialize stays the identity authority.
    let grouped = grouped_recall(&pool, &serving_key).await.map_err(|_| {
        eprintln!("humaux-gateway: recall request_id={request_id} card_profile_policy_read_failed");
        ErrorCode::DependencyUnavailable
    })?;
    let permit = runtime.qdrant_permit()?;
    // ADR-0083 D-C: the dense and the sparse leg run concurrently, both scoped by `dense`'s one filter; the sparse leg
    // alone is bounded by the registered `sparse_timeout_ms`, so a hung sparse request degrades instead of spending the
    // handler deadline.
    let (dense_outcome, sparse_outcome) = tokio::join!(
        dense_leg(runtime.qdrant.as_ref(), &permit, &dense, grouped),
        sparse_leg(
            runtime.qdrant.as_ref(),
            &permit,
            &dense,
            trusted_query.text(),
            sparse_corpus.as_ref(),
            Duration::from_millis(u64::from(bootstrap.profile.sparse_timeout_ms())),
        ),
    );
    let dense_candidates = dense_outcome.map_err(|error| {
        // ADR-0014: a `WriteDenied` here means the registered `QDRANT_REST` entry itself is
        // misconfigured (a read-only permit rejected a request `query_dense` never should
        // have shaped as a write) — a Forbidden, not a transient dependency failure a
        // caller could usefully retry.
        if matches!(
            error,
            humaux_adapters::qdrant::QdrantTransportError::Transport(
                humaux_infra_cell::IntraCellError::WriteDenied
            )
        ) {
            ErrorCode::Forbidden
        } else {
            // Operator signal: transport error class only (no body/URL), §ADR-0014.
            eprintln!("humaux-gateway: recall request_id={request_id} qdrant_query_failed");
            ErrorCode::DependencyUnavailable
        }
    })?;
    // ADR-0083 D-C: a sparse-leg failure never fails the recall — the answer comes from the dense leg, the sparse lane
    // reads `failed` and `SPARSE_LANE_UNAVAILABLE` is reported (never silent). The code itself is emitted in
    // `accepted_output`, beside LANE_SUBSTITUTED, so a later error never leaves a counted degrade without a finished
    // retrieval. A dense-leg failure was refused above.
    let mut sparse_candidates = Vec::new();
    let mut sparse = SparseLeg::NotRun;
    if let Some((outcome, elapsed)) = sparse_outcome {
        clock.note_sparse(elapsed);
        match outcome {
            Ok(found) => {
                sparse_candidates = found;
                sparse = SparseLeg::Answered;
            }
            Err(error) => {
                eprintln!(
                    "humaux-gateway: recall request_id={request_id} sparse_leg_failed class={}",
                    sparse_failure_class(&error)
                );
                sparse = SparseLeg::Failed;
            }
        }
    }
    let candidates = fuse_rrf(
        [dense_candidates.as_slice(), sparse_candidates.as_slice()],
        bootstrap.profile.rrf_k(),
        grouped,
        retrieval.cand_k() as usize,
    );
    clock.lap(Stage::Qdrant);
    let mut materialized = materialize_private_read_serving_about(
        &pool,
        input.consistency_token.as_deref(),
        &authorization,
        &family,
        &projection_version,
        &runtime.embedding_version,
        &candidates,
        &input.subject_ids,
        input.affect.as_ref(),
        // ADR-0084 D-C 3: the texts come from the hydrate transaction itself, for the Memories that passed its gate.
        if rerank_selected {
            GatedTexts::Read
        } else {
            GatedTexts::Skip
        },
    )
    .await
    .map_err(|error| match error {
        humaux_adapters::retrieve::RetrieveError::CrossTenant
        | humaux_adapters::retrieve::RetrieveError::CrossWorkspace
        | humaux_adapters::retrieve::RetrieveError::UntrustedStreamFamily => ErrorCode::Forbidden,
        // §15.5 token refusals are caller-fault, but they must not be *silent* caller-fault:
        // an expired token and a malformed one produce the same `INVALID_INPUT` on the wire,
        // and card 16's post-drain replay spent a run being refused for a TTL it had outlived
        // with nothing in the log to say so. The reason class only — never the token.
        error @ (humaux_adapters::retrieve::RetrieveError::TokenMalformed(_)
        | humaux_adapters::retrieve::RetrieveError::TokenExpired
        | humaux_adapters::retrieve::RetrieveError::TokenNotIssued) => {
            let reason = match error {
                humaux_adapters::retrieve::RetrieveError::TokenMalformed(_) => "token_malformed",
                humaux_adapters::retrieve::RetrieveError::TokenExpired => "token_expired",
                _ => "token_not_issued",
            };
            eprintln!(
                "humaux-gateway: recall request_id={request_id} consistency_token_refused \
                 reason={reason}"
            );
            ErrorCode::InvalidInput
        }
        // ADR-0059 D-G: bootstrap installs the token keys before the listener starts, so this is
        // a server fault, never a caller one.
        humaux_adapters::retrieve::RetrieveError::TokenKeysUnset => {
            eprintln!(
                "humaux-gateway: recall request_id={request_id} materialize_failed \
                 class=token_keys_unset"
            );
            ErrorCode::DependencyUnavailable
        }
        error => {
            // Operator signal, same discipline as the qdrant_query_failed line above: the
            // RetrieveError class only — `Db` carries driver text and is reduced to its name.
            let class = if matches!(error, humaux_adapters::retrieve::RetrieveError::Db(_)) {
                "db_error".to_owned()
            } else {
                error.to_string()
            };
            eprintln!(
                "humaux-gateway: recall request_id={request_id} materialize_failed class={class}"
            );
            ErrorCode::DependencyUnavailable
        }
    })?;
    clock.lap(Stage::Hydrate);
    // ADR-0084 D-C 3 to 5: the local rerank reorders the visible Memories by cross-encoder score, order only. It runs
    // after the hydrate gate and sends only the texts that gate returned; its wait is part of the Rerank lap.
    let rerank = rerank_stage(
        &RerankStageInput {
            lane: runtime.rerank.as_ref(),
            selected: rerank_selected,
            depth: usize::try_from(bootstrap.profile.rerank_depth()).unwrap_or(usize::MAX),
            max_len: bootstrap.profile.rerank_max_len(),
            wait: rerank_wait(
                Duration::from_millis(u64::from(bootstrap.profile.rerank_timeout_ms())),
                runtime.handler_timeout,
                clock.elapsed(),
                // The steps after the rerank are one PostgreSQL read and one Qdrant count: the registered budget of
                // one Qdrant request, `sparse_timeout_ms`, is the nearest existing stage budget (no new key, §78.1).
                Duration::from_millis(u64::from(bootstrap.profile.sparse_timeout_ms())),
            ),
            call_id: request_id,
            query: trusted_query.text(),
        },
        &mut materialized.bodies.items,
        &materialized.point_slots,
        &materialized.gated_texts,
    )
    .await;
    // ADR-0030 D-D (kept by ADR-0055 D-A): the mood rerank is a permutation of the visible set
    // — the first profile `top_k` survivors in dense order — never a selection over all
    // `cand_k` survivors, where a congruent deep candidate would evict a relevant top hit
    // (no-affect memories score the 5000 midpoint). `limit` then shortens the reranked list.
    truncate_memory_items(&mut materialized.bodies.items, retrieval.top_k());
    let mood_reranked = match input.mood_congruence {
        None => 0,
        Some(mood) => mood_rerank(&pool, &authorization, &mut materialized.bodies.items, mood)
            .await
            .map_err(|_| {
                eprintln!("humaux-gateway: recall request_id={request_id} mood_rerank_failed");
                ErrorCode::DependencyUnavailable
            })?,
    };
    truncate_memory_items(
        &mut materialized.bodies.items,
        input.limit.unwrap_or_else(|| retrieval.top_k()),
    );
    clock.lap(Stage::Rerank);
    // §23.3: `reranked_count` is what the cross-encoder scored (0 on any degradation, ADR-0084 D-D) while the lane is
    // selected, otherwise what the mood rerank permuted.
    let rerank = RerankReport {
        reranked_count: if rerank_selected {
            rerank.reranked_count
        } else {
            mood_reranked
        },
        ..rerank
    };
    // §23.1②: the live index count, taken against the SERVING version this request actually
    // read (`family_read_state` above), never the token's. `None` here is not a
    // failure to handle — it is the honest "cannot establish" input `build_projection_block`
    // already knows how to report.
    let visible = visible_index_count(
        &pool,
        &authorization,
        IndexFace {
            transport: runtime.qdrant.as_ref(),
            permit: &runtime.qdrant_permit()?,
            collection: &placement.collection_name,
        },
        &family.with_version(projection_version.clone()),
        Some(projection_version.as_str()),
        &materialized.ledger,
    )
    .await;
    if visible.is_none() {
        eprintln!("humaux-gateway: recall request_id={request_id} visible_index_count_unavailable");
    }
    accepted_output(
        materialized,
        &retrieval,
        &bootstrap,
        &runtime,
        &projection_version,
        &embedding_model_id,
        candidates.len(),
        rerank,
        &catalog,
        visible,
        input.mode.is_some(),
        sparse,
        clock,
    )
}

/// The dense leg (unchanged request shape, ADR-0083 D-C): grouped by Memory when the serving projection chunks long
/// notes (ADR-0068 D-E), plain points otherwise; `query` carries `leg_depth` as its limit.
async fn dense_leg(
    transport: &dyn IntraCellHttpTransport,
    permit: &CellAccessPermit,
    query: &DenseQuery,
    grouped: bool,
) -> Result<Vec<DenseCandidate>, QdrantTransportError> {
    if grouped {
        query_dense_groups_bounded(transport, permit, query, RETRIEVAL_GROUP_QUERY_MAX_CALLS).await
    } else {
        query_dense(transport, permit, query).await
    }
}

/// Why a sparse leg that ran did not answer (ADR-0083 D-C): the registered budget elapsed, or Qdrant failed.
enum SparseFailure {
    Timeout,
    Qdrant(QdrantTransportError),
}

/// A sparse leg that ran: its candidates or its failure, and its own wall time (ADR-0083 U7).
type SparseLegRun = (Result<Vec<DenseCandidate>, SparseFailure>, Duration);

/// The sparse leg (ADR-0083 D-C): `None` when it does not run, otherwise its [`SparseLegRun`]. Sends the exact query
/// bytes (§20.0) under the dense leg's filter and `corpus` as the IDF corpus. Only this leg is bounded by `budget`
/// (the registered `sparse_timeout_ms`): the transport's own timeout equals the handler's, so without it a hung sparse
/// request would hold the join until the handler deadline fires and fail the whole recall.
async fn sparse_leg(
    transport: &dyn IntraCellHttpTransport,
    permit: &CellAccessPermit,
    query: &DenseQuery,
    text: &str,
    corpus: Option<&DenseQueryFilter>,
    budget: Duration,
) -> Option<SparseLegRun> {
    let corpus = corpus?;
    let started = Instant::now();
    let outcome = match tokio::time::timeout(
        budget,
        query_sparse_groups(transport, permit, query, text, corpus),
    )
    .await
    {
        Ok(answered) => answered.map_err(SparseFailure::Qdrant),
        Err(_elapsed) => Err(SparseFailure::Timeout),
    };
    Some((outcome, started.elapsed()))
}

/// ADR-0083 D-A / D-E, U5 / U6: the IDF-corpus filter of the sparse leg, or `None` when the leg does not run — the
/// profile has not enabled it (U6: after the T-RET-6b backfill reads zero missing) or tenant policy forbids in-Cell
/// text processing (`SKIPPED_BY_POLICY`, §17.6). Pure over its three inputs so the 2x2 decision is testable; the caller
/// reads `enabled` from the registered profile and `text_processing_allowed` from the one function the write path uses.
fn sparse_corpus_filter(
    enabled: bool,
    text_processing_allowed: bool,
    scope: &AuthorizationScope,
) -> Option<DenseQueryFilter> {
    if !enabled {
        return None;
    }
    match build_sparse_lane(scope, &[], text_processing_allowed) {
        SparseLane::Executed { filter } => Some(filter),
        SparseLane::SkippedByPolicy => None,
    }
}

/// What the sparse leg did in one recall (ADR-0083 D-C, U5). The lane status and the degradation are derived from it in
/// [`accepted_output`], where `LANE_SUBSTITUTED` is emitted too.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SparseLeg {
    /// It did not run: `not_required`.
    NotRun,
    Answered,
    Failed,
}

/// The error class only, for the operator line: never a body, a URL or any part of the query (ADR-0014).
fn sparse_failure_class(failure: &SparseFailure) -> &'static str {
    match failure {
        SparseFailure::Timeout => "timeout",
        SparseFailure::Qdrant(QdrantTransportError::Transport(_)) => "transport",
        SparseFailure::Qdrant(QdrantTransportError::NonSuccessStatus { .. }) => "non_2xx",
        SparseFailure::Qdrant(QdrantTransportError::UnexpectedResponseShape(_)) => {
            "unexpected_shape"
        }
        SparseFailure::Qdrant(
            QdrantTransportError::InvalidCollectionName(_)
            | QdrantTransportError::InvalidDenseQuery(_),
        ) => "invalid_query",
    }
}

/// The identity two legs agree on: the Memory when the dense leg is grouped by Memory, the point otherwise (a plain
/// dense hit carries no `memory_id`, and one point is one Memory there). A `Num` point id never occurs in a private
/// projection (the hydrate gate refuses it); it maps to a distinct key so it is neither merged nor dropped.
fn fusion_key(candidate: &DenseCandidate, by_memory: bool) -> Uuid {
    match (by_memory, candidate.memory_id, candidate.point_id) {
        (true, Some(memory_id), _) => memory_id,
        (_, _, PointId::Uuid(point)) => point,
        (_, _, PointId::Num(number)) => Uuid::from_u128(u128::from(number)),
    }
}

/// ADR-0083 D-C: reciprocal-rank fusion of the two legs over Memory ranks, in the gateway.
/// `score(m) = sum 1 / (rrf_k + rank)` over the legs that returned `m`, ranks 1-based; ties break by the identity
/// ([`fusion_key`], the `memory_id` when grouped) ascending, never by arrival order. The result is cut to `cap`
/// (`cand_k`) and each candidate's `score` is its fused score; with an empty leg it is the other leg's order.
/// Which candidate (point) stands for a Memory seen by both legs is the dense leg's: the PG gate resolves any of a
/// Memory's points to the same Memory.
fn fuse_rrf(
    legs: [&[DenseCandidate]; 2],
    rrf_k: u32,
    by_memory: bool,
    cap: usize,
) -> Vec<DenseCandidate> {
    let mut slot: HashMap<Uuid, usize> = HashMap::new();
    let mut fused: Vec<(Uuid, DenseCandidate)> = Vec::new();
    for leg in legs {
        for (index, candidate) in leg.iter().enumerate() {
            let key = fusion_key(candidate, by_memory);
            let share = 1.0 / (f64::from(rrf_k) + (index + 1) as f64);
            let at = *slot.entry(key).or_insert(fused.len());
            if at == fused.len() {
                let mut first = candidate.clone();
                first.score = share;
                fused.push((key, first));
            } else {
                fused[at].1.score += share;
            }
        }
    }
    fused.sort_by(|a, b| b.1.score.total_cmp(&a.1.score).then_with(|| a.0.cmp(&b.0)));
    fused.truncate(cap);
    fused.into_iter().map(|(_, candidate)| candidate).collect()
}

/// ADR-0055 D-A: keeps the first `keep` memory items (current order) and every overlay item
/// — a §15.5 read-your-writes item is bounded by its token's range, and dropping one would break
/// RYW.
fn truncate_memory_items(items: &mut Vec<MaterializedItem>, keep: u32) {
    let mut memories = 0_u32;
    items.retain(|item| match item {
        MaterializedItem::Memory { .. } => {
            memories += 1;
            memories <= keep
        }
        _ => true,
    });
}

/// ADR-0084 D-D row 1: the rerank branch is selected only when the profile turns the lane on AND tenant policy allows
/// in-Cell text processing (`in_cell_text_processing_allowed`, the decision the sparse leg and the write path read).
/// Pure over its two inputs, so the 2x2 table is a unit test.
fn rerank_branch_selected(enabled: bool, text_processing_allowed: bool) -> bool {
    enabled && text_processing_allowed
}

/// ADR-0084 D-E / U7: the wait for the rerank RPC is the registered `rerank_timeout_ms`, never more than the handler
/// budget the request has left less `reserve`, the time kept for the steps that follow (the mood rerank's read, the live
/// index count and the assembly), so a slow rerank degrades the answer instead of letting the handler deadline
/// (`guard.rs`) fail it. Zero when nothing is left over: the call is then not made.
fn rerank_wait(
    registered: Duration,
    handler_timeout: Duration,
    elapsed: Duration,
    reserve: Duration,
) -> Duration {
    registered.min(
        handler_timeout
            .saturating_sub(elapsed)
            .saturating_sub(reserve),
    )
}

/// What the rerank stage needs besides the hydrated items.
struct RerankStageInput<'a> {
    /// The runtime's lane; `None` when no worker serves rerank.
    lane: Option<&'a RerankLane>,
    /// [`rerank_branch_selected`]'s verdict.
    selected: bool,
    /// The registered `rerank_depth`: most visible Memories scored.
    depth: usize,
    /// The registered `rerank_max_len`.
    max_len: u32,
    /// [`rerank_wait`]'s verdict.
    wait: Duration,
    /// Names the call in the worker's counts and in the operator line (the request id).
    call_id: Uuid,
    /// The query, in-Cell text.
    query: &'a str,
}

/// What the rerank stage tells the envelope: the count, `provenance.rerank_model_id` and the fallback, if any.
struct RerankReport {
    /// `completeness.reranked_count`.
    reranked_count: u32,
    /// `provenance.rerank_model_id` (§23.1③).
    model: ProvenanceValue,
    /// Set on a fallback; the code is emitted in `accepted_output`, never here.
    failure: Option<RerankFailure>,
}

/// The Memory ids of `items` in their current order; overlay items hold none.
fn memory_ids(items: &[MaterializedItem]) -> Vec<Uuid> {
    items
        .iter()
        .filter_map(|item| match item {
            MaterializedItem::Memory { memory_id, .. } => Some(*memory_id),
            _ => None,
        })
        .collect()
}

/// Puts the Memory items of `items` into the order `order` names, leaving every other item where it is. `order` is a
/// permutation of the Memory ids (`retrieval::rerank::settle` guarantees it); an id it does not name sorts last.
fn apply_memory_order(items: &mut [MaterializedItem], order: &[Uuid]) {
    let rank: HashMap<Uuid, usize> = order.iter().enumerate().map(|(at, id)| (*id, at)).collect();
    let mut memories: Vec<MaterializedItem> = items
        .iter()
        .filter(|item| matches!(item, MaterializedItem::Memory { .. }))
        .cloned()
        .collect();
    memories.sort_by_key(|item| match item {
        MaterializedItem::Memory { memory_id, .. } => {
            rank.get(memory_id).copied().unwrap_or(usize::MAX)
        }
        _ => usize::MAX,
    });
    let mut ordered = memories.into_iter();
    for slot in items.iter_mut() {
        if matches!(slot, MaterializedItem::Memory { .. })
            && let Some(next) = ordered.next()
        {
            *slot = next;
        }
    }
}

/// ADR-0084 D-C 3 to 5, D-D: scores the first `depth` visible Memories that have a document and puts the Memory items
/// into the rerank order, order only.
///
/// - Not selected, or no visible Memory: nothing is read or called; `not_applicable` (§23.3 allows it for the lane off,
///   the tenant's policy, and nothing to rank).
/// - The documents are built from `texts` and `slots`, which the hydrate transaction produced for the Memories that
///   passed its gate and for no others (G-RET-13). A Memory without a document (an unknown slot, an ordinal past the
///   body, no readable body) is not sent and keeps its fused place after the scored ones. With visible Memories and no
///   document at all, the selected branch has failed: the fused order, [`RerankFailure::Unavailable`].
/// - The call is bounded by `wait` (no call when it is zero); a timeout, a failed or unusable answer and another
///   model's answer are the fused order with a [`RerankFailure`]. The code itself is emitted in `accepted_output`.
async fn rerank_stage(
    input: &RerankStageInput<'_>,
    items: &mut [MaterializedItem],
    slots: &PointSlots,
    texts: &BTreeMap<Uuid, MemoryText>,
) -> RerankReport {
    let visible = memory_ids(items);
    let report = |settlement: humaux_retrieval::rerank::Settlement<Uuid>| RerankReport {
        reranked_count: settlement.reranked_count,
        model: settlement.rerank_model_id,
        failure: settlement.failure,
    };
    if !input.selected || visible.is_empty() {
        return report(not_run(&visible));
    }
    let mut sent: Vec<Uuid> = Vec::new();
    let mut documents: Vec<String> = Vec::new();
    for memory_id in visible.iter().take(input.depth) {
        let Some(Some(slot)) = slots.get(memory_id).copied() else {
            continue;
        };
        let Some(text) = texts.get(memory_id) else {
            continue;
        };
        let Some(body) = text.body.as_deref() else {
            continue;
        };
        if let Some(document) = rerank_document(text.title.as_deref().unwrap_or(""), body, slot) {
            sent.push(*memory_id);
            documents.push(document);
        }
    }
    if documents.is_empty() {
        // §23.1③ / D-D: the branch was selected and there are Memories to rank, so failing to build any document is a
        // failure of the branch, never `not_applicable` (that is only the lane off, the tenant's policy, or no Memory).
        eprintln!(
            "humaux-gateway: recall request_id={} rerank_failed class=no_documents visible={}",
            input.call_id,
            visible.len()
        );
        return report(unavailable(&visible));
    }
    let Some(lane) = input.lane else {
        eprintln!(
            "humaux-gateway: recall request_id={} rerank_failed class=no_lane",
            input.call_id
        );
        return report(unavailable(&visible));
    };
    if input.wait.is_zero() {
        eprintln!(
            "humaux-gateway: recall request_id={} rerank_failed class=no_budget",
            input.call_id
        );
        return report(settle(&visible, &sent, lane.pin(), Executor::Unavailable));
    }
    let answered = tokio::time::timeout(
        input.wait,
        lane.port().rerank(RerankCall {
            call_id: input.call_id,
            query: input.query,
            documents: &documents,
            max_len: input.max_len,
        }),
    )
    .await;
    let settlement = match &answered {
        Ok(RerankAnswer::Scored { scores, model }) => settle(
            &visible,
            &sent,
            lane.pin(),
            Executor::Scored {
                scores: scores.as_slice(),
                model,
            },
        ),
        Ok(RerankAnswer::Failed { class }) => {
            eprintln!(
                "humaux-gateway: recall request_id={} rerank_failed class={class}",
                input.call_id
            );
            settle(&visible, &sent, lane.pin(), Executor::Unavailable)
        }
        Err(_elapsed) => {
            eprintln!(
                "humaux-gateway: recall request_id={} rerank_failed class=timeout",
                input.call_id
            );
            settle(&visible, &sent, lane.pin(), Executor::Unavailable)
        }
    };
    apply_memory_order(items, &settlement.order);
    report(settlement)
}

/// ADR-0030 D-D late rerank: reorders the visible Memory items by mood congruence
/// (`application::affect::rerank_by_mood`, stable) using the rows' affects read under the
/// caller's RLS; overlay items keep their place after the memories. Returns how many memory
/// items were reranked (the envelope's `reranked_count`). Never adds or drops an item.
async fn mood_rerank(
    pool: &RuntimeDbPool,
    authorization: &AuthorizationScope,
    items: &mut [MaterializedItem],
    mood: MoodPoint,
) -> Result<u32, ErrorCode> {
    let memory_ids: Vec<uuid::Uuid> = items
        .iter()
        .filter_map(|item| match item {
            MaterializedItem::Memory { memory_id, .. } => Some(*memory_id),
            _ => None,
        })
        .collect();
    let rows = affect_repo::affects_for_memories(pool, authorization, &memory_ids).await?;
    let observed = affect_repo::observed(&rows, time::OffsetDateTime::now_utc());
    let order = rerank_by_mood(memory_ids, mood, &observed);
    let rank = |item: &MaterializedItem| match item {
        MaterializedItem::Memory { memory_id, .. } => order
            .iter()
            .position(|id| id == memory_id)
            .unwrap_or(usize::MAX),
        _ => usize::MAX,
    };
    items.sort_by_key(rank);
    u32::try_from(order.len()).map_err(|_| ErrorCode::Internal)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // One envelope-assembly step over the request's own fixed field set.
fn accepted_output(
    materialized: MaterializedPrivateReadServing,
    request: &humaux_retrieval::request::RetrievalRequest,
    bootstrap: &ContextBootstrap,
    runtime: &SemanticRecallRuntime,
    projection_version: &str,
    embedding_model_id: &str,
    candidate_count: usize,
    rerank: RerankReport,
    catalog: &CanonicalCatalog,
    visible: Option<u64>,
    explicit_mode: bool,
    sparse: SparseLeg,
    mut clock: StageClock,
) -> Result<(PendingEnvelope<ToolOutput>, QueryLogCounts), ErrorCode> {
    let items = render_items(materialized.bodies.items);
    let returned = u32::try_from(items.len()).map_err(|_| ErrorCode::Internal)?;
    let candidate_count = u32::try_from(candidate_count).map_err(|_| ErrorCode::Internal)?;
    let projection =
        build_projection_block(&materialized.ledger, visible, bootstrap.projection_lag);
    // §23.3④ (ADR-0041 D-H): the request's own six-column `StreamKey` ledger, counted in the
    // same RR snapshot that closed the ledger and hydrated the bodies. `classify()` maps this
    // route's `PlannerDecision::Class(_)` to `SemanticBounded`, so — unlike `memory.enumerate`
    // — no census travels with these counts and §22.0's exact-without-a-predicate trap is not
    // on this path. What they buy is the removal of `count_unknown`: the one reading that kept
    // a healthy semantic read at `cannot_establish` after card 18 made its ratio real.
    let (evidence, knowledge) = materialized.pipeline.blocks();
    let pipeline = PipelineBlock {
        evidence,
        knowledge,
        projection: projection.value,
    };
    let provenance = ProvenanceBlock {
        binary_build: bootstrap.binary_build.clone(),
        projection_version: ProvenanceValue::Used {
            id: projection_version.to_owned(),
        },
        embedding_model_id: ProvenanceValue::Used {
            id: format!("{embedding_model_id}@{}", runtime.embedding_version),
        },
        rerank_model_id: rerank.model.clone(),
        card_builder_version: ProvenanceValue::NotApplicable {},
        profile_fingerprint: request.profile_fingerprint_identity().clone(),
        profile: ProfileBlock {
            top_k: request.top_k(),
            cand_k: request.cand_k(),
            cand_k_formula: request.cand_k_formula(),
            // The legs this answer ran: the sparse leg is a profile lane once it ran, `ok` or `failed` (ADR-0083 D-C).
            lanes: std::iter::once("dense")
                .chain((sparse != SparseLeg::NotRun).then_some("sparse"))
                .map(str::to_owned)
                .collect(),
        },
    };
    // The classifier judges the lane whose answer this is (dense); a failed sparse leg degrades, it does not make the
    // answer unestablishable (ADR-0083 D-C, §52.3 Q1).
    let lane_status = LaneStatus::Ok;
    let census = CensusResult::ok_without_enumeration();
    let planner_class = request
        .planner_decision()
        .wire_class()
        .map_or("CANNOT_ESTABLISH", QueryClass::as_wire_name);
    let substituted = dense_lane_substitution(request.planner_decision(), explicit_mode);
    // ADR-0083 D-C / §53.1: a failed sparse leg is counted here, with `LANE_SUBSTITUTED`, once the answer is being
    // assembled — never before the hydrate gate, where a later error would leave a counted degrade without a retrieval.
    let (sparse_lane, sparse_degradations) = match sparse {
        SparseLeg::NotRun => (LaneStatus::NotRequired, Vec::new()),
        SparseLeg::Answered => (LaneStatus::Ok, Vec::new()),
        SparseLeg::Failed => {
            let (lane, codes) = sparse_lane_unavailable();
            (
                lane,
                codes
                    .into_iter()
                    .map(|code| code.line_format())
                    .collect::<Vec<String>>(),
            )
        }
    };
    // ADR-0084 D-D / §53.1: a rerank fallback is counted here too, once the answer is being assembled and never before the
    // hydrate gate, so a later error leaves no counted degrade without a finished retrieval.
    let rerank_degradations: Vec<String> = degradations(rerank.failure)
        .into_iter()
        .map(|code| code.line_format())
        .collect();
    let reranked_count = rerank.reranked_count;
    // The object the answer reports as `provenance.stage_ms`, kept for the query-hash log (ADR-0081 D-A).
    let mut stage_ms = None;
    let pending = dense_lane_outcome_block(
        request,
        CompletenessInputs {
            lane_status: &lane_status,
            census: &census,
            ledger: &materialized.ledger,
            pipeline: &pipeline,
            provenance: &provenance,
            visible,
            context: None,
            mandatory_missing: 0,
            lag_threshold: bootstrap.projection_lag,
        },
        |outcome| {
            let value = serde_json::to_value(Envelope {
                items,
                completeness: CompletenessBlock {
                    class: outcome.class,
                    reason: outcome.reason,
                    exact: outcome.exact,
                    known_lower_bound: outcome.known_lower_bound,
                    lanes: std::collections::BTreeMap::from([
                        ("dense".to_owned(), lane_status),
                        ("sparse".to_owned(), sparse_lane),
                    ]),
                    candidate_count,
                    reranked_count,
                    returned,
                    truncated: candidate_count > returned,
                    degradations: projection
                        .degradations
                        .iter()
                        .chain(&substituted)
                        .map(|code| code.line_format())
                        .chain(sparse_degradations.iter().cloned())
                        .chain(rerank_degradations.iter().cloned())
                        .collect(),
                },
                pipeline: pipeline.clone(),
                provenance: provenance.clone(),
                freshness: FreshnessBlock {
                    class: FreshnessClass::Unknown,
                    latest_evidence_at: None,
                    state_age_seconds: None,
                },
                grounding: materialized.grounding,
                mandatory: MandatoryReport::NotRun,
                pinned: PinnedReport::NotRun,
            })
            .map_err(|_| ErrorCode::Internal)?;
            clock.lap(Stage::Assemble);
            // ADR-0055 D-C/D-E: recall-only provenance keys, inserted here rather than on the
            // shared `ProvenanceBlock` (context/memory schemas are additionalProperties:false).
            let mut value = value;
            let provenance = value
                .get_mut("provenance")
                .and_then(Value::as_object_mut)
                .ok_or(ErrorCode::Internal)?;
            provenance.insert("planner_class".to_owned(), json!(planner_class));
            let report = clock.to_json();
            stage_ms = Some(report.clone());
            provenance.insert("stage_ms".to_owned(), report);
            catalog.validate_output(ToolName::Recall, &value)?;
            let text = serde_json::to_string(&value).map_err(|_| ErrorCode::Internal)?;
            Ok(ToolOutput {
                text,
                structured_content: value,
                is_error: false,
            })
        },
    )?;
    let counts = QueryLogCounts {
        cand_k: request.cand_k(),
        candidates: candidate_count,
        visible,
        returned,
        stage_ms,
    };
    Ok((pending, counts))
}

fn render_items(items: Vec<MaterializedItem>) -> Vec<Value> {
    items
        .into_iter()
        .map(|item| match item {
            MaterializedItem::Memory { memory_id, content } => json!({
                "kind": "memory",
                "memory_id": memory_id,
                "content": content,
            }),
            MaterializedItem::TemporaryEvidence {
                evidence_id,
                stream_seq,
                processing_state,
                payload,
                linked_memory_ids,
            } => json!({
                "kind": "temporary_evidence",
                "evidence_id": evidence_id,
                "stream_seq": stream_seq,
                "processing_state": processing_state.as_db_str(),
                "payload": payload,
                "linked_memory_ids": linked_memory_ids,
            }),
            MaterializedItem::ArtifactUnavailable {
                evidence_id,
                stream_seq,
                processing_state,
                linked_memory_ids,
            } => json!({
                "kind": "artifact_unavailable",
                "evidence_id": evidence_id,
                "stream_seq": stream_seq,
                "processing_state": processing_state.as_db_str(),
                "linked_memory_ids": linked_memory_ids,
            }),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use humaux_adapters::retrieve::ProcessingState;
    use humaux_domain::identity::{BoundedSet, PrincipalId};
    use humaux_projection::dense::build_dense_filter;
    use humaux_projection::note_chunks::CardSlot;
    use humaux_retrieval::rerank::ModelIdentity;
    use std::sync::{Mutex, atomic::AtomicUsize, atomic::Ordering};

    use crate::rerank_client::RerankPort;

    fn clock_after(laps: &[Stage]) -> Value {
        let mut clock = StageClock::start();
        for stage in laps {
            clock.lap(*stage);
        }
        clock.to_json()
    }

    #[test]
    fn stage_clock_reports_every_stage_only_for_the_full_lap_sequence() {
        let full = clock_after(&LAP_SEQUENCE);
        for name in STAGE_NAMES.iter().chain(&["total"]) {
            assert!(full[name].is_f64(), "{name} missing: {full}");
        }
        // A dropped inner lap (hydrate), a dropped first route lap, a dropped final assemble lap
        // and a doubled lap all fold time into a neighbour — each must lose the split.
        let without = |skip: usize| {
            let laps: Vec<Stage> = LAP_SEQUENCE
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != skip)
                .map(|(_, s)| *s)
                .collect();
            clock_after(&laps)
        };
        let mut doubled = LAP_SEQUENCE.to_vec();
        doubled.insert(4, Stage::Embed);
        for (label, broken) in [
            ("no hydrate lap", without(6)),
            ("no first route lap", without(0)),
            ("no assemble lap", without(8)),
            ("doubled embed lap", clock_after(&doubled)),
        ] {
            let object = broken.as_object().expect("stage_ms object");
            assert_eq!(
                object.keys().collect::<Vec<_>>(),
                ["total"],
                "{label}: {broken}"
            );
        }
    }

    fn scope() -> AuthorizationScope {
        AuthorizationScope::new(
            TenantId::new(),
            PrincipalId::new(),
            None,
            BoundedSet::new(Vec::<WorkspaceId>::new()).expect("empty workspace set"),
        )
    }

    /// ADR-0083 U5 / U6 / D-A, the gateway's sparse decision as a 2x2 truth table: the leg runs only when the profile
    /// enables it AND tenant policy allows in-Cell text processing, and then its corpus filter is exactly the
    /// unnarrowed tenant + visibility predicate (`build_dense_filter` with no narrowing), never anything wider.
    /// Fault: ignore the policy input (pass `true` on to `build_sparse_lane`), ignore `enabled`, or build the corpus
    /// from anything but the scope's own predicate ⇒ red.
    #[test]
    fn sparse_corpus_filter_follows_the_flag_and_the_policy_and_is_the_authorization_predicate() {
        let scope = scope();
        for (enabled, allowed, runs) in [
            (false, false, false),
            (false, true, false),
            (true, false, false),
            (true, true, true),
        ] {
            let corpus = sparse_corpus_filter(enabled, allowed, &scope);
            assert_eq!(
                corpus.is_some(),
                runs,
                "enabled={enabled} allowed={allowed}"
            );
            if let Some(corpus) = corpus {
                assert_eq!(
                    corpus.as_condition(),
                    build_dense_filter(&scope, &[]).as_condition()
                );
            }
        }
    }

    /// ADR-0083 U7: the sparse leg's own time is a sub-timing beside the eight stages: present only when the leg ran
    /// (and the laps were whole), never one of the eight, and it moves no lap.
    #[test]
    fn sparse_sub_timing_rides_beside_the_stages_only_when_the_leg_ran() {
        let mut clock = StageClock::start();
        for stage in LAP_SEQUENCE {
            clock.lap(stage);
        }
        assert!(clock.to_json().get(SPARSE_SUB_TIMING).is_none());
        clock.note_sparse(Duration::from_millis(7));
        let report = clock.to_json();
        assert_eq!(report[SPARSE_SUB_TIMING], json!(7.0));
        for name in STAGE_NAMES {
            assert!(report[name].is_f64(), "{name} missing: {report}");
        }
        assert!(
            !STAGE_NAMES.contains(&SPARSE_SUB_TIMING),
            "a sub-timing is not a stage"
        );
    }

    fn leg(entries: &[(u128, Option<u128>)]) -> Vec<DenseCandidate> {
        entries
            .iter()
            .map(|(point, memory)| DenseCandidate {
                point_id: PointId::Uuid(Uuid::from_u128(*point)),
                score: 0.0,
                memory_id: memory.map(Uuid::from_u128),
            })
            .collect()
    }

    fn fused_memories(fused: &[DenseCandidate]) -> Vec<u128> {
        fused
            .iter()
            .map(|c| c.memory_id.expect("grouped fixture").as_u128())
            .collect()
    }

    /// G-RET-9 (ADR-0083 D-C): `score(m) = sum 1 / (rrf_k + rank)` over the legs that returned `m`, ranks 1-based. A
    /// Memory both legs found outranks one a single leg found at the same depth, and a Memory only the sparse leg found
    /// is ordered by that one contribution.
    /// Fault: drop a leg from the sum, or count ranks from 0 ⇒ red.
    #[test]
    fn rrf_sums_reciprocal_ranks_over_the_legs_that_found_the_memory() {
        // dense: 1, 2, 3 ; sparse: 3, 4 — 3 is found by both (ranks 3 and 1).
        let dense = leg(&[(11, Some(1)), (12, Some(2)), (13, Some(3))]);
        let sparse = leg(&[(23, Some(3)), (24, Some(4))]);
        let fused = fuse_rrf([&dense, &sparse], 60, true, 10);
        // 3 leads on 1/63 + 1/61; 1 is 1/61; 2 (dense rank 2) and 4 (sparse rank 2) tie on 1/62, 2 first by id.
        assert_eq!(fused_memories(&fused), [3, 1, 2, 4]);
        let expected = 1.0 / 63.0 + 1.0 / 61.0;
        assert!(
            (fused[0].score - expected).abs() < 1e-12,
            "{}",
            fused[0].score
        );
        assert!(
            (fused[3].score - 1.0 / 62.0).abs() < 1e-12,
            "one leg, rank 2"
        );
        // The dense leg's point stands for a Memory both legs found.
        assert_eq!(fused[0].point_id, PointId::Uuid(Uuid::from_u128(13)));
        // The cut keeps the best `cap`.
        assert_eq!(
            fused_memories(&fuse_rrf([&dense, &sparse], 60, true, 2)),
            [3, 1]
        );
    }

    /// G-RET-9 (ADR-0083 D-C): equal scores order by `memory_id` ascending, never by arrival: the same two legs given in
    /// either order, and with the tied entries permuted inside their legs, give one list.
    /// Fault: break ties by insertion order (a stable sort on the score alone) ⇒ red.
    #[test]
    fn rrf_ties_order_by_memory_id_ascending_and_repeat_identically() {
        // Memory 9 is dense rank 1, memory 2 is sparse rank 1, memory 5 is dense rank 2 and sparse rank 2 is memory 7:
        // 9 ties 2 (1/61) and 5 ties 7 (1/62).
        let dense = leg(&[(19, Some(9)), (15, Some(5))]);
        let sparse = leg(&[(22, Some(2)), (27, Some(7))]);
        let forward = fuse_rrf([&dense, &sparse], 60, true, 10);
        assert_eq!(fused_memories(&forward), [2, 9, 5, 7]);
        let swapped = fuse_rrf([&sparse, &dense], 60, true, 10);
        assert_eq!(
            fused_memories(&swapped),
            [2, 9, 5, 7],
            "leg order is not a tie-break"
        );
        assert_eq!(forward, fuse_rrf([&dense, &sparse], 60, true, 10), "repeat");
    }

    // ---- ADR-0084: the rerank stage, D-C 3 to 5 and D-D, without a database or a model ----

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn pin() -> ModelIdentity {
        ModelIdentity::new("org/model", "rev", "recipe", HASH, HASH).expect("a valid identity")
    }

    /// How a [`StubPort`] answers, given the documents it was sent.
    type Script = Box<dyn Fn(&[String]) -> RerankAnswer + Send + Sync>;

    /// A rerank port that counts its calls, records the documents it was sent and answers as scripted after `delay`.
    struct StubPort {
        calls: AtomicUsize,
        sent: Mutex<Vec<Vec<String>>>,
        delay: Duration,
        answer: Script,
    }

    #[async_trait::async_trait]
    impl RerankPort for StubPort {
        async fn rerank(&self, call: RerankCall<'_>) -> RerankAnswer {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.sent
                .lock()
                .expect("sent lock")
                .push(call.documents.to_vec());
            tokio::time::sleep(self.delay).await;
            (self.answer)(call.documents)
        }
    }

    fn stub(
        delay: Duration,
        answer: impl Fn(&[String]) -> RerankAnswer + Send + Sync + 'static,
    ) -> Arc<StubPort> {
        Arc::new(StubPort {
            calls: AtomicUsize::new(0),
            sent: Mutex::new(Vec::new()),
            delay,
            answer: Box::new(answer),
        })
    }

    /// A port that scores the document at index `i` as `i`, so the last document ranks first.
    fn reversing(delay: Duration) -> Arc<StubPort> {
        stub(delay, |documents| RerankAnswer::Scored {
            scores: (0..documents.len()).map(|i| i as f32).collect(),
            model: pin(),
        })
    }

    fn memory(id: u128) -> MaterializedItem {
        MaterializedItem::Memory {
            memory_id: Uuid::from_u128(id),
            content: json!({}),
        }
    }

    fn overlay() -> MaterializedItem {
        MaterializedItem::ArtifactUnavailable {
            evidence_id: Uuid::from_u128(900),
            stream_seq: 1,
            processing_state: ProcessingState::Issued,
            linked_memory_ids: Vec::new(),
        }
    }

    fn ids(items: &[MaterializedItem]) -> Vec<u128> {
        memory_ids(items).iter().map(Uuid::as_u128).collect()
    }

    /// Slots and texts for the given Memories: a legacy slot, title `t<id>`, body `b<id>`.
    fn hydrated(ids: &[u128]) -> (PointSlots, BTreeMap<Uuid, MemoryText>) {
        let slots = ids
            .iter()
            .map(|id| (Uuid::from_u128(*id), Some(CardSlot::Legacy)))
            .collect();
        let texts = ids
            .iter()
            .map(|id| {
                (
                    Uuid::from_u128(*id),
                    MemoryText {
                        memory_id: Uuid::from_u128(*id),
                        title: Some(format!("t{id}")),
                        body: Some(format!("b{id}")),
                    },
                )
            })
            .collect();
        (slots, texts)
    }

    fn input(lane: Option<&RerankLane>, selected: bool, depth: usize) -> RerankStageInput<'_> {
        RerankStageInput {
            lane,
            selected,
            depth,
            max_len: 256,
            wait: Duration::from_millis(500),
            call_id: Uuid::from_u128(1),
            query: "the query",
        }
    }

    /// ADR-0084 D-D row 1: the rerank branch is selected only with the profile switch AND tenant policy.
    /// Fault: ignore the policy input ⇒ the (true, false) row goes red.
    #[test]
    fn the_rerank_branch_needs_the_profile_switch_and_the_tenant_policy() {
        for (enabled, allowed, selected) in [
            (false, false, false),
            (false, true, false),
            (true, false, false),
            (true, true, true),
        ] {
            assert_eq!(
                rerank_branch_selected(enabled, allowed),
                selected,
                "enabled={enabled} allowed={allowed}"
            );
        }
    }

    /// The named in-cell test (ADR-0084 D-B Policy, T-RET-7d): a tenant whose `in_cell_text_processing_allowed` is false
    /// gets no rerank call and the fused order. The stage is handed the verdict `rerank_branch_selected(true, false)`,
    /// a counting port that would reverse every list, and hydrated texts: nothing is called, the items keep their
    /// order, `rerank_model_id` is `not_applicable`, and there is no degradation.
    /// Fault: ignore the policy in `rerank_branch_selected` ⇒ the port is called and the order reverses ⇒ red.
    #[tokio::test]
    async fn a_tenant_without_in_cell_text_processing_gets_no_rerank_call_and_the_fused_order() {
        let port = reversing(Duration::ZERO);
        let lane = RerankLane::new(port.clone(), pin());
        let (slots, texts) = hydrated(&[1, 2, 3]);
        let mut items = vec![memory(1), memory(2), memory(3)];
        let selected = rerank_branch_selected(true, false);
        let report = rerank_stage(
            &input(Some(&lane), selected, 25),
            &mut items,
            &slots,
            &texts,
        )
        .await;
        assert_eq!(port.calls.load(Ordering::SeqCst), 0, "no rerank call");
        assert_eq!(ids(&items), [1, 2, 3], "the fused order");
        assert_eq!(report.model, ProvenanceValue::NotApplicable {});
        assert_eq!(report.reranked_count, 0);
        assert_eq!(report.failure, None);
    }

    /// ADR-0084 D-C 3 and G-RET-13: the documents are the first `depth` visible Memories that the hydrate transaction
    /// returned a text for, in visible order. A Memory with no text entry (the gate refused it, so the transaction
    /// never read it), one with an unknown slot and one with no body are not sent and keep their place after the scored
    /// ones; a Memory beyond `depth` likewise.
    /// Fault: send the documents of every visible Memory, or of a Memory with no gated text ⇒ red.
    #[tokio::test]
    async fn only_gated_texts_inside_the_depth_window_are_sent() {
        let port = reversing(Duration::ZERO);
        let lane = RerankLane::new(port.clone(), pin());
        let (mut slots, mut texts) = hydrated(&[1, 2, 3, 4, 5, 6]);
        texts.remove(&Uuid::from_u128(2)); // refused by the gate: the transaction read no text for it
        slots.insert(Uuid::from_u128(3), None); // a profile this build does not know
        texts.insert(
            Uuid::from_u128(4),
            MemoryText {
                memory_id: Uuid::from_u128(4),
                title: Some("t4".to_owned()),
                body: None, // a Memory with no body
            },
        );
        let mut items = vec![
            memory(1),
            memory(2),
            memory(3),
            memory(4),
            memory(5),
            memory(6),
        ];
        // depth 5: Memories 1 to 5 are the window; 6 is beyond it.
        let report = rerank_stage(&input(Some(&lane), true, 5), &mut items, &slots, &texts).await;
        let sent = port.sent.lock().expect("sent lock");
        assert_eq!(
            *sent,
            [vec![format!("t1{NL}b1"), format!("t5{NL}b5")]],
            "documents of Memories 1 and 5 only, one call"
        );
        drop(sent);
        // Scored: 1 and 5 (5 first, it scored higher), then the rest in fused order.
        assert_eq!(ids(&items), [5, 1, 2, 3, 4, 6]);
        assert_eq!(report.reranked_count, 2);
        assert_eq!(report.failure, None);
    }

    /// The `\n` between title and body (`projection::note_chunks` separator) as a literal for the expectations above.
    const NL: &str = humaux_projection::note_chunks::NOTE_CHUNKS_V1_SEPARATOR;

    /// ADR-0084 D-C 5: a scored reply reorders the Memory items only; an overlay item keeps its place, nothing is added
    /// or dropped, and the report reads `used` with the count of the scored.
    #[tokio::test]
    async fn a_scored_reply_reorders_the_memory_items_only() {
        let port = reversing(Duration::ZERO);
        let lane = RerankLane::new(port, pin());
        let (slots, texts) = hydrated(&[1, 2, 3]);
        let mut items = vec![memory(1), overlay(), memory(2), memory(3)];
        let report = rerank_stage(&input(Some(&lane), true, 25), &mut items, &slots, &texts).await;
        assert_eq!(ids(&items), [3, 2, 1]);
        assert_eq!(items[1], overlay(), "an overlay item is not moved");
        assert_eq!(items.len(), 4);
        assert_eq!(report.reranked_count, 3);
        assert_eq!(
            report.model,
            ProvenanceValue::Used {
                id: pin().model_id().as_str().to_owned()
            }
        );
        assert_eq!(report.failure, None);
    }

    /// ADR-0084 D-D rows 3 and 4 (G-RET-12 at unit level): a stalled port past the wait, a failed answer, an unusable
    /// reply and another model's answer each keep the fused order, count 0, `cannot_establish` and name the fallback.
    /// Fault: swallow the timeout and answer the scored order ⇒ red.
    #[tokio::test]
    async fn a_stalled_failed_or_foreign_answer_keeps_the_fused_order() {
        let other = ModelIdentity::new("org/model", "other", "recipe", HASH, HASH).expect("valid");
        let cases: Vec<(&str, Arc<StubPort>, RerankFailure)> = vec![
            (
                "stalled past the wait",
                reversing(Duration::from_secs(5)),
                RerankFailure::Unavailable,
            ),
            (
                "failed",
                stub(Duration::ZERO, |_| RerankAnswer::Failed {
                    class: "transport",
                }),
                RerankFailure::Unavailable,
            ),
            (
                "a score per document is missing",
                stub(Duration::ZERO, |_| RerankAnswer::Scored {
                    scores: vec![1.0],
                    model: pin(),
                }),
                RerankFailure::Unavailable,
            ),
            (
                "another model answered",
                stub(Duration::ZERO, move |documents| RerankAnswer::Scored {
                    scores: vec![0.5; documents.len()],
                    model: other.clone(),
                }),
                RerankFailure::ModelMismatch,
            ),
        ];
        for (label, port, failure) in cases {
            let lane = RerankLane::new(port.clone(), pin());
            let (slots, texts) = hydrated(&[1, 2, 3]);
            let mut items = vec![memory(1), memory(2), memory(3)];
            let mut stage = input(Some(&lane), true, 25);
            stage.wait = Duration::from_millis(50);
            let report = rerank_stage(&stage, &mut items, &slots, &texts).await;
            assert_eq!(ids(&items), [1, 2, 3], "{label}: the fused order");
            assert_eq!(report.reranked_count, 0, "{label}");
            assert_eq!(report.model, ProvenanceValue::CannotEstablish {}, "{label}");
            assert_eq!(report.failure, Some(failure), "{label}");
            assert_eq!(port.calls.load(Ordering::SeqCst), 1, "{label}: one call");
        }
    }

    /// §23.1③ / ADR-0084 D-D: `not_applicable` is only the lane off, the tenant's policy, or no visible Memory to rank. A
    /// selected branch with visible Memories that cannot be scored is a failure, never `not_applicable`: no lane wired,
    /// and no document buildable (an unknown slot, an ordinal past the body, no readable text), each give the fused order,
    /// `RerankFailure::Unavailable` and `cannot_establish`, with no call; no visible Memory reads `not_applicable`.
    /// Fault: return `not_run` for a selected branch with no document ⇒ the second block goes red.
    #[tokio::test]
    async fn a_selected_branch_that_cannot_score_is_a_failure_and_no_memory_is_not_applicable() {
        let (slots, texts) = hydrated(&[1, 2]);
        let mut items = vec![memory(1), memory(2)];
        let report = rerank_stage(&input(None, true, 25), &mut items, &slots, &texts).await;
        assert_eq!(ids(&items), [1, 2]);
        assert_eq!(report.failure, Some(RerankFailure::Unavailable));
        assert_eq!(report.model, ProvenanceValue::CannotEstablish {});

        let port = reversing(Duration::ZERO);
        let lane = RerankLane::new(port.clone(), pin());
        // Visible Memories, no slot and no text for any: no document can be built.
        let report = rerank_stage(
            &input(Some(&lane), true, 25),
            &mut items,
            &PointSlots::new(),
            &BTreeMap::new(),
        )
        .await;
        assert_eq!(port.calls.load(Ordering::SeqCst), 0, "no document, no call");
        assert_eq!(ids(&items), [1, 2], "the fused order");
        assert_eq!(
            report.failure,
            Some(RerankFailure::Unavailable),
            "a selected branch that could not score is a failure"
        );
        assert_eq!(report.model, ProvenanceValue::CannotEstablish {});
        assert_eq!(report.reranked_count, 0);

        let mut empty: Vec<MaterializedItem> = Vec::new();
        let report = rerank_stage(&input(Some(&lane), true, 25), &mut empty, &slots, &texts).await;
        assert_eq!(
            report.model,
            ProvenanceValue::NotApplicable {},
            "no visible Memory: nothing was selected to fail"
        );
        assert_eq!(report.failure, None);
    }

    /// ADR-0084 U7: no budget left means no call: the stage degrades to the fused order at once instead of dialling a
    /// worker whose answer could not be waited for. Fault: dial anyway ⇒ the port is called ⇒ red.
    #[tokio::test]
    async fn a_zero_wait_degrades_without_calling_the_worker() {
        let port = reversing(Duration::ZERO);
        let lane = RerankLane::new(port.clone(), pin());
        let (slots, texts) = hydrated(&[1, 2, 3]);
        let mut items = vec![memory(1), memory(2), memory(3)];
        let mut stage = input(Some(&lane), true, 25);
        stage.wait = Duration::ZERO;
        let report = rerank_stage(&stage, &mut items, &slots, &texts).await;
        assert_eq!(port.calls.load(Ordering::SeqCst), 0, "no budget, no call");
        assert_eq!(ids(&items), [1, 2, 3], "the fused order");
        assert_eq!(report.failure, Some(RerankFailure::Unavailable));
        assert_eq!(report.model, ProvenanceValue::CannotEstablish {});
    }

    /// ADR-0084 U7: the wait is the registered `rerank_timeout_ms` capped by the handler budget that is left less the
    /// reserve kept for the steps after the rerank, and never negative. Fault: drop the reserve ⇒ the second row goes
    /// red; wait the whole budget left instead of the registered wait ⇒ the first row goes red.
    #[test]
    fn the_rerank_wait_leaves_the_reserve_and_never_outlives_the_handler_budget() {
        let ms = Duration::from_millis;
        let wait = |elapsed, reserve| rerank_wait(ms(4_000), ms(20_000), ms(elapsed), ms(reserve));
        assert_eq!(
            wait(100, 1_000),
            ms(4_000),
            "plenty left: the registered wait"
        );
        assert_eq!(
            wait(15_500, 1_000),
            ms(3_500),
            "the budget left less the reserve"
        );
        assert_eq!(wait(18_800, 1_000), ms(200), "a thin budget");
        assert_eq!(
            wait(19_500, 1_000),
            Duration::ZERO,
            "the reserve takes what is left"
        );
        assert_eq!(wait(25_000, 1_000), Duration::ZERO, "past the deadline");
    }

    /// ADR-0084 D-C 3: the point that stands for a fused Memory is its best leg hit's, dense first: the dense leg's point
    /// for a Memory both legs found, the sparse leg's for a Memory only the sparse leg found. That point is the one whose
    /// registry slot picks the chunk the reranker scores (`retrieve::stand_in_points` keeps the first point per Memory).
    /// Fault: let the sparse candidate replace the dense one for a Memory both legs found ⇒ red on the first assertion.
    #[test]
    fn the_fused_candidate_is_the_dense_hit_else_the_sparse_hit() {
        let dense = leg(&[(11, Some(1))]);
        let sparse = leg(&[(22, Some(2)), (21, Some(1))]);
        let fused = fuse_rrf([&dense, &sparse], 60, true, 10);
        let point_of = |memory: u128| {
            fused
                .iter()
                .find(|c| c.memory_id == Some(Uuid::from_u128(memory)))
                .map(|c| c.point_id)
        };
        assert_eq!(point_of(1), Some(PointId::Uuid(Uuid::from_u128(11))));
        assert_eq!(point_of(2), Some(PointId::Uuid(Uuid::from_u128(22))));
    }

    /// ADR-0083 D-C: a plain (ungrouped) dense leg carries no `memory_id`, so the legs agree on the point; a sparse hit
    /// of the same point merges into it. With one empty leg the fusion is the other leg's order.
    #[test]
    fn rrf_keys_plain_dense_hits_by_point_and_passes_one_leg_through() {
        let dense = leg(&[(31, None), (32, None)]);
        let sparse = leg(&[(32, Some(302))]);
        let fused = fuse_rrf([&dense, &sparse], 60, false, 10);
        assert_eq!(
            fused.iter().map(|c| c.point_id).collect::<Vec<_>>(),
            [
                PointId::Uuid(Uuid::from_u128(32)),
                PointId::Uuid(Uuid::from_u128(31))
            ],
            "the point both legs found leads"
        );
        let only_dense = fuse_rrf([&dense, &[]], 60, false, 10);
        assert_eq!(
            only_dense.iter().map(|c| c.point_id).collect::<Vec<_>>(),
            dense.iter().map(|c| c.point_id).collect::<Vec<_>>(),
        );
    }
}
