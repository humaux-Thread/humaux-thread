//! `gateway::recall` — Native authenticated semantic recall HTTP/MCP adapter boundary (ADR-0130).
//! Depends-on: crates=[async-trait, humaux-adapters, humaux-application, humaux-domain, humaux-infra-cell, humaux-projection, humaux-protocol, humaux-retrieval, serde_json, time, tokio, uuid]; services=[]; env=[]; modules=[adapters::postgres, application::affect, application::recall_read, application::retrieval_embedding_port, domain::affect, domain::error, domain::identity, domain::ids, domain::subject, gateway::bootstrap, gateway::context, gateway::rerank_client, infra-cell::resource, infra-cell::transport, projection::stream, protocol::mcp, protocol::mcp_catalog, retrieval::completeness, retrieval::envelope]
//! Called-by: [gateway::bootstrap, gateway::context, gateway::mcp_application, tests]
//! Invariants: [this module owns only HTTP/MCP input/output mapping, late mood rerank composition, and async runtime primitives; all semantic recall orchestration, RRF, degrade sequencing, and single-gate hydration flow through application::recall_read::search_recall]
//! Spec: Baseline §17.3; §17.6; §19.1; §23.3; §33; §48.1; §55.1; §78.1; ADR-0029; ADR-0031; ADR-0055; ADR-0056; ADR-0081; ADR-0083; ADR-0084; ADR-0130

use std::{
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use humaux_adapters::postgres::RuntimeDbPool;
use humaux_application::affect::{affects_for_memories, observed, rerank_by_mood};
use humaux_application::recall_read::{
    BoxFuture, DenseLegFailure, LateMemoryRerankPort, MaterializedItem, RecallAsyncSupport,
    RecallQueryLogJob, RecallQueryLogPort, RerankAnswer, SearchRecallConfig, SearchRecallInput,
    SparseLegFailure, report_query_log_failure, search_recall,
};
use humaux_application::retrieval_embedding_port::RetrievalEmbeddingPort;
use humaux_domain::{
    affect::{AffectFilter, MoodPoint},
    error::ErrorCode,
    identity::AuthorizationScope,
    ids::{TenantId, WorkspaceId},
    subject::SubjectId,
};
use humaux_infra_cell::{IntraCellHttpTransport, IntraCellResourceRegistry};
use humaux_projection::stream::StreamKey;
use humaux_protocol::{
    mcp::{ToolName, ToolOutput},
    mcp_catalog::CanonicalCatalog,
};
use humaux_retrieval::{completeness::LedgerClosure, envelope::PendingEnvelope};
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::context::ContextBootstrap;
use crate::rerank_client::RerankLane;

/// Bootstrap-owned components for the one native private-memory dense lane.
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
    /// for both the sparse leg and the rerank branch. Production leaves the default, `bootstrap::default_text_processing_policy`;
    /// a test sets another through [`SemanticRecallRuntime::with_text_processing_policy`].
    text_processing_allowed: fn(TenantId) -> bool,
}

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
            text_processing_allowed: crate::bootstrap::default_text_processing_policy(),
        })
    }

    /// A runtime that reads `policy` instead of the default policy for every tenant.
    #[must_use]
    pub fn with_text_processing_policy(mut self, policy: fn(TenantId) -> bool) -> Self {
        self.text_processing_allowed = policy;
        self
    }

    /// At most a quarter of the pool (minimum one) writes log rows at once, so the log can never take the answer path's
    /// connections, and a write lives no longer than the pool's own acquire timeout.
    fn query_log_gate(&self, log_port: &dyn RecallQueryLogPort) -> &(Arc<Semaphore>, Duration) {
        self.query_log_gate.get_or_init(|| {
            let (max_connections, acquire_timeout) = log_port.query_log_limits();
            let permits = usize::try_from(max_connections / 4)
                .unwrap_or(usize::MAX)
                .max(1);
            (Arc::new(Semaphore::new(permits)), acquire_timeout)
        })
    }

    /// §23.1② live `visible` for the two PG-only read routes (`memory.*`, `context.assemble`),
    /// which hold no Qdrant transport of their own.
    pub(crate) async fn visible_index_count(
        &self,
        pool: &RuntimeDbPool,
        authorization: &AuthorizationScope,
        key: &StreamKey,
        serving_version: Option<&str>,
        ledger: &LedgerClosure,
    ) -> Option<u64> {
        let route_store = crate::bootstrap::recall_route_store(pool);
        let index_store =
            crate::bootstrap::recall_index_store(pool, self.qdrant.as_ref(), &self.cell_registry);
        humaux_application::recall_read::visible_index_count(
            &route_store,
            &index_store,
            authorization,
            key,
            serving_version,
            ledger,
        )
        .await
    }
}

pub struct RecallSearchRequest {
    pub query: String,
    pub workspace_id: WorkspaceId,
    pub consistency_token: Option<String>,
    pub mode: Option<String>,
    pub completeness_request: Option<String>,
    pub limit: Option<u32>,
    pub subject_ids: Vec<SubjectId>,
    pub affect: Option<AffectFilter>,
    pub mood_congruence: Option<MoodPoint>,
}

struct GatewayMoodRerank {
    pool: Arc<RuntimeDbPool>,
    mood: Option<MoodPoint>,
}

#[async_trait]
impl LateMemoryRerankPort for GatewayMoodRerank {
    async fn rerank_memories(
        &self,
        authorization: &AuthorizationScope,
        items: &mut [MaterializedItem],
    ) -> Result<u32, ErrorCode> {
        let Some(mood) = self.mood else {
            return Ok(0);
        };
        let memory_ids: Vec<Uuid> = items
            .iter()
            .filter_map(|item| match item {
                MaterializedItem::Memory { memory_id, .. } => Some(*memory_id),
                _ => None,
            })
            .collect();
        let store = crate::bootstrap::affect_store(&self.pool);
        let rows = affects_for_memories(&store, authorization, &memory_ids).await?;
        let observed = observed(&rows, time::OffsetDateTime::now_utc());
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
}

struct GatewayRecallSupport {
    log_gate: Arc<Semaphore>,
    log_deadline: Duration,
}

#[async_trait]
impl RecallAsyncSupport for GatewayRecallSupport {
    async fn run_candidate_legs(
        &self,
        dense: BoxFuture<
            '_,
            Result<Vec<humaux_application::recall_read::RecallCandidate>, DenseLegFailure>,
        >,
        sparse: Option<(
            Duration,
            BoxFuture<
                '_,
                Result<Vec<humaux_application::recall_read::RecallCandidate>, &'static str>,
            >,
        )>,
    ) -> (
        Result<Vec<humaux_application::recall_read::RecallCandidate>, DenseLegFailure>,
        Option<(
            Result<Vec<humaux_application::recall_read::RecallCandidate>, SparseLegFailure>,
            Duration,
        )>,
    ) {
        let sparse_fut = async move {
            let (budget, call) = sparse?;
            let started = Instant::now();
            let outcome = match tokio::time::timeout(budget, call).await {
                Ok(Ok(candidates)) => Ok(candidates),
                Ok(Err(class)) => Err(SparseLegFailure::Class(class)),
                Err(_elapsed) => Err(SparseLegFailure::Timeout),
            };
            Some((outcome, started.elapsed()))
        };
        tokio::join!(dense, sparse_fut)
    }

    async fn timeout_rerank(
        &self,
        wait: Duration,
        call: BoxFuture<'_, RerankAnswer>,
    ) -> Option<RerankAnswer> {
        tokio::time::timeout(wait, call).await.ok()
    }

    fn spawn_query_log(
        &self,
        request_id: Uuid,
        log_port: Arc<dyn RecallQueryLogPort>,
        job: RecallQueryLogJob,
    ) {
        let Ok(permit) = Arc::clone(&self.log_gate).try_acquire_owned() else {
            report_query_log_failure(request_id, "dropped_backpressure");
            return;
        };
        let deadline = self.log_deadline;
        // ponytail: rows in flight at shutdown are lost; observability only
        tokio::spawn(async move {
            let _permit = permit;
            let RecallQueryLogJob {
                tenant_id,
                workspace_id,
                user_id,
                digest,
                counts,
            } = job;
            let logged = tokio::time::timeout(
                deadline,
                log_port.record_query(tenant_id, workspace_id, user_id, &digest, &counts),
            )
            .await;
            match logged {
                Ok(Ok(())) => {}
                Ok(Err(reason)) => report_query_log_failure(request_id, &reason),
                Err(_elapsed) => report_query_log_failure(request_id, "timeout"),
            }
        });
    }
}

/// Answers one `recall.search` through [`search_recall`] and maps the validated payload into an MCP [`ToolOutput`].
pub async fn search(
    pool: Arc<RuntimeDbPool>,
    runtime: Arc<SemanticRecallRuntime>,
    catalog: Arc<CanonicalCatalog>,
    authorization: AuthorizationScope,
    request_id: Uuid,
    bootstrap: ContextBootstrap,
    input: RecallSearchRequest,
) -> Result<PendingEnvelope<ToolOutput>, ErrorCode> {
    if input.mode.as_deref().is_some_and(|mode| mode != "semantic")
        || input.completeness_request.as_deref() == Some("required")
    {
        return Err(ErrorCode::DependencyUnavailable);
    }
    let text_processing_allowed = (runtime.text_processing_allowed)(authorization.tenant_id());
    let (family, key) = bootstrap.request_stream(authorization.tenant_id(), input.workspace_id);
    let route_store = crate::bootstrap::recall_route_store(&pool);
    let index_store = crate::bootstrap::recall_index_store(
        &pool,
        runtime.qdrant.as_ref(),
        &runtime.cell_registry,
    );
    let log_port = crate::bootstrap::recall_query_log_store(Arc::clone(&pool));
    let (log_gate, log_deadline) = runtime.query_log_gate(log_port.as_ref());
    let async_support = GatewayRecallSupport {
        log_gate: Arc::clone(log_gate),
        log_deadline: *log_deadline,
    };
    let late_rerank = GatewayMoodRerank {
        pool: Arc::clone(&pool),
        mood: input.mood_congruence,
    };
    let config = SearchRecallConfig {
        request_id,
        authorization,
        family,
        key,
        profile: &bootstrap.profile,
        binary_build: &bootstrap.binary_build,
        projection_lag: bootstrap.projection_lag,
        embedding_version: &runtime.embedding_version,
        embedding_dimension: runtime.dimension,
        handler_timeout: runtime.handler_timeout,
        rerank: runtime.rerank.as_ref(),
        text_processing_allowed,
    };
    let use_case_input = SearchRecallInput {
        query: input.query,
        workspace_id: input.workspace_id,
        consistency_token: input.consistency_token,
        mode: input.mode,
        completeness_request: input.completeness_request,
        limit: input.limit,
        subject_ids: input.subject_ids,
        affect: input.affect,
    };
    search_recall(
        runtime.port.as_ref(),
        &route_store,
        &index_store,
        pool.as_ref(),
        log_port,
        &late_rerank,
        &async_support,
        config,
        use_case_input,
        |value| {
            catalog.validate_output(ToolName::Recall, &value)?;
            let text = serde_json::to_string(&value).map_err(|_| ErrorCode::Internal)?;
            Ok(ToolOutput {
                text,
                structured_content: value,
                is_error: false,
            })
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use humaux_application::recall_read::{
        ItemFreshness, MaterializationSnapshot, MaterializedBodies, ProcessingState,
        render_recall_items,
    };
    use humaux_retrieval::completeness::FreshnessClass;
    use humaux_retrieval::rerank::ModelIdentity;
    use serde_json::json;
    use std::collections::HashMap;

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn pin() -> ModelIdentity {
        ModelIdentity::new("org/model", "rev", "recipe", HASH, HASH).expect("a valid identity")
    }

    /// ADR-0111 D-C: unclassified Evidence prevents a fresh-only envelope claim.
    #[test]
    fn fresh_memory_with_temporary_evidence_has_unknown_summary() {
        let memory_id = Uuid::from_u128(1);
        let evidence_id = Uuid::from_u128(2);
        let unknown = ItemFreshness {
            class: FreshnessClass::Unknown,
            policy_id: None,
            policy_version: None,
            latest_evidence_at: None,
            state_age_seconds: None,
        };
        let mut fresh = unknown.clone();
        fresh.class = FreshnessClass::Fresh;
        fresh.policy_id = Some("evidence-per-type");
        fresh.policy_version = Some(1);
        let bodies = MaterializedBodies {
            snapshot: MaterializationSnapshot {
                context_snapshot_seq: 0,
                snapshot_token_sha256: String::new(),
            },
            items: vec![
                MaterializedItem::Memory {
                    memory_id,
                    content: json!({}),
                },
                MaterializedItem::TemporaryEvidence {
                    evidence_id,
                    stream_seq: 1,
                    processing_state: ProcessingState::Processing,
                    payload: json!({}),
                    linked_memory_ids: vec![],
                },
            ],
            freshness: HashMap::from([(memory_id, fresh), (evidence_id, unknown.clone())]),
        };
        assert_eq!(
            bodies.freshness_summary().class,
            FreshnessClass::Unknown,
            "ADR-0111 D-C: temporary Evidence must participate in the summary"
        );
        let rendered = render_recall_items(bodies.items, &bodies.freshness).expect("recall items");
        assert_eq!(rendered.len(), 2);
        CanonicalCatalog::load()
            .expect("catalog")
            .validate_output(ToolName::Recall, &json!({"items": rendered}))
            .expect("closed recall item schema");
        assert_eq!(
            rendered[1]["freshness"],
            serde_json::to_value(unknown).expect("annotation")
        );
    }

    #[tokio::test]
    async fn gateway_recall_support_times_out_stalled_rerank() {
        let support = GatewayRecallSupport {
            log_gate: Arc::new(Semaphore::new(1)),
            log_deadline: Duration::from_secs(1),
        };
        let answer = support
            .timeout_rerank(
                Duration::from_millis(20),
                Box::pin(async {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    RerankAnswer::Scored {
                        scores: vec![1.0],
                        model: pin(),
                    }
                }),
            )
            .await;
        assert_eq!(answer, None);
    }
}
