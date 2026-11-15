//! `application::recall_read` — ordered candidates enter one authoritative snapshot (Baseline §23 / ADR-0130).
//! Depends-on: crates=[async-trait, humaux-domain, humaux-projection, humaux-retrieval, serde, serde_json, time, uuid]; services=[]; env=[]; modules=[domain::affect, domain::identity, domain::subject, projection::note_chunks, projection::serving, retrieval::completeness, retrieval::envelope, retrieval::signals]
//! Called-by: [adapters::retrieve, gateway::recall]
//! Invariants: [the read port owns the complete same-snapshot hydration; candidates confer no authority]
//! Spec: Baseline §15.5; §22; §23; ADR-0130 D7.2

use async_trait::async_trait;
use humaux_domain::{affect::AffectFilter, identity::AuthorizationScope, subject::SubjectId};
use humaux_projection::{note_chunks::CardSlot, serving::StreamFamily};
use humaux_retrieval::{
    completeness::{FreshnessClass, LedgerClosure},
    envelope::{CountScope, EvidenceBlock, FreshnessBlock, GroundingBlock, KnowledgeBlock},
    signals::summarize_freshness,
};
use std::collections::{BTreeMap, HashMap};
use time::OffsetDateTime;
use uuid::Uuid;

/// Identity of the authoritative hydration snapshot (§23).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializationSnapshot {
    pub context_snapshot_seq: i64,
    pub snapshot_token_sha256: String,
}

/// Authorized Memory or read-your-writes Evidence (§15.5).
#[derive(Debug, Clone, PartialEq)]
pub enum MaterializedItem {
    Memory {
        memory_id: Uuid,
        content: serde_json::Value,
    },
    TemporaryEvidence {
        evidence_id: Uuid,
        stream_seq: i64,
        processing_state: ProcessingState,
        payload: serde_json::Value,
        linked_memory_ids: Vec<Uuid>,
    },
    ArtifactUnavailable {
        evidence_id: Uuid,
        stream_seq: i64,
        processing_state: ProcessingState,
        linked_memory_ids: Vec<Uuid>,
    },
}

/// Authorized bodies and freshness from the same snapshot (§23).
#[derive(Debug, Clone, PartialEq)]
pub struct MaterializedBodies {
    pub snapshot: MaterializationSnapshot,
    pub items: Vec<MaterializedItem>,
    /// §21.5 / ADR-0111: annotations for admitted items, independent of their content shape.
    pub freshness: HashMap<Uuid, ItemFreshness>,
}

/// §21.5: the sole classifier's annotation, with §23.3 RFC 3339 Evidence time.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ItemFreshness {
    /// ADR-0111 D-C: independent of completeness and ranking.
    pub class: FreshnessClass,
    /// §50: the values file identity used by the classifier.
    pub policy_id: Option<&'static str>,
    /// §50: the values file version.
    pub policy_version: Option<u32>,
    /// §9: only backing Evidence occurred_at; absent for legacy missing Evidence.
    pub latest_evidence_at: Option<String>,
    /// §21.5: age against the transaction's database clock, absent when unknown.
    pub state_age_seconds: Option<u64>,
}

impl MaterializedBodies {
    /// ADR-0111 D-C: summarize only returned items, after any truncation or reranking.
    pub fn freshness_summary(&self) -> FreshnessBlock {
        let readings: Vec<_> = self
            .items
            .iter()
            .filter_map(|item| match item {
                MaterializedItem::Memory { memory_id, .. } => self.freshness.get(memory_id),
                MaterializedItem::TemporaryEvidence { evidence_id, .. }
                | MaterializedItem::ArtifactUnavailable { evidence_id, .. } => {
                    self.freshness.get(evidence_id)
                }
            })
            .collect();
        FreshnessBlock {
            class: summarize_freshness(readings.iter().map(|reading| reading.class)),
            latest_evidence_at: readings
                .iter()
                .filter_map(|reading| reading.latest_evidence_at.as_ref())
                .filter_map(|at| {
                    OffsetDateTime::parse(at, &time::format_description::well_known::Rfc3339)
                        .ok()
                        .map(|parsed| (parsed, at))
                })
                .max_by_key(|(parsed, _)| *parsed)
                .map(|(_, at)| at.clone()),
            state_age_seconds: readings
                .iter()
                .filter_map(|reading| reading.state_age_seconds)
                .max(),
        }
    }
}

/// One row of `private.memory_text_v`: the canonical text of one Memory (M07 D1, ADR-0085 D-A). `None` is SQL NULL: a Memory
/// whose `content` has no `title` / `key_claim` (a non-note kind), or an identity note whose Evidence payload is not a JSON
/// string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryText {
    /// The Memory this text belongs to.
    pub memory_id: Uuid,
    /// `content ->> 'title'`.
    pub title: Option<String>,
    /// The identity note's Evidence payload text, or `content ->> 'key_claim'` for any other Memory (ADR-0085 D-A).
    pub body: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamPipelineCounts {
    pub evidence_persisted: u64,
    pub knowledge_eligible: u64,
    pub knowledge_processed: u64,
    pub knowledge_waiting_key: u64,
    pub knowledge_failed: u64,
}

impl StreamPipelineCounts {
    /// The §23.3④ wire pair these readings are allowed to fill, minted in ONE place for all
    /// three read routes. §23.3④ freezes the scope label together with the numbers ("同一块的
    /// 计数必须来自同一实际全集、同一授权与快照"), so a route that hand-wrote the two blocks
    /// could pair a `stream_ledger` reading with an `authorized_view` label — a
    /// `count_scope_mismatch` that no type would catch. `expected` stays `null`: §23.1①, these
    /// routes carry no `batch_id`, and it is never backfilled from `persisted`.
    #[must_use]
    pub fn blocks(self) -> (EvidenceBlock, KnowledgeBlock) {
        (
            EvidenceBlock::no_batch(Some(self.evidence_persisted), CountScope::StreamLedger),
            KnowledgeBlock {
                eligible: Some(self.knowledge_eligible),
                processed: Some(self.knowledge_processed),
                waiting_key: Some(self.knowledge_waiting_key),
                failed: Some(self.knowledge_failed),
                count_scope: CountScope::StreamLedger,
            },
        )
    }
}

/// §15.1 ten-state closed set, reused here as the wire value returned to callers under
/// `processing_state` for an Evidence that has not finished distillation (§15.5: "允许把该
/// Evidence 作为带 `processing_state` 的临时上下文候选返回...但不能冒充已完成 Memory").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessingState {
    Issued,
    Processing,
    WaitingKey,
    RetryWait,
    Lost,
    Done,
    SkippedByPolicy,
    Failed,
    Tombstoned,
    /// §15.2 amendment (migration `0167`, ADR-0042): an exhausted `Failed` ticket that
    /// `role_maintenance` retired through `projection.retire_failed_ticket`, DLQ-style. Terminal
    /// and settled; the failure itself survives in `error_class` + `retired_at`/`retired_by`.
    RetiredFailed,
}

impl ProcessingState {
    pub const ALL: [ProcessingState; 10] = [
        Self::Issued,
        Self::Processing,
        Self::WaitingKey,
        Self::RetryWait,
        Self::Lost,
        Self::Done,
        Self::SkippedByPolicy,
        Self::Failed,
        Self::Tombstoned,
        Self::RetiredFailed,
    ];

    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Issued => "ISSUED",
            Self::Processing => "PROCESSING",
            Self::WaitingKey => "WAITING_KEY",
            Self::RetryWait => "RETRY_WAIT",
            Self::Lost => "LOST",
            Self::Done => "DONE",
            Self::SkippedByPolicy => "SKIPPED_BY_POLICY",
            Self::Failed => "FAILED",
            Self::Tombstoned => "TOMBSTONED",
            Self::RetiredFailed => "RETIRED_FAILED",
        }
    }

    /// Parse the database closed set, leaving adapter error translation at its boundary (§15.1).
    pub fn parse(s: &str) -> Result<Self, String> {
        Self::ALL
            .into_iter()
            .find(|v| v.as_db_str() == s)
            .ok_or_else(|| s.to_string())
    }

    /// §15.2/§15.4 `SETTLED_OK = DONE | SKIPPED_BY_POLICY | TOMBSTONED | RETIRED_FAILED` — an
    /// Evidence in one of these states is safe to present as if it were a completed Memory
    /// candidate (still carrying `processing_state` per §15.5's "不能冒充已完成 Memory", but no
    /// longer *only* a temporary placeholder).
    ///
    /// `RetiredFailed` is in the set by the §15.2 amendment migration `0167` carries: retirement
    /// is the audited act of declaring an exhausted failure settled, and the whole point of it is
    /// that §15.4's prefix stops treating that seq as a gap. It is the one member that never had
    /// a record to show — see that migration's header for why that makes retirement an
    /// EXECUTE-gated operator action and not something the worker that failed can do to itself.
    pub fn is_settled_ok(self) -> bool {
        matches!(
            self,
            Self::Done | Self::SkippedByPolicy | Self::Tombstoned | Self::RetiredFailed
        )
    }
}

/// ADR-0084 D-C 3: the card slot of the best candidate point of each Memory a hydrate resolved; `None` as a value is a
/// point whose profile this build does not know.
pub type PointSlots = BTreeMap<Uuid, Option<CardSlot>>;

/// Whether the hydrate transaction also reads the canonical text of the Memories that pass its gate (ADR-0084 D-C 3).
/// The read is part of the gate's own transaction and takes its ids from the gated items, so the text of a Memory the gate
/// refused (archived, superseded, secret-backed, tombstoned, outside the subject or affect filter) is never read (G-RET-13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatedTexts {
    /// Read nothing: [`MaterializedPrivateReadServing::gated_texts`] is empty.
    Skip,
    /// Read `(title, body)` of every Memory item the gate returned, in the same snapshot.
    Read,
}

/// One private semantic result whose bodies, ledger closure, and conservative grounding report
/// were all produced under the same PostgreSQL repeatable-read snapshot.
#[derive(Debug, Clone)]
pub struct MaterializedPrivateReadServing {
    pub bodies: MaterializedBodies,
    /// ADR-0084 D-C 3: for every Memory a candidate point resolved to, the card slot of the FIRST candidate point that
    /// resolved to it (the caller's candidate order is the leg order, so that is the best leg hit), from the same
    /// registry read that gated the point. `None` as a value: the point's profile is unknown to this build. A Memory
    /// the hydrate gate then dropped is still listed; the caller looks up only the Memories of `bodies`.
    pub point_slots: PointSlots,
    /// ADR-0084 D-C 3: the canonical text (`private.memory_text_v`, ADR-0085) of exactly the Memories in `bodies`,
    /// read in this same snapshot after the gate when the caller asked for [`GatedTexts::Read`]; empty otherwise. A
    /// Memory the gate dropped has no entry, by construction: there is no other way to obtain a text from this module.
    pub gated_texts: BTreeMap<Uuid, MemoryText>,
    pub ledger: LedgerClosure,
    /// §23.3④ `stream_ledger` pipeline readings for the same six-column `StreamKey` the ledger
    /// closed on, taken in the same snapshot (ADR-0041 D-H). Not an `Option`: no census travels
    /// with it and `classify()` maps this route's `PlannerDecision::Class(_)` to
    /// `SemanticBounded`, so §22.0's exact-without-a-predicate trap is not on this path.
    pub pipeline: StreamPipelineCounts,
    pub grounding: GroundingBlock,
}

/// An opaque candidate identity; the PostgreSQL registry remains authoritative (ADR-0068).
#[derive(Debug, Clone, Copy)]
pub enum RecallPoint {
    /// Numeric projection identity, retained for the existing fail-closed refusal.
    Num(u64),
    /// UUID projection identity, distinct from a Memory ID.
    Uuid(Uuid),
}

/// Untrusted ranked nomination, before any final visibility decision (§23).
pub struct RecallCandidate {
    /// Opaque projection identity.
    pub point_id: RecallPoint,
    /// Original ranking score.
    pub score: f64,
    /// Optional group nomination, rechecked in the projection registry.
    pub memory_id: Option<Uuid>,
}

/// Trusted routing and ordered nominations for one complete hydration snapshot (§23).
pub struct RecallHydrationRequest<'a> {
    /// Authenticated scope, independent of the consistency token.
    pub authorization: &'a AuthorizationScope,
    /// Optional read-your-writes token.
    pub consistency_token: Option<&'a str>,
    /// Bootstrap-selected stream family.
    pub family: &'a StreamFamily,
    /// Projection selected for the candidate search; rechecked by the port.
    pub projection_version: &'a str,
    /// Registered embedding identity.
    pub embedding_version: &'a str,
    /// Ordered, untrusted nominations.
    pub candidates: &'a [RecallCandidate],
    /// Subject any-of filter, rechecked during hydration.
    pub subject_ids: &'a [SubjectId],
    /// Optional affect filter, rechecked during hydration.
    pub affect: Option<&'a AffectFilter>,
    /// Canonical text read policy inside the same snapshot.
    pub texts: GatedTexts,
}

/// Read purpose: hydrate recall candidates, overlay, texts, ledger and grounding in one snapshot.
#[async_trait]
pub trait RecallHydrationReadPort: Send + Sync {
    /// Existing adapter refusal type, preserved while the remaining reads migrate in SLICE-2b.
    type Error: Send;
    /// Apply the unique final read gate before returning any body (ADR-0130 D7.2).
    async fn hydrate(
        &self,
        request: RecallHydrationRequest<'_>,
    ) -> Result<MaterializedPrivateReadServing, Self::Error>;
}

/// Execute the recall hydration use case through the complete snapshot port (§23).
pub async fn hydrate_recall<P: RecallHydrationReadPort>(
    port: &P,
    request: RecallHydrationRequest<'_>,
) -> Result<MaterializedPrivateReadServing, P::Error> {
    port.hydrate(request).await
}
