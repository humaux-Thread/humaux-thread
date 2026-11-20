//! `application::recall_read` — ordered candidates enter one authoritative snapshot (Baseline §23 / ADR-0130).
//! Depends-on: crates=[async-trait, humaux-domain, humaux-projection, humaux-retrieval, serde, serde_json, time, tokio, uuid]; services=[]; env=[]; modules=[application::retrieval_embedding_port, application::retrieve, domain::affect_read, domain::authority, domain::context::budget_views, domain::error, domain::identity, domain::ids, domain::note, domain::subject, projection::dense, projection::note_chunks, projection::serving, projection::sparse, projection::stream, retrieval::compiler, retrieval::completeness, retrieval::envelope, retrieval::handoff, retrieval::planner, retrieval::request, retrieval::rerank, retrieval::signals]
//! Called-by: [adapters::context_repo, adapters::exact_census, adapters::grep_repo, adapters::memory_repo, adapters::read_materialize, adapters::retrieve, adapters::serving_repo, gateway::bootstrap, gateway::context, gateway::mcp_application, gateway::memory, gateway::recall, tests]
//! Invariants: [the read port owns the complete same-snapshot hydration; candidates confer no authority]
//! Spec: Baseline §15.5; §22; §23; ADR-0130 D7.2

use async_trait::async_trait;
use humaux_domain::{
    affect_read::AffectReadFilter, identity::AuthorizationScope, subject::SubjectId,
};
use humaux_domain::{
    authority::MemoryId,
    context::budget_views::ContextBudgetLimits,
    error::ErrorCode,
    ids::{Scope, TenantId, WorkspaceId},
    note::NoteKind,
};
use humaux_projection::stream::StreamKey;
use humaux_projection::{
    dense::DenseQueryFilter,
    note_chunks::{CardSlot, rerank_document},
    serving::StreamFamily,
    sparse::{SparseLane, build_sparse_lane},
};
use humaux_retrieval::{
    compiler::ContextOutcome,
    envelope::{FrontierBlock, FrontierPipelineBlock},
    handoff::Handoff,
    planner::QueryClass,
    request::{RegisteredRetrievalProfile, RetrievalIntent, RetrievalRequest},
    rerank::{
        Executor, ModelIdentity, RerankFailure, Settlement, degradations, not_run, settle,
        unavailable,
    },
};
use humaux_retrieval::{
    completeness::{CensusResult, FreshnessClass, LedgerClosure},
    envelope::{
        CompletenessBlock, CompletenessInputs, CountScope, Envelope, EvidenceBlock, FreshnessBlock,
        GroundingBlock, KnowledgeBlock, LaneStatus, MandatoryReport, PendingEnvelope, PinnedReport,
        PipelineBlock, ProfileBlock, ProvenanceBlock, ProvenanceValue, build_projection_block,
        dense_lane_outcome_block, dense_lane_substitution, no_serving_projection_envelope,
        sparse_lane_unavailable,
    },
    signals::summarize_freshness,
};
use serde_json::{Value, json};
use std::any::Any;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::retrieval_embedding_port::{
    RetrievalEmbeddingInput, RetrievalEmbeddingOutcome, RetrievalEmbeddingPort,
};
use crate::retrieve::prepare_request;

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
/// §23.3④ `pipeline.evidence` / `pipeline.knowledge` readings in the **`stream_ledger`**
/// universe — the request's full six-column [`humaux_projection::stream::StreamKey`] ledger, not the caller's authorized
/// view (§23.3④: "同一块的计数必须来自同一实际全集、同一授权与快照"; the authorized EXACT
/// census is a different universe and may never fill these, "禁止填 `0`、返回条数、
/// `issued_highwater` 或其他块的值充数").
///
/// Both blocks read `projection.stream_log` rows for that key. §15.1/§60 issue a stream_seq in
/// the same transaction that persists its Evidence and its `ops.outbox` row, so a row's
/// existence *is* the "Evidence fully persisted" reading; §15.2's state set is what partitions
/// the knowledge layer. The equation §23.3④ freezes (`evidence.persisted ==
/// knowledge.eligible == projection.expected`, and `processed + waiting_key + failed ==
/// eligible`) therefore discriminates on two real axes: the ledger rows against
/// `stream_checkpoints.issued_highwater` (a separately-written watermark — a hole in the dense
/// sequence, or a watermark ahead of its rows, fails it), and the knowledge partition against
/// its own base (anything still in flight fails it).
// ponytail: derived from `stream_log` at read time because nothing in the workspace advances
// `stream_checkpoints.evidence_highwater` / `knowledge_highwater` (grep: migration 0011's
// GRANT and two fixtures). Upgrade path: when the distill/projection workers start advancing
// those two watermarks, read them here instead — the two blocks then become genuinely
// independent per-layer readings rather than two statements over one ledger.
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
    pub fn parse(s: &str) -> Result<Self, UnknownProcessingState> {
        Self::ALL
            .into_iter()
            .find(|v| v.as_db_str() == s)
            .ok_or_else(|| UnknownProcessingState(s.to_owned()))
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecallPoint {
    /// Numeric projection identity, retained for the existing fail-closed refusal.
    Num(u64),
    /// UUID projection identity, distinct from a Memory ID.
    Uuid(Uuid),
}

/// Untrusted ranked nomination, before any final visibility decision (§23).
#[derive(Debug, Clone, PartialEq)]
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
    pub projection_version: Option<&'a str>,
    /// Visibility observation taken before this batch queried the selected index.
    pub frontier: Option<RecallServingFrontier>,
    /// Registered embedding identity.
    pub embedding_version: &'a str,
    /// Ordered, untrusted nominations.
    pub candidates: &'a [RecallCandidate],
    /// Subject any-of filter, rechecked during hydration.
    pub subject_ids: &'a [SubjectId],
    /// Optional affect filter, rechecked during hydration.
    pub affect: Option<&'a AffectReadFilter>,
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

/// ADR-0067 D-J2: the lifecycle statuses a read admits. `revoked` / `expired` are not representable (L-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusSet {
    Active,
    Superseded,
    Both,
}

/// ADR-0067 D-J2: how a read treats `archived_at` (ADR-0024 D-C).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveMode {
    Exclude,
    Only,
    Include,
}

/// ADR-0067 D-J2: one typed lifecycle selection of the shared final gate — statuses ⊆ {active, superseded}
/// (non-empty) × archive ∈ {exclude, only, include}. The fields are private: a value comes only from
/// [`Lifecycle::CURRENT`], `for_get`, [`Lifecycle::for_enumerate`] or the census's `ACTIVE_FINAL`, and the
/// recall/context entry points of this module accept none at all (they run `CURRENT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifecycle {
    statuses: StatusSet,
    archive: ArchiveMode,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::CURRENT
    }
}

impl Lifecycle {
    /// Recall, context and the default enumerate: active, not superseded, not archived.
    pub const CURRENT: Self = Self {
        statuses: StatusSet::Active,
        archive: ArchiveMode::Exclude,
    };

    /// The §22.1 registry census's `ACTIVE_FINAL`: active and not superseded, archive not consulted (a registry
    /// predicate owns its own archive stance).
    pub const ACTIVE_FINAL: Self = Self {
        statuses: StatusSet::Active,
        archive: ArchiveMode::Include,
    };

    /// ADR-0067 D-H / D-J2: `memory.get` admits archived rows (it reports `archived:true`), and with
    /// `include_history` the exact superseded version too.
    pub const fn for_get(include_history: bool) -> Self {
        Self {
            statuses: if include_history {
                StatusSet::Both
            } else {
                StatusSet::Active
            },
            archive: ArchiveMode::Include,
        }
    }

    /// ADR-0067 D-J2: `memory.enumerate`'s selector from its wire values. `None` = the defaults (`["active"]`,
    /// `"exclude"`).
    ///
    /// # Errors
    /// [`ErrorCode::InvalidInput`] for an empty list, more than two entries, a duplicate, `revoked` / `expired`
    /// (L-6) or any other value, and for an archive mode outside `exclude` / `only` / `include`.
    pub fn for_enumerate(
        statuses: Option<&[&str]>,
        archive: Option<&str>,
    ) -> Result<Self, ErrorCode> {
        let statuses = statuses.unwrap_or(&["active"][..]);
        if statuses.is_empty() || statuses.len() > 2 {
            return Err(ErrorCode::InvalidInput);
        }
        let (mut active, mut superseded) = (false, false);
        for status in statuses {
            match *status {
                "active" if !active => active = true,
                "superseded" if !superseded => superseded = true,
                _ => return Err(ErrorCode::InvalidInput),
            }
        }
        let statuses = match (active, superseded) {
            (true, false) => StatusSet::Active,
            (false, true) => StatusSet::Superseded,
            (true, true) => StatusSet::Both,
            (false, false) => return Err(ErrorCode::InvalidInput),
        };
        let archive = match archive.unwrap_or("exclude") {
            "exclude" => ArchiveMode::Exclude,
            "only" => ArchiveMode::Only,
            "include" => ArchiveMode::Include,
            _ => return Err(ErrorCode::InvalidInput),
        };
        Ok(Self { statuses, archive })
    }

    /// The bound `text[]` of statuses, in canonical order (`active` before `superseded`).
    pub fn status_wires(self) -> Vec<String> {
        let wires: &[&str] = match self.statuses {
            StatusSet::Active => &["active"],
            StatusSet::Superseded => &["superseded"],
            StatusSet::Both => &["active", "superseded"],
        };
        wires.iter().map(|wire| (*wire).to_owned()).collect()
    }

    /// The bound archive mode.
    pub const fn archive_wire(self) -> &'static str {
        match self.archive {
            ArchiveMode::Exclude => "exclude",
            ArchiveMode::Only => "only",
            ArchiveMode::Include => "include",
        }
    }

    /// The canonical text a cursor fingerprint binds: statuses joined by `,`, then `/` and the archive mode.
    pub fn canonical(self) -> String {
        format!("{}/{}", self.status_wires().join(","), self.archive_wire())
    }
}

/// ADR-0067 D-H: one Memory version's lifecycle and provenance, as `memory.get` with `include_history` reports it.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryHistory {
    /// The version described — always the id asked for, never its successor.
    pub memory_id: Uuid,
    /// `"active"` or `"superseded"`: the only two states the final gate admits with history.
    pub status: &'static str,
    /// The successor, present only when the caller may read it (`read_gate::readable_memory_ids`).
    pub superseded_by: Option<Uuid>,
    /// Where the version came from.
    pub provenance: MemoryProvenance,
}

/// ADR-0067 D-H `provenance`. Evidence-side fields are `None` when the PRIMARY Evidence is not visible to the caller.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryProvenance {
    /// The PRIMARY `memory_evidence` link's Evidence.
    pub primary_evidence_id: Option<Uuid>,
    /// `private.events.event_kind` of that Evidence (`None` for an artifact).
    pub event_kind: Option<String>,
    /// `private.evidence_objects.origin_class` of that Evidence.
    pub origin: Option<String>,
    /// The identity contract's `strategy` for a note, else `"distill"`.
    pub derivation_strategy: String,
    /// `private.memory_records.asserted_at`.
    pub asserted_at: OffsetDateTime,
    /// `private.memory_records.authority_class`.
    pub authority_class: String,
    /// The identity contract's SHA-256 of the verbatim body (notes only; ADR-0067 D-E).
    pub body_sha256: Option<Vec<u8>>,
}

/// One exact, object-level Memory read from the caller's trusted serving stream.
///
/// `bodies` carries the same RR snapshot identity as the final Memory body. `ledger` and
/// `grounding` were read in that same transaction, but this type does not claim a complete
/// stream or pipeline census. `L` is the projection-side reading `ledger` holds: the stream
/// ledger closure by default (enumerate, [`materialize_memory_get_target`]), and the checkpoint
/// frontier on the one door `memory.get` uses ([`materialize_memory_get_frontier_target`],
/// ADR-0110 D-A).
pub struct MaterializedMemory<L = humaux_retrieval::completeness::LedgerClosure> {
    /// The final body rows, gated and read in one RR snapshot.
    pub bodies: MaterializedBodies,
    /// The projection-side reading taken in that same transaction (see the type's `L`).
    pub ledger: L,
    /// The §8.8 grounding tally of the admitted Memory rows.
    pub grounding: GroundingBlock,
    /// §6.1.3 (ADR-0028 D-D): `memory_id → linked subject ids` (link order) for every body in
    /// `bodies`, read in the same RR snapshot under the caller's RLS. A memory with no link has
    /// no entry.
    pub subjects: HashMap<Uuid, Vec<Uuid>>,
    /// Q3/ADR-0024 D-C: `true` when this one `memory.get` Memory carries `archived_at IS NOT NULL`. Every other read
    /// sets `false`; an enumerate page that selected archived rows reports them per item in `archived_ids`.
    pub archived: bool,
    /// ADR-0067 D-J2: the archived ids of a `memory.enumerate` page, read in its snapshot; empty on every other read.
    pub archived_ids: HashSet<Uuid>,
    /// ADR-0067 D-J2: `memory_id → "active" | "superseded"` for every body of a `memory.enumerate` page, read in its
    /// snapshot; empty on every other read.
    pub statuses: HashMap<Uuid, &'static str>,
    /// ADR-0067 D-D: `memory_id → note_kind` for every body in `bodies` that is a note, read in the same RR snapshot.
    /// A non-note Memory has no entry.
    pub note_kinds: HashMap<Uuid, NoteKind>,
    /// ADR-0067 D-J: `memory_id → note_id` for the same notes, from the same read. A non-note Memory has no entry.
    pub note_ids: HashMap<Uuid, Uuid>,
    /// ADR-0067 D-H: lifecycle and provenance of the one Memory `memory.get` read with `include_history`; `None` on
    /// every other read, so their output is unchanged.
    pub history: Option<MemoryHistory>,
}

/// Trusted server-side pagination inputs for an authorized memory enumeration.
pub struct MemoryEnumerationParams<'a> {
    /// The opaque continuation cursor of a later page; `None` mints the first segment.
    pub cursor: Option<&'a str>,
    /// Items per page, 1..=100.
    pub page_size: u16,
    /// `HUMAUX_GATEWAY_ENUMERATION_TTL_SECONDS` (§78.1): one manifest segment's lifetime.
    pub ttl: std::time::Duration,
    /// `HUMAUX_GATEWAY_ENUMERATION_MANIFEST_CAP` (> 0, ADR-0062 D-K): the most ids one manifest segment stores;
    /// a larger universe continues in keyset segments, each with its own exact census.
    pub manifest_cap: usize,
    /// The key the manifest's page cursors are MAC-signed and verified with (ADR-0062 D-K); never empty.
    pub mac_key: &'a [u8],
    /// §6.1.3 (ADR-0028 D-D): restrict the EXACT enumeration predicate to memories linked to
    /// this subject (`private.memory_subjects`, under RLS). Part of the manifest's query
    /// fingerprint, so a cursor minted with one filter cannot page another; never a
    /// post-filter, so the page's completeness claim stays what the manifest says.
    pub subject_id: Option<Uuid>,
}

/// ADR-0067 D-G (40b) / D-J2 (40c-2): the note and history axes of the EXACT enumeration predicate — `note_kind` ∈
/// `note_kinds`, `occurred_at ∈ [occurred_since, occurred_until)`, `note_id`, and the [`Lifecycle`] selection. Like
/// `subject_id`, every axis rides inside the manifest predicate, its census and the page's final gate (never a
/// post-filter) and enters the manifest's query fingerprint. `Default` = no note axis, [`Lifecycle::CURRENT`].
#[derive(Debug, Clone, Default)]
pub struct NoteEnumerationFilter {
    /// `Some` = only notes of these kinds (non-empty); `None` = any Memory, note or not.
    pub note_kinds: Option<Vec<NoteKind>>,
    /// Inclusive lower bound on `memory_records.occurred_at`.
    pub occurred_since: Option<OffsetDateTime>,
    /// Exclusive upper bound on `memory_records.occurred_at`.
    pub occurred_until: Option<OffsetDateTime>,
    /// ADR-0067 D-J2: only the versions of this note (`memory_records.note_id`); `None` = no note axis.
    pub note_id: Option<Uuid>,
    /// ADR-0067 D-J2: which lifecycle statuses and archive states the predicate admits.
    pub lifecycle: Lifecycle,
}

impl NoteEnumerationFilter {
    /// The kinds as the bound `text[]` of DB wire strings (`private.memory_records.note_kind`, migration 0235).
    pub fn kind_wires(&self) -> Option<Vec<String>> {
        self.note_kinds
            .as_ref()
            .map(|kinds| kinds.iter().map(|kind| kind.wire().to_owned()).collect())
    }

    /// The fingerprint segment: kinds sorted and deduplicated, joined by `,`; bounds as unix nanoseconds; empty when
    /// absent. `None` when no axis is set, so an unfiltered manifest keeps its pre-40b fingerprint.
    pub fn fingerprint_segment(&self) -> Option<String> {
        if self.note_kinds.is_none()
            && self.occurred_since.is_none()
            && self.occurred_until.is_none()
        {
            return None;
        }
        let mut kinds: Vec<&str> = self
            .note_kinds
            .iter()
            .flatten()
            .map(|kind| kind.wire())
            .collect();
        kinds.sort_unstable();
        kinds.dedup();
        let nanos = |at: Option<OffsetDateTime>| {
            at.map(|at| at.unix_timestamp_nanos().to_string())
                .unwrap_or_default()
        };
        Some(format!(
            "{}:{}:{}",
            kinds.join(","),
            nanos(self.occurred_since),
            nanos(self.occurred_until)
        ))
    }

    /// ADR-0067 D-J2: the canonical history selection (statuses sorted, archive mode, note id), `None` when it is the
    /// default (`CURRENT`, no note) so an unfiltered manifest keeps its pre-40c-2 fingerprint. Tagged and colon-free,
    /// so it never reads as the note segment.
    pub fn history_segment(&self) -> Option<String> {
        if self.note_id.is_none() && self.lifecycle == Lifecycle::CURRENT {
            return None;
        }
        Some(format!(
            "history={};{}",
            self.lifecycle.canonical(),
            self.note_id.map(|id| id.to_string()).unwrap_or_default()
        ))
    }

    /// An empty kind set or `since >= until` describes no window a caller can mean: `InvalidInput`.
    pub fn validate(&self) -> Result<(), ErrorCode> {
        if self.note_kinds.as_ref().is_some_and(Vec::is_empty) {
            return Err(ErrorCode::InvalidInput);
        }
        if let (Some(since), Some(until)) = (self.occurred_since, self.occurred_until)
            && since >= until
        {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(())
    }
}

/// One immutable manifest page whose body, grounding and ledger share one PostgreSQL snapshot.
pub struct MaterializedMemoryPage {
    /// The manifest snapshot this page was cut from.
    pub snapshot_id: Uuid,
    /// The cursor of the next page; `None` at the end of the last segment.
    pub next_cursor: Option<String>,
    /// The page's bodies, ledger, grounding and per-item readings.
    pub memory: MaterializedMemory,
    /// §22.1 census + §23.3④ pipeline readings for THIS page, or `None` when this call had no
    /// workspace-scoped universe to enumerate at all.
    ///
    /// The two travel together on purpose: §22.0 makes `class=exact` without an enumeration a
    /// hard 5xx, and `classify()` maps this route's frozen `PlannerDecision::Enumerate` to
    /// `Exact` as soon as the pipeline counts stop being unknown — so a caller that took the
    /// counts without the census would 5xx, and one that took the census without the counts
    /// would report `cannot_establish/count_unknown` while holding a proven total. One
    /// `Option` over both makes neither half reachable on its own.
    pub census: Option<EnumerationCensus>,
}

/// ADR-0067 D-J2: what `memory.get` names — one version, or one note (resolved to its head). The two namespaces never
/// fall back into each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryGetTarget {
    /// One immutable version by its `memory_id`.
    Memory(MemoryId),
    /// One note by its `note_id`, read at `private.note_heads.head_memory_id`.
    Note(Uuid),
}

/// [`crate::read_gate::MaterializedMemoryPage::census`]'s payload: the §22.1 verdict for this page and the
/// `stream_ledger`-universe pipeline counts read in the same transaction.
pub struct EnumerationCensus {
    pub census: humaux_retrieval::completeness::CensusResult,
    pub pipeline: StreamPipelineCounts,
}

/// Gateway-callable Context manifest and bodies produced from one PostgreSQL snapshot.
pub struct MaterializedContext {
    /// Canonical v1 manifest assembled from the frozen lanes.
    pub handoff: Handoff,
    /// Compiler outcome that produced the manifest, including mandatory overflow.
    pub outcome: ContextOutcome,
    /// Final body rows rechecked in the manifest's transaction snapshot.
    pub bodies: MaterializedBodies,
    /// Stream ledger closure read in that same transaction snapshot.
    pub ledger: humaux_retrieval::completeness::LedgerClosure,
    /// §23.3④ `stream_ledger` pipeline readings for `validated_key`, taken in that same
    /// snapshot as the ledger and the bodies (ADR-0041 D-H). Not an `Option`: unlike
    /// [`crate::read_gate::MaterializedMemoryPage::census`] there is no census travelling with it and
    /// `classify()` maps this route's `PlannerDecision::Class(_)` to `SemanticBounded`, so
    /// §22.0's exact-without-a-predicate trap is not on this path.
    pub pipeline: StreamPipelineCounts,
    /// Actual §8.8 states retained from compiled mandatory and pinned rows.
    pub grounding: GroundingBlock,
}

/// §15.3: the frontier of one stream as its `stream_checkpoints` row holds it. Carries only what has a writer on main
/// (`issued_highwater` by the ticket door, `projection_highwater` by [`advance_prefix`], `serving` by the maintenance
/// switch); `evidence_highwater` / `knowledge_highwater` are absent until M13 gives them one, because exposing a
/// column nobody writes would present a fabricated 0 (§23.3④). No `visible`, no per-state count either: those come
/// from [`fetch_ledger_closure`], and which reader an envelope uses is M13's ruling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frontier {
    /// `issued_highwater` — A1's `expected` (§15.4).
    pub issued_hw: u64,
    /// `projection_highwater` — the §15.4 contiguous-done prefix [`advance_prefix`] last stored.
    pub projection_hw: u64,
    /// `serving` — the §15.3 read-routing flag.
    pub serving: bool,
    /// The row's last-write time (`stream_checkpoints_touch_updated_at`, DB clock).
    pub updated_at: time::OffsetDateTime,
}

/// ADR-0110 D-A: the `pipeline` of a `memory.get` envelope from the frontier its snapshot read. The one mapping from a
/// [`Frontier`] to the wire: `None` (no checkpoint row) is `projection: null` with `no_checkpoint`, never a zero
/// frontier (§23.1④, G-M13-2); a row becomes a [`FrontierBlock`], whose `behind` is derived there and nowhere else.
/// `observed_at` is the row's DB-clock write time in RFC 3339.
pub fn frontier_pipeline_block(
    frontier: Option<Frontier>,
) -> Result<FrontierPipelineBlock, ErrorCode> {
    let block = match frontier {
        Some(frontier) => {
            let observed_at = frontier
                .updated_at
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|_| ErrorCode::Internal)?;
            Some(FrontierBlock::new(
                frontier.issued_hw,
                frontier.projection_hw,
                frontier.serving,
                observed_at,
            ))
        }
        None => None,
    };
    Ok(FrontierPipelineBlock::new(block))
}

/// Authenticated get_target inputs (§23 / ADR-0130 D7).
pub struct MaterializeMemoryGetTargetRequest<'a> {
    /// Trusted read input, validated at the existing snapshot boundary.
    pub authorization: &'a AuthorizationScope,
    /// Trusted read input, validated at the existing snapshot boundary.
    pub scope: &'a Scope,
    /// Trusted read input, validated at the existing snapshot boundary.
    pub expected_family: &'a StreamFamily,
    /// Trusted read input, validated at the existing snapshot boundary.
    pub validated_key: &'a StreamKey,
    /// Trusted read input, validated at the existing snapshot boundary.
    pub target: MemoryGetTarget,
    /// Trusted read input, validated at the existing snapshot boundary.
    pub include_history: bool,
}

/// Authenticated get_frontier inputs (§23 / ADR-0130 D7).
pub struct MaterializeMemoryGetFrontierTargetRequest<'a> {
    /// Trusted read input, validated at the existing snapshot boundary.
    pub authorization: &'a AuthorizationScope,
    /// Trusted read input, validated at the existing snapshot boundary.
    pub scope: &'a Scope,
    /// Trusted read input, validated at the existing snapshot boundary.
    pub expected_family: &'a StreamFamily,
    /// Trusted read input, validated at the existing snapshot boundary.
    pub validated_key: &'a StreamKey,
    /// Trusted read input, validated at the existing snapshot boundary.
    pub target: MemoryGetTarget,
    /// Trusted read input, validated at the existing snapshot boundary.
    pub include_history: bool,
}

/// Authenticated enumerate_filtered inputs (§23 / ADR-0130 D7).
pub struct MaterializeMemoryEnumerationFilteredRequest<'a> {
    /// Trusted read input, validated at the existing snapshot boundary.
    pub authorization: &'a AuthorizationScope,
    /// Trusted read input, validated at the existing snapshot boundary.
    pub scope: &'a Scope,
    /// Trusted read input, validated at the existing snapshot boundary.
    pub expected_family: &'a StreamFamily,
    /// Trusted read input, validated at the existing snapshot boundary.
    pub validated_key: &'a StreamKey,
    /// Trusted read input, validated at the existing snapshot boundary.
    pub params: MemoryEnumerationParams<'a>,
    /// Trusted read input, validated at the existing snapshot boundary.
    pub notes: &'a NoteEnumerationFilter,
}

/// Purpose-specific read port; implementations retain the same snapshot and final gate (§23).
#[async_trait]
pub trait MemoryGetReadPort: Send + Sync {
    async fn get_target(
        &self,
        request: MaterializeMemoryGetTargetRequest<'_>,
    ) -> Result<MaterializedMemory, ErrorCode>;
    async fn get_frontier(
        &self,
        request: MaterializeMemoryGetFrontierTargetRequest<'_>,
    ) -> Result<MaterializedMemory<Option<Frontier>>, ErrorCode>;
}

/// Purpose-specific read port; implementations retain the same snapshot and final gate (§23).
#[async_trait]
pub trait MemoryEnumerationReadPort: Send + Sync {
    async fn enumerate_filtered(
        &self,
        request: MaterializeMemoryEnumerationFilteredRequest<'_>,
    ) -> Result<MaterializedMemoryPage, ErrorCode>;
}

/// Authenticated read use case; the port owns one complete snapshot (§23).
pub async fn materialize_memory_get<P: MemoryGetReadPort + Sync>(
    pool: &P,
    authorization: &AuthorizationScope,
    scope: &Scope,
    expected_family: &StreamFamily,
    validated_key: &StreamKey,
    memory_id: MemoryId,
) -> Result<MaterializedMemory, ErrorCode> {
    materialize_memory_get_versioned(
        pool,
        authorization,
        scope,
        expected_family,
        validated_key,
        memory_id,
        false,
    )
    .await
}

/// Authenticated read use case; the port owns one complete snapshot (§23).
pub async fn materialize_memory_get_versioned<P: MemoryGetReadPort + Sync>(
    pool: &P,
    authorization: &AuthorizationScope,
    scope: &Scope,
    expected_family: &StreamFamily,
    validated_key: &StreamKey,
    memory_id: MemoryId,
    include_history: bool,
) -> Result<MaterializedMemory, ErrorCode> {
    materialize_memory_get_target(
        pool,
        authorization,
        scope,
        expected_family,
        validated_key,
        MemoryGetTarget::Memory(memory_id),
        include_history,
    )
    .await
}

/// Authenticated read use case; the port owns one complete snapshot (§23).
pub async fn materialize_memory_get_target<P: MemoryGetReadPort + Sync>(
    pool: &P,
    authorization: &AuthorizationScope,
    scope: &Scope,
    expected_family: &StreamFamily,
    validated_key: &StreamKey,
    target: MemoryGetTarget,
    include_history: bool,
) -> Result<MaterializedMemory, ErrorCode> {
    pool.get_target(MaterializeMemoryGetTargetRequest {
        authorization,
        scope,
        expected_family,
        validated_key,
        target,
        include_history,
    })
    .await
}

/// Authenticated read use case; the port owns one complete snapshot (§23).
pub async fn materialize_memory_get_frontier_target<P: MemoryGetReadPort + Sync>(
    pool: &P,
    authorization: &AuthorizationScope,
    scope: &Scope,
    expected_family: &StreamFamily,
    validated_key: &StreamKey,
    target: MemoryGetTarget,
    include_history: bool,
) -> Result<MaterializedMemory<Option<Frontier>>, ErrorCode> {
    pool.get_frontier(MaterializeMemoryGetFrontierTargetRequest {
        authorization,
        scope,
        expected_family,
        validated_key,
        target,
        include_history,
    })
    .await
}

/// Authenticated read use case; the port owns one complete snapshot (§23).
pub async fn materialize_memory_enumeration<P: MemoryEnumerationReadPort + Sync>(
    pool: &P,
    authorization: &AuthorizationScope,
    scope: &Scope,
    expected_family: &StreamFamily,
    validated_key: &StreamKey,
    params: MemoryEnumerationParams<'_>,
) -> Result<MaterializedMemoryPage, ErrorCode> {
    materialize_memory_enumeration_filtered(
        pool,
        authorization,
        scope,
        expected_family,
        validated_key,
        params,
        &NoteEnumerationFilter::default(),
    )
    .await
}

/// Authenticated read use case; the port owns one complete snapshot (§23).
pub async fn materialize_memory_enumeration_filtered<P: MemoryEnumerationReadPort + Sync>(
    pool: &P,
    authorization: &AuthorizationScope,
    scope: &Scope,
    expected_family: &StreamFamily,
    validated_key: &StreamKey,
    params: MemoryEnumerationParams<'_>,
    notes: &NoteEnumerationFilter,
) -> Result<MaterializedMemoryPage, ErrorCode> {
    pool.enumerate_filtered(MaterializeMemoryEnumerationFilteredRequest {
        authorization,
        scope,
        expected_family,
        validated_key,
        params,
        notes,
    })
    .await
}

/// Authenticated Context read inputs (§25).
pub struct ContextReadRequest<'a> {
    /// Caller authorization.
    pub authorization: &'a AuthorizationScope,
    /// Canonical scope.
    pub scope: &'a Scope,
    /// Compiler budget.
    pub budget: ContextBudgetLimits,
    /// Trusted serving family.
    pub expected_family: &'a StreamFamily,
    /// Validated stream.
    pub validated_key: &'a StreamKey,
}
/// One authoritative Context snapshot (§25 / ADR-0130 D7).
#[async_trait]
pub trait ContextAssemblyReadPort: Send + Sync {
    /// Compile and materialize the same snapshot.
    async fn assemble_context(
        &self,
        request: ContextReadRequest<'_>,
    ) -> Result<MaterializedContext, ErrorCode>;
}
/// Assemble the authenticated Context through its read port.
pub async fn assemble_materialized<P: ContextAssemblyReadPort + Sync>(
    pool: &P,
    authorization: &AuthorizationScope,
    scope: &Scope,
    budget: impl Into<ContextBudgetLimits>,
    expected_family: &StreamFamily,
    validated_key: &StreamKey,
) -> Result<MaterializedContext, ErrorCode> {
    pool.assemble_context(ContextReadRequest {
        authorization,
        scope,
        budget: budget.into(),
        expected_family,
        validated_key,
    })
    .await
}

/// Unrecognized database state; adapters retain their existing public error mapping (§15.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownProcessingState(pub String);

#[async_trait]
impl<P: MemoryGetReadPort + ?Sized> MemoryGetReadPort for std::sync::Arc<P> {
    async fn get_target(
        &self,
        request: MaterializeMemoryGetTargetRequest<'_>,
    ) -> Result<MaterializedMemory, ErrorCode> {
        self.as_ref().get_target(request).await
    }
    async fn get_frontier(
        &self,
        request: MaterializeMemoryGetFrontierTargetRequest<'_>,
    ) -> Result<MaterializedMemory<Option<Frontier>>, ErrorCode> {
        self.as_ref().get_frontier(request).await
    }
}

#[async_trait]
impl<P: MemoryEnumerationReadPort + ?Sized> MemoryEnumerationReadPort for std::sync::Arc<P> {
    async fn enumerate_filtered(
        &self,
        request: MaterializeMemoryEnumerationFilteredRequest<'_>,
    ) -> Result<MaterializedMemoryPage, ErrorCode> {
        self.as_ref().enumerate_filtered(request).await
    }
}

#[async_trait]
impl<P: ContextAssemblyReadPort + ?Sized> ContextAssemblyReadPort for std::sync::Arc<P> {
    async fn assemble_context(
        &self,
        request: ContextReadRequest<'_>,
    ) -> Result<MaterializedContext, ErrorCode> {
        self.as_ref().assemble_context(request).await
    }
}

/// Whether `family_read_state` reads the key's O(stream) ledger closure and pipeline counts when the key
/// is initialised but its family has no serving version. A route that never reports them must say
/// [`UnservedLedger::Skip`] (ADR-0110 D-A: `memory.get` reads the frontier only, recall / context / enumerate keep
/// the closure); a bare `bool` would let a new caller pay the closure by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnservedLedger {
    /// Close the ledger and count the pipeline: `FamilyReadState::unserved` is `Some` on an unserved key.
    Read,
    /// Touch neither `stream_log` nor `stream_point_ledger`: `FamilyReadState::unserved` is `None`.
    Skip,
}

/// ADR-0069 D-B: the longest pattern accepted, in Unicode scalars (the contract's `maxLength`).
pub const MAX_PATTERN_CHARS: usize = 512;

/// One validated `memory.grep` request.
#[derive(Debug, Clone)]
pub struct GrepQuery {
    pattern: String,
    lifecycle: Lifecycle,
    page_size: u16,
    after: Option<(Uuid, i64)>,
    budget: Option<std::time::Duration>,
}

impl GrepQuery {
    /// `after` is the last `(memory_id, line_no)` of the previous page (from a verified cursor); `budget` overrides the
    /// role's statement timeout for this read (`None` = the pool's §78 setting).
    ///
    /// # Errors
    /// [`ErrorCode::InvalidInput`] for an empty pattern, one longer than [`MAX_PATTERN_CHARS`], one containing a line
    /// break (a hit is one line, ADR-0069 D-B), or a page size outside 1..=100.
    pub fn new(
        pattern: &str,
        lifecycle: Lifecycle,
        page_size: u16,
        after: Option<(Uuid, i64)>,
        budget: Option<std::time::Duration>,
    ) -> Result<Self, ErrorCode> {
        if pattern.is_empty()
            || pattern.chars().count() > MAX_PATTERN_CHARS
            || pattern.contains(['\n', '\r'])
            || !(1..=100).contains(&page_size)
        {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self {
            pattern: pattern.to_owned(),
            lifecycle,
            page_size,
            after,
            budget,
        })
    }

    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    pub const fn lifecycle(&self) -> Lifecycle {
        self.lifecycle
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub const fn after(&self) -> Option<(Uuid, i64)> {
        self.after
    }

    pub const fn budget(&self) -> Option<std::time::Duration> {
        self.budget
    }
}

/// One matching line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrepHit {
    /// The memory the line belongs to.
    pub memory_id: Uuid,
    /// 1-based, over `MEMORY_TEXT`'s lines.
    pub line_no: i64,
    /// The matching line.
    pub line: String,
    /// The line before it, `None` on the first line.
    pub before: Option<String>,
    /// The line after it, `None` on the last line.
    pub after: Option<String>,
    /// Every matching line of this memory in the whole result, not only this page's.
    pub memory_matching_lines: i64,
    /// `active` or `superseded`.
    pub status: String,
    /// Whether the memory is archived (only with an `archive` selection that admits archived rows).
    pub archived: bool,
}

/// One keyset page with the totals of the same snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrepPage {
    /// This page's hits, ordered by `(memory_id, line_no)`.
    pub items: Vec<GrepHit>,
    /// Every matching line in the caller's view, in this snapshot.
    pub total_matching_lines: i64,
    /// The memories those lines belong to.
    pub total_memories: i64,
    /// Whether hits follow this page.
    pub has_more: bool,
}

impl GrepPage {
    /// The keyset position after this page's last hit, `None` when nothing follows.
    pub fn next_after(&self) -> Option<(Uuid, i64)> {
        if !self.has_more {
            return None;
        }
        self.items.last().map(|hit| (hit.memory_id, hit.line_no))
    }
}

/// Literal substring grep boundary in one REPEATABLE READ snapshot (§33; ADR-0069; ADR-0130).
#[async_trait]
pub trait GrepStore: Send + Sync {
    /// Execute one `memory.grep` page read over `workspace`.
    async fn grep(
        &self,
        authorization: &AuthorizationScope,
        workspace: humaux_domain::ids::WorkspaceId,
        query: &GrepQuery,
    ) -> Result<GrepPage, ErrorCode>;
}

/// Execute `memory.grep` through the read store port (§33; ADR-0069).
pub async fn grep_memories(
    store: &dyn GrepStore,
    authorization: &AuthorizationScope,
    workspace: humaux_domain::ids::WorkspaceId,
    query: &GrepQuery,
) -> Result<GrepPage, ErrorCode> {
    store.grep(authorization, workspace, query).await
}

// ============================================================================
// Native semantic recall use case & outbound ports (ADR-0130: retrieval_read_model)
// ============================================================================

/// Boxed `Send` future used across outbound async coordination ports without adding a `tokio` dependency.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One rerank call: the query and the documents to score against it, in-Cell text that is never sealed and never
/// logged.
pub struct RerankCall<'a> {
    /// Names the call in the worker's counts and timings.
    pub call_id: Uuid,
    /// The query exactly as the caller sent it.
    pub query: &'a str,
    /// One document per hydrated, visible Memory (ADR-0084 D-C 3).
    pub documents: &'a [String],
    /// The registered `rerank_max_len`: the token cap of one (query, document) pair.
    pub max_len: u32,
}

/// What a rerank port answered.
#[derive(Debug, Clone, PartialEq)]
pub enum RerankAnswer {
    /// Every document scored: one raw logit per document in request order, and the identity the worker reported.
    Scored {
        /// One raw logit per document.
        scores: Vec<f32>,
        /// The model identity the worker reported.
        model: ModelIdentity,
    },
    /// No usable scores. `class` is a short machine-stable tag for the operator line.
    Failed {
        /// Why: `permit`, `encode`, `transport`, `non_2xx`, `malformed`, `not_scored` or `count_mismatch`.
        class: &'static str,
    },
}

/// The seam the recall path scores through; the gateway's UDS implementation lives in `gateway::rerank_client`.
#[async_trait]
pub trait RerankPort: Send + Sync {
    /// Scores every document of `call` against its query, or says why not. All or nothing.
    async fn rerank(&self, call: RerankCall<'_>) -> RerankAnswer;
}

/// The rerank lane: the port and the deployment model pin (ADR-0084 D-E) the identity each reply reports is
/// compared with.
#[derive(Clone)]
pub struct RerankLane {
    port: Arc<dyn RerankPort>,
    pin: ModelIdentity,
}

impl RerankLane {
    /// A lane over `port` that accepts only scores of the model `pin` names.
    #[must_use]
    pub fn new(port: Arc<dyn RerankPort>, pin: ModelIdentity) -> Self {
        Self { port, pin }
    }

    /// The port to score through.
    #[must_use]
    pub fn port(&self) -> &dyn RerankPort {
        self.port.as_ref()
    }

    /// The pinned model identity.
    #[must_use]
    pub fn pin(&self) -> &ModelIdentity {
        &self.pin
    }
}

/// Opaque tenant placement handle produced by [`RecallRoutePort`] and consumed by [`RecallCandidateIndexPort`]
/// without leaking adapter row types out of adapters.
#[derive(Clone)]
pub struct RecallPlacement(Arc<dyn Any + Send + Sync>);

impl RecallPlacement {
    pub fn new<T: Send + Sync + 'static>(inner: T) -> Self {
        Self(Arc::new(inner))
    }

    pub fn downcast_ref<T: 'static>(&self) -> Option<&T> {
        self.0.downcast_ref::<T>()
    }
}

impl std::fmt::Debug for RecallPlacement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecallPlacement")
    }
}

/// Opaque Qdrant cell access permit minted by [`RecallCandidateIndexPort::authorize_index_access`].
#[derive(Clone)]
pub struct RecallIndexPermit(Arc<dyn Any + Send + Sync>);

impl RecallIndexPermit {
    pub fn new<T: Send + Sync + 'static>(inner: T) -> Self {
        Self(Arc::new(inner))
    }

    pub fn downcast_ref<T: 'static>(&self) -> Option<&T> {
        self.0.downcast_ref::<T>()
    }
}

/// Opaque prepared dense query built once and shared across concurrent dense and sparse legs.
#[derive(Clone)]
pub struct PreparedDenseQuery(Arc<dyn Any + Send + Sync>);

impl PreparedDenseQuery {
    pub fn new<T: Send + Sync + 'static>(inner: T) -> Self {
        Self(Arc::new(inner))
    }

    pub fn downcast_ref<T: 'static>(&self) -> Option<&T> {
        self.0.downcast_ref::<T>()
    }
}

/// Opaque keyed query HMAC computed before execution and written off the answer path (ADR-0081 D-A).
#[derive(Clone)]
pub struct PreparedQueryDigest(Arc<dyn Any + Send + Sync>);

impl PreparedQueryDigest {
    pub fn new<T: Send + Sync + 'static>(inner: T) -> Self {
        Self(Arc::new(inner))
    }

    pub fn downcast_ref<T: 'static>(&self) -> Option<&T> {
        self.0.downcast_ref::<T>()
    }
}

/// A pre-query observation for one exact serving target.
#[derive(Debug, Clone)]
pub struct RecallServingFrontier {
    pub key: StreamKey,
    pub highwater: i64,
    pub contiguous_done_prefix: i64,
}

/// Family read-routing state returned by [`RecallRoutePort::family_read_state`].
#[derive(Debug, Clone)]
pub struct RecallReadState {
    pub initialized: bool,
    pub serving: Option<String>,
    pub unserved: Option<(LedgerClosure, StreamPipelineCounts)>,
}

/// Counts recorded for one answered recall by [`RecallQueryLogPort`].
#[derive(Debug, Clone, PartialEq)]
pub struct RecallQueryLogCounts {
    pub cand_k: u32,
    pub candidates: u32,
    pub visible: Option<u64>,
    pub returned: u32,
    pub stage_ms: Option<Value>,
}

/// Complete off-path query log job handed to [`RecallAsyncSupport::spawn_query_log`].
pub struct RecallQueryLogJob {
    pub tenant_id: TenantId,
    pub workspace_id: WorkspaceId,
    pub user_id: Option<Uuid>,
    pub digest: PreparedQueryDigest,
    pub counts: RecallQueryLogCounts,
}

/// Closed refusal reasons from [`RecallRoutePort::private_memory_placement`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementLookupError {
    LookupFailed,
    Missing,
}

/// Closed failure categories from [`RecallCandidateIndexPort::search_dense`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenseLegFailure {
    WriteDenied,
    Unavailable,
}

/// Closed failure categories from the bounded sparse leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SparseLegFailure {
    Timeout,
    Class(&'static str),
}

/// Refusal classes translated at the snapshot hydration boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HydrateRefusal {
    Forbidden,
    ProjectionLag,
    ConsistencyTokenRefused { reason: &'static str },
    TokenKeysUnset,
    DependencyUnavailable { class: String },
}

/// Inputs to build the concurrent candidate search query (`DenseQuery`).
pub struct RecallCandidateSearchRequest<'a> {
    pub authorization: &'a AuthorizationScope,
    pub placement: &'a RecallPlacement,
    pub projection_version: &'a str,
    pub embedding_version: &'a str,
    pub vector: Vec<f32>,
    pub limit: u32,
    pub subject_ids: &'a [SubjectId],
    pub affect: Option<&'a AffectReadFilter>,
    pub workspace_id: WorkspaceId,
    pub tombstoned_seqs: Vec<i64>,
}

/// Outbound port for recall routing, read state, tombstones, and chunking policy in PostgreSQL.
#[async_trait]
pub trait RecallRoutePort: Send + Sync {
    async fn private_memory_placement(
        &self,
        tenant_id: TenantId,
    ) -> Result<Option<RecallPlacement>, PlacementLookupError>;

    async fn family_read_state(
        &self,
        authorization: &AuthorizationScope,
        key: &StreamKey,
        unserved: UnservedLedger,
    ) -> Result<RecallReadState, ErrorCode>;

    async fn observe_candidate_frontier(
        &self,
        authorization: &AuthorizationScope,
        key: &StreamKey,
    ) -> Result<RecallServingFrontier, ErrorCode>;

    async fn tombstoned_source_seqs(
        &self,
        authorization: &AuthorizationScope,
        key: &StreamKey,
    ) -> Result<Vec<i64>, ErrorCode>;

    async fn grouped_recall(&self, key: &StreamKey) -> Result<bool, ErrorCode>;
}

/// Outbound port for candidate search and live visible count on the index face.
#[async_trait]
pub trait RecallCandidateIndexPort: Send + Sync {
    fn build_query(
        &self,
        request: RecallCandidateSearchRequest<'_>,
    ) -> Result<PreparedDenseQuery, ErrorCode>;

    fn authorize_index_access(&self) -> Result<RecallIndexPermit, ErrorCode>;

    async fn search_dense(
        &self,
        permit: &RecallIndexPermit,
        query: &PreparedDenseQuery,
        grouped: bool,
    ) -> Result<Vec<RecallCandidate>, DenseLegFailure>;

    async fn search_sparse(
        &self,
        permit: &RecallIndexPermit,
        query: &PreparedDenseQuery,
        text: &str,
        corpus: &DenseQueryFilter,
    ) -> Result<Vec<RecallCandidate>, &'static str>;

    async fn visible_index_count(
        &self,
        permit: &RecallIndexPermit,
        authorization: &AuthorizationScope,
        placement: &RecallPlacement,
        key: &StreamKey,
        serving_version: Option<&str>,
        ledger: &LedgerClosure,
    ) -> Option<u64>;
}

/// Outbound port for off-path query-hash logging (ADR-0081 D-A).
#[async_trait]
pub trait RecallQueryLogPort: Send + Sync {
    fn prepare_digest(
        &self,
        tenant_id: TenantId,
        query: &[u8],
    ) -> Result<PreparedQueryDigest, String>;
    fn query_log_limits(&self) -> (u32, Duration);
    async fn record_query(
        &self,
        tenant_id: TenantId,
        workspace_id: WorkspaceId,
        user_id: Option<Uuid>,
        digest: &PreparedQueryDigest,
        counts: &RecallQueryLogCounts,
    ) -> Result<(), String>;
}

/// Optional late permutation port over the already-visible Memory items (e.g. mood congruence in
/// `knowledge_lifecycle`, kept opaque here to preserve bounded-context direction).
#[async_trait]
pub trait LateMemoryRerankPort: Send + Sync {
    async fn rerank_memories(
        &self,
        authorization: &AuthorizationScope,
        items: &mut [MaterializedItem],
    ) -> Result<u32, ErrorCode>;
}

/// Structured operator diagnostic emitted during [`search_recall`]; the gateway boundary
/// renders each event to stderr verbatim without exposing query text or authorization.
pub enum RecallDiagnostic<'a> {
    QueryLogFailed {
        request_id: Uuid,
        reason: &'a str,
    },
    StageClockOutOfSequence {
        laps: Option<usize>,
    },
    PlacementMissing {
        request_id: Uuid,
    },
    PlacementLookupFailed {
        request_id: Uuid,
    },
    LimitNotProfileTopK {
        request_id: Uuid,
        limit: u32,
        profile_top_k: u32,
    },
    ProjectionSelectorFailed {
        request_id: Uuid,
    },
    StreamUninitialized {
        request_id: Uuid,
    },
    NoServingProjection {
        request_id: Uuid,
    },
    QueryEmbeddingDimensionMismatch {
        request_id: Uuid,
        reported: u32,
        vector_len: usize,
        expected: u32,
    },
    QueryEmbeddingSkipped {
        request_id: Uuid,
    },
    QueryScanRejected {
        request_id: Uuid,
    },
    QueryEmbeddingUnavailable {
        request_id: Uuid,
        reason: &'a str,
    },
    TombstoneReadFailed {
        request_id: Uuid,
    },
    DenseQueryBuildFailed {
        request_id: Uuid,
    },
    CardProfilePolicyReadFailed {
        request_id: Uuid,
    },
    QdrantQueryFailed {
        request_id: Uuid,
    },
    SparseLegFailed {
        request_id: Uuid,
        class: &'a str,
    },
    ConsistencyTokenRefused {
        request_id: Uuid,
        reason: &'a str,
    },
    MaterializeFailed {
        request_id: Uuid,
        class: &'a str,
    },
    MoodRerankFailed {
        request_id: Uuid,
    },
    VisibleIndexCountUnavailable {
        request_id: Uuid,
    },
    RerankFailedNoDocuments {
        call_id: Uuid,
        visible_len: usize,
    },
    RerankFailedClass {
        call_id: Uuid,
        class: &'a str,
    },
}

/// Runtime-provided async primitives (join, timeout, supervised background task, and diagnostic rendering).
#[async_trait]
pub trait RecallAsyncSupport: Send + Sync {
    async fn run_candidate_legs(
        &self,
        dense: BoxFuture<'_, Result<Vec<RecallCandidate>, DenseLegFailure>>,
        sparse: Option<(
            Duration,
            BoxFuture<'_, Result<Vec<RecallCandidate>, &'static str>>,
        )>,
    ) -> (
        Result<Vec<RecallCandidate>, DenseLegFailure>,
        Option<(Result<Vec<RecallCandidate>, SparseLegFailure>, Duration)>,
    );

    async fn timeout_rerank(
        &self,
        wait: Duration,
        call: BoxFuture<'_, RerankAnswer>,
    ) -> Option<RerankAnswer>;

    fn spawn_query_log(
        &self,
        request_id: Uuid,
        log_port: Arc<dyn RecallQueryLogPort>,
        job: RecallQueryLogJob,
    );

    fn record_diagnostic(&self, diagnostic: RecallDiagnostic<'_>);
}

/// Inputs to [`search_recall`].
pub struct SearchRecallInput {
    pub query: String,
    pub workspace_id: WorkspaceId,
    pub consistency_token: Option<String>,
    pub mode: Option<String>,
    pub completeness_request: Option<String>,
    pub limit: Option<u32>,
    pub subject_ids: Vec<SubjectId>,
    pub affect: Option<AffectReadFilter>,
}

/// Per-request configuration & dependencies for [`search_recall`].
pub struct SearchRecallConfig<'a> {
    pub request_id: Uuid,
    pub authorization: AuthorizationScope,
    pub family: StreamFamily,
    pub key: StreamKey,
    pub profile: &'a RegisteredRetrievalProfile,
    pub binary_build: &'a str,
    pub projection_lag: Duration,
    pub embedding_version: &'a str,
    pub embedding_dimension: u32,
    pub handler_timeout: Duration,
    pub rerank: Option<&'a RerankLane>,
    pub text_processing_allowed: bool,
}

/// §23.1② live `visible` for PG-only read routes (`memory.*`, `context.assemble`) through the route and index ports.
pub async fn visible_index_count(
    route: &dyn RecallRoutePort,
    index: &dyn RecallCandidateIndexPort,
    authorization: &AuthorizationScope,
    key: &StreamKey,
    serving_version: Option<&str>,
    ledger: &LedgerClosure,
) -> Option<u64> {
    let placement = route
        .private_memory_placement(authorization.tenant_id())
        .await
        .ok()??;
    let permit = index.authorize_index_access().ok()?;
    index
        .visible_index_count(
            &permit,
            authorization,
            &placement,
            key,
            serving_version,
            ledger,
        )
        .await
}

/// Render hydrated Memory/Evidence items into the JSON items shape expected by the Recall schema.
pub fn render_recall_items(
    items: Vec<MaterializedItem>,
    freshness: &HashMap<Uuid, ItemFreshness>,
) -> Result<Vec<Value>, ErrorCode> {
    items
        .into_iter()
        .map(|item| match item {
            MaterializedItem::Memory { memory_id, content } => Ok(json!({
                "kind": "memory",
                "memory_id": memory_id.to_string(),
                "content": content,
                "freshness": freshness.get(&memory_id).ok_or(ErrorCode::Internal)?,
            })),
            MaterializedItem::TemporaryEvidence {
                evidence_id,
                stream_seq,
                processing_state,
                payload,
                linked_memory_ids,
            } => Ok(json!({
                "kind": "temporary_evidence",
                "freshness": freshness.get(&evidence_id).ok_or(ErrorCode::Internal)?,
                "evidence_id": evidence_id.to_string(),
                "stream_seq": stream_seq,
                "processing_state": processing_state.as_db_str(),
                "payload": payload,
                "linked_memory_ids": linked_memory_ids.iter().map(Uuid::to_string).collect::<Vec<_>>(),
            })),
            MaterializedItem::ArtifactUnavailable {
                evidence_id,
                stream_seq,
                processing_state,
                linked_memory_ids,
            } => Ok(json!({
                "kind": "artifact_unavailable",
                "freshness": freshness.get(&evidence_id).ok_or(ErrorCode::Internal)?,
                "evidence_id": evidence_id.to_string(),
                "stream_seq": stream_seq,
                "processing_state": processing_state.as_db_str(),
                "linked_memory_ids": linked_memory_ids.iter().map(Uuid::to_string).collect::<Vec<_>>(),
            })),
        })
        .collect()
}

/// ADR-0055 D-E: the fixed, exhaustive partition of [`answer_recall`] reported as `provenance.stage_ms`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Route,
    Planner,
    Scan,
    Embed,
    Qdrant,
    Hydrate,
    Rerank,
    Assemble,
}

const STAGE_NAMES: [&str; 8] = [
    "route", "planner", "scan", "embed", "qdrant", "hydrate", "rerank", "assemble",
];

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

const SPARSE_SUB_TIMING: &str = "qdrant_sparse";

struct StageClock {
    start: Instant,
    last: Instant,
    ms: [f64; 8],
    laps: Option<usize>,
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

    fn note_sparse(&mut self, elapsed: Duration) {
        self.sparse_ms = Some(elapsed.as_secs_f64() * 1_000.0);
    }

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

    fn out_of_sequence_laps(&self) -> Option<Option<usize>> {
        (self.laps != Some(LAP_SEQUENCE.len())).then_some(self.laps)
    }

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
        }
        map.insert(
            "total".to_owned(),
            json!(round(self.start.elapsed().as_secs_f64() * 1_000.0)),
        );
        Value::Object(map)
    }
}

/// Outbound ports required to answer one [`search_recall`] call.
pub struct SearchRecallPorts<'a, H> {
    pub embedding: &'a dyn RetrievalEmbeddingPort,
    pub route: &'a dyn RecallRoutePort,
    pub index: &'a dyn RecallCandidateIndexPort,
    pub hydration: &'a H,
    pub query_log: Arc<dyn RecallQueryLogPort>,
    pub late_rerank: &'a dyn LateMemoryRerankPort,
    pub async_support: &'a dyn RecallAsyncSupport,
}

/// Answers one `recall.search` through the outbound ports and then hands off its query-hash log row off the answer path.
pub async fn search_recall<H, T, F>(
    ports: SearchRecallPorts<'_, H>,
    config: SearchRecallConfig<'_>,
    input: SearchRecallInput,
    render_output: F,
) -> Result<PendingEnvelope<T>, ErrorCode>
where
    H: RecallHydrationReadPort + Sync,
    H::Error: Into<HydrateRefusal>,
    F: FnOnce(Value) -> Result<T, ErrorCode>,
{
    let request_id = config.request_id;
    let digest = ports
        .query_log
        .prepare_digest(config.authorization.tenant_id(), input.query.as_bytes());
    let (tenant_id, user_id) = (
        config.authorization.tenant_id(),
        config.authorization.user_id().map(|user| user.0),
    );
    let workspace_id = input.workspace_id;
    let (pending, counts) = answer_recall(
        ports.embedding,
        ports.route,
        ports.index,
        ports.hydration,
        ports.late_rerank,
        ports.async_support,
        config,
        input,
        render_output,
    )
    .await?;
    match digest {
        Ok(digest) => ports.async_support.spawn_query_log(
            request_id,
            ports.query_log,
            RecallQueryLogJob {
                tenant_id,
                workspace_id,
                user_id,
                digest,
                counts,
            },
        ),
        Err(reason) => ports
            .async_support
            .record_diagnostic(RecallDiagnostic::QueryLogFailed {
                request_id,
                reason: &reason,
            }),
    }
    Ok(pending)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn answer_recall<H, T, F>(
    embedding_port: &dyn RetrievalEmbeddingPort,
    route_port: &dyn RecallRoutePort,
    index_port: &dyn RecallCandidateIndexPort,
    hydration_port: &H,
    late_rerank: &dyn LateMemoryRerankPort,
    async_support: &dyn RecallAsyncSupport,
    config: SearchRecallConfig<'_>,
    input: SearchRecallInput,
    render_output: F,
) -> Result<(PendingEnvelope<T>, RecallQueryLogCounts), ErrorCode>
where
    H: RecallHydrationReadPort + Sync,
    H::Error: Into<HydrateRefusal>,
    F: FnOnce(Value) -> Result<T, ErrorCode>,
{
    let mut clock = StageClock::start();
    if input.mode.as_deref().is_some_and(|mode| mode != "semantic")
        || input.completeness_request.as_deref() == Some("required")
    {
        return Err(ErrorCode::DependencyUnavailable);
    }
    let request_id = config.request_id;
    let authorization = config.authorization.narrow(input.workspace_id)?;
    clock.lap(Stage::Route);
    let intent = RetrievalIntent::new(input.query, Vec::new(), BTreeSet::new(), BTreeSet::new())
        .map_err(|_| ErrorCode::InvalidInput)?;
    let retrieval = prepare_request(intent, config.profile).map_err(|_| ErrorCode::Internal)?;
    if let Some(limit) = input.limit
        && (limit == 0 || limit > retrieval.top_k())
    {
        async_support.record_diagnostic(RecallDiagnostic::LimitNotProfileTopK {
            request_id,
            limit,
            profile_top_k: retrieval.top_k(),
        });
        return Err(ErrorCode::InvalidInput);
    }
    clock.lap(Stage::Planner);
    let state = route_port
        .family_read_state(
            &authorization,
            &config.key,
            if input.consistency_token.is_some() {
                UnservedLedger::Skip
            } else {
                UnservedLedger::Read
            },
        )
        .await
        .map_err(|_| {
            async_support
                .record_diagnostic(RecallDiagnostic::ProjectionSelectorFailed { request_id });
            ErrorCode::DependencyUnavailable
        })?;
    if !state.initialized && input.consistency_token.is_none() {
        async_support.record_diagnostic(RecallDiagnostic::StreamUninitialized { request_id });
        return Err(ErrorCode::DependencyUnavailable);
    }
    if state.serving.is_none()
        && let Some(token) = input.consistency_token.as_deref()
    {
        let mut materialized = hydrate_recall(
            hydration_port,
            RecallHydrationRequest {
                authorization: &authorization,
                consistency_token: Some(token),
                family: &config.family,
                projection_version: None,
                frontier: None,
                embedding_version: config.embedding_version,
                candidates: &[],
                subject_ids: &input.subject_ids,
                affect: input.affect.as_ref(),
                texts: GatedTexts::Skip,
            },
        )
        .await
        .map_err(|error| recall_hydration_error(error.into(), async_support, request_id))?;
        truncate_memory_items(
            &mut materialized.bodies.items,
            input.limit.unwrap_or_else(|| retrieval.top_k()),
        );
        let freshness = materialized.bodies.freshness_summary();
        let grounding =
            GroundingBlock::tally(std::iter::repeat_n(None, materialized.bodies.items.len()));
        let items = render_recall_items(materialized.bodies.items, &materialized.bodies.freshness)?;
        let returned = u32::try_from(items.len()).map_err(|_| ErrorCode::Internal)?;
        let (evidence, knowledge) = materialized.pipeline.blocks();
        let pending = no_serving_projection_envelope(
            &retrieval,
            config.binary_build,
            vec!["dense".to_owned()],
            &materialized.ledger,
            evidence,
            knowledge,
            |mut envelope: Envelope<Value>| {
                envelope.items = items;
                envelope.completeness.returned = returned;
                envelope.freshness = freshness;
                envelope.grounding = grounding;
                render_output(serde_json::to_value(envelope).map_err(|_| ErrorCode::Internal)?)
            },
        )?;
        return Ok((
            pending,
            RecallQueryLogCounts {
                cand_k: retrieval.cand_k(),
                candidates: 0,
                visible: None,
                returned,
                stage_ms: None,
            },
        ));
    }
    let placement = match route_port
        .private_memory_placement(authorization.tenant_id())
        .await
    {
        Ok(Some(placement)) => placement,
        Ok(None) => {
            async_support.record_diagnostic(RecallDiagnostic::PlacementMissing { request_id });
            return Err(ErrorCode::DependencyUnavailable);
        }
        Err(PlacementLookupError::LookupFailed) => {
            async_support.record_diagnostic(RecallDiagnostic::PlacementLookupFailed { request_id });
            return Err(ErrorCode::DependencyUnavailable);
        }
        Err(PlacementLookupError::Missing) => {
            async_support.record_diagnostic(RecallDiagnostic::PlacementMissing { request_id });
            return Err(ErrorCode::DependencyUnavailable);
        }
    };
    let projection_version = match (state.serving, state.unserved) {
        (Some(version), _) => version,
        (None, Some((ledger, pipeline))) => {
            async_support.record_diagnostic(RecallDiagnostic::NoServingProjection { request_id });
            let (evidence, knowledge) = pipeline.blocks();
            return no_serving_projection_envelope(
                &retrieval,
                config.binary_build,
                vec!["dense".to_owned()],
                &ledger,
                evidence,
                knowledge,
                |envelope: Envelope<Value>| {
                    let value = serde_json::to_value(envelope).map_err(|_| ErrorCode::Internal)?;
                    render_output(value)
                },
            )
            .map(|pending| {
                let counts = RecallQueryLogCounts {
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
            async_support.record_diagnostic(RecallDiagnostic::NoServingProjection { request_id });
            return Err(ErrorCode::DependencyUnavailable);
        }
    };
    clock.lap(Stage::Route);
    let trusted_query = retrieval.trusted_query().ok_or(ErrorCode::Internal)?;
    clock.lap(Stage::Scan);
    let deadline_unix_ms = {
        let deadline = SystemTime::now() + config.handler_timeout;
        i64::try_from(
            deadline
                .duration_since(UNIX_EPOCH)
                .map_err(|_| ErrorCode::Internal)?
                .as_millis(),
        )
        .map_err(|_| ErrorCode::Internal)?
    };
    let embedding_input = RetrievalEmbeddingInput {
        authorization: &authorization,
        workspace_id: input.workspace_id,
        request_id,
        logical_call_id: request_id,
        attempt_no: 1,
        profile_fingerprint: retrieval.profile_fingerprint_identity().as_str(),
        dimension: config.embedding_dimension,
        query: trusted_query.text(),
        deadline_unix_ms,
    };
    let (vector, embedding_model_id) = match embedding_port.embed_query(embedding_input).await? {
        RetrievalEmbeddingOutcome::Embedded {
            vector,
            dimension,
            model_id,
            ..
        } if dimension == config.embedding_dimension
            && vector.len() == config.embedding_dimension as usize =>
        {
            (vector, model_id)
        }
        RetrievalEmbeddingOutcome::Embedded {
            vector, dimension, ..
        } => {
            async_support.record_diagnostic(RecallDiagnostic::QueryEmbeddingDimensionMismatch {
                request_id,
                reported: dimension,
                vector_len: vector.len(),
                expected: config.embedding_dimension,
            });
            return Err(ErrorCode::DependencyUnavailable);
        }
        RetrievalEmbeddingOutcome::Skipped => {
            async_support.record_diagnostic(RecallDiagnostic::QueryEmbeddingSkipped { request_id });
            return Err(ErrorCode::DependencyUnavailable);
        }
        RetrievalEmbeddingOutcome::Unavailable { reason } if reason == "SCAN_REJECTED" => {
            async_support.record_diagnostic(RecallDiagnostic::QueryScanRejected { request_id });
            return Err(ErrorCode::Forbidden);
        }
        RetrievalEmbeddingOutcome::Unavailable { reason } => {
            async_support.record_diagnostic(RecallDiagnostic::QueryEmbeddingUnavailable {
                request_id,
                reason: &reason,
            });
            return Err(ErrorCode::DependencyUnavailable);
        }
    };
    clock.lap(Stage::Embed);
    let serving_key = config.family.with_version(projection_version.clone());
    let tombstoned_seqs = route_port
        .tombstoned_source_seqs(&authorization, &serving_key)
        .await
        .map_err(|_| {
            async_support.record_diagnostic(RecallDiagnostic::TombstoneReadFailed { request_id });
            ErrorCode::DependencyUnavailable
        })?;
    let sparse_corpus = sparse_corpus_filter(
        config.profile.sparse_leg_enabled(),
        config.text_processing_allowed,
        &authorization,
    );
    let rerank_selected = rerank_branch_selected(
        config.profile.rerank_enabled(),
        config.text_processing_allowed,
    );
    let leg_limit = if sparse_corpus.is_some() {
        config.profile.leg_depth()
    } else {
        retrieval.cand_k()
    };
    let dense = index_port
        .build_query(RecallCandidateSearchRequest {
            authorization: &authorization,
            placement: &placement,
            projection_version: &projection_version,
            embedding_version: config.embedding_version,
            vector,
            limit: leg_limit,
            subject_ids: &input.subject_ids,
            affect: input.affect.as_ref(),
            workspace_id: input.workspace_id,
            tombstoned_seqs,
        })
        .map_err(|_| {
            async_support.record_diagnostic(RecallDiagnostic::DenseQueryBuildFailed { request_id });
            ErrorCode::DependencyUnavailable
        })?;
    let grouped = route_port.grouped_recall(&serving_key).await.map_err(|_| {
        async_support
            .record_diagnostic(RecallDiagnostic::CardProfilePolicyReadFailed { request_id });
        ErrorCode::DependencyUnavailable
    })?;
    let permit = index_port.authorize_index_access()?;
    let sparse_leg_input = sparse_corpus.as_ref().map(|corpus| {
        (
            Duration::from_millis(u64::from(config.profile.sparse_timeout_ms())),
            Box::pin(index_port.search_sparse(&permit, &dense, trusted_query.text(), corpus))
                as BoxFuture<'_, Result<Vec<RecallCandidate>, &'static str>>,
        )
    });
    let frontier = if input.consistency_token.is_some() {
        Some(
            route_port
                .observe_candidate_frontier(&authorization, &serving_key)
                .await?,
        )
    } else {
        None
    };
    let (dense_outcome, sparse_outcome) = async_support
        .run_candidate_legs(
            Box::pin(index_port.search_dense(&permit, &dense, grouped)),
            sparse_leg_input,
        )
        .await;
    let dense_candidates = dense_outcome.map_err(|error| match error {
        DenseLegFailure::WriteDenied => ErrorCode::Forbidden,
        DenseLegFailure::Unavailable => {
            async_support.record_diagnostic(RecallDiagnostic::QdrantQueryFailed { request_id });
            ErrorCode::DependencyUnavailable
        }
    })?;
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
                async_support.record_diagnostic(RecallDiagnostic::SparseLegFailed {
                    request_id,
                    class: sparse_failure_class(&error),
                });
                sparse = SparseLeg::Failed;
            }
        }
    }
    let candidates = fuse_rrf(
        [dense_candidates.as_slice(), sparse_candidates.as_slice()],
        config.profile.rrf_k(),
        grouped,
        retrieval.cand_k() as usize,
    );
    clock.lap(Stage::Qdrant);
    let mut materialized = hydrate_recall(
        hydration_port,
        RecallHydrationRequest {
            authorization: &authorization,
            consistency_token: input.consistency_token.as_deref(),
            family: &config.family,
            projection_version: Some(&projection_version),
            frontier,
            embedding_version: config.embedding_version,
            candidates: &candidates,
            subject_ids: &input.subject_ids,
            affect: input.affect.as_ref(),
            texts: if rerank_selected {
                GatedTexts::Read
            } else {
                GatedTexts::Skip
            },
        },
    )
    .await
    .map_err(|error| recall_hydration_error(error.into(), async_support, request_id))?;
    clock.lap(Stage::Hydrate);
    let rerank = rerank_stage(
        async_support,
        &RerankStageInput {
            lane: config.rerank,
            selected: rerank_selected,
            depth: usize::try_from(config.profile.rerank_depth()).unwrap_or(usize::MAX),
            max_len: config.profile.rerank_max_len(),
            wait: rerank_wait(
                Duration::from_millis(u64::from(config.profile.rerank_timeout_ms())),
                config.handler_timeout,
                clock.elapsed(),
                Duration::from_millis(u64::from(config.profile.sparse_timeout_ms())),
            ),
            call_id: request_id,
            query: trusted_query.text(),
        },
        &mut materialized.bodies.items,
        &materialized.point_slots,
        &materialized.gated_texts,
    )
    .await;
    truncate_memory_items(&mut materialized.bodies.items, retrieval.top_k());
    let mood_reranked = late_rerank
        .rerank_memories(&authorization, &mut materialized.bodies.items)
        .await
        .map_err(|_| {
            async_support.record_diagnostic(RecallDiagnostic::MoodRerankFailed { request_id });
            ErrorCode::DependencyUnavailable
        })?;
    truncate_memory_items(
        &mut materialized.bodies.items,
        input.limit.unwrap_or_else(|| retrieval.top_k()),
    );
    clock.lap(Stage::Rerank);
    let rerank = RerankReport {
        reranked_count: if rerank_selected {
            rerank.reranked_count
        } else {
            mood_reranked
        },
        ..rerank
    };
    let assemble_permit = index_port.authorize_index_access()?;
    let visible = index_port
        .visible_index_count(
            &assemble_permit,
            &authorization,
            &placement,
            &config.family.with_version(projection_version.clone()),
            Some(projection_version.as_str()),
            &materialized.ledger,
        )
        .await;
    if visible.is_none() {
        async_support
            .record_diagnostic(RecallDiagnostic::VisibleIndexCountUnavailable { request_id });
    }
    accepted_output(
        async_support,
        materialized,
        &retrieval,
        config.binary_build,
        config.projection_lag,
        config.embedding_version,
        &projection_version,
        &embedding_model_id,
        candidates.len(),
        rerank,
        visible,
        input.mode.is_some(),
        sparse,
        clock,
        render_output,
    )
}

fn recall_hydration_error(
    error: HydrateRefusal,
    async_support: &dyn RecallAsyncSupport,
    request_id: Uuid,
) -> ErrorCode {
    match error {
        HydrateRefusal::Forbidden => ErrorCode::Forbidden,
        HydrateRefusal::ProjectionLag => ErrorCode::ProjectionLag,
        HydrateRefusal::ConsistencyTokenRefused { reason } => {
            async_support.record_diagnostic(RecallDiagnostic::ConsistencyTokenRefused {
                request_id,
                reason,
            });
            ErrorCode::InvalidInput
        }
        HydrateRefusal::TokenKeysUnset => {
            async_support.record_diagnostic(RecallDiagnostic::MaterializeFailed {
                request_id,
                class: "token_keys_unset",
            });
            ErrorCode::DependencyUnavailable
        }
        HydrateRefusal::DependencyUnavailable { class } => {
            async_support.record_diagnostic(RecallDiagnostic::MaterializeFailed {
                request_id,
                class: &class,
            });
            ErrorCode::DependencyUnavailable
        }
    }
}

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

#[derive(Clone, Copy, PartialEq, Eq)]
enum SparseLeg {
    NotRun,
    Answered,
    Failed,
}

fn sparse_failure_class(failure: &SparseLegFailure) -> &'static str {
    match failure {
        SparseLegFailure::Timeout => "timeout",
        SparseLegFailure::Class(class) => class,
    }
}

fn fusion_key(candidate: &RecallCandidate, by_memory: bool) -> Uuid {
    match (by_memory, candidate.memory_id, candidate.point_id) {
        (true, Some(memory_id), _) => memory_id,
        (_, _, RecallPoint::Uuid(point)) => point,
        (_, _, RecallPoint::Num(number)) => Uuid::from_u128(u128::from(number)),
    }
}

fn fuse_rrf(
    legs: [&[RecallCandidate]; 2],
    rrf_k: u32,
    by_memory: bool,
    cap: usize,
) -> Vec<RecallCandidate> {
    let mut slot: HashMap<Uuid, usize> = HashMap::new();
    let mut fused: Vec<(Uuid, RecallCandidate)> = Vec::new();
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

fn rerank_branch_selected(enabled: bool, text_processing_allowed: bool) -> bool {
    enabled && text_processing_allowed
}

/// ADR-0084 D-E / U7: the wait for the rerank RPC is the registered `rerank_timeout_ms`, never more than the handler
/// budget the request has left less `reserve`, and never negative.
pub fn rerank_wait(
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

struct RerankStageInput<'a> {
    lane: Option<&'a RerankLane>,
    selected: bool,
    depth: usize,
    max_len: u32,
    wait: Duration,
    call_id: Uuid,
    query: &'a str,
}

struct RerankReport {
    reranked_count: u32,
    model: ProvenanceValue,
    failure: Option<RerankFailure>,
}

fn memory_ids(items: &[MaterializedItem]) -> Vec<Uuid> {
    items
        .iter()
        .filter_map(|item| match item {
            MaterializedItem::Memory { memory_id, .. } => Some(*memory_id),
            _ => None,
        })
        .collect()
}

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

async fn rerank_stage(
    async_support: &dyn RecallAsyncSupport,
    input: &RerankStageInput<'_>,
    items: &mut [MaterializedItem],
    slots: &PointSlots,
    texts: &BTreeMap<Uuid, MemoryText>,
) -> RerankReport {
    let visible = memory_ids(items);
    let report = |settlement: Settlement<Uuid>| RerankReport {
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
        async_support.record_diagnostic(RecallDiagnostic::RerankFailedNoDocuments {
            call_id: input.call_id,
            visible_len: visible.len(),
        });
        return report(unavailable(&visible));
    }
    let Some(lane) = input.lane else {
        async_support.record_diagnostic(RecallDiagnostic::RerankFailedClass {
            call_id: input.call_id,
            class: "no_lane",
        });
        return report(unavailable(&visible));
    };
    if input.wait.is_zero() {
        async_support.record_diagnostic(RecallDiagnostic::RerankFailedClass {
            call_id: input.call_id,
            class: "no_budget",
        });
        return report(settle(&visible, &sent, lane.pin(), Executor::Unavailable));
    }
    let answered = async_support
        .timeout_rerank(
            input.wait,
            Box::pin(lane.port().rerank(RerankCall {
                call_id: input.call_id,
                query: input.query,
                documents: &documents,
                max_len: input.max_len,
            })),
        )
        .await;
    let settlement = match &answered {
        Some(RerankAnswer::Scored { scores, model }) => settle(
            &visible,
            &sent,
            lane.pin(),
            Executor::Scored {
                scores: scores.as_slice(),
                model,
            },
        ),
        Some(RerankAnswer::Failed { class }) => {
            async_support.record_diagnostic(RecallDiagnostic::RerankFailedClass {
                call_id: input.call_id,
                class,
            });
            settle(&visible, &sent, lane.pin(), Executor::Unavailable)
        }
        None => {
            async_support.record_diagnostic(RecallDiagnostic::RerankFailedClass {
                call_id: input.call_id,
                class: "timeout",
            });
            settle(&visible, &sent, lane.pin(), Executor::Unavailable)
        }
    };
    apply_memory_order(items, &settlement.order);
    report(settlement)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn accepted_output<T, F>(
    async_support: &dyn RecallAsyncSupport,
    materialized: MaterializedPrivateReadServing,
    request: &RetrievalRequest,
    binary_build: &str,
    projection_lag: Duration,
    embedding_version: &str,
    projection_version: &str,
    embedding_model_id: &str,
    candidate_count: usize,
    rerank: RerankReport,
    visible: Option<u64>,
    explicit_mode: bool,
    sparse: SparseLeg,
    mut clock: StageClock,
    render_output: F,
) -> Result<(PendingEnvelope<T>, RecallQueryLogCounts), ErrorCode>
where
    F: FnOnce(Value) -> Result<T, ErrorCode>,
{
    let freshness = materialized.bodies.freshness_summary();
    let items = render_recall_items(materialized.bodies.items, &materialized.bodies.freshness)?;
    let returned = u32::try_from(items.len()).map_err(|_| ErrorCode::Internal)?;
    let candidate_count = u32::try_from(candidate_count).map_err(|_| ErrorCode::Internal)?;
    let projection = build_projection_block(&materialized.ledger, visible, projection_lag);
    let (evidence, knowledge) = materialized.pipeline.blocks();
    let pipeline = PipelineBlock {
        evidence,
        knowledge,
        projection: projection.value,
    };
    let provenance = ProvenanceBlock {
        binary_build: binary_build.to_owned(),
        projection_version: ProvenanceValue::Used {
            id: projection_version.to_owned(),
        },
        embedding_model_id: ProvenanceValue::Used {
            id: format!("{embedding_model_id}@{embedding_version}"),
        },
        rerank_model_id: rerank.model.clone(),
        card_builder_version: ProvenanceValue::NotApplicable {},
        profile_fingerprint: request.profile_fingerprint_identity().clone(),
        profile: ProfileBlock {
            top_k: request.top_k(),
            cand_k: request.cand_k(),
            cand_k_formula: request.cand_k_formula(),
            lanes: std::iter::once("dense")
                .chain((sparse != SparseLeg::NotRun).then_some("sparse"))
                .map(str::to_owned)
                .collect(),
        },
    };
    let lane_status = LaneStatus::Ok;
    let census = CensusResult::ok_without_enumeration();
    let planner_class = request
        .planner_decision()
        .wire_class()
        .map_or("CANNOT_ESTABLISH", QueryClass::as_wire_name);
    let substituted = dense_lane_substitution(request.planner_decision(), explicit_mode);
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
    let rerank_degradations: Vec<String> = degradations(rerank.failure)
        .into_iter()
        .map(|code| code.line_format())
        .collect();
    let reranked_count = rerank.reranked_count;
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
            lag_threshold: projection_lag,
        },
        |outcome| {
            let value = serde_json::to_value(Envelope {
                items,
                completeness: CompletenessBlock {
                    class: outcome.class,
                    reason: outcome.reason,
                    exact: outcome.exact,
                    known_lower_bound: outcome.known_lower_bound,
                    lanes: BTreeMap::from([
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
                freshness,
                grounding: materialized.grounding,
                mandatory: MandatoryReport::NotRun,
                pinned: PinnedReport::NotRun,
            })
            .map_err(|_| ErrorCode::Internal)?;
            clock.lap(Stage::Assemble);
            if let Some(laps) = clock.out_of_sequence_laps() {
                async_support.record_diagnostic(RecallDiagnostic::StageClockOutOfSequence { laps });
            }
            let mut value = value;
            let provenance = value
                .get_mut("provenance")
                .and_then(Value::as_object_mut)
                .ok_or(ErrorCode::Internal)?;
            provenance.insert("planner_class".to_owned(), json!(planner_class));
            let report = clock.to_json();
            stage_ms = Some(report.clone());
            provenance.insert("stage_ms".to_owned(), report);
            render_output(value)
        },
    )?;
    let counts = RecallQueryLogCounts {
        cand_k: request.cand_k(),
        candidates: candidate_count,
        visible,
        returned,
        stage_ms,
    };
    Ok((pending, counts))
}

#[cfg(test)]
mod recall_tests {
    use super::*;
    use humaux_domain::identity::{BoundedSet, PrincipalId};
    use humaux_projection::dense::build_dense_filter;
    use std::sync::{Mutex, atomic::AtomicUsize, atomic::Ordering};

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

    fn leg(entries: &[(u128, Option<u128>)]) -> Vec<RecallCandidate> {
        entries
            .iter()
            .map(|(point, memory)| RecallCandidate {
                point_id: RecallPoint::Uuid(Uuid::from_u128(*point)),
                score: 0.0,
                memory_id: memory.map(Uuid::from_u128),
            })
            .collect()
    }

    fn fused_memories(fused: &[RecallCandidate]) -> Vec<u128> {
        fused
            .iter()
            .map(|c| c.memory_id.expect("grouped fixture").as_u128())
            .collect()
    }

    #[test]
    fn rrf_sums_reciprocal_ranks_over_the_legs_that_found_the_memory() {
        let dense = leg(&[(11, Some(1)), (12, Some(2)), (13, Some(3))]);
        let sparse = leg(&[(23, Some(3)), (24, Some(4))]);
        let fused = fuse_rrf([&dense, &sparse], 60, true, 10);
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
        assert_eq!(fused[0].point_id, RecallPoint::Uuid(Uuid::from_u128(13)));
        assert_eq!(
            fused_memories(&fuse_rrf([&dense, &sparse], 60, true, 2)),
            [3, 1]
        );
    }

    #[test]
    fn rrf_ties_order_by_memory_id_ascending_and_repeat_identically() {
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

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn pin() -> ModelIdentity {
        ModelIdentity::new("org/model", "rev", "recipe", HASH, HASH).expect("a valid identity")
    }

    struct StubSupport {
        timeout_rerank: bool,
    }

    #[async_trait]
    impl RecallAsyncSupport for StubSupport {
        async fn run_candidate_legs(
            &self,
            _dense: BoxFuture<'_, Result<Vec<RecallCandidate>, DenseLegFailure>>,
            _sparse: Option<(
                Duration,
                BoxFuture<'_, Result<Vec<RecallCandidate>, &'static str>>,
            )>,
        ) -> (
            Result<Vec<RecallCandidate>, DenseLegFailure>,
            Option<(Result<Vec<RecallCandidate>, SparseLegFailure>, Duration)>,
        ) {
            unreachable!("not used in rerank_stage unit tests")
        }

        async fn timeout_rerank(
            &self,
            _wait: Duration,
            call: BoxFuture<'_, RerankAnswer>,
        ) -> Option<RerankAnswer> {
            let answer = call.await;
            if self.timeout_rerank {
                None
            } else {
                Some(answer)
            }
        }

        fn spawn_query_log(
            &self,
            _request_id: Uuid,
            _log_port: Arc<dyn RecallQueryLogPort>,
            _job: RecallQueryLogJob,
        ) {
        }

        fn record_diagnostic(&self, _diagnostic: RecallDiagnostic<'_>) {}
    }

    type Script = Box<dyn Fn(&[String]) -> RerankAnswer + Send + Sync>;

    struct StubPort {
        calls: AtomicUsize,
        sent: Mutex<Vec<Vec<String>>>,
        answer: Script,
    }

    #[async_trait]
    impl RerankPort for StubPort {
        async fn rerank(&self, call: RerankCall<'_>) -> RerankAnswer {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.sent
                .lock()
                .expect("sent lock")
                .push(call.documents.to_vec());
            (self.answer)(call.documents)
        }
    }

    fn stub(answer: impl Fn(&[String]) -> RerankAnswer + Send + Sync + 'static) -> Arc<StubPort> {
        Arc::new(StubPort {
            calls: AtomicUsize::new(0),
            sent: Mutex::new(Vec::new()),
            answer: Box::new(answer),
        })
    }

    fn reversing() -> Arc<StubPort> {
        stub(|documents| RerankAnswer::Scored {
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

    #[tokio::test]
    async fn a_tenant_without_in_cell_text_processing_gets_no_rerank_call_and_the_fused_order() {
        let support = StubSupport {
            timeout_rerank: false,
        };
        let port = reversing();
        let lane = RerankLane::new(port.clone(), pin());
        let (slots, texts) = hydrated(&[1, 2, 3]);
        let mut items = vec![memory(1), memory(2), memory(3)];
        let selected = rerank_branch_selected(true, false);
        let report = rerank_stage(
            &support,
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

    #[tokio::test]
    async fn only_gated_texts_inside_the_depth_window_are_sent() {
        let support = StubSupport {
            timeout_rerank: false,
        };
        let port = reversing();
        let lane = RerankLane::new(port.clone(), pin());
        let (mut slots, mut texts) = hydrated(&[1, 2, 3, 4, 5, 6]);
        texts.remove(&Uuid::from_u128(2));
        slots.insert(Uuid::from_u128(3), None);
        texts.insert(
            Uuid::from_u128(4),
            MemoryText {
                memory_id: Uuid::from_u128(4),
                title: Some("t4".to_owned()),
                body: None,
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
        let report = rerank_stage(
            &support,
            &input(Some(&lane), true, 5),
            &mut items,
            &slots,
            &texts,
        )
        .await;
        let sent = port.sent.lock().expect("sent lock");
        assert_eq!(
            *sent,
            [vec![format!("t1{NL}b1"), format!("t5{NL}b5")]],
            "documents of Memories 1 and 5 only, one call"
        );
        drop(sent);
        assert_eq!(ids(&items), [5, 1, 2, 3, 4, 6]);
        assert_eq!(report.reranked_count, 2);
        assert_eq!(report.failure, None);
    }

    const NL: &str = humaux_projection::note_chunks::NOTE_CHUNKS_V1_SEPARATOR;

    #[tokio::test]
    async fn a_scored_reply_reorders_the_memory_items_only() {
        let support = StubSupport {
            timeout_rerank: false,
        };
        let port = reversing();
        let lane = RerankLane::new(port, pin());
        let (slots, texts) = hydrated(&[1, 2, 3]);
        let mut items = vec![memory(1), overlay(), memory(2), memory(3)];
        let report = rerank_stage(
            &support,
            &input(Some(&lane), true, 25),
            &mut items,
            &slots,
            &texts,
        )
        .await;
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

    #[tokio::test]
    async fn a_stalled_failed_or_foreign_answer_keeps_the_fused_order() {
        let other = ModelIdentity::new("org/model", "other", "recipe", HASH, HASH).expect("valid");
        let cases: Vec<(&str, bool, Arc<StubPort>, RerankFailure)> = vec![
            (
                "stalled past the wait",
                true,
                reversing(),
                RerankFailure::Unavailable,
            ),
            (
                "failed",
                false,
                stub(|_| RerankAnswer::Failed { class: "transport" }),
                RerankFailure::Unavailable,
            ),
            (
                "a score per document is missing",
                false,
                stub(|_| RerankAnswer::Scored {
                    scores: vec![1.0],
                    model: pin(),
                }),
                RerankFailure::Unavailable,
            ),
            (
                "another model answered",
                false,
                stub(move |documents| RerankAnswer::Scored {
                    scores: vec![0.5; documents.len()],
                    model: other.clone(),
                }),
                RerankFailure::ModelMismatch,
            ),
        ];
        for (label, timeout_rerank, port, failure) in cases {
            let support = StubSupport { timeout_rerank };
            let lane = RerankLane::new(port.clone(), pin());
            let (slots, texts) = hydrated(&[1, 2, 3]);
            let mut items = vec![memory(1), memory(2), memory(3)];
            let mut stage = input(Some(&lane), true, 25);
            stage.wait = Duration::from_millis(50);
            let report = rerank_stage(&support, &stage, &mut items, &slots, &texts).await;
            assert_eq!(ids(&items), [1, 2, 3], "{label}: the fused order");
            assert_eq!(report.reranked_count, 0, "{label}");
            assert_eq!(report.model, ProvenanceValue::CannotEstablish {}, "{label}");
            assert_eq!(report.failure, Some(failure), "{label}");
            assert_eq!(port.calls.load(Ordering::SeqCst), 1, "{label}: one call");
        }
    }

    #[tokio::test]
    async fn a_selected_branch_that_cannot_score_is_a_failure_and_no_memory_is_not_applicable() {
        let support = StubSupport {
            timeout_rerank: false,
        };
        let (slots, texts) = hydrated(&[1, 2]);
        let mut items = vec![memory(1), memory(2)];
        let report =
            rerank_stage(&support, &input(None, true, 25), &mut items, &slots, &texts).await;
        assert_eq!(ids(&items), [1, 2]);
        assert_eq!(report.failure, Some(RerankFailure::Unavailable));
        assert_eq!(report.model, ProvenanceValue::CannotEstablish {});

        let port = reversing();
        let lane = RerankLane::new(port.clone(), pin());
        let report = rerank_stage(
            &support,
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
        let report = rerank_stage(
            &support,
            &input(Some(&lane), true, 25),
            &mut empty,
            &slots,
            &texts,
        )
        .await;
        assert_eq!(
            report.model,
            ProvenanceValue::NotApplicable {},
            "no visible Memory: nothing was selected to fail"
        );
        assert_eq!(report.failure, None);
    }

    #[tokio::test]
    async fn a_zero_wait_degrades_without_calling_the_worker() {
        let support = StubSupport {
            timeout_rerank: false,
        };
        let port = reversing();
        let lane = RerankLane::new(port.clone(), pin());
        let (slots, texts) = hydrated(&[1, 2, 3]);
        let mut items = vec![memory(1), memory(2), memory(3)];
        let mut stage = input(Some(&lane), true, 25);
        stage.wait = Duration::ZERO;
        let report = rerank_stage(&support, &stage, &mut items, &slots, &texts).await;
        assert_eq!(port.calls.load(Ordering::SeqCst), 0, "no budget, no call");
        assert_eq!(ids(&items), [1, 2, 3], "the fused order");
        assert_eq!(report.failure, Some(RerankFailure::Unavailable));
        assert_eq!(report.model, ProvenanceValue::CannotEstablish {});
    }

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
        assert_eq!(point_of(1), Some(RecallPoint::Uuid(Uuid::from_u128(11))));
        assert_eq!(point_of(2), Some(RecallPoint::Uuid(Uuid::from_u128(22))));
    }

    #[test]
    fn rrf_keys_plain_dense_hits_by_point_and_passes_one_leg_through() {
        let dense = leg(&[(31, None), (32, None)]);
        let sparse = leg(&[(32, Some(302))]);
        let fused = fuse_rrf([&dense, &sparse], 60, false, 10);
        assert_eq!(
            fused.iter().map(|c| c.point_id).collect::<Vec<_>>(),
            [
                RecallPoint::Uuid(Uuid::from_u128(32)),
                RecallPoint::Uuid(Uuid::from_u128(31))
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
