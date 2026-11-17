//! `application::recall_read` — ordered candidates enter one authoritative snapshot (Baseline §23 / ADR-0130).
//! Depends-on: crates=[async-trait, humaux-domain, humaux-projection, humaux-retrieval, serde, serde_json, time, uuid]; services=[]; env=[]; modules=[domain::affect, domain::authority, domain::context, domain::error, domain::identity, domain::ids, domain::note, domain::subject, projection::note_chunks, projection::serving, projection::stream, retrieval::compiler, retrieval::completeness, retrieval::envelope, retrieval::handoff, retrieval::signals]
//! Called-by: [adapters::context_repo, adapters::exact_census, adapters::grep_repo, adapters::memory_repo, adapters::read_materialize, adapters::retrieve, adapters::serving_repo, gateway::bootstrap, gateway::context, gateway::mcp_application, gateway::memory, gateway::recall, tests]
//! Invariants: [the read port owns the complete same-snapshot hydration; candidates confer no authority]
//! Spec: Baseline §15.5; §22; §23; ADR-0130 D7.2

use async_trait::async_trait;
use humaux_domain::{affect::AffectFilter, identity::AuthorizationScope, subject::SubjectId};
use humaux_domain::{
    authority::MemoryId, context::ContextBudget, error::ErrorCode, ids::Scope, note::NoteKind,
};
use humaux_projection::stream::StreamKey;
use humaux_projection::{note_chunks::CardSlot, serving::StreamFamily};
use humaux_retrieval::{
    compiler::ContextOutcome,
    envelope::{FrontierBlock, FrontierPipelineBlock},
    handoff::Handoff,
};
use humaux_retrieval::{
    completeness::{FreshnessClass, LedgerClosure},
    envelope::{CountScope, EvidenceBlock, FreshnessBlock, GroundingBlock, KnowledgeBlock},
    signals::summarize_freshness,
};
use std::collections::{BTreeMap, HashMap, HashSet};
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
    pub budget: ContextBudget,
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
    budget: ContextBudget,
    expected_family: &StreamFamily,
    validated_key: &StreamKey,
) -> Result<MaterializedContext, ErrorCode> {
    pool.assemble_context(ContextReadRequest {
        authorization,
        scope,
        budget,
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
