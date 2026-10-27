//! `application::forget` — T4.8: §37 `DeletionPlan` step order, deletion state machine, and `DeletionGraph`
//!   provenance closure.
//! Depends-on: crates=[sha2, uuid]; services=[]; env=[]; modules=[]
//! Called-by: [adapters::forget_repo, tests]
//! Invariants: [a manifest hash is a function of the SET of (kind, id) targets only: order- and duplicate-insensitive, and
//!   one target more or less changes it; an ImpactPreview is built only from already-visibility-filtered inputs, so a
//!   count or a title of an unreadable object cannot be expressed]
//! Spec: §37; §3; §78.3; §37.2; ADR-0092 D-A, D-B; ADR-0079 D-J
//!
//! Pure, no I/O — same rule as every other module in this crate (see `scheduler.rs`'s doc:
//! `humaux-application`'s `Cargo.toml` carries no SQL/HTTP driver dependency, §3/§78.3).
//! ADR-0092 D-C amends §37.2: `adapters::forget_repo::tombstone` and the 0278 deletion accept door are the two
//! tombstone exits. This pure module owns scope and manifest encodings, never database writes.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};
use uuid::Uuid;

/// §37 `DeletionPlan`'s eight steps, in the frozen order — tombstone first, not last
/// (§37: "旧顺序（第 4 步删 point、第 8 步才写 tombstone）...作废"). The ordinal doubling as
/// array index is deliberate: [`DeletionPlan::new`] can only ever produce this exact
/// sequence, so "which step is first" is a compile-time fact, not a runtime one a caller
/// could get backwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DeletionStep {
    /// Step 1. `retention::tombstone(scope, seq)` (§37.2). Not skippable — skipping it is
    /// "把删除伪装成洞" (§37).
    StreamLogTombstone,
    /// Step 2. Authority DB rows.
    AuthorityRows,
    /// Step 3. Relations.
    Relations,
    /// Step 4. Projection events.
    ProjectionEvents,
    /// Step 5. Qdrant points — physical purge. Idempotent/replayable (§37: "物理 purge：幂等、
    /// 可重放"); §65 owns the replay loop.
    QdrantPoints,
    /// Step 6. Object bytes.
    ObjectBytes,
    /// Step 7. Cache invalidation.
    CacheInvalidation,
    /// Step 8. Public contribution handling.
    PublicContributionHandling,
}

impl DeletionStep {
    /// The frozen order itself (§37's numbered list, verbatim). This is the single place the
    /// sequence is written down; [`DeletionPlan::new`] and every step-ordinal lookup below
    /// read it, none re-derives it.
    pub const ORDER: [DeletionStep; 8] = [
        DeletionStep::StreamLogTombstone,
        DeletionStep::AuthorityRows,
        DeletionStep::Relations,
        DeletionStep::ProjectionEvents,
        DeletionStep::QdrantPoints,
        DeletionStep::ObjectBytes,
        DeletionStep::CacheInvalidation,
        DeletionStep::PublicContributionHandling,
    ];

    /// 1-based position in §37's fixed order (`STREAM_LOG_TOMBSTONE` = 1).
    pub fn ordinal(self) -> u8 {
        Self::ORDER
            .iter()
            .position(|s| *s == self)
            .expect("ORDER enumerates every variant") as u8
            + 1
    }

    /// Stable DB text form (`ops.deletion_plan_steps.step`) — a closed set the CHECK
    /// constraint mirrors, not free text (CLAUDE.md 硬边界: 禁止 stringly-typed domain).
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::StreamLogTombstone => "STREAM_LOG_TOMBSTONE",
            Self::AuthorityRows => "AUTHORITY_ROWS",
            Self::Relations => "RELATIONS",
            Self::ProjectionEvents => "PROJECTION_EVENTS",
            Self::QdrantPoints => "QDRANT_POINTS",
            Self::ObjectBytes => "OBJECT_BYTES",
            Self::CacheInvalidation => "CACHE_INVALIDATION",
            Self::PublicContributionHandling => "PUBLIC_CONTRIBUTION_HANDLING",
        }
    }

    /// Inverse of [`Self::as_db_str`]. `None` for anything outside the closed set — a caller
    /// reading back a corrupt/foreign value gets a typed absence, never a silently-accepted
    /// guess.
    pub fn from_db_str(s: &str) -> Option<Self> {
        Self::ORDER.into_iter().find(|step| step.as_db_str() == s)
    }
}

/// `ops.deletion_plan_steps.outcome`'s closed set (0054's CHECK) — a typed counterpart to
/// [`DeletionStep`] so a step's completion outcome is never a bare `&str` at the call site
/// (CLAUDE.md 硬边界: 禁止 stringly-typed domain). `Done` is the only outcome that should
/// ever count as "this step is finished" — `ExternalPending`/`CannotErase`/`Failed` are
/// named non-terminal or non-success outcomes a caller must branch on, not ignore (see
/// `adapters::forget_repo`'s own doc for why treating any of the four alike is the root
/// cause of a false-green purge SLA gauge).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletionStepOutcome {
    Done,
    ExternalPending,
    CannotErase,
    Failed,
}

impl DeletionStepOutcome {
    /// Stable DB text form (`ops.deletion_plan_steps.outcome`) — mirrors the CHECK
    /// constraint's four-value set exactly, same reasoning as [`DeletionStep::as_db_str`].
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Done => "DONE",
            Self::ExternalPending => "EXTERNAL_PENDING",
            Self::CannotErase => "CANNOT_ERASE",
            Self::Failed => "FAILED",
        }
    }

    /// Inverse of [`Self::as_db_str`]. `None` for anything outside the closed set.
    pub fn from_db_str(s: &str) -> Option<Self> {
        [
            Self::Done,
            Self::ExternalPending,
            Self::CannotErase,
            Self::Failed,
        ]
        .into_iter()
        .find(|o| o.as_db_str() == s)
    }
}

/// §37 `DeletionPlan`: the eight steps, frozen order. [`Self::new`] is the sole constructor —
/// there is no way to build one with a custom or partial order (CLAUDE.md "唯一构造点模式").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeletionPlan {
    steps: [DeletionStep; 8],
}

impl DeletionPlan {
    /// The only way to obtain a `DeletionPlan` — always §37's frozen order.
    pub fn new() -> Self {
        Self {
            steps: DeletionStep::ORDER,
        }
    }

    /// The eight steps in execution order.
    pub fn steps(&self) -> &[DeletionStep; 8] {
        &self.steps
    }

    /// Steps not yet present in `completed` (their DB text form), still in plan order — the
    /// pure half of §65's replay job: given what `ops.deletion_plan_steps` already has for
    /// one `deletion_request_id`, what is left to (re)try. A crash between two steps resumes
    /// here instead of re-running everything (idempotent replay, not "start over").
    pub fn pending(&self, completed: &BTreeSet<DeletionStep>) -> Vec<DeletionStep> {
        self.steps
            .iter()
            .copied()
            .filter(|s| !completed.contains(s))
            .collect()
    }
}

impl Default for DeletionPlan {
    fn default() -> Self {
        Self::new()
    }
}

/// §37 DeletionGraph's deletion status machine: `REQUESTED … EXTERNAL_PENDING /
/// PARTIAL_CANNOT_ERASE` (verbatim variant set, Deletion Propagation section). "已删除" is
/// never claimed just because an API call returned 200 — `Completed` is one of four possible
/// terminal states, not the only one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletionState {
    Requested,
    Planned,
    InProgress,
    ExternalPending,
    Completed,
    PartialCannotErase,
    Failed,
}

impl DeletionState {
    /// Every state, in the order of `control.deletion_requests.state`'s CHECK (0054); a contract test reconciles the set
    /// both ways (§78.2).
    pub const ALL: [DeletionState; 7] = [
        Self::Requested,
        Self::Planned,
        Self::InProgress,
        Self::ExternalPending,
        Self::Completed,
        Self::PartialCannotErase,
        Self::Failed,
    ];

    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Requested => "REQUESTED",
            Self::Planned => "PLANNED",
            Self::InProgress => "IN_PROGRESS",
            Self::ExternalPending => "EXTERNAL_PENDING",
            Self::Completed => "COMPLETED",
            Self::PartialCannotErase => "PARTIAL_CANNOT_ERASE",
            Self::Failed => "FAILED",
        }
    }

    pub fn from_db_str(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|st| st.as_db_str() == s)
    }

    /// Terminal states never advance further — `Completed` is not special among them (a
    /// caller must not treat it as reopenable while treating the other two as final).
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::PartialCannotErase | Self::Failed
        )
    }

    /// Validates one state edge (mechanism, not discipline — same reasoning §37.2 applies to
    /// `stream_log`'s own guard trigger). Fail-loud on an illegal edge (§50), never a silent
    /// clamp: a caller trying to jump `Requested -> Completed` skipped the plan entirely and
    /// that must be visible, not swallowed.
    pub fn transition(self, next: Self) -> Result<Self, IllegalDeletionTransition> {
        let legal = matches!(
            (self, next),
            (Self::Requested, Self::Planned)
                | (Self::Planned, Self::InProgress)
                | (Self::InProgress, Self::ExternalPending)
                | (Self::InProgress, Self::Completed)
                | (Self::InProgress, Self::PartialCannotErase)
                | (Self::InProgress, Self::Failed)
                | (Self::ExternalPending, Self::InProgress)
                | (Self::ExternalPending, Self::Completed)
                | (Self::ExternalPending, Self::PartialCannotErase)
                | (Self::ExternalPending, Self::Failed)
        );
        if legal {
            Ok(next)
        } else {
            Err(IllegalDeletionTransition {
                from: self,
                to: next,
            })
        }
    }
}

/// [`DeletionState::transition`]'s failure — adapter-local-shaped error (not one of §52's two
/// frozen domain enums; same reasoning as `stream_repo::AdvanceError`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IllegalDeletionTransition {
    pub from: DeletionState,
    pub to: DeletionState,
}

impl std::fmt::Display for IllegalDeletionTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "illegal deletion state transition {} -> {}",
            self.from.as_db_str(),
            self.to.as_db_str()
        )
    }
}

impl std::error::Error for IllegalDeletionTransition {}

/// The eight subsystems a `DeletionGraph` must check simultaneously (§37 DeletionGraph
/// section, verbatim list) — a checklist, not something derived from the provenance edges
/// below (a plan with zero derived objects still owes every subsystem an explicit
/// completed/not-applicable answer, it does not get to skip the question).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeletionSubsystem {
    AuthorityDb,
    Relations,
    QdrantProjection,
    ObjectStore,
    Cache,
    PublicContributionDag,
    DisclosureLedgerProcessorProcedure,
    BackupsPerRetentionPolicy,
}

impl DeletionSubsystem {
    pub const CHECKLIST: [DeletionSubsystem; 8] = [
        DeletionSubsystem::AuthorityDb,
        DeletionSubsystem::Relations,
        DeletionSubsystem::QdrantProjection,
        DeletionSubsystem::ObjectStore,
        DeletionSubsystem::Cache,
        DeletionSubsystem::PublicContributionDag,
        DeletionSubsystem::DisclosureLedgerProcessorProcedure,
        DeletionSubsystem::BackupsPerRetentionPolicy,
    ];
}

/// §37 DeletionGraph: follows provenance to find derived objects a deletion must cascade to
/// (e.g. an L0 raw event's L1 distillation, an L2 rollup, a public-release object — "沿
/// provenance 找需连带删除的派生物"). Edges are `(parent, derived_child)`; object identity is
/// left as an opaque string on purpose — provenance spans Evidence/Memory/Rollup/Qdrant-point
/// ids of different concrete types, and this module has no business minting a sum type for
/// them (adapters own the real ids, this module only walks the graph).
///
/// **Not yet wired into `DeletionPlan` by this ticket** — [`evidence_closure_targets`] (M19-2) deliberately does
/// not walk this graph (ADR-0092 D-A rejects `DERIVED_FROM` as the closure source); nothing builds a
/// [`DeletionGraph`] outside this module's own unit tests and nothing reads [`DeletionSubsystem::CHECKLIST`]
/// outside them either. A deletion executed today cascades only as far as a frozen
/// closure and the eight-subsystem checklist is never actually answered by any code path.
/// Recorded here so this remains undelivered-and-known rather than silently read as
/// covered by T4.8.
#[derive(Debug, Clone)]
pub struct DeletionGraph {
    /// `parent -> derived_child`, i.e. deleting `parent` requires also deleting `child`.
    edges: Vec<(String, String)>,
}

impl DeletionGraph {
    pub fn new(edges: Vec<(String, String)>) -> Self {
        Self { edges }
    }

    /// BFS closure: every object transitively derived from `roots`, `roots` themselves
    /// included (deleting a root always deletes the root). No object appears twice even if
    /// reachable through more than one provenance path.
    pub fn cascade_closure(&self, roots: &[String]) -> BTreeSet<String> {
        let mut seen: BTreeSet<String> = roots.iter().cloned().collect();
        let mut frontier: Vec<String> = roots.to_vec();
        while let Some(current) = frontier.pop() {
            for (parent, child) in &self.edges {
                if parent == &current && seen.insert(child.clone()) {
                    frontier.push(child.clone());
                }
            }
        }
        seen
    }
}

/// The five deletion scopes of ADR-0092 D-A. The DB text form mirrors `control.deletion_requests.scope_kind`'s CHECK (0272);
/// the pairing is reconciled by a contract test (§78.2). Only `Memory` and `EvidenceClosure` have a closure fn so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeletionScopeKind {
    /// One Memory; its source Evidence is retained.
    Memory,
    /// Explicit Evidence roots plus everything derived from them (ADR-0079 D-J).
    EvidenceClosure,
    /// One registered subject (closure fn: M19-7).
    Subject,
    /// One document (closure fn: ADR-0079 T-DOC-6).
    Document,
    /// A whole account (closure fn: M19-8a).
    Tenant,
}

impl DeletionScopeKind {
    /// Every scope, in the CHECK's order.
    pub const ALL: [DeletionScopeKind; 5] = [
        DeletionScopeKind::Memory,
        DeletionScopeKind::EvidenceClosure,
        DeletionScopeKind::Subject,
        DeletionScopeKind::Document,
        DeletionScopeKind::Tenant,
    ];

    /// Stable DB text form (`control.deletion_requests.scope_kind`).
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Memory => "MEMORY",
            Self::EvidenceClosure => "EVIDENCE_CLOSURE",
            Self::Subject => "SUBJECT",
            Self::Document => "DOCUMENT",
            Self::Tenant => "TENANT",
        }
    }

    /// Inverse of [`Self::as_db_str`]; `None` outside the closed set.
    pub fn from_db_str(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_db_str() == s)
    }
}

/// What a frozen target row names (`control.deletion_targets.kind`, 0272's CHECK).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeletionTargetKind {
    /// A `private.memory_records` row.
    Memory,
    /// A `private.evidence_objects` row.
    Evidence,
}

impl DeletionTargetKind {
    /// Every target kind, in the CHECK's order.
    pub const ALL: [DeletionTargetKind; 2] =
        [DeletionTargetKind::Memory, DeletionTargetKind::Evidence];

    /// Stable DB text form (`control.deletion_targets.kind`).
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Memory => "MEMORY",
            Self::Evidence => "EVIDENCE",
        }
    }

    /// Inverse of [`Self::as_db_str`]; `None` outside the closed set.
    pub fn from_db_str(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_db_str() == s)
    }
}

/// One member of a frozen closure: ids only, never content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeletionTarget {
    /// Which table `id` belongs to.
    pub kind: DeletionTargetKind,
    /// The row id.
    pub id: Uuid,
}

/// `MEMORY` scope closure (ADR-0092 D-A): the Memory alone; its source Evidence is retained (`source_retained = true`).
pub fn memory_scope_targets(memory_id: Uuid) -> Vec<DeletionTarget> {
    vec![DeletionTarget {
        kind: DeletionTargetKind::Memory,
        id: memory_id,
    }]
}

/// `EVIDENCE_CLOSURE` scope closure (ADR-0092 D-A): exactly the explicit `roots`, plus every Memory with ANY input
/// (`memory_inputs` = `(memory, evidence)` rows of `private.memory_evidence`, any role) among them, as a whole. Other
/// derived Evidence is never added (ADR-0079 D-J; ADR-0092 D-A rejects the `evidence_edges` `DERIVED_FROM` closure).
/// Sorted, duplicate-free. The DB door `control.deletion_request_freeze` computes the same set in SQL; this fn is the
/// reference the pairing test compares it with.
pub fn evidence_closure_targets(
    roots: &[Uuid],
    memory_inputs: &[(Uuid, Uuid)],
) -> Vec<DeletionTarget> {
    let evidence: BTreeSet<Uuid> = roots.iter().copied().collect();
    let mut targets: BTreeSet<DeletionTarget> = evidence
        .iter()
        .map(|id| DeletionTarget {
            kind: DeletionTargetKind::Evidence,
            id: *id,
        })
        .collect();
    targets.extend(
        memory_inputs
            .iter()
            .filter(|(_, evidence_id)| evidence.contains(evidence_id))
            .map(|(memory_id, _)| DeletionTarget {
                kind: DeletionTargetKind::Memory,
                id: *memory_id,
            }),
    );
    targets.into_iter().collect()
}

/// Domain separator of [`manifest_hash`]; a change is a new manifest version.
const MANIFEST_HASH_DOMAIN: &[u8] = b"humaux.deletion.manifest.v1\n";

/// `manifest_hash` of a frozen closure: SHA-256 over the canonical, sorted, duplicate-free `(kind, id)` list. The sole
/// reference encoding of the value stored in `control.deletion_requests.manifest_hash` (written by the freeze door, which
/// computes the same bytes in SQL; `forget_repo` re-checks the match on every freeze) and later bound into the confirm token.
pub fn manifest_hash(targets: &[DeletionTarget]) -> [u8; 32] {
    let canonical: BTreeSet<(&'static str, Uuid)> = targets
        .iter()
        .map(|target| (target.kind.as_db_str(), target.id))
        .collect();
    let mut hasher = Sha256::new();
    hasher.update(MANIFEST_HASH_DOMAIN);
    for (kind, id) in canonical {
        hasher.update(kind.as_bytes());
        hasher.update([0u8]);
        hasher.update(id.as_bytes());
    }
    hasher.finalize().into()
}

/// ADR-0092 D-B: confirmation intent binds the scope and frozen manifest independently of the nonce and request id.
/// Migration 0278 computes the same encoding inside the accept door (Baseline §33.10 rule 9).
pub fn confirmation_digest(scope: DeletionScopeKind, manifest: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"humaux.deletion.confirm.v1\n");
    hash.update(scope.as_db_str().as_bytes());
    hash.update([0u8]);
    hash.update(manifest);
    hash.finalize().into()
}

/// A Memory the caller may read, as the preview sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VisibleMemory {
    /// The readable Memory.
    pub memory_id: Uuid,
    /// Its title when it has one.
    pub title: Option<String>,
}

/// D2 round-1 impact preview. Every count, title and id in it comes from objects the caller may read: the only constructor
/// takes the already-filtered sets, so an unreadable target cannot change a displayed number (G-M19-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImpactPreview {
    pub scope_kind: DeletionScopeKind,
    /// Readable Memories in the closure.
    pub memory_count: usize,
    /// Readable Evidence rows in the closure.
    pub evidence_count: usize,
    /// Titles of the readable Memories that have one, sorted.
    pub memory_titles: Vec<String>,
    /// Readable closure Evidence linked to two or more subjects, sorted.
    pub multi_person_evidence: Vec<Uuid>,
    /// `true` for `MEMORY` scope (D-A: the source Evidence stays).
    pub source_retained: bool,
    /// Always `false`: a confirmed deletion is not restorable (D2).
    pub restore_supported: bool,
    /// Hash of the whole frozen closure, readable or not; carries no count or title.
    pub manifest_hash: [u8; 32],
}

impl ImpactPreview {
    /// The only way to build a preview. `multi_person` is intersected with `visible_evidence` here.
    pub fn from_visible(
        scope_kind: DeletionScopeKind,
        visible_memories: &[VisibleMemory],
        visible_evidence: &BTreeSet<Uuid>,
        multi_person: &BTreeSet<Uuid>,
        manifest_hash: [u8; 32],
    ) -> Self {
        let mut memory_titles: Vec<String> = visible_memories
            .iter()
            .filter_map(|memory| memory.title.clone())
            .collect();
        memory_titles.sort();
        Self {
            scope_kind,
            memory_count: visible_memories.len(),
            evidence_count: visible_evidence.len(),
            memory_titles,
            multi_person_evidence: multi_person
                .intersection(visible_evidence)
                .copied()
                .collect(),
            source_retained: scope_kind == DeletionScopeKind::Memory,
            restore_supported: false,
            manifest_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_order_is_frozen_and_tombstone_is_first() {
        let plan = DeletionPlan::new();
        assert_eq!(plan.steps()[0], DeletionStep::StreamLogTombstone);
        assert_eq!(DeletionStep::StreamLogTombstone.ordinal(), 1);
        assert_eq!(DeletionStep::PublicContributionHandling.ordinal(), 8);
        // §37: "旧顺序（第 4 步删 point、第 8 步才写 tombstone）作废" — pin the negative too.
        assert_ne!(plan.steps()[3], DeletionStep::StreamLogTombstone);
        assert_ne!(plan.steps()[7], DeletionStep::StreamLogTombstone);
    }

    #[test]
    fn db_str_round_trips_every_step() {
        for step in DeletionStep::ORDER {
            assert_eq!(DeletionStep::from_db_str(step.as_db_str()), Some(step));
        }
        assert_eq!(DeletionStep::from_db_str("NOT_A_STEP"), None);
    }

    /// Reconciles with `ops.deletion_plan_steps`'s CHECK set (0054): the four literal
    /// strings here must stay byte-for-byte identical to that migration's
    /// `CHECK (outcome IN (...))` list, or a value this enum considers legal would be
    /// rejected by the DB (or vice versa) — the exact drift §78.2 requires DB/Rust enums
    /// to be reconciled against.
    #[test]
    fn db_str_round_trips_every_outcome() {
        for outcome in [
            DeletionStepOutcome::Done,
            DeletionStepOutcome::ExternalPending,
            DeletionStepOutcome::CannotErase,
            DeletionStepOutcome::Failed,
        ] {
            assert_eq!(
                DeletionStepOutcome::from_db_str(outcome.as_db_str()),
                Some(outcome)
            );
        }
        assert_eq!(DeletionStepOutcome::from_db_str("NOT_AN_OUTCOME"), None);
        assert_eq!(
            BTreeSet::from(["DONE", "EXTERNAL_PENDING", "CANNOT_ERASE", "FAILED"]),
            [
                DeletionStepOutcome::Done,
                DeletionStepOutcome::ExternalPending,
                DeletionStepOutcome::CannotErase,
                DeletionStepOutcome::Failed,
            ]
            .map(DeletionStepOutcome::as_db_str)
            .into_iter()
            .collect(),
            "must equal 0054's CHECK (outcome IN (...)) set verbatim"
        );
    }

    #[test]
    fn pending_excludes_completed_steps_in_order() {
        let plan = DeletionPlan::new();
        let completed = BTreeSet::from([DeletionStep::StreamLogTombstone, DeletionStep::Relations]);
        let pending = plan.pending(&completed);
        assert_eq!(
            pending,
            vec![
                DeletionStep::AuthorityRows,
                DeletionStep::ProjectionEvents,
                DeletionStep::QdrantPoints,
                DeletionStep::ObjectBytes,
                DeletionStep::CacheInvalidation,
                DeletionStep::PublicContributionHandling,
            ]
        );
    }

    #[test]
    fn deletion_state_legal_transitions_hold() {
        assert_eq!(
            DeletionState::Requested.transition(DeletionState::Planned),
            Ok(DeletionState::Planned)
        );
        assert_eq!(
            DeletionState::InProgress.transition(DeletionState::ExternalPending),
            Ok(DeletionState::ExternalPending)
        );
        assert_eq!(
            DeletionState::ExternalPending.transition(DeletionState::PartialCannotErase),
            Ok(DeletionState::PartialCannotErase)
        );
    }

    #[test]
    fn deletion_state_skipping_the_plan_is_illegal() {
        // §37: an "already deleted" claim must not shortcut the plan (API 200 != physically
        // gone everywhere) — Requested -> Completed skips Planned/InProgress entirely.
        let err = DeletionState::Requested
            .transition(DeletionState::Completed)
            .unwrap_err();
        assert_eq!(err.from, DeletionState::Requested);
        assert_eq!(err.to, DeletionState::Completed);
    }

    #[test]
    fn terminal_states_are_exactly_the_three_named() {
        assert!(DeletionState::Completed.is_terminal());
        assert!(DeletionState::PartialCannotErase.is_terminal());
        assert!(DeletionState::Failed.is_terminal());
        assert!(!DeletionState::Requested.is_terminal());
        assert!(!DeletionState::Planned.is_terminal());
        assert!(!DeletionState::InProgress.is_terminal());
        assert!(!DeletionState::ExternalPending.is_terminal());
    }

    #[test]
    fn cascade_closure_follows_multi_hop_provenance_without_duplicates() {
        // L0 event -> L1 memory -> L2 rollup, plus a second L1 sharing the same rollup —
        // the diamond must not appear twice in the closure.
        let graph = DeletionGraph::new(vec![
            ("evidence:1".into(), "memory:1".into()),
            ("evidence:1".into(), "memory:2".into()),
            ("memory:1".into(), "rollup:1".into()),
            ("memory:2".into(), "rollup:1".into()),
        ]);
        let closure = graph.cascade_closure(&["evidence:1".to_string()]);
        assert_eq!(
            closure,
            BTreeSet::from([
                "evidence:1".to_string(),
                "memory:1".to_string(),
                "memory:2".to_string(),
                "rollup:1".to_string(),
            ])
        );
    }

    #[test]
    fn cascade_closure_root_with_no_derivations_is_itself_only() {
        let graph = DeletionGraph::new(vec![]);
        let closure = graph.cascade_closure(&["evidence:lonely".to_string()]);
        assert_eq!(closure, BTreeSet::from(["evidence:lonely".to_string()]));
    }

    #[test]
    fn subsystem_checklist_has_eight_distinct_entries() {
        let set: BTreeSet<_> = DeletionSubsystem::CHECKLIST.into_iter().collect();
        assert_eq!(set.len(), 8);
    }

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn target(kind: DeletionTargetKind, n: u128) -> DeletionTarget {
        DeletionTarget { kind, id: id(n) }
    }

    /// Reconciles with 0272's two CHECK lists (§78.2): the literals are the migration's, byte for byte.
    #[test]
    fn scope_and_target_kinds_match_the_0272_check_sets() {
        assert_eq!(
            DeletionScopeKind::ALL.map(DeletionScopeKind::as_db_str),
            [
                "MEMORY",
                "EVIDENCE_CLOSURE",
                "SUBJECT",
                "DOCUMENT",
                "TENANT"
            ]
        );
        for kind in DeletionScopeKind::ALL {
            assert_eq!(DeletionScopeKind::from_db_str(kind.as_db_str()), Some(kind));
        }
        assert_eq!(DeletionScopeKind::from_db_str("memory"), None);
        assert_eq!(
            DeletionTargetKind::ALL.map(DeletionTargetKind::as_db_str),
            ["MEMORY", "EVIDENCE"]
        );
        for kind in DeletionTargetKind::ALL {
            assert_eq!(
                DeletionTargetKind::from_db_str(kind.as_db_str()),
                Some(kind)
            );
        }
    }

    #[test]
    fn evidence_closure_is_the_roots_plus_every_memory_with_any_input_among_them() {
        // Roots e1 and e3. m1 reads e1, m2 reads e3 AND e9 (any input among the roots is enough, whole Memory),
        // m3 reads only e9. e2 is derived from e1 elsewhere but is not a root, so it stays out (ADR-0079 D-J).
        let inputs = [
            (id(101), id(1)),
            (id(102), id(3)),
            (id(102), id(9)),
            (id(103), id(9)),
        ];
        let got = evidence_closure_targets(&[id(3), id(1)], &inputs);
        let want = vec![
            target(DeletionTargetKind::Memory, 101),
            target(DeletionTargetKind::Memory, 102),
            target(DeletionTargetKind::Evidence, 1),
            target(DeletionTargetKind::Evidence, 3),
        ];
        assert_eq!(got, want);
    }

    #[test]
    fn memory_scope_is_the_memory_alone() {
        assert_eq!(
            memory_scope_targets(id(5)),
            vec![target(DeletionTargetKind::Memory, 5)]
        );
    }

    #[test]
    fn manifest_hash_is_deterministic_order_insensitive_and_sensitive_to_one_more_target() {
        let a = target(DeletionTargetKind::Memory, 1);
        let b = target(DeletionTargetKind::Evidence, 1);
        let c = target(DeletionTargetKind::Evidence, 2);
        let base = manifest_hash(&[a, b]);
        assert_eq!(base, manifest_hash(&[a, b]));
        assert_eq!(
            base,
            manifest_hash(&[b, a, b]),
            "order and duplicates do not matter"
        );
        assert_ne!(
            base,
            manifest_hash(&[a, b, c]),
            "one target more changes the hash"
        );
        assert_ne!(
            base,
            manifest_hash(&[a]),
            "one target less changes the hash"
        );
        assert_ne!(
            manifest_hash(&[a]),
            manifest_hash(&[b]),
            "the kind is part of the identity"
        );
    }

    #[test]
    fn preview_counts_only_the_visible_inputs_and_never_restores() {
        let visible = [
            VisibleMemory {
                memory_id: id(1),
                title: Some("b".into()),
            },
            VisibleMemory {
                memory_id: id(2),
                title: Some("a".into()),
            },
            VisibleMemory {
                memory_id: id(3),
                title: None,
            },
        ];
        let evidence = BTreeSet::from([id(10), id(11)]);
        // id(12) is multi-person but not visible: it must not be listed.
        let multi = BTreeSet::from([id(11), id(12)]);
        let preview = ImpactPreview::from_visible(
            DeletionScopeKind::EvidenceClosure,
            &visible,
            &evidence,
            &multi,
            [7u8; 32],
        );
        assert_eq!(preview.memory_count, 3);
        assert_eq!(preview.evidence_count, 2);
        assert_eq!(
            preview.memory_titles,
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(preview.multi_person_evidence, vec![id(11)]);
        assert!(!preview.source_retained);
        assert!(!preview.restore_supported);
        assert_eq!(preview.manifest_hash, [7u8; 32]);
        let memory_scope = ImpactPreview::from_visible(
            DeletionScopeKind::Memory,
            &[],
            &BTreeSet::new(),
            &BTreeSet::new(),
            [0; 32],
        );
        assert!(memory_scope.source_retained);
    }
}
