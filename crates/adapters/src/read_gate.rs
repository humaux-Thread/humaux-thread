//! `adapters::read_gate` — the one home of the final read gate: the all-backing-evidence closure (`readable_memory_ids`) and the
//!   `memory.get` / `memory.enumerate` materializers that read only through it.
//! Depends-on: crates=[humaux-domain, humaux-projection, humaux-retrieval, sqlx];
//!   services=[PostgreSQL(any) r=[private.evidence_objects, private.memory_evidence, private.memory_records,
//!   private.memory_subjects, private.note_heads]]; env=[]; modules=[adapters::context_repo, adapters::postgres,
//!   adapters::read_materialize, adapters::selection_repo, adapters::stream_repo, domain::authority, domain::error,
//!   domain::grounding, domain::identity, domain::ids, domain::note, domain::selection, projection::serving,
//!   projection::stream, retrieval::completeness, retrieval::envelope]
//! Called-by: [adapters::context_repo, adapters::exact_census, adapters::memory_governance_repo,
//!   adapters::read_materialize, gateway::mcp_application, gateway::memory, tests]
//! Invariants: [a Memory is readable only when all six conjuncts hold: (1) tenant, the Memory row and each Evidence
//!   row are read under the caller's tenant_id and RLS; (2) visibility, `identity::can_read` over the Memory's own
//!   descriptor (§6.1.1); (3) lifecycle selection, one bound `Lifecycle` (ADR-0067 D-J2); (4) subject guard, any-of
//!   over the requested subjects (§6.1.3); (5) secret-backed and tombstoned exclusion (ADR-0071); (6) all-backing-evidence closure, a Memory with
//!   zero Evidence rows, or with any Evidence row unreadable or hidden by RLS, fails closed (§8.6); (1), (2) and (6)
//!   are computed here by `readable_memory_ids`, (3) to (5) by the anti-join SQL of
//!   `read_materialize::final_memory_ids_with_readable_in_txn`, which calls it first; the materializers here read
//!   under one REPEATABLE READ snapshot and surface absent, hidden and gated rows alike as NotFound, a PG error as
//!   DependencyUnavailable or Internal, never an empty page; no cached allow decision, and the only write is the
//!   enumeration manifest a first page mints through `context_repo` and `selection_repo`]
//! Spec: Baseline §6.1.1; §6.1.3; §8.6; §22.1; ADR-0067 D-J2; ADR-0071
//!
//! M08 D1 (module design "one gate, one home"): every read op passes the shared final gate before any body leaves
//! PostgreSQL, and the closure it rests on lives in this file, so a change to the readability rule edits one module.
//! `can_read(` is called from this file and from the few declared exceptions only; the `G-M08-2` sentinel in
//! `xtask/src/architecture_check.rs` pins that set with `==`, so a new read op that judges visibility itself is red
//! until it is routed through [`readable_memory_ids`] or declared there.
//!
//! The materializers here are the `memory.get` and `memory.enumerate` entry points. Census minting, the frozen
//! census readout and the stream pipeline counts stay in [`crate::context_repo`] (§22.1, §23.3④, module M13); this
//! file only calls them inside the transaction it owns.

use humaux_domain::authority::MemoryId;
use humaux_domain::error::ErrorCode;
use humaux_domain::grounding::RowGrounding;
use humaux_domain::identity::{AuthorizationScope, VisibilityDescriptor, can_read};
use humaux_domain::ids::Scope;
use humaux_domain::note::NoteKind;
use humaux_domain::selection::{AUTHORIZED_MEMORY_ENUMERATION_V1, Cursor, query_fingerprint};
use humaux_projection::serving::StreamFamily;
use humaux_projection::stream::StreamKey;
use humaux_retrieval::envelope::GroundingBlock;
use sqlx::Row;
use sqlx::types::Uuid;
use sqlx::types::time::OffsetDateTime;
use std::collections::{HashMap, HashSet};

use crate::context_repo::{
    EnumerationCensus, EnumerationFilter, body_ids, canonical_scope, continuation_bound,
    frozen_census_in_txn, grounding_from_facts, materialized_identity, mint_segment_in_txn,
    set_authorization_local, stream_pipeline_counts_in_txn, visibility_from_row,
};
use crate::postgres::RuntimeDbPool;
use crate::read_materialize::{
    Lifecycle, MaterializedBodies, MemoryHistory, materialize_one_memory_in_txn,
    materialize_selected_bodies_in_txn, memory_history_in_txn, memory_note_kinds_in_txn,
    memory_versions_in_txn,
};
use crate::selection_repo::fetch_authorized_snapshot_page_in_txn;
use crate::stream_repo::close_ledger_in_txn;

type Txn<'c> = sqlx::Transaction<'c, sqlx::Postgres>;

/// Runs `can_read` against real Memory and backing Evidence rows. A Memory without a backing
/// Evidence row, or with any Evidence row hidden by RLS, fails closed (§6.1.1/§8.6).
pub(crate) async fn readable_memory_ids(
    txn: &mut Txn<'_>,
    authorization: &AuthorizationScope,
    candidate_ids: &[Uuid],
) -> Result<HashSet<Uuid>, ErrorCode> {
    if candidate_ids.is_empty() {
        return Ok(HashSet::new());
    }
    let memories = sqlx::query(
        "SELECT memory_id, visibility_class, visibility_user_id, visibility_workspace_id \
         FROM private.memory_records WHERE tenant_id = $1 AND memory_id = ANY($2)",
    )
    .bind(authorization.tenant_id().0)
    .bind(candidate_ids)
    .fetch_all(&mut **txn)
    .await
    .map_err(|_| ErrorCode::Internal)?;
    let mut memory_visibility = HashMap::with_capacity(memories.len());
    for row in memories {
        let memory_id = row.try_get("memory_id").map_err(|_| ErrorCode::Internal)?;
        memory_visibility.insert(memory_id, visibility_from_row(&row)?);
    }

    // `memory_evidence` remains visible through its Memory RLS policy; the LEFT JOIN exposes
    // a hidden Evidence row as NULL, so a tenant-visible Memory cannot smuggle a private source
    // into Context merely because the Evidence table's RLS omitted it from the join.
    let evidence = sqlx::query(
        "SELECT me.memory_id, eo.evidence_id AS visible_evidence_id, eo.visibility_class, \
                eo.visibility_user_id, eo.visibility_workspace_id \
         FROM private.memory_evidence me \
         LEFT JOIN private.evidence_objects eo \
           ON eo.evidence_id = me.evidence_id AND eo.tenant_id = $1 \
         WHERE me.memory_id = ANY($2)",
    )
    .bind(authorization.tenant_id().0)
    .bind(candidate_ids)
    .fetch_all(&mut **txn)
    .await
    .map_err(|_| ErrorCode::Internal)?;
    let mut evidence_by_memory: HashMap<Uuid, Vec<Option<VisibilityDescriptor>>> = HashMap::new();
    for row in evidence {
        let memory_id = row.try_get("memory_id").map_err(|_| ErrorCode::Internal)?;
        let visible: Option<Uuid> = row
            .try_get("visible_evidence_id")
            .map_err(|_| ErrorCode::Internal)?;
        let descriptor = visible.map(|_| visibility_from_row(&row)).transpose()?;
        evidence_by_memory
            .entry(memory_id)
            .or_default()
            .push(descriptor);
    }

    Ok(memory_visibility
        .into_iter()
        .filter_map(|(memory_id, descriptor)| {
            let evidence = evidence_by_memory.get(&memory_id)?;
            (can_read(authorization, &descriptor)
                && !evidence.is_empty()
                && evidence.iter().all(|descriptor| {
                    descriptor.is_some_and(|value| can_read(authorization, &value))
                }))
            .then_some(memory_id)
        })
        .collect())
}

/// One exact, object-level Memory read from the caller's trusted serving stream.
///
/// `bodies` carries the same RR snapshot identity as the final Memory body. `ledger` and
/// `grounding` were read in that same transaction, but this type does not claim a complete
/// stream or pipeline census.
pub struct MaterializedMemory {
    /// The final body rows, gated and read in one RR snapshot.
    pub bodies: MaterializedBodies,
    /// The stream ledger closure read in that same transaction.
    pub ledger: humaux_retrieval::completeness::LedgerClosure,
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
    pub(crate) fn kind_wires(&self) -> Option<Vec<String>> {
        self.note_kinds
            .as_ref()
            .map(|kinds| kinds.iter().map(|kind| kind.wire().to_owned()).collect())
    }

    /// The fingerprint segment: kinds sorted and deduplicated, joined by `,`; bounds as unix nanoseconds; empty when
    /// absent. `None` when no axis is set, so an unfiltered manifest keeps its pre-40b fingerprint.
    fn fingerprint_segment(&self) -> Option<String> {
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
    fn history_segment(&self) -> Option<String> {
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
    fn validate(&self) -> Result<(), ErrorCode> {
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

/// Reads grounding facts for a Memory already admitted by final materialization.
///
/// The preceding body read has already performed the Memory-plus-all-Evidence authorization
/// gate. A missing row in this same RR snapshot is therefore an invariant break, rather than
/// a second observable existence oracle. `lifecycle` is the same selection that body read made (ADR-0067 D-H,
/// D-J2), so the two never disagree about one row.
async fn direct_get_grounding_in_txn(
    txn: &mut Txn<'_>,
    authorization: &AuthorizationScope,
    memory_id: MemoryId,
    lifecycle: Lifecycle,
) -> Result<GroundingBlock, ErrorCode> {
    // $1 tenant, $2 memory id, $3/$4 the lifecycle (statuses, archive mode).
    let sql = format!(
        r#"
        SELECT EXISTS(
                   SELECT 1
                   FROM private.memory_evidence AS me
                   WHERE me.memory_id = m.memory_id
                     AND me.grounding_mode = 'LIVE'
               ) AS has_live,
               EXISTS(
                   SELECT 1
                   FROM private.memory_evidence AS me
                   WHERE me.memory_id = m.memory_id
                     AND me.grounding_mode = 'LIVE'
                     AND me.recorded_version IS NULL
               ) AS has_live_unversioned
        FROM private.memory_records AS m
        WHERE m.tenant_id = $1
          AND m.memory_id = $2
          AND {lifecycle}
        "#,
        lifecycle = Lifecycle::sql("m", 3),
    );
    let row = sqlx::query(&sql)
        .bind(authorization.tenant_id().0)
        .bind(memory_id.0)
        .bind(lifecycle.status_wires())
        .bind(lifecycle.archive_wire())
        .fetch_optional(&mut **txn)
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?
        .ok_or(ErrorCode::Internal)?;
    let grounding = grounding_from_facts(
        row.try_get("has_live").map_err(|_| ErrorCode::Internal)?,
        row.try_get("has_live_unversioned")
            .map_err(|_| ErrorCode::Internal)?,
    );
    let state = match grounding {
        RowGrounding::Judged(state) => Some(state),
        RowGrounding::NotJudged => None,
    };
    Ok(GroundingBlock::tally([state]))
}

/// Materializes one exact Memory, its final body, ledger and grounding in one RR snapshot.
///
/// Scope canonicalization runs before object access, so a requested foreign workspace remains
/// `FORBIDDEN`; all object-level absence and final-body policy failures map to `NOT_FOUND`.
/// `expected_family` and `validated_key` must be supplied by trusted serving/token validation.
/// Current versions only ([`materialize_memory_get_versioned`] without history).
pub async fn materialize_memory_get(
    pool: &RuntimeDbPool,
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

/// [`materialize_memory_get`] with the ADR-0067 D-H `include_history` choice. `true` also admits the exact version
/// asked for when it is `superseded` (never a jump to its successor) and reads its [`MemoryHistory`]; `revoked` /
/// `expired`, tombstoned, forgotten and `SECRET_MATERIAL`-backed rows stay `NOT_FOUND` — the shared final gate
/// decides that, with only its lifecycle selection widened.
pub async fn materialize_memory_get_versioned(
    pool: &RuntimeDbPool,
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

/// ADR-0067 D-J2: what `memory.get` names — one version, or one note (resolved to its head). The two namespaces never
/// fall back into each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryGetTarget {
    /// One immutable version by its `memory_id`.
    Memory(MemoryId),
    /// One note by its `note_id`, read at `private.note_heads.head_memory_id`.
    Note(Uuid),
}

/// ADR-0067 D-J2: `private.note_heads` resolves a note to its head under the tenant RLS GUC of `txn` (migration 0236:
/// the head row's policy is tenant-only; visibility, forget and lifecycle are the final gate's). An unknown note is
/// `NOT_FOUND`.
async fn note_head_in_txn(
    txn: &mut Txn<'_>,
    tenant_id: Uuid,
    note_id: Uuid,
) -> Result<MemoryId, ErrorCode> {
    let head: Option<Uuid> = sqlx::query_scalar(
        "SELECT head_memory_id FROM private.note_heads WHERE tenant_id = $1 AND note_id = $2",
    )
    .bind(tenant_id)
    .bind(note_id)
    .fetch_optional(&mut **txn)
    .await
    .map_err(|_| ErrorCode::DependencyUnavailable)?;
    head.map(MemoryId).ok_or(ErrorCode::NotFound)
}

/// [`materialize_memory_get_versioned`] for either [`MemoryGetTarget`]. A note resolves to its head in the same RR
/// snapshot, then runs exactly the version read: a head that fails the final gate (forgotten, tombstoned, revoked,
/// invisible) is `NOT_FOUND`, never an older version. `include_history` with a note targets the head.
pub async fn materialize_memory_get_target(
    pool: &RuntimeDbPool,
    authorization: &AuthorizationScope,
    scope: &Scope,
    expected_family: &StreamFamily,
    validated_key: &StreamKey,
    target: MemoryGetTarget,
    include_history: bool,
) -> Result<MaterializedMemory, ErrorCode> {
    let (read_authorization, _) = canonical_scope(authorization, scope)?;
    materialized_identity(scope, expected_family, validated_key)?;
    let mut txn = pool
        .pool()
        // dep: PostgreSQL(any) — opens a PostgreSQL transaction
        .begin()
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *txn)
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    let memory_id = match target {
        MemoryGetTarget::Memory(memory_id) => memory_id,
        MemoryGetTarget::Note(note_id) => {
            set_authorization_local(&mut txn, &read_authorization).await?;
            note_head_in_txn(&mut txn, authorization.tenant_id().0, note_id).await?
        }
    };
    let bodies = materialize_one_memory_in_txn(
        &mut txn,
        authorization,
        expected_family,
        validated_key,
        memory_id,
        include_history,
    )
    .await?;
    let grounding = direct_get_grounding_in_txn(
        &mut txn,
        authorization,
        memory_id,
        Lifecycle::for_get(include_history),
    )
    .await?;
    // Q3/ADR-0024 D-C: memory.get surfaces `archived:true` (unlike recall/context, which
    // exclude archived rows). The body read above already gated visibility/lifecycle, so a
    // missing row here is an invariant break in the same RR snapshot, not an existence oracle.
    // ADR-0067 L-6: the enumerate path's second, fail-closed lifecycle layer, here too — the
    // admitted version must be `active`, or `superseded` with `include_history`; a `revoked` /
    // `expired` row (or a superseded one without history) got past the final gate: `Internal`.
    let (statuses, archived_ids) =
        memory_versions_in_txn(&mut txn, authorization.tenant_id().0, &[memory_id.0]).await?;
    let admitted = match statuses.get(&memory_id.0).copied() {
        Some("active") => true,
        Some("superseded") => include_history,
        _ => false,
    };
    if !admitted {
        return Err(ErrorCode::Internal);
    }
    let archived = archived_ids.contains(&memory_id.0);
    let subjects =
        memory_subjects_in_txn(&mut txn, authorization.tenant_id().0, &[memory_id.0]).await?;
    let (note_kinds, note_ids) =
        memory_note_kinds_in_txn(&mut txn, authorization.tenant_id().0, &[memory_id.0]).await?;
    // ADR-0067 D-H: read in the same RR snapshot the body gate just admitted the row in.
    let history = if include_history {
        Some(memory_history_in_txn(&mut txn, &read_authorization, memory_id).await?)
    } else {
        None
    };
    let ledger = close_ledger_in_txn(&mut txn, validated_key, authorization)
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    txn.commit()
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    Ok(MaterializedMemory {
        bodies,
        ledger,
        grounding,
        subjects,
        archived,
        archived_ids: HashSet::new(),
        statuses: HashMap::new(),
        note_kinds,
        note_ids,
        history,
    })
}

fn enumeration_fingerprint(
    authorization: &AuthorizationScope,
    scope: &Scope,
    subject_id: Option<Uuid>,
    notes: &NoteEnumerationFilter,
) -> String {
    let workspace = scope
        .workspace_id
        .map(|id| id.0.to_string())
        .unwrap_or_default();
    let user = authorization
        .user_id()
        .map(|id| id.0.to_string())
        .unwrap_or_default();
    // The subject filter is part of the predicate identity (empty segment when absent), so a
    // cursor minted under one filter never pages another manifest.
    let subject = subject_id.map(|id| id.to_string()).unwrap_or_default();
    let mut identity = format!(
        "{AUTHORIZED_MEMORY_ENUMERATION_V1}:{}:{}:{}:{subject}",
        authorization.principal().0,
        user,
        workspace
    );
    // ADR-0067 D-G: the note axes are part of the predicate identity too. Appended only when set, so the segment
    // count tells a filtered identity from an unfiltered one and existing cursors keep their fingerprint.
    if let Some(segment) = notes.fingerprint_segment() {
        identity.push(':');
        identity.push_str(&segment);
    }
    // ADR-0067 D-J2: likewise the history selection, appended only when it is not the default.
    if let Some(segment) = notes.history_segment() {
        identity.push(':');
        identity.push_str(&segment);
    }
    query_fingerprint(&identity, authorization.tenant_id().0)
}

/// §6.1.3 (ADR-0028 D-D): linked subject ids for each of `ids`, in link order, under the
/// transaction's RLS (`private.memory_subjects` is visible exactly where its memory is).
async fn memory_subjects_in_txn(
    txn: &mut Txn<'_>,
    tenant_id: Uuid,
    ids: &[Uuid],
) -> Result<HashMap<Uuid, Vec<Uuid>>, ErrorCode> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = sqlx::query(
        "SELECT memory_id, subject_id FROM private.memory_subjects \
         WHERE tenant_id = $1 AND memory_id = ANY($2) \
         ORDER BY memory_id, created_at, subject_id",
    )
    .bind(tenant_id)
    .bind(ids)
    .fetch_all(&mut **txn)
    .await
    .map_err(|_| ErrorCode::DependencyUnavailable)?;
    let mut out: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    for row in rows {
        let memory_id: Uuid = row.try_get("memory_id").map_err(|_| ErrorCode::Internal)?;
        let subject_id: Uuid = row.try_get("subject_id").map_err(|_| ErrorCode::Internal)?;
        out.entry(memory_id).or_default().push(subject_id);
    }
    Ok(out)
}

fn validate_enumeration_params(params: &MemoryEnumerationParams<'_>) -> Result<(), ErrorCode> {
    if !(1..=100).contains(&params.page_size)
        || params.manifest_cap == 0
        || !(1..=86_400).contains(&params.ttl.as_secs())
        || params.ttl.subsec_nanos() != 0
        || params.mac_key.is_empty()
        || params
            .cursor
            .is_some_and(|cursor| cursor.is_empty() || cursor.len() > 1024)
    {
        return Err(ErrorCode::InvalidInput);
    }
    Ok(())
}

async fn page_grounding_in_txn(
    txn: &mut Txn<'_>,
    authorization: &AuthorizationScope,
    ids: &[Uuid],
    lifecycle: Lifecycle,
) -> Result<GroundingBlock, ErrorCode> {
    let mut result = GroundingBlock::tally([]);
    for id in ids {
        let block =
            direct_get_grounding_in_txn(txn, authorization, MemoryId(*id), lifecycle).await?;
        result.current += block.current;
        result.recheck_required += block.recheck_required;
        result.unresolved += block.unresolved;
        result.cannot_establish += block.cannot_establish;
        result.not_judged += block.not_judged;
        result.revokes_current_truth_assumption += block.revokes_current_truth_assumption;
    }
    Ok(result)
}

/// Materializes an authorization-bound immutable Memory page with no note axis
/// ([`materialize_memory_enumeration_filtered`] with [`NoteEnumerationFilter::default`]).
pub async fn materialize_memory_enumeration(
    pool: &RuntimeDbPool,
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

/// Materializes an authorization-bound immutable Memory page whose EXACT predicate also carries the ADR-0067 D-G
/// note axes (`notes`), in the manifest SQL, the census and the fingerprint alike.
#[allow(clippy::too_many_lines)] // ADR-0028 D-D: the exact enumeration predicate now carries the subject_id filter inside the same manifest SQL + fingerprint; splitting it would separate the predicate from the completeness classification it must stay honest with.
pub async fn materialize_memory_enumeration_filtered(
    pool: &RuntimeDbPool,
    authorization: &AuthorizationScope,
    scope: &Scope,
    expected_family: &StreamFamily,
    validated_key: &StreamKey,
    params: MemoryEnumerationParams<'_>,
    notes: &NoteEnumerationFilter,
) -> Result<MaterializedMemoryPage, ErrorCode> {
    validate_enumeration_params(&params)?;
    notes.validate()?;
    let (authorization, scope) = canonical_scope(authorization, scope)?;
    materialized_identity(&scope, expected_family, validated_key)?;
    let fingerprint = enumeration_fingerprint(&authorization, &scope, params.subject_id, notes);
    // ADR-0062 D-K: a cursor standing at the end of a capped manifest opens the next segment. The segment bound is
    // read (one statement) before the transaction mode is chosen, because a new segment mints and needs READ WRITE.
    let cursor = params
        .cursor
        .map(|encoded| Cursor::decode(encoded).map_err(|_| ErrorCode::InvalidInput))
        .transpose()?;
    let mint = match &cursor {
        None => Some(None),
        Some(cursor) => {
            continuation_bound(pool, &authorization, cursor, &fingerprint, params.mac_key)
                .await?
                .map(Some)
        }
    };
    let mut txn = pool
        .pool()
        // dep: PostgreSQL(any) — opens a PostgreSQL transaction
        .begin()
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    sqlx::query(if mint.is_some() {
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ WRITE"
    } else {
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
    })
    .execute(&mut *txn)
    .await
    .map_err(|_| ErrorCode::DependencyUnavailable)?;
    set_authorization_local(&mut txn, &authorization).await?;
    let (page, frozen_census) = match (mint, &cursor) {
        (None, Some(cursor)) => {
            let page = fetch_authorized_snapshot_page_in_txn(
                &mut txn,
                authorization.tenant_id().0,
                cursor,
                &fingerprint,
                params.page_size as i64,
                params.mac_key,
            )
            .await?;
            // §22.1: a later page's denominator is the one frozen WITH the manifest (migration
            // 0165). Re-counting here would pair a younger snapshot's total with frozen items.
            let census =
                frozen_census_in_txn(&mut txn, authorization.tenant_id().0, page.snapshot_id)
                    .await?;
            (page, census)
        }
        (Some(before_id), _) => {
            let filter = EnumerationFilter {
                subject_id: params.subject_id,
                before_id,
                notes,
            };
            mint_segment_in_txn(
                &mut txn,
                &authorization,
                &scope,
                validated_key,
                &params,
                &fingerprint,
                filter,
            )
            .await?
        }
        // `mint` is `None` only for a cursor call.
        (None, None) => return Err(ErrorCode::Internal),
    };
    let expected: HashSet<_> = page.items.iter().copied().collect();
    if expected.len() != page.items.len() {
        return Err(ErrorCode::Internal);
    }
    // ADR-0067 D-J2: a later page re-validates under the request's selection, which the cursor fingerprint binds.
    let bodies = materialize_selected_bodies_in_txn(
        &mut txn,
        &authorization,
        expected_family,
        validated_key,
        &page.items,
        notes.lifecycle,
    )
    .await?;
    let materialized = body_ids(&bodies);
    if materialized.len() != bodies.items.len()
        || materialized.iter().any(|id| !expected.contains(id))
        || materialized.iter().collect::<HashSet<_>>().len() != materialized.len()
    {
        return Err(ErrorCode::Internal);
    }
    if materialized.len() != page.items.len() {
        return Err(ErrorCode::NotFound);
    }
    let grounding =
        page_grounding_in_txn(&mut txn, &authorization, &page.items, notes.lifecycle).await?;
    let subjects =
        memory_subjects_in_txn(&mut txn, authorization.tenant_id().0, &page.items).await?;
    let (note_kinds, note_ids) =
        memory_note_kinds_in_txn(&mut txn, authorization.tenant_id().0, &page.items).await?;
    let (statuses, archived_ids) =
        memory_versions_in_txn(&mut txn, authorization.tenant_id().0, &page.items).await?;
    let ledger = close_ledger_in_txn(&mut txn, validated_key, &authorization)
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    // §23.3④: read in the same transaction as the ledger whose `expected` they are compared
    // against. `None` census ⇒ no counts either (see `MaterializedMemoryPage::census`).
    let census = match scope.workspace_id {
        Some(_) => Some(EnumerationCensus {
            census: frozen_census.as_ref().map_or_else(
                humaux_retrieval::completeness::CensusResult::failed,
                |census| census.for_page(page.items.len()),
            ),
            pipeline: stream_pipeline_counts_in_txn(&mut txn, validated_key).await?,
        }),
        None => None,
    };
    txn.commit()
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    Ok(MaterializedMemoryPage {
        snapshot_id: page.snapshot_id,
        next_cursor: page.next_cursor.map(|cursor| cursor.encode()),
        memory: MaterializedMemory {
            bodies,
            ledger,
            grounding,
            subjects,
            // The single-item flag is memory.get's; a page reports its archived rows per item (ADR-0067 D-J2).
            archived: false,
            archived_ids,
            statuses,
            note_kinds,
            note_ids,
            history: None,
        },
        census,
    })
}
