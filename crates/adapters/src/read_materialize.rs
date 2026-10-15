//! `adapters::read_materialize` — Final PostgreSQL body materialization after authorization and token-ledger
//!   validation.
//! Depends-on: crates=[humaux-application, humaux-domain, humaux-projection, serde_json, sha2, sqlx];
//!   services=[PostgreSQL(role_gateway) r=[ops.outbox, private.events, private.evidence_objects,
//!   private.evidence_subjects, private.identity_note_materializations, private.memory_evidence,
//!   private.memory_records, private.memory_subjects, projection.stream_log]]; env=[]; modules=[adapters::affect_repo,
//!   adapters::context_repo, adapters::postgres, adapters::read_gate, adapters::retrieve, application::affect, domain::affect,
//!   domain::authority, domain::error, domain::identity, domain::ids, domain::note, domain::subject,
//!   projection::serving, projection::stream]
//! Called-by: [adapters::context_repo, adapters::continuity_read, adapters::exact_census, adapters::grep_repo, adapters::operation_receipt, adapters::read_gate, adapters::retrieve, gateway::context, gateway::mcp_application, gateway::memory, gateway::recall, tests]
//! Invariants: [read-only on role_gateway under RLS; an invisible or unknown source is NotFound/Forbidden, never
//!   partially materialized; a PG error is DependencyUnavailable; the recall/context entry points take no
//!   [`Lifecycle`] and always run [`Lifecycle::CURRENT`] (ADR-0067 D-J2)]
//! Spec: ADR-0067 D-J2

use std::collections::{HashMap, HashSet};

use humaux_application::affect::memories_matching;
use humaux_domain::affect::AffectFilter;
use humaux_domain::authority::MemoryId;
use humaux_domain::error::ErrorCode;
use humaux_domain::identity::{AuthorizationScope, can_read};
use humaux_domain::ids::WorkspaceId;
use humaux_domain::note::NoteKind;
use humaux_domain::subject::SubjectId;
use humaux_projection::serving::StreamFamily;
use humaux_projection::stream::StreamKey;
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::types::Uuid;
use sqlx::types::time::OffsetDateTime;

use crate::affect_repo;
use crate::context_repo::{set_authorization_local, visibility_from_row};
use crate::postgres::RuntimeDbPool;
use crate::read_gate::readable_memory_ids;
use crate::retrieve::{OverlayCandidate, ProcessingState};

type Txn<'c> = sqlx::Transaction<'c, sqlx::Postgres>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializationSnapshot {
    pub context_snapshot_seq: i64,
    pub snapshot_token_sha256: String,
}

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

#[derive(Debug, Clone, PartialEq)]
pub struct MaterializedBodies {
    pub snapshot: MaterializationSnapshot,
    pub items: Vec<MaterializedItem>,
}

fn dedup<T: std::hash::Hash + Eq + Copy>(items: impl IntoIterator<Item = T>) -> Vec<T> {
    let mut seen = HashSet::new();
    items
        .into_iter()
        .filter(|item| seen.insert(*item))
        .collect()
}

fn effective_authorization(
    authorization: &AuthorizationScope,
    expected_family: &StreamFamily,
    key: &StreamKey,
) -> Result<AuthorizationScope, ErrorCode> {
    if key.tenant_id != authorization.tenant_id()
        || expected_family.tenant_id != authorization.tenant_id()
        || key.tenant_id != expected_family.tenant_id
        || key.scope_kind != expected_family.scope_kind
        || key.scope_id != expected_family.scope_id
        || key.domain != expected_family.domain
        || key.projection_kind != expected_family.projection_kind
    {
        return Err(ErrorCode::Forbidden);
    }
    match key.scope_kind.as_str() {
        "tenant" if key.scope_id == authorization.tenant_id().0 => Ok(authorization.clone()),
        "workspace" => authorization.narrow(WorkspaceId(key.scope_id)),
        _ => Err(ErrorCode::Forbidden),
    }
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

/// [`Lifecycle::sql`]'s text. `{t}` = the `memory_records` alias, `{s}` = the bound `text[]` of statuses,
/// `{a}` = the bound archive mode. Each status keeps its §59.1 G59-4 pairing with `superseded_by`; an unknown
/// archive mode matches nothing (fail-closed).
// ponytail: the archive CASE on a bound parameter may defeat the `archived_at IS NULL` partial index under generic
// plans (ADR-0067 D-J2 "Possible plan cost"), split per-mode statements or force a custom plan when the
// `enumerate_scale` bar regresses.
const LIFECYCLE_SQL: &str = "((({t}.status = 'active' AND {t}.superseded_by IS NULL \
        AND 'active' = ANY(${s}::text[])) \
     OR ({t}.status = 'superseded' AND {t}.superseded_by IS NOT NULL \
        AND 'superseded' = ANY(${s}::text[]))) \
    AND (CASE ${a}::text WHEN 'exclude' THEN {t}.archived_at IS NULL \
                         WHEN 'only' THEN {t}.archived_at IS NOT NULL \
                         WHEN 'include' THEN true \
                         ELSE false END))";

impl Lifecycle {
    /// Recall, context and the default enumerate: active, not superseded, not archived.
    pub const CURRENT: Self = Self {
        statuses: StatusSet::Active,
        archive: ArchiveMode::Exclude,
    };

    /// The §22.1 registry census's `ACTIVE_FINAL`: active and not superseded, archive not consulted (a registry
    /// predicate owns its own archive stance).
    pub(crate) const ACTIVE_FINAL: Self = Self {
        statuses: StatusSet::Active,
        archive: ArchiveMode::Include,
    };

    /// ADR-0067 D-H / D-J2: `memory.get` admits archived rows (it reports `archived:true`), and with
    /// `include_history` the exact superseded version too.
    pub(crate) const fn for_get(include_history: bool) -> Self {
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
    pub(crate) fn canonical(self) -> String {
        format!("{}/{}", self.status_wires().join(","), self.archive_wire())
    }

    /// The selection as one SQL conjunct over `alias`, with the statuses bound at `$first` and the archive mode at
    /// `$first + 1` ([`Self::status_wires`], [`Self::archive_wire`]). `alias` is server-owned text, never input.
    pub(crate) fn sql(alias: &str, first: u8) -> String {
        LIFECYCLE_SQL
            .replace("{t}", alias)
            .replace("{s}", &first.to_string())
            .replace("{a}", &(first + 1).to_string())
    }
}

/// Returns only Memory ids that may enter a final materialization in this transaction.
///
/// This is the shared final eligibility gate: `can_read`, lifecycle, secret backing sources,
/// and tombstoned backing Evidence. It deliberately returns ids rather than content so callers
/// creating a snapshot manifest do not load and discard every Memory body. Current versions only
/// ([`Lifecycle::CURRENT`]): the recall/context face of the gate takes no selection (ADR-0067 D-J2).
pub(crate) async fn final_memory_ids_in_txn(
    txn: &mut Txn<'_>,
    authorization: &AuthorizationScope,
    candidates: &[Uuid],
) -> Result<Vec<Uuid>, ErrorCode> {
    final_memory_ids_about_in_txn(
        txn,
        authorization,
        candidates,
        Lifecycle::CURRENT,
        &[],
        None,
    )
    .await
}

/// [`final_memory_ids_in_txn`] plus the §6.1.3 / ADR-0029 D-A subject re-check: when
/// `subject_ids` is non-empty, only memories linked (`private.memory_subjects`, read under the
/// caller's RLS) to at least one of them survive. Qdrant's `subject_ids` payload prefilter is
/// never trusted on its own — this is the authoritative membership test, in the same shared
/// gate the [`Lifecycle`] selection lives in. Empty `subject_ids` = no subject narrowing.
///
/// §8.5.1 / ADR-0030 D-D: `affect` is the explicit affect query, re-checked here per annotation
/// on the read-time effective intensity (Qdrant's flat-array prefilter is an over-approximation
/// across annotations and cannot compute decay). ONE extra round trip for the whole candidate
/// set (`affect_repo::AFFECTS_FOR_MEMORIES_SQL`), never a per-row query. `None` = unscoped.
///
/// ADR-0067 D-J2: `lifecycle` is the read's typed selection (recall/context reach this gate only through
/// [`final_memory_ids_in_txn`] / [`materialize_final_bodies_about_in_txn`], which pass [`Lifecycle::CURRENT`]).
/// `revoked`/`expired` (L-6), secret backing and tombstoned Evidence stay excluded under every selection.
pub(crate) async fn final_memory_ids_about_in_txn(
    txn: &mut Txn<'_>,
    authorization: &AuthorizationScope,
    candidates: &[Uuid],
    lifecycle: Lifecycle,
    subject_ids: &[SubjectId],
    affect: Option<&AffectFilter>,
) -> Result<Vec<Uuid>, ErrorCode> {
    final_memory_ids_with_readable_in_txn(
        txn,
        authorization,
        candidates,
        lifecycle,
        subject_ids,
        affect,
    )
    .await
    .map(|(survivors, _)| survivors)
}

/// ADR-0071 D-C: the `can_read` set ([`readable_memory_ids`]) the shared final gate computed over its candidates,
/// in the caller's transaction. Only [`final_memory_ids_with_readable_in_txn`] constructs it, so a census handed one
/// narrows by a set the gate itself produced — never by an arbitrary id list.
pub struct GateReadable(HashSet<Uuid>);

impl GateReadable {
    /// Whether the gate found `memory_id` readable.
    pub(crate) fn contains(&self, memory_id: &Uuid) -> bool {
        self.0.contains(memory_id)
    }
}

/// [`final_memory_ids_about_in_txn`], also handing back the [`GateReadable`] set it computed over `candidates`.
/// ADR-0071 D-C: `memory.enumerate`'s mint passes it to its §22.1 census, whose candidates are a subset of these in
/// the same snapshot.
pub(crate) async fn final_memory_ids_with_readable_in_txn(
    txn: &mut Txn<'_>,
    authorization: &AuthorizationScope,
    candidates: &[Uuid],
    lifecycle: Lifecycle,
    subject_ids: &[SubjectId],
    affect: Option<&AffectFilter>,
) -> Result<(Vec<Uuid>, GateReadable), ErrorCode> {
    let readable = readable_memory_ids(txn, authorization, candidates).await?;
    let subject_filter: Option<Vec<Uuid>> =
        (!subject_ids.is_empty()).then(|| subject_ids.iter().map(|s| s.0).collect());
    // $1 tenant, $2 candidates, $3 subject filter, $4/$5 the ADR-0067 D-J2 lifecycle (statuses, archive mode).
    let sql = format!(
        r#"
        SELECT m.memory_id
        FROM private.memory_records AS m
        WHERE $1::uuid IS NOT NULL
          AND m.memory_id = ANY($2)
          -- ADR-0067 D-J2 (Q3/ADR-0024 D-C for the archive mode): one bound lifecycle selection.
          AND {lifecycle}
          -- §6.1.3/ADR-0029 D-A: subject any-of re-check (NULL = not subject-scoped).
          AND ($3::uuid[] IS NULL OR EXISTS (
              SELECT 1
              FROM private.memory_subjects AS ms
              WHERE ms.tenant_id = m.tenant_id
                AND ms.memory_id = m.memory_id
                AND ms.subject_id = ANY($3::uuid[])
          ))
          -- ADR-0071 D-A: the secret-backed and the tombstoned memories among the candidates, each one uncorrelated
          -- set the planner hashes once (`memory_evidence.memory_id` is NOT NULL, so NOT IN is the exact anti-join).
          -- Both are bounded by $2, so a small read never pays for the tenant's whole history; the tenant legs bind
          -- $1, which `m.tenant_id = $1` above already fixes.
          AND m.memory_id NOT IN (
              SELECT me.memory_id
              FROM private.memory_evidence AS me
              JOIN private.evidence_objects AS source
                ON source.evidence_id = me.evidence_id
               AND source.tenant_id = $1
              WHERE me.memory_id = ANY($2)
                AND source.data_class = 'SECRET_MATERIAL'
          )
          AND m.memory_id NOT IN (
              SELECT me.memory_id
              FROM private.memory_evidence AS me
              JOIN ops.outbox AS ob
                ON ob.tenant_id = $1
               AND ob.evidence_id = me.evidence_id
              JOIN projection.stream_log AS sl
                ON sl.tenant_id = ob.tenant_id
               AND sl.commit_seq = ob.commit_seq
              WHERE me.memory_id = ANY($2)
                AND sl.state = 'TOMBSTONED'
          )
        "#,
        lifecycle = Lifecycle::sql("m", 4),
    );
    let rows = sqlx::query(&sql)
        .bind(authorization.tenant_id().0)
        .bind(candidates)
        .bind(subject_filter)
        .bind(lifecycle.status_wires())
        .bind(lifecycle.archive_wire())
        .fetch_all(&mut **txn)
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;

    let eligible = rows
        .into_iter()
        .map(|row| row.try_get("memory_id").map_err(|_| ErrorCode::Internal))
        .collect::<Result<HashSet<Uuid>, ErrorCode>>()?;
    let mut survivors: Vec<Uuid> = candidates
        .iter()
        .filter(|id| readable.contains(id) && eligible.contains(id))
        .copied()
        .collect();
    if let Some(filter) = affect {
        let rows =
            affect_repo::affects_for_memories_in_txn(txn, authorization.tenant_id().0, &survivors)
                .await
                .map_err(|_| ErrorCode::DependencyUnavailable)?;
        let matching = memories_matching(
            filter,
            &affect_repo::observed(&rows, OffsetDateTime::now_utc()),
        );
        survivors.retain(|id| matching.contains(id));
    }
    Ok((survivors, GateReadable(readable)))
}

async fn load_memories(
    txn: &mut Txn<'_>,
    authorization: &AuthorizationScope,
    candidates: &[Uuid],
    lifecycle: Lifecycle,
    subject_ids: &[SubjectId],
    affect: Option<&AffectFilter>,
) -> Result<Vec<(Uuid, serde_json::Value)>, ErrorCode> {
    let eligible = final_memory_ids_about_in_txn(
        txn,
        authorization,
        candidates,
        lifecycle,
        subject_ids,
        affect,
    )
    .await?;
    let rows = sqlx::query(
        r#"
        SELECT m.memory_id, m.content
        FROM private.memory_records AS m
        WHERE m.tenant_id = $1
          AND m.memory_id = ANY($2)
        "#,
    )
    .bind(authorization.tenant_id().0)
    .bind(&eligible)
    .fetch_all(&mut **txn)
    .await
    .map_err(|_| ErrorCode::DependencyUnavailable)?;

    let mut values = HashMap::with_capacity(rows.len());
    for row in rows {
        let memory_id: Uuid = row.try_get("memory_id").map_err(|_| ErrorCode::Internal)?;
        values.insert(
            memory_id,
            row.try_get("content").map_err(|_| ErrorCode::Internal)?,
        );
    }
    eligible
        .into_iter()
        .map(|id| {
            values
                .remove(&id)
                .map(|content| (id, content))
                .ok_or(ErrorCode::Internal)
        })
        .collect::<Result<_, _>>()
}

struct RecheckedOverlay {
    evidence_id: Uuid,
    stream_seq: i64,
    processing_state: ProcessingState,
    evidence_kind: String,
    payload: Option<serde_json::Value>,
    linked_memory_ids: Vec<Uuid>,
}

/// Re-checks the RYW overlay under the caller's RLS snapshot. `subject_ids` (§6.1.3 / ADR-0029
/// D-A) is the same any-of scope the memory gate applies: when non-empty, an overlay Evidence
/// rides in only if `private.evidence_subjects` declares it about one of those subjects —
/// otherwise a subject-scoped recall carrying a consistency_token would return the raw body of
/// a just-written Evidence about someone else as `temporary_evidence`. Applied here, in the one
/// overlay loader, so every caller of the shared gate inherits it.
async fn load_overlay(
    txn: &mut Txn<'_>,
    authorization: &AuthorizationScope,
    key: &StreamKey,
    input: &[OverlayCandidate],
    subject_ids: &[SubjectId],
) -> Result<Vec<RecheckedOverlay>, ErrorCode> {
    let requested = dedup(input.iter().map(|item| (item.stream_seq, item.evidence_id)));
    if requested.is_empty() {
        return Ok(Vec::new());
    }
    let subject_filter: Option<Vec<Uuid>> =
        (!subject_ids.is_empty()).then(|| subject_ids.iter().map(|s| s.0).collect());
    let seqs = requested.iter().map(|(seq, _)| *seq).collect::<Vec<_>>();
    let evidence_ids = requested.iter().map(|(_, id)| *id).collect::<Vec<_>>();
    let rows = sqlx::query(
        r#"
        WITH requested(stream_seq, evidence_id) AS (
            SELECT * FROM UNNEST($7::bigint[], $8::uuid[])
        )
        SELECT sl.stream_seq,
               sl.state,
               ob.evidence_id,
               eo.evidence_kind,
               eo.visibility_class,
               eo.visibility_user_id,
               eo.visibility_workspace_id,
               event.payload
        FROM projection.stream_log AS sl
        JOIN ops.outbox AS ob
          ON ob.tenant_id = sl.tenant_id
         AND ob.commit_seq = sl.commit_seq
        JOIN requested AS requested
          ON requested.stream_seq = sl.stream_seq
         AND requested.evidence_id = ob.evidence_id
        JOIN private.evidence_objects AS eo
          ON eo.evidence_id = ob.evidence_id
         AND eo.tenant_id = sl.tenant_id
        LEFT JOIN private.events AS event ON event.event_id = eo.evidence_id
        WHERE sl.tenant_id = $1
          AND sl.scope_kind = $2
          AND sl.scope_id = $3
          AND sl.domain = $4
          AND sl.projection_kind = $5
          AND sl.projection_version = $6
          AND sl.state <> 'TOMBSTONED'
          AND eo.data_class <> 'SECRET_MATERIAL'
          -- §6.1.3/ADR-0029 D-A: subject any-of re-check for the overlay (NULL = not scoped).
          AND ($9::uuid[] IS NULL OR EXISTS (
              SELECT 1
              FROM private.evidence_subjects AS es
              WHERE es.tenant_id = eo.tenant_id
                AND es.evidence_id = eo.evidence_id
                AND es.subject_id = ANY($9::uuid[])
          ))
        ORDER BY sl.stream_seq, ob.evidence_id
        "#,
    )
    .bind(key.tenant_id.0)
    .bind(&key.scope_kind)
    .bind(key.scope_id)
    .bind(&key.domain)
    .bind(&key.projection_kind)
    .bind(&key.projection_version)
    .bind(seqs)
    .bind(evidence_ids)
    .bind(subject_filter)
    .fetch_all(&mut **txn)
    .await
    .map_err(|_| ErrorCode::DependencyUnavailable)?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let visibility = visibility_from_row(&row)?;
        if !can_read(authorization, &visibility) {
            continue;
        }
        let state: String = row.try_get("state").map_err(|_| ErrorCode::Internal)?;
        out.push(RecheckedOverlay {
            evidence_id: row
                .try_get("evidence_id")
                .map_err(|_| ErrorCode::Internal)?,
            stream_seq: row.try_get("stream_seq").map_err(|_| ErrorCode::Internal)?,
            processing_state: ProcessingState::parse(&state).map_err(|_| ErrorCode::Internal)?,
            evidence_kind: row
                .try_get("evidence_kind")
                .map_err(|_| ErrorCode::Internal)?,
            payload: row.try_get("payload").map_err(|_| ErrorCode::Internal)?,
            linked_memory_ids: Vec::new(),
        });
    }
    let evidence_ids = out.iter().map(|item| item.evidence_id).collect::<Vec<_>>();
    let mut links = load_links(txn, authorization, &evidence_ids).await?;
    for item in &mut out {
        item.linked_memory_ids = links.remove(&item.evidence_id).unwrap_or_default();
    }
    Ok(out)
}

async fn load_links(
    txn: &mut Txn<'_>,
    authorization: &AuthorizationScope,
    evidence_ids: &[Uuid],
) -> Result<HashMap<Uuid, Vec<Uuid>>, ErrorCode> {
    let rows = sqlx::query(
        r#"
        SELECT me.evidence_id, me.memory_id
        FROM private.memory_evidence AS me
        JOIN private.memory_records AS m
          ON m.memory_id = me.memory_id
         AND m.tenant_id = $1
         AND m.status = 'active'
         AND m.superseded_by IS NULL
        WHERE me.evidence_id = ANY($2)
        ORDER BY me.evidence_id, me.memory_id
        "#,
    )
    .bind(authorization.tenant_id().0)
    .bind(evidence_ids)
    .fetch_all(&mut **txn)
    .await
    .map_err(|_| ErrorCode::DependencyUnavailable)?;
    let memory_ids = dedup(
        rows.iter()
            .map(|row| row.try_get("memory_id").map_err(|_| ErrorCode::Internal))
            .collect::<Result<Vec<Uuid>, ErrorCode>>()?,
    );
    let readable = readable_memory_ids(txn, authorization, &memory_ids).await?;
    let mut result = HashMap::<Uuid, Vec<Uuid>>::new();
    for row in rows {
        let memory_id = row.try_get("memory_id").map_err(|_| ErrorCode::Internal)?;
        if readable.contains(&memory_id) {
            let evidence_id = row
                .try_get("evidence_id")
                .map_err(|_| ErrorCode::Internal)?;
            result.entry(evidence_id).or_default().push(memory_id);
        }
    }
    for ids in result.values_mut() {
        *ids = dedup(ids.iter().copied());
    }
    Ok(result)
}

async fn snapshot(txn: &mut Txn<'_>) -> Result<MaterializationSnapshot, ErrorCode> {
    let row = sqlx::query(
        r#"
        SELECT pg_snapshot_xmin(pg_current_snapshot())::text::bigint AS seq,
               pg_current_snapshot()::text AS token
        "#,
    )
    .fetch_one(&mut **txn)
    .await
    .map_err(|_| ErrorCode::DependencyUnavailable)?;
    let token: String = row.try_get("token").map_err(|_| ErrorCode::Internal)?;
    Ok(MaterializationSnapshot {
        context_snapshot_seq: row.try_get("seq").map_err(|_| ErrorCode::Internal)?,
        snapshot_token_sha256: Sha256::digest(token.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    })
}

pub async fn materialize_final_bodies(
    pool: &RuntimeDbPool,
    authorization: &AuthorizationScope,
    expected_family: &StreamFamily,
    validated_key: &StreamKey,
    memory_ids: &[Uuid],
    overlay: &[OverlayCandidate],
) -> Result<MaterializedBodies, ErrorCode> {
    let _ = effective_authorization(authorization, expected_family, validated_key)?;
    // dep: PostgreSQL(role_gateway) — transaction entry for `materialize_final_bodies`
    let mut txn = pool
        .pool()
        .begin()
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *txn)
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    let bodies = materialize_final_bodies_in_txn(
        &mut txn,
        authorization,
        expected_family,
        validated_key,
        memory_ids,
        overlay,
    )
    .await?;
    txn.commit()
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    Ok(bodies)
}

/// Materializes one trusted Memory id through a caller-owned repeatable-read transaction.
///
/// This keeps the final body policy in [`materialize_final_bodies_in_txn`]: tenant and
/// visibility gates, active/supersession lifecycle, secret backing-source exclusion, and
/// tombstoned Evidence exclusion all stay in that single implementation. An absent final
/// Memory row intentionally maps to the object-level `NOT_FOUND` result.
///
/// ADR-0067 D-H / D-J2: `include_history` (memory.get) also admits the exact version asked for when it is
/// `superseded`; archived rows are always admitted here (ADR-0024 D-C); every other gate conjunct is unchanged.
pub(crate) async fn materialize_one_memory_in_txn(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    authorization: &AuthorizationScope,
    expected_family: &StreamFamily,
    validated_key: &StreamKey,
    memory_id: MemoryId,
    include_history: bool,
) -> Result<MaterializedBodies, ErrorCode> {
    let bodies = materialize_final_bodies_gated_in_txn(
        txn,
        authorization,
        expected_family,
        validated_key,
        &[memory_id.0],
        &[],
        Lifecycle::for_get(include_history),
        &[],
        None,
    )
    .await?;
    match bodies.items.as_slice() {
        [] => return Err(ErrorCode::NotFound),
        [
            MaterializedItem::Memory {
                memory_id: actual, ..
            },
        ] if *actual == memory_id.0 => {}
        _ => return Err(ErrorCode::Internal),
    }
    Ok(bodies)
}

/// Materializes final bodies through a caller-owned repeatable-read transaction, current versions only
/// ([`Lifecycle::CURRENT`]).
///
/// The trusted StreamFamily and complete StreamKey are revalidated before any
/// query. Callers establish repeatable-read before their first query; authorized manifest
/// creation may use read-write mode without changing the final body policy.
pub(crate) async fn materialize_final_bodies_in_txn(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    authorization: &AuthorizationScope,
    expected_family: &StreamFamily,
    validated_key: &StreamKey,
    memory_ids: &[Uuid],
    overlay: &[OverlayCandidate],
) -> Result<MaterializedBodies, ErrorCode> {
    materialize_final_bodies_about_in_txn(
        txn,
        authorization,
        expected_family,
        validated_key,
        memory_ids,
        overlay,
        &[],
        None,
    )
    .await
}

/// ADR-0067 D-J2: the `memory.enumerate` page bodies under the request's [`Lifecycle`] (no overlay, no subject or
/// affect re-check — the manifest predicate already carried those axes).
pub(crate) async fn materialize_selected_bodies_in_txn(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    authorization: &AuthorizationScope,
    expected_family: &StreamFamily,
    validated_key: &StreamKey,
    memory_ids: &[Uuid],
    lifecycle: Lifecycle,
) -> Result<MaterializedBodies, ErrorCode> {
    materialize_final_bodies_gated_in_txn(
        txn,
        authorization,
        expected_family,
        validated_key,
        memory_ids,
        &[],
        lifecycle,
        &[],
        None,
    )
    .await
}

/// [`materialize_final_bodies_in_txn`] with the §6.1.3 / ADR-0029 D-A subject any-of re-check
/// applied at the shared final-eligibility gate — to the candidate memories, to the memories an
/// overlay item links, and to the overlay Evidence items themselves (via
/// `private.evidence_subjects` in [`load_overlay`]): a not-yet-projected write about someone
/// else never rides in on the RYW overlay, neither as a linked memory nor as raw
/// `temporary_evidence`.
///
/// §8.5.1 / ADR-0030 D-D: with an `affect` filter the overlay's raw Evidence items are dropped
/// too — an Evidence has no affect rows (affects hang on memories), so it can never satisfy the
/// filter; the memories it links still enter the candidate set and pass the same gate.
///
/// Recall's face of the gate: always [`Lifecycle::CURRENT`] (Q3/ADR-0024 D-C, ADR-0067 D-J2).
#[allow(clippy::too_many_arguments)] // One gate, two more axes (subject, affect).
pub(crate) async fn materialize_final_bodies_about_in_txn(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    authorization: &AuthorizationScope,
    expected_family: &StreamFamily,
    validated_key: &StreamKey,
    memory_ids: &[Uuid],
    overlay: &[OverlayCandidate],
    subject_ids: &[SubjectId],
    affect: Option<&AffectFilter>,
) -> Result<MaterializedBodies, ErrorCode> {
    materialize_final_bodies_gated_in_txn(
        txn,
        authorization,
        expected_family,
        validated_key,
        memory_ids,
        overlay,
        Lifecycle::CURRENT,
        subject_ids,
        affect,
    )
    .await
}

/// The one body of every final-body read, with the ADR-0067 D-J2 [`Lifecycle`] of the shared gate.
#[allow(clippy::too_many_arguments)] // the gate's axes, one call per read route
async fn materialize_final_bodies_gated_in_txn(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    authorization: &AuthorizationScope,
    expected_family: &StreamFamily,
    validated_key: &StreamKey,
    memory_ids: &[Uuid],
    overlay: &[OverlayCandidate],
    lifecycle: Lifecycle,
    subject_ids: &[SubjectId],
    affect: Option<&AffectFilter>,
) -> Result<MaterializedBodies, ErrorCode> {
    let authorization = effective_authorization(authorization, expected_family, validated_key)?;
    set_authorization_local(txn, &authorization).await?;
    let mut overlay =
        load_overlay(txn, &authorization, validated_key, overlay, subject_ids).await?;
    let candidate_ids = dedup(
        memory_ids.iter().copied().chain(
            overlay
                .iter()
                .flat_map(|item| item.linked_memory_ids.iter().copied()),
        ),
    );
    let memories = load_memories(
        txn,
        &authorization,
        &candidate_ids,
        lifecycle,
        subject_ids,
        affect,
    )
    .await?;
    if affect.is_some() {
        overlay.clear();
    }
    let readable_memory_ids = memories.iter().map(|(id, _)| *id).collect::<HashSet<_>>();
    for item in &mut overlay {
        item.linked_memory_ids
            .retain(|id| readable_memory_ids.contains(id));
    }
    let mut items = memories
        .into_iter()
        .map(|(memory_id, content)| MaterializedItem::Memory { memory_id, content })
        .collect::<Vec<_>>();
    for item in overlay {
        let RecheckedOverlay {
            evidence_id,
            stream_seq,
            processing_state,
            evidence_kind,
            payload,
            linked_memory_ids,
        } = item;
        match (evidence_kind.as_str(), payload) {
            ("EVENT", Some(payload)) => items.push(MaterializedItem::TemporaryEvidence {
                evidence_id,
                stream_seq,
                processing_state,
                payload,
                linked_memory_ids,
            }),
            ("EVENT", None) => return Err(ErrorCode::Internal),
            (_, _) => items.push(MaterializedItem::ArtifactUnavailable {
                evidence_id,
                stream_seq,
                processing_state,
                linked_memory_ids,
            }),
        }
    }
    let snapshot = snapshot(txn).await?;
    Ok(MaterializedBodies { snapshot, items })
}

/// ADR-0067 D-D / D-J: `memory_id → note_kind` and `memory_id → note_id` for the notes among `ids`, under the
/// transaction's RLS. A non-note Memory (`note_kind IS NULL`) has no entry; a value outside [`NoteKind`] is the 0235
/// CHECK drifting, so `Internal`.
pub(crate) async fn memory_note_kinds_in_txn(
    txn: &mut Txn<'_>,
    tenant_id: Uuid,
    ids: &[Uuid],
) -> Result<(HashMap<Uuid, NoteKind>, HashMap<Uuid, Uuid>), ErrorCode> {
    let mut kinds = HashMap::new();
    let mut note_ids = HashMap::new();
    if ids.is_empty() {
        return Ok((kinds, note_ids));
    }
    let rows = sqlx::query(
        "SELECT memory_id, note_kind, note_id FROM private.memory_records \
         WHERE tenant_id = $1 AND memory_id = ANY($2) AND note_kind IS NOT NULL",
    )
    .bind(tenant_id)
    .bind(ids)
    .fetch_all(&mut **txn)
    .await
    .map_err(|_| ErrorCode::DependencyUnavailable)?;
    for row in &rows {
        let memory_id: Uuid = row.try_get("memory_id").map_err(|_| ErrorCode::Internal)?;
        let wire: String = row.try_get("note_kind").map_err(|_| ErrorCode::Internal)?;
        let note_id: Uuid = row.try_get("note_id").map_err(|_| ErrorCode::Internal)?;
        kinds.insert(
            memory_id,
            NoteKind::parse_wire(&wire).ok_or(ErrorCode::Internal)?,
        );
        note_ids.insert(memory_id, note_id);
    }
    Ok((kinds, note_ids))
}

/// ADR-0067 D-J2: `memory_id → "active" | "superseded"` and the archived ids among `ids`, under the transaction's RLS —
/// the per-item lifecycle a `memory.enumerate` page reports. A status outside the two (L-6) is a gate bypass, so
/// `Internal`.
pub(crate) async fn memory_versions_in_txn(
    txn: &mut Txn<'_>,
    tenant_id: Uuid,
    ids: &[Uuid],
) -> Result<(HashMap<Uuid, &'static str>, HashSet<Uuid>), ErrorCode> {
    let mut statuses = HashMap::new();
    let mut archived = HashSet::new();
    if ids.is_empty() {
        return Ok((statuses, archived));
    }
    let rows = sqlx::query(
        "SELECT memory_id, status, archived_at IS NOT NULL AS archived FROM private.memory_records \
         WHERE tenant_id = $1 AND memory_id = ANY($2)",
    )
    .bind(tenant_id)
    .bind(ids)
    .fetch_all(&mut **txn)
    .await
    .map_err(|_| ErrorCode::DependencyUnavailable)?;
    for row in &rows {
        let memory_id: Uuid = row.try_get("memory_id").map_err(|_| ErrorCode::Internal)?;
        let status: String = row.try_get("status").map_err(|_| ErrorCode::Internal)?;
        let status = match status.as_str() {
            "active" => "active",
            "superseded" => "superseded",
            _ => return Err(ErrorCode::Internal),
        };
        statuses.insert(memory_id, status);
        if row
            .try_get::<bool, _>("archived")
            .map_err(|_| ErrorCode::Internal)?
        {
            archived.insert(memory_id);
        }
    }
    Ok((statuses, archived))
}

/// ADR-0067 D-H: `derivation_strategy` of a Memory with no identity contract. Every such Memory reaches the store
/// through the semantic path whose §16.1 processor kind is `distill_reasoner::DISTILL_PROCESSOR_KIND`.
const NON_NOTE_DERIVATION: &str = "distill";

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

/// Reads [`MemoryHistory`] for a Memory the final gate already admitted in this RR snapshot, under the caller's RLS
/// (installed by that gate), so a missing row is an invariant break (`Internal`), never an existence oracle.
pub(crate) async fn memory_history_in_txn(
    txn: &mut Txn<'_>,
    authorization: &AuthorizationScope,
    memory_id: MemoryId,
) -> Result<MemoryHistory, ErrorCode> {
    let row = sqlx::query(
        r#"
        SELECT m.status,
               m.superseded_by,
               m.asserted_at,
               m.authority_class,
               eo.evidence_id AS primary_evidence_id,
               eo.origin_class,
               event.event_kind,
               contract.strategy,
               contract.body_sha256
        FROM private.memory_records AS m
        LEFT JOIN LATERAL (
            SELECT me.evidence_id
            FROM private.memory_evidence AS me
            WHERE me.memory_id = m.memory_id
              AND me.role = 'PRIMARY'
            ORDER BY me.ordinal, me.evidence_id
            LIMIT 1
        ) AS primary_link ON true
        LEFT JOIN private.evidence_objects AS eo
          ON eo.evidence_id = primary_link.evidence_id
         AND eo.tenant_id = m.tenant_id
        LEFT JOIN private.events AS event ON event.event_id = eo.evidence_id
        LEFT JOIN private.identity_note_materializations AS contract
          ON contract.tenant_id = m.tenant_id
         AND contract.output_memory_id = m.memory_id
        WHERE m.tenant_id = $1
          AND m.memory_id = $2
        "#,
    )
    .bind(authorization.tenant_id().0)
    .bind(memory_id.0)
    .fetch_optional(&mut **txn)
    .await
    .map_err(|_| ErrorCode::DependencyUnavailable)?
    .ok_or(ErrorCode::Internal)?;
    let status: String = row.try_get("status").map_err(|_| ErrorCode::Internal)?;
    let status = match status.as_str() {
        "active" => "active",
        "superseded" => "superseded",
        _ => return Err(ErrorCode::Internal),
    };
    let successor: Option<Uuid> = row
        .try_get("superseded_by")
        .map_err(|_| ErrorCode::Internal)?;
    // ADR-0067 D-H: a reference the caller may not read is omitted, never named.
    let superseded_by = match successor {
        Some(next) => readable_memory_ids(txn, authorization, &[next])
            .await?
            .contains(&next)
            .then_some(next),
        None => None,
    };
    let strategy: Option<String> = row.try_get("strategy").map_err(|_| ErrorCode::Internal)?;
    Ok(MemoryHistory {
        memory_id: memory_id.0,
        status,
        superseded_by,
        provenance: MemoryProvenance {
            primary_evidence_id: row
                .try_get("primary_evidence_id")
                .map_err(|_| ErrorCode::Internal)?,
            event_kind: row.try_get("event_kind").map_err(|_| ErrorCode::Internal)?,
            origin: row
                .try_get("origin_class")
                .map_err(|_| ErrorCode::Internal)?,
            derivation_strategy: strategy.unwrap_or_else(|| NON_NOTE_DERIVATION.to_owned()),
            asserted_at: row
                .try_get("asserted_at")
                .map_err(|_| ErrorCode::Internal)?,
            authority_class: row
                .try_get("authority_class")
                .map_err(|_| ErrorCode::Internal)?,
            body_sha256: row
                .try_get("body_sha256")
                .map_err(|_| ErrorCode::Internal)?,
        },
    })
}
