//! `adapters::read_materialize` — Final PostgreSQL body materialization after authorization and token-ledger
//!   validation.
//! Depends-on: crates=[async-trait, humaux-application, humaux-domain, humaux-projection, humaux-retrieval, serde_json, sha2, sqlx, time]; services=[PostgreSQL(role_gateway) r=[ops.outbox, private.events, private.evidence_objects, private.evidence_subjects, private.identity_note_materializations, private.memory_evidence, private.memory_records, private.memory_subjects, private.note_heads, private.memory_text_v, projection.stream_log]]; env=[]; modules=[adapters::context_repo, adapters::postgres, adapters::read_gate, adapters::retrieve, adapters::selection_repo, adapters::stream_repo, application::recall_read, domain::affect, domain::authority, domain::error, domain::identity, domain::ids, domain::memory, domain::note, domain::selection, domain::subject, projection::serving, projection::stream, retrieval::completeness, retrieval::envelope, retrieval::signals]
//! Called-by: [adapters::affect_repo, adapters::context_repo, adapters::continuity_read, adapters::exact_census, adapters::grep_repo, adapters::operation_receipt, adapters::retrieve, tests]
//! Invariants: [read-only on role_gateway under RLS; an invisible or unknown source is NotFound/Forbidden, never
//!   partially materialized; a PG error is DependencyUnavailable; the recall/context entry points take no
//!   [`Lifecycle`] and always run [`Lifecycle::CURRENT`] (ADR-0067 D-J2)]
//! Spec: §9; §21.5; §23.3; ADR-0067 D-J2; ADR-0111 D-A/D-C/D-D

use std::collections::{HashMap, HashSet};

use humaux_domain::affect::AffectFilter;
use humaux_domain::authority::MemoryId;
use humaux_domain::error::ErrorCode;
use humaux_domain::identity::AuthorizationScope;
use humaux_domain::ids::WorkspaceId;
use humaux_domain::memory::MemoryType;
use humaux_domain::note::NoteKind;
use humaux_domain::subject::SubjectId;
use humaux_projection::serving::StreamFamily;
use humaux_projection::stream::StreamKey;
use humaux_retrieval::{completeness::FreshnessClass, signals::compute_freshness};
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::types::Uuid;
use sqlx::types::time::OffsetDateTime;

use crate::context_repo::{set_authorization_local, visibility_from_row};
use crate::postgres::RuntimeDbPool;
use crate::read_gate::{readable_memory_ids, visibility_readable};
use crate::retrieve::OverlayCandidate;

type Txn<'c> = sqlx::Transaction<'c, sqlx::Postgres>;

/// Re-checks the candidate IDs against the affect source in the caller's authorization snapshot.
pub type AffectMatchReadPort = for<'a, 'tx> fn(
    &'a mut Txn<'tx>,
    Uuid,
    &'a [Uuid],
    &'a AffectFilter,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<HashSet<Uuid>, sqlx::Error>> + Send + 'a>,
>;

type AffectRead<'a> = (&'a AffectFilter, AffectMatchReadPort);

use humaux_application::recall_read::{
    ItemFreshness, MaterializationSnapshot, MaterializedBodies, MaterializedItem,
};

fn item_freshness(row: &sqlx::postgres::PgRow) -> Result<ItemFreshness, ErrorCode> {
    let kind: String = row
        .try_get("memory_type")
        .map_err(|_| ErrorCode::Internal)?;
    let kind = MemoryType::parse_wire(&kind).ok_or(ErrorCode::Internal)?;
    let evidence: Option<OffsetDateTime> = row
        .try_get("latest_evidence_at")
        .map_err(|_| ErrorCode::Internal)?;
    let now: OffsetDateTime = row
        .try_get("freshness_now")
        .map_err(|_| ErrorCode::Internal)?;
    let signal = compute_freshness(kind, evidence.map(Into::into), now.into(), None, None);
    Ok(ItemFreshness {
        class: signal.class,
        policy_id: Some(signal.policy_id),
        policy_version: Some(signal.policy_version),
        latest_evidence_at: evidence
            .map(|at| {
                at.format(&time::format_description::well_known::Rfc3339)
                    .map_err(|_| ErrorCode::Internal)
            })
            .transpose()?,
        state_age_seconds: signal.state_age_seconds,
    })
}

// §21.5 / ADR-0111 D-C: non-Memory items have no per-MemoryType policy.
fn overlay_freshness(row: &sqlx::postgres::PgRow) -> Result<ItemFreshness, ErrorCode> {
    let evidence: Option<OffsetDateTime> = row
        .try_get("occurred_at")
        .map_err(|_| ErrorCode::Internal)?;
    let now: OffsetDateTime = row
        .try_get("freshness_now")
        .map_err(|_| ErrorCode::Internal)?;
    Ok(ItemFreshness {
        class: FreshnessClass::Unknown,
        policy_id: None,
        policy_version: None,
        latest_evidence_at: evidence
            .map(|at| {
                at.format(&time::format_description::well_known::Rfc3339)
                    .map_err(|_| ErrorCode::Internal)
            })
            .transpose()?,
        state_age_seconds: evidence.and_then(|at| u64::try_from((now - at).whole_seconds()).ok()),
    })
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

/// The selection as one SQL conjunct over `alias`, with the statuses bound at `$first` and the archive mode at
/// `$first + 1` ([`Self::status_wires`], [`Self::archive_wire`]). `alias` is server-owned text, never input.
pub(crate) fn lifecycle_sql(alias: &str, first: u8) -> String {
    LIFECYCLE_SQL
        .replace("{t}", alias)
        .replace("{s}", &first.to_string())
        .replace("{a}", &(first + 1).to_string())
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
    affect: Option<AffectRead<'_>>,
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
    affect: Option<AffectRead<'_>>,
) -> Result<(Vec<Uuid>, GateReadable), ErrorCode> {
    let readable = readable_memory_ids(txn, authorization, candidates).await?;
    let subject_filter: Option<Vec<Uuid>> =
        (!subject_ids.is_empty()).then(|| subject_ids.iter().map(|s| s.0).collect());
    // $1 tenant, $2 candidates, $3 subject filter, $4/$5 the ADR-0067 D-J2 lifecycle (statuses, archive mode).
    let sql = format!(
        r#"
        SELECT m.memory_id
        FROM private.memory_records AS m
        WHERE m.tenant_id = $1
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
        lifecycle = lifecycle_sql("m", 4),
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
    if let Some((filter, read_matching)) = affect {
        let matching = read_matching(txn, authorization.tenant_id().0, &survivors, filter)
            .await
            .map_err(|_| ErrorCode::DependencyUnavailable)?;
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
    affect: Option<AffectRead<'_>>,
) -> Result<Vec<(Uuid, serde_json::Value, ItemFreshness)>, ErrorCode> {
    let eligible = final_memory_ids_about_in_txn(
        txn,
        authorization,
        candidates,
        lifecycle,
        subject_ids,
        affect,
    )
    .await?;
    // ADR-0085 D-A (M07 D1): the two text keys are resolved by `private.memory_text_v`, the one place a Memory's text
    // is resolved; every other key stays the row's own. A non-object `content` (the `memory.correct` bare-string
    // shape) has no text keys to replace and is returned unchanged; the view resolves none for it either.
    let rows = sqlx::query(
        r#"
        SELECT m.memory_id, m.content, mt.title, mt.body, m.memory_type,
               backing.latest_evidence_at, CURRENT_TIMESTAMP AS freshness_now
        FROM private.memory_records AS m
        LEFT JOIN private.memory_text_v AS mt
          ON mt.tenant_id = m.tenant_id
         AND mt.memory_id = m.memory_id
        -- §9 / ADR-0111: bounded by returned ids; missing Evidence time remains unknown.
        LEFT JOIN LATERAL (
            SELECT max(source.occurred_at) AS latest_evidence_at
            FROM private.memory_evidence AS me
            JOIN private.evidence_objects AS source
              ON source.evidence_id = me.evidence_id AND source.tenant_id = m.tenant_id
            WHERE me.memory_id = m.memory_id
        ) AS backing ON true
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
        let mut content: serde_json::Value =
            row.try_get("content").map_err(|_| ErrorCode::Internal)?;
        let title: Option<String> = row.try_get("title").map_err(|_| ErrorCode::Internal)?;
        let body: Option<String> = row.try_get("body").map_err(|_| ErrorCode::Internal)?;
        if let Some(object) = content.as_object_mut() {
            // No fallback to the row's own keys (ADR-0085 D-A): a NULL from the view means no text, so the key is
            // absent rather than the base column resurfacing.
            match title {
                Some(title) => {
                    object.insert("title".to_owned(), serde_json::Value::String(title));
                }
                None => {
                    object.remove("title");
                }
            }
            match body {
                Some(body) => {
                    object.insert("key_claim".to_owned(), serde_json::Value::String(body));
                }
                None => {
                    object.remove("key_claim");
                }
            }
        }
        values.insert(memory_id, (content, item_freshness(&row)?));
    }
    eligible
        .into_iter()
        .map(|id| {
            values
                .remove(&id)
                .map(|(content, freshness)| (id, content, freshness))
                .ok_or(ErrorCode::Internal)
        })
        .collect::<Result<_, _>>()
}

struct RecheckedOverlay {
    freshness: ItemFreshness,
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
               CASE WHEN eo.evidence_kind = 'EVENT' THEN eo.occurred_at END AS occurred_at,
               CURRENT_TIMESTAMP AS freshness_now,
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
        if !visibility_readable(authorization, &visibility) {
            continue;
        }
        let state: String = row.try_get("state").map_err(|_| ErrorCode::Internal)?;
        out.push(RecheckedOverlay {
            freshness: overlay_freshness(&row)?,
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
    affect: Option<AffectRead<'_>>,
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
    affect: Option<AffectRead<'_>>,
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
    let readable_memory_ids = memories
        .iter()
        .map(|(id, _, _)| *id)
        .collect::<HashSet<_>>();
    for item in &mut overlay {
        item.linked_memory_ids
            .retain(|id| readable_memory_ids.contains(id));
    }
    let mut freshness: HashMap<_, _> = memories
        .iter()
        .map(|(id, _, reading)| (*id, reading.clone()))
        .collect();
    let mut items = memories
        .into_iter()
        .map(|(memory_id, content, _)| MaterializedItem::Memory { memory_id, content })
        .collect::<Vec<_>>();
    for item in overlay {
        let RecheckedOverlay {
            freshness: reading,
            evidence_id,
            stream_seq,
            processing_state,
            evidence_kind,
            payload,
            linked_memory_ids,
        } = item;
        freshness.insert(evidence_id, reading);
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
    Ok(MaterializedBodies {
        snapshot,
        items,
        freshness,
    })
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

use crate::context_repo::{
    EnumerationFilter, body_ids, canonical_scope, continuation_bound, frozen_census_in_txn,
    grounding_from_facts, materialized_identity, mint_segment_in_txn,
    stream_pipeline_counts_in_txn,
};

use crate::selection_repo::fetch_authorized_snapshot_page_in_txn;
use crate::stream_repo::{Frontier, close_ledger_in_txn, ledger_frontier_in_txn};

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
        lifecycle = lifecycle_sql("m", 3),
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
    Ok(GroundingBlock::tally([grounding.read_view()]))
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

/// Everything one `memory.get` snapshot reads except its projection-side reading: the body, grounding, subject links,
/// note identity and history that [`begin_get_snapshot`] reads under one RR transaction. The reading itself is the one
/// thing the two doors differ in, so it is attached last by [`GetRead::with_reading`].
struct GetRead {
    bodies: MaterializedBodies,
    grounding: GroundingBlock,
    subjects: HashMap<Uuid, Vec<Uuid>>,
    archived: bool,
    note_kinds: HashMap<Uuid, NoteKind>,
    note_ids: HashMap<Uuid, Uuid>,
    history: Option<MemoryHistory>,
}

impl GetRead {
    /// The finished [`MaterializedMemory`], carrying the reading taken in the same transaction. The enumerate-only
    /// fields are empty: a get names its one item, it does not page (ADR-0067 D-J2).
    fn with_reading<L>(self, ledger: L) -> MaterializedMemory<L> {
        MaterializedMemory {
            bodies: self.bodies,
            ledger,
            grounding: self.grounding,
            subjects: self.subjects,
            archived: self.archived,
            archived_ids: HashSet::new(),
            statuses: HashMap::new(),
            note_kinds: self.note_kinds,
            note_ids: self.note_ids,
            history: self.history,
        }
    }
}

/// Opens the RR READ ONLY snapshot of one `memory.get` and reads everything but the projection side. The transaction
/// is handed back uncommitted so the caller reads its reading in the same snapshot.
async fn begin_get_snapshot(
    pool: &RuntimeDbPool,
    authorization: &AuthorizationScope,
    scope: &Scope,
    expected_family: &StreamFamily,
    validated_key: &StreamKey,
    target: MemoryGetTarget,
    include_history: bool,
) -> Result<(Txn<'static>, GetRead), ErrorCode> {
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
    let read = GetRead {
        bodies,
        grounding,
        subjects,
        archived,
        note_kinds,
        note_ids,
        history,
    };
    Ok((txn, read))
}

/// [`materialize_memory_get_versioned`] for either [`MemoryGetTarget`], reading the stream ledger closure: O(stream)
/// in `projection.stream_point_ledger` and `stream_log`. `memory.get` no longer calls it (ADR-0110 D-A:
/// [`materialize_memory_get_frontier_target`]); it stays for the closure-reading callers and their tests. A note
/// resolves to its head in the same RR snapshot, then runs exactly the version read: a head that fails the final gate
/// (forgotten, tombstoned, revoked, invisible) is `NOT_FOUND`, never an older version. `include_history` with a note
/// targets the head.
async fn materialize_memory_get_target_snapshot(
    pool: &RuntimeDbPool,
    authorization: &AuthorizationScope,
    scope: &Scope,
    expected_family: &StreamFamily,
    validated_key: &StreamKey,
    target: MemoryGetTarget,
    include_history: bool,
) -> Result<MaterializedMemory, ErrorCode> {
    let (mut txn, read) = begin_get_snapshot(
        pool,
        authorization,
        scope,
        expected_family,
        validated_key,
        target,
        include_history,
    )
    .await?;
    let ledger = close_ledger_in_txn(&mut txn, validated_key, authorization)
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    txn.commit()
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    Ok(read.with_reading(ledger))
}

/// ADR-0110 D-A: the `memory.get` door. Everything [`materialize_memory_get_target`] reads, but the projection side is
/// the stream frontier, one primary-key lookup on `stream_checkpoints` in the same RR snapshot
/// ([`ledger_frontier_in_txn`]): never the closure, `stream_log`, the point ledger or an index count. The PostgreSQL
/// read stays authoritative (§15.5). `None` in `ledger` means the stream has no checkpoint row; callers report that
/// through [`frontier_pipeline_block`], never as a zero frontier (§23.1④).
async fn materialize_memory_get_frontier_target_snapshot(
    pool: &RuntimeDbPool,
    authorization: &AuthorizationScope,
    scope: &Scope,
    expected_family: &StreamFamily,
    validated_key: &StreamKey,
    target: MemoryGetTarget,
    include_history: bool,
) -> Result<MaterializedMemory<Option<Frontier>>, ErrorCode> {
    let (mut txn, read) = begin_get_snapshot(
        pool,
        authorization,
        scope,
        expected_family,
        validated_key,
        target,
        include_history,
    )
    .await?;
    let frontier = ledger_frontier_in_txn(&mut txn, validated_key)
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    txn.commit()
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    Ok(read.with_reading(frontier))
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

/// Materializes an authorization-bound immutable Memory page whose EXACT predicate also carries the ADR-0067 D-G
/// note axes (`notes`), in the manifest SQL, the census and the fingerprint alike.
#[allow(clippy::too_many_lines)] // ADR-0028 D-D: the exact enumeration predicate now carries the subject_id filter inside the same manifest SQL + fingerprint; splitting it would separate the predicate from the completeness classification it must stay honest with.
async fn materialize_memory_enumeration_filtered_snapshot(
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

#[async_trait::async_trait]
impl MemoryGetReadPort for RuntimeDbPool {
    async fn get_target(
        &self,
        request: MaterializeMemoryGetTargetRequest<'_>,
    ) -> Result<MaterializedMemory, ErrorCode> {
        materialize_memory_get_target_snapshot(
            self,
            request.authorization,
            request.scope,
            request.expected_family,
            request.validated_key,
            request.target,
            request.include_history,
        )
        .await
    }
    async fn get_frontier(
        &self,
        request: MaterializeMemoryGetFrontierTargetRequest<'_>,
    ) -> Result<MaterializedMemory<Option<Frontier>>, ErrorCode> {
        materialize_memory_get_frontier_target_snapshot(
            self,
            request.authorization,
            request.scope,
            request.expected_family,
            request.validated_key,
            request.target,
            request.include_history,
        )
        .await
    }
}

#[async_trait::async_trait]
impl MemoryEnumerationReadPort for RuntimeDbPool {
    async fn enumerate_filtered(
        &self,
        request: MaterializeMemoryEnumerationFilteredRequest<'_>,
    ) -> Result<MaterializedMemoryPage, ErrorCode> {
        materialize_memory_enumeration_filtered_snapshot(
            self,
            request.authorization,
            request.scope,
            request.expected_family,
            request.validated_key,
            request.params,
            request.notes,
        )
        .await
    }
}

use humaux_application::recall_read::*;

pub use humaux_application::recall_read::Lifecycle;
use humaux_domain::{
    ids::Scope,
    selection::{AUTHORIZED_MEMORY_ENUMERATION_V1, Cursor, query_fingerprint},
};
use humaux_retrieval::envelope::GroundingBlock;
