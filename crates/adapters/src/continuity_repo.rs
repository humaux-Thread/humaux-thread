//! `adapters::continuity_repo` — Typed role_gateway bindings for Project Continuity registration and facet publication.
//! Depends-on: crates=[humaux-domain, serde_json, sqlx, uuid]; services=[PostgreSQL(any) x=[private.publish_continuity_facet, private.read_continuity_project_storage_v1, private.register_continuity_project]]; env=[]; modules=[adapters::postgres, domain::continuity, domain::error, domain::identity, domain::ids]
//! Called-by: [gateway::continuity, gateway::mcp_application, tests]
//! Invariants: [registration and facet publication go only through the SECURITY DEFINER functions; the slot version a
//!   publication is checked against is the door's own in-transaction read, never a caller value (§25.3.1, ADR-0094
//!   D-C); scalar facets never retry, list facets merge-and-retry at most three times; their SQLSTATEs map to
//!   Conflict/Forbidden/InvalidInput, never a silent retry]
//! Spec: Baseline §25.3.1; §52 D-B; ADR-0094
//!
//! Two paths over one transaction: `GOAL` / `CURRENT_STATE` are strict compare-and-set; the seven list facets are a
//! server-side union merge by item `source_id` (ADR-0094 D-D). A lost compare-and-set never aborts the caller's
//! transaction here — each attempt runs under a savepoint, because a raised SQL error would otherwise poison it.

use crate::postgres::RuntimeDbPool;
use humaux_domain::{
    continuity::{
        ContinuityFacetKind, ContinuityFacetVersionId, ContinuityPublishResult,
        ContinuityPublishState, ProjectId,
    },
    error::{ConflictReason, ErrorCode},
    identity::AuthorizationScope,
    ids::WorkspaceId,
};
use serde_json::Value;
use sqlx::{Row, Transaction};
use std::collections::BTreeMap;
use uuid::Uuid;

const NIL_UUID: Uuid = Uuid::nil();

/// Scalar facets written under the strict slot compare-and-set (ADR-0094 D-B).
const SCALAR_FACETS: [ContinuityFacetKind; 2] =
    [ContinuityFacetKind::Goal, ContinuityFacetKind::CurrentState];

/// List facets written under the union merge with retry (ADR-0094 D-D).
const LIST_FACETS: [ContinuityFacetKind; 7] = [
    ContinuityFacetKind::Decisions,
    ContinuityFacetKind::Rejections,
    ContinuityFacetKind::Constraints,
    ContinuityFacetKind::KnownIssues,
    ContinuityFacetKind::NextActions,
    ContinuityFacetKind::Procedures,
    ContinuityFacetKind::Outcomes,
];

/// ADR-0094 D-D: a list publication re-reads, merges and retries at most three times; the next
/// loss is the caller's `CONFLICT` with [`ConflictReason::FACET_MERGE_RETRY_EXHAUSTED`].
const LIST_MERGE_ATTEMPTS: usize = 3;

/// The canonical body of a list facet is exactly `{"items": [...]}`; this is its only key.
const LIST_ITEMS: &str = "items";

/// Identity key of one list item: the source id the union keys on (ADR-0094 D-D).
const ITEM_SOURCE_ID: &str = "source_id";

/// Longest accepted item `source_id`; a bounded wire key, not a deployment setting.
const ITEM_SOURCE_ID_MAX: usize = 256;

/// Savepoint of one publish attempt, so a lost compare-and-set leaves the caller's transaction usable.
const PUBLISH_SAVEPOINT: &str = "continuity_publish_attempt";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContinuityMemorySource {
    pub memory_id: Uuid,
    pub content_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContinuityEvidenceSource {
    pub evidence_id: Uuid,
    pub payload_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterContinuityProject<'a> {
    pub workspace_id: WorkspaceId,
    pub project_id: ProjectId,
    pub title: &'a str,
}

/// One `continuity.publish` input. The expected slot version is deliberately absent: it is the
/// door's own in-transaction read, never a caller value (ADR-0094 D-C).
#[derive(Debug, Clone)]
pub struct PublishContinuityFacet<'a> {
    pub workspace_id: WorkspaceId,
    pub project_id: ProjectId,
    pub facet_kind: ContinuityFacetKind,
    pub published_state: ContinuityPublishState,
    pub body: &'a Value,
    pub memories: &'a [ContinuityMemorySource],
    pub evidence: &'a [ContinuityEvidenceSource],
    /// `source_id`s dropped after the union; empty for every scalar facet.
    pub removals: &'a [String],
}

/// The outcome of one facet publication. `Conflict` is success-shaped (nothing was written): the
/// caller gets the typed §52 D-B sub-reason and the slot version to merge against, so it can retry
/// without a second error registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishFacetOutcome {
    /// The immutable version, its links and the slot compare-and-swap committed.
    Published(ContinuityPublishResult),
    /// The slot did not hold the version the door read; `current_slot_version` is what it holds now.
    Conflict {
        reason: ConflictReason,
        current_slot_version: i64,
    },
}

/// One slot snapshot read through the 0137 reader (the only runtime read of continuity storage).
#[derive(Debug, Clone, PartialEq)]
struct SlotSnapshot {
    slot_version: i64,
    body: Option<Value>,
}

/// What one savepointed attempt produced.
enum AttemptOutcome {
    Published(ContinuityPublishResult),
    Conflict,
}

async fn install_context(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    scope: &AuthorizationScope,
    workspace_id: WorkspaceId,
) -> Result<(), ErrorCode> {
    let user = scope.user_id().map_or(NIL_UUID, |id| id.0);
    sqlx::query(
        "SELECT set_config('humaux.tenant_id',$1,true),\
                set_config('humaux.workspace_id',$2,true),\
                set_config('humaux.principal_id',$3,true),\
                set_config('humaux.user_id',$4,true)",
    )
    .bind(scope.tenant_id().0.to_string())
    .bind(workspace_id.0.to_string())
    .bind(scope.principal().0.to_string())
    .bind(user.to_string())
    .execute(&mut **tx)
    .await
    .map_err(map_db_error)?;
    Ok(())
}

/// §25.3.1 / 0137: the storage reader authorises a project before it installs a workspace, so it
/// requires the workspace GUC to be nil; `None` restores that state for the slot read.
async fn install_workspace_guc(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    workspace_id: Option<Uuid>,
) -> Result<(), ErrorCode> {
    let value = workspace_id.unwrap_or(NIL_UUID).to_string();
    sqlx::query("SELECT set_config('humaux.workspace_id',$1,true)")
        .bind(value)
        .execute(&mut **tx)
        .await
        .map_err(map_db_error)?;
    Ok(())
}

fn map_db_error(error: sqlx::Error) -> ErrorCode {
    match error.as_database_error().and_then(|db| db.code()) {
        Some(code) if code == "P9C01" => ErrorCode::Conflict,
        Some(code) if code == "P9I01" => ErrorCode::Internal,
        Some(code) if code == "42501" => ErrorCode::Forbidden,
        Some(code) if code.starts_with("22") || code == "23514" || code == "23503" => {
            ErrorCode::InvalidInput
        }
        _ => ErrorCode::Internal,
    }
}

async fn savepoint(tx: &mut Transaction<'_, sqlx::Postgres>) -> Result<(), ErrorCode> {
    let statement = format!("SAVEPOINT {PUBLISH_SAVEPOINT}");
    sqlx::query(&statement)
        .execute(&mut **tx)
        .await
        .map_err(map_db_error)?;
    Ok(())
}

async fn rollback_to_savepoint(tx: &mut Transaction<'_, sqlx::Postgres>) -> Result<(), ErrorCode> {
    let statement = format!("ROLLBACK TO SAVEPOINT {PUBLISH_SAVEPOINT}");
    sqlx::query(&statement)
        .execute(&mut **tx)
        .await
        .map_err(map_db_error)?;
    release_savepoint(tx).await
}

async fn release_savepoint(tx: &mut Transaction<'_, sqlx::Postgres>) -> Result<(), ErrorCode> {
    let statement = format!("RELEASE SAVEPOINT {PUBLISH_SAVEPOINT}");
    sqlx::query(&statement)
        .execute(&mut **tx)
        .await
        .map_err(map_db_error)?;
    Ok(())
}

/// Parses a list-facet body into its items keyed by `source_id`; rejects every shape the merge
/// cannot key on. `{**current, **incoming}` (CLAUDE.md status-merge rule) needs one identity key.
fn parse_list_items(body: &Value) -> Result<BTreeMap<String, Value>, ErrorCode> {
    let object = body.as_object().ok_or(ErrorCode::InvalidInput)?;
    if object.len() != 1 {
        return Err(ErrorCode::InvalidInput);
    }
    let items = object
        .get(LIST_ITEMS)
        .and_then(Value::as_array)
        .ok_or(ErrorCode::InvalidInput)?;
    let mut parsed = BTreeMap::new();
    for item in items {
        if item.as_object().is_none() {
            return Err(ErrorCode::InvalidInput);
        }
        let source_id = item
            .get(ITEM_SOURCE_ID)
            .and_then(Value::as_str)
            .ok_or(ErrorCode::InvalidInput)?;
        if source_id.is_empty() || source_id.chars().count() > ITEM_SOURCE_ID_MAX {
            return Err(ErrorCode::InvalidInput);
        }
        if parsed.insert(source_id.to_string(), item.clone()).is_some() {
            return Err(ErrorCode::InvalidInput);
        }
    }
    Ok(parsed)
}

/// `{**current, **incoming}` for one item: incoming keys win, keys only the stored item carries
/// survive. The identity key is equal on both sides by construction.
fn merge_item(current: &mut Value, incoming: &Value) -> Result<(), ErrorCode> {
    let (Some(current), Some(incoming)) = (current.as_object_mut(), incoming.as_object()) else {
        return Err(ErrorCode::InvalidInput);
    };
    for (key, value) in incoming {
        current.insert(key.clone(), value.clone());
    }
    Ok(())
}

/// The one deterministic list merge (ADR-0094 D-D; CLAUDE.md "状态合并禁止整体替换", never a
/// whole-list replace). Union by item `source_id` — incoming wins per item — then the explicit
/// removals; the result is ordered by `source_id`, so equal sets always have equal bytes and the
/// stored `body_sha256` stays canonical (§25.3.1).
pub fn merge_list_facet(
    current: Option<&Value>,
    incoming: &Value,
    removals: &[String],
) -> Result<Value, ErrorCode> {
    let mut merged = match current {
        Some(body) => parse_list_items(body)?,
        None => BTreeMap::new(),
    };
    for (source_id, item) in parse_list_items(incoming)? {
        match merged.get_mut(&source_id) {
            Some(existing) => merge_item(existing, &item)?,
            None => {
                merged.insert(source_id, item);
            }
        }
    }
    for source_id in removals {
        merged.remove(source_id);
    }
    let mut body = serde_json::Map::new();
    body.insert(
        LIST_ITEMS.to_string(),
        Value::Array(merged.into_values().collect()),
    );
    Ok(Value::Object(body))
}

/// Reads the slot the publication will be checked against, through the one runtime reader.
async fn read_slot_snapshot(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    authorization: &AuthorizationScope,
    command: &PublishContinuityFacet<'_>,
) -> Result<SlotSnapshot, ErrorCode> {
    let mut workspaces: Vec<Uuid> = authorization
        .allowed_workspace_ids()
        .iter()
        .map(|value| value.0)
        .collect();
    workspaces.sort_unstable();
    let rows = sqlx::query(
        "SELECT facet_kind,slot_version,body_text \
         FROM private.read_continuity_project_storage_v1($1,$2,$3,$4,$5,$6)",
    )
    .bind(authorization.tenant_id().0)
    .bind(command.project_id.0)
    .bind(Some(command.workspace_id.0))
    .bind(authorization.principal().0)
    .bind(authorization.user_id().map(|id| id.0))
    .bind(workspaces)
    .fetch_all(&mut **tx)
    .await
    .map_err(map_db_error)?;
    if rows.is_empty() {
        return Err(ErrorCode::NotFound);
    }
    let Some(row) = rows.iter().find(|row| {
        row.try_get::<Option<String>, _>("facet_kind")
            .is_ok_and(|kind| kind.as_deref() == Some(command.facet_kind.as_str()))
    }) else {
        return Err(ErrorCode::Internal);
    };
    let slot_version: Option<i64> = row
        .try_get("slot_version")
        .map_err(|_| ErrorCode::Internal)?;
    let body_text: Option<String> = row.try_get("body_text").map_err(|_| ErrorCode::Internal)?;
    let slot_version = slot_version.ok_or(ErrorCode::Internal)?;
    let body = match (slot_version, body_text) {
        (0, None) => None,
        (0, Some(_)) => return Err(ErrorCode::Internal),
        (_, None) => return Err(ErrorCode::Internal),
        (_, Some(text)) => Some(serde_json::from_str(&text).map_err(|_| ErrorCode::Internal)?),
    };
    Ok(SlotSnapshot { slot_version, body })
}

async fn call_publish_function(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    authorization: &AuthorizationScope,
    command: &PublishContinuityFacet<'_>,
    expected_slot_version: i64,
    body: &Value,
) -> Result<ContinuityPublishResult, ErrorCode> {
    let user = authorization.user_id().map(|id| id.0);
    let memory_ids: Vec<Uuid> = command
        .memories
        .iter()
        .map(|source| source.memory_id)
        .collect();
    let memory_hashes: Vec<Vec<u8>> = command
        .memories
        .iter()
        .map(|source| source.content_sha256.to_vec())
        .collect();
    let evidence_ids: Vec<Uuid> = command
        .evidence
        .iter()
        .map(|source| source.evidence_id)
        .collect();
    let evidence_hashes: Vec<Vec<u8>> = command
        .evidence
        .iter()
        .map(|source| source.payload_sha256.to_vec())
        .collect();
    let row = sqlx::query(
        "SELECT facet_version_id,facet_version,slot_version,body_sha256 \
         FROM private.publish_continuity_facet(\
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
    )
    .bind(authorization.tenant_id().0)
    .bind(command.workspace_id.0)
    .bind(command.project_id.0)
    .bind(authorization.principal().0)
    .bind(user)
    .bind(command.facet_kind.as_str())
    .bind(expected_slot_version)
    .bind(command.published_state.as_str())
    .bind(body)
    .bind(memory_ids)
    .bind(memory_hashes)
    .bind(evidence_ids)
    .bind(evidence_hashes)
    .fetch_one(&mut **tx)
    .await
    .map_err(map_db_error)?;
    let body_hash: Vec<u8> = row.try_get("body_sha256").map_err(map_db_error)?;
    let body_sha256: [u8; 32] = body_hash.try_into().map_err(|_| ErrorCode::Internal)?;
    Ok(ContinuityPublishResult {
        facet_version_id: ContinuityFacetVersionId(
            row.try_get("facet_version_id").map_err(map_db_error)?,
        ),
        facet_version: row.try_get("facet_version").map_err(map_db_error)?,
        slot_version: row.try_get("slot_version").map_err(map_db_error)?,
        body_sha256,
    })
}

async fn publish_attempt(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    authorization: &AuthorizationScope,
    command: &PublishContinuityFacet<'_>,
    scalar: bool,
) -> Result<AttemptOutcome, ErrorCode> {
    savepoint(tx).await?;
    install_context(tx, authorization, command.workspace_id).await?;
    install_workspace_guc(tx, None).await?;
    let snapshot = read_slot_snapshot(tx, authorization, command).await?;
    install_workspace_guc(tx, Some(command.workspace_id.0)).await?;
    let body = if scalar {
        command.body.clone()
    } else {
        merge_list_facet(snapshot.body.as_ref(), command.body, command.removals)?
    };
    match call_publish_function(tx, authorization, command, snapshot.slot_version, &body).await {
        Ok(result) => {
            release_savepoint(tx).await?;
            Ok(AttemptOutcome::Published(result))
        }
        Err(ErrorCode::Conflict) => {
            rollback_to_savepoint(tx).await?;
            Ok(AttemptOutcome::Conflict)
        }
        Err(error) => Err(error),
    }
}

/// §25.3.1 / ADR-0094 D-A: the only publish door. It runs inside the caller's transaction, so
/// M18's `checkpoint` can publish facets in the same transaction as its hand-off.
pub async fn publish_facets_in_txn(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    authorization: &AuthorizationScope,
    command: &PublishContinuityFacet<'_>,
) -> Result<PublishFacetOutcome, ErrorCode> {
    let narrowed = authorization.narrow(command.workspace_id)?;
    let scalar = SCALAR_FACETS.contains(&command.facet_kind);
    if !scalar && !LIST_FACETS.contains(&command.facet_kind) {
        return Err(ErrorCode::InvalidInput);
    }
    if scalar && !command.removals.is_empty() {
        return Err(ErrorCode::InvalidInput);
    }
    let attempts = if scalar { 1 } else { LIST_MERGE_ATTEMPTS };
    for attempt in 1..=attempts {
        match publish_attempt(tx, &narrowed, command, scalar).await? {
            AttemptOutcome::Published(result) => return Ok(PublishFacetOutcome::Published(result)),
            AttemptOutcome::Conflict if attempt < attempts => {}
            AttemptOutcome::Conflict => {
                install_context(tx, &narrowed, command.workspace_id).await?;
                install_workspace_guc(tx, None).await?;
                let current = read_slot_snapshot(tx, &narrowed, command).await?;
                let reason = if scalar {
                    ConflictReason::FACET_SLOT_VERSION_CONFLICT
                } else {
                    ConflictReason::FACET_MERGE_RETRY_EXHAUSTED
                };
                return Ok(PublishFacetOutcome::Conflict {
                    reason,
                    current_slot_version: current.slot_version,
                });
            }
        }
    }
    // `attempts >= 1`, so the last iteration always returns; a zero attempt budget is a bug.
    Err(ErrorCode::Internal)
}

/// One-call publish: opens the transaction, runs the door and commits a winner. A conflict rolls
/// the transaction back and is returned as [`PublishFacetOutcome::Conflict`], never as a write.
pub async fn publish_facet(
    pool: &RuntimeDbPool,
    authorization: &AuthorizationScope,
    command: &PublishContinuityFacet<'_>,
) -> Result<PublishFacetOutcome, ErrorCode> {
    // dep: PostgreSQL(any) — opens a PostgreSQL transaction
    let mut tx = pool.pool().begin().await.map_err(map_db_error)?;
    let outcome = publish_facets_in_txn(&mut tx, authorization, command).await?;
    match outcome {
        PublishFacetOutcome::Published(result) => {
            tx.commit().await.map_err(map_db_error)?;
            Ok(PublishFacetOutcome::Published(result))
        }
        conflict => {
            tx.rollback().await.map_err(map_db_error)?;
            Ok(conflict)
        }
    }
}

pub async fn register_project(
    pool: &RuntimeDbPool,
    authorization: &AuthorizationScope,
    command: &RegisterContinuityProject<'_>,
) -> Result<ProjectId, ErrorCode> {
    let narrowed = authorization.narrow(command.workspace_id)?;
    // dep: PostgreSQL(any) — opens a PostgreSQL transaction
    let mut tx = pool.pool().begin().await.map_err(map_db_error)?;
    install_context(&mut tx, &narrowed, command.workspace_id).await?;
    let user = narrowed.user_id().map(|id| id.0);
    let row =
        sqlx::query("SELECT private.register_continuity_project($1,$2,$3,$4,$5,$6) AS project_id")
            .bind(narrowed.tenant_id().0)
            .bind(command.workspace_id.0)
            .bind(command.project_id.0)
            .bind(narrowed.principal().0)
            .bind(user)
            .bind(command.title)
            .fetch_one(&mut *tx)
            .await
            .map_err(map_db_error)?;
    let project_id: Uuid = row.try_get("project_id").map_err(map_db_error)?;
    tx.commit().await.map_err(map_db_error)?;
    Ok(ProjectId(project_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn item(source_id: &str, text: &str) -> Value {
        json!({ "source_id": source_id, "text": text })
    }

    fn ids(body: &Value) -> Vec<String> {
        body[LIST_ITEMS]
            .as_array()
            .expect("items array")
            .iter()
            .map(|item| {
                item[ITEM_SOURCE_ID]
                    .as_str()
                    .expect("source_id")
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn scalar_and_list_sets_partition_the_publishable_facets() {
        assert_eq!(SCALAR_FACETS.len(), 2);
        assert_eq!(LIST_FACETS.len(), 7);
        for scalar in SCALAR_FACETS {
            assert!(!LIST_FACETS.contains(&scalar), "{scalar:?} is both paths");
            assert!(ContinuityFacetKind::ALL.contains(&scalar));
        }
        for list in LIST_FACETS {
            assert!(ContinuityFacetKind::ALL.contains(&list));
        }
        let publishable = SCALAR_FACETS
            .len()
            .checked_add(LIST_FACETS.len())
            .expect("census");
        assert_eq!(publishable, 9);
        assert_eq!(ContinuityFacetKind::ALL.len() - publishable, 6);
    }

    #[test]
    fn union_is_the_exact_set_of_both_sides_in_source_id_order() {
        let current = json!({"items": [item("b", "stored"), item("a", "first")]});
        let incoming = json!({"items": [item("d", "new"), item("c", "new")]});
        let merged = merge_list_facet(Some(&current), &incoming, &[]).expect("merge");
        assert_eq!(ids(&merged), vec!["a", "b", "c", "d"]);
        assert_eq!(merged[LIST_ITEMS].as_array().expect("items").len(), 4);
    }

    #[test]
    fn incoming_item_wins_per_key_and_survives_removals() {
        let current = json!({"items": [{"source_id": "a", "text": "old", "kept": 1}]});
        let incoming = json!({"items": [{"source_id": "a", "text": "new"}]});
        let merged = merge_list_facet(Some(&current), &incoming, &[]).expect("merge");
        assert_eq!(
            merged,
            json!({"items": [{"source_id": "a", "text": "new", "kept": 1}]})
        );
        let removed = merge_list_facet(Some(&merged), &json!({"items": []}), &["a".to_string()])
            .expect("drop");
        assert_eq!(removed, json!({"items": []}));
    }

    #[test]
    fn merge_is_order_independent_and_rejects_malformed_bodies() {
        let first = merge_list_facet(
            None,
            &json!({"items": [item("a", "one"), item("b", "two")]}),
            &[],
        )
        .expect("merge");
        let second = merge_list_facet(
            None,
            &json!({"items": [item("b", "two"), item("a", "one")]}),
            &[],
        )
        .expect("merge");
        assert_eq!(first, second);
        for malformed in [
            json!({"items": [{"text": "no id"}]}),
            json!({"items": [item("a", "one"), item("a", "two")]}),
            json!({"items": [{"source_id": "", "text": "empty"}]}),
            json!({"items": "not an array"}),
            json!({"items": [], "extra": true}),
            json!([item("a", "one")]),
        ] {
            assert_eq!(
                merge_list_facet(None, &malformed, &[]),
                Err(ErrorCode::InvalidInput),
                "{malformed} must be rejected"
            );
        }
    }
}
