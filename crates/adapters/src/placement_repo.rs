//! `adapters::placement_repo` — §17.3 `projection.tenant_placements` access: the gateway's read-only lookup and the
//!   projection worker's point-counter writer (migration 0068).
//! Depends-on: crates=[humaux-domain, sqlx]; services=[PostgreSQL(any) r=[projection.tenant_placements] w=[projection.tenant_placements]]; env=[]; modules=[adapters::postgres, adapters::qdrant, domain::error, domain::ids]
//! Called-by: [adapters::private_projection_registry, adapters::stream_repo, gateway::recall]
//! Invariants: [the gateway read is SELECT-only under role_gateway and a missing row means not indexed yet, never a
//!   fallback to another tenant's placement; the one counter writer moves point_count/bytes_estimate only inside the
//!   caller's binding transaction, only by a delta that caller's own point write produced, and never below zero]
//! Spec: Baseline §6.2.1; §17.3
//!
//! Two callers, two grant shapes. `role_gateway` holds only `SELECT` on this table (§6.2.1 domain
//! default), so the read half exists so `bins/gateway/src/recall.rs` can resolve a tenant's
//! placement per request instead of holding one fixed `TenantPlacementRow` for the life of the
//! process (a single-tenant assumption the previous `SemanticRecallRuntime` shape made): a row's
//! absence means "not indexed yet for this tenant/family", which the caller must treat as
//! `DependencyUnavailable`, never a cross-tenant fallback to somebody else's placement.
//!
//! The write half is [`add_point_counters`], called by `adapters::private_projection_registry`
//! inside the transaction that binds or retires the point being counted. It reads no Qdrant state:
//! the worker's own committed writes are the only evidence §17.3's two bookkeeping columns need, so
//! the projection hot path adds no count scan.

use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row, Transaction};

use humaux_domain::error::ErrorCode;
use humaux_domain::ids::TenantId;

use crate::postgres::RuntimeDbPool;
use crate::qdrant::{PlacementClass, PromotionState, RetrievalFamily, TenantPlacementRow};

/// Looks up the one placement row (migration 0068's primary key is `(tenant_id,
/// projection_family)`) for `tenant_id`/`family`, under the requesting tenant's own RLS
/// binding. `Ok(None)` — not an error — means this tenant has no placement for `family` yet;
/// the caller (`bins/gateway/src/recall.rs`) turns that into `ErrorCode::DependencyUnavailable`
/// rather than inventing or borrowing a placement.
pub async fn tenant_placement(
    pool: &RuntimeDbPool,
    tenant_id: TenantId,
    family: RetrievalFamily,
) -> Result<Option<TenantPlacementRow>, ErrorCode> {
    // `set_config(..., true)` is transaction-local (`is_local = true`): issued outside an
    // explicit transaction it reverts before the next statement runs, so the following SELECT
    // would see `humaux.tenant_id` unset and RLS would deny every row. Both statements must
    // run inside one transaction (mirrors `retrieval_embedding_rpc::set_tenant_local`).
    // dep: PostgreSQL(any) — opens a PostgreSQL transaction
    let mut txn = pool.pool().begin().await.map_err(db_error)?;
    sqlx::query("SELECT set_config('humaux.tenant_id', $1, true)")
        .bind(tenant_id.0.to_string())
        .execute(&mut *txn)
        .await
        .map_err(db_error)?;
    let row = sqlx::query(
        "SELECT tenant_id, projection_family, collection_name, shard_key, placement_class, \
                point_count, bytes_estimate, promotion_state \
         FROM projection.tenant_placements \
         WHERE tenant_id = $1 AND projection_family = $2",
    )
    .bind(tenant_id.0)
    .bind(family.as_db_str())
    .fetch_optional(&mut *txn)
    .await
    .map_err(db_error)?;
    txn.commit().await.map_err(db_error)?;
    row.as_ref().map(from_row).transpose()
}

/// The §17.1 retrieval family every private-memory point belongs to — the one `projection.tenant_placements`
/// row `adapters::private_projection_registry`'s bindings are counted into (migration 0068's
/// `private_memory_v1` CHECK value). Public knowledge and code projection are other families with their own
/// writers; the private registry never moves their counters.
pub(crate) const PRIVATE_PROJECTION_FAMILY: RetrievalFamily = RetrievalFamily::PrivateMemoryV1;

/// The dense-vector bytes one point contributes to §17.3 `bytes_estimate`: the f32 array the worker actually
/// upserts, 4 bytes per dimension. Payload and HNSW bytes are measured by R11-H and deliberately not guessed
/// here (module design M10 D5); this is the one per-point size both a registration and a retirement know
/// without reading Qdrant.
pub(crate) const fn point_vector_bytes(dimension: i64) -> i64 {
    dimension.saturating_mul(4)
}

/// Moves one tenant's §17.3 `point_count`/`bytes_estimate` by the delta one successful point write produced
/// (`+1` per newly bound point, `-1` per binding this transaction retires), inside the caller's already-open
/// transaction. `adapters::private_projection_registry` calls it in the same transaction as the binding row, so a
/// committed counter and a committed binding cannot disagree, and a replayed registration (`AlreadyRegistered`)
/// moves nothing — one point is counted once (§17.3's `point_count` is a placement fact, not a write counter).
///
/// No Qdrant read: the caller's own committed writes are the whole input, which is what keeps the projection hot
/// path free of a collection count scan. The table's blanket tenant RLS policy (0012) admits the row only with
/// `humaux.tenant_id` already set by the caller's authorization context, and `role_retrieval_worker` holds the
/// domain-default `R+W` on `projection.*` (0011) the update needs.
///
/// A counter never goes below zero (clamped, not an error): a promoted or re-onboarded row can be reset under a
/// lease, and these columns are §17.3 bookkeeping — the binding row, never the counter, decides what is served.
///
/// Returns the affected row count; `0` means the tenant has no placement row for `family`. Provisioning creates
/// that row before any ticket (`projection.ensure_tenant_placement`, 0186) and the resident claim joins it, so only
/// a test-shaped caller reaches the no-row case, and it must stay a no-op rather than fail the point write.
// ponytail: the counters are per `(tenant, projection_family)`, not per collection generation; a generation
// switch (M10-3/M10-4) counts a rebuild's new collection into the same row until a per-generation placement row
// exists.
pub(crate) async fn add_point_counters(
    txn: &mut Transaction<'_, Postgres>,
    tenant_id: TenantId,
    family: RetrievalFamily,
    point_delta: i64,
    byte_delta: i64,
) -> Result<u64, sqlx::Error> {
    // dep: PostgreSQL(any) — the caller's transaction, RLS-bound to `tenant_id`
    Ok(sqlx::query(
        "UPDATE projection.tenant_placements \
            SET point_count = GREATEST(point_count + $3, 0), \
                bytes_estimate = GREATEST(bytes_estimate + $4, 0) \
          WHERE tenant_id = $1 AND projection_family = $2",
    )
    .bind(tenant_id.0)
    .bind(family.as_db_str())
    .bind(point_delta)
    .bind(byte_delta)
    .execute(&mut **txn)
    .await?
    .rows_affected())
}

/// The one parser of a `projection.tenant_placements` row shape. `pub(crate)` so
/// `stream_repo::claim_issued` (ADR-0052 D-C) parses the placement columns the claim returns
/// with this same function instead of a second copy of the three enum parsers.
pub(crate) fn from_row(row: &PgRow) -> Result<TenantPlacementRow, ErrorCode> {
    let projection_family: String = row
        .try_get("projection_family")
        .map_err(|_| ErrorCode::Internal)?;
    let placement_class: String = row
        .try_get("placement_class")
        .map_err(|_| ErrorCode::Internal)?;
    let promotion_state: String = row
        .try_get("promotion_state")
        .map_err(|_| ErrorCode::Internal)?;
    Ok(TenantPlacementRow {
        tenant_id: TenantId(row.try_get("tenant_id").map_err(|_| ErrorCode::Internal)?),
        projection_family: parse_family(&projection_family)?,
        collection_name: row
            .try_get("collection_name")
            .map_err(|_| ErrorCode::Internal)?,
        shard_key: row.try_get("shard_key").map_err(|_| ErrorCode::Internal)?,
        placement_class: parse_placement_class(&placement_class)?,
        point_count: row
            .try_get("point_count")
            .map_err(|_| ErrorCode::Internal)?,
        bytes_estimate: row
            .try_get("bytes_estimate")
            .map_err(|_| ErrorCode::Internal)?,
        promotion_state: parse_promotion_state(&promotion_state)?,
    })
}

fn parse_family(value: &str) -> Result<RetrievalFamily, ErrorCode> {
    RetrievalFamily::ALL
        .into_iter()
        .find(|family| family.as_db_str() == value)
        .ok_or(ErrorCode::Internal)
}

fn parse_placement_class(value: &str) -> Result<PlacementClass, ErrorCode> {
    PlacementClass::ALL
        .into_iter()
        .find(|class| class.as_db_str() == value)
        .ok_or(ErrorCode::Internal)
}

fn parse_promotion_state(value: &str) -> Result<PromotionState, ErrorCode> {
    PromotionState::ALL
        .into_iter()
        .find(|state| state.as_db_str() == value)
        .ok_or(ErrorCode::Internal)
}

fn db_error(error: sqlx::Error) -> ErrorCode {
    match error {
        sqlx::Error::RowNotFound => ErrorCode::NotFound,
        sqlx::Error::Database(ref db) => match db.code().as_deref() {
            Some("42501") => ErrorCode::Forbidden,
            Some("23505" | "40001" | "40P01" | "55P03") => ErrorCode::Conflict,
            Some("22023" | "22P02" | "22003" | "23514") => ErrorCode::InvalidInput,
            Some("23503") => ErrorCode::TenantBoundary,
            _ => ErrorCode::Internal,
        },
        _ => ErrorCode::DependencyUnavailable,
    }
}
