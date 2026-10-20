//! `adapters::retrieval_query_log` — the one INSERT into `ops.retrieval_query_log` (migration 0258), the query-hash log
//!   `gateway::recall` writes once per answered recall (ADR-0081 D-A, the in-repo part of G-RET-6).
//! Depends-on: crates=[serde_json, sqlx]; services=[PostgreSQL(role_gateway) w=[ops.retrieval_query_log]]; env=[]; modules=[]
//! Called-by: [adapters::retrieve, gateway::recall]
//! Invariants: [role_gateway holds INSERT on the table and nothing else, so this module has no read, update or delete;
//!   the query arrives only as a 32-byte HMAC and the kid of the key behind it, never as text; the transaction the
//!   caller passes has bound humaux.tenant_id (the table's WITH CHECK refuses any other tenant); the INSERT names
//!   neither log_id nor called_at, which the table mints (uuidv7, clock_timestamp)]
//! Spec: Baseline §19.1, §48.1; ADR-0063; ADR-0081 D-A
//!
//! The pool, the tenant binding and the HMAC live in [`crate::retrieve`], next to the installed token-key set, so that
//! key bytes never leave that module and this one stays a pure SQL leaf.

use sqlx::types::Uuid;

/// The counts one answered recall reports, in the units its envelope reports them.
#[derive(Debug, Clone, PartialEq)]
pub struct QueryLogCounts {
    /// The registered profile's candidate depth (`provenance.profile.cand_k`).
    pub cand_k: u32,
    /// Candidates the dense lane returned (`completeness.candidate_count`); never above `cand_k`.
    pub candidates: u32,
    /// §23.1② live visible count; `None` when it could not be established.
    pub visible: Option<u64>,
    /// Items in the answer (`completeness.returned`).
    pub returned: u32,
    /// `provenance.stage_ms` as the answer carried it; `None` when the answer carried none.
    pub stage_ms: Option<serde_json::Value>,
}

/// A count as the table's `integer` column; a value above `i32::MAX` is a protocol error, not a clamp.
fn int(n: impl TryInto<i32>) -> Result<i32, sqlx::Error> {
    n.try_into()
        .map_err(|_| sqlx::Error::Protocol("query log count exceeds i32".to_owned()))
}

/// Inserts one row for an answered recall inside the caller's tenant-bound transaction.
pub async fn insert(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    workspace_id: Uuid,
    user_id: Option<Uuid>,
    query_hmac: &[u8],
    key_id: &str,
    counts: &QueryLogCounts,
) -> Result<(), sqlx::Error> {
    // dep: PostgreSQL(role_gateway) — the query-hash log INSERT (§19.1, ADR-0081 D-A)
    sqlx::query(
        "INSERT INTO ops.retrieval_query_log \
             (tenant_id, workspace_id, user_id, query_hmac, key_id, cand_k, candidates, visible, returned, stage_ms) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(user_id)
    .bind(query_hmac)
    .bind(key_id)
    .bind(int(counts.cand_k)?)
    .bind(int(counts.candidates)?)
    .bind(counts.visible.map(int).transpose()?)
    .bind(int(counts.returned)?)
    .bind(&counts.stage_ms)
    .execute(&mut **txn)
    .await?;
    Ok(())
}
