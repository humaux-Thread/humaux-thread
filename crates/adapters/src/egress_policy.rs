//! `adapters::egress_policy` — tenant retrieval egress opt-in lookup.
//! Depends-on: crates=[humaux-domain, sqlx]; services=[PostgreSQL(role_retrieval_worker) r=[control.egress_policies]]; env=[]; modules=[adapters::postgres, domain::error, domain::ids]
//! Called-by: [retrieval-provider::adapters]
//! Invariants: [missing or false denies; database failure denies; tenant RLS is transaction-local]
//! Spec: Baseline §7.2; migrations/0051_egress_policies.sql

use humaux_domain::{error::ErrorCode, ids::TenantId};

use crate::postgres::RetrievalWorkerDbPool;

/// Checks the requesting tenant's explicit opt-in before any retrieval egress reservation.
///
/// # Errors
/// Returns `Forbidden` for false or missing policy and `DependencyUnavailable` on database errors.
pub async fn authorize_retrieval(
    pool: &RetrievalWorkerDbPool,
    tenant_id: TenantId,
) -> Result<(), ErrorCode> {
    let mut txn = pool
        .pool()
        .begin()
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    sqlx::query("SELECT set_config('humaux.tenant_id', $1, true)")
        .bind(tenant_id.0.to_string())
        .execute(&mut *txn)
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    let allowed: Option<bool> = sqlx::query_scalar(
        "SELECT private_retrieval_external_allowed FROM control.egress_policies WHERE tenant_id = $1",
    )
    .bind(tenant_id.0)
    .fetch_optional(&mut *txn)
    .await
    .map_err(|_| ErrorCode::DependencyUnavailable)?;
    txn.commit()
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    if allowed == Some(true) {
        Ok(())
    } else {
        Err(ErrorCode::Forbidden)
    }
}
