//! `adapters::cost_repo` — the producer cost door, inside the caller's transaction (§19).
//! Depends-on: crates=[humaux-domain, sqlx]; services=[]; env=[]; modules=[adapters::provisioning, adapters::tenant_cost_write_repo, domain::error]
//! Called-by: [tests]
//! Invariants: [missing periods are refused before SQL; tenant binding is transaction-local; no commit here]
//! Spec: Baseline §19; §52; §78.2; M04 D11

pub use crate::tenant_cost_write_repo::{CostEvent, CostKind};
use humaux_domain::error::ErrorCode;

/// §19 / M04 D11: records one cost without committing the producer's business transaction.
pub async fn record_in_txn(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    event: CostEvent,
) -> Result<(), ErrorCode> {
    let period = event.period.ok_or(ErrorCode::InvalidInput)?;
    if period.day() != 1
        || !nonnegative(event.quantity)
        || !nonnegative(event.estimated_cost)
        || event
            .estimated_unit_cost
            .is_some_and(|cost| !nonnegative(cost))
        || event.unit.trim().is_empty()
    {
        return Err(ErrorCode::InvalidInput);
    }
    crate::provisioning::set_tenant(txn, event.tenant_id)
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    crate::tenant_cost_write_repo::record_cost_in_txn(txn, event, period)
        .await
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    Ok(())
}

fn nonnegative(value: f64) -> bool {
    value.is_finite() && value >= 0.0
}
