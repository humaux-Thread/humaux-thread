//! `adapters::cost_repo` — the producer cost door, inside the caller's transaction (§19).
//! Depends-on: crates=[humaux-domain, sqlx]; services=[PostgreSQL(any) w=[ops.tenant_cost_events]]; env=[]; modules=[adapters::provisioning, domain::error]
//! Called-by: [tests]
//! Invariants: [missing periods are refused before SQL; tenant binding is transaction-local; no commit here]
//! Spec: Baseline §19; §52; §78.2; M04 D11

use humaux_domain::error::ErrorCode;
use sqlx::types::{Uuid, time::Date};

/// §19 Tenant Full Cost Ledger's closed producer vocabulary; the DB remains free text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CostKind {
    /// §19 storage byte-hours.
    StorageByteHours,
    /// §19 artifact GB-month.
    ArtifactGbMonth,
    /// §19 vector points / vector storage.
    VectorStorage,
    /// §19 DB rows/storage class.
    DbStorage,
    /// §19 network egress.
    NetworkEgress,
    /// §19 parser pages.
    ParserPages,
    /// §19 worker compute units.
    WorkerComputeUnits,
    /// §19 email sends.
    EmailSends,
    /// §19 external model tokens.
    ExternalModelTokens,
}

impl CostKind {
    /// §78.2: every producer kind, in §19 order.
    pub const ALL: [Self; 9] = [
        Self::StorageByteHours,
        Self::ArtifactGbMonth,
        Self::VectorStorage,
        Self::DbStorage,
        Self::NetworkEgress,
        Self::ParserPages,
        Self::WorkerComputeUnits,
        Self::EmailSends,
        Self::ExternalModelTokens,
    ];

    /// §19: wire names retain the specification's spelling verbatim.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StorageByteHours => "storage byte-hours",
            Self::ArtifactGbMonth => "artifact GB-month",
            Self::VectorStorage => "vector points / vector storage",
            Self::DbStorage => "DB rows/storage class",
            Self::NetworkEgress => "network egress",
            Self::ParserPages => "parser pages",
            Self::WorkerComputeUnits => "worker compute units",
            Self::EmailSends => "email sends",
            Self::ExternalModelTokens => "external model tokens",
        }
    }
}

/// §19: producer-supplied quantities and USD estimates; prices are never computed here.
pub struct CostEvent {
    /// Tenant whose cost is bound to the transaction (§6.1).
    pub tenant_id: Uuid,
    /// §19 closed producer kind.
    pub cost_kind: CostKind,
    /// Finite nonnegative measured quantity (§19).
    pub quantity: f64,
    /// Nonempty measurement unit (§19).
    pub unit: String,
    /// Optional finite nonnegative USD unit estimate (§19).
    pub estimated_unit_cost: Option<f64>,
    /// Finite nonnegative USD total estimate (§19).
    pub estimated_cost: f64,
    /// Producer provenance (§19).
    pub source: String,
    /// Explicit month start; absence is refused before SQL (M04 D11).
    pub period: Option<Date>,
}

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
    sqlx::query("INSERT INTO ops.tenant_cost_events \
        (tenant_id, cost_type, quantity, unit, estimated_unit_cost, estimated_cost, source, period) \
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
        .bind(event.tenant_id).bind(event.cost_kind.as_str()).bind(event.quantity)
        .bind(event.unit).bind(event.estimated_unit_cost).bind(event.estimated_cost)
        .bind(event.source).bind(period).execute(&mut **txn)
        .await.map_err(|_| ErrorCode::DependencyUnavailable)?;
    Ok(())
}

fn nonnegative(value: f64) -> bool {
    value.is_finite() && value >= 0.0
}
