//! Commercial owns the two tenant cost INSERT commands (Baseline §19).
//! Depends-on: crates=[sqlx]; services=[PostgreSQL(any) w=[ops.tenant_cost_events]]; env=[]; modules=[]
//! Called-by: [adapters::cost_repo, adapters::model_call_ledger]
//! Invariants: [producers validate their inputs and bind tenant scope on the supplied transaction; no commit here]
//! Spec: Baseline §19; §78.2; M04 D11

use sqlx::{
    Postgres, Transaction,
    types::{Uuid, time::Date},
};

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

/// Writes a validated producer cost inside the tenant-scoped transaction (M04 D11).
pub(crate) async fn record_cost_in_txn(
    txn: &mut Transaction<'_, Postgres>,
    event: CostEvent,
    period: Date,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO ops.tenant_cost_events \
        (tenant_id, cost_type, quantity, unit, estimated_unit_cost, estimated_cost, source, period) \
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
        .bind(event.tenant_id).bind(event.cost_kind.as_str()).bind(event.quantity)
        .bind(event.unit).bind(event.estimated_unit_cost).bind(event.estimated_cost)
        .bind(event.source).bind(period).execute(&mut **txn)
        .await?;
    Ok(())
}

/// Writes the explicit ledger bridge event, retaining its existing §19 cost type and unit.
pub(crate) async fn record_external_model_cost_event(
    txn: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    request_id: Uuid,
    billable_tokens: i64,
    estimated_unit_cost: Option<f64>,
    cost: f64,
    period: Date,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO ops.tenant_cost_events \
           (tenant_id, cost_type, quantity, unit, estimated_unit_cost, estimated_cost, \
            source, period) \
         VALUES ($1, 'external_model_tokens', $2, 'tokens', $3, $4, $5, $6)",
    )
    .bind(tenant_id)
    .bind(billable_tokens as f64)
    .bind(estimated_unit_cost)
    .bind(cost)
    .bind(request_id.to_string())
    .bind(period)
    .execute(&mut **txn)
    .await?;

    Ok(())
}
