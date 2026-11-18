//! `billing-worker::process` — assembly for the durable billing inbox use case (§71.3).
//! Depends-on: crates=[humaux-adapters, humaux-application, humaux-domain]; services=[]; env=[]; modules=[adapters::billing_processor_repo, adapters::postgres, application::billing, application::billing_process, billing-worker::normalize, domain::error]
//! Called-by: [tests]
//! Invariants: [maintenance identity; processing policy and persistence live behind application ports]
//! Spec: Baseline §71.3; ADR-0130 D2

use crate::normalize::StoredEnvelope;
use humaux_adapters::{billing_processor_repo, postgres::MaintenanceDbPool};
use humaux_application::{billing::BillingProvider, billing_process};
use humaux_domain::error::ErrorCode;

/// §78.1: caller-provided provider product to plan mapping.
pub use humaux_application::billing_process::ProcessorConfig;

/// §71.3: assemble the inbox adapter and process one verified event.
pub async fn process_one(
    pool: &MaintenanceDbPool,
    provider: &dyn BillingProvider,
    config: &ProcessorConfig,
) -> Result<bool, ErrorCode> {
    billing_process::process_one(
        &billing_processor_repo::processor_inbox(pool, StoredEnvelope),
        provider,
        config,
    )
    .await
}
