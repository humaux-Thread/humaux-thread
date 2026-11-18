//! `public-worker::bootstrap` — Compose the outbound public projection adapter.
//! Depends-on: crates=[humaux-infra-cell, humaux-public-pool]; services=[]; env=[]; modules=[infra-cell::permit, infra-cell::transport, public-pool::public_projection]
//! Called-by: [public-worker::main]
//! Invariants: [the caller supplies the authorized transport and resource permit]
//! Spec: ADR-0130 D2

use humaux_infra_cell::{CellAccessPermit, IntraCellHttpTransport};
use humaux_public_pool::public_projection::PublicProjectionAdapter;

/// Construct the same-cell projection adapter before opening the worker database pool.
pub(crate) fn projection<'a>(
    transport: &'a dyn IntraCellHttpTransport,
    permit: &'a CellAccessPermit,
    collection: &'a str,
) -> Result<PublicProjectionAdapter<'a>, impl std::error::Error> {
    PublicProjectionAdapter::new(transport, permit, collection)
}
