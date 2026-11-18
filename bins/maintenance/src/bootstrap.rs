//! `maintenance::bootstrap` — Constructs the maintenance Qdrant adapter from operator configuration (ADR-0130 D2).
//! Depends-on: crates=[humaux-adapters, humaux-application]; services=[]; env=[HUMAUX_MAINTENANCE_EMBEDDING_DIMENSION, HUMAUX_MAINTENANCE_PRIVATE_MEMORY_COLLECTION, HUMAUX_MAINTENANCE_QDRANT_CIDR,
//!   HUMAUX_MAINTENANCE_QDRANT_HOST, HUMAUX_MAINTENANCE_QDRANT_PORT]; modules=[adapters::postgres, adapters::provisioning, application::operator_provisioning, maintenance::main]
//! Called-by: [maintenance::main]
//! Invariants: [construction only; the application ports drive all operations]
//! Spec: ADR-0053; ADR-0130 D2 / SLICE-15c

use humaux_adapters::postgres::MaintenanceDbPool;
use humaux_adapters::provisioning::{QdrantFace, WorkspaceActivationAdapter};
use humaux_application::operator_provisioning::{
    CollectionProvisioningPort, WorkspaceActivationPort,
};

use crate::{Result, env, env_parsed};

/// The Qdrant face and the collection/dimension every onboarding step uses.
pub(super) struct Qdrant {
    face: QdrantFace,
    pub(super) collection: String,
    pub(super) dimension: u32,
}

pub(super) fn qdrant() -> Result<Qdrant> {
    let face = QdrantFace::new(
        &env("HUMAUX_MAINTENANCE_QDRANT_HOST")?,
        env_parsed("HUMAUX_MAINTENANCE_QDRANT_PORT")?,
        &env("HUMAUX_MAINTENANCE_QDRANT_CIDR")?,
    )?;
    Ok(Qdrant {
        face,
        collection: env("HUMAUX_MAINTENANCE_PRIVATE_MEMORY_COLLECTION")?,
        dimension: env_parsed("HUMAUX_MAINTENANCE_EMBEDDING_DIMENSION")?,
    })
}
impl Qdrant {
    pub(super) fn collection_port(&self) -> &impl CollectionProvisioningPort {
        &self.face
    }

    pub(super) fn activation_port<'a>(
        &'a self,
        pool: &'a MaintenanceDbPool,
    ) -> impl WorkspaceActivationPort + 'a {
        WorkspaceActivationAdapter::new(pool, &self.face)
    }
}
