//! `application::mechanism_observation` — Read explicit mechanism targets and derive registry status (§1.14).
//! Depends-on: crates=[async-trait, humaux-contracts, humaux-domain, serde_json]; services=[]; env=[]; modules=[contracts::mechanism_registry, domain::error]
//! Called-by: [adapters::mechanism_observation, admin::mechanism]
//! Invariants: [derive status from the actual snapshot; stale and contradictory stored status fail readiness]
//! Spec: §1.14; ADR-0130 D2

use std::collections::BTreeMap;

use humaux_contracts::mechanism_registry::{
    DerivedMechanismStatus, MechanismE2eEvidence, MechanismObservation, MechanismSpec,
    MechanismStatus, ObservationTarget, derive_status,
};
use humaux_domain::error::ErrorCode;
use serde_json::{Value, json};

/// A consistent read of the requested deployment/cell, never of a fallback target.
#[derive(Clone, Debug)]
pub struct RuntimeObservations {
    /// Scope supplied by the caller and included in both database queries.
    pub target: ObservationTarget,
    /// Database clock at the end of the read, in Unix microseconds.
    pub checked_at_micros: i64,
    /// Latest row per canonical mechanism ID, including stale rows.
    pub latest: BTreeMap<String, MechanismObservation>,
    /// Completed runs whose `after` is the selected latest observation.
    pub evidence: BTreeMap<String, MechanismE2eEvidence>,
}

impl RuntimeObservations {
    /// Recompute, rather than trust the stored `derived_status` cache.
    pub fn status(&self, spec: &MechanismSpec) -> DerivedMechanismStatus {
        let id = spec.id();
        derive_status(
            spec,
            &self.target,
            self.latest.get(&id),
            self.evidence.get(&id),
            self.checked_at_micros,
        )
    }

    /// Operational output keeps absence and stale evidence visible and reports the
    /// exact target. This is a registry view, not a §4.4 scalar probe envelope.
    pub fn render_json(&self, specs: &[MechanismSpec]) -> Value {
        json!({"deployment_id": self.target.deployment_id, "cell_id": self.target.cell_id,
            "checked_at_micros": self.checked_at_micros,
            "mechanisms": specs.iter().map(|spec| {
                let derived = self.status(spec);
                json!({"mechanism_id": spec.id(), "status": derived.status.map(MechanismStatus::as_str),
                    "reason": derived.reason, "observation": self.latest.get(&spec.id()),
                    "e2e_run_id": self.evidence.get(&spec.id()).map(|e| &e.run_id)})
            }).collect::<Vec<_>>()})
    }

    /// A stale mechanism cannot establish runtime readiness. A fresh stored cache
    /// contradicting the recomputed result also fails G5 rather than being ignored.
    pub fn cannot_establish(&self, specs: &[MechanismSpec]) -> bool {
        specs.iter().any(|spec| {
            let derived = self.status(spec);
            derived.status == Some(MechanismStatus::Stale)
                || self.latest.get(&spec.id()).is_some_and(|obs| {
                    derived
                        .status
                        .is_some_and(|status| status != obs.recorded_status)
                })
        })
    }
}

/// Read-only mechanism registry observation port for an explicit deployment/cell.
#[async_trait::async_trait]
pub trait MechanismObservationPort: Send + Sync {
    /// Read the database clock, latest observations and their witnesses in one snapshot.
    async fn runtime_observations(
        &self,
        target: &ObservationTarget,
    ) -> Result<RuntimeObservations, ErrorCode>;
}
