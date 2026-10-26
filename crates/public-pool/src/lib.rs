//! `humaux-public-pool` — the cloud edition's governed public knowledge pool (M20): admission, receipts, revocation,
//!   projection and provenance probes over the `public.*` schema.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: [crate(humaux-public-worker)]
//! Invariants: [`edition = "cloud"`: no core crate (domain, adapters, application, bins of the core edition) depends on
//!   this crate (G-M01-2); the `public.*` writers run only on `PublicWorkerDbPool`]
//! Spec: Baseline §12.6; §13; ADR-0073 D-B; ADR-0074
//!
//! Layer direction is cloud → core: this crate reaches the typed pools and `QdrantTransportError` through
//! `humaux-adapters`. The reverse seam is `humaux_adapters::mechanism_observation::PublicClaimEvaluator`, implemented
//! here by [`public_repo::PublicRepoEvaluator`].

pub mod public_evolve;
pub mod public_projection;
pub mod public_provenance;
pub mod public_repo;
