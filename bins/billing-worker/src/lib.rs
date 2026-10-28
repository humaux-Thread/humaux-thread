//! `humaux-billing-worker` — cloud-only billing startup boundary (§71.2).
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: []
//! Invariants: [no processing loop or provider port implementation]
//! Spec: Baseline §71.2; ADR-0074

/// §71.2: explicit non-live startup and destination selection.
pub mod mode;
