//! `humaux-billing-worker` — cloud-only startup and pure provider boundaries (§71.2).
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: []
//! Invariants: [no processing loop; no live mode]
//! Spec: Baseline §71.2; ADR-0074

/// §71.2: explicit non-live startup and destination selection.
pub mod mode;
/// §71.3: pure provider envelope normalization.
pub mod normalize;
/// §71.3: raw webhook signature verification.
pub mod signature;

/// §71.2: Creem port implementation and authoritative reads.
pub mod creem;
/// §79.4: fake provider never enters a production binary.
#[cfg(test)]
pub mod fake_creem;
