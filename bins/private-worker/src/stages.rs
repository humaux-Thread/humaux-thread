//! `private-worker::stages` — closed §39 stage labels shared by the binary and library.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: [private-worker::main, private-worker::distill]
//! Invariants: [the library and binary use the same closed label set]
//! Spec: Baseline §39; §78.2

/// §39: resident seat work and lease writes.
pub(crate) const STAGES: [&str; 2] = ["distill_seat", "distill_lease_renewal"];
