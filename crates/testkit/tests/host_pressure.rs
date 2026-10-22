//! `testkit::tests::host_pressure` — G-M22-1 fixture gate, also run as the PSI metric witness.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[testkit::tests::metrics::host_pressure_ratio]
//! Called-by: [cargo-test]
//! Invariants: [the targeted selector executes the same absent-family assertions as the registry witness]
//! Spec: Baseline §41.2; §80.2

#[path = "metrics/host_pressure_ratio.rs"]
mod host_pressure_ratio;
