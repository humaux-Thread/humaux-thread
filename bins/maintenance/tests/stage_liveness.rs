//! `maintenance::tests::stage_liveness` — CI selector for the §39 output witness.
//! Depends-on: crates=[]; services=[]; env=[];
//!   modules=[testkit::tests::metrics::stage_last_output_timestamp_seconds]
//! Called-by: [cargo-test]
//! Invariants: [the targeted red runs the same witness as the §80.2 registry gate]
//! Spec: Baseline §39; §41.2; §80.2

#[path = "../../../crates/testkit/tests/metrics/stage_last_output_timestamp_seconds.rs"]
mod output;
