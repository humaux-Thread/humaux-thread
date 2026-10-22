//! `testkit::tests::fault::sparse_lane_unavailable` — §53.4 fault record for `DegradeCode::SparseLaneUnavailable`
//!   (§53.3 rule 2 counts one fault file per variant).
//! Depends-on: crates=[humaux-telemetry]; services=[]; env=[]; modules=[humaux-testkit, telemetry::degrade]
//! Called-by: [testkit::tests::fault_main]
//! Invariants: []
//! Spec: Baseline §53.4; §53.1; ADR-0083 D-C
//!
//! DORMANT until T-RET-6c-2 (row in `dormant.toml`): no recall path emits this code yet, so this test calls the single
//! exit `abstain()` directly. T-RET-6c-2 wires the sparse leg, deletes the dormant row and rewrites this file to drive
//! the production function with a failing Qdrant sparse request (G-RET-10, ADR-0083 D-F).

use humaux_telemetry::degrade::{DegradeCode, abstain, degrade_total_count};
use humaux_testkit::{FaultObservation, assert_fault_observed};

#[test]
fn sparse_lane_unavailable_increments_counter_and_reports_both_forms() {
    let before = degrade_total_count(DegradeCode::SparseLaneUnavailable);
    let outcome = abstain(
        DegradeCode::SparseLaneUnavailable,
        "dense-leg-answer".to_string(),
    );
    let after = degrade_total_count(DegradeCode::SparseLaneUnavailable);

    let degradations_wire: Vec<String> = outcome
        .degradations
        .iter()
        .map(|c| c.line_format())
        .collect();

    // §53.2: label form is the variant name, wire form is its fold.
    assert_eq!(degradations_wire, ["SPARSE_LANE_UNAVAILABLE"]);
    assert_fault_observed(&FaultObservation {
        degrade_variant: DegradeCode::SparseLaneUnavailable.as_str(),
        degrade_total_before: before,
        degrade_total_after: after,
        completeness_degradations: &degradations_wire,
    });
}
