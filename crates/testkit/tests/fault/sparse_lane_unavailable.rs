//! `testkit::tests::fault::sparse_lane_unavailable` — §53.4 fault record for `DegradeCode::SparseLaneUnavailable`
//!   (§53.3 rule 2 counts one fault file per variant).
//! Depends-on: crates=[humaux-retrieval, humaux-telemetry]; services=[]; env=[]; modules=[humaux-testkit, retrieval::envelope, telemetry::degrade]
//! Called-by: [testkit::tests::fault_main]
//! Invariants: [the code is emitted by retrieval::envelope::sparse_lane_unavailable, the function the gateway calls when
//!   the sparse leg failed, together with the Failed lane status; this file never names the exit point (M01 D4 / G-M01-4)]
//! Spec: Baseline §53.4; §53.1; ADR-0077; ADR-0083 D-C
//!
//! Real path (G-RET-10 at unit level; the gateway-level run is `semantic_recall_wiring`): the production function that
//! turns a failed sparse leg into its degradation is driven directly, so a deleted emit leaves this test red. The
//! sparse request failing against a real Qdrant while the dense request succeeds is proved end to end there.

use humaux_retrieval::envelope::{LaneStatus, sparse_lane_unavailable};
use humaux_telemetry::degrade::{DegradeCode, degrade_total_count};
use humaux_testkit::{FaultObservation, assert_fault_observed};

#[test]
fn sparse_lane_unavailable_increments_counter_and_reports_both_forms() {
    let before = degrade_total_count(DegradeCode::SparseLaneUnavailable);
    let (lane, degradations) = sparse_lane_unavailable();
    let after = degrade_total_count(DegradeCode::SparseLaneUnavailable);

    let degradations_wire: Vec<String> = degradations.iter().map(|c| c.line_format()).collect();

    // §53.2: label form is the variant name, wire form is its fold.
    assert_eq!(degradations_wire, ["SPARSE_LANE_UNAVAILABLE"]);
    // The lane reads `failed` in the same breath as the degradation (ADR-0083 D-C).
    assert_eq!(lane, LaneStatus::Failed);
    assert_fault_observed(&FaultObservation {
        degrade_variant: DegradeCode::SparseLaneUnavailable.as_str(),
        degrade_total_before: before,
        degrade_total_after: after,
        completeness_degradations: &degradations_wire,
    });
}
