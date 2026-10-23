//! `testkit::tests::fault::rerank_model_mismatch` — §53.4 fault record for `DegradeCode::RerankModelMismatch`
//!   (§53.3 rule 2 counts one fault file per variant).
//! Depends-on: crates=[humaux-retrieval, humaux-telemetry]; services=[]; env=[]; modules=[humaux-testkit, retrieval::rerank, telemetry::degrade]
//! Called-by: [testkit::tests::fault_main]
//! Invariants: [the code is emitted by retrieval::rerank::degradations, the function the gateway calls once the
//!   identity a worker reported differs from the pin; this file never names the exit point (M01 D4 / G-M01-4)]
//! Spec: Baseline §53.4; §53.1; ADR-0077; ADR-0084 D-D
//!
//! Real path: a worker answers with scores of another model than the pinned one. `settle` discards the scores (never a
//! switch to that model) and keeps the fused order, and the production function that turns that failure into its
//! degradation is driven directly, so a deleted emit leaves this test red.

use humaux_retrieval::rerank::{Executor, ModelIdentity, degradations, settle};
use humaux_telemetry::degrade::{DegradeCode, degrade_total_count};
use humaux_testkit::{FaultObservation, assert_fault_observed};

const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn rerank_model_mismatch_increments_counter_and_reports_both_forms() {
    let pinned = ModelIdentity::new("org/model", "revision", "recipe", HASH, HASH)
        .expect("a valid identity");
    let answered = ModelIdentity::new("org/model", "another-revision", "recipe", HASH, HASH)
        .expect("a valid identity");
    let visible = [11_u8, 22, 33];
    // Scores that would reverse the order if they were applied.
    let settlement = settle(
        &visible,
        &visible,
        &pinned,
        Executor::Scored {
            scores: &[0.1, 0.5, 0.9],
            model: &answered,
        },
    );
    assert_eq!(
        settlement.order, visible,
        "the scores of the wrong model are discarded"
    );
    assert_eq!(settlement.reranked_count, 0, "nothing was reranked");

    let before = degrade_total_count(DegradeCode::RerankModelMismatch);
    let codes = degradations(settlement.failure);
    let after = degrade_total_count(DegradeCode::RerankModelMismatch);

    let degradations_wire: Vec<String> = codes.iter().map(|c| c.line_format()).collect();
    assert_eq!(degradations_wire, ["RERANK_MODEL_MISMATCH"]);
    assert_fault_observed(&FaultObservation {
        degrade_variant: DegradeCode::RerankModelMismatch.as_str(),
        degrade_total_before: before,
        degrade_total_after: after,
        completeness_degradations: &degradations_wire,
    });
}
