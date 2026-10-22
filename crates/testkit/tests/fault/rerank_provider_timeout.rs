//! `testkit::tests::fault::rerank_provider_timeout` — §53.4 fault record for `DegradeCode::RerankProviderTimeout`
//!   (§53.3 rule 2 counts one fault file per variant).
//! Depends-on: crates=[humaux-retrieval, humaux-telemetry]; services=[]; env=[]; modules=[humaux-testkit, retrieval::rerank, telemetry::degrade]
//! Called-by: [testkit::tests::fault_main]
//! Invariants: [the code is emitted by retrieval::rerank::degradations, the function the gateway calls once a selected
//!   rerank branch got no usable scores; this file never names the exit point (M01 D4 / G-M01-4)]
//! Spec: Baseline §53.4; §53.1; §19; §23.3; ADR-0077; ADR-0084 D-D
//!
//! Real path (G-RET-12 at unit level; the gateway-level run is `semantic_recall_wiring`): the executor answers nothing
//! within the timeout, `settle` falls back to the fused order with every item kept (§53.4's registered injection: the
//! fallback ranking still returns), and the production function that turns that failure into its degradation is driven
//! directly, so a deleted emit leaves this test red.

use humaux_retrieval::rerank::{Executor, ModelIdentity, degradations, settle};
use humaux_telemetry::degrade::{DegradeCode, degrade_total_count};
use humaux_testkit::{FaultObservation, assert_fault_observed};

const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn pinned() -> ModelIdentity {
    ModelIdentity::new("org/model", "revision", "recipe", HASH, HASH).expect("a valid identity")
}

#[test]
fn rerank_provider_timeout_increments_counter_and_reports_both_forms() {
    let visible = [11_u8, 22, 33];
    // A stalled worker is `Unavailable` once the gateway's wait has elapsed.
    let settlement = settle(&visible, &visible, &pinned(), Executor::Unavailable);
    assert_eq!(
        settlement.order, visible,
        "the fallback ranking keeps every item in fused order"
    );
    assert_eq!(settlement.reranked_count, 0, "nothing was reranked");

    let before = degrade_total_count(DegradeCode::RerankProviderTimeout);
    let codes = degradations(settlement.failure);
    let after = degrade_total_count(DegradeCode::RerankProviderTimeout);

    let degradations_wire: Vec<String> = codes.iter().map(|c| c.line_format()).collect();
    // §53.2: label form is the variant name, wire form is its fold.
    assert_eq!(degradations_wire, ["RERANK_PROVIDER_TIMEOUT"]);
    assert_fault_observed(&FaultObservation {
        degrade_variant: DegradeCode::RerankProviderTimeout.as_str(),
        degrade_total_before: before,
        degrade_total_after: after,
        completeness_degradations: &degradations_wire,
    });
}
