//! `testkit::tests::fault::lane_substituted` — §53.4 注错测试：`DegradeCode::LaneSubstituted` 的一条注错记录（每个 reason
//!   必须有一条测试，从未触发过的 reason 不许合并，§53.3 规则2 的三数相等 把这句话变成 CI 事实）。
//! Depends-on: crates=[humaux-retrieval, humaux-telemetry]; services=[]; env=[]; modules=[humaux-testkit, retrieval::envelope, retrieval::planner, telemetry::degrade]
//! Called-by: [testkit::tests::fault_main]
//! Invariants: [the substitution is reported by retrieval::envelope::dense_lane_substitution for a planner decision other than semantic and no explicit mode; an explicit mode moves nothing; this file never names the exit point (M01 D4 / G-M01-4)]
//! Spec: Baseline §53.4; §53.1; ADR-0055; ADR-0077
//!
//! planner 把查询路由到未交付的 lane、调用方未指定 `mode`，dense lane 代答（ADR-0055 D-C）。
//!
//! Real path: a temporal planner decision with no caller `mode` is answered by the dense lane, so the production
//! `dense_lane_substitution` reports `LaneSubstituted`. §53.4 also registers the negative control — an explicit
//! `mode` means the caller chose dense, nothing was substituted — which is asserted on the same counter.

use humaux_retrieval::envelope::dense_lane_substitution;
use humaux_retrieval::planner::{PlannerDecision, QueryClass};
use humaux_telemetry::degrade::{DegradeCode, degrade_total_count};
use humaux_testkit::{FaultObservation, assert_fault_observed};

#[test]
fn lane_substituted_increments_counter_and_reports_both_forms() {
    let decision = PlannerDecision::Class(QueryClass::Temporal);

    let before = degrade_total_count(DegradeCode::LaneSubstituted);
    let degradations = dense_lane_substitution(&decision, false);
    let after = degrade_total_count(DegradeCode::LaneSubstituted);

    let degradations_wire: Vec<String> = degradations.iter().map(|c| c.line_format()).collect();

    // §53.4: unify both assertions in one place (see tests/fault/README.md).
    assert_fault_observed(&FaultObservation {
        degrade_variant: DegradeCode::LaneSubstituted.as_str(),
        degrade_total_before: before,
        degrade_total_after: after,
        completeness_degradations: &degradations_wire,
    });

    // §53.4 negative control: `mode:"semantic"` named by the caller does not substitute anything.
    assert!(dense_lane_substitution(&decision, true).is_empty());
    assert_eq!(
        degrade_total_count(DegradeCode::LaneSubstituted),
        after,
        "an explicit mode must not move degrade_total"
    );
}
