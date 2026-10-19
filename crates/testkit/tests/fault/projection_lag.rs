//! `testkit::tests::fault::projection_lag` — §53.4 注错测试：`DegradeCode::ProjectionLag` 的一条注错记录（每个 reason 必须有一条测试，从未触发过的
//!   reason 不许合并，§53.3 规则2 的三数相等 把这句话变成 CI 事实）。
//! Depends-on: crates=[humaux-retrieval, humaux-telemetry]; services=[]; env=[]; modules=[humaux-testkit, retrieval::completeness, retrieval::envelope, telemetry::degrade]
//! Called-by: [testkit::tests::fault_main]
//! Invariants: [the lag verdict is produced by retrieval::envelope::build_projection_block from a real ledger::close closure; this file never names the exit point, so removing the production emit turns it red (M01 D4 / G-M01-4)]
//! Spec: Baseline §52.2; §53.4; §53.1; ADR-0057; ADR-0077
//!
//! 结果返回但已知落后于应反映的写入（§52.2 与 ErrorCode::ProjectionLag 概念对，§53.4 照变体语义注入）。
//!
//! Real path: the oldest pending ticket of the stream is older than the lag threshold, so
//! `build_projection_block` degrades through the production `.also(ProjectionLag)` at its tail (ADR-0057 D-E).
//! The closure comes from `ledger::close` and the A2 reading is closed (`visible == points_settled`), so lag is the
//! only verdict and the frozen `current` formula is left alone.

use std::time::Duration;

use humaux_retrieval::completeness::ledger::{self, LedgerReads, ProjectionReads};
use humaux_retrieval::envelope::build_projection_block;
use humaux_telemetry::degrade::{DegradeCode, degrade_total_count};
use humaux_testkit::{FaultObservation, assert_fault_observed};

#[test]
fn projection_lag_increments_counter_and_reports_both_forms() {
    // One pending ticket, 31 s old against a 30 s threshold; A1 holds (4 done + 1 pending == 5 expected).
    let stream = ledger::close(
        LedgerReads {
            expected: 5,
            done: 4,
            pending: 1,
            ..LedgerReads::default()
        },
        ProjectionReads {
            points_expected: 5,
            points_settled: 4,
            points_in_flight: 1,
            oldest_pending_age_secs: Some(31),
            ..ProjectionReads::default()
        },
    );

    let before = degrade_total_count(DegradeCode::ProjectionLag);
    let outcome = build_projection_block(&stream, Some(4), Duration::from_secs(30));
    let after = degrade_total_count(DegradeCode::ProjectionLag);

    // Lag alone: no loss verdict rides along, and `current` keeps its frozen formula.
    assert_eq!(
        outcome.degradations.as_slice(),
        &[DegradeCode::ProjectionLag]
    );
    assert!(outcome.value.current);

    let degradations_wire: Vec<String> = outcome
        .degradations
        .iter()
        .map(|c| c.line_format())
        .collect();

    // §53.4: unify both assertions in one place (see tests/fault/README.md).
    assert_fault_observed(&FaultObservation {
        degrade_variant: DegradeCode::ProjectionLag.as_str(),
        degrade_total_before: before,
        degrade_total_after: after,
        completeness_degradations: &degradations_wire,
    });
}
