//! `testkit::tests::fault::projection_invisible_loss` — §53.4 注错测试：`DegradeCode::ProjectionInvisibleLoss` 的一条注错记录（每个
//!   reason 必须有一条测试，从未触发过的 reason 不许合并，§53.3 规则2 的三数相等 把这句话变成 CI 事实）。
//! Depends-on: crates=[humaux-retrieval, humaux-telemetry]; services=[]; env=[]; modules=[humaux-testkit, retrieval::completeness, retrieval::envelope, telemetry::degrade]
//! Called-by: [testkit::tests::fault_main]
//! Invariants: [the loss verdict is produced by retrieval::envelope::build_projection_block (A2) from a real ledger::close closure; this file never names the exit point; the Qdrant-level injection of §23.4 G23-2 is M13's G80-5, not repeated here (M01 D4 / G-M01-4)]
//! Spec: Baseline §53.4; §23.1; §23.4; §53.1; ADR-0057; ADR-0077
//!
//! §53.4 登记的注入读数：visible 100 → 90，done 恒 100，deleted 恒 0，A2 违反。
//!
//! Real path, at the envelope level: the ledger side is the registered reading (100 expected, 100 done, 0 deleted,
//! 100 settled points) and the index side reports 90 visible points, so A2 fails and `build_projection_block`
//! degrades through its production loss branch. Deleting 10 real Qdrant points past `retention::tombstone` is the
//! Qdrant-level half of the registration; it needs the live index and belongs to M13 (G80-5).

use std::time::Duration;

use humaux_retrieval::completeness::ledger::{self, LedgerReads, ProjectionReads};
use humaux_retrieval::envelope::build_projection_block;
use humaux_telemetry::degrade::{DegradeCode, degrade_total_count};
use humaux_testkit::{FaultObservation, assert_fault_observed};

#[test]
fn projection_invisible_loss_increments_counter_and_reports_both_forms() {
    // Nothing pending (so no lag verdict), A1 closed: 100 done == 100 expected.
    let stream = ledger::close(
        LedgerReads {
            expected: 100,
            done: 100,
            ..LedgerReads::default()
        },
        ProjectionReads {
            points_expected: 100,
            points_settled: 100,
            ..ProjectionReads::default()
        },
    );

    let before = degrade_total_count(DegradeCode::ProjectionInvisibleLoss);
    let outcome = build_projection_block(&stream, Some(90), Duration::from_secs(30));
    let after = degrade_total_count(DegradeCode::ProjectionInvisibleLoss);

    // The registered readings survive into the block: done and deleted unchanged, visible down 10, A2 violated.
    assert_eq!(
        (
            outcome.value.done,
            outcome.value.deleted,
            outcome.value.visible
        ),
        (100, 0, Some(90))
    );
    assert!(!outcome.value.current);
    assert_eq!(
        outcome.degradations.as_slice(),
        &[DegradeCode::ProjectionInvisibleLoss]
    );

    let degradations_wire: Vec<String> = outcome
        .degradations
        .iter()
        .map(|c| c.line_format())
        .collect();

    // §53.4: unify both assertions in one place (see tests/fault/README.md).
    assert_fault_observed(&FaultObservation {
        degrade_variant: DegradeCode::ProjectionInvisibleLoss.as_str(),
        degrade_total_before: before,
        degrade_total_after: after,
        completeness_degradations: &degradations_wire,
    });
}
