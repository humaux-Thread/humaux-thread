//! `testkit::tests::pair::projection_lag_degraded` — §52.2 projection lag pair, degraded side through the production envelope.
//! Depends-on: crates=[humaux-domain, humaux-retrieval, humaux-telemetry]; services=[]; env=[]; modules=[domain::error, retrieval::completeness, retrieval::envelope, telemetry::degrade]
//! Called-by: [testkit::tests::pair_main]
//! Invariants: [a lagged result remains available and carries ProjectionLag]
//! Spec: Baseline §52.2; §52.4 G52-5; ADR-0057 D-E

use std::time::Duration;

use humaux_domain::error::ErrorCode;
use humaux_retrieval::completeness::ledger::{self, LedgerReads, ProjectionReads};
use humaux_retrieval::envelope::build_projection_block;
use humaux_telemetry::degrade::DegradeCode;

#[test]
fn projection_lag_degraded_when_read_your_write_not_required() {
    // Close A1 and A2 so the pending ticket's age is the only degradation.
    let ledger = ledger::close(
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

    let outcome = build_projection_block(&ledger, Some(4), Duration::from_secs(30));
    assert_eq!(outcome.value.visible, Some(4));
    assert_eq!(outcome.value.pending, 1);
    assert_eq!(
        outcome.degradations.as_slice(),
        &[DegradeCode::ProjectionLag]
    );
    assert_eq!(
        outcome.degradations.as_slice()[0].line_format(),
        ErrorCode::ProjectionLag.as_str(),
        "§52.2: the concept pair shares the same wire spelling"
    );
}
