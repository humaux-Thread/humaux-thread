// witness: family=stage_last_output_timestamp_seconds labels=stage
//! `testkit::tests::metrics::stage_last_output_timestamp_seconds` — §39 timestamp witness.
//! Depends-on: crates=[humaux-telemetry]; services=[]; env=[];
//!   modules=[adapters::maintenance_repo, telemetry::metrics]
//! Called-by: [maintenance::tests::stage_liveness]
//! Invariants: [exact closed stage set and values; only committed affected rows advance last_output]
//! Spec: Baseline §39; §41.2; §80.2; ADR-0123

use humaux_adapters::maintenance_repo::MaintenanceTask;
use humaux_telemetry::metrics::{render_stage_liveness, stage_finished, stage_started};

#[test]
fn stage_last_output_timestamp_seconds() {
    let stages = MaintenanceTask::ALL.map(MaintenanceTask::label);
    assert_eq!(stages.len(), 13);
    assert_eq!(
        stages.join(","),
        "lost,ingest_tickets,quota_reservations,quota_renewal,provider_budgets,confirm_tokens,snapshots,jobs,reissue,redrive,partitions,dr_evidence,authority_i4"
    );
    for (step, value) in [0, 0, 11, 11, 31].into_iter().enumerate() {
        for stage in stages {
            match step {
                1 => stage_started(stage, 10.0),
                2 => stage_finished(stage, 11.0, true, true),
                3 => {
                    stage_started(stage, 20.0);
                    stage_finished(stage, 21.0, true, false);
                }
                4 => {
                    stage_started(stage, 30.0);
                    stage_finished(stage, 31.0, false, true);
                }
                _ => {}
            }
        }
        let mut out = String::new();
        render_stage_liveness(&mut out, &stages);
        let actual: Vec<_> = out
            .lines()
            .filter(|l| l.starts_with("stage_last_output_timestamp_seconds{"))
            .map(str::to_owned)
            .collect();
        let expected: Vec<_> = stages
            .iter()
            .map(|stage| {
                format!("stage_last_output_timestamp_seconds{{stage=\"{stage}\"}} {value}")
            })
            .collect();
        assert_eq!(actual.len(), 13);
        assert_eq!(actual, expected, "step {step}");
        if step == 3 {
            for stage in stages {
                stage_finished(stage, 25.0, false, false);
            }
            let mut failed = String::new();
            render_stage_liveness(&mut failed, &stages);
            assert_eq!(failed, out, "failure without output preserves history");
        }
    }
}
