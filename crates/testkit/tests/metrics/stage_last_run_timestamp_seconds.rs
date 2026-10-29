// witness: family=stage_last_run_timestamp_seconds labels=stage
//! `testkit::tests::metrics::stage_last_run_timestamp_seconds` — §39 timestamp witness.
//! Depends-on: crates=[humaux-telemetry]; services=[]; env=[];
//!   modules=[adapters::maintenance_repo, telemetry::metrics]
//! Called-by: []
//! Invariants: [exact closed stage set and values; attempt starts alone advance last_run]
//! Spec: Baseline §39; §41.2; §80.2; ADR-0123

use humaux_adapters::maintenance_repo::MaintenanceTask;
use humaux_telemetry::metrics::{render_stage_liveness, stage_finished, stage_started};

#[test]
fn stage_last_run_timestamp_seconds() {
    let stages = MaintenanceTask::ALL.map(MaintenanceTask::label);
    for (step, value) in [0, 10, 10, 20, 30].into_iter().enumerate() {
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
            .filter(|l| l.starts_with("stage_last_run_timestamp_seconds{"))
            .map(str::to_owned)
            .collect();
        let expected: Vec<_> = stages
            .iter()
            .map(|stage| {
                format!("stage_last_run_timestamp_seconds{{stage=\"{stage}\"}} {value}")
            })
            .collect();
        assert_eq!(actual.len(), MaintenanceTask::ALL.len());
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
