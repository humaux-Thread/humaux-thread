// witness: family=stage_last_error_class labels=stage
//! `testkit::tests::metrics::stage_last_error_class` — §39 result witness.
//! Depends-on: crates=[humaux-domain, humaux-telemetry]; services=[]; env=[]; modules=[domain::error, telemetry::metrics]
//! Called-by: []
//! Invariants: [last ErrorCode survives a later successful attempt]
//! Spec: Baseline §39; §41.2; §80.2
use humaux_domain::error::ErrorCode;
use humaux_telemetry::metrics::{render_stage_liveness, stage_recorded};
#[test]
fn stage_last_error_class() {
    for (step, expected) in [0, 18, 18].into_iter().enumerate() {
        if step == 1 { stage_recorded("lost", 10.0, Some(ErrorCode::Internal), [3, 2]); }
        if step == 2 { stage_recorded("lost", 11.0, None, [0, 0]); }
        let mut out = String::new();
        render_stage_liveness(&mut out, &["lost"]);
        let actual: Vec<_> = out.lines().filter(|l| l.starts_with("stage_last_error_class{")).collect();
        assert_eq!(actual.len(), 1);
        assert_eq!(actual, [format!("stage_last_error_class{{stage=\"lost\"}} {expected}")]);
    }
}
