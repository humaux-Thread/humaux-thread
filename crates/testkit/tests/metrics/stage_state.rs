// witness: family=stage_state labels=stage
//! `testkit::tests::metrics::stage_state` — §39 six-state derivation.
//! Depends-on: crates=[humaux-domain, humaux-telemetry]; services=[]; env=[]; modules=[domain::error, telemetry::metrics]
//! Called-by: [maintenance::tests::stage_liveness]
//! Invariants: [exact six state codes; attempted runs alone never imply output]
//! Spec: Baseline §39; §41.2; §80.2
use humaux_domain::error::ErrorCode;
use humaux_telemetry::metrics::{
    render_stage_liveness, stage_declared, stage_recorded, stage_started,
};
#[test]
fn stage_state() {
    let cases = [
        ("baseline", 0),
        ("ok", 1),
        ("empty", 2),
        ("error", 3),
        ("disabled", 4),
        ("cannot", 5),
    ];
    assert_eq!(cases.len(), 6);
    for (stage, expected) in cases {
        stage_declared(stage, expected != 4, expected != 5);
        if (1..=3).contains(&expected) {
            stage_started(stage, 10.0);
            let error = match expected {
                3 => Some(ErrorCode::Internal),
                _ => None,
            };
            stage_recorded(stage, 11.0, error, [3, u64::from(expected == 1)]);
        }
        let mut out = String::new();
        render_stage_liveness(&mut out, &[stage]);
        let actual: Vec<_> = out
            .lines()
            .filter(|l| l.starts_with("stage_state{"))
            .collect();
        assert_eq!(actual.len(), 1);
        assert_eq!(
            actual,
            [format!("stage_state{{stage=\"{stage}\"}} {expected}")],
            "{stage}"
        );
    }
}
