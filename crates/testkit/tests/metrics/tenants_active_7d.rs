// witness: family=tenants_active_7d labels=-
//! `testkit::tests::metrics::tenants_active_7d` — Metric Witness for `tenants_active_7d` (§80.2 W-side; registry row
//!   §41.2: M22-2 `ops.health_snapshot()` sample; consumer M22-3 headroom rules).
//! Depends-on: crates=[humaux-telemetry]; services=[]; env=[]; modules=[telemetry::health]
//! Called-by: []
//! Invariants: [drives the family's one `.set(` (`telemetry::health::publish`) from a fixture whose 1-day and 7-day
//!   counts differ, so an emit wired to the 1-day field is red; the family is declared at 0 before any publish (an exact
//!   SQL count, unlike the host families that stay absent), then renders exactly one unlabeled sample]
//! Spec: Baseline §41.2; §80.2; ADR-0061 D-D
//!
//! Compiled and run standalone by `cargo xtask metrics-registry` (`run_witness_probe`). One test only: the family
//! lives in a process-global static, so a second test publishing here would race the zero-state assertion.

use humaux_telemetry::health::{HealthSnapshot, publish, render};

/// Every sample line of `tenants_active_7d` in one render of the health exposition.
fn samples() -> Vec<String> {
    let mut out = String::new();
    render(&mut out);
    out.lines()
        .filter(|l| !l.starts_with('#'))
        .filter(|l| l.split(['{', ' ']).next() == Some("tenants_active_7d"))
        .map(str::to_owned)
        .collect()
}

/// Zero state declares one sample at 0; a publish replaces it with the 7-day count and nothing else.
#[test]
fn zero_state_declares_zero_then_the_published_seven_day_count_renders() {
    assert_eq!(samples(), ["tenants_active_7d 0"]);
    publish(&HealthSnapshot {
        tenants_active_1d: 43,
        tenants_active_7d: 47,
        ..HealthSnapshot::default()
    });
    assert_eq!(samples(), ["tenants_active_7d 47"]);
}
