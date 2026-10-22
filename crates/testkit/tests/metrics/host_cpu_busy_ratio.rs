// witness: family=host_cpu_busy_ratio labels=-
//! `testkit::tests::metrics::host_cpu_busy_ratio` — Metric Witness for `host_cpu_busy_ratio` (§80.2 W-side;
//!   registry row §41.2: `humaux-maintenance health serve` 每个采样周期 · 1; consumer §42 capacity rules).
//! Depends-on: crates=[humaux-telemetry]; services=[]; env=[]; modules=[telemetry::host]
//! Called-by: []
//! Invariants: [drives the family's one `.set(` through `telemetry::host::publish`, and a reading without the ratio
//!   (the first sample, a zero delta, an unreadable file) carries no sample at all, never a 0 (§4.4); the /proc/stat
//!   delta itself is proven by `telemetry::host`'s own lib tests]
//! Spec: Baseline §41.2; §4.4; §42; §80.2; ADR-0061 D-A
//!
//! Compiled and run standalone by `cargo xtask metrics-registry` (`run_witness_probe`).

use humaux_telemetry::host::{HostReading, publish, render};

/// The one rendered sample's value, or `None` while the family carries no sample.
fn sample(out: &str) -> Option<f64> {
    out.lines()
        .filter(|l| l.starts_with("host_cpu_busy_ratio "))
        .map(|l| {
            l.rsplit_once(' ')
                .expect("a sample has a value")
                .1
                .parse()
                .expect("a bare float")
        })
        .next()
}

/// A carried ratio renders; an absent one renders nothing at all, while the header stays.
#[test]
fn busy_ratio_and_absence() {
    let reading = HostReading {
        cpu_busy_ratio: Some(0.75),
        ..HostReading::default()
    };
    publish(&reading);
    let mut out = String::new();
    render(&mut out);
    assert!(out.contains("# TYPE host_cpu_busy_ratio gauge\n"), "{out}");
    assert_eq!(
        sample(&out),
        Some(0.75),
        "the ratio is the delta's busy share: {out}"
    );

    publish(&HostReading::default());
    let mut out = String::new();
    render(&mut out);
    assert_eq!(
        sample(&out),
        None,
        "no ratio (first sample, zero delta or no file) renders no sample, never a 0 (§4.4): {out}"
    );
    assert!(
        out.contains("# TYPE host_cpu_busy_ratio gauge\n"),
        "the header stays so --metrics-families names the family: {out}"
    );
}
