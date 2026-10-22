// witness: family=host_cpu_busy_ratio labels=-
//! `testkit::tests::metrics::host_cpu_busy_ratio` — Metric Witness for `host_cpu_busy_ratio` (registry row §41.2: M22-1
//!   `health serve` sample · 1; consumer M22-3 capacity rules).
//! Depends-on: crates=[humaux-telemetry]; services=[]; env=[]; modules=[telemetry::host]
//! Called-by: []
//! Invariants: [drives the family's one `.set(` (`telemetry::host::publish`) from fixture /proc/stat texts; the value
//!   is a delta of two samples: the first sample, a zero total delta and an unreadable file render no family, and an
//!   unreadable file makes the next readable sample a first sample again]
//! Spec: Baseline §41.2; §4.4; §80.2
//!
//! Compiled and run standalone by `cargo xtask metrics-registry` (`run_witness_probe`).

use humaux_telemetry::host::{HostSampler, HostSources, publish, render};

/// total 1000, busy 200.
const STAT_1: &str = "cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 100 0 100 800 0 0 0 0 0 0\n";
/// total 1200, busy 300: a delta of 100 busy in 200 total.
const STAT_2: &str = "cpu  150 0 150 900 0 0 0 0 0 0\ncpu0 150 0 150 900 0 0 0 0 0 0\n";

/// The `host_cpu_busy_ratio` line (or `None`) after publishing one more sample.
fn next(sampler: &mut HostSampler) -> Option<String> {
    publish(&sampler.sample());
    let mut out = String::new();
    render(&mut out);
    let line = out.lines().find(|l| l.starts_with("host_cpu_busy_ratio ")).map(str::to_owned);
    assert_eq!(line.is_some(), out.contains("# TYPE host_cpu_busy_ratio gauge\n"), "{out}");
    line
}

/// First sample, zero delta and unreadable file are absent; a real delta is 0.5.
#[test]
fn host_cpu_busy_ratio() {
    let dir = std::env::temp_dir().join(format!("witness-host-cpu-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("fixture dir");
    let stat = dir.join("stat");
    let mut sampler = HostSampler::new(HostSources {
        stat: stat.clone(),
        ..HostSources::default()
    });
    let half = Some("host_cpu_busy_ratio 0.5".to_owned());

    std::fs::write(&stat, STAT_1).expect("stat 1");
    assert_eq!(next(&mut sampler), None, "first sample");
    std::fs::write(&stat, STAT_2).expect("stat 2");
    assert_eq!(next(&mut sampler), half, "delta");
    assert_eq!(next(&mut sampler), None, "zero total delta");

    std::fs::remove_file(&stat).expect("remove stat");
    assert_eq!(next(&mut sampler), None, "unreadable");
    std::fs::write(&stat, STAT_1).expect("stat 1 again");
    assert_eq!(next(&mut sampler), None, "first sample again after an unreadable one");
    std::fs::write(&stat, STAT_2).expect("stat 2 again");
    assert_eq!(next(&mut sampler), half, "delta again");

    let _ = std::fs::remove_dir_all(dir);
}
