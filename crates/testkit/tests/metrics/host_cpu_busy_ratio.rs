// witness: family=host_cpu_busy_ratio labels=-
//! `testkit::tests::metrics::host_cpu_busy_ratio` — consecutive CPU sample witness.
//! Depends-on: crates=[humaux-telemetry]; services=[fs(fixtures)]; env=[]; modules=[telemetry::host]
//! Called-by: []
//! Invariants: [first samples and zero deltas never emit a synthetic CPU busy zero]
//! Spec: Baseline §41.2; §4.4; §80.2

use humaux_telemetry::host::{HostPaths, HostSampler, render};

/// §80.2: idle plus iowait is excluded, guest time is not added twice.
#[test]
fn cpu_busy_witness() {
    let id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let file = std::env::temp_dir().join(format!("host-cpu-{}-{id}", std::process::id()));
    let paths = HostPaths {
        pressure: std::array::from_fn(|_| file.with_extension("missing")),
        meminfo: file.with_extension("missing"),
        stat: file.clone(),
    };
    let mut sampler = HostSampler::default();
    // dep: fs(fixtures) — synthetic aggregate CPU counters (§79).
    std::fs::write(&file, "cpu 100 0 50 100 50 0 0 0 20 0\n").unwrap();
    sampler.sample(&paths);
    let mut first = String::new();
    render(&mut first);
    // dep: fs(fixtures) — busy delta 50, idle+iowait delta 50 (§41.2).
    std::fs::write(&file, "cpu 140 0 60 140 60 0 0 0 50 0\n").unwrap();
    sampler.sample(&paths);
    let mut second = String::new();
    render(&mut second);
    sampler.sample(&paths);
    let mut unchanged = String::new();
    render(&mut unchanged);
    // dep: fs(fixtures) — reclaim only this test's input (§79).
    std::fs::remove_file(file).unwrap();
    assert!(!first.lines().any(|line| line.starts_with("host_cpu_busy_ratio ")));
    assert!(second.lines().any(|line| line == "host_cpu_busy_ratio 0.5"));
    assert!(!unchanged.lines().any(|line| line.starts_with("host_cpu_busy_ratio ")));
}
