// witness: family=host_memory_available_bytes labels=-
//! `testkit::tests::metrics::host_memory_available_bytes` — MemAvailable byte and absence witness.
//! Depends-on: crates=[humaux-telemetry]; services=[fs(fixtures)]; env=[]; modules=[telemetry::host]
//! Called-by: []
//! Invariants: [a missing file clears the previously published memory sample]
//! Spec: Baseline §41.2; §4.4; §80.2

use humaux_telemetry::host::{HostPaths, HostSampler, render};

/// §80.2: the production sampler converts kB and does not retain stale memory values.
#[test]
fn memory_available_witness() {
    let id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let file = std::env::temp_dir().join(format!("host-memory-{}-{id}", std::process::id()));
    let paths = HostPaths {
        pressure: std::array::from_fn(|_| file.with_extension("missing")),
        meminfo: file.clone(),
        stat: file.with_extension("missing"),
    };
    // dep: fs(fixtures) — a uniquely named synthetic meminfo (§79).
    std::fs::write(&file, "MemTotal: 2000 kB\nMemAvailable: 500 kB\n").unwrap();
    let mut sampler = HostSampler::default();
    sampler.sample(&paths);
    let mut out = String::new();
    render(&mut out);
    // dep: fs(fixtures) — remove only the file this test wrote (§79).
    std::fs::remove_file(file).unwrap();
    assert!(
        out.lines()
            .any(|line| line == "host_memory_available_bytes 512000")
    );
    sampler.sample(&paths);
    out.clear();
    render(&mut out);
    assert!(!out.lines().any(|line| line.starts_with("host_memory_available_bytes ")));
}
