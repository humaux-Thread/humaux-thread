// witness: family=host_memory_available_bytes labels=-
//! `testkit::tests::metrics::host_memory_available_bytes` — Metric Witness for `host_memory_available_bytes` (registry
//!   row §41.2: M22-1 `health serve` sample · 1; consumer M22-3 capacity rules).
//! Depends-on: crates=[humaux-telemetry]; services=[]; env=[]; modules=[telemetry::host]
//! Called-by: []
//! Invariants: [drives the family's one `.set(` (`telemetry::host::publish`) from a fixture meminfo; MemAvailable is
//!   rendered in bytes (kB × 1024); a missing file, a missing MemTotal or MemAvailable above MemTotal leaves the
//!   family out of the exposition, never a 0]
//! Spec: Baseline §41.2; §4.4; §80.2
//!
//! Compiled and run standalone by `cargo xtask metrics-registry` (`run_witness_probe`).

use std::path::{Path, PathBuf};

use humaux_telemetry::host::{HostSampler, HostSources, publish, render};

/// A fixture directory removed when its owner leaves scope, including while a failed assertion unwinds (#193).
struct FixtureDir(PathBuf);

impl FixtureDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("witness-host-mem-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("fixture dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The exposition after one sample of `meminfo` (`None` = no such file).
fn exposition(meminfo: Option<&str>) -> String {
    let dir = FixtureDir::new("host_memory_available_bytes");
    let path = dir.path().join("meminfo");
    let _ = std::fs::remove_file(&path);
    if let Some(text) = meminfo {
        std::fs::write(&path, text).expect("meminfo fixture");
    }
    let sources = HostSources {
        meminfo: path,
        ..HostSources::default()
    };
    publish(&HostSampler::new(sources).sample());
    let mut out = String::new();
    render(&mut out);
    out
}

/// Present renders bytes; missing and malformed render no family at all.
#[test]
fn host_memory_available_bytes() {
    let out = exposition(Some("MemTotal:  8388608 kB\nMemFree: 1 kB\nMemAvailable:  4194304 kB\n"));
    assert!(out.contains("# TYPE host_memory_available_bytes gauge\n"), "{out}");
    assert!(out.lines().any(|l| l == "host_memory_available_bytes 4294967296"), "{out}");

    for (case, meminfo) in [
        ("file missing", None),
        ("MemTotal missing", Some("MemAvailable: 4194304 kB\n")),
        ("available above total", Some("MemTotal: 1 kB\nMemAvailable: 2 kB\n")),
        ("garbage", Some("not meminfo\n")),
    ] {
        let out = exposition(meminfo);
        assert!(!out.contains("host_memory_available_bytes"), "{case}:\n{out}");
    }
}
