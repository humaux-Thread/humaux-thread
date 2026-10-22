// witness: family=host_pressure_ratio labels=resource,kind
//! `testkit::tests::metrics::host_pressure_ratio` — Metric Witness for `host_pressure_ratio` and the test of gate G-M22-1
//!   (host gauge truth; registry row §41.2: M22-1 `health serve` sample · 1; consumer M22-3 capacity rules).
//! Depends-on: crates=[humaux-telemetry]; services=[]; env=[]; modules=[telemetry::host]
//! Called-by: []
//! Invariants: [drives the family's one `.set(` (`telemetry::host::publish`) from fixture files for present, missing,
//!   malformed and `full`-less cpu PSI sources; a source that cannot be read leaves its series out of the exposition
//!   and the family disappears with its last series, never a 0]
//! Spec: Baseline §41.2; §4.4; §57.1; §80.2
//!
//! The read paths are `HostSources` values, so the same sampler runs against fixture files instead of `/proc`.
//! Compiled and run standalone by `cargo xtask metrics-registry` (`run_witness_probe`).

use std::path::{Path, PathBuf};

use humaux_telemetry::host::{HostSampler, HostSources, Resource, publish, render};

/// `some` 25 / `full` 0 on cpu, 12.5 / 50 on memory, 75 / 100 on io: a genuine 0 must stay visible.
const PSI: [&str; 3] = [
    "some avg10=1.00 avg60=25.00 avg300=9.00 total=10\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
    "some avg10=1.00 avg60=12.50 avg300=9.00 total=10\nfull avg10=0.00 avg60=50.00 avg300=0.00 total=5\n",
    "some avg10=1.00 avg60=75.00 avg300=9.00 total=10\nfull avg10=0.00 avg60=100.00 avg300=0.00 total=7\n",
];

/// A fixture directory removed when its owner leaves scope, including while a failed assertion unwinds (#193).
struct FixtureDir(PathBuf);

impl FixtureDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("witness-host-pressure-{}-{tag}", std::process::id()));
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

fn fixture() -> (FixtureDir, HostSources) {
    let dir = FixtureDir::new("host_pressure_ratio");
    let sources = HostSources {
        pressure: Resource::ALL.map(|r| dir.path().join(r.as_str())),
        ..HostSources::default()
    };
    for (path, text) in sources.pressure.iter().zip(PSI) {
        std::fs::write(path, text).expect("psi fixture");
    }
    (dir, sources)
}

/// One sample of `sources`, published and rendered; the series lines of the family, in order.
fn series(sources: &HostSources) -> Vec<String> {
    publish(&HostSampler::new(sources.clone()).sample());
    let mut out = String::new();
    render(&mut out);
    let lines: Vec<String> = out
        .lines()
        .filter(|l| l.starts_with("host_pressure_ratio{"))
        .map(str::to_owned)
        .collect();
    if lines.is_empty() {
        assert!(!out.contains("host_pressure_ratio"), "header without a series:\n{out}");
    }
    lines
}

fn line(resource: &str, kind: &str, value: &str) -> String {
    format!("host_pressure_ratio{{resource=\"{resource}\",kind=\"{kind}\"}} {value}")
}

/// Present, missing, malformed and `full`-less sources each render exactly what could be read.
#[test]
fn host_pressure_ratio() {
    let (_dir, sources) = fixture();

    let all = vec![
        line("cpu", "some", "0.25"),
        line("cpu", "full", "0"),
        line("memory", "some", "0.125"),
        line("memory", "full", "0.5"),
        line("io", "some", "0.75"),
        line("io", "full", "1"),
    ];
    assert_eq!(series(&sources), all, "present");

    // G-M22-1: a missing /proc/pressure/cpu is an absent series, not `0`.
    std::fs::remove_file(&sources.pressure[0]).expect("remove cpu psi");
    assert_eq!(series(&sources), all[2..].to_vec(), "cpu file missing");

    // An older kernel's cpu file has no `full` line: only that series is absent.
    std::fs::write(&sources.pressure[0], PSI[0].lines().next().expect("some line")).expect("old cpu psi");
    let old_cpu: Vec<String> = [&all[..1], &all[2..]].concat();
    assert_eq!(series(&sources), old_cpu, "cpu without full");

    // A malformed file counts as unreadable.
    std::fs::write(&sources.pressure[0], PSI[0]).expect("restore cpu psi");
    std::fs::write(&sources.pressure[1], "some avg10=1.00 avg60=high avg300=9.00 total=10\n").expect("bad memory psi");
    let bad_memory: Vec<String> = [&all[..2], &all[4..]].concat();
    assert_eq!(series(&sources), bad_memory, "memory some malformed, full line gone");

    // No source at all: no series and no `# TYPE` line.
    for path in &sources.pressure {
        let _ = std::fs::remove_file(path);
    }
    assert!(series(&sources).is_empty(), "all missing");
}
