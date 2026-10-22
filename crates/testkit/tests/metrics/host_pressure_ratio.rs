// witness: family=host_pressure_ratio labels=resource,kind
//! `testkit::tests::metrics::host_pressure_ratio` — G-M22-1 host source truth fixtures.
//! Depends-on: crates=[humaux-telemetry]; services=[fs(fixtures)]; env=[]; modules=[telemetry::host]
//! Called-by: [testkit::tests::host_pressure]
//! Invariants: [missing or invalid sources clear prior samples; unavailable CPU full is never seeded]
//! Spec: Baseline §41.2; §4.4; §80.2

use humaux_telemetry::host::{HostPaths, HostSampler, render};
use std::path::PathBuf;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("host-pressure-{}-{id}", std::process::id()));
        // dep: fs(fixtures) — only the test-owned directory is written (§79).
        std::fs::create_dir(&dir).unwrap();
        Self(dir)
    }

    fn paths(&self) -> HostPaths {
        HostPaths {
            pressure: ["cpu", "memory", "io"].map(|p| self.0.join(p)),
            meminfo: self.0.join("meminfo"),
            stat: self.0.join("stat"),
        }
    }

    fn write(&self, file: &str, text: &str) {
        // dep: fs(fixtures) — synthetic kernel inputs, never a real /proc write (§79).
        std::fs::write(self.0.join(file), text).unwrap();
    }

    fn remove(&self, file: &str) {
        // dep: fs(fixtures) — removes only the named test input (§79).
        std::fs::remove_file(self.0.join(file)).unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // dep: fs(fixtures) — reclaim this fixture on success or assertion failure (§79).
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn exposition(sampler: &mut HostSampler, paths: &HostPaths) -> String {
    sampler.sample(paths);
    let mut out = String::new();
    render(&mut out);
    out.lines()
        .filter(|line| !line.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

fn value(out: &str, series: &str) -> Option<f64> {
    out.lines()
        .find_map(|line| line.strip_prefix(series)?.strip_prefix(' ')?.parse().ok())
}

/// G-M22-1: positive fixtures, failure after success, old CPU PSI and valid fallback (§4.4).
#[test]
fn host_pressure_truth() {
    let fixture = Fixture::new();
    let paths = fixture.paths();
    let mut sampler = HostSampler::default();
    let pressure = "some avg10=91.00 avg60=20.00 avg300=3.00 total=100\nfull avg10=9.00 avg60=5.00 avg300=1.00 total=50\n";
    for resource in ["cpu", "memory", "io"] {
        fixture.write(resource, pressure);
    }
    fixture.write("meminfo", "MemTotal: 1000 kB\nMemAvailable: 250 kB\n");
    fixture.write("stat", "cpu 100 20 30 400 50 6 7 8 90 10\ncpu0 1 1 1 1\n");
    let first = exposition(&mut sampler, &paths);
    for resource in ["cpu", "memory", "io"] {
        for (kind, expected) in [("some", 0.2), ("full", 0.05)] {
            assert_eq!(
                value(
                    &first,
                    &format!("host_pressure_ratio{{resource=\"{resource}\",kind=\"{kind}\"}}")
                ),
                Some(expected)
            );
        }
    }
    assert_eq!(value(&first, "host_memory_available_bytes"), Some(256000.0));
    assert!(
        !first.contains("host_cpu_busy_ratio"),
        "first sample must be absent"
    );
    fixture.write("stat", "cpu 130 20 40 440 60 8 10 13 120 20\n");
    let second = exposition(&mut sampler, &paths);
    assert_eq!(
        value(&second, "host_cpu_busy_ratio"),
        Some(0.5),
        "guest counters must not be counted twice"
    );
    assert!(
        !exposition(&mut sampler, &paths).contains("host_cpu_busy_ratio"),
        "zero delta is absent"
    );

    fixture.remove("cpu");
    let missing = exposition(&mut sampler, &paths);
    assert!(
        !missing.contains("resource=\"cpu\""),
        "missing CPU PSI must be absent, never zero"
    );
    assert!(missing.contains("resource=\"memory\""));
    assert!(missing.contains("host_memory_available_bytes"));
    fixture.write("cpu", "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n");
    let older = exposition(&mut sampler, &paths);
    assert_eq!(
        value(
            &older,
            "host_pressure_ratio{resource=\"cpu\",kind=\"some\"}"
        ),
        Some(0.0)
    );
    assert!(!older.contains("resource=\"cpu\",kind=\"full\""));

    for malformed in [
        "garbage",
        "some avg60=20\n",
        "some avg10=0 avg60=NaN avg300=0 total=0\n",
        "some avg10=0 avg60=101 avg300=0 total=0\n",
        "some avg10=0 avg60=20 avg300=0 total=oops\n",
    ] {
        fixture.write("cpu", malformed);
        assert!(
            !exposition(&mut sampler, &paths).contains("resource=\"cpu\""),
            "malformed CPU PSI must be absent: {malformed}"
        );
    }
    for resource in ["memory", "io"] {
        for malformed in ["garbage", "some avg10=0 avg60=20 avg300=0 total=0\n"] {
            fixture.write(resource, malformed);
            assert!(
                !exposition(&mut sampler, &paths).contains(&format!("resource=\"{resource}\"")),
                "invalid {resource} PSI must be absent"
            );
        }
        fixture.write(resource, pressure);
    }
    for resource in ["cpu", "memory", "io"] {
        fixture.remove(resource);
    }
    let fallback = exposition(&mut sampler, &paths);
    assert!(!fallback.contains("host_pressure_ratio"));
    assert!(fallback.contains("host_memory_available_bytes"));
    for malformed in [
        "MemAvailable: 250 kB\n",
        "MemTotal: 1000 kB\nMemAvailable: x kB\n",
        "MemTotal: 1 kB\nMemAvailable: 2 kB\n",
        "MemTotal: 1000 kB\nMemAvailable: 250 MB\n",
        "MemTotal: 18446744073709551615 kB\nMemAvailable: 250 kB\n",
    ] {
        fixture.write("meminfo", malformed);
        assert!(!exposition(&mut sampler, &paths).contains("host_memory_available_bytes"));
    }
    fixture.remove("meminfo");
    fixture.write("stat", "cpu 10 0 0 10 0 0 0 0\n");
    assert!(
        !exposition(&mut sampler, &paths).contains("host_cpu_busy_ratio"),
        "counter rollback must be absent"
    );
    for malformed in ["cpu x 0 0 10\n", "cpu0 1 2 3 4\n", "cpu 1 2 3\n"] {
        fixture.write("stat", malformed);
        assert!(!exposition(&mut sampler, &paths).contains("host_cpu_busy_ratio"));
    }
    fixture.write("stat", "cpu 20 0 0 20 0 0 0 0\n");
    assert!(
        !exposition(&mut sampler, &paths).contains("host_cpu_busy_ratio"),
        "invalid sample breaks the delta chain"
    );
    fixture.write("stat", "cpu 30 0 0 30 0 0 0 0\n");
    assert_eq!(
        value(&exposition(&mut sampler, &paths), "host_cpu_busy_ratio"),
        Some(0.5)
    );
    fixture.remove("stat");
    assert!(
        exposition(&mut sampler, &paths).is_empty(),
        "all missing families are absent"
    );
}
