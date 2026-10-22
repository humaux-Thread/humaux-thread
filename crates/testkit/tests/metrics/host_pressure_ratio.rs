// witness: family=host_pressure_ratio labels=resource,kind
//! `testkit::tests::metrics::host_pressure_ratio` — Metric Witness for `host_pressure_ratio{resource,kind}` (§80.2
//!   W-side; registry row §41.2: `humaux-maintenance health serve` 每个采样周期 · 1; consumer §42 capacity rules).
//! Depends-on: crates=[humaux-telemetry]; services=[]; env=[]; modules=[telemetry::host]
//! Called-by: []
//! Invariants: [drives the family's one `.set(` through `telemetry::host::publish`; the present, missing, malformed
//!   and no-`full`-line fixtures render exactly the series their source carries; a missing or unparsable source
//!   renders no series at all, never a 0 (§4.4)]
//! Spec: Baseline §41.2; §4.4; §42; §80.2; ADR-0061 D-A
//!
//! G-M22-1's gate file, so its assertion is the invariant itself: with `/proc/pressure/cpu` missing, no
//! `resource="cpu"` sample may appear. The red record mutates `telemetry::host::read_pressure` into writing 0 for
//! the missing file, and this file goes red on the `cpu` series. Compiled and run standalone by
//! `cargo xtask metrics-registry` (`run_witness_probe`).

use std::path::{Path, PathBuf};

use humaux_telemetry::host::{
    HostPaths, PressureKind, PressureResource, Reader, publish, render,
};

fn fixture(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "humaux-witness-host-pressure-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("pressure")).expect("fixture pressure dir");
    dir
}

fn write_pressure(dir: &Path, resource: PressureResource, body: &str) {
    std::fs::write(dir.join("pressure").join(resource.as_str()), body).expect("fixture pressure file");
}

/// One `avg10=… avg60=… avg300=… total=…` line, the kernel's own shape.
fn line(kind: PressureKind, avg60: &str) -> String {
    format!(
        "{} avg10=0.00 avg60={avg60} avg300=0.00 total=1024\n",
        kind.as_str()
    )
}

/// `(label set verbatim, value)` per rendered sample, in file order.
fn samples(out: &str) -> Vec<(String, f64)> {
    out.lines()
        .filter(|l| l.starts_with("host_pressure_ratio{"))
        .map(|l| {
            let (labels, value) = l.rsplit_once(' ').expect("a sample has a value");
            (labels.to_string(), value.parse().expect("a bare float"))
        })
        .collect()
}

/// G-M22-1: each `resource`/`kind` series exists only while its own line parses; a missing `cpu` file leaves the
/// family present (memory, io) but with no `cpu` sample at all.
#[test]
fn pressure_series_exist_only_while_their_source_parses() {
    let dir = fixture("gate");
    write_pressure(&dir, PressureResource::Cpu, &line(PressureKind::Some, "50.00"));
    write_pressure(
        &dir,
        PressureResource::Memory,
        &format!(
            "{}{}",
            line(PressureKind::Some, "25.00"),
            line(PressureKind::Full, "10.00"),
        ),
    );
    write_pressure(
        &dir,
        PressureResource::Io,
        &format!(
            "{}{}",
            line(PressureKind::Some, "5.00"),
            line(PressureKind::Full, "1.00"),
        ),
    );
    let mut reader = Reader::new(HostPaths::under(&dir));

    publish(&reader.read());
    let mut out = String::new();
    render(&mut out);
    assert!(
        out.contains("# TYPE host_pressure_ratio gauge\n"),
        "the family must be declared: {out}"
    );
    let got = samples(&out);
    let labels: Vec<&str> = got.iter().map(|(labels, _)| labels.as_str()).collect();
    assert_eq!(
        labels,
        [
            "host_pressure_ratio{resource=\"cpu\",kind=\"some\"}",
            "host_pressure_ratio{resource=\"memory\",kind=\"some\"}",
            "host_pressure_ratio{resource=\"memory\",kind=\"full\"}",
            "host_pressure_ratio{resource=\"io\",kind=\"some\"}",
            "host_pressure_ratio{resource=\"io\",kind=\"full\"}",
        ],
        "the §41.2 label keys and the cpu file's missing full line: {out}"
    );
    let expected = [0.5, 0.25, 0.1, 0.05, 0.01];
    for (index, (_, value)) in got.iter().enumerate() {
        assert!(
            (value - expected[index]).abs() < 1e-12,
            "avg60 is a 0-1 ratio: expected {}, got {value} in {out}",
            expected[index]
        );
    }

    std::fs::remove_file(dir.join("pressure").join(PressureResource::Cpu.as_str()))
        .expect("remove the cpu source");
    publish(&reader.read());
    let mut out = String::new();
    render(&mut out);
    assert!(
        !out.contains("resource=\"cpu\""),
        "a missing /proc/pressure/cpu must render no cpu series, never a 0 (G-M22-1): {out}"
    );
    assert_eq!(
        samples(&out).len(),
        4,
        "the other resources still render: {out}"
    );

    write_pressure(
        &dir,
        PressureResource::Io,
        &line(PressureKind::Some, "not-a-number"),
    );
    publish(&reader.read());
    let mut out = String::new();
    render(&mut out);
    assert!(
        !out.contains("resource=\"io\""),
        "an unparsable avg60 renders no io series, never a 0: {out}"
    );

    std::fs::remove_file(dir.join("pressure").join(PressureResource::Memory.as_str()))
        .expect("remove the memory source");
    publish(&reader.read());
    let mut out = String::new();
    render(&mut out);
    assert!(
        samples(&out).is_empty(),
        "no readable source means no sample at all: {out}"
    );
    assert!(
        out.contains("# TYPE host_pressure_ratio gauge\n"),
        "the header stays while every source is absent: {out}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
