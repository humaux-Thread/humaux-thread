//! `telemetry::host` — the §41.2 host resource families read from procfs: PSI `avg60` per resource, `MemAvailable`
//!   in bytes and the `/proc/stat` CPU busy ratio; [`publish`] is their one emit point, [`render`] their exposition.
//! Depends-on: crates=[]; services=[fs(procfs reads)]; env=[]; modules=[telemetry::metrics]
//! Called-by: [maintenance::health_serve, tests]
//! Invariants: [a family whose source file is missing or unparsable carries no sample at all, never a 0 (§4.4);
//!   every family's HELP/TYPE is written from the first scrape, so `--metrics-families` and a live scrape name the
//!   same family set; the CPU ratio is the delta of two `/proc/stat` readings and the first reading yields none,
//!   as does a zero delta (no division by zero); every label value is a `&'static str` from a closed enum]
//! Spec: Baseline §41.2; §4.4; §42; ADR-0061 D-A
//!
//! The sampler is `humaux-maintenance health serve` (the ADR-0061 D-D owner of the resident gauges): it holds one
//! [`Reader`], publishes each reading, and every scrape renders the last publish — no scrape opens a file. No
//! function here reads the environment (§78.3): the caller passes the [`HostPaths`] it was configured with, and
//! [`HostPaths::under`] is how a test points the same code at fixture files.
//!
//! §4.4 is the point of this module: a missing or unparsable source must not become a 0, because a 0 is
//! indistinguishable from a healthy idle host and would keep a capacity rule silent. Absent means absent.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::metrics::{Gauges, families, write_family};

/// §41.2 frozen `host_pressure_ratio.resource` values: the `/proc/pressure/<resource>` file, one per cgroup resource
/// the kernel tracks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureResource {
    /// `/proc/pressure/cpu`: tasks waiting for a CPU.
    Cpu,
    /// `/proc/pressure/memory`: tasks stalled on reclaim or swap.
    Memory,
    /// `/proc/pressure/io`: tasks stalled on block I/O.
    Io,
}

impl PressureResource {
    /// Every resource, in render order.
    pub const ALL: [PressureResource; 3] = [Self::Cpu, Self::Memory, Self::Io];

    /// The §41.2 label value, which is also the file name under the pressure directory.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::Io => "io",
        }
    }
}

/// §41.2 frozen `host_pressure_ratio.kind` values: the two PSI stall classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureKind {
    /// `some`: at least one task was stalled.
    Some,
    /// `full`: every task was stalled. The kernel emits no `full` line for `cpu`, so that series never exists.
    Full,
}

impl PressureKind {
    /// Every kind, in render order.
    pub const ALL: [PressureKind; 2] = [Self::Some, Self::Full];

    /// The §41.2 label value, also the line's first word in the pressure file.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Some => "some",
            Self::Full => "full",
        }
    }

    fn from_line(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == word)
    }
}

/// The three procfs paths this module reads. Configuration, not a business constant: the caller decides where they
/// point, and [`HostPaths::default`] is this kernel's own procfs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPaths {
    /// Directory holding `cpu`, `memory` and `io`; the kernel's is `/proc/pressure`.
    pub pressure_dir: PathBuf,
    /// The meminfo file; the kernel's is `/proc/meminfo`.
    pub meminfo: PathBuf,
    /// The stat file; the kernel's is `/proc/stat`.
    pub stat: PathBuf,
}

impl Default for HostPaths {
    fn default() -> Self {
        Self {
            pressure_dir: PathBuf::from("/proc/pressure"),
            meminfo: PathBuf::from("/proc/meminfo"),
            stat: PathBuf::from("/proc/stat"),
        }
    }
}

impl HostPaths {
    /// The three paths under one directory — `dir/pressure/{cpu,memory,io}`, `dir/meminfo`, `dir/stat` — so a test
    /// can drive the real reader against fixture files instead of procfs.
    pub fn under(dir: &Path) -> Self {
        Self {
            pressure_dir: dir.join("pressure"),
            meminfo: dir.join("meminfo"),
            stat: dir.join("stat"),
        }
    }
}

/// One reading of the three host sources. A source missing from this value (no entry, or `None`) renders no sample
/// at all; it never becomes a 0 (§4.4).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostReading {
    /// PSI `avg60` per resource and stall kind the pressure files carried (0–1, not percent).
    pub pressure: Vec<(PressureResource, PressureKind, f64)>,
    /// `/proc/meminfo` `MemAvailable` in bytes.
    pub memory_available_bytes: Option<f64>,
    /// `/proc/stat` busy ratio over the interval since the previous reading of the same [`Reader`].
    pub cpu_busy_ratio: Option<f64>,
}

/// The six `host_pressure_ratio` slots, in render order (the slot index is the position here).
const PRESSURE_SLOTS: [(PressureResource, PressureKind); 6] = [
    (PressureResource::Cpu, PressureKind::Some),
    (PressureResource::Cpu, PressureKind::Full),
    (PressureResource::Memory, PressureKind::Some),
    (PressureResource::Memory, PressureKind::Full),
    (PressureResource::Io, PressureKind::Some),
    (PressureResource::Io, PressureKind::Full),
];

/// Number of `host_pressure_ratio` slots: one per [`PRESSURE_SLOTS`] entry.
const PRESSURE_SLOTS_LEN: usize = PRESSURE_SLOTS.len();

static HOST_PRESSURE_RATIO: Gauges<{ PRESSURE_SLOTS_LEN }> = Gauges::new();
static PRESSURE_PRESENT: [AtomicBool; PRESSURE_SLOTS_LEN] =
    [const { AtomicBool::new(false) }; PRESSURE_SLOTS_LEN];
static HOST_MEMORY_AVAILABLE_BYTES: Gauges<1> = Gauges::new();
static MEMORY_PRESENT: AtomicBool = AtomicBool::new(false);
static HOST_CPU_BUSY_RATIO: Gauges<1> = Gauges::new();
static CPU_PRESENT: AtomicBool = AtomicBool::new(false);
/// The empty label set of the two unlabeled families.
const NO_LABELS: &[&'static str] = &[];

/// Publishes one reading: every slot the reading carries is set, every other slot loses its sample, so a source
/// that stopped being readable stops being scraped instead of leaving a stale or invented value (§4.4).
pub fn publish(reading: &HostReading) {
    for (slot, (resource, kind)) in PRESSURE_SLOTS.iter().enumerate() {
        let value = reading
            .pressure
            .iter()
            .find(|(r, k, _)| r == resource && k == kind)
            .map(|(_, _, v)| *v);
        PRESSURE_PRESENT[slot].store(value.is_some(), Ordering::Relaxed);
        if let Some(value) = value {
            // labels: resource,kind
            HOST_PRESSURE_RATIO.set(slot, value);
        }
    }
    MEMORY_PRESENT.store(reading.memory_available_bytes.is_some(), Ordering::Relaxed);
    if let Some(bytes) = reading.memory_available_bytes {
        HOST_MEMORY_AVAILABLE_BYTES.set(0, bytes);
    }
    CPU_PRESENT.store(reading.cpu_busy_ratio.is_some(), Ordering::Relaxed);
    if let Some(ratio) = reading.cpu_busy_ratio {
        HOST_CPU_BUSY_RATIO.set(0, ratio);
    }
}

/// Renders the three families from the last [`publish`]. Every header is written even while a source is absent, so
/// `--metrics-families` and a live scrape always name the same family set (ADR-0061 D-C / D-H).
pub fn render(out: &mut String) {
    let mut pressure: Vec<([&'static str; 2], f64)> = Vec::new();
    for (slot, (resource, kind)) in PRESSURE_SLOTS.iter().enumerate() {
        if PRESSURE_PRESENT[slot].load(Ordering::Relaxed) {
            pressure.push((
                [resource.as_str(), kind.as_str()],
                HOST_PRESSURE_RATIO.get(slot),
            ));
        }
    }
    let samples: Vec<(&[&'static str], f64)> = pressure
        .iter()
        .map(|(labels, value)| (labels.as_slice(), *value))
        .collect();
    write_family(out, &families::HOST_PRESSURE_RATIO, &samples);
    let memory: Vec<(&[&'static str], f64)> = MEMORY_PRESENT
        .load(Ordering::Relaxed)
        .then_some((NO_LABELS, HOST_MEMORY_AVAILABLE_BYTES.get(0)))
        .into_iter()
        .collect();
    write_family(out, &families::HOST_MEMORY_AVAILABLE_BYTES, &memory);
    let busy: Vec<(&[&'static str], f64)> = CPU_PRESENT
        .load(Ordering::Relaxed)
        .then_some((NO_LABELS, HOST_CPU_BUSY_RATIO.get(0)))
        .into_iter()
        .collect();
    write_family(out, &families::HOST_CPU_BUSY_RATIO, &busy);
}

/// Reads the three procfs sources and holds the previous `/proc/stat` counters, so the busy ratio is the delta
/// between two readings of the same reader.
pub struct Reader {
    paths: HostPaths,
    previous: Option<CpuTimes>,
}

impl Reader {
    /// A reader over `paths`; its first [`Reader::read`] never yields a CPU ratio, it only stores the counters.
    pub fn new(paths: HostPaths) -> Self {
        Self {
            paths,
            previous: None,
        }
    }

    /// One reading of all three sources. Never fails: a missing or unparsable source is absent from the value, which
    /// is the signal every consumer renders (§4.4).
    // dep: fs(procfs reads) — read-only procfs; a missing file is an absent family, never a 0 (§4.4)
    pub fn read(&mut self) -> HostReading {
        HostReading {
            pressure: read_pressure(&self.paths.pressure_dir),
            memory_available_bytes: std::fs::read_to_string(&self.paths.meminfo)
                .ok()
                .and_then(|text| parse_memory_available_bytes(&text)),
            cpu_busy_ratio: self.read_cpu_busy(),
        }
    }

    fn read_cpu_busy(&mut self) -> Option<f64> {
        match std::fs::read_to_string(&self.paths.stat)
            .ok()
            .and_then(|text| parse_cpu_times(&text))
        {
            Some(current) => busy_ratio(self.previous.replace(current)?, current),
            None => {
                // The interval a later reading covers is unknown after a gap, so the next good reading starts over.
                self.previous = None;
                None
            }
        }
    }
}

fn read_pressure(dir: &Path) -> Vec<(PressureResource, PressureKind, f64)> {
    let mut out = Vec::new();
    for resource in PressureResource::ALL {
        let Ok(text) = std::fs::read_to_string(dir.join(resource.as_str())) else {
            continue;
        };
        for (kind, ratio) in parse_pressure(&text) {
            out.push((resource, kind, ratio));
        }
    }
    out
}

/// The `avg60` of every parsable `<kind> avg10=… avg60=… avg300=… total=…` line, as a 0–1 ratio. A line without a
/// parsable `avg60` contributes nothing: the caller then renders no sample for it, never a 0 (§4.4).
// ponytail: avg60 only — the window the §42 capacity rules use; avg10/avg300 would need more label values.
fn parse_pressure(text: &str) -> Vec<(PressureKind, f64)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(kind) = fields.next().and_then(PressureKind::from_line) else {
            continue;
        };
        let Some(percent) = fields
            .find_map(|field| field.strip_prefix("avg60="))
            .and_then(|value| value.parse::<f64>().ok())
        else {
            continue;
        };
        if percent.is_finite() && percent >= 0.0 {
            out.push((kind, percent / 100.0));
        }
    }
    out
}

/// `MemAvailable` in bytes, bounded by `MemTotal`: a reading above the total is malformed rather than clamped, since
/// a made-up number is exactly the 0-class lie §4.4 forbids.
fn parse_memory_available_bytes(text: &str) -> Option<f64> {
    let available_kb = meminfo_kb(text, "MemAvailable:")?;
    let total_kb = meminfo_kb(text, "MemTotal:")?;
    if available_kb > total_kb {
        return None;
    }
    Some(available_kb as f64 * 1024.0)
}

fn meminfo_kb(text: &str, key: &str) -> Option<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix(key))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// `/proc/stat`'s aggregate `cpu` line reduced to what the busy ratio needs: `idle + iowait` and the sum of the
/// first eight fields (user..steal; `guest` already sits inside `user`, so summing it would double-count).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CpuTimes {
    idle: u64,
    total: u64,
}

fn parse_cpu_times(text: &str) -> Option<CpuTimes> {
    let line = text
        .lines()
        .find(|line| line.split_whitespace().next() == Some("cpu"))?;
    let fields: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .take(8)
        .map(|field| field.parse().ok())
        .collect::<Option<Vec<u64>>>()?;
    if fields.len() < 4 {
        // user, nice, system, idle are the kernel's immutable first four columns.
        return None;
    }
    let idle = fields[3] + fields.get(4).copied().unwrap_or(0);
    let total = fields.iter().sum();
    Some(CpuTimes { idle, total })
}

/// `1 − Δ(idle + iowait) / Δtotal`. `None` when the counters did not advance: a zero delta must not divide by zero,
/// and a fabricated 0 would read as an idle host (§4.4).
fn busy_ratio(previous: CpuTimes, current: CpuTimes) -> Option<f64> {
    let total = current.total.checked_sub(previous.total)?;
    if total == 0 {
        return None;
    }
    let idle = current.idle.saturating_sub(previous.idle).min(total);
    let busy = 1.0 - (idle as f64 / total as f64);
    busy.is_finite().then(|| busy.clamp(0.0, 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_file(dir: &Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).unwrap();
    }

    fn write_pressure(dir: &Path, resource: PressureResource, body: &str) {
        std::fs::write(dir.join("pressure").join(resource.as_str()), body).unwrap();
    }

    fn fixture(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("humaux-host-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("pressure")).unwrap();
        dir
    }

    fn pressure_line(kind: PressureKind, avg60: &str) -> String {
        format!(
            "{} avg10=0.00 avg60={avg60} avg300=0.00 total=100\n",
            kind.as_str()
        )
    }

    #[test]
    fn parse_pressure_takes_avg60_and_skips_unparsable_lines() {
        let text = format!(
            "{}{}garbage\n",
            pressure_line(PressureKind::Some, "12.5"),
            pressure_line(PressureKind::Full, "oops"),
        );
        assert_eq!(
            parse_pressure(&text),
            vec![(PressureKind::Some, 0.125)],
            "an unparsable avg60 yields no sample, never a 0"
        );
        assert!(parse_pressure("").is_empty());
    }

    #[test]
    fn meminfo_available_is_bounded_by_total() {
        assert_eq!(
            parse_memory_available_bytes("MemTotal: 1000 kB\nMemAvailable: 400 kB\n"),
            Some(409_600.0)
        );
        assert_eq!(
            parse_memory_available_bytes("MemAvailable: 400 kB\n"),
            None,
            "MemTotal is the bound; without it the reading is not trusted"
        );
        assert_eq!(
            parse_memory_available_bytes("MemTotal: 1000 kB\nMemAvailable: 2000 kB\n"),
            None,
            "above the total is malformed, not clamped"
        );
        assert_eq!(
            parse_memory_available_bytes("MemTotal: 1000 kB\nMemAvailable: many kB\n"),
            None
        );
    }

    #[test]
    fn cpu_busy_is_the_second_deltas_ratio_and_zero_delta_yields_none() {
        let dir = fixture("cpu");
        let mut reader = Reader::new(HostPaths::under(&dir));
        write_file(
            &dir,
            "stat",
            "cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 1 2 3 4\n",
        );
        assert_eq!(
            reader.read().cpu_busy_ratio,
            None,
            "the first reading only stores the counters"
        );
        write_file(
            &dir,
            "stat",
            "cpu  200 0 200 900 0 0 0 0 0 0\ncpu0 1 2 3 4\n",
        );
        let busy = reader.read().cpu_busy_ratio.expect("a second reading");
        assert!(
            (busy - 2.0 / 3.0).abs() < 1e-12,
            "busy = 1 - 100/300, got {busy}"
        );
        assert_eq!(
            reader.read().cpu_busy_ratio,
            None,
            "counter deltas of zero must not divide by zero"
        );
        std::fs::remove_file(dir.join("stat")).unwrap();
        assert_eq!(reader.read().cpu_busy_ratio, None);
        write_file(&dir, "stat", "cpu  300 0 300 1000 0 0 0 0 0 0\n");
        assert_eq!(
            reader.read().cpu_busy_ratio,
            None,
            "the interval across a gap is unknown, so the next reading starts over"
        );
    }

    /// The only lib test that publishes: all other tests here are pure or fixture-only, so no test races the statics.
    #[test]
    fn absent_sources_render_no_sample_and_never_zero() {
        let dir = fixture("publish");
        let mut reader = Reader::new(HostPaths::under(&dir));
        write_pressure(
            &dir,
            PressureResource::Cpu,
            &pressure_line(PressureKind::Some, "50.00"),
        );
        write_pressure(
            &dir,
            PressureResource::Memory,
            &format!(
                "{}{}",
                pressure_line(PressureKind::Some, "25.00"),
                pressure_line(PressureKind::Full, "10.00"),
            ),
        );
        write_file(&dir, "meminfo", "MemTotal: 1000 kB\nMemAvailable: 400 kB\n");
        write_file(&dir, "stat", "cpu  100 0 100 800 0 0 0 0\n");

        publish(&reader.read());
        let mut out = String::new();
        render(&mut out);
        assert!(
            out.contains("host_pressure_ratio{resource=\"cpu\",kind=\"some\"} 0.5\n"),
            "{out}"
        );
        assert!(
            out.contains("host_pressure_ratio{resource=\"memory\",kind=\"full\"} 0.1\n"),
            "{out}"
        );
        assert!(
            !out.contains("resource=\"cpu\",kind=\"full\""),
            "the kernel has no full cpu line, so no series may be invented: {out}"
        );
        assert!(!out.contains("resource=\"io\""), "{out}");
        assert!(
            out.contains("\nhost_memory_available_bytes 409600\n"),
            "{out}"
        );
        assert!(
            !out.contains("\nhost_cpu_busy_ratio "),
            "a first reading yields no ratio: {out}"
        );

        std::fs::remove_file(dir.join("pressure").join(PressureResource::Cpu.as_str())).unwrap();
        publish(&reader.read());
        let mut out = String::new();
        render(&mut out);
        assert!(
            !out.contains("host_pressure_ratio{resource=\"cpu\""),
            "a missing /proc/pressure/cpu must render no cpu sample, never a 0: {out}"
        );
        assert!(
            out.contains("host_pressure_ratio{resource=\"memory\",kind=\"some\"}"),
            "the other resources still render: {out}"
        );

        write_pressure(
            &dir,
            PressureResource::Io,
            &pressure_line(PressureKind::Some, "oops"),
        );
        publish(&reader.read());
        let mut out = String::new();
        render(&mut out);
        assert!(
            !out.contains("resource=\"io\""),
            "an unparsable file renders no series, never a 0: {out}"
        );

        std::fs::remove_file(dir.join("pressure").join(PressureResource::Memory.as_str())).unwrap();
        std::fs::remove_file(dir.join("meminfo")).unwrap();
        publish(&reader.read());
        let mut out = String::new();
        render(&mut out);
        for family in [
            "host_pressure_ratio",
            "host_memory_available_bytes",
            "host_cpu_busy_ratio",
        ] {
            assert!(
                out.contains(&format!("# TYPE {family} gauge\n")),
                "the header stays so --metrics-families names the family: {out}"
            );
            assert!(
                !out.lines()
                    .any(|line| !line.starts_with('#') && line.starts_with(family)),
                "no source is readable, so {family} has no sample: {out}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
