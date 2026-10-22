//! `telemetry::host` — the three §41.2 host families of M22-1 (PSI pressure, MemAvailable, CPU busy): [`HostSampler`]
//!   reads them from `/proc`, `publish()` is their one emit point and `render()` their exposition.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[telemetry::metrics]
//! Called-by: [maintenance::health_serve, tests]
//! Invariants: [a series renders only from a value parsed in the latest publish: a missing, unreadable or malformed
//!   source leaves its series (or whole family) out and is never written as 0; before the first publish nothing
//!   renders; the CPU busy ratio is the delta of two readable /proc/stat samples, absent for the first sample and
//!   for a zero total delta; publish() holds exactly one `.set(` per family]
//! Spec: Baseline §41.2; §4.4; §78.1; §78.3
//!
//! §4.4: "not scanned" is not "none". A host without PSI (kernel < 4.20, `psi=0`, no `full` line on older CPU
//! files) therefore exposes fewer series, and a rule over them sees an absent vector, not a calm host. The read
//! paths are [`HostSources`] values passed in by the caller (no environment read here, §78.3); its default is the
//! real `/proc` layout, so a test points the same code at fixture files.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::metrics::{Gauges, families, write_family};

/// §41.2 frozen `host_pressure_ratio.resource` values (the `/proc/pressure/<name>` file names).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    /// `/proc/pressure/cpu`.
    Cpu,
    /// `/proc/pressure/memory`.
    Memory,
    /// `/proc/pressure/io`.
    Io,
}

impl Resource {
    /// Every resource, in render order (the slot order of [`HostSources::pressure`]).
    pub const ALL: [Resource; 3] = [Self::Cpu, Self::Memory, Self::Io];

    /// The label value, verbatim §41.2.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::Io => "io",
        }
    }
}

/// §41.2 frozen `host_pressure_ratio.kind` values (the line prefix in a PSI file).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureKind {
    /// Some tasks stalled.
    Some,
    /// All non-idle tasks stalled; the cpu file has no such line before kernel 5.13.
    Full,
}

impl PressureKind {
    /// Every kind, in render order.
    pub const ALL: [PressureKind; 2] = [Self::Some, Self::Full];

    /// The label value, verbatim §41.2.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Some => "some",
            Self::Full => "full",
        }
    }
}

/// Where each source is read. [`Default`] is the real `/proc` layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSources {
    /// One PSI file per [`Resource::ALL`] slot.
    pub pressure: [PathBuf; 3],
    /// `/proc/meminfo`.
    pub meminfo: PathBuf,
    /// `/proc/stat`.
    pub stat: PathBuf,
}

impl Default for HostSources {
    fn default() -> Self {
        Self {
            pressure: Resource::ALL.map(|r| Path::new("/proc/pressure").join(r.as_str())),
            meminfo: PathBuf::from("/proc/meminfo"),
            stat: PathBuf::from("/proc/stat"),
        }
    }
}

/// One sample of the host. `None` = that source was missing, unreadable or malformed: its series is left out.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostReading {
    /// PSI `avg60 / 100` per [`Resource::ALL`] row and [`PressureKind::ALL`] column.
    pub pressure_ratio: [[Option<f64>; 2]; 3],
    /// `MemAvailable` in bytes.
    pub memory_available_bytes: Option<f64>,
    /// Busy share of the interval since the previous sample; `None` for the first sample.
    pub cpu_busy_ratio: Option<f64>,
}

/// Cumulative `/proc/stat` jiffies of the aggregate `cpu` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuTimes {
    busy: u64,
    total: u64,
}

/// `avg60` of the first `kind` line of a PSI file, as a ratio in 0..=1. A value outside 0..=100 or not a finite
/// number is malformed, so the series is absent rather than clamped.
fn avg60_ratio(text: &str, kind: PressureKind) -> Option<f64> {
    text.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        if words.next()? != kind.as_str() {
            return None;
        }
        let percent: f64 = words.find_map(|w| w.strip_prefix("avg60="))?.parse().ok()?;
        (percent.is_finite() && (0.0..=100.0).contains(&percent)).then_some(percent / 100.0)
    })
}

/// Both PSI lines of one file, each independently: a file without its `full` line still yields `some`.
pub fn parse_pressure(text: &str) -> [Option<f64>; 2] {
    PressureKind::ALL.map(|kind| avg60_ratio(text, kind))
}

/// `MemAvailable` of a `/proc/meminfo` text in bytes. `MemTotal` must be present and at least `MemAvailable`: a
/// file failing that is not a meminfo this code understands.
pub fn parse_mem_available(text: &str) -> Option<f64> {
    let kib = |key: &str| {
        text.lines().find_map(|line| {
            let mut words = line
                .strip_prefix(key)?
                .strip_prefix(':')?
                .split_whitespace();
            let n: u64 = words.next()?.parse().ok()?;
            (words.next() == Some("kB") && words.next().is_none()).then_some(n)
        })
    };
    let (available, total) = (kib("MemAvailable")?, kib("MemTotal")?);
    if total == 0 || available > total {
        return None;
    }
    available.checked_mul(1024).map(|bytes| bytes as f64)
}

/// The aggregate `cpu` line of a `/proc/stat` text. Busy = total − idle − iowait; guest time is already inside
/// user, so it is not added twice.
pub fn parse_cpu_times(text: &str) -> Option<CpuTimes> {
    let line = text
        .lines()
        .find(|l| l.split_whitespace().next() == Some("cpu"))?;
    let jiffies: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .take(8)
        .map(|w| w.parse::<u64>().ok())
        .collect::<Option<_>>()?;
    // user, nice, system, idle are the four every kernel prints; iowait..steal follow on any kernel since 2.6.11.
    if jiffies.len() < 4 {
        return None;
    }
    let total = jiffies.iter().try_fold(0u64, |a, j| a.checked_add(*j))?;
    let idle = jiffies[3] + jiffies.get(4).copied().unwrap_or(0);
    Some(CpuTimes {
        busy: total - idle,
        total,
    })
}

/// Busy share between two readings. `None` when the total did not advance (no division by zero) or a counter went
/// backwards (reset); the result is clamped to 1 because the idle counters are not strictly monotonic.
pub fn busy_ratio(prev: CpuTimes, cur: CpuTimes) -> Option<f64> {
    let total = cur.total.checked_sub(prev.total).filter(|t| *t > 0)?;
    let busy = cur.busy.checked_sub(prev.busy)?;
    Some((busy as f64 / total as f64).min(1.0))
}

fn read(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Reads [`HostSources`] and keeps the previous `/proc/stat` reading the CPU delta needs.
#[derive(Debug)]
pub struct HostSampler {
    sources: HostSources,
    prev_cpu: Option<CpuTimes>,
}

impl HostSampler {
    /// A sampler with no previous CPU reading, so its first [`sample`](Self::sample) carries no busy ratio.
    pub fn new(sources: HostSources) -> Self {
        Self {
            sources,
            prev_cpu: None,
        }
    }

    /// Reads every source once. A source that cannot be read or parsed yields `None` for its series; an
    /// unreadable `/proc/stat` also drops the previous reading, so the next busy ratio is again a first sample.
    pub fn sample(&mut self) -> HostReading {
        let mut pressure_ratio = [[None; 2]; 3];
        for (row, path) in pressure_ratio.iter_mut().zip(&self.sources.pressure) {
            *row = read(path).map_or([None; 2], |text| parse_pressure(&text));
        }
        let cpu = read(&self.sources.stat).and_then(|text| parse_cpu_times(&text));
        let cpu_busy_ratio = self.prev_cpu.zip(cpu).and_then(|(p, c)| busy_ratio(p, c));
        self.prev_cpu = cpu;
        HostReading {
            pressure_ratio,
            memory_available_bytes: read(&self.sources.meminfo)
                .and_then(|text| parse_mem_available(&text)),
            cpu_busy_ratio,
        }
    }
}

const fn slot(resource: usize, kind: usize) -> usize {
    resource * PressureKind::ALL.len() + kind
}

static PUBLISHED: AtomicBool = AtomicBool::new(false);
static HOST_PRESSURE_RATIO: Gauges<{ Resource::ALL.len() * PressureKind::ALL.len() }> =
    Gauges::new();
static HOST_MEMORY_AVAILABLE_BYTES: Gauges<1> = Gauges::new();
static HOST_CPU_BUSY_RATIO: Gauges<1> = Gauges::new();

/// An absent value is stored as NaN, which no parser can produce.
fn stored(v: Option<f64>) -> f64 {
    v.filter(|x| x.is_finite()).unwrap_or(f64::NAN)
}

fn loaded(v: f64) -> Option<f64> {
    (!v.is_nan()).then_some(v)
}

/// Publishes one reading: every series is set, an absent one as absent (not 0), so a source that disappears
/// between samples also disappears from the exposition.
pub fn publish(r: &HostReading) {
    for (ri, row) in r.pressure_ratio.iter().enumerate() {
        for (ki, v) in row.iter().enumerate() {
            // labels: resource,kind
            HOST_PRESSURE_RATIO.set(slot(ri, ki), stored(*v));
        }
    }
    // labels: -
    HOST_MEMORY_AVAILABLE_BYTES.set(0, stored(r.memory_available_bytes));
    // labels: -
    HOST_CPU_BUSY_RATIO.set(0, stored(r.cpu_busy_ratio));
    PUBLISHED.store(true, Ordering::Release);
}

fn write_reading(out: &mut String, r: &HostReading) {
    let mut pressure: Vec<([&'static str; 2], f64)> = Vec::new();
    for (resource, row) in Resource::ALL.into_iter().zip(&r.pressure_ratio) {
        for (kind, v) in PressureKind::ALL.into_iter().zip(row) {
            if let Some(v) = v {
                pressure.push(([resource.as_str(), kind.as_str()], *v));
            }
        }
    }
    if !pressure.is_empty() {
        let samples: Vec<(&[&'static str], f64)> = pressure
            .iter()
            .map(|(labels, v)| (labels.as_slice(), *v))
            .collect();
        write_family(out, &families::HOST_PRESSURE_RATIO, &samples);
    }
    for (family, value) in [
        (
            &families::HOST_MEMORY_AVAILABLE_BYTES,
            r.memory_available_bytes,
        ),
        (&families::HOST_CPU_BUSY_RATIO, r.cpu_busy_ratio),
    ] {
        if let Some(v) = value {
            write_family(out, family, &[(&[], v)]);
        }
    }
}

/// Renders the series of the last [`publish`]. Before the first publish, and for every absent series, nothing is
/// written, not even a `# TYPE` line (§4.4: an empty family is not a zero).
pub fn render(out: &mut String) {
    if !PUBLISHED.load(Ordering::Acquire) {
        return;
    }
    let mut pressure_ratio = [[None; 2]; 3];
    for (ri, row) in pressure_ratio.iter_mut().enumerate() {
        for (ki, cell) in row.iter_mut().enumerate() {
            *cell = loaded(HOST_PRESSURE_RATIO.get(slot(ri, ki)));
        }
    }
    write_reading(
        out,
        &HostReading {
            pressure_ratio,
            memory_available_bytes: loaded(HOST_MEMORY_AVAILABLE_BYTES.get(0)),
            cpu_busy_ratio: loaded(HOST_CPU_BUSY_RATIO.get(0)),
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const PSI: &str = "some avg10=0.00 avg60=12.50 avg300=3.00 total=123456\nfull avg10=0.00 avg60=50.00 avg300=0.00 total=0\n";
    const MEMINFO: &str =
        "MemTotal:       8388608 kB\nMemFree:          1024 kB\nMemAvailable:   4194304 kB\n";
    const STAT_1: &str = "cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 100 0 100 800 0 0 0 0 0 0\n";
    const STAT_2: &str = "cpu  150 0 150 900 0 0 0 0 0 0\ncpu0 150 0 150 900 0 0 0 0 0 0\n";

    /// A fresh fixture directory laid out like `/proc`, with every source present.
    fn fixture(tag: &str) -> (PathBuf, HostSources) {
        let dir = std::env::temp_dir().join(format!("host-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let sources = HostSources {
            pressure: Resource::ALL.map(|r| dir.join(format!("pressure-{}", r.as_str()))),
            meminfo: dir.join("meminfo"),
            stat: dir.join("stat"),
        };
        for p in &sources.pressure {
            std::fs::write(p, PSI).expect("psi fixture");
        }
        std::fs::write(&sources.meminfo, MEMINFO).expect("meminfo fixture");
        std::fs::write(&sources.stat, STAT_1).expect("stat fixture");
        (dir, sources)
    }

    fn rendered(r: &HostReading) -> String {
        let mut out = String::new();
        write_reading(&mut out, r);
        out
    }

    #[test]
    fn default_sources_are_the_real_proc_paths() {
        let d = HostSources::default();
        assert_eq!(d.pressure[0], PathBuf::from("/proc/pressure/cpu"));
        assert_eq!(d.pressure[2], PathBuf::from("/proc/pressure/io"));
        assert_eq!(d.meminfo, PathBuf::from("/proc/meminfo"));
        assert_eq!(d.stat, PathBuf::from("/proc/stat"));
    }

    /// Each PSI line is parsed on its own: the cpu file of an older kernel has no `full` line.
    #[test]
    fn pressure_parses_each_line_independently() {
        assert_eq!(parse_pressure(PSI), [Some(0.125), Some(0.5)]);
        let cpu_old = "some avg10=0.00 avg60=25.00 avg300=0.00 total=1\n";
        assert_eq!(parse_pressure(cpu_old), [Some(0.25), None]);
        let broken_some = "some avg10=0.00 avg60=oops avg300=0.00 total=1\nfull avg10=0.00 avg60=100.00 avg300=0.00 total=1\n";
        assert_eq!(parse_pressure(broken_some), [None, Some(1.0)]);
        for bad in [
            "",
            "garbage\n",
            "some avg60=nan\n",
            "some avg60=101\n",
            "some avg60=-1\n",
            "some avg10=1.0\n",
        ] {
            assert_eq!(parse_pressure(bad), [None, None], "{bad:?}");
        }
    }

    #[test]
    fn meminfo_needs_a_sane_available_and_total() {
        assert_eq!(parse_mem_available(MEMINFO), Some(4_294_967_296.0));
        for bad in [
            "",
            "MemTotal: 10 kB\n",
            "MemAvailable: 10 kB\n",
            "MemTotal: 10 kB\nMemAvailable: 11 kB\n",
            "MemTotal: 0 kB\nMemAvailable: 0 kB\n",
            "MemTotal: 10 kB\nMemAvailable: x kB\n",
            "MemTotal: 10 kB\nMemAvailable: 5 MB\n",
        ] {
            assert_eq!(parse_mem_available(bad), None, "{bad:?}");
        }
    }

    /// The busy ratio is a delta; a first sample, a zero total delta and a counter reset carry no value.
    #[test]
    fn busy_ratio_is_a_delta_and_never_divides_by_zero() {
        let (a, b) = (
            parse_cpu_times(STAT_1).expect("stat 1"),
            parse_cpu_times(STAT_2).expect("stat 2"),
        );
        assert_eq!(busy_ratio(a, b), Some(0.5));
        assert_eq!(busy_ratio(a, a), None);
        assert_eq!(busy_ratio(b, a), None);
        assert_eq!(parse_cpu_times("cpu  1 2 3\n"), None);
        assert_eq!(parse_cpu_times("cpu  1 2 3 x\n"), None);
        assert_eq!(parse_cpu_times("intr 1 2 3 4\n"), None);
    }

    #[test]
    fn sampler_first_cpu_sample_has_no_ratio_second_has() {
        let (dir, sources) = fixture("cpu-delta");
        let mut sampler = HostSampler::new(sources.clone());
        let first = sampler.sample();
        assert_eq!(first.cpu_busy_ratio, None);
        assert_eq!(first.memory_available_bytes, Some(4_294_967_296.0));
        assert_eq!(first.pressure_ratio[1], [Some(0.125), Some(0.5)]);
        std::fs::write(&sources.stat, STAT_2).expect("stat 2");
        assert_eq!(sampler.sample().cpu_busy_ratio, Some(0.5));
        assert_eq!(sampler.sample().cpu_busy_ratio, None, "zero total delta");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// G-M22-1: a missing source is an absent series, never 0. Fault: write 0 for a missing
    /// `/proc/pressure/cpu` ⇒ the cpu series appear with 0 ⇒ red.
    #[test]
    fn missing_pressure_file_is_absent_not_zero() {
        let (dir, sources) = fixture("missing");
        std::fs::remove_file(&sources.pressure[0]).expect("remove cpu psi");
        let out = rendered(&HostSampler::new(sources).sample());
        assert!(!out.contains("resource=\"cpu\""), "{out}");
        assert!(
            out.contains("host_pressure_ratio{resource=\"memory\",kind=\"some\"} 0.125\n"),
            "{out}"
        );
        assert!(
            out.contains("host_pressure_ratio{resource=\"io\",kind=\"full\"} 0.5\n"),
            "{out}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn malformed_and_old_kernel_files_drop_only_their_series() {
        let (dir, sources) = fixture("malformed");
        std::fs::write(
            &sources.pressure[0],
            "some avg10=0.00 avg60=25.00 avg300=0.00 total=1\n",
        )
        .expect("old cpu");
        std::fs::write(&sources.pressure[1], "not a psi file\n").expect("garbage");
        std::fs::write(&sources.meminfo, "MemTotal: 1 kB\n").expect("bad meminfo");
        let out = rendered(&HostSampler::new(sources).sample());
        assert!(
            out.contains("host_pressure_ratio{resource=\"cpu\",kind=\"some\"} 0.25\n"),
            "{out}"
        );
        assert!(!out.contains("resource=\"cpu\",kind=\"full\""), "{out}");
        assert!(!out.contains("resource=\"memory\""), "{out}");
        assert!(out.contains("resource=\"io\",kind=\"full\""), "{out}");
        assert!(!out.contains("host_memory_available_bytes"), "{out}");
        assert!(!out.contains("host_cpu_busy_ratio"), "first sample: {out}");
        assert_eq!(rendered(&HostReading::default()), "");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The only lib test that publishes, so no other test races these statics.
    #[test]
    fn publish_renders_nothing_before_and_drops_a_series_that_goes_missing() {
        let mut out = String::new();
        render(&mut out);
        assert_eq!(out, "", "nothing renders before the first publish");
        let mut reading = HostReading {
            pressure_ratio: [[Some(0.25), None]; 3],
            memory_available_bytes: Some(1024.0),
            cpu_busy_ratio: Some(0.75),
        };
        publish(&reading);
        render(&mut out);
        for line in [
            "host_pressure_ratio{resource=\"cpu\",kind=\"some\"} 0.25",
            "host_pressure_ratio{resource=\"io\",kind=\"some\"} 0.25",
            "host_memory_available_bytes 1024",
            "host_cpu_busy_ratio 0.75",
        ] {
            assert!(out.lines().any(|l| l == line), "{line} missing in\n{out}");
        }
        assert!(!out.contains("kind=\"full\""), "{out}");
        reading.pressure_ratio[0] = [None, None];
        reading.cpu_busy_ratio = None;
        publish(&reading);
        let mut after = String::new();
        render(&mut after);
        assert!(!after.contains("resource=\"cpu\""), "{after}");
        assert!(!after.contains("host_cpu_busy_ratio"), "{after}");
        assert!(
            after.contains("host_memory_available_bytes 1024\n"),
            "{after}"
        );
    }
}
