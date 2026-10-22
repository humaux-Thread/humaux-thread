//! `telemetry::host` — read-only Linux host samples for the existing §41.2 exposition.
//! Depends-on: crates=[]; services=[fs(proc)]; env=[]; modules=[telemetry::metrics]
//! Called-by: [maintenance::health_serve, tests]
//! Invariants: [unavailable or invalid sources remove their samples; CPU busy needs two consecutive valid
//!   readings; guest time is already included in user/nice; scrapes never read files]
//! Spec: Baseline §41.2; §4.4; §78.1; ADR-0061 D-A

use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use crate::metrics::{families, write_family};

/// Configurable read paths; defaults are the kernel interfaces (§78.1, M22 D2).
#[derive(Debug, Clone)]
pub struct HostPaths {
    /// PSI paths in cpu, memory, io order (§41.2 resource labels).
    pub pressure: [PathBuf; 3],
    /// MemAvailable and MemTotal source (§41.2).
    pub meminfo: PathBuf,
    /// Aggregate CPU counters source (§41.2).
    pub stat: PathBuf,
}

impl Default for HostPaths {
    fn default() -> Self {
        Self {
            pressure: [
                "/proc/pressure/cpu",
                "/proc/pressure/memory",
                "/proc/pressure/io",
            ]
            .map(PathBuf::from),
            meminfo: "/proc/meminfo".into(),
            stat: "/proc/stat".into(),
        }
    }
}

struct OptionalGauges<const N: usize>(Mutex<[Option<f64>; N]>);

impl<const N: usize> OptionalGauges<N> {
    const fn new() -> Self {
        Self(Mutex::new([None; N]))
    }

    fn set(&self, values: [Option<f64>; N]) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = values;
    }

    fn get(&self) -> [Option<f64>; N] {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

static HOST_PRESSURE_RATIO: OptionalGauges<6> = OptionalGauges::new();
static HOST_MEMORY_AVAILABLE_BYTES: OptionalGauges<1> = OptionalGauges::new();
static HOST_CPU_BUSY_RATIO: OptionalGauges<1> = OptionalGauges::new();

/// One resident sampler's previous counters; no value is invented at startup (§4.4).
#[derive(Default)]
pub struct HostSampler {
    previous_cpu: Option<[u64; 8]>,
}

impl HostSampler {
    /// Replaces every family, including clearing failed sources (§41.2; G-M22-1).
    pub fn sample(&mut self, paths: &HostPaths) {
        let pressure: [[Option<f64>; 2]; 3] = std::array::from_fn(|resource| {
            read(&paths.pressure[resource])
                .and_then(|text| parse_pressure(&text, resource == 0))
                .unwrap_or([None; 2])
        });
        // labels: resource,kind
        HOST_PRESSURE_RATIO.set(std::array::from_fn(|i| pressure[i / 2][i % 2]));
        HOST_MEMORY_AVAILABLE_BYTES.set([read(&paths.meminfo).and_then(|s| memory_available(&s))]);
        let cpu = read(&paths.stat).and_then(|s| cpu_counters(&s));
        let busy = self.previous_cpu.zip(cpu).and_then(|(before, after)| {
            let mut delta = [0_u64; 8];
            for i in 0..8 {
                delta[i] = after[i].checked_sub(before[i])?;
            }
            let total = delta.iter().try_fold(0_u64, |sum, n| sum.checked_add(*n))?;
            let idle = delta[3].checked_add(delta[4])?;
            (total > 0).then(|| (total - idle) as f64 / total as f64)
        });
        self.previous_cpu = cpu;
        HOST_CPU_BUSY_RATIO.set([busy]);
    }
}

fn read(path: &Path) -> Option<String> {
    // dep: fs(proc) — missing/unreadable kernel interfaces are absent, not zero (§4.4).
    std::fs::read_to_string(path).ok()
}

fn parse_pressure(text: &str, cpu: bool) -> Option<[Option<f64>; 2]> {
    let mut values = [None; 2];
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let slot = match fields.next()? {
            "some" => 0,
            "full" => 1,
            _ => return None,
        };
        if values[slot].is_some() {
            return None;
        }
        let mut avg60 = None;
        for key in ["avg10", "avg60", "avg300", "total"] {
            let (name, value) = fields.next()?.split_once('=')?;
            if name != key {
                return None;
            }
            if key == "total" {
                value.parse::<u64>().ok()?;
            } else {
                let value = value.parse::<f64>().ok()?;
                if !value.is_finite() || !(0.0..=100.0).contains(&value) {
                    return None;
                }
                if key == "avg60" {
                    avg60 = Some(value / 100.0);
                }
            }
        }
        if fields.next().is_some() {
            return None;
        }
        values[slot] = avg60;
    }
    (values[0].is_some() && (cpu || values[1].is_some())).then_some(values)
}

fn memory_available(text: &str) -> Option<f64> {
    let mut values = [None; 2];
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let slot = match fields.next() {
            Some("MemAvailable:") => 0,
            Some("MemTotal:") => 1,
            _ => continue,
        };
        if values[slot].is_some() {
            return None;
        }
        let value = fields.next()?.parse::<u64>().ok()?.checked_mul(1024)?;
        if fields.next()? != "kB" || fields.next().is_some() {
            return None;
        }
        values[slot] = Some(value);
    }
    let (available, total) = (values[0]?, values[1]?);
    (total > 0 && available <= total).then_some(available as f64)
}

fn cpu_counters(text: &str) -> Option<[u64; 8]> {
    let mut fields = text.lines().next()?.split_whitespace();
    if fields.next()? != "cpu" {
        return None;
    }
    let counters = fields
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if counters.len() < 4 {
        return None;
    }
    let mut result = [0; 8];
    for (dst, value) in result.iter_mut().zip(counters) {
        *dst = value;
    }
    Some(result)
}

/// Latest samples only; missing sources have no samples or synthetic zero (§41.2; G-M22-1).
pub fn render(out: &mut String) {
    let labels = [
        ["cpu", "some"],
        ["cpu", "full"],
        ["memory", "some"],
        ["memory", "full"],
        ["io", "some"],
        ["io", "full"],
    ];
    let samples: Vec<_> = HOST_PRESSURE_RATIO
        .get()
        .into_iter()
        .enumerate()
        .filter_map(|(i, value)| value.map(|v| (labels[i].as_slice(), v)))
        .collect();
    // §41.2 / ADR-0061 D-C: metadata declares the family; only samples assert a measurement.
    write_family(out, &families::HOST_PRESSURE_RATIO, &samples);
    for (family, value) in [
        (
            &families::HOST_MEMORY_AVAILABLE_BYTES,
            HOST_MEMORY_AVAILABLE_BYTES.get()[0],
        ),
        (&families::HOST_CPU_BUSY_RATIO, HOST_CPU_BUSY_RATIO.get()[0]),
    ] {
        let samples: Vec<(&[&str], f64)> =
            value.into_iter().map(|value| (&[][..], value)).collect();
        write_family(out, family, &samples);
    }
}
