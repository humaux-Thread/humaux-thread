//! `contracts::freshness` — §50 embedded values for §21.5 / ADR-0111.
//! Depends-on: crates=[serde, toml]; services=[]; env=[]; modules=[contracts::config_registry]
//! Called-by: [retrieval::signals, tests]
//! Invariants: [exactly one row per caller-supplied MemoryType wire set; missing and unknown rows fail loading]
//! Spec: Baseline §21.5; §50; §78.1; ADR-0111

use std::{collections::BTreeSet, sync::OnceLock, time::Duration};

use serde::Deserialize;

use crate::config_registry::ConfigResolveError;

/// §50's release-pinned source of freshness thresholds.
pub const VALUES: &str = include_str!("../../../config/freshness.toml");

/// Validated config table; this is data, not a second classifier (§21.5).
#[derive(Debug)]
pub struct FreshnessValues {
    /// §21.5's explainable policy identity.
    pub policy_id: String,
    /// §50's values version.
    pub version: u32,
    /// Exactly one row per supplied MemoryType (§8.5).
    pub rows: Vec<FreshnessRow>,
}

/// One validated values-file row (§50); absent thresholds mean never (ADR-0111).
#[derive(Debug)]
pub struct FreshnessRow {
    /// MemoryType wire label at the config boundary (§8.5).
    pub name: String,
    /// Inclusive fresh boundary (§21.5).
    pub aging_after: Option<Duration>,
    /// Inclusive aging boundary (§21.5).
    pub stale_after: Option<Duration>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawValues {
    policy_id: String,
    version: u32,
    memory_type: Vec<RawRow>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRow {
    name: String,
    aging_after_days: Option<u64>,
    stale_after_days: Option<u64>,
}

fn invalid(reason: impl Into<String>) -> ConfigResolveError {
    ConfigResolveError {
        entry_name: "freshness".to_owned(),
        reason: reason.into(),
    }
}

fn days(value: Option<u64>) -> Result<Option<Duration>, ConfigResolveError> {
    value
        .map(|n| {
            n.checked_mul(86_400)
                .map(Duration::from_secs)
                .ok_or_else(|| invalid("threshold overflows seconds"))
        })
        .transpose()
}

/// §50 fail-loud parser; the consumer supplies the existing §8.5 closed set, avoiding a second enum.
///
/// # Errors
/// Rejects invalid TOML, identity, thresholds, duplicate, missing and unknown types.
pub fn parse_values(
    raw: &str,
    memory_types: &[&str],
) -> Result<FreshnessValues, ConfigResolveError> {
    let raw: RawValues = toml::from_str(raw).map_err(|e| invalid(e.to_string()))?;
    if raw.policy_id.trim().is_empty() || raw.version == 0 {
        return Err(invalid("policy_id must be nonempty and version positive"));
    }
    let expected: BTreeSet<_> = memory_types.iter().copied().collect();
    let actual: BTreeSet<_> = raw
        .memory_type
        .iter()
        .map(|row| row.name.as_str())
        .collect();
    if actual.len() != raw.memory_type.len() {
        return Err(invalid("duplicate MemoryType row"));
    }
    if actual != expected {
        return Err(invalid(format!(
            "MemoryType rows differ: missing={:?}, unknown={:?}",
            expected.difference(&actual).collect::<Vec<_>>(),
            actual.difference(&expected).collect::<Vec<_>>()
        )));
    }
    let rows = raw
        .memory_type
        .into_iter()
        .map(|row| {
            if row
                .stale_after_days
                .is_some_and(|stale| row.aging_after_days.is_none_or(|aging| aging > stale))
            {
                return Err(invalid(format!("invalid thresholds for {}", row.name)));
            }
            Ok(FreshnessRow {
                name: row.name,
                aging_after: days(row.aging_after_days)?,
                stale_after: days(row.stale_after_days)?,
            })
        })
        .collect::<Result<Vec<_>, ConfigResolveError>>()?;
    Ok(FreshnessValues {
        policy_id: raw.policy_id,
        version: raw.version,
        rows,
    })
}

/// §50: parses the embedded file once; every caller still validates its domain's exact set.
///
/// # Errors
/// Returns the embedded file's loading error or a mismatched consumer type set.
pub fn values(memory_types: &[&str]) -> Result<&'static FreshnessValues, ConfigResolveError> {
    static TABLE: OnceLock<Result<FreshnessValues, ConfigResolveError>> = OnceLock::new();
    let table = TABLE
        .get_or_init(|| parse_values(VALUES, memory_types))
        .as_ref()
        .map_err(Clone::clone)?;
    let expected: BTreeSet<_> = memory_types.iter().copied().collect();
    let actual: BTreeSet<_> = table.rows.iter().map(|row| row.name.as_str()).collect();
    if actual != expected {
        return Err(invalid("consumer MemoryType set differs from loaded table"));
    }
    Ok(table)
}
