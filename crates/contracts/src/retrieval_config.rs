//! `contracts::retrieval_config` — Typed retrieval-profile configuration (§50 / §55.6).
//! Depends-on: crates=[]; services=[]; env=[]; modules=[contracts::config_registry]
//! Called-by: [gateway::bootstrap, gateway::recall, retrieval-worker::rerank, retrieval-worker::rpc, retrieval::request, tests]
//! Invariants: [the five depth/fusion values (`top_k`, `cand_multiplier`, `leg_depth`, `rrf_k`, `sparse_leg_enabled`)
//!   and the five rerank values (`rerank_enabled`, `rerank_depth`, `rerank_max_len`, `rerank_timeout_ms`,
//!   `rerank_threads`) are read here and nowhere else; each is bounds-checked when the registry loads]
//! Spec: Baseline §50; §55.1; §55.6; ADR-0083 D-D; ADR-0084 D-E
//!
//! This is the sole bootstrap boundary for retrieval depth. A request caller receives an
//! already-resolved [`RegisteredRetrievalProfile`] and therefore cannot turn a request-local
//! `top_k` into a second tuning surface.

use std::collections::BTreeMap;
use std::fmt;

use crate::config_registry::{
    ConfigEntry, ConfigResolveError, effective_config_fingerprint, resolve_effective_config,
};

const PROFILE_ID: &str = "retrieval.profile.id";
const QUERY_TRANSFORM: &str = "retrieval.profile.query_transform";
const TOP_K: &str = "retrieval.profile.top_k";
const PRODUCTION_ENABLED: &str = "retrieval.profile.production_enabled";
/// ADR-0083 D-D: `cand_k = min(top_k * cand_multiplier, cap)`. Replaces the former constant multiplier 5 (ADR-0081 D-E).
const CAND_MULTIPLIER: &str = "retrieval.profile.cand_multiplier";
/// ADR-0083 D-D: `limit` of each leg's grouped request, in Memories (the fused list is then cut to `cand_k`).
const LEG_DEPTH: &str = "retrieval.profile.leg_depth";
/// ADR-0083 D-C: the constant in `score(m) = sum 1 / (rrf_k + rank)`.
const RRF_K: &str = "retrieval.profile.rrf_k";
/// ADR-0083 D-D / U6: turns the sparse leg on for the profile once the bm25 backfill reads zero missing.
const SPARSE_LEG_ENABLED: &str = "retrieval.profile.sparse_leg_enabled";
/// ADR-0084 D-E: turns the local rerank lane on for the profile once the artifact is deployed and U2 is read.
pub const RERANK_ENABLED: &str = "retrieval.profile.rerank_enabled";
/// ADR-0084 D-E: the most visible Memories scored per recall.
const RERANK_DEPTH: &str = "retrieval.profile.rerank_depth";
/// ADR-0084 D-E: token cap of one (query, document) pair.
const RERANK_MAX_LEN: &str = "retrieval.profile.rerank_max_len";
/// ADR-0084 D-E: the gateway's wait for the rerank RPC, in milliseconds.
const RERANK_TIMEOUT_MS: &str = "retrieval.profile.rerank_timeout_ms";
/// ADR-0084 D-E: intra-op threads of the retrieval-worker's rerank session.
pub const RERANK_THREADS: &str = "retrieval.profile.rerank_threads";

/// §23.3 / §55.6: the most Memories the candidate pool (`cand_k`) can hold. The one definition: `retrieval::request`
/// computes `cand_k` with it and the bounds below derive from it, so they cannot drift apart.
pub const RETRIEVAL_CANDIDATE_CAP: u32 = 200;

// Bounds, checked when the registry loads (ADR-0083 D-D). The defaults sit inside every range.
/// Below 1 `cand_k < top_k`: the pool could not hold the answer, breaking §23.3 `candidate_count >= returned`.
const CAND_MULTIPLIER_MIN: u32 = 1;
/// `cand_k` is capped at [`RETRIEVAL_CANDIDATE_CAP`] and `top_k >= 1`, so a multiplier above the cap changes nothing.
const CAND_MULTIPLIER_MAX: u32 = RETRIEVAL_CANDIDATE_CAP;
/// Each leg must be at least as deep as any `cand_k` (which never exceeds the cap): a shallower leg could not fill
/// the candidate pool, so `candidate_count` would fall below `cand_k` and break the §23.3 invariant.
const LEG_DEPTH_MIN: u32 = RETRIEVAL_CANDIDATE_CAP;
/// Cost guard (ADR-0083 U7): the fused list is cut to `cand_k <= 200`, so five times that already over-fetches.
const LEG_DEPTH_MAX: u32 = 1000;
/// RRF ranks are 1-based, so 0 is legal arithmetic but weights rank 1 a hundredfold over rank 100; 1 is the floor.
const RRF_K_MIN: u32 = 1;
/// At 1000 the weights across a 200-deep leg differ by under 20%: fusion degenerates into counting legs.
const RRF_K_MAX: u32 = 1000;
/// ADR-0084 D-E: the tokenizer's own pair limit (`tokenizer_config.json`); `rerank_max_len` and the worker's per-call
/// `max_len` both stop here, so one definition bounds registry and wire.
pub const RERANK_MAX_LEN_MAX: u32 = 512;
/// ADR-0084 D-E: the registry floor for `rerank_max_len` and `rerank_threads`.
const RERANK_FLOOR: u32 = 1;
/// ADR-0068 D-E: the most grouped dense calls one recall makes — the first plus at most two refills of the groups
/// Qdrant's bounded group search left short of `cand_k`. The budget stays `cand_k` Memories across every call.
pub const RETRIEVAL_GROUP_QUERY_MAX_CALLS: u32 = 3;

/// The transform that §55.1 places on a request after profile resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryTransform {
    Deterministic,
}

/// A profile accepted by the typed §50 bootstrap registry.
///
/// Fields are private and this type has no public constructor: callers can select neither
/// request depth nor transform. Add a production-capable profile by extending
/// [`retrieval_profile_registry`], never by constructing this value at a request call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredRetrievalProfile {
    profile_id: String,
    query_transform: QueryTransform,
    top_k: u32,
    cand_multiplier: u32,
    leg_depth: u32,
    rrf_k: u32,
    sparse_leg_enabled: bool,
    rerank_enabled: bool,
    rerank_depth: u32,
    rerank_max_len: u32,
    rerank_timeout_ms: u32,
    rerank_threads: u32,
    effective_config_fingerprint: String,
}

impl RegisteredRetrievalProfile {
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    #[must_use]
    pub fn query_transform(&self) -> QueryTransform {
        self.query_transform
    }

    #[must_use]
    pub fn top_k(&self) -> u32 {
        self.top_k
    }

    /// ADR-0083 D-D: `cand_k = min(top_k * cand_multiplier, cap)`.
    #[must_use]
    pub fn cand_multiplier(&self) -> u32 {
        self.cand_multiplier
    }

    /// ADR-0083 D-D: the `limit` of each leg's grouped request, in Memories.
    #[must_use]
    pub fn leg_depth(&self) -> u32 {
        self.leg_depth
    }

    /// ADR-0083 D-C: the reciprocal-rank-fusion constant.
    #[must_use]
    pub fn rrf_k(&self) -> u32 {
        self.rrf_k
    }

    /// ADR-0083 D-D / U6: whether the sparse leg runs for this profile.
    #[must_use]
    pub fn sparse_leg_enabled(&self) -> bool {
        self.sparse_leg_enabled
    }

    /// ADR-0084 D-E: whether the local rerank lane runs for this profile.
    #[must_use]
    pub fn rerank_enabled(&self) -> bool {
        self.rerank_enabled
    }

    /// ADR-0084 D-E: the most visible Memories scored per recall (at most the profile's `cand_k`).
    #[must_use]
    pub fn rerank_depth(&self) -> u32 {
        self.rerank_depth
    }

    /// ADR-0084 D-E: the token cap of one (query, document) pair.
    #[must_use]
    pub fn rerank_max_len(&self) -> u32 {
        self.rerank_max_len
    }

    /// ADR-0084 D-E: how long the gateway waits for the rerank RPC, in milliseconds (never 0).
    #[must_use]
    pub fn rerank_timeout_ms(&self) -> u32 {
        self.rerank_timeout_ms
    }

    /// ADR-0084 D-E: intra-op threads of the worker's rerank session (never 0).
    #[must_use]
    pub fn rerank_threads(&self) -> u32 {
        self.rerank_threads
    }

    #[must_use]
    pub fn effective_config_fingerprint(&self) -> &str {
        &self.effective_config_fingerprint
    }
}

/// Parsing errors at the retrieval-specific typed boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetrievalConfigError {
    Registry(ConfigResolveError),
    BlankProfileId,
    UnsupportedQueryTransform(String),
    GenerativeContractUnavailable,
    InvalidTopK(String),
    InvalidCandMultiplier(String),
    InvalidLegDepth(String),
    InvalidRrfK(String),
    InvalidSparseLegEnabled(String),
    InvalidRerankEnabled(String),
    InvalidRerankDepth(String),
    InvalidRerankMaxLen(String),
    InvalidRerankTimeoutMs(String),
    InvalidRerankThreads(String),
    InvalidProductionEnabled(String),
    ProductionDisabled,
}

impl fmt::Display for RetrievalConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry(error) => error.fmt(f),
            Self::BlankProfileId => write!(f, "retrieval profile id must not be blank"),
            Self::UnsupportedQueryTransform(transform) => {
                write!(f, "unsupported retrieval query transform {transform:?}")
            }
            Self::GenerativeContractUnavailable => write!(
                f,
                "generative retrieval profiles require provider, purpose, budget, timeout, fallback, and manifest contracts"
            ),
            Self::InvalidTopK(value) => write!(f, "invalid retrieval profile top_k {value:?}"),
            Self::InvalidCandMultiplier(value) => write!(
                f,
                "invalid retrieval profile cand_multiplier {value:?} (allowed {CAND_MULTIPLIER_MIN}..={CAND_MULTIPLIER_MAX})"
            ),
            Self::InvalidLegDepth(value) => write!(
                f,
                "invalid retrieval profile leg_depth {value:?} (allowed {LEG_DEPTH_MIN}..={LEG_DEPTH_MAX})"
            ),
            Self::InvalidRrfK(value) => write!(
                f,
                "invalid retrieval profile rrf_k {value:?} (allowed {RRF_K_MIN}..={RRF_K_MAX})"
            ),
            Self::InvalidSparseLegEnabled(value) => {
                write!(f, "invalid retrieval profile sparse_leg_enabled {value:?}")
            }
            Self::InvalidRerankEnabled(value) => {
                write!(f, "invalid retrieval profile rerank_enabled {value:?}")
            }
            Self::InvalidRerankDepth(value) => write!(
                f,
                "invalid retrieval profile rerank_depth {value:?} (allowed {RERANK_FLOOR}..=cand_k of the profile)"
            ),
            Self::InvalidRerankMaxLen(value) => write!(
                f,
                "invalid retrieval profile rerank_max_len {value:?} (allowed {RERANK_FLOOR}..={RERANK_MAX_LEN_MAX})"
            ),
            Self::InvalidRerankTimeoutMs(value) => write!(
                f,
                "invalid retrieval profile rerank_timeout_ms {value:?} (allowed at least 1)"
            ),
            Self::InvalidRerankThreads(value) => write!(
                f,
                "invalid retrieval profile rerank_threads {value:?} (allowed at least {RERANK_FLOOR})"
            ),
            Self::InvalidProductionEnabled(value) => {
                write!(f, "invalid retrieval profile production_enabled {value:?}")
            }
            Self::ProductionDisabled => {
                write!(f, "retrieval profile must be production_enabled=true")
            }
        }
    }
}

impl std::error::Error for RetrievalConfigError {}

/// The one §50 registry declaration for the currently shipped deterministic profile.
#[must_use]
pub fn retrieval_profile_registry() -> Vec<ConfigEntry> {
    vec![
        entry(PROFILE_ID, "string", "default_deterministic"),
        entry(
            QUERY_TRANSFORM,
            "enum:deterministic|generative",
            "deterministic",
        ),
        entry(TOP_K, "u32", "5"),
        entry(CAND_MULTIPLIER, "u32", "5"),
        entry(LEG_DEPTH, "u32", "200"),
        entry(RRF_K, "u32", "60"),
        entry(SPARSE_LEG_ENABLED, "bool", "false"),
        entry(RERANK_ENABLED, "bool", "false"),
        entry(RERANK_DEPTH, "u32", "25"),
        entry(RERANK_MAX_LEN, "u32", "256"),
        entry(RERANK_TIMEOUT_MS, "u32", "4000"),
        entry(RERANK_THREADS, "u32", "4"),
        entry(PRODUCTION_ENABLED, "bool", "true"),
    ]
}

/// Resolves process bootstrap configuration into the only type request construction accepts.
///
/// `raw` is intentionally accepted here, rather than at the request API: it belongs to a
/// process/config bootstrapper, and `resolve_effective_config` rejects undeclared values before
/// request handling can begin.
pub fn resolve_registered_retrieval_profile(
    raw: &BTreeMap<String, String>,
) -> Result<RegisteredRetrievalProfile, RetrievalConfigError> {
    let effective = resolve_effective_config(&retrieval_profile_registry(), raw)
        .map_err(RetrievalConfigError::Registry)?;
    let profile_id = required(&effective, PROFILE_ID).to_string();
    if profile_id.trim().is_empty() {
        return Err(RetrievalConfigError::BlankProfileId);
    }
    let query_transform = match required(&effective, QUERY_TRANSFORM) {
        "deterministic" => QueryTransform::Deterministic,
        "generative" => return Err(RetrievalConfigError::GenerativeContractUnavailable),
        other => {
            return Err(RetrievalConfigError::UnsupportedQueryTransform(
                other.to_string(),
            ));
        }
    };
    let cand_multiplier_text = required(&effective, CAND_MULTIPLIER);
    let cand_multiplier = parse_in(
        cand_multiplier_text,
        CAND_MULTIPLIER_MIN,
        CAND_MULTIPLIER_MAX,
    )
    .ok_or_else(|| RetrievalConfigError::InvalidCandMultiplier(cand_multiplier_text.to_string()))?;
    let top_k_text = required(&effective, TOP_K);
    let top_k = top_k_text
        .parse::<u32>()
        .ok()
        .filter(|top_k| *top_k > 0 && top_k.checked_mul(cand_multiplier).is_some())
        .ok_or_else(|| RetrievalConfigError::InvalidTopK(top_k_text.to_string()))?;
    let leg_depth_text = required(&effective, LEG_DEPTH);
    let leg_depth = parse_in(leg_depth_text, LEG_DEPTH_MIN, LEG_DEPTH_MAX)
        .ok_or_else(|| RetrievalConfigError::InvalidLegDepth(leg_depth_text.to_string()))?;
    let rrf_k_text = required(&effective, RRF_K);
    let rrf_k = parse_in(rrf_k_text, RRF_K_MIN, RRF_K_MAX)
        .ok_or_else(|| RetrievalConfigError::InvalidRrfK(rrf_k_text.to_string()))?;
    let sparse_leg_enabled = required(&effective, SPARSE_LEG_ENABLED)
        .parse::<bool>()
        .map_err(|_| {
            RetrievalConfigError::InvalidSparseLegEnabled(
                required(&effective, SPARSE_LEG_ENABLED).to_string(),
            )
        })?;
    let rerank = resolve_rerank(&effective, top_k.saturating_mul(cand_multiplier))?;
    let production_enabled = required(&effective, PRODUCTION_ENABLED)
        .parse::<bool>()
        .map_err(|_| {
            RetrievalConfigError::InvalidProductionEnabled(
                required(&effective, PRODUCTION_ENABLED).to_string(),
            )
        })?;
    if !production_enabled {
        return Err(RetrievalConfigError::ProductionDisabled);
    }
    Ok(RegisteredRetrievalProfile {
        profile_id,
        query_transform,
        top_k,
        cand_multiplier,
        leg_depth,
        rrf_k,
        sparse_leg_enabled,
        rerank_enabled: rerank.enabled,
        rerank_depth: rerank.depth,
        rerank_max_len: rerank.max_len,
        rerank_timeout_ms: rerank.timeout_ms,
        rerank_threads: rerank.threads,
        effective_config_fingerprint: effective_config_fingerprint(&effective),
    })
}

/// The five ADR-0084 D-E values after their bounds were checked.
struct RerankSettings {
    enabled: bool,
    depth: u32,
    max_len: u32,
    timeout_ms: u32,
    threads: u32,
}

/// ADR-0084 D-E / D-C 1: `rerank_depth` may not exceed the profile's `cand_k` (`min(top_k * cand_multiplier, cap)`),
/// or the rerank window would be wider than the pool it reorders.
fn resolve_rerank(
    effective: &BTreeMap<String, String>,
    pool: u32,
) -> Result<RerankSettings, RetrievalConfigError> {
    let cand_k = pool.min(RETRIEVAL_CANDIDATE_CAP);
    let enabled_text = required(effective, RERANK_ENABLED);
    let enabled = enabled_text
        .parse::<bool>()
        .map_err(|_| RetrievalConfigError::InvalidRerankEnabled(enabled_text.to_string()))?;
    let depth_text = required(effective, RERANK_DEPTH);
    let depth = parse_in(depth_text, RERANK_FLOOR, cand_k)
        .ok_or_else(|| RetrievalConfigError::InvalidRerankDepth(depth_text.to_string()))?;
    let max_len_text = required(effective, RERANK_MAX_LEN);
    let max_len = parse_in(max_len_text, RERANK_FLOOR, RERANK_MAX_LEN_MAX)
        .ok_or_else(|| RetrievalConfigError::InvalidRerankMaxLen(max_len_text.to_string()))?;
    let timeout_text = required(effective, RERANK_TIMEOUT_MS);
    let timeout_ms = parse_in(timeout_text, RERANK_FLOOR, u32::MAX)
        .ok_or_else(|| RetrievalConfigError::InvalidRerankTimeoutMs(timeout_text.to_string()))?;
    let threads_text = required(effective, RERANK_THREADS);
    let threads = parse_in(threads_text, RERANK_FLOOR, u32::MAX)
        .ok_or_else(|| RetrievalConfigError::InvalidRerankThreads(threads_text.to_string()))?;
    Ok(RerankSettings {
        enabled,
        depth,
        max_len,
        timeout_ms,
        threads,
    })
}

/// `text` as a `u32` inside `min..=max`, else `None`.
fn parse_in(text: &str, min: u32, max: u32) -> Option<u32> {
    text.parse::<u32>().ok().filter(|v| (min..=max).contains(v))
}

fn entry(name: &str, type_name: &str, default: &str) -> ConfigEntry {
    ConfigEntry {
        name: name.to_string(),
        type_name: type_name.to_string(),
        default: Some(default.to_string()),
        scope: "process".to_string(),
        secret: false,
        reloadability: "static".to_string(),
        owner_module: "retrieval".to_string(),
    }
}

fn required<'a>(effective: &'a BTreeMap<String, String>, key: &str) -> &'a str {
    effective
        .get(key)
        .expect("retrieval profile registry resolves every declared key")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_defaults_resolve_to_the_registered_production_profile() {
        let profile = resolve_registered_retrieval_profile(&BTreeMap::new()).expect("defaults");
        assert_eq!(profile.profile_id(), "default_deterministic");
        assert_eq!(profile.query_transform(), QueryTransform::Deterministic);
        assert_eq!(profile.top_k(), 5);
        assert_eq!(profile.cand_multiplier(), 5);
        assert_eq!(profile.leg_depth(), 200);
        assert_eq!(profile.rrf_k(), 60);
        assert!(!profile.sparse_leg_enabled());
        assert_eq!(profile.effective_config_fingerprint().len(), 64);
    }

    fn resolve_one(
        key: &str,
        value: &str,
    ) -> Result<RegisteredRetrievalProfile, RetrievalConfigError> {
        resolve_registered_retrieval_profile(&BTreeMap::from([(
            key.to_string(),
            value.to_string(),
        )]))
    }

    fn resolve_pairs(
        entries: &[(&str, &str)],
    ) -> Result<RegisteredRetrievalProfile, RetrievalConfigError> {
        resolve_registered_retrieval_profile(
            &entries
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
        )
    }

    /// G6c1-2: a value one step outside either bound is refused at load with that entry's own error, and the
    /// bound itself resolves. Fault: drop one bound from `parse_in`'s callers => the matching row goes red.
    #[test]
    fn hybrid_entries_are_bounds_checked_at_load_with_a_named_error() {
        let rows = [
            (CAND_MULTIPLIER, CAND_MULTIPLIER_MIN, CAND_MULTIPLIER_MAX),
            (LEG_DEPTH, LEG_DEPTH_MIN, LEG_DEPTH_MAX),
            (RRF_K, RRF_K_MIN, RRF_K_MAX),
        ];
        for (key, min, max) in rows {
            for outside in [
                (min - 1).to_string(),
                (max + 1).to_string(),
                "x".to_string(),
            ] {
                let error = resolve_one(key, &outside).expect_err(key);
                let named = match key {
                    CAND_MULTIPLIER => {
                        matches!(error, RetrievalConfigError::InvalidCandMultiplier(_))
                    }
                    LEG_DEPTH => matches!(error, RetrievalConfigError::InvalidLegDepth(_)),
                    _ => matches!(error, RetrievalConfigError::InvalidRrfK(_)),
                };
                assert!(named, "{key}={outside}: {error:?}");
            }
            for inside in [min, max] {
                // A multiplier of 1 leaves `cand_k` at 5, under the default `rerank_depth` (ADR-0084 D-C 1), so the
                // depth moves with it; every other row keeps the default.
                let depth = if key == CAND_MULTIPLIER && inside == min {
                    "1"
                } else {
                    "25"
                };
                let text = inside.to_string();
                assert!(
                    resolve_pairs(&[(key, text.as_str()), (RERANK_DEPTH, depth)]).is_ok(),
                    "{key}={inside}"
                );
            }
        }
        assert!(matches!(
            resolve_one(SPARSE_LEG_ENABLED, "yes"),
            Err(RetrievalConfigError::InvalidSparseLegEnabled(_))
        ));
        assert!(
            resolve_one(SPARSE_LEG_ENABLED, "true")
                .expect("bool")
                .sparse_leg_enabled()
        );
    }

    /// G6c1-1 (registry half): each of the four entries moves the effective-config fingerprint on its own.
    #[test]
    fn each_hybrid_entry_moves_the_effective_fingerprint() {
        let default = resolve_registered_retrieval_profile(&BTreeMap::new()).expect("defaults");
        for (key, value) in [
            (CAND_MULTIPLIER, "6"),
            (LEG_DEPTH, "201"),
            (RRF_K, "61"),
            (SPARSE_LEG_ENABLED, "true"),
        ] {
            let changed = resolve_one(key, value).expect(key);
            assert_ne!(
                default.effective_config_fingerprint(),
                changed.effective_config_fingerprint(),
                "{key}"
            );
        }
    }

    /// ADR-0084 D-E: the five rerank defaults, then each entry one step outside its bound is refused at load with
    /// its own named error and the bound itself resolves. Fault: drop one bound from `resolve_rerank` => its row
    /// goes red.
    #[test]
    fn rerank_entries_are_bounds_checked_at_load_with_a_named_error() {
        let defaults = resolve_registered_retrieval_profile(&BTreeMap::new()).expect("defaults");
        assert!(!defaults.rerank_enabled());
        assert_eq!(defaults.rerank_depth(), 25);
        assert_eq!(defaults.rerank_max_len(), 256);
        assert_eq!(defaults.rerank_timeout_ms(), 4000);
        assert_eq!(defaults.rerank_threads(), 4);

        type Named = fn(&RetrievalConfigError) -> bool;
        let rows: [(&str, [&str; 2], &str, Named); 5] = [
            (RERANK_ENABLED, ["yes", "x"], "true", |e| {
                matches!(e, RetrievalConfigError::InvalidRerankEnabled(_))
            }),
            (RERANK_DEPTH, ["0", "26"], "25", |e| {
                matches!(e, RetrievalConfigError::InvalidRerankDepth(_))
            }),
            (RERANK_MAX_LEN, ["0", "513"], "512", |e| {
                matches!(e, RetrievalConfigError::InvalidRerankMaxLen(_))
            }),
            (RERANK_TIMEOUT_MS, ["0", "x"], "1", |e| {
                matches!(e, RetrievalConfigError::InvalidRerankTimeoutMs(_))
            }),
            (RERANK_THREADS, ["0", "x"], "1", |e| {
                matches!(e, RetrievalConfigError::InvalidRerankThreads(_))
            }),
        ];
        for (key, outside, inside, named) in rows {
            for value in outside {
                let error = resolve_one(key, value).expect_err(key);
                assert!(named(&error), "{key}={value}: {error:?}");
            }
            assert!(resolve_one(key, inside).is_ok(), "{key}={inside}");
        }
        // The depth bound is the profile's own `cand_k`: 26 fits only once `top_k * cand_multiplier` reaches 26.
        assert!(resolve_pairs(&[(TOP_K, "6"), (RERANK_DEPTH, "26")]).is_ok());
        assert!(resolve_pairs(&[(TOP_K, "5"), (RERANK_DEPTH, "26")]).is_err());
    }

    /// ADR-0084 D-E: each of the five entries moves the effective-config fingerprint on its own.
    #[test]
    fn each_rerank_entry_moves_the_effective_fingerprint() {
        let default = resolve_registered_retrieval_profile(&BTreeMap::new()).expect("defaults");
        for (key, value) in [
            (RERANK_ENABLED, "true"),
            (RERANK_DEPTH, "24"),
            (RERANK_MAX_LEN, "255"),
            (RERANK_TIMEOUT_MS, "3999"),
            (RERANK_THREADS, "3"),
        ] {
            let changed = resolve_one(key, value).expect(key);
            assert_ne!(
                default.effective_config_fingerprint(),
                changed.effective_config_fingerprint(),
                "{key}"
            );
        }
    }

    #[test]
    fn rejects_garbage_disabled_and_invalid_depth_values() {
        let mut raw = BTreeMap::new();
        raw.insert("not.registered".to_string(), "x".to_string());
        assert!(matches!(
            resolve_registered_retrieval_profile(&raw),
            Err(RetrievalConfigError::Registry(_))
        ));

        let mut raw = BTreeMap::new();
        raw.insert(TOP_K.to_string(), "0".to_string());
        assert!(matches!(
            resolve_registered_retrieval_profile(&raw),
            Err(RetrievalConfigError::InvalidTopK(_))
        ));

        let mut raw = BTreeMap::new();
        raw.insert(PRODUCTION_ENABLED.to_string(), "false".to_string());
        assert_eq!(
            resolve_registered_retrieval_profile(&raw),
            Err(RetrievalConfigError::ProductionDisabled)
        );

        let mut raw = BTreeMap::new();
        raw.insert(PRODUCTION_ENABLED.to_string(), "yes".to_string());
        assert!(matches!(
            resolve_registered_retrieval_profile(&raw),
            Err(RetrievalConfigError::InvalidProductionEnabled(_))
        ));
    }

    #[test]
    fn generative_profile_is_fail_closed_until_its_complete_contract_exists() {
        let mut raw = BTreeMap::new();
        raw.insert(QUERY_TRANSFORM.to_string(), "generative".to_string());
        assert_eq!(
            resolve_registered_retrieval_profile(&raw),
            Err(RetrievalConfigError::GenerativeContractUnavailable)
        );
    }

    #[test]
    fn effective_fingerprint_changes_with_registered_depth() {
        let default = resolve_registered_retrieval_profile(&BTreeMap::new()).expect("defaults");
        let mut raw = BTreeMap::new();
        raw.insert(TOP_K.to_string(), "10".to_string());
        let deeper = resolve_registered_retrieval_profile(&raw).expect("registered depth");
        assert_eq!(deeper.top_k(), 10);
        assert_ne!(
            default.effective_config_fingerprint(),
            deeper.effective_config_fingerprint()
        );
    }
}
