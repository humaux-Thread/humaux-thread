//! `contracts::config_registry` — Typed Config Registry + effective config fingerprint (§50).
//! Depends-on: crates=[sha2]; services=[]; env=[]; modules=[]
//! Called-by: [adapters::qdrant, contracts::retrieval_config, gateway::bootstrap, infra-egress::http, retrieval::request, tests]
//! Invariants: [the Qdrant collection knobs (datatype, HNSW, generation label) are read here and nowhere else; the
//!   unset configuration resolves to Qdrant's own defaults, so a default collection body carries none of them]
//! Spec: Baseline §50; §50.1; §17.7; §78; §78.1
//!
//! §50: 所有配置集中 typed registry，字段 name/type/default/scope/secret?/reloadability/owner
//! module；垃圾值 fail-loud；生产运行必须记录 effective config fingerprint，而不是只看 `.env`。

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

/// The one sanctioned raw `std::env::var` read site outside process bootstrap (`bins/*`) and
/// CI-gate tooling (`xtask/`) — module doc/§50.1: "humaux-contracts owns the one legitimate
/// config-read point". Every other crate that needs a single named environment variable's
/// value (rather than the full typed [`resolve_effective_config`] flow, which expects the raw
/// key/value map already assembled) calls this function instead of naming `std::env::var`
/// itself; `xtask`'s §78 boundary lint (`architecture_check::env_var_scan`) is a hard CI gate
/// that fails on any other file containing that call. Returns `None` for both "unset" and
/// "present but empty" alike — callers that must tell those two apart read
/// `std::env::var(name)`'s own `Result` directly instead of going through this helper, but no
/// caller in this workspace has needed that distinction yet.
pub fn read_env_var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// 单条 typed config registry entry（§50 字段表逐字对应）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigEntry {
    /// 配置键名。
    pub name: String,
    /// 声明类型名（如 "bool"/"u64"/"string"），供上层做进一步类型化解析。
    pub type_name: String,
    /// 缺省值；`None` 表示该条无默认值，运行时必须提供。
    pub default: Option<String>,
    /// 生效范围（如 "process"/"tenant"/"deployment"），自由文本——§50 未冻结取值闭集。
    pub scope: String,
    /// 是否敏感值；敏感值不得出现在日志/fingerprint 原文中（由调用方在记录前脱敏）。
    pub secret: bool,
    /// 是否可热加载（如 "static"/"hot"），自由文本——§50 未冻结取值闭集。
    pub reloadability: String,
    /// 拥有该配置项语义的模块名，用于追责与变更评审路由。
    pub owner_module: String,
}

/// Effective config 解析失败（§50: 垃圾值 fail-loud，禁止用 `Default` 掩盖缺口）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigResolveError {
    /// 出错的配置键名。
    pub entry_name: String,
    /// 失败原因（人读文本，供日志/CI 输出）。
    pub reason: String,
}

impl fmt::Display for ConfigResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "config entry {:?}: {}", self.entry_name, self.reason)
    }
}

impl std::error::Error for ConfigResolveError {}

/// 由 registry 声明与运行时已解析的原始键值对构造 effective config。
///
/// fail-loud（§50）：任一声明项既无运行时值又无 `default`，或 `raw` 携带 registry 未声明的键
/// （垃圾值），一律返回 `Err`——不得静默丢弃、不得用 `Default::default()` 兜底吞掉缺口。
pub fn resolve_effective_config(
    registry: &[ConfigEntry],
    raw: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, ConfigResolveError> {
    let mut effective = BTreeMap::new();
    for entry in registry {
        let value = raw.get(&entry.name).or(entry.default.as_ref());
        match value {
            Some(v) => {
                effective.insert(entry.name.clone(), v.clone());
            }
            None => {
                return Err(ConfigResolveError {
                    entry_name: entry.name.clone(),
                    reason: "missing runtime value and no default".to_string(),
                });
            }
        }
    }
    for key in raw.keys() {
        if !registry.iter().any(|entry| &entry.name == key) {
            return Err(ConfigResolveError {
                entry_name: key.clone(),
                reason: "value present for key not declared in registry".to_string(),
            });
        }
    }
    Ok(effective)
}

/// Effective config fingerprint（§50: 生产运行必须记录 effective config fingerprint）。
///
/// 规范序列化：按 key 升序拼接 `"key=value\n"`（`effective` 已是 `BTreeMap`，迭代天然有序），
/// 避免 hash 结果随 map 内部实现的迭代顺序漂移；secret 项的值应由调用方在传入前脱敏/占位。
pub fn effective_config_fingerprint(effective: &BTreeMap<String, String>) -> String {
    let mut canonical = String::new();
    for (key, value) in effective {
        canonical.push_str(key);
        canonical.push('=');
        canonical.push_str(value);
        canonical.push('\n');
    }
    let digest = Sha256::digest(canonical.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

// ============================================================================
// Qdrant collection knobs (§17.7, §78.1) — the typed half of `adapters::qdrant::CollectionSpec`
// ============================================================================

const GENERATION_LABEL: &str = "qdrant.collection.generation_label";
const DATATYPE: &str = "qdrant.collection.datatype";
const HNSW_M: &str = "qdrant.collection.hnsw_m";
const HNSW_PAYLOAD_M: &str = "qdrant.collection.hnsw_payload_m";
const HNSW_EF_CONSTRUCT: &str = "qdrant.collection.hnsw_ef_construct";

/// Longest generation label: a label becomes part of a Qdrant collection name and of tenant placement rows.
const GENERATION_LABEL_MAX_LEN: usize = 32;
/// Upper bound of `m` and `payload_m`: above it the graph's memory cost is out of proportion to any recall gain.
const HNSW_LINKS_MAX: u32 = 64;
/// Qdrant rejects an `ef_construct` below 4.
const HNSW_EF_CONSTRUCT_MIN: u32 = 4;
/// Cost guard: index build time grows with `ef_construct`.
const HNSW_EF_CONSTRUCT_MAX: u32 = 1000;

/// The dense vector storage type of a collection (§17.7). A datatype is a property of the collection, never of a
/// point: changing it is a new generation plus a rebuild, never an in-place mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectionDatatype {
    /// Qdrant's default storage; the wire body omits it.
    Float32,
    /// Native half precision (2 bytes per dimension, no original kept).
    Float16,
    /// Qdrant 1.19 4-bit TurboQuant as the only representation: no float copy, no rescoring.
    Turbo4,
}

impl CollectionDatatype {
    /// Qdrant's `vectors.datatype` spelling.
    #[must_use]
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Float32 => "float32",
            Self::Float16 => "float16",
            Self::Turbo4 => "turbo4",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        [Self::Float32, Self::Float16, Self::Turbo4]
            .into_iter()
            .find(|d| d.as_wire() == text)
    }
}

/// A collection-level HNSW configuration. `m = 0` builds no global graph; the per-payload graphs of
/// `payload_m` then serve every tenant-filtered query (§17.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HnswConfig {
    /// Links per node of the global graph; `0` disables it.
    pub m: u32,
    /// Links per node of the payload-indexed (tenant) graphs; `None` leaves Qdrant's behaviour of reusing `m`.
    pub payload_m: Option<u32>,
    /// Candidate list size while building.
    pub ef_construct: u32,
}

impl HnswConfig {
    /// Qdrant's own defaults (`m` 16, `ef_construct` 100, no `payload_m`). The registry defaults are these values, so
    /// an unconfigured deployment is byte-for-byte the collection body it had before this registry existed.
    pub const QDRANT_DEFAULT: HnswConfig = HnswConfig {
        m: 16,
        payload_m: None,
        ef_construct: 100,
    };
}

/// The resolved collection knobs. Build it only through [`resolve_collection_config`] (bounds checked) or take
/// [`CollectionConfig::default`]; `adapters::qdrant::CollectionSpec` adds family and dimension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionConfig {
    /// Suffix of the collection name (`{family}_{label}`); `None` is the unlabelled first generation, whose name is
    /// the bare family name.
    pub generation_label: Option<String>,
    /// Dense vector storage type.
    pub datatype: CollectionDatatype,
    /// Collection-level HNSW parameters.
    pub hnsw: HnswConfig,
}

impl Default for CollectionConfig {
    fn default() -> Self {
        Self {
            generation_label: None,
            datatype: CollectionDatatype::Float32,
            hnsw: HnswConfig::QDRANT_DEFAULT,
        }
    }
}

/// A collection knob failed its bounds (§50: garbage values fail loud).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectionConfigError {
    /// The registry rejected the raw map (missing value, undeclared key).
    Registry(ConfigResolveError),
    /// `key` holds `value`, which is outside what the registry accepts.
    Invalid {
        /// The registry key.
        key: &'static str,
        /// The offending text.
        value: String,
    },
    /// `m = 0` with no `payload_m` leaves a collection with no vector index at all (every query a full scan).
    NoIndexGraph,
}

impl fmt::Display for CollectionConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry(error) => error.fmt(f),
            Self::Invalid { key, value } => write!(f, "invalid collection config {key} {value:?}"),
            Self::NoIndexGraph => write!(
                f,
                "collection config {HNSW_M}=0 requires {HNSW_PAYLOAD_M}: no graph would exist"
            ),
        }
    }
}

impl std::error::Error for CollectionConfigError {}

/// The registry declaration of the collection knobs. An empty `generation_label` or `hnsw_payload_m` means unset.
#[must_use]
pub fn collection_config_registry() -> Vec<ConfigEntry> {
    let d = HnswConfig::QDRANT_DEFAULT;
    let entry = |name: &str, type_name: &str, default: String| ConfigEntry {
        name: name.to_string(),
        type_name: type_name.to_string(),
        default: Some(default),
        scope: "process".to_string(),
        secret: false,
        reloadability: "static".to_string(),
        owner_module: "projection".to_string(),
    };
    vec![
        entry(GENERATION_LABEL, "string", String::new()),
        entry(
            DATATYPE,
            "enum:float32|float16|turbo4",
            CollectionDatatype::Float32.as_wire().to_string(),
        ),
        entry(HNSW_M, "u32", d.m.to_string()),
        entry(
            HNSW_PAYLOAD_M,
            "u32",
            d.payload_m.map(|v| v.to_string()).unwrap_or_default(),
        ),
        entry(HNSW_EF_CONSTRUCT, "u32", d.ef_construct.to_string()),
    ]
}

/// Resolves the raw key/value map into a bounds-checked [`CollectionConfig`] (§50 fail-loud, §17.7).
pub fn resolve_collection_config(
    raw: &BTreeMap<String, String>,
) -> Result<CollectionConfig, CollectionConfigError> {
    let effective = resolve_effective_config(&collection_config_registry(), raw)
        .map_err(CollectionConfigError::Registry)?;
    let get = |key: &'static str| {
        effective
            .get(key)
            .expect("collection registry resolves every declared key")
            .as_str()
    };
    let invalid = |key: &'static str, value: &str| CollectionConfigError::Invalid {
        key,
        value: value.to_string(),
    };
    let parse_in = |key: &'static str, text: &str, min: u32, max: u32| {
        text.parse::<u32>()
            .ok()
            .filter(|v| (min..=max).contains(v))
            .ok_or_else(|| invalid(key, text))
    };

    let label = get(GENERATION_LABEL);
    let label_ok = label.len() <= GENERATION_LABEL_MAX_LEN
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if !label_ok {
        return Err(invalid(GENERATION_LABEL, label));
    }
    let datatype =
        CollectionDatatype::parse(get(DATATYPE)).ok_or_else(|| invalid(DATATYPE, get(DATATYPE)))?;
    let m = parse_in(HNSW_M, get(HNSW_M), 0, HNSW_LINKS_MAX)?;
    let payload_m = match get(HNSW_PAYLOAD_M) {
        "" => None,
        text => Some(parse_in(HNSW_PAYLOAD_M, text, 1, HNSW_LINKS_MAX)?),
    };
    let ef_construct = parse_in(
        HNSW_EF_CONSTRUCT,
        get(HNSW_EF_CONSTRUCT),
        HNSW_EF_CONSTRUCT_MIN,
        HNSW_EF_CONSTRUCT_MAX,
    )?;
    if m == 0 && payload_m.is_none() {
        return Err(CollectionConfigError::NoIndexGraph);
    }
    Ok(CollectionConfig {
        generation_label: (!label.is_empty()).then(|| label.to_string()),
        datatype,
        hnsw: HnswConfig {
            m,
            payload_m,
            ef_construct,
        },
    })
}

/// M03 registered start values (§78.1; ADR-0100); X-RATE remains owner-gated.
/// Process bootstrap supplies its private key names so shared defaults do not declare other processes
/// as readers of gateway-only inputs (§50; ADR-0066 D-T).
pub fn gateway_limiter_registry(
    [max_subjects, deployment, heartbeat]: [&str; 3],
) -> Vec<ConfigEntry> {
    // ponytail: conservative start values, X-RATE certifies; account 128/20 is the B23 starting point.
    let mut entries = Vec::new();
    for (tier, capacity, refill) in [
        ("PREAUTH_IP", "256", "128"),
        ("CREDENTIAL", "64", "20"),
        ("USER", "128", "20"),
        ("TENANT", "128", "20"),
        ("OPERATION", "64", "20"),
    ] {
        for (suffix, default) in [("CAPACITY", capacity), ("REFILL_PER_SECOND", refill)] {
            entries.push(gateway_limiter_entry(
                &format!("HUMAUX_GATEWAY_RATE_{tier}_{suffix}"),
                "i64",
                default,
            ));
        }
    }
    entries.extend([
        gateway_limiter_entry(max_subjects, "usize", "50000"),
        gateway_limiter_entry(deployment, "string", "default"),
        gateway_limiter_entry(heartbeat, "u64", "5"),
    ]);
    entries
}

fn gateway_limiter_entry(name: &str, type_name: &str, default: &str) -> ConfigEntry {
    ConfigEntry {
        name: name.to_owned(),
        type_name: type_name.to_owned(),
        default: Some(default.to_owned()),
        scope: "process".to_owned(),
        secret: false,
        reloadability: "static".to_owned(),
        owner_module: "gateway.bootstrap".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, default: Option<&str>) -> ConfigEntry {
        ConfigEntry {
            name: name.to_string(),
            type_name: "string".to_string(),
            default: default.map(str::to_string),
            scope: "process".to_string(),
            secret: false,
            reloadability: "static".to_string(),
            owner_module: "test".to_string(),
        }
    }

    #[test]
    fn missing_value_and_no_default_is_fail_loud_err() {
        let registry = vec![entry("a", None)];
        let raw = BTreeMap::new();
        let err = resolve_effective_config(&registry, &raw).unwrap_err();
        assert_eq!(err.entry_name, "a");
    }

    #[test]
    fn undeclared_key_is_fail_loud_err() {
        let registry = vec![entry("a", Some("1"))];
        let mut raw = BTreeMap::new();
        raw.insert("garbage".to_string(), "x".to_string());
        let err = resolve_effective_config(&registry, &raw).unwrap_err();
        assert_eq!(err.entry_name, "garbage");
    }

    #[test]
    fn fingerprint_is_deterministic_and_order_independent() {
        let mut a = BTreeMap::new();
        a.insert("b".to_string(), "2".to_string());
        a.insert("a".to_string(), "1".to_string());
        let mut b = BTreeMap::new();
        b.insert("a".to_string(), "1".to_string());
        b.insert("b".to_string(), "2".to_string());
        assert_eq!(
            effective_config_fingerprint(&a),
            effective_config_fingerprint(&b)
        );
    }

    #[test]
    fn fingerprint_changes_when_value_changes() {
        let mut a = BTreeMap::new();
        a.insert("a".to_string(), "1".to_string());
        let mut b = BTreeMap::new();
        b.insert("a".to_string(), "2".to_string());
        assert_ne!(
            effective_config_fingerprint(&a),
            effective_config_fingerprint(&b)
        );
    }

    fn collection_raw(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn unset_collection_config_is_qdrants_own_default() {
        let config = resolve_collection_config(&BTreeMap::new()).expect("defaults");
        assert_eq!(config, CollectionConfig::default());
        assert_eq!(config.hnsw, HnswConfig::QDRANT_DEFAULT);
    }

    #[test]
    fn collection_config_reads_every_knob() {
        let config = resolve_collection_config(&collection_raw(&[
            (GENERATION_LABEL, "g2"),
            (DATATYPE, "turbo4"),
            (HNSW_M, "0"),
            (HNSW_PAYLOAD_M, "16"),
            (HNSW_EF_CONSTRUCT, "100"),
        ]))
        .expect("tenant-local graphs");
        assert_eq!(config.generation_label.as_deref(), Some("g2"));
        assert_eq!(config.datatype, CollectionDatatype::Turbo4);
        assert_eq!(config.hnsw.m, 0);
        assert_eq!(config.hnsw.payload_m, Some(16));
    }

    #[test]
    fn garbage_collection_config_is_fail_loud() {
        for (key, value) in [
            (GENERATION_LABEL, "Has Space"),
            (GENERATION_LABEL, "x234567890123456789012345678901234"),
            (DATATYPE, "int8"),
            (HNSW_M, "65"),
            (HNSW_M, "-1"),
            (HNSW_PAYLOAD_M, "0"),
            (HNSW_PAYLOAD_M, "65"),
            (HNSW_EF_CONSTRUCT, "3"),
            (HNSW_EF_CONSTRUCT, "1001"),
        ] {
            let expected = CollectionConfigError::Invalid {
                key,
                value: value.to_string(),
            };
            let err = resolve_collection_config(&collection_raw(&[(key, value)]))
                .expect_err("garbage must be rejected");
            assert_eq!(
                err, expected,
                "{key}={value} must fail with its own variant"
            );
            assert_eq!(
                err.to_string(),
                format!("invalid collection config {key} {value:?}"),
                "{key}={value} must name the offending key and value"
            );
        }
        assert_eq!(
            resolve_collection_config(&collection_raw(&[("qdrant.collection.nope", "1")]))
                .unwrap_err(),
            CollectionConfigError::Registry(ConfigResolveError {
                entry_name: "qdrant.collection.nope".to_string(),
                reason: "value present for key not declared in registry".to_string(),
            })
        );
    }

    #[test]
    fn collection_config_accepts_the_upper_bounds_of_m_and_ef_construct() {
        let config = resolve_collection_config(&collection_raw(&[
            (HNSW_M, "64"),
            (HNSW_EF_CONSTRUCT, "1000"),
        ]))
        .expect("m = 64 and ef_construct = 1000 are inside the bounds");
        assert_eq!(
            config,
            CollectionConfig {
                generation_label: None,
                datatype: CollectionDatatype::Float32,
                hnsw: HnswConfig {
                    m: 64,
                    payload_m: None,
                    ef_construct: 1000,
                },
            }
        );
    }

    #[test]
    fn no_graph_at_all_is_rejected() {
        assert_eq!(
            resolve_collection_config(&collection_raw(&[(HNSW_M, "0")])).unwrap_err(),
            CollectionConfigError::NoIndexGraph
        );
    }
}
