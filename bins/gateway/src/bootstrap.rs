//! `gateway::bootstrap` — Process bootstrap: the process-wide stream family `(scope_kind, domain, projection_kind,
//!   projection_version)` that the read routes AND `remember.put` attach to each request's own `(tenant, workspace)`
//!   (ADR-0031 D-A / ADR-0032 D-A, §34.0.1 Q9: one process serves every pair; no registry table, no per-process
//!   stream cache) — the same family the 14 governance / subject / affect writes attach to since ADR-0054, so
//!   the process holds no default write pair at all.
//! Depends-on: crates=[hex, humaux-adapters, humaux-application, humaux-cache, humaux-contracts, humaux-domain,
//!   humaux-infra-cell, humaux-protocol, humaux-retrieval, humaux-retrieval-worker, humaux-telemetry, serde_json, tokio, uuid];
//!   services=[PostgreSQL(role_gateway)];
//!   env=[HUMAUX_CONTINUITY_LIST_MERGE_ATTEMPTS, HUMAUX_GATEWAY_ADMISSION_BODY_READ_TIMEOUT_MS, HUMAUX_GATEWAY_ADMISSION_CONCURRENCY,
//!   HUMAUX_GATEWAY_ADMISSION_MAX_WAIT_MS, HUMAUX_GATEWAY_ADMISSION_PER_KEY_LIMIT, HUMAUX_GATEWAY_ADMISSION_QUEUE_DEPTH,
//!   HUMAUX_GATEWAY_ALLOWED_HOSTS, HUMAUX_GATEWAY_ALLOWED_ORIGINS, HUMAUX_GATEWAY_AUTH_HMAC_KEY,
//!   HUMAUX_GATEWAY_AUTH_HMAC_KEY_PREVIOUS, HUMAUX_GATEWAY_AUTH_SURFACE_ENABLED, HUMAUX_GATEWAY_BIND_ADDR,
//!   HUMAUX_GATEWAY_CACHE_EMBED_QUERY_BYTES, HUMAUX_GATEWAY_CACHE_EMBED_QUERY_ENABLED,
//!   HUMAUX_GATEWAY_CACHE_EMBED_QUERY_TTL_SECONDS, HUMAUX_GATEWAY_CACHE_PER_TENANT_BYTES,
//!   HUMAUX_GATEWAY_CALLER_ID, HUMAUX_GATEWAY_CELL_ID, HUMAUX_GATEWAY_CONFIRM_TOKEN_TTL_SECONDS,
//!   HUMAUX_GATEWAY_CONTEXT_MANDATORY_TOKENS, HUMAUX_GATEWAY_CONTEXT_TOTAL_TOKENS,
//!   HUMAUX_GATEWAY_CREDENTIAL_PEPPER_HEX, HUMAUX_GATEWAY_CREDENTIAL_PEPPER_PREVIOUS_HEX,
//!   HUMAUX_GATEWAY_CREDENTIAL_TOUCH_INTERVAL_SECONDS,
//!   HUMAUX_GATEWAY_EMBEDDING_DIMENSION, HUMAUX_GATEWAY_EMBEDDING_MODEL_ID, HUMAUX_GATEWAY_EMBEDDING_MODEL_REVISION,
//!   HUMAUX_GATEWAY_EMBEDDING_PROVIDER_ID, HUMAUX_GATEWAY_EMBEDDING_VERSION, HUMAUX_GATEWAY_ENUMERATION_MANIFEST_CAP,
//!   HUMAUX_GATEWAY_ENUMERATION_TTL_SECONDS, HUMAUX_GATEWAY_FINALIZE_TIMEOUT_SECONDS,
//!   HUMAUX_GATEWAY_GLOBAL_DENYLIST, HUMAUX_GATEWAY_GLOBAL_EMERGENCY_ALLOWLIST,
//!   HUMAUX_GATEWAY_HANDLER_TIMEOUT_SECONDS, HUMAUX_GATEWAY_MAX_FORWARDED_HOPS,
//!   HUMAUX_GATEWAY_MAX_REQUEST_BODY_BYTES, HUMAUX_GATEWAY_METRICS_ADDR, HUMAUX_GATEWAY_MOOD_HALF_LIFE_SECONDS,
//!   HUMAUX_GATEWAY_PG_ACQUIRE_TIMEOUT_MS, HUMAUX_GATEWAY_PG_DSN,
//!   HUMAUX_GATEWAY_PG_IDLE_IN_TRANSACTION_TIMEOUT_MS, HUMAUX_GATEWAY_PG_IDLE_TIMEOUT_SECONDS,
//!   HUMAUX_GATEWAY_PG_MAX_LIFETIME_SECONDS, HUMAUX_GATEWAY_PG_POOL_MAX_CONNECTIONS,
//!   HUMAUX_GATEWAY_PG_POOL_MIN_CONNECTIONS, HUMAUX_GATEWAY_PG_STATEMENT_TIMEOUT_MS,
//!   HUMAUX_GATEWAY_PROJECTION_LAG_SECONDS, HUMAUX_GATEWAY_QDRANT_CIDR,
//!   HUMAUX_GATEWAY_QDRANT_HOST, HUMAUX_GATEWAY_QDRANT_PORT, HUMAUX_GATEWAY_QDRANT_TLS,
//!   HUMAUX_GATEWAY_RATE_{PREAUTH_IP,CREDENTIAL,USER,TENANT,OPERATION}_{CAPACITY,REFILL_PER_SECOND},
//!   HUMAUX_GATEWAY_RATE_LOCK_TIMEOUT_MS, HUMAUX_GATEWAY_RATE_PREAUTH_IPV6_PREFIX_BITS,
//!   HUMAUX_GATEWAY_READINESS_REFRESH_SECONDS, HUMAUX_GATEWAY_REMEMBER_DATA_CLASS, HUMAUX_GATEWAY_REMEMBER_DOMAIN,
//!   HUMAUX_GATEWAY_REMEMBER_EVENT_KIND, HUMAUX_GATEWAY_REMEMBER_PROJECTION_KIND,
//!   HUMAUX_GATEWAY_REMEMBER_PROJECTION_VERSION, HUMAUX_GATEWAY_REMEMBER_REASONING_DOMAIN_ID,
//!   HUMAUX_GATEWAY_REMEMBER_SCOPE_KIND, HUMAUX_GATEWAY_REMEMBER_TENANT_ID,
//!   HUMAUX_GATEWAY_REMEMBER_TOKEN_TTL_SECONDS, HUMAUX_GATEWAY_REMEMBER_VISIBILITY_CLASS,
//!   HUMAUX_GATEWAY_REMEMBER_WORKSPACE_ID, HUMAUX_GATEWAY_REPLAY_TTL_SECONDS, HUMAUX_GATEWAY_RERANK_MODEL_SHA256,
//!   HUMAUX_GATEWAY_RERANK_RECIPE, HUMAUX_GATEWAY_RERANK_REPO, HUMAUX_GATEWAY_RERANK_REVISION,
//!   HUMAUX_GATEWAY_RERANK_TOKENIZER_SHA256,
//!   HUMAUX_GATEWAY_RESERVATION_TTL_SECONDS, HUMAUX_GATEWAY_RETRIEVAL_PROFILE_PRODUCTION_ENABLED,
//!   HUMAUX_GATEWAY_RETRIEVAL_PROFILE_QUERY_TRANSFORM, HUMAUX_GATEWAY_RETRIEVAL_PROFILE_TOP_K,
//!   HUMAUX_GATEWAY_RETRIEVAL_RPC_PERMIT_TTL_SECONDS, HUMAUX_GATEWAY_RETRIEVAL_RPC_SERVER_UID,
//!   HUMAUX_GATEWAY_RETRIEVAL_RPC_SOCKET_PATH, HUMAUX_GATEWAY_TASK_LEASE_TTL_SECONDS,
//!   HUMAUX_GATEWAY_TOKEN_HMAC_KEY, HUMAUX_GATEWAY_TOKEN_HMAC_KEY_PREVIOUS, HUMAUX_GATEWAY_TRUSTED_PROXY_CIDRS,
//!   HUMAUX_GATEWAY_UNDO_WINDOW_SECONDS, HUMAUX_GATEWAY_UNKNOWN]; modules=[adapters::attribution_repo, adapters::postgres, adapters::quota_repo,
//!   adapters::retrieve, application::retrieval_embedding_port, cache::bounded, contracts::config_registry,
//!   contracts::retrieval_config, domain::context, domain::dataclass, domain::identity, gateway::admission,
//!   gateway::cached_embedding, gateway::context,
//!   gateway::guard, gateway::mcp_application, gateway::recall, gateway::remember, gateway::rerank_client,
//!   gateway::retrieval_embedding_client, gateway::status, infra-cell::permit, infra-cell::resource,
//!   infra-cell::transport, protocol::edge, protocol::mcp, protocol::mcp_catalog, retrieval::rerank, telemetry::metrics]
//! Called-by: [gateway::guard, gateway::main, gateway::mcp_application, gateway::memory, tests]
//! Invariants: [one process serves every (tenant, workspace) pair with no per-process stream cache or registry table; GuardSettings::tenant_network stays empty until a separate authorization approves a tenant-specific network policy]
//! Spec: Baseline §34.0.1; §78.1; ADR-0031; ADR-0032; ADR-0054; ADR-0084 D-E; ADR-0084 U7
//!
//! This module owns process configuration only. Tool arguments never select a
//! stream version, credential verifier, listener, or rate policy; a tool argument selects a
//! workspace only inside the credential's already-authorized membership (`narrow`).
//! `GuardSettings::tenant_network` is deliberately empty in this single-policy
//! process. A tenant-specific network-policy loader needs a separate approved
//! authorization and acceptance gate before this bootstrap can serve it.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use humaux_adapters::{
    attribution_repo::AttributionLadder,
    postgres::{PoolSettings, RuntimeDbPool},
    quota_repo::RatePolicy,
    retrieve::{TokenKeys, install_token_keys},
};
use humaux_application::retrieval_embedding_port::RetrievalEmbeddingPort;
use humaux_cache::CacheConfig;
use humaux_contracts::config_registry::{
    ConfigEntry, effective_config_fingerprint, resolve_effective_config,
};
use humaux_contracts::retrieval_config::{
    RERANK_TIMEOUT_MS, resolve_registered_retrieval_profile, retrieval_profile_registry,
};
use humaux_domain::{context::ContextBudget, dataclass::DataClass, identity::VisibilityClass};
use humaux_infra_cell::{
    CallerId, CellAccessMode, CellCidr, CellId, DEFAULT_MAX_RESPONSE_BYTES, HttpIntraCellTransport,
    IntraCellResource, IntraCellResourceRegistry, ResourceEntry,
};
use humaux_protocol::{
    edge::{Cidr, TrustedProxyConfig},
    mcp::{McpAdapter, McpHttpConfig},
    mcp_catalog::CanonicalCatalog,
};
use humaux_retrieval::rerank::ModelIdentity;
use uuid::Uuid;

use serde_json::{Map, Value};

use crate::{
    admission::{Admission, AdmissionSettings},
    cached_embedding::{CachedEmbeddingPort, GenerationStamp},
    context::ContextBootstrap,
    guard::{GatewayGuard, GuardRatePolicies, GuardSettings},
    mcp_application::GatewayMcpApplication,
    recall::{SemanticRecallRuntime, SemanticRecallVersions},
    remember::{self, ProcessFamily, RememberEventKind, RememberPolicy},
    rerank_client::{GatewayRerankClient, RerankLane},
    retrieval_embedding_client::GatewayRetrievalEmbeddingClient,
    status::{METRICS_ADDR_KEY, READINESS_REFRESH_KEY, ReadinessProbe, SemanticDeps},
};

const PREFIX: &str = "HUMAUX_GATEWAY_";
const ENUMERATION_TTL_KEY: &str = "HUMAUX_GATEWAY_ENUMERATION_TTL_SECONDS";
const ENUMERATION_MANIFEST_CAP_KEY: &str = "HUMAUX_GATEWAY_ENUMERATION_MANIFEST_CAP";
const TASK_LEASE_TTL_KEY: &str = "HUMAUX_GATEWAY_TASK_LEASE_TTL_SECONDS";
/// ADR-0084 D-E: the five parts of the deployment model pin, in `ModelIdentity::new` order (repo, revision, recipe, onnx
/// sha256, tokenizer sha256). The retrieval worker's `HUMAUX_RETRIEVAL_WORKER_RERANK_*` identity values must equal them.
const RERANK_PIN_KEYS: [&str; 5] = [
    "HUMAUX_GATEWAY_RERANK_REPO",
    "HUMAUX_GATEWAY_RERANK_REVISION",
    "HUMAUX_GATEWAY_RERANK_RECIPE",
    "HUMAUX_GATEWAY_RERANK_MODEL_SHA256",
    "HUMAUX_GATEWAY_RERANK_TOKENIZER_SHA256",
];
/// M02 D3: `true` enables the auth surface; only then is [`AUTH_HMAC_KEY_KEY`] required (no default, never logged).
const AUTH_SURFACE_ENABLED_KEY: &str = "HUMAUX_GATEWAY_AUTH_SURFACE_ENABLED";
const AUTH_HMAC_KEY_KEY: &str = "HUMAUX_GATEWAY_AUTH_HMAC_KEY";
const AUTH_HMAC_KEY_PREVIOUS_KEY: &str = "HUMAUX_GATEWAY_AUTH_HMAC_KEY_PREVIOUS";
const CREDENTIAL_TOUCH_INTERVAL_KEY: &str = "HUMAUX_GATEWAY_CREDENTIAL_TOUCH_INTERVAL_SECONDS";
/// Largest accepted credential touch interval: one hour. A technical bound, not a business limit: the stamp feeds the
/// 24 h activity window of `ops.health_snapshot` (0261), and an interval beyond an hour would blur it by more than a
/// twenty-fourth. Zero is accepted: it writes the stamp on every request, the behaviour before M02-2.
const MAX_CREDENTIAL_TOUCH_INTERVAL_SECONDS: u64 = 3600;
/// Largest accepted task-lease TTL, `u32::MAX` seconds (about 136 years). A technical bound, not a business limit:
/// `adapters::coord_repo` adds the TTL to the DB clock through `make_interval(secs => double precision)` (§30.2), so
/// the value must stay exact as an `f64`, its microseconds must fit the interval's `int64` field (4.3e15 here against
/// 9.2e18) and `clock_timestamp() + ttl` must stay inside `timestamptz` (last year 294276; this bound lands near
/// 2162). A larger value cannot be a lease anyone reclaims from a crashed owner. Zero is refused too: a lease that has
/// already expired when it is granted.
const MAX_TASK_LEASE_TTL_SECONDS: u64 = 4_294_967_295;
/// ADR-0065 D-B: the `application_name` of every gateway session — the process identity in `pg_stat_activity`
/// (the name `/status` reports), not a tunable.
const APPLICATION_NAME: &str = "humaux-gateway";

/// ADR-0078 D-A / D-D: the gateway's one M29 attribution implementation. Every Memory door caller in this process
/// (`memory.confirm`, `memory.correct`, `memory.note_put`) passes it to `memory_repo::insert_memory_in_txn`.
// ponytail: a static rather than a GatewayGuard / GatewayMcpApplication constructor field, because the ladder is
// stateless; make it a field once an implementation carries state (a pool, a config).
pub static MEMORY_ATTRIBUTION: AttributionLadder = AttributionLadder;
const PG_POOL_MAX_KEY: &str = "HUMAUX_GATEWAY_PG_POOL_MAX_CONNECTIONS";
const PG_POOL_MIN_KEY: &str = "HUMAUX_GATEWAY_PG_POOL_MIN_CONNECTIONS";
const PG_ACQUIRE_TIMEOUT_KEY: &str = "HUMAUX_GATEWAY_PG_ACQUIRE_TIMEOUT_MS";
const PG_IDLE_TIMEOUT_KEY: &str = "HUMAUX_GATEWAY_PG_IDLE_TIMEOUT_SECONDS";
const PG_MAX_LIFETIME_KEY: &str = "HUMAUX_GATEWAY_PG_MAX_LIFETIME_SECONDS";
const PG_STATEMENT_TIMEOUT_KEY: &str = "HUMAUX_GATEWAY_PG_STATEMENT_TIMEOUT_MS";
const PG_IDLE_IN_TRANSACTION_TIMEOUT_KEY: &str = "HUMAUX_GATEWAY_PG_IDLE_IN_TRANSACTION_TIMEOUT_MS";
const RATE_LOCK_TIMEOUT_KEY: &str = "HUMAUX_GATEWAY_RATE_LOCK_TIMEOUT_MS";
const RATE_PREAUTH_IPV6_PREFIX_BITS_KEY: &str = "HUMAUX_GATEWAY_RATE_PREAUTH_IPV6_PREFIX_BITS";
const ADMISSION_CONCURRENCY_KEY: &str = "HUMAUX_GATEWAY_ADMISSION_CONCURRENCY";
/// §67.2 / ADR-0065 D-D: `(class, capacity key, refill key)` of the five rate buckets, in `GuardRatePolicies` field
/// order. Every key is a whole literal so `xtask dep-map` sees it (ADR-0066 review fix 4: names built with `format!`
/// were invisible to the env examples and missing from the release bundle).
const RATE_BUCKET_KEYS: [(&str, &str, &str); 5] = [
    (
        "PREAUTH_IP",
        "HUMAUX_GATEWAY_RATE_PREAUTH_IP_CAPACITY",
        "HUMAUX_GATEWAY_RATE_PREAUTH_IP_REFILL_PER_SECOND",
    ),
    (
        "CREDENTIAL",
        "HUMAUX_GATEWAY_RATE_CREDENTIAL_CAPACITY",
        "HUMAUX_GATEWAY_RATE_CREDENTIAL_REFILL_PER_SECOND",
    ),
    (
        "USER",
        "HUMAUX_GATEWAY_RATE_USER_CAPACITY",
        "HUMAUX_GATEWAY_RATE_USER_REFILL_PER_SECOND",
    ),
    (
        "TENANT",
        "HUMAUX_GATEWAY_RATE_TENANT_CAPACITY",
        "HUMAUX_GATEWAY_RATE_TENANT_REFILL_PER_SECOND",
    ),
    (
        "OPERATION",
        "HUMAUX_GATEWAY_RATE_OPERATION_CAPACITY",
        "HUMAUX_GATEWAY_RATE_OPERATION_REFILL_PER_SECOND",
    ),
];
const ADMISSION_QUEUE_DEPTH_KEY: &str = "HUMAUX_GATEWAY_ADMISSION_QUEUE_DEPTH";
const ADMISSION_MAX_WAIT_KEY: &str = "HUMAUX_GATEWAY_ADMISSION_MAX_WAIT_MS";
const ADMISSION_PER_KEY_LIMIT_KEY: &str = "HUMAUX_GATEWAY_ADMISSION_PER_KEY_LIMIT";
const ADMISSION_BODY_READ_TIMEOUT_KEY: &str = "HUMAUX_GATEWAY_ADMISSION_BODY_READ_TIMEOUT_MS";

/// A fail-closed bootstrap error. It intentionally contains configuration keys,
/// never a DSN, pepper, or another secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapError {
    key: String,
    reason: &'static str,
}

impl BootstrapError {
    fn new(key: impl Into<String>, reason: &'static str) -> Self {
        Self {
            key: key.into(),
            reason,
        }
    }
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "gateway bootstrap configuration {}: {}",
            self.key, self.reason
        )
    }
}

impl std::error::Error for BootstrapError {}

/// Parsed process configuration. Secret fields stay private and this type does
/// not implement `Debug` so a normal startup error path cannot expose them.
pub struct GatewayBootstrap {
    bind_addr: SocketAddr,
    http: McpHttpConfig,
    pg_dsn: String,
    /// ADR-0065 D-A / D-B: the `role_gateway` pool's size and session timeouts, from the `PG_*` keys.
    pool_settings: PoolSettings,
    /// ADR-0065 D-C: the §67.2 admission bounds, from the five `ADMISSION_*` keys.
    admission: AdmissionSettings,
    guard: GuardSettings,
    remember_policy: RememberPolicy,
    remember_event_kind: RememberEventKind,
    context_bootstrap: ContextBootstrap,
    config_fingerprint: String,
    semantic_recall: Option<SemanticRecallConfig>,
    /// Copied out of `guard` before it moves into [`GatewayGuard::new`] (`build`) — the one
    /// piece of guard config the semantic-recall wiring also needs, for the Qdrant transport's
    /// own request timeout (never a literal, §78.1).
    handler_timeout: Duration,
    /// §33.10 rule 9 confirm-token lifetime (ADR-0018), `HUMAUX_GATEWAY_CONFIRM_TOKEN_TTL_SECONDS`.
    confirm_token_ttl: Duration,
    /// §78.1 memory.restore undo window (ADR-0020), `HUMAUX_GATEWAY_UNDO_WINDOW_SECONDS`.
    undo_window: Duration,
    /// §8.5.1 / ADR-0030 D-B frozen mood half-life policy (§78.1, no literal),
    /// `HUMAUX_GATEWAY_MOOD_HALF_LIFE_SECONDS`.
    mood_half_life: Duration,
    /// §15.5 / ADR-0059 D-G consistency-token MAC keys, installed process-wide in [`Self::build`].
    token_keys: TokenKeys,
    /// M02 D3 auth-surface MAC keys; `Some` exactly when `HUMAUX_GATEWAY_AUTH_SURFACE_ENABLED` is true. A separate
    /// key pair from `token_keys`: one leak must not mint both token families.
    auth_keys: Option<TokenKeys>,
    /// ADR-0061 D-B `HUMAUX_GATEWAY_METRICS_ADDR`: the loopback ops listener (`/metrics`, `/status`).
    metrics_addr: SocketAddr,
    /// ADR-0061 D-F `HUMAUX_GATEWAY_READINESS_REFRESH_SECONDS`.
    readiness_refresh: Duration,
    /// §30.2 / §78.1 `HUMAUX_GATEWAY_TASK_LEASE_TTL_SECONDS`: the lease `coordinate.task_claim` / `task_heartbeat` grant.
    task_lease_ttl: Duration,
    /// M02 D8 / §78.1 `HUMAUX_GATEWAY_CREDENTIAL_TOUCH_INTERVAL_SECONDS`: the least time between two `last_used_at`
    /// writes of one credential; every request still validates the credential.
    credential_touch_interval: Duration,
    /// ADR-0062 D-K `HUMAUX_GATEWAY_ENUMERATION_TTL_SECONDS`: one memory.enumerate manifest segment's lifetime.
    enumeration_ttl: Duration,
    /// ADR-0062 D-K `HUMAUX_GATEWAY_ENUMERATION_MANIFEST_CAP`: the most ids one manifest segment stores.
    enumeration_manifest_cap: usize,
    /// ADR-0061 D-B: one `{name, source, value | secret}` row per `registry()` entry, for `/status`.
    effective_config: Value,
}

/// Parsed `HUMAUX_GATEWAY_RETRIEVAL_RPC_*` / `HUMAUX_GATEWAY_EMBEDDING_*` /
/// `HUMAUX_GATEWAY_QDRANT_*` / `HUMAUX_GATEWAY_CELL_ID` / `HUMAUX_GATEWAY_CALLER_ID`
/// configuration — present only when
/// `HUMAUX_GATEWAY_RETRIEVAL_RPC_SOCKET_PATH` is non-empty (`parse_semantic_recall`'s doc).
struct SemanticRecallConfig {
    socket_path: String,
    /// ADR-0066 D-L: the retrieval worker's uid, verified on every dial.
    server_uid: u32,
    permit_ttl: Duration,
    embedding_dimension: u32,
    embedding_version: String,
    qdrant_host: String,
    qdrant_port: u16,
    qdrant_cidr: CellCidr,
    qdrant_tls: bool,
    cell_id: CellId,
    caller_id: CallerId,
    /// M12 D2: the query-embedding cache; `None` when no generation stamp is configured.
    query_cache: Option<(GenerationStamp, CacheConfig)>,
    /// ADR-0084 D-E: the deployment model pin; `Some` exactly when the profile turns the rerank lane on.
    rerank_pin: Option<ModelIdentity>,
}

/// Ready-to-serve components for `main`: bind [`Self::bind_addr`], then serve
/// [`Self::adapter`] through axum's `into_make_service_with_connect_info`.
pub struct GatewayRuntime {
    bind_addr: SocketAddr,
    adapter: McpAdapter,
    config_fingerprint: String,
    guard: Arc<GatewayGuard>,
    admission: Arc<Admission>,
    readiness: Option<ReadinessProbe>,
    metrics_addr: SocketAddr,
    readiness_refresh: Duration,
    effective_config: Value,
    auth_keys: Option<TokenKeys>,
}

impl GatewayRuntime {
    /// M02 D3: hands the auth-surface key set to the auth wiring once (`None` when the surface is off, or after the
    /// first call).
    pub fn take_auth_keys(&mut self) -> Option<TokenKeys> {
        self.auth_keys.take()
    }

    #[must_use]
    pub const fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    #[must_use]
    pub fn adapter(&self) -> &McpAdapter {
        &self.adapter
    }

    /// Safe to record at startup: every secret was replaced with `<redacted>`.
    #[must_use]
    pub fn config_fingerprint(&self) -> &str {
        &self.config_fingerprint
    }

    /// The guard whose counters `/metrics` renders.
    #[must_use]
    pub fn guard(&self) -> Arc<GatewayGuard> {
        Arc::clone(&self.guard)
    }

    /// ADR-0065 D-C: the admission state `main` wraps the MCP router with.
    #[must_use]
    pub fn admission(&self) -> Arc<Admission> {
        Arc::clone(&self.admission)
    }

    /// The readiness checks, handed once to the refresh task (`None` after the first call).
    pub fn take_readiness_probe(&mut self) -> Option<ReadinessProbe> {
        self.readiness.take()
    }

    /// ADR-0061 D-B: the loopback ops listener address.
    #[must_use]
    pub const fn metrics_addr(&self) -> SocketAddr {
        self.metrics_addr
    }

    /// ADR-0061 D-F: the readiness refresh interval (also each check's deadline).
    #[must_use]
    pub const fn readiness_refresh(&self) -> Duration {
        self.readiness_refresh
    }

    /// The `/status` `effective_config` rows; no secret value is in them.
    #[must_use]
    pub fn effective_config(&self) -> &Value {
        &self.effective_config
    }
}

impl GatewayBootstrap {
    /// Loads every `HUMAUX_GATEWAY_*` variable through the declared typed
    /// registry. Unknown, missing, empty, and malformed configuration fails
    /// before any database connection or listener bind.
    pub fn load_from_env() -> Result<Self, BootstrapError> {
        let raw = std::env::vars_os()
            .filter(|(key, _)| key.to_string_lossy().starts_with(PREFIX))
            .map(|(key, value)| {
                let key = key
                    .into_string()
                    .map_err(|_| BootstrapError::new(PREFIX, "non-Unicode configuration key"))?;
                let value = value
                    .into_string()
                    .map_err(|_| BootstrapError::new(&key, "non-Unicode configuration value"))?;
                Ok((key, value))
            })
            .collect::<Result<BTreeMap<_, _>, BootstrapError>>()?;
        Self::from_raw(raw)
    }

    /// Connects the checked `role_gateway` pool, then constructs the existing
    /// Guard/application/adapter chain. No caller can inject an alternate pool
    /// or a per-request write policy.
    pub async fn build(self) -> Result<GatewayRuntime, BootstrapError> {
        // ADR-0059 D-G: the one production install, before the pool, the guard and the listener.
        install_token_keys(self.token_keys).map_err(|_| {
            BootstrapError::new(
                "HUMAUX_GATEWAY_TOKEN_HMAC_KEY",
                "a different key set is already installed",
            )
        })?;
        // dep: PostgreSQL(role_gateway) — opens the sized role_gateway pool the rest of bootstrap wires into the app state
        let pool = RuntimeDbPool::connect_with(&self.pg_dsn, &self.pool_settings)
            .await
            .map_err(|_| BootstrapError::new("HUMAUX_GATEWAY_PG_DSN", "connection rejected"))?;
        let guard = Arc::new(
            GatewayGuard::new(pool, self.guard)
                .map_err(|_| BootstrapError::new("gateway guard", "unsafe configuration"))?
                .with_credential_touch_interval(self.credential_touch_interval),
        );
        let catalog = CanonicalCatalog::load().map_err(|_| {
            BootstrapError::new("canonical MCP catalog", "invalid embedded contract")
        })?;
        let advertised = catalog.trusted_catalog().map_err(|_| {
            BootstrapError::new("canonical MCP catalog", "invalid embedded contract")
        })?;
        let mut application = GatewayMcpApplication::new(
            catalog,
            guard.clone(),
            self.remember_policy,
            self.remember_event_kind,
            self.context_bootstrap,
        )
        .with_confirm_token_ttl(self.confirm_token_ttl)
        .map_err(|_| {
            BootstrapError::new(
                "HUMAUX_GATEWAY_CONFIRM_TOKEN_TTL_SECONDS",
                "must be positive seconds",
            )
        })?
        .with_undo_window(self.undo_window)
        .map_err(|_| {
            BootstrapError::new(
                "HUMAUX_GATEWAY_UNDO_WINDOW_SECONDS",
                "must be positive seconds",
            )
        })?
        .with_mood_half_life(self.mood_half_life)
        .map_err(|_| {
            BootstrapError::new(
                "HUMAUX_GATEWAY_MOOD_HALF_LIFE_SECONDS",
                "must be positive seconds",
            )
        })?
        .with_enumeration(self.enumeration_ttl, self.enumeration_manifest_cap)
        .map_err(|_| BootstrapError::new(ENUMERATION_TTL_KEY, "must be positive seconds"))?
        .with_task_lease_ttl(self.task_lease_ttl)
        .map_err(|_| BootstrapError::new(TASK_LEASE_TTL_KEY, "must be positive seconds"))?;
        let mut semantic = None;
        match self.semantic_recall {
            Some(config) => {
                let (runtime, deps) = build_semantic_recall_runtime(
                    guard.runtime_pool(),
                    config,
                    self.handler_timeout,
                )?;
                application = application.with_semantic_recall(runtime);
                semantic = Some(deps);
            }
            None => {
                // §57.1: not_applicable prints the missing object's name, not a silent skip.
                eprintln!(
                    "gateway bootstrap: not_applicable: HUMAUX_GATEWAY_RETRIEVAL_RPC_SOCKET_PATH \
                     (semantic recall stays disabled, recall.search keeps returning DependencyUnavailable)"
                );
            }
        }
        let application = Arc::new(application);
        Ok(GatewayRuntime {
            bind_addr: self.bind_addr,
            adapter: McpAdapter::new(application, advertised, self.http),
            config_fingerprint: self.config_fingerprint,
            readiness: Some(ReadinessProbe {
                pool: guard.runtime_pool(),
                semantic,
            }),
            guard,
            admission: Arc::new(Admission::new(self.admission)),
            metrics_addr: self.metrics_addr,
            readiness_refresh: self.readiness_refresh,
            effective_config: self.effective_config,
            auth_keys: self.auth_keys,
        })
    }

    fn from_raw(raw: BTreeMap<String, String>) -> Result<Self, BootstrapError> {
        let registry = registry();
        let effective = resolve_effective_config(&registry, &raw)
            .map_err(|error| BootstrapError::new(error.entry_name, "missing or undeclared"))?;
        validate_continuity_config(&effective)?;
        let remember_policy = parse_remember_policy(&effective)?;
        let context_bootstrap = parse_context_bootstrap(&effective, &remember_policy)?;
        let guard = parse_guard(&effective)?;
        let handler_timeout = guard.handler_timeout;
        let pool_settings = parse_pool(&effective, guard.rates.lock_timeout, handler_timeout)?;
        let admission = parse_admission(&effective, handler_timeout)?;
        let confirm_token_ttl = seconds(
            required(&effective, "HUMAUX_GATEWAY_CONFIRM_TOKEN_TTL_SECONDS")?,
            "HUMAUX_GATEWAY_CONFIRM_TOKEN_TTL_SECONDS",
        )?;
        let undo_window = seconds(
            required(&effective, "HUMAUX_GATEWAY_UNDO_WINDOW_SECONDS")?,
            "HUMAUX_GATEWAY_UNDO_WINDOW_SECONDS",
        )?;
        let mood_half_life = seconds(
            required(&effective, "HUMAUX_GATEWAY_MOOD_HALF_LIFE_SECONDS")?,
            "HUMAUX_GATEWAY_MOOD_HALF_LIFE_SECONDS",
        )?;
        let token_keys = parse_token_keys(&effective)?;
        let auth_keys = parse_auth_keys(&effective, &token_keys)?;
        let metrics_addr = parse_metrics_addr(required(&effective, METRICS_ADDR_KEY)?)?;
        let readiness_refresh = seconds(
            required(&effective, READINESS_REFRESH_KEY)?,
            READINESS_REFRESH_KEY,
        )?;
        // ADR-0084 D-E / U7: while the lane is on, the gateway needs the model pin, and its wait must fit in the handler.
        let rerank_enabled = context_bootstrap.profile.rerank_enabled();
        check_rerank_timeout(
            rerank_enabled,
            context_bootstrap.profile.rerank_timeout_ms(),
            handler_timeout,
        )?;
        let semantic_recall = match parse_semantic_recall(&effective)? {
            Some(config) => Some(SemanticRecallConfig {
                rerank_pin: parse_rerank_pin(&effective, rerank_enabled)?,
                ..config
            }),
            None => None,
        };
        let task_lease_ttl = task_lease_ttl(required(&effective, TASK_LEASE_TTL_KEY)?)?;
        let credential_touch_interval =
            credential_touch_interval(required(&effective, CREDENTIAL_TOUCH_INTERVAL_KEY)?)?;
        let enumeration_ttl = seconds(
            required(&effective, ENUMERATION_TTL_KEY)?,
            ENUMERATION_TTL_KEY,
        )?;
        let enumeration_manifest_cap = parse_usize(
            required(&effective, ENUMERATION_MANIFEST_CAP_KEY)?,
            ENUMERATION_MANIFEST_CAP_KEY,
        )?;

        Ok(Self {
            bind_addr: parse_bind_addr(required(&effective, "HUMAUX_GATEWAY_BIND_ADDR")?)?,
            http: parse_http(&effective)?,
            pg_dsn: required(&effective, "HUMAUX_GATEWAY_PG_DSN")?.to_owned(),
            pool_settings,
            admission,
            guard,
            remember_policy,
            remember_event_kind: parse_remember_event_kind(&effective)?,
            context_bootstrap,
            config_fingerprint: redacted_fingerprint(&registry, &effective),
            semantic_recall,
            handler_timeout,
            confirm_token_ttl,
            undo_window,
            mood_half_life,
            token_keys,
            auth_keys,
            metrics_addr,
            readiness_refresh,
            task_lease_ttl,
            credential_touch_interval,
            enumeration_ttl,
            enumeration_manifest_cap,
            effective_config: effective_config_rows(&registry, &raw, &effective),
        })
    }
}

fn validate_continuity_config(effective: &BTreeMap<String, String>) -> Result<(), BootstrapError> {
    use humaux_contracts::config_registry::{
        CONTINUITY_LIST_MERGE_ATTEMPTS, continuity_list_merge_attempts,
    };
    continuity_list_merge_attempts(
        effective
            .get(CONTINUITY_LIST_MERGE_ATTEMPTS)
            .map(String::as_str),
    )
    .map(|_| ())
    .map_err(|error| BootstrapError::new(error.entry_name, "must be a positive integer"))
}

/// ADR-0061 D-B: the ops listener binds loopback only, on a fixed port Prometheus can target.
fn parse_metrics_addr(value: &str) -> Result<SocketAddr, BootstrapError> {
    humaux_telemetry::metrics::parse_ops_addr(value)
        .map_err(|reason| BootstrapError::new(METRICS_ADDR_KEY, reason))
}

/// ADR-0061 D-B: the `/status` `effective_config` rows — `source` is `env` when the variable was
/// set and `default` otherwise. The one place a value is exposed, and it reads the entry's own
/// `secret` flag for every entry whichever constructor (`entry` / `entry_with_default`) made it:
/// a secret row carries `secret: true` and no `value` key at all.
fn effective_config_rows(
    registry: &[ConfigEntry],
    raw: &BTreeMap<String, String>,
    effective: &BTreeMap<String, String>,
) -> Value {
    registry
        .iter()
        .map(|entry| {
            let source = if raw.contains_key(&entry.name) {
                "env"
            } else {
                "default"
            };
            let mut row = Map::new();
            row.insert("name".into(), Value::from(entry.name.as_str()));
            row.insert("source".into(), Value::from(source));
            if entry.secret {
                row.insert("secret".into(), Value::Bool(true));
            } else {
                row.insert(
                    "value".into(),
                    effective
                        .get(&entry.name)
                        .map_or(Value::Null, |v| Value::from(v.as_str())),
                );
            }
            Value::Object(row)
        })
        .collect()
}

/// ADR-0059 D-G: `HUMAUX_GATEWAY_TOKEN_HMAC_KEY` (required, no default) and the optional rotation
/// twin `…_PREVIOUS` (empty = window closed). Errors name the key, never a value.
fn parse_token_keys(effective: &BTreeMap<String, String>) -> Result<TokenKeys, BootstrapError> {
    const CURRENT: &str = "HUMAUX_GATEWAY_TOKEN_HMAC_KEY";
    const PREVIOUS: &str = "HUMAUX_GATEWAY_TOKEN_HMAC_KEY_PREVIOUS";
    let current = hex::decode(required(effective, CURRENT)?)
        .map_err(|_| BootstrapError::new(CURRENT, "invalid hex"))?;
    let previous = optional_hex(effective, PREVIOUS)?;
    // TokenKeys::new names the failing key ("current …" / "previous …") without its value.
    TokenKeys::new(current, previous).map_err(|why| {
        BootstrapError::new(
            if why.starts_with("current") {
                CURRENT
            } else {
                PREVIOUS
            },
            why,
        )
    })
}

/// M02 D3: the auth-surface key pair. `None` while `HUMAUX_GATEWAY_AUTH_SURFACE_ENABLED` is false; when true the key
/// is required — unset or empty refuses to boot naming the key, there is no fallback key — and must share no key
/// with the consistency-token set. Errors name the key, never a value.
fn parse_auth_keys(
    effective: &BTreeMap<String, String>,
    token_keys: &TokenKeys,
) -> Result<Option<TokenKeys>, BootstrapError> {
    match present(effective, AUTH_SURFACE_ENABLED_KEY)? {
        "true" => {}
        "false" => return Ok(None),
        _ => {
            return Err(BootstrapError::new(
                AUTH_SURFACE_ENABLED_KEY,
                "must be true or false",
            ));
        }
    }
    let current = hex::decode(required(effective, AUTH_HMAC_KEY_KEY)?)
        .map_err(|_| BootstrapError::new(AUTH_HMAC_KEY_KEY, "invalid hex"))?;
    let previous = optional_hex(effective, AUTH_HMAC_KEY_PREVIOUS_KEY)?;
    let keys = TokenKeys::new(current, previous).map_err(|why| {
        BootstrapError::new(
            if why.starts_with("current") {
                AUTH_HMAC_KEY_KEY
            } else {
                AUTH_HMAC_KEY_PREVIOUS_KEY
            },
            why,
        )
    })?;
    if keys.shares_key_with(token_keys) {
        return Err(BootstrapError::new(
            AUTH_HMAC_KEY_KEY,
            "must differ from the consistency-token keys",
        ));
    }
    Ok(Some(keys))
}

/// An optional secret hex key registered with default `""`: empty = absent; otherwise valid hex.
fn optional_hex(
    effective: &BTreeMap<String, String>,
    key: &str,
) -> Result<Option<Vec<u8>>, BootstrapError> {
    let value = present(effective, key)?;
    if value.trim().is_empty() {
        return Ok(None);
    }
    hex::decode(value)
        .map(Some)
        .map_err(|_| BootstrapError::new(key, "invalid hex"))
}

fn parse_http(effective: &BTreeMap<String, String>) -> Result<McpHttpConfig, BootstrapError> {
    McpHttpConfig::new(
        csv_nonempty(
            required(effective, "HUMAUX_GATEWAY_ALLOWED_HOSTS")?,
            "HUMAUX_GATEWAY_ALLOWED_HOSTS",
        )?,
        csv_nonempty(
            required(effective, "HUMAUX_GATEWAY_ALLOWED_ORIGINS")?,
            "HUMAUX_GATEWAY_ALLOWED_ORIGINS",
        )?,
        parse_usize(
            required(effective, "HUMAUX_GATEWAY_MAX_REQUEST_BODY_BYTES")?,
            "HUMAUX_GATEWAY_MAX_REQUEST_BODY_BYTES",
        )?,
    )
    .map_err(|_| BootstrapError::new("HUMAUX_GATEWAY_MAX_REQUEST_BODY_BYTES", "invalid"))
}

fn parse_guard(effective: &BTreeMap<String, String>) -> Result<GuardSettings, BootstrapError> {
    let pepper = hex::decode(required(effective, "HUMAUX_GATEWAY_CREDENTIAL_PEPPER_HEX")?)
        .map_err(|_| BootstrapError::new("HUMAUX_GATEWAY_CREDENTIAL_PEPPER_HEX", "invalid hex"))?;
    if pepper.is_empty() {
        return Err(BootstrapError::new(
            "HUMAUX_GATEWAY_CREDENTIAL_PEPPER_HEX",
            "must not be empty",
        ));
    }
    // ADR-0059 D-H: the rotation window is open exactly while this key is set (runbook Rotate).
    let pepper_previous = optional_hex(effective, "HUMAUX_GATEWAY_CREDENTIAL_PEPPER_PREVIOUS_HEX")?;
    if pepper_previous.as_ref() == Some(&pepper) {
        return Err(BootstrapError::new(
            "HUMAUX_GATEWAY_CREDENTIAL_PEPPER_PREVIOUS_HEX",
            "must differ from the current pepper",
        ));
    }
    let guard = GuardSettings {
        credential_pepper: pepper,
        credential_pepper_previous: pepper_previous,
        trusted_proxies: TrustedProxyConfig {
            trusted_proxy_cidrs: cidrs(
                present(effective, "HUMAUX_GATEWAY_TRUSTED_PROXY_CIDRS")?,
                "HUMAUX_GATEWAY_TRUSTED_PROXY_CIDRS",
            )?,
            max_forwarded_hops: parse_usize(
                required(effective, "HUMAUX_GATEWAY_MAX_FORWARDED_HOPS")?,
                "HUMAUX_GATEWAY_MAX_FORWARDED_HOPS",
            )?,
        },
        global_denylist: cidrs(
            present(effective, "HUMAUX_GATEWAY_GLOBAL_DENYLIST")?,
            "HUMAUX_GATEWAY_GLOBAL_DENYLIST",
        )?,
        global_emergency_allowlist: cidrs(
            present(effective, "HUMAUX_GATEWAY_GLOBAL_EMERGENCY_ALLOWLIST")?,
            "HUMAUX_GATEWAY_GLOBAL_EMERGENCY_ALLOWLIST",
        )?,
        tenant_network: BTreeMap::new(),
        rates: GuardRatePolicies {
            preauth_ip: rate(effective, RATE_BUCKET_KEYS[0])?,
            credential: rate(effective, RATE_BUCKET_KEYS[1])?,
            user: rate(effective, RATE_BUCKET_KEYS[2])?,
            tenant: rate(effective, RATE_BUCKET_KEYS[3])?,
            operation: rate(effective, RATE_BUCKET_KEYS[4])?,
            lock_timeout: millis(
                required(effective, RATE_LOCK_TIMEOUT_KEY)?,
                RATE_LOCK_TIMEOUT_KEY,
            )?,
            preauth_ipv6_prefix_bits: required(effective, RATE_PREAUTH_IPV6_PREFIX_BITS_KEY)?
                .parse::<u8>()
                .ok()
                .filter(|bits| (1..=128).contains(bits))
                .ok_or_else(|| {
                    BootstrapError::new(RATE_PREAUTH_IPV6_PREFIX_BITS_KEY, "must be 1..=128")
                })?,
        },
        reservation_ttl: seconds(
            required(effective, "HUMAUX_GATEWAY_RESERVATION_TTL_SECONDS")?,
            "HUMAUX_GATEWAY_RESERVATION_TTL_SECONDS",
        )?,
        handler_timeout: seconds(
            required(effective, "HUMAUX_GATEWAY_HANDLER_TIMEOUT_SECONDS")?,
            "HUMAUX_GATEWAY_HANDLER_TIMEOUT_SECONDS",
        )?,
        finalize_timeout: seconds(
            required(effective, "HUMAUX_GATEWAY_FINALIZE_TIMEOUT_SECONDS")?,
            "HUMAUX_GATEWAY_FINALIZE_TIMEOUT_SECONDS",
        )?,
        replay_ttl: seconds(
            required(effective, "HUMAUX_GATEWAY_REPLAY_TTL_SECONDS")?,
            "HUMAUX_GATEWAY_REPLAY_TTL_SECONDS",
        )?,
    };
    validate_guard(&guard)?;
    Ok(guard)
}

fn parse_remember_policy(
    effective: &BTreeMap<String, String>,
) -> Result<RememberPolicy, BootstrapError> {
    // ADR-0054 D-D: the former default write pair is optional and unused. A present value must
    // still be a UUID (fail closed on garbage); it only earns one startup line. The keys stay
    // registered because `xtask e2e-onboard` still passes them.
    for key in [
        "HUMAUX_GATEWAY_REMEMBER_TENANT_ID",
        "HUMAUX_GATEWAY_REMEMBER_WORKSPACE_ID",
    ] {
        let value = present(effective, key)?;
        if !value.trim().is_empty() {
            uuid(value, key)?;
            eprintln!(
                "gateway bootstrap: {key} ignored since ADR-0054 (writes derive (tenant, workspace) per request)"
            );
        }
    }
    let scope_kind = required(effective, "HUMAUX_GATEWAY_REMEMBER_SCOPE_KIND")?;
    if scope_kind != "workspace" {
        return Err(BootstrapError::new(
            "HUMAUX_GATEWAY_REMEMBER_SCOPE_KIND",
            "only workspace is enabled",
        ));
    }
    let family = ProcessFamily::new(
        scope_kind,
        nonempty(
            required(effective, "HUMAUX_GATEWAY_REMEMBER_DOMAIN")?,
            "HUMAUX_GATEWAY_REMEMBER_DOMAIN",
        )?,
        nonempty(
            required(effective, "HUMAUX_GATEWAY_REMEMBER_PROJECTION_KIND")?,
            "HUMAUX_GATEWAY_REMEMBER_PROJECTION_KIND",
        )?,
        nonempty(
            required(effective, "HUMAUX_GATEWAY_REMEMBER_PROJECTION_VERSION")?,
            "HUMAUX_GATEWAY_REMEMBER_PROJECTION_VERSION",
        )?,
    )
    .map_err(|_| BootstrapError::new("HUMAUX_GATEWAY_REMEMBER_*", "invalid stream family"))?;
    RememberPolicy::new(
        family,
        uuid(
            required(effective, "HUMAUX_GATEWAY_REMEMBER_REASONING_DOMAIN_ID")?,
            "HUMAUX_GATEWAY_REMEMBER_REASONING_DOMAIN_ID",
        )?,
        seconds(
            required(effective, "HUMAUX_GATEWAY_REMEMBER_TOKEN_TTL_SECONDS")?,
            "HUMAUX_GATEWAY_REMEMBER_TOKEN_TTL_SECONDS",
        )?,
        data_class(required(effective, "HUMAUX_GATEWAY_REMEMBER_DATA_CLASS")?)?,
        visibility(required(
            effective,
            "HUMAUX_GATEWAY_REMEMBER_VISIBILITY_CLASS",
        )?)?,
    )
    .map_err(|_| BootstrapError::new("HUMAUX_GATEWAY_REMEMBER_*", "invalid write policy"))
}

fn parse_remember_event_kind(
    effective: &BTreeMap<String, String>,
) -> Result<RememberEventKind, BootstrapError> {
    event_kind(required(effective, "HUMAUX_GATEWAY_REMEMBER_EVENT_KIND")?)
}

fn parse_context_bootstrap(
    effective: &BTreeMap<String, String>,
    write_policy: &RememberPolicy,
) -> Result<ContextBootstrap, BootstrapError> {
    let budget = ContextBudget::new(
        parse_u32(
            required(effective, "HUMAUX_GATEWAY_CONTEXT_TOTAL_TOKENS")?,
            "HUMAUX_GATEWAY_CONTEXT_TOTAL_TOKENS",
        )?,
        parse_u32(
            required(effective, "HUMAUX_GATEWAY_CONTEXT_MANDATORY_TOKENS")?,
            "HUMAUX_GATEWAY_CONTEXT_MANDATORY_TOKENS",
        )?,
    )
    .map_err(|_| BootstrapError::new("HUMAUX_GATEWAY_CONTEXT_*_TOKENS", "invalid budget"))?;
    let raw = retrieval_profile_registry()
        .into_iter()
        .map(|entry| {
            let value = required(effective, &retrieval_env_key(&entry.name))?.to_owned();
            Ok((entry.name, value))
        })
        .collect::<Result<BTreeMap<_, _>, BootstrapError>>()?;
    let profile = resolve_registered_retrieval_profile(&raw)
        .map_err(|_| BootstrapError::new("HUMAUX_GATEWAY_RETRIEVAL_*", "invalid profile"))?;
    let projection_lag = seconds(
        required(effective, "HUMAUX_GATEWAY_PROJECTION_LAG_SECONDS")?,
        "HUMAUX_GATEWAY_PROJECTION_LAG_SECONDS",
    )?;
    ContextBootstrap::new(budget, profile, write_policy, projection_lag)
        .map_err(|_| BootstrapError::new("gateway binary", "provenance unavailable"))
}

/// `HUMAUX_GATEWAY_RETRIEVAL_RPC_SOCKET_PATH` gates the whole feature: empty (not merely
/// "unset" — see [`registry`]'s doc on why every declared key must literally be present, even
/// blank) means semantic recall stays disabled and every other `HUMAUX_GATEWAY_{RETRIEVAL_RPC,
/// EMBEDDING,QDRANT,CELL_ID,CALLER_ID}_*` key may itself be blank. A non-empty socket
/// path requires all of them filled in.
fn parse_semantic_recall(
    effective: &BTreeMap<String, String>,
) -> Result<Option<SemanticRecallConfig>, BootstrapError> {
    let socket_path = present(effective, "HUMAUX_GATEWAY_RETRIEVAL_RPC_SOCKET_PATH")?;
    if socket_path.trim().is_empty() {
        return Ok(None);
    }
    let embedding_dimension = parse_u32(
        required(effective, "HUMAUX_GATEWAY_EMBEDDING_DIMENSION")?,
        "HUMAUX_GATEWAY_EMBEDDING_DIMENSION",
    )?;
    let embedding_version = nonempty(
        required(effective, "HUMAUX_GATEWAY_EMBEDDING_VERSION")?,
        "HUMAUX_GATEWAY_EMBEDDING_VERSION",
    )?
    .to_owned();
    Ok(Some(SemanticRecallConfig {
        rerank_pin: None,
        query_cache: parse_query_cache(effective, &embedding_version, embedding_dimension)?,
        socket_path: socket_path.to_owned(),
        server_uid: parse_u32(
            required(effective, "HUMAUX_GATEWAY_RETRIEVAL_RPC_SERVER_UID")?,
            "HUMAUX_GATEWAY_RETRIEVAL_RPC_SERVER_UID",
        )?,
        permit_ttl: seconds(
            required(effective, "HUMAUX_GATEWAY_RETRIEVAL_RPC_PERMIT_TTL_SECONDS")?,
            "HUMAUX_GATEWAY_RETRIEVAL_RPC_PERMIT_TTL_SECONDS",
        )?,
        embedding_dimension,
        embedding_version,
        qdrant_host: nonempty(
            required(effective, "HUMAUX_GATEWAY_QDRANT_HOST")?,
            "HUMAUX_GATEWAY_QDRANT_HOST",
        )?
        .to_owned(),
        qdrant_port: {
            let port = parse_u32(
                required(effective, "HUMAUX_GATEWAY_QDRANT_PORT")?,
                "HUMAUX_GATEWAY_QDRANT_PORT",
            )?;
            u16::try_from(port)
                .map_err(|_| BootstrapError::new("HUMAUX_GATEWAY_QDRANT_PORT", "must fit u16"))?
        },
        qdrant_cidr: required(effective, "HUMAUX_GATEWAY_QDRANT_CIDR")?
            .parse()
            .map_err(|_| BootstrapError::new("HUMAUX_GATEWAY_QDRANT_CIDR", "invalid CIDR"))?,
        qdrant_tls: match required(effective, "HUMAUX_GATEWAY_QDRANT_TLS")? {
            "true" => true,
            "false" => false,
            _ => {
                return Err(BootstrapError::new(
                    "HUMAUX_GATEWAY_QDRANT_TLS",
                    "must be true or false",
                ));
            }
        },
        cell_id: CellId(uuid(
            required(effective, "HUMAUX_GATEWAY_CELL_ID")?,
            "HUMAUX_GATEWAY_CELL_ID",
        )?),
        caller_id: CallerId(
            nonempty(
                required(effective, "HUMAUX_GATEWAY_CALLER_ID")?,
                "HUMAUX_GATEWAY_CALLER_ID",
            )?
            .to_owned(),
        ),
    }))
}

/// ADR-0084 D-E: the deployment model pin. While `rerank_enabled` is false the keys are not read; while it is true all
/// five are required and must form a valid identity (`ModelIdentity::new`), or the process refuses to boot: a lane with
/// no pin could not tell which model answered. Hashes are accepted in either case and compared in lower case, as the
/// worker reports them.
fn parse_rerank_pin(
    effective: &BTreeMap<String, String>,
    rerank_enabled: bool,
) -> Result<Option<ModelIdentity>, BootstrapError> {
    if !rerank_enabled {
        return Ok(None);
    }
    let [repo, revision, recipe, onnx, tokenizer] = RERANK_PIN_KEYS;
    ModelIdentity::new(
        required(effective, repo)?.trim(),
        required(effective, revision)?.trim(),
        required(effective, recipe)?.trim(),
        &required(effective, onnx)?.trim().to_ascii_lowercase(),
        &required(effective, tokenizer)?.trim().to_ascii_lowercase(),
    )
    .map(Some)
    .ok_or_else(|| BootstrapError::new("HUMAUX_GATEWAY_RERANK_*", "invalid model identity"))
}

/// ADR-0084 U7: while the lane is on, `rerank_timeout_ms` must be below the handler timeout, or the handler's deadline
/// would always fire before the wait elapsed and a slow worker would fail the recall instead of degrading it. The wait
/// is also capped at run time by what is left of the handler budget (`recall::rerank_wait`).
fn check_rerank_timeout(
    rerank_enabled: bool,
    rerank_timeout_ms: u32,
    handler_timeout: Duration,
) -> Result<(), BootstrapError> {
    if rerank_enabled && Duration::from_millis(u64::from(rerank_timeout_ms)) >= handler_timeout {
        return Err(BootstrapError::new(
            retrieval_env_key(RERANK_TIMEOUT_MS),
            "must be below HUMAUX_GATEWAY_HANDLER_TIMEOUT_SECONDS (ADR-0084 U7)",
        ));
    }
    Ok(())
}

/// M12 D4 / D5 (§51, §78.1): the query-embedding cache of the semantic-recall lane. An all-blank generation stamp
/// (`EMBEDDING_{PROVIDER_ID,MODEL_ID,MODEL_REVISION}`) is `None`: the cache stays off and `build` prints
/// not_applicable. A partly filled stamp is a boot error, never a cache keyed on a guessed field.
fn parse_query_cache(
    effective: &BTreeMap<String, String>,
    embedding_version: &str,
    dimension: u32,
) -> Result<Option<(GenerationStamp, CacheConfig)>, BootstrapError> {
    const STAMP: [&str; 3] = [
        "HUMAUX_GATEWAY_EMBEDDING_PROVIDER_ID",
        "HUMAUX_GATEWAY_EMBEDDING_MODEL_ID",
        "HUMAUX_GATEWAY_EMBEDDING_MODEL_REVISION",
    ];
    const ENABLED: &str = "HUMAUX_GATEWAY_CACHE_EMBED_QUERY_ENABLED";
    const BYTES: &str = "HUMAUX_GATEWAY_CACHE_EMBED_QUERY_BYTES";
    const PER_TENANT_BYTES: &str = "HUMAUX_GATEWAY_CACHE_PER_TENANT_BYTES";
    const TTL: &str = "HUMAUX_GATEWAY_CACHE_EMBED_QUERY_TTL_SECONDS";
    let stamp = STAMP.map(|key| effective.get(key).map_or("", |value| value.trim()));
    if stamp.iter().all(|value| value.is_empty()) {
        return Ok(None);
    }
    if let Some(missing) = stamp.iter().position(|value| value.is_empty()) {
        return Err(BootstrapError::new(STAMP[missing], "missing or empty"));
    }
    let [provider_id, model_id, model_revision] = stamp;
    let bytes = |key: &str| -> Result<u64, BootstrapError> {
        required(effective, key)?
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| BootstrapError::new(key, "must be a positive integer"))
    };
    let enabled = match required(effective, ENABLED)? {
        "true" => true,
        "false" => false,
        _ => return Err(BootstrapError::new(ENABLED, "must be true or false")),
    };
    Ok(Some((
        GenerationStamp {
            embedding_version: embedding_version.to_owned(),
            provider_id: provider_id.to_owned(),
            model_id: model_id.to_owned(),
            model_revision: model_revision.to_owned(),
            dimension,
        },
        CacheConfig {
            capacity_bytes: bytes(BYTES)?,
            per_tenant_bytes: bytes(PER_TENANT_BYTES)?,
            // u32 seconds (~136 years) keeps the TTL under moka's 1000-year limit, which panics (cache::bounded).
            ttl: Duration::from_secs(u64::from(parse_u32(required(effective, TTL)?, TTL)?)),
            enabled,
        },
    )))
}

/// Builds the one native semantic-recall lane's runtime — `IntraCellResource::QDRANT_REST`
/// registered [`CellAccessMode::QdrantReadOnly`] (2026-08-30 ruling), never `ReadWrite`;
/// `xtask architecture-check`'s ADR-0014 gate statically asserts this file never constructs
/// the latter. `IntraCellResource::RETRIEVAL_EMBEDDING_RPC` shares the same registry/Cell/
/// caller identity (ADR-0012 §决定3) even though its actual transport bypasses
/// `IntraCellHttpTransport` entirely (`GatewayRetrievalEmbeddingClient`'s own doc).
fn build_semantic_recall_runtime(
    pool: Arc<RuntimeDbPool>,
    config: SemanticRecallConfig,
    handler_timeout: Duration,
) -> Result<(SemanticRecallRuntime, SemanticDeps), BootstrapError> {
    let mut entries = BTreeMap::new();
    entries.insert(
        IntraCellResource::QDRANT_REST,
        ResourceEntry::new(
            config.qdrant_host,
            config.qdrant_port,
            config.cell_id,
            vec![config.qdrant_cidr],
            BTreeSet::from([config.caller_id.clone()]),
            config.qdrant_tls,
        )
        .map_err(|_| BootstrapError::new("HUMAUX_GATEWAY_QDRANT_*", "invalid Qdrant resource"))?
        .with_access_mode(CellAccessMode::QdrantReadOnly),
    );
    entries.insert(
        IntraCellResource::RETRIEVAL_EMBEDDING_RPC,
        ResourceEntry::new(
            "unix-socket",
            0,
            config.cell_id,
            vec![],
            BTreeSet::from([config.caller_id.clone()]),
            false,
        )
        .map_err(|_| {
            BootstrapError::new("gateway semantic recall", "invalid RPC resource entry")
        })?,
    );
    let registry = IntraCellResourceRegistry::new(entries, config.cell_id, config.caller_id);

    let qdrant_transport = Arc::new(
        HttpIntraCellTransport::new(
            registry.clone(),
            handler_timeout,
            DEFAULT_MAX_RESPONSE_BYTES,
        )
        .map_err(|_| {
            BootstrapError::new(
                "gateway semantic recall",
                "could not construct Qdrant transport",
            )
        })?,
    );
    let client = Arc::new(GatewayRetrievalEmbeddingClient::new(
        pool,
        config.socket_path.clone(),
        config.server_uid,
        registry.clone(),
        config.permit_ttl,
    ));
    // ADR-0084 D-B: the rerank client dials the same socket as the embedding client, behind the same uid check.
    let rerank = config.rerank_pin.map(|pin| {
        RerankLane::new(
            Arc::new(GatewayRerankClient::new(
                config.socket_path.clone(),
                config.server_uid,
                registry.clone(),
                config.permit_ttl,
            )),
            pin,
        )
    });
    // ADR-0061 D-F: readiness checks the same client, socket, transport and registry recall uses.
    let deps = SemanticDeps {
        rpc: Arc::clone(&client),
        socket_path: config.socket_path,
        qdrant: qdrant_transport.clone(),
        registry: registry.clone(),
    };
    let embedding_port: Arc<dyn RetrievalEmbeddingPort> = match config.query_cache {
        Some((stamp, cache)) => Arc::new(CachedEmbeddingPort::new(client, stamp, cache)),
        None => {
            // §57.1: not_applicable names the missing object.
            eprintln!(
                "gateway bootstrap: not_applicable: HUMAUX_GATEWAY_EMBEDDING_{{PROVIDER_ID,MODEL_ID,MODEL_REVISION}} \
                 (query-embedding cache stays off, every recall embeds through the retrieval worker)"
            );
            client
        }
    };
    // ADR-0056 D-C: no scanner here — the retrieval worker's `seal_query` is the one query seal.
    SemanticRecallRuntime::new(
        embedding_port,
        qdrant_transport,
        registry,
        SemanticRecallVersions {
            embedding_version: config.embedding_version,
            dimension: config.embedding_dimension,
        },
        handler_timeout,
        rerank,
    )
    .map(|runtime| (runtime, deps))
    .map_err(|_| BootstrapError::new("gateway semantic recall", "invalid runtime configuration"))
}

fn retrieval_env_key(canonical_key: &str) -> String {
    format!(
        "{PREFIX}{}",
        canonical_key.replace('.', "_").to_ascii_uppercase()
    )
}

/// Every `HUMAUX_GATEWAY_*` key this process reads (§78.1): the boot validator, the config
/// fingerprint and the `/status` `effective_config` all derive from this one list. Public so the
/// ops-listener test derives its secret canaries from it rather than from a hand list.
#[must_use]
#[allow(clippy::too_many_lines)] // One flat declaration list per §78.1 key; splitting it would hide a key from review.
pub fn registry() -> Vec<ConfigEntry> {
    let mut entries = [
        ("BIND_ADDR", "socket_addr", false),
        ("ALLOWED_HOSTS", "csv", false),
        ("ALLOWED_ORIGINS", "csv", false),
        ("MAX_REQUEST_BODY_BYTES", "usize", false),
        ("PG_DSN", "dsn", true),
        ("CREDENTIAL_PEPPER_HEX", "hex", true),
        // ADR-0059 D-G: no default — boot-fatal when absent.
        ("TOKEN_HMAC_KEY", "hex", true),
        ("TRUSTED_PROXY_CIDRS", "csv-cidr", false),
        ("MAX_FORWARDED_HOPS", "usize", false),
        ("GLOBAL_DENYLIST", "csv-cidr", false),
        ("GLOBAL_EMERGENCY_ALLOWLIST", "csv-cidr", false),
        ("RESERVATION_TTL_SECONDS", "u64", false),
        ("HANDLER_TIMEOUT_SECONDS", "u64", false),
        ("FINALIZE_TIMEOUT_SECONDS", "u64", false),
        ("REPLAY_TTL_SECONDS", "u64", false),
        ("CONFIRM_TOKEN_TTL_SECONDS", "u64", false),
        ("UNDO_WINDOW_SECONDS", "u64", false),
        ("MOOD_HALF_LIFE_SECONDS", "u64", false),
        // §78.1: no default — boot-fatal when absent (ADR-0057 D-F, §22.4 projection lag).
        ("PROJECTION_LAG_SECONDS", "u64", false),
        // ADR-0062 D-K / §78.1: no default — boot-fatal when absent (memory.enumerate manifest lifetime and cap).
        ("ENUMERATION_TTL_SECONDS", "u64", false),
        ("ENUMERATION_MANIFEST_CAP", "usize", false),
        ("REMEMBER_SCOPE_KIND", "enum:workspace", false),
        ("REMEMBER_DOMAIN", "string", false),
        ("REMEMBER_PROJECTION_KIND", "string", false),
        ("REMEMBER_PROJECTION_VERSION", "string", false),
        ("REMEMBER_REASONING_DOMAIN_ID", "uuid", false),
        ("REMEMBER_TOKEN_TTL_SECONDS", "u64", false),
        (
            "REMEMBER_DATA_CLASS",
            "enum:PUBLIC|INTERNAL|PRIVATE|SENSITIVE|SECRET_MATERIAL",
            false,
        ),
        (
            "REMEMBER_VISIBILITY_CLASS",
            "enum:USER_PRIVATE|WORKSPACE_SHARED",
            false,
        ),
        ("REMEMBER_EVENT_KIND", "enum", false),
        ("CONTEXT_TOTAL_TOKENS", "u32", false),
        ("CONTEXT_MANDATORY_TOKENS", "u32", false),
        // ADR-0061 D-B / D-F: no default — boot-fatal when absent.
        ("METRICS_ADDR", "socket_addr", false),
        ("READINESS_REFRESH_SECONDS", "u64", false),
        // ADR-0065 D-A / D-B (§78.1): no default — boot-fatal when absent; the measured start values live in the
        // launchers and ADR-0065, never here (ruling R-5).
        ("PG_POOL_MAX_CONNECTIONS", "u32", false),
        ("PG_POOL_MIN_CONNECTIONS", "u32", false),
        ("PG_ACQUIRE_TIMEOUT_MS", "u64", false),
        ("PG_IDLE_TIMEOUT_SECONDS", "u64", false),
        ("PG_MAX_LIFETIME_SECONDS", "u64", false),
        ("PG_STATEMENT_TIMEOUT_MS", "u64", false),
        ("PG_IDLE_IN_TRANSACTION_TIMEOUT_MS", "u64", false),
        // ADR-0065 D-D / D-E (§78.1 限流阈值): no default — boot-fatal when absent (ruling R-5).
        ("RATE_LOCK_TIMEOUT_MS", "u64", false),
        ("RATE_PREAUTH_IPV6_PREFIX_BITS", "u8", false),
        // ADR-0065 D-C (§67.2, §78.1): no default — boot-fatal when absent (ruling R-5).
        ("ADMISSION_CONCURRENCY", "u32", false),
        ("ADMISSION_QUEUE_DEPTH", "u32", false),
        ("ADMISSION_MAX_WAIT_MS", "u64", false),
        ("ADMISSION_PER_KEY_LIMIT", "u32", false),
        ("ADMISSION_BODY_READ_TIMEOUT_MS", "u64", false),
    ]
    .into_iter()
    .map(|(suffix, type_name, secret)| entry(&format!("{PREFIX}{suffix}"), type_name, secret))
    .collect::<Vec<_>>();
    // ADR-0054 D-D: the former default write pair. No write compares against it and no put
    // falls back to it any more — every route derives (tenant, workspace) per request — so both
    // are optional (default "") and ignored; a present value must still parse as a UUID. Kept
    // registered only because `xtask e2e-onboard` still passes them; the follow-up that drops
    // them there deletes these two entries (their presence then becomes a boot error).
    // ADR-0059 D-G / D-H rotation twins: empty (the default) = rotation window closed.
    entries.extend(
        [
            "TOKEN_HMAC_KEY_PREVIOUS",
            "CREDENTIAL_PEPPER_PREVIOUS_HEX",
            // M02 D3: empty (the default) = no auth key; required only when AUTH_SURFACE_ENABLED is true.
            "AUTH_HMAC_KEY",
            "AUTH_HMAC_KEY_PREVIOUS",
        ]
        .into_iter()
        .map(|suffix| entry_with_default(&format!("{PREFIX}{suffix}"), "hex", true, "")),
    );
    entries.extend(
        ["REMEMBER_TENANT_ID", "REMEMBER_WORKSPACE_ID"]
            .into_iter()
            .map(|suffix| entry_with_default(&format!("{PREFIX}{suffix}"), "uuid", false, "")),
    );
    // Semantic-recall wiring keys: gated as a group by `RETRIEVAL_RPC_SOCKET_PATH`
    // (`parse_semantic_recall`'s doc) — absent is a valid, expected deployment shape (semantic
    // recall stays disabled), so each gets `default: ""` rather than `None`. `None` would make
    // `resolve_effective_config` hard-fail startup on any deployment that hasn't turned the
    // feature on yet, instead of reaching the `not_applicable` degrade path in `build`.
    entries.extend(
        [
            ("RETRIEVAL_RPC_SOCKET_PATH", "path", false),
            // ADR-0066 D-L: required (in this group) whenever the socket path is set.
            ("RETRIEVAL_RPC_SERVER_UID", "u32", false),
            ("RETRIEVAL_RPC_PERMIT_TTL_SECONDS", "u64", false),
            ("EMBEDDING_DIMENSION", "u32", false),
            ("EMBEDDING_VERSION", "string", false),
            ("QDRANT_HOST", "string", false),
            ("QDRANT_PORT", "u16", false),
            ("QDRANT_CIDR", "cidr", false),
            ("QDRANT_TLS", "bool", false),
            ("CELL_ID", "uuid", false),
            ("CALLER_ID", "string", false),
        ]
        .into_iter()
        .map(|(suffix, type_name, secret)| {
            entry_with_default(&format!("{PREFIX}{suffix}"), type_name, secret, "")
        }),
    );
    // ADR-0084 D-E: the deployment model pin the gateway compares each rerank reply's identity with. Blank (the default)
    // is valid while `rerank_enabled` is false; while it is true all five are required (`parse_rerank_pin`). They must
    // equal the retrieval worker's HUMAUX_RETRIEVAL_WORKER_RERANK_{REPO,REVISION,RECIPE,MODEL_SHA256,TOKENIZER_SHA256}.
    entries.extend(
        RERANK_PIN_KEYS
            .into_iter()
            .map(|name| entry_with_default(name, "string", false, "")),
    );
    // M12 D4: the generation stamp the query-embedding cache admits; blank (the default) keeps the cache off
    // (`parse_query_cache`). It must equal what the retrieval worker reports for HUMAUX_GATEWAY_EMBEDDING_VERSION.
    entries.extend(
        [
            "EMBEDDING_PROVIDER_ID",
            "EMBEDDING_MODEL_ID",
            "EMBEDDING_MODEL_REVISION",
        ]
        .into_iter()
        .map(|suffix| entry_with_default(&format!("{PREFIX}{suffix}"), "string", false, "")),
    );
    // M12 D5 (§51, §78.1): the design's starting sizes (256 MiB total, 16 MiB per tenant, 24 h); the B23 load test
    // sets the deployed values. The gateway's memory ceiling must hold the total (deploy/compose/prod.yml).
    entries.extend(
        [
            ("AUTH_SURFACE_ENABLED", "bool", "false"),
            ("CACHE_EMBED_QUERY_ENABLED", "bool", "true"),
            ("CACHE_EMBED_QUERY_BYTES", "u64", "268435456"),
            ("CACHE_PER_TENANT_BYTES", "u64", "16777216"),
            ("CACHE_EMBED_QUERY_TTL_SECONDS", "u32", "86400"),
        ]
        .into_iter()
        .map(|(suffix, type_name, default)| {
            entry_with_default(&format!("{PREFIX}{suffix}"), type_name, false, default)
        }),
    );
    // §30.2 / §78.1 (M29 T04a/T04b): the coord task-run lease length `coordinate.task_claim` / `task_heartbeat` hand to
    // adapters::coord_repo; `task_lease_ttl` bounds it at boot. 300 s bounds how long a crashed owner keeps a task.
    entries.push(entry_with_default(TASK_LEASE_TTL_KEY, "u64", false, "300"));
    // M02 D8 (§78.1): the bearer hot path writes a credential's `last_used_at` at most once per this many seconds; 60 s
    // keeps the stamp inside the minute while taking one UPDATE per request off `control.api_keys`.
    entries.push(entry_with_default(
        CREDENTIAL_TOUCH_INTERVAL_KEY,
        "u64",
        false,
        "60",
    ));
    for (_, capacity_key, refill_key) in RATE_BUCKET_KEYS {
        entries.push(entry(capacity_key, "i64", false));
        entries.push(entry(refill_key, "i64", false));
    }
    entries.extend(humaux_contracts::config_registry::continuity_config_registry());
    entries.extend(retrieval_profile_registry().into_iter().map(|mut entry| {
        entry.name = retrieval_env_key(&entry.name);
        entry
    }));
    entries
}

fn entry(name: &str, type_name: &str, secret: bool) -> ConfigEntry {
    ConfigEntry {
        name: name.to_owned(),
        type_name: type_name.to_owned(),
        default: None,
        scope: "process".to_owned(),
        secret,
        reloadability: "static".to_owned(),
        owner_module: "gateway.bootstrap".to_owned(),
    }
}

fn entry_with_default(name: &str, type_name: &str, secret: bool, default: &str) -> ConfigEntry {
    ConfigEntry {
        default: Some(default.to_owned()),
        ..entry(name, type_name, secret)
    }
}

fn required<'a>(
    effective: &'a BTreeMap<String, String>,
    key: &str,
) -> Result<&'a str, BootstrapError> {
    effective
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .map(String::as_str)
        .ok_or_else(|| BootstrapError::new(key, "missing or empty"))
}

fn present<'a>(
    effective: &'a BTreeMap<String, String>,
    key: &str,
) -> Result<&'a str, BootstrapError> {
    effective
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| BootstrapError::new(key, "missing"))
}

fn nonempty<'a>(value: &'a str, key: &str) -> Result<&'a str, BootstrapError> {
    (!value.trim().is_empty())
        .then_some(value)
        .ok_or_else(|| BootstrapError::new(key, "missing or empty"))
}

fn parse_bind_addr(value: &str) -> Result<SocketAddr, BootstrapError> {
    let addr = value
        .parse::<SocketAddr>()
        .map_err(|_| BootstrapError::new("HUMAUX_GATEWAY_BIND_ADDR", "invalid socket address"))?;
    let unsafe_ip = match addr.ip() {
        IpAddr::V4(ip) => ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast(),
        IpAddr::V6(ip) => ip.is_unspecified() || ip.is_multicast(),
    };
    if addr.port() == 0 || unsafe_ip {
        return Err(BootstrapError::new(
            "HUMAUX_GATEWAY_BIND_ADDR",
            "unsafe listener address",
        ));
    }
    Ok(addr)
}

fn parse_usize(value: &str, key: &str) -> Result<usize, BootstrapError> {
    value
        .parse::<usize>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| BootstrapError::new(key, "must be a positive integer"))
}

fn parse_u32(value: &str, key: &str) -> Result<u32, BootstrapError> {
    value
        .parse::<u32>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| BootstrapError::new(key, "must be a positive integer"))
}

fn seconds(value: &str, key: &str) -> Result<Duration, BootstrapError> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .map(Duration::from_secs)
        .ok_or_else(|| BootstrapError::new(key, "must be positive seconds"))
}

/// `1..=MAX_TASK_LEASE_TTL_SECONDS`; anything else refuses to boot naming the key (issue 86 item 7).
fn task_lease_ttl(value: &str) -> Result<Duration, BootstrapError> {
    value
        .parse::<u64>()
        .ok()
        .filter(|secs| (1..=MAX_TASK_LEASE_TTL_SECONDS).contains(secs))
        .map(Duration::from_secs)
        .ok_or_else(|| BootstrapError::new(TASK_LEASE_TTL_KEY, "must be 1..=4294967295 seconds"))
}

/// `0..=MAX_CREDENTIAL_TOUCH_INTERVAL_SECONDS`; anything else refuses to boot naming the key.
fn credential_touch_interval(value: &str) -> Result<Duration, BootstrapError> {
    value
        .parse::<u64>()
        .ok()
        .filter(|secs| *secs <= MAX_CREDENTIAL_TOUCH_INTERVAL_SECONDS)
        .map(Duration::from_secs)
        .ok_or_else(|| {
            BootstrapError::new(CREDENTIAL_TOUCH_INTERVAL_KEY, "must be 0..=3600 seconds")
        })
}

fn millis(value: &str, key: &str) -> Result<Duration, BootstrapError> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .map(Duration::from_millis)
        .ok_or_else(|| BootstrapError::new(key, "must be positive milliseconds"))
}

fn uuid(value: &str, key: &str) -> Result<Uuid, BootstrapError> {
    Uuid::parse_str(value)
        .ok()
        .filter(|value| !value.is_nil())
        .ok_or_else(|| BootstrapError::new(key, "must be a non-nil UUID"))
}

fn csv_nonempty(value: &str, key: &str) -> Result<Vec<String>, BootstrapError> {
    let values = value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if values.is_empty() || value.split(',').any(|item| item.trim().is_empty()) {
        return Err(BootstrapError::new(key, "must be a nonempty CSV"));
    }
    Ok(values)
}

fn cidrs(value: &str, key: &str) -> Result<Vec<Cidr>, BootstrapError> {
    if value.is_empty() {
        return Ok(vec![]);
    }
    csv_nonempty(value, key)?
        .into_iter()
        .map(|cidr| {
            cidr.parse()
                .map_err(|_| BootstrapError::new(key, "invalid CIDR"))
        })
        .collect()
}

fn rate(
    effective: &BTreeMap<String, String>,
    (name, capacity_key, refill_key): (&str, &str, &str),
) -> Result<RatePolicy, BootstrapError> {
    let capacity = required(effective, capacity_key)?
        .parse::<i64>()
        .map_err(|_| BootstrapError::new(capacity_key, "invalid integer"))?;
    let refill = required(effective, refill_key)?
        .parse::<i64>()
        .map_err(|_| BootstrapError::new(refill_key, "invalid integer"))?;
    RatePolicy::new(capacity, refill).map_err(|_| BootstrapError::new(name, "invalid rate policy"))
}

/// ADR-0065 D-A / D-B: the gateway pool from its seven `PG_*` keys. Bounds: max ≥ 1, min ≤ max, acquire / idle
/// timeouts > 0, max lifetime > idle timeout; then [`validate_timeout_order`]. P ≥ C+2 is deliberately not checked
/// here (D-A rejected b: the S7 fault run boots P = 2); the load measurement asserts it.
fn parse_pool(
    effective: &BTreeMap<String, String>,
    lock_timeout: Duration,
    handler_timeout: Duration,
) -> Result<PoolSettings, BootstrapError> {
    let max_connections = parse_u32(required(effective, PG_POOL_MAX_KEY)?, PG_POOL_MAX_KEY)?;
    let min_connections = required(effective, PG_POOL_MIN_KEY)?
        .parse::<u32>()
        .map_err(|_| BootstrapError::new(PG_POOL_MIN_KEY, "must be a non-negative integer"))?;
    if min_connections > max_connections {
        return Err(BootstrapError::new(
            PG_POOL_MIN_KEY,
            "must not exceed HUMAUX_GATEWAY_PG_POOL_MAX_CONNECTIONS",
        ));
    }
    let idle_timeout = seconds(
        required(effective, PG_IDLE_TIMEOUT_KEY)?,
        PG_IDLE_TIMEOUT_KEY,
    )?;
    let max_lifetime = seconds(
        required(effective, PG_MAX_LIFETIME_KEY)?,
        PG_MAX_LIFETIME_KEY,
    )?;
    if max_lifetime <= idle_timeout {
        return Err(BootstrapError::new(
            PG_MAX_LIFETIME_KEY,
            "must exceed HUMAUX_GATEWAY_PG_IDLE_TIMEOUT_SECONDS",
        ));
    }
    let settings = PoolSettings {
        max_connections,
        min_connections,
        acquire_timeout: millis(
            required(effective, PG_ACQUIRE_TIMEOUT_KEY)?,
            PG_ACQUIRE_TIMEOUT_KEY,
        )?,
        idle_timeout,
        max_lifetime,
        statement_timeout: millis(
            required(effective, PG_STATEMENT_TIMEOUT_KEY)?,
            PG_STATEMENT_TIMEOUT_KEY,
        )?,
        idle_in_transaction_timeout: millis(
            required(effective, PG_IDLE_IN_TRANSACTION_TIMEOUT_KEY)?,
            PG_IDLE_IN_TRANSACTION_TIMEOUT_KEY,
        )?,
        application_name: APPLICATION_NAME.to_owned(),
    };
    validate_timeout_order(&settings, lock_timeout, handler_timeout)?;
    Ok(settings)
}

/// ADR-0065 D-C: the §67.2 admission bounds. C ≥ 1, Q ≥ 0, W > 0, 1 ≤ K ≤ C + Q (a larger K could never decide), and
/// 0 < B ≤ the handler timeout (B is a protective bound: `MAX_REQUEST_BODY_BYTES` / B is the slowest accepted upload).
fn parse_admission(
    effective: &BTreeMap<String, String>,
    handler_timeout: Duration,
) -> Result<AdmissionSettings, BootstrapError> {
    let concurrency = parse_u32(
        required(effective, ADMISSION_CONCURRENCY_KEY)?,
        ADMISSION_CONCURRENCY_KEY,
    )?;
    let queue_depth = required(effective, ADMISSION_QUEUE_DEPTH_KEY)?
        .parse::<u32>()
        .map_err(|_| {
            BootstrapError::new(ADMISSION_QUEUE_DEPTH_KEY, "must be a non-negative integer")
        })?;
    let per_key_limit = parse_u32(
        required(effective, ADMISSION_PER_KEY_LIMIT_KEY)?,
        ADMISSION_PER_KEY_LIMIT_KEY,
    )?;
    if u64::from(per_key_limit) > u64::from(concurrency) + u64::from(queue_depth) {
        return Err(BootstrapError::new(
            ADMISSION_PER_KEY_LIMIT_KEY,
            "must not exceed HUMAUX_GATEWAY_ADMISSION_CONCURRENCY + HUMAUX_GATEWAY_ADMISSION_QUEUE_DEPTH (ADR-0065 D-C)",
        ));
    }
    let body_read_timeout = millis(
        required(effective, ADMISSION_BODY_READ_TIMEOUT_KEY)?,
        ADMISSION_BODY_READ_TIMEOUT_KEY,
    )?;
    if body_read_timeout > handler_timeout {
        return Err(BootstrapError::new(
            ADMISSION_BODY_READ_TIMEOUT_KEY,
            "must not exceed HUMAUX_GATEWAY_HANDLER_TIMEOUT_SECONDS (ADR-0065 D-C)",
        ));
    }
    Ok(AdmissionSettings {
        concurrency,
        queue_depth,
        max_wait: millis(
            required(effective, ADMISSION_MAX_WAIT_KEY)?,
            ADMISSION_MAX_WAIT_KEY,
        )?,
        per_key_limit,
        body_read_timeout,
        max_request_body_bytes: parse_usize(
            required(effective, "HUMAUX_GATEWAY_MAX_REQUEST_BODY_BYTES")?,
            "HUMAUX_GATEWAY_MAX_REQUEST_BODY_BYTES",
        )?,
    })
}

/// ADR-0065 D-B: lock_timeout < statement_timeout < handler timeout, and an idle transaction never outlives the
/// handler — so the server cancels a statement before the client stops waiting for it (a dropped future sends no
/// CancelRequest, F19 / L6). A violation refuses to boot naming the key and the order.
fn validate_timeout_order(
    pool: &PoolSettings,
    lock_timeout: Duration,
    handler_timeout: Duration,
) -> Result<(), BootstrapError> {
    // ADR-0065 D-D: a rate-lock wait ends as 55P03 (503) before statement_timeout could end it as 57014.
    if lock_timeout >= pool.statement_timeout {
        return Err(BootstrapError::new(
            RATE_LOCK_TIMEOUT_KEY,
            "must be below HUMAUX_GATEWAY_PG_STATEMENT_TIMEOUT_MS (ADR-0065 D-B order: lock_timeout < statement_timeout < handler timeout)",
        ));
    }
    if pool.statement_timeout >= handler_timeout {
        return Err(BootstrapError::new(
            PG_STATEMENT_TIMEOUT_KEY,
            "must be below HUMAUX_GATEWAY_HANDLER_TIMEOUT_SECONDS (ADR-0065 D-B order: lock_timeout < statement_timeout < handler timeout)",
        ));
    }
    if pool.idle_in_transaction_timeout > handler_timeout {
        return Err(BootstrapError::new(
            PG_IDLE_IN_TRANSACTION_TIMEOUT_KEY,
            "must not exceed HUMAUX_GATEWAY_HANDLER_TIMEOUT_SECONDS (ADR-0065 D-B)",
        ));
    }
    Ok(())
}

fn validate_guard(guard: &GuardSettings) -> Result<(), BootstrapError> {
    let execution = guard
        .handler_timeout
        .checked_add(guard.finalize_timeout)
        .ok_or_else(|| BootstrapError::new("HUMAUX_GATEWAY_HANDLER_TIMEOUT_SECONDS", "overflow"))?;
    if guard.trusted_proxies.max_forwarded_hops == 0 || guard.reservation_ttl <= execution {
        return Err(BootstrapError::new(
            "gateway guard",
            "unsafe TTL or proxy policy",
        ));
    }
    Ok(())
}

// The three closed-set parsers are `remember`'s (ADR-0032 D-B: one parser each for the env
// default and the per-call argument, so the two spellings can never drift apart).
fn data_class(value: &str) -> Result<DataClass, BootstrapError> {
    remember::parse_data_class(value).map_err(|_| {
        BootstrapError::new(
            "HUMAUX_GATEWAY_REMEMBER_DATA_CLASS",
            "unknown closed enum value",
        )
    })
}

/// The process DEFAULT may not be `TENANT_SHARED`: that class is reachable per call only,
/// behind the OWNER/ADMIN membership gate (ADR-0032 D-B).
fn visibility(value: &str) -> Result<VisibilityClass, BootstrapError> {
    match remember::parse_visibility_class(value) {
        Ok(class) if class != VisibilityClass::TenantShared => Ok(class),
        _ => Err(BootstrapError::new(
            "HUMAUX_GATEWAY_REMEMBER_VISIBILITY_CLASS",
            "only USER_PRIVATE or WORKSPACE_SHARED is enabled",
        )),
    }
}

fn event_kind(value: &str) -> Result<RememberEventKind, BootstrapError> {
    RememberEventKind::parse(value).map_err(|_| {
        BootstrapError::new(
            "HUMAUX_GATEWAY_REMEMBER_EVENT_KIND",
            "unknown closed enum value",
        )
    })
}

fn redacted_fingerprint(registry: &[ConfigEntry], effective: &BTreeMap<String, String>) -> String {
    let redacted = effective
        .iter()
        .map(|(key, value)| {
            let secret = registry
                .iter()
                .any(|entry| entry.name == *key && entry.secret);
            (
                key.clone(),
                if secret {
                    "<redacted>".to_owned()
                } else {
                    value.clone()
                },
            )
        })
        .collect();
    effective_config_fingerprint(&redacted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use humaux_contracts::retrieval_config::RERANK_ENABLED;
    use humaux_retrieval_worker::rerank::{
        KEY_MODEL_SHA256, KEY_RECIPE, KEY_REPO, KEY_REVISION, KEY_TOKENIZER_SHA256,
    };

    fn raw() -> BTreeMap<String, String> {
        let tenant = Uuid::now_v7();
        let workspace = Uuid::now_v7();
        let reasoning = Uuid::now_v7();
        let mut raw = BTreeMap::new();
        for entry in registry() {
            let value = match entry.name.as_str() {
                "HUMAUX_GATEWAY_BIND_ADDR" => "127.0.0.1:8080".into(),
                "HUMAUX_GATEWAY_ALLOWED_HOSTS" => "mcp.example.test".into(),
                "HUMAUX_GATEWAY_ALLOWED_ORIGINS" => "https://mcp.example.test".into(),
                "HUMAUX_GATEWAY_MAX_REQUEST_BODY_BYTES" => "65536".into(),
                "HUMAUX_GATEWAY_PG_DSN" => "postgres://redacted".into(),
                "HUMAUX_GATEWAY_CREDENTIAL_PEPPER_HEX" => "00112233".into(),
                "HUMAUX_GATEWAY_TOKEN_HMAC_KEY" => generated_key_hex(),
                "HUMAUX_GATEWAY_TRUSTED_PROXY_CIDRS"
                | "HUMAUX_GATEWAY_GLOBAL_DENYLIST"
                | "HUMAUX_GATEWAY_GLOBAL_EMERGENCY_ALLOWLIST" => String::new(),
                "HUMAUX_GATEWAY_MAX_FORWARDED_HOPS" => "1".into(),
                "HUMAUX_GATEWAY_RESERVATION_TTL_SECONDS" => "30".into(),
                "HUMAUX_GATEWAY_HANDLER_TIMEOUT_SECONDS" => "5".into(),
                "HUMAUX_GATEWAY_FINALIZE_TIMEOUT_SECONDS" => "2".into(),
                "HUMAUX_GATEWAY_REPLAY_TTL_SECONDS" => "60".into(),
                "HUMAUX_GATEWAY_CONFIRM_TOKEN_TTL_SECONDS" => "300".into(),
                "HUMAUX_GATEWAY_UNDO_WINDOW_SECONDS" => "86400".into(),
                "HUMAUX_GATEWAY_MOOD_HALF_LIFE_SECONDS" => "21600".into(),
                "HUMAUX_GATEWAY_PROJECTION_LAG_SECONDS" => "60".into(),
                "HUMAUX_GATEWAY_ENUMERATION_TTL_SECONDS" => "900".into(),
                "HUMAUX_GATEWAY_ENUMERATION_MANIFEST_CAP" => "1000".into(),
                "HUMAUX_GATEWAY_REMEMBER_TENANT_ID" => tenant.to_string(),
                "HUMAUX_GATEWAY_REMEMBER_WORKSPACE_ID" => workspace.to_string(),
                "HUMAUX_GATEWAY_REMEMBER_SCOPE_KIND" => "workspace".into(),
                "HUMAUX_GATEWAY_REMEMBER_DOMAIN" => "knowledge".into(),
                "HUMAUX_GATEWAY_REMEMBER_PROJECTION_KIND" => "ingest".into(),
                "HUMAUX_GATEWAY_REMEMBER_PROJECTION_VERSION" => "v1".into(),
                "HUMAUX_GATEWAY_REMEMBER_REASONING_DOMAIN_ID" => reasoning.to_string(),
                "HUMAUX_GATEWAY_REMEMBER_TOKEN_TTL_SECONDS" => "60".into(),
                "HUMAUX_GATEWAY_REMEMBER_DATA_CLASS" => "INTERNAL".into(),
                "HUMAUX_GATEWAY_REMEMBER_VISIBILITY_CLASS" => "WORKSPACE_SHARED".into(),
                "HUMAUX_GATEWAY_REMEMBER_EVENT_KIND" => "USER_MESSAGE".into(),
                "HUMAUX_GATEWAY_CONTEXT_TOTAL_TOKENS" => "2048".into(),
                "HUMAUX_GATEWAY_CONTEXT_MANDATORY_TOKENS" => "1024".into(),
                "HUMAUX_GATEWAY_METRICS_ADDR" => "127.0.0.1:9101".into(),
                "HUMAUX_GATEWAY_READINESS_REFRESH_SECONDS" => "2".into(),
                "HUMAUX_GATEWAY_PG_POOL_MAX_CONNECTIONS" => "18".into(),
                "HUMAUX_GATEWAY_PG_POOL_MIN_CONNECTIONS" => "2".into(),
                "HUMAUX_GATEWAY_PG_ACQUIRE_TIMEOUT_MS" => "1000".into(),
                "HUMAUX_GATEWAY_PG_IDLE_TIMEOUT_SECONDS" => "300".into(),
                "HUMAUX_GATEWAY_PG_MAX_LIFETIME_SECONDS" => "1800".into(),
                "HUMAUX_GATEWAY_PG_STATEMENT_TIMEOUT_MS" => "4000".into(),
                "HUMAUX_GATEWAY_PG_IDLE_IN_TRANSACTION_TIMEOUT_MS" => "4000".into(),
                "HUMAUX_GATEWAY_RATE_LOCK_TIMEOUT_MS" => "2000".into(),
                "HUMAUX_GATEWAY_RATE_PREAUTH_IPV6_PREFIX_BITS" => "64".into(),
                "HUMAUX_GATEWAY_ADMISSION_CONCURRENCY" => "16".into(),
                "HUMAUX_GATEWAY_ADMISSION_QUEUE_DEPTH" => "64".into(),
                "HUMAUX_GATEWAY_ADMISSION_MAX_WAIT_MS" => "5000".into(),
                "HUMAUX_GATEWAY_ADMISSION_PER_KEY_LIMIT" => "16".into(),
                "HUMAUX_GATEWAY_ADMISSION_BODY_READ_TIMEOUT_MS" => "5000".into(),
                // Semantic recall stays disabled in this fixture (empty socket path) — every
                // other key in this group may legitimately be blank when it is.
                "HUMAUX_GATEWAY_RETRIEVAL_RPC_SOCKET_PATH"
                | "HUMAUX_GATEWAY_RETRIEVAL_RPC_PERMIT_TTL_SECONDS"
                | "HUMAUX_GATEWAY_EMBEDDING_DIMENSION"
                | "HUMAUX_GATEWAY_EMBEDDING_VERSION"
                | "HUMAUX_GATEWAY_QDRANT_HOST"
                | "HUMAUX_GATEWAY_QDRANT_PORT"
                | "HUMAUX_GATEWAY_QDRANT_CIDR"
                | "HUMAUX_GATEWAY_QDRANT_TLS"
                | "HUMAUX_GATEWAY_CELL_ID"
                | "HUMAUX_GATEWAY_CALLER_ID" => String::new(),
                key if key.contains("_CAPACITY") || key.contains("_REFILL_PER_SECOND") => {
                    "100".into()
                }
                key => entry
                    .default
                    .clone()
                    .unwrap_or_else(|| panic!("unhandled gateway config key {key}")),
            };
            raw.insert(entry.name, value);
        }
        raw
    }

    /// A per-call generated 32-byte key, hex-encoded (never a literal key).
    fn generated_key_hex() -> String {
        format!("{}{}", Uuid::now_v7().simple(), Uuid::now_v7().simple())
    }

    fn rejected_key(values: BTreeMap<String, String>) -> String {
        match GatewayBootstrap::from_raw(values) {
            Ok(_) => panic!("configuration must be rejected"),
            Err(error) => error.key,
        }
    }

    /// G-T04b-4 (issue 86 item 7, §30.2): a zero or overflowing task-lease TTL refuses to boot naming the key; the
    /// 300 s default and both ends of the range boot. Fault: the lower bound moved to 0, or the upper bound removed.
    #[test]
    fn task_lease_ttl_is_bounded_at_boot() {
        let refused_key = |value: &str| {
            let mut values = raw();
            values.insert(TASK_LEASE_TTL_KEY.into(), value.into());
            GatewayBootstrap::from_raw(values)
                .err()
                .map(|error| error.key)
        };
        assert_eq!(
            refused_key("0").as_deref(),
            Some(TASK_LEASE_TTL_KEY),
            "zero lease"
        );
        assert_eq!(
            refused_key("4294967296").as_deref(),
            Some(TASK_LEASE_TTL_KEY),
            "one second past the bound"
        );
        for value in ["-1", "soon"] {
            assert_eq!(
                refused_key(value).as_deref(),
                Some(TASK_LEASE_TTL_KEY),
                "{value:?}"
            );
        }
        for value in ["1", "4294967295"] {
            assert_eq!(refused_key(value), None, "{value} boots");
        }
        let default = match GatewayBootstrap::from_raw(raw()) {
            Ok(boot) => boot,
            Err(error) => panic!("the full fixture boots: {}", error.key),
        };
        assert_eq!(default.task_lease_ttl, Duration::from_secs(300));
    }

    /// G-M02-2 (M02 D8, §78.1): the credential touch interval is config. The 60 s default boots, both ends of the
    /// range boot, and a value past an hour or one that is not a number refuses to boot naming the key. Fault: the
    /// upper bound removed, or the default moved into code.
    #[test]
    fn credential_touch_interval_is_bounded_at_boot() {
        let outcome = |value: &str| {
            let mut values = raw();
            values.insert(CREDENTIAL_TOUCH_INTERVAL_KEY.into(), value.into());
            GatewayBootstrap::from_raw(values)
                .map(|boot| boot.credential_touch_interval)
                .map_err(|error| error.key)
        };
        for value in ["3601", "-1", "soon", "1.5"] {
            assert_eq!(
                outcome(value),
                Err(CREDENTIAL_TOUCH_INTERVAL_KEY.to_owned()),
                "{value:?}"
            );
        }
        assert_eq!(outcome("0"), Ok(Duration::ZERO));
        assert_eq!(outcome("3600"), Ok(Duration::from_secs(3600)));
        let registered: Vec<_> = registry()
            .into_iter()
            .filter(|entry| entry.name == CREDENTIAL_TOUCH_INTERVAL_KEY)
            .collect();
        assert_eq!(registered.len(), 1, "declared exactly once");
        assert_eq!(registered[0].default.as_deref(), Some("60"));
        let mut values = raw();
        values.remove(CREDENTIAL_TOUCH_INTERVAL_KEY);
        assert_eq!(
            GatewayBootstrap::from_raw(values).map(|boot| boot.credential_touch_interval),
            Ok(Duration::from_secs(60)),
            "unset resolves to the registered default"
        );
    }

    /// Every card-38 key (ADR-0065; S3 and S4 append theirs to this one list).
    const CARD38_KEYS: [&str; 14] = [
        "HUMAUX_GATEWAY_PG_POOL_MAX_CONNECTIONS",
        "HUMAUX_GATEWAY_PG_POOL_MIN_CONNECTIONS",
        "HUMAUX_GATEWAY_PG_ACQUIRE_TIMEOUT_MS",
        "HUMAUX_GATEWAY_PG_IDLE_TIMEOUT_SECONDS",
        "HUMAUX_GATEWAY_PG_MAX_LIFETIME_SECONDS",
        "HUMAUX_GATEWAY_PG_STATEMENT_TIMEOUT_MS",
        "HUMAUX_GATEWAY_PG_IDLE_IN_TRANSACTION_TIMEOUT_MS",
        "HUMAUX_GATEWAY_RATE_LOCK_TIMEOUT_MS",
        "HUMAUX_GATEWAY_RATE_PREAUTH_IPV6_PREFIX_BITS",
        "HUMAUX_GATEWAY_ADMISSION_CONCURRENCY",
        "HUMAUX_GATEWAY_ADMISSION_QUEUE_DEPTH",
        "HUMAUX_GATEWAY_ADMISSION_MAX_WAIT_MS",
        "HUMAUX_GATEWAY_ADMISSION_PER_KEY_LIMIT",
        "HUMAUX_GATEWAY_ADMISSION_BODY_READ_TIMEOUT_MS",
    ];

    /// ADR-0065 D-A / ruling R-5 (§78.1): each card-38 key is declared once with no default, and boot without it,
    /// or with it empty, fails naming exactly that key. Fault: one key moved to `entry_with_default` ⇒ red.
    #[test]
    fn every_card38_key_is_required_and_named() {
        assert!(
            GatewayBootstrap::from_raw(raw()).is_ok(),
            "the full fixture boots"
        );
        let registry = registry();
        for key in CARD38_KEYS {
            let declared: Vec<_> = registry.iter().filter(|e| e.name == key).collect();
            assert_eq!(declared.len(), 1, "{key} must be declared exactly once");
            assert!(
                declared[0].default.is_none(),
                "{key} must have no default (§78.1, R-5)"
            );
            let mut values = raw();
            values.remove(key);
            assert_eq!(rejected_key(values), key, "boot without {key}");
            let mut values = raw();
            values.insert(key.into(), String::new());
            assert_eq!(rejected_key(values), key, "boot with {key} empty");
        }
        let bits = "HUMAUX_GATEWAY_RATE_PREAUTH_IPV6_PREFIX_BITS";
        for value in ["0", "129"] {
            let mut values = raw();
            values.insert(bits.into(), value.into());
            assert_eq!(rejected_key(values), bits, "{bits}={value}");
        }
        // ADR-0065 D-C bounds (fixture C = 16, Q = 64, handler timeout 5 s): C ≥ 1, W > 0, K ≤ C + Q, B ≤ handler.
        for (key, value) in [
            ("HUMAUX_GATEWAY_ADMISSION_CONCURRENCY", "0"),
            ("HUMAUX_GATEWAY_ADMISSION_MAX_WAIT_MS", "0"),
            ("HUMAUX_GATEWAY_ADMISSION_PER_KEY_LIMIT", "0"),
            ("HUMAUX_GATEWAY_ADMISSION_PER_KEY_LIMIT", "81"),
            ("HUMAUX_GATEWAY_ADMISSION_BODY_READ_TIMEOUT_MS", "0"),
            ("HUMAUX_GATEWAY_ADMISSION_BODY_READ_TIMEOUT_MS", "5001"),
        ] {
            let mut values = raw();
            values.insert(key.into(), value.into());
            assert_eq!(rejected_key(values), key, "{key}={value}");
        }
        for (key, value) in [
            ("HUMAUX_GATEWAY_ADMISSION_QUEUE_DEPTH", "0"),
            ("HUMAUX_GATEWAY_ADMISSION_PER_KEY_LIMIT", "80"),
        ] {
            let mut values = raw();
            values.insert(key.into(), value.into());
            assert!(
                GatewayBootstrap::from_raw(values).is_ok(),
                "{key}={value} boots"
            );
        }
    }

    /// ADR-0065 D-B: statement_timeout < handler timeout, idle-in-transaction ≤ handler timeout; a violation refuses
    /// to boot naming the key. Fault: the order check removed ⇒ red.
    /// ADR-0066 review fix 4: the five §67.2 classes, each with a literal key pair of the one spelling `rate` reads.
    #[test]
    fn rate_bucket_keys_are_the_five_classes_with_literal_key_pairs() {
        let classes: Vec<&str> = RATE_BUCKET_KEYS
            .iter()
            .map(|(class, _, _)| *class)
            .collect();
        assert_eq!(
            classes,
            ["PREAUTH_IP", "CREDENTIAL", "USER", "TENANT", "OPERATION"]
        );
        for (class, capacity_key, refill_key) in RATE_BUCKET_KEYS {
            for (key, suffix) in [
                (capacity_key, "_CAPACITY"),
                (refill_key, "_REFILL_PER_SECOND"),
            ] {
                assert!(key.starts_with("HUMAUX_GATEWAY_RATE_"), "{key}");
                assert!(key.ends_with(suffix), "{key}");
                assert_eq!(key, format!("HUMAUX_GATEWAY_RATE_{class}{suffix}"));
            }
        }
    }

    #[test]
    fn timeout_ordering_is_refused_at_boot() {
        // The fixture's handler timeout is 5 s.
        let with = |key: &str, value: &str| {
            let mut values = raw();
            values.insert(key.into(), value.into());
            values
        };
        let statement = "HUMAUX_GATEWAY_PG_STATEMENT_TIMEOUT_MS";
        let idle_txn = "HUMAUX_GATEWAY_PG_IDLE_IN_TRANSACTION_TIMEOUT_MS";
        assert_eq!(rejected_key(with(statement, "5000")), statement);
        assert_eq!(rejected_key(with(statement, "60000")), statement);
        assert!(GatewayBootstrap::from_raw(with(statement, "4999")).is_ok());
        assert_eq!(rejected_key(with(idle_txn, "5001")), idle_txn);
        assert!(GatewayBootstrap::from_raw(with(idle_txn, "5000")).is_ok());
        // The fixture's statement_timeout is 4000 ms.
        let lock = "HUMAUX_GATEWAY_RATE_LOCK_TIMEOUT_MS";
        assert_eq!(rejected_key(with(lock, "4000")), lock);
        assert!(GatewayBootstrap::from_raw(with(lock, "3999")).is_ok());
        match GatewayBootstrap::from_raw(with(statement, "5000")) {
            Err(error) => assert!(
                error
                    .to_string()
                    .contains("lock_timeout < statement_timeout < handler timeout"),
                "the refusal names the order: {error}"
            ),
            Ok(_) => panic!("statement_timeout = handler timeout must be refused"),
        }
    }

    #[test]
    fn bootstrap_without_token_hmac_key_fails_naming_the_key() {
        let mut values = raw();
        values.remove("HUMAUX_GATEWAY_TOKEN_HMAC_KEY");
        assert_eq!(rejected_key(values), "HUMAUX_GATEWAY_TOKEN_HMAC_KEY");
        let mut values = raw();
        values.insert("HUMAUX_GATEWAY_TOKEN_HMAC_KEY".into(), String::new());
        assert_eq!(rejected_key(values), "HUMAUX_GATEWAY_TOKEN_HMAC_KEY");
    }

    #[test]
    fn bootstrap_rejects_short_or_equal_previous_token_key() {
        let mut values = raw();
        values.insert("HUMAUX_GATEWAY_TOKEN_HMAC_KEY".into(), "00".repeat(31));
        assert_eq!(rejected_key(values), "HUMAUX_GATEWAY_TOKEN_HMAC_KEY");
        let mut values = raw();
        values.insert(
            "HUMAUX_GATEWAY_TOKEN_HMAC_KEY_PREVIOUS".into(),
            "00".repeat(31),
        );
        assert_eq!(
            rejected_key(values),
            "HUMAUX_GATEWAY_TOKEN_HMAC_KEY_PREVIOUS"
        );
        let mut values = raw();
        let current = values["HUMAUX_GATEWAY_TOKEN_HMAC_KEY"].clone();
        values.insert("HUMAUX_GATEWAY_TOKEN_HMAC_KEY_PREVIOUS".into(), current);
        assert_eq!(
            rejected_key(values),
            "HUMAUX_GATEWAY_TOKEN_HMAC_KEY_PREVIOUS"
        );
        let mut values = raw();
        values.insert(
            "HUMAUX_GATEWAY_TOKEN_HMAC_KEY_PREVIOUS".into(),
            generated_key_hex(),
        );
        assert!(GatewayBootstrap::from_raw(values).is_ok());
    }

    /// M02-3 / M02 D3: the auth key is required exactly when the auth surface is enabled, and its absence is a
    /// refusal naming the key — never a default key. Fault: fall back to an empty key when it is unset ⇒ red.
    #[test]
    fn auth_key_unset_refuses_boot_when_the_auth_surface_is_enabled() {
        let refusal = |values: BTreeMap<String, String>| match GatewayBootstrap::from_raw(values) {
            Err(error) => (error.key.clone(), error.reason, error.to_string()),
            Ok(_) => panic!("configuration must be rejected"),
        };
        let enabled = || {
            let mut values = raw();
            values.insert(AUTH_SURFACE_ENABLED_KEY.into(), "true".into());
            values
        };
        // Surface off (the registered default): no key needed, none installed.
        assert!(GatewayBootstrap::from_raw(raw()).is_ok());
        let (key, reason, _) = refusal(enabled());
        assert_eq!(
            (key.as_str(), reason),
            (AUTH_HMAC_KEY_KEY, "missing or empty")
        );
        let mut values = enabled();
        values.remove(AUTH_HMAC_KEY_KEY);
        let (key, reason, _) = refusal(values);
        assert_eq!(
            (key.as_str(), reason),
            (AUTH_HMAC_KEY_KEY, "missing or empty")
        );
        let mut values = enabled();
        values.insert(AUTH_HMAC_KEY_KEY.into(), "  ".into());
        let (key, reason, _) = refusal(values);
        assert_eq!(
            (key.as_str(), reason),
            (AUTH_HMAC_KEY_KEY, "missing or empty")
        );
    }

    /// M02-3: a set auth key is validated like the token key, never echoed, and must not share bytes with the
    /// consistency-token set; a valid distinct pair boots with the keys held for the auth wiring.
    #[test]
    fn auth_key_is_validated_distinct_and_never_echoed() {
        let refusal = |values: BTreeMap<String, String>| match GatewayBootstrap::from_raw(values) {
            Err(error) => (error.key.clone(), error.reason, error.to_string()),
            Ok(_) => panic!("configuration must be rejected"),
        };
        let base = raw();
        let token = base["HUMAUX_GATEWAY_TOKEN_HMAC_KEY"].clone();
        let with = |pairs: &[(&str, &str)]| {
            let mut values = base.clone();
            values.insert(AUTH_SURFACE_ENABLED_KEY.into(), "true".into());
            for (key, value) in pairs {
                values.insert((*key).to_owned(), (*value).to_owned());
            }
            values
        };
        let (key, reason, _) = refusal(with(&[(AUTH_SURFACE_ENABLED_KEY, "yes")]));
        assert_eq!(
            (key.as_str(), reason),
            (AUTH_SURFACE_ENABLED_KEY, "must be true or false")
        );
        let short = "ab".repeat(31);
        let (key, _, shown) = refusal(with(&[(AUTH_HMAC_KEY_KEY, &short)]));
        assert_eq!(key, AUTH_HMAC_KEY_KEY);
        assert!(!shown.contains(&short));
        let (key, reason, _) = refusal(with(&[(AUTH_HMAC_KEY_KEY, "not hex")]));
        assert_eq!((key.as_str(), reason), (AUTH_HMAC_KEY_KEY, "invalid hex"));
        let good = generated_key_hex();
        let (key, _, _) = refusal(with(&[
            (AUTH_HMAC_KEY_KEY, &good),
            (AUTH_HMAC_KEY_PREVIOUS_KEY, &"ab".repeat(31)),
        ]));
        assert_eq!(key, AUTH_HMAC_KEY_PREVIOUS_KEY);
        let (key, reason, _) = refusal(with(&[(AUTH_HMAC_KEY_KEY, &token)]));
        assert_eq!(
            (key.as_str(), reason),
            (
                AUTH_HMAC_KEY_KEY,
                "must differ from the consistency-token keys"
            )
        );
        let (key, reason, _) = refusal(with(&[
            (AUTH_HMAC_KEY_KEY, &good),
            (AUTH_HMAC_KEY_PREVIOUS_KEY, &token),
        ]));
        assert_eq!(
            (key.as_str(), reason),
            (
                AUTH_HMAC_KEY_KEY,
                "must differ from the consistency-token keys"
            )
        );
        assert!(GatewayBootstrap::from_raw(with(&[(AUTH_HMAC_KEY_KEY, &good)])).is_ok());
    }

    #[test]
    fn bootstrap_rejects_previous_pepper_equal_to_current() {
        let mut values = raw();
        let current = values["HUMAUX_GATEWAY_CREDENTIAL_PEPPER_HEX"].clone();
        values.insert(
            "HUMAUX_GATEWAY_CREDENTIAL_PEPPER_PREVIOUS_HEX".into(),
            current,
        );
        assert_eq!(
            rejected_key(values),
            "HUMAUX_GATEWAY_CREDENTIAL_PEPPER_PREVIOUS_HEX"
        );
        let mut values = raw();
        values.insert(
            "HUMAUX_GATEWAY_CREDENTIAL_PEPPER_PREVIOUS_HEX".into(),
            "not hex".into(),
        );
        assert_eq!(
            rejected_key(values),
            "HUMAUX_GATEWAY_CREDENTIAL_PEPPER_PREVIOUS_HEX"
        );
        let mut values = raw();
        values.insert(
            "HUMAUX_GATEWAY_CREDENTIAL_PEPPER_PREVIOUS_HEX".into(),
            generated_key_hex(),
        );
        assert!(GatewayBootstrap::from_raw(values).is_ok());
    }

    #[test]
    fn bootstrap_rejects_unknown_missing_and_unsafe_listener_values() {
        let mut values = raw();
        values.insert("HUMAUX_GATEWAY_UNKNOWN".into(), "x".into());
        assert!(GatewayBootstrap::from_raw(values).is_err());

        let mut values = raw();
        values.remove("HUMAUX_GATEWAY_PG_DSN");
        assert!(GatewayBootstrap::from_raw(values).is_err());

        let mut values = raw();
        values.insert("HUMAUX_GATEWAY_BIND_ADDR".into(), "0.0.0.0:8080".into());
        assert!(GatewayBootstrap::from_raw(values).is_err());
    }

    /// ADR-0057 D-F (test 35): `PROJECTION_LAG_SECONDS` has no default — boot without it fails
    /// naming the key, and zero is refused. Fault: give the registry entry a default.
    #[test]
    fn bootstrap_without_projection_lag_seconds_fails_naming_the_key() {
        let key = "HUMAUX_GATEWAY_PROJECTION_LAG_SECONDS";
        assert!(
            registry()
                .iter()
                .any(|entry| entry.name == key && entry.default.is_none()),
            "{key} must be declared without a default"
        );
        let mut values = raw();
        values.remove(key);
        let error = GatewayBootstrap::from_raw(values)
            .err()
            .expect("boot must fail without the lag key");
        assert!(error.to_string().contains(key), "{error}");

        let mut values = raw();
        values.insert(key.into(), "0".into());
        let error = GatewayBootstrap::from_raw(values)
            .err()
            .expect("a zero lag threshold must be refused");
        assert!(error.to_string().contains(key), "{error}");

        assert!(GatewayBootstrap::from_raw(raw()).is_ok());
    }

    /// ADR-0062 D-K (T-K4): the enumeration TTL and manifest cap have no default — boot without either fails
    /// naming that key, and zero is refused. Fault: give either registry entry a default.
    #[test]
    fn bootstrap_without_enumeration_cap_or_ttl_fails_naming_the_key() {
        for key in [ENUMERATION_TTL_KEY, ENUMERATION_MANIFEST_CAP_KEY] {
            assert!(
                registry()
                    .iter()
                    .any(|entry| entry.name == key && entry.default.is_none()),
                "{key} must be declared without a default"
            );
            let mut values = raw();
            values.remove(key);
            let error = GatewayBootstrap::from_raw(values)
                .err()
                .unwrap_or_else(|| panic!("boot must fail without {key}"));
            assert!(error.to_string().contains(key), "{error}");

            let mut values = raw();
            values.insert(key.into(), "0".into());
            let error = GatewayBootstrap::from_raw(values)
                .err()
                .unwrap_or_else(|| panic!("a zero {key} must be refused"));
            assert!(error.to_string().contains(key), "{error}");
        }
        assert!(GatewayBootstrap::from_raw(raw()).is_ok());
    }

    /// ADR-0054 D-D: the former default write pair is optional — the process boots without
    /// both keys (every write derives its pair per request) — but a present value must still be
    /// a UUID, so a typo fails closed instead of being silently ignored.
    #[test]
    fn bootstrap_starts_without_the_default_write_pair() {
        let mut values = raw();
        values.remove("HUMAUX_GATEWAY_REMEMBER_TENANT_ID");
        values.remove("HUMAUX_GATEWAY_REMEMBER_WORKSPACE_ID");
        assert!(GatewayBootstrap::from_raw(values).is_ok());

        let mut values = raw();
        values.insert("HUMAUX_GATEWAY_REMEMBER_TENANT_ID".into(), String::new());
        values.insert("HUMAUX_GATEWAY_REMEMBER_WORKSPACE_ID".into(), String::new());
        assert!(GatewayBootstrap::from_raw(values).is_ok());

        for key in [
            "HUMAUX_GATEWAY_REMEMBER_TENANT_ID",
            "HUMAUX_GATEWAY_REMEMBER_WORKSPACE_ID",
        ] {
            let mut values = raw();
            values.insert(key.into(), "not-a-uuid".into());
            assert!(GatewayBootstrap::from_raw(values).is_err(), "{key}");
        }
    }

    #[test]
    fn fingerprint_changes_for_public_values_but_not_secret_values() {
        let values = raw();
        let first = GatewayBootstrap::from_raw(values.clone()).expect("valid fixture config");

        let mut changed_secrets = values.clone();
        changed_secrets.insert("HUMAUX_GATEWAY_PG_DSN".into(), "postgres://other".into());
        changed_secrets.insert(
            "HUMAUX_GATEWAY_CREDENTIAL_PEPPER_HEX".into(),
            "aabbccdd".into(),
        );
        let secret_changed =
            GatewayBootstrap::from_raw(changed_secrets).expect("valid secret-changed config");
        assert_eq!(first.config_fingerprint, secret_changed.config_fingerprint);

        let mut changed = values;
        changed.insert("HUMAUX_GATEWAY_CONTEXT_TOTAL_TOKENS".into(), "4096".into());
        let second = GatewayBootstrap::from_raw(changed).expect("valid changed config");
        assert_ne!(first.config_fingerprint, second.config_fingerprint);
    }

    #[test]
    fn context_profile_uses_registered_validation_and_fingerprint() {
        let baseline = raw();
        let first =
            GatewayBootstrap::from_raw(baseline.clone()).expect("registered default profile");
        for (key, value) in [
            ("HUMAUX_GATEWAY_RETRIEVAL_PROFILE_TOP_K", "0"),
            (
                "HUMAUX_GATEWAY_RETRIEVAL_PROFILE_PRODUCTION_ENABLED",
                "false",
            ),
            (
                "HUMAUX_GATEWAY_RETRIEVAL_PROFILE_QUERY_TRANSFORM",
                "client-prompt",
            ),
        ] {
            let mut values = baseline.clone();
            values.insert(key.into(), value.into());
            assert!(
                GatewayBootstrap::from_raw(values).is_err(),
                "{key} must use the registered gate"
            );
        }
        let mut values = baseline;
        values.insert("HUMAUX_GATEWAY_RETRIEVAL_PROFILE_TOP_K".into(), "7".into());
        let changed = GatewayBootstrap::from_raw(values).expect("registered profile override");
        assert_ne!(first.config_fingerprint, changed.config_fingerprint);
    }

    /// ADR-0061 D-B / D-F: both new keys are required with no code default; a non-loopback or
    /// port-0 ops address and a zero refresh are refused naming the key (T-G6 at the parser).
    #[test]
    fn ops_keys_are_required_and_the_ops_address_is_loopback_only() {
        for key in [METRICS_ADDR_KEY, READINESS_REFRESH_KEY] {
            assert!(
                registry()
                    .iter()
                    .any(|entry| entry.name == key && entry.default.is_none()),
                "{key} must be declared without a default"
            );
            let mut values = raw();
            values.remove(key);
            assert_eq!(rejected_key(values), key);
        }
        for bad in ["0.0.0.0:9101", "10.0.0.1:9101", "127.0.0.1:0", "nonsense"] {
            let mut values = raw();
            values.insert(METRICS_ADDR_KEY.into(), bad.into());
            assert_eq!(rejected_key(values), METRICS_ADDR_KEY, "{bad}");
        }
        let mut values = raw();
        values.insert(READINESS_REFRESH_KEY.into(), "0".into());
        assert_eq!(rejected_key(values), READINESS_REFRESH_KEY);
    }

    /// ADR-0061 D-B: every registry entry has one `/status` row; a secret row has no `value` key,
    /// whichever constructor declared it. Fault: emit `value` for `entry_with_default` rows ⇒ red.
    #[test]
    fn effective_config_rows_never_carry_a_secret_value() {
        let mut values = raw();
        values.insert(
            "HUMAUX_GATEWAY_TOKEN_HMAC_KEY_PREVIOUS".into(),
            generated_key_hex(),
        );
        values.remove("HUMAUX_GATEWAY_REMEMBER_TENANT_ID");
        let boot = GatewayBootstrap::from_raw(values.clone()).expect("valid config");
        let rows = boot.effective_config.as_array().expect("rows");
        assert_eq!(rows.len(), registry().len());
        for entry in registry() {
            let row = rows
                .iter()
                .find(|r| r["name"] == entry.name.as_str())
                .unwrap_or_else(|| panic!("{} has no row", entry.name));
            if entry.secret {
                assert_eq!(row["secret"], true, "{row}");
                assert!(row.get("value").is_none(), "{row}");
                if let Some(secret) = values.get(&entry.name).filter(|v| !v.is_empty()) {
                    assert!(!boot.effective_config.to_string().contains(secret.as_str()));
                }
            } else {
                assert!(row.get("value").is_some(), "{row}");
            }
        }
        let source =
            |name: &str| rows.iter().find(|r| r["name"] == name).expect("row")["source"].clone();
        assert_eq!(source("HUMAUX_GATEWAY_BIND_ADDR"), "env");
        assert_eq!(source("HUMAUX_GATEWAY_REMEMBER_TENANT_ID"), "default");
    }

    fn semantic_recall_enabled_values() -> BTreeMap<String, String> {
        let mut values = raw();
        let cell_id = Uuid::now_v7().to_string();
        for (key, value) in [
            (
                "HUMAUX_GATEWAY_RETRIEVAL_RPC_SOCKET_PATH",
                "/tmp/hgb-test.sock",
            ),
            ("HUMAUX_GATEWAY_RETRIEVAL_RPC_PERMIT_TTL_SECONDS", "30"),
            ("HUMAUX_GATEWAY_RETRIEVAL_RPC_SERVER_UID", "10102"),
            ("HUMAUX_GATEWAY_EMBEDDING_DIMENSION", "4"),
            ("HUMAUX_GATEWAY_EMBEDDING_VERSION", "embed-v1"),
            ("HUMAUX_GATEWAY_QDRANT_HOST", "127.0.0.1"),
            ("HUMAUX_GATEWAY_QDRANT_PORT", "6333"),
            ("HUMAUX_GATEWAY_QDRANT_CIDR", "127.0.0.1/32"),
            ("HUMAUX_GATEWAY_QDRANT_TLS", "false"),
            ("HUMAUX_GATEWAY_CALLER_ID", "gateway"),
        ] {
            values.insert(key.into(), value.into());
        }
        values.insert("HUMAUX_GATEWAY_CELL_ID".into(), cell_id);
        values
    }

    /// A non-empty `HUMAUX_GATEWAY_RETRIEVAL_RPC_SOCKET_PATH` requires every other
    /// `HUMAUX_GATEWAY_{RETRIEVAL_RPC,EMBEDDING,QDRANT,CELL_ID,CALLER_ID}_*` key —
    /// dropping any one of them must fail closed, never silently disable the lane.
    #[test]
    fn semantic_recall_requires_every_field_once_the_socket_path_is_set() {
        let values = semantic_recall_enabled_values();
        GatewayBootstrap::from_raw(values.clone()).expect("fully configured semantic recall");
        for key in [
            // ADR-0066 D-L: the dial verifies the serving uid, so the key is required with the socket path.
            "HUMAUX_GATEWAY_RETRIEVAL_RPC_SERVER_UID",
            "HUMAUX_GATEWAY_EMBEDDING_DIMENSION",
            "HUMAUX_GATEWAY_EMBEDDING_VERSION",
            "HUMAUX_GATEWAY_QDRANT_HOST",
            "HUMAUX_GATEWAY_QDRANT_CIDR",
            "HUMAUX_GATEWAY_CELL_ID",
            "HUMAUX_GATEWAY_CALLER_ID",
        ] {
            let mut broken = values.clone();
            broken.insert(key.into(), String::new());
            assert!(
                GatewayBootstrap::from_raw(broken).is_err(),
                "{key} must be required once semantic recall is enabled"
            );
        }
    }

    /// ADR-0084 D-E: the model pin is read only while `rerank_enabled` is true; then all five keys are required and must
    /// form a valid identity, hash case is folded, and one blank part or an identity that cannot be told apart refuses to
    /// boot. Fault: read the pin while the lane is off, or let a blank part through ⇒ red.
    #[test]
    fn the_rerank_pin_is_required_exactly_while_the_lane_is_on() {
        let pin_of = |boot: GatewayBootstrap| boot.semantic_recall.expect("configured").rerank_pin;
        let mut values = semantic_recall_enabled_values();
        let off = GatewayBootstrap::from_raw(values.clone()).expect("lane off boots without a pin");
        assert!(
            pin_of(off).is_none(),
            "no pin is kept while the lane is off"
        );

        values.insert(retrieval_env_key(RERANK_ENABLED), "true".into());
        assert!(
            GatewayBootstrap::from_raw(values.clone()).is_err(),
            "the lane is on and the pin is blank"
        );
        for (key, value) in RERANK_PIN_KEYS.into_iter().zip([
            "org/model".to_owned(),
            "rev1".to_owned(),
            "recipe-v1".to_owned(),
            "a".repeat(64),
            "B".repeat(64),
        ]) {
            values.insert(key.into(), value);
        }
        let on = GatewayBootstrap::from_raw(values.clone()).expect("the lane is on with its pin");
        assert_eq!(
            pin_of(on),
            ModelIdentity::new(
                "org/model",
                "rev1",
                "recipe-v1",
                &"a".repeat(64),
                &"b".repeat(64)
            ),
            "the pin reaches the lane, hash case folded"
        );
        for key in RERANK_PIN_KEYS {
            let mut broken = values.clone();
            broken.insert(key.into(), String::new());
            assert!(
                GatewayBootstrap::from_raw(broken).is_err(),
                "{key} is required while the lane is on"
            );
        }
        let mut blurred = values;
        blurred.insert(RERANK_PIN_KEYS[0].into(), "org model".into());
        assert!(
            GatewayBootstrap::from_raw(blurred).is_err(),
            "an identity whose parts blur into one another"
        );
    }

    /// ADR-0084 U7: while the lane is on, `rerank_timeout_ms` must be below the handler timeout; off, it is not checked.
    /// Fault: drop the comparison ⇒ the boundary row goes red.
    #[test]
    fn the_rerank_timeout_must_be_below_the_handler_timeout_while_the_lane_is_on() {
        let handler = Duration::from_secs(5);
        assert!(check_rerank_timeout(false, 60_000, handler).is_ok());
        assert!(check_rerank_timeout(true, 4_999, handler).is_ok());
        assert!(check_rerank_timeout(true, 5_000, handler).is_err());

        let mut values = semantic_recall_enabled_values();
        for (key, value) in RERANK_PIN_KEYS.into_iter().zip([
            "org/model".to_owned(),
            "rev1".to_owned(),
            "recipe-v1".to_owned(),
            "a".repeat(64),
            "b".repeat(64),
        ]) {
            values.insert(key.into(), value);
        }
        values.insert(retrieval_env_key(RERANK_ENABLED), "true".into());
        GatewayBootstrap::from_raw(values.clone())
            .expect("the registered 4000 ms fits a 5 s handler");
        values.insert(retrieval_env_key(RERANK_TIMEOUT_MS), "5000".into());
        assert!(GatewayBootstrap::from_raw(values).is_err());
    }

    /// ADR-0084 D-E: the gateway's pin in `values/gateway.env` and the worker's identity in `values/retrieval-worker.env`
    /// are one identity written twice; this keeps them from drifting. Fault: change one hash digit in either file ⇒ red.
    #[test]
    fn the_gateway_pin_equals_the_workers_identity_in_the_values_files() {
        let gateway = include_str!("../../../deploy/env/values/gateway.env");
        let worker = include_str!("../../../deploy/env/values/retrieval-worker.env");
        let value = |text: &str, key: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(&format!("{key}=")))
                .unwrap_or_else(|| panic!("{key} is missing from its values file"))
                .to_owned()
        };
        // `RERANK_PIN_KEYS` and the worker's `KEY_*` constants list the five parts in the same order.
        for (gateway_key, worker_key) in RERANK_PIN_KEYS.into_iter().zip([
            KEY_REPO,
            KEY_REVISION,
            KEY_RECIPE,
            KEY_MODEL_SHA256,
            KEY_TOKENIZER_SHA256,
        ]) {
            assert_eq!(
                value(gateway, gateway_key),
                value(worker, worker_key),
                "{gateway_key}"
            );
        }
    }

    /// M12 D4: the query-embedding cache needs the whole generation stamp. All blank keeps it off, all set turns it on
    /// with the registry sizes, and any one blank of a filled stamp refuses to boot (never a guessed field).
    #[test]
    fn query_cache_needs_the_whole_generation_stamp_or_none() {
        let values = semantic_recall_enabled_values();
        let config = |values: BTreeMap<String, String>| {
            GatewayBootstrap::from_raw(values).map(|boot| {
                boot.semantic_recall
                    .expect("semantic recall is configured")
                    .query_cache
            })
        };
        assert!(config(values.clone()).expect("blank stamp boots").is_none());
        let stamp = [
            ("HUMAUX_GATEWAY_EMBEDDING_PROVIDER_ID", "test-provider"),
            ("HUMAUX_GATEWAY_EMBEDDING_MODEL_ID", "test-model"),
            ("HUMAUX_GATEWAY_EMBEDDING_MODEL_REVISION", "v1"),
        ];
        let mut full = values;
        for (key, value) in stamp {
            full.insert(key.into(), value.into());
        }
        let (generation, cache) = config(full.clone())
            .expect("full stamp boots")
            .expect("full stamp enables the cache");
        assert_eq!(generation.model_id, "test-model");
        assert_eq!(generation.dimension, 4);
        assert!(cache.enabled && cache.capacity_bytes > 0 && cache.per_tenant_bytes > 0);
        for (key, _) in stamp {
            let mut partial = full.clone();
            partial.insert(key.into(), String::new());
            assert!(
                config(partial).is_err(),
                "{key} blank in a filled stamp must refuse to boot"
            );
        }
    }

    /// The real build path (`GatewayBootstrap::build`'s `build_semantic_recall_runtime`) wires
    /// a working `SemanticRecallRuntime` — proven by constructing it directly here with the
    /// same parser this bootstrap uses, against a real `role_gateway` pool (§79.2: no mock
    /// PostgreSQL), rather than spinning up the whole HTTP-listener stack `build()` needs.
    #[tokio::test]
    async fn semantic_recall_config_builds_a_runtime() {
        let effective = resolve_effective_config(&registry(), &semantic_recall_enabled_values())
            .expect("effective config");
        let config = parse_semantic_recall(&effective)
            .expect("valid semantic recall config")
            .expect("socket path is non-empty");
        let handler_timeout = parse_guard(&effective)
            .expect("valid guard")
            .handler_timeout;
        let pool = Arc::new(
            // dep: PostgreSQL(role_gateway) — opens a fresh pool for the drain/shutdown health check
            RuntimeDbPool::connect(
                &std::env::var("HUMAUX_GATEWAY_PG_DSN")
                    .expect("semantic recall bootstrap test requires HUMAUX_GATEWAY_PG_DSN"),
            )
            .await
            .expect("real role_gateway pool"),
        );
        build_semantic_recall_runtime(pool, config, handler_timeout)
            .expect("semantic recall runtime builds from valid config");
    }
}
