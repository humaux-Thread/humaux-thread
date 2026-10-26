//! Boot configuration for the isolated singleton process tests (§79; ADR-0100).
//! Depends-on: crates=[uuid]; services=[]; env=[]; modules=[]
//! Called-by: [tests]
//! Invariants: [each gateway receives its own deployment unless a test explicitly shares one]
//! Spec: Baseline §79; ADR-0100
use std::{collections::BTreeMap, net::SocketAddr};
use uuid::Uuid;
const PREFIX: &str = "HUMAUX_GATEWAY_";
/// A complete gateway environment; semantic recall stays disabled (§79).
pub fn base_env(pg_dsn: &str, bind: SocketAddr, ops: SocketAddr) -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> = [
        ("BIND_ADDR", bind.to_string()),
        ("ALLOWED_HOSTS", bind.to_string()),
        ("ALLOWED_ORIGINS", format!("http://{bind}")),
        ("MAX_REQUEST_BODY_BYTES", "65536".into()),
        ("PG_DSN", pg_dsn.into()),
        ("DEPLOYMENT", Uuid::now_v7().to_string()),
        ("CREDENTIAL_PEPPER_HEX", random_hex("")),
        ("TOKEN_HMAC_KEY", random_hex("")),
        ("TRUSTED_PROXY_CIDRS", String::new()),
        ("MAX_FORWARDED_HOPS", "1".into()),
        ("GLOBAL_DENYLIST", String::new()),
        ("GLOBAL_EMERGENCY_ALLOWLIST", String::new()),
        ("RESERVATION_TTL_SECONDS", "30".into()),
        ("HANDLER_TIMEOUT_SECONDS", "5".into()),
        ("FINALIZE_TIMEOUT_SECONDS", "2".into()),
        ("REPLAY_TTL_SECONDS", "60".into()),
        ("CONFIRM_TOKEN_TTL_SECONDS", "300".into()),
        ("UNDO_WINDOW_SECONDS", "86400".into()),
        ("MOOD_HALF_LIFE_SECONDS", "21600".into()),
        ("PROJECTION_LAG_SECONDS", "60".into()),
        ("ENUMERATION_TTL_SECONDS", "900".into()),
        ("ENUMERATION_MANIFEST_CAP", "1000".into()),
        ("REMEMBER_SCOPE_KIND", "workspace".into()),
        ("REMEMBER_DOMAIN", "knowledge".into()),
        ("REMEMBER_PROJECTION_KIND", "ingest".into()),
        ("REMEMBER_PROJECTION_VERSION", "v1".into()),
        ("REMEMBER_REASONING_DOMAIN_ID", Uuid::now_v7().to_string()),
        ("REMEMBER_TOKEN_TTL_SECONDS", "60".into()),
        ("REMEMBER_DATA_CLASS", "INTERNAL".into()),
        ("REMEMBER_VISIBILITY_CLASS", "WORKSPACE_SHARED".into()),
        ("REMEMBER_EVENT_KIND", "USER_MESSAGE".into()),
        ("CONTEXT_TOTAL_TOKENS", "2048".into()),
        ("CONTEXT_MANDATORY_TOKENS", "1024".into()),
        ("METRICS_ADDR", ops.to_string()),
        ("READINESS_REFRESH_SECONDS", 1.to_string()),
        // ADR-0065 D-A / D-B: the sqlx 0.8.6 defaults this fixture ran on before card 38; both session timeouts
        // below the 5 s handler timeout (the boot order rule).
        ("PG_POOL_MAX_CONNECTIONS", "10".into()),
        ("PG_POOL_MIN_CONNECTIONS", "0".into()),
        ("PG_ACQUIRE_TIMEOUT_MS", "30000".into()),
        ("PG_IDLE_TIMEOUT_SECONDS", "600".into()),
        ("PG_MAX_LIFETIME_SECONDS", "1800".into()),
        ("PG_STATEMENT_TIMEOUT_MS", "4000".into()),
        ("PG_IDLE_IN_TRANSACTION_TIMEOUT_MS", "4000".into()),
        // ADR-0065 D-D / D-E: the former lock_timeout literal (below statement_timeout) and the /64 SEC-6 prefix.
        ("RATE_LOCK_TIMEOUT_MS", "2000".into()),
        ("RATE_PREAUTH_IPV6_PREFIX_BITS", "64".into()),
        // ADR-0065 D-C: the §67.2 start values; B within the 5 s handler timeout (the boot bound).
        ("ADMISSION_CONCURRENCY", "16".into()),
        ("ADMISSION_QUEUE_DEPTH", "64".into()),
        ("ADMISSION_MAX_WAIT_MS", "5000".into()),
        ("ADMISSION_PER_KEY_LIMIT", "16".into()),
        ("ADMISSION_BODY_READ_TIMEOUT_MS", "5000".into()),
    ]
    .into_iter()
    .map(|(k, v)| (format!("{PREFIX}{k}"), v))
    .collect();
    for name in ["PREAUTH_IP", "CREDENTIAL", "USER", "TENANT", "OPERATION"] {
        env.insert(format!("{PREFIX}RATE_{name}_CAPACITY"), "100".into());
        env.insert(
            format!("{PREFIX}RATE_{name}_REFILL_PER_SECOND"),
            "100".into(),
        );
    }
    env
}

/// 32 bytes of hex: `marker` (itself hex) then random v7 hex.
fn random_hex(marker: &str) -> String {
    let random = format!("{}{}", Uuid::now_v7().simple(), Uuid::now_v7().simple());
    format!("{marker}{}", &random[marker.len()..])
}
