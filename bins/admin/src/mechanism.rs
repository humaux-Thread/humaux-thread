//! `admin::mechanism` — Read-only operational mechanism status.
//! Depends-on: crates=[humaux-adapters, humaux-contracts,
//!   tokio]; services=[PostgreSQL(role_admin)]; env=[CARGO_MANIFEST_DIR,
//!   HUMAUX_ADMIN_PG_DSN, HUMAUX_ADMIN_PG_POOL_MAX_CONNECTIONS]; modules=[adapters::mechanism_observation, adapters::postgres,
//!   contracts::mechanism_registry]
//! Called-by: [admin::main, admin::render]
//! Invariants: [a query against a mechanism the registry does not recognise returns the typed NotFound, never a default row]
//! Spec: Baseline §48.1; §78.1; ADR-0065 D-A/D-B; ADR-0061 D-D; ADR-0066 D-B/D-G; ADR-0100
//!
//! No default target and no bootstrap fallback.

use humaux_adapters::{
    mechanism_observation::{RuntimeObservations, read_target},
    postgres::AdminDbPool,
};
use humaux_contracts::mechanism_registry::{MechanismSpec, parse_registry, parse_target_args};

/// §48.1 / ADR-0065 D-A/D-B: admin observations use the configured process ceiling.
pub(crate) async fn connect_pool(dsn: &str) -> Result<AdminDbPool, String> {
    let raw = std::env::var("HUMAUX_ADMIN_PG_POOL_MAX_CONNECTIONS");
    let raw = match raw {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(_) => return Err("invalid HUMAUX_ADMIN_PG_POOL_MAX_CONNECTIONS".to_owned()),
    };
    let settings = humaux_adapters::postgres::load_pool_settings(raw.as_deref())?;
    // dep: PostgreSQL(role_admin) — sized read-only pool; role identity checked before use
    AdminDbPool::connect_with(dsn, &settings)
        .await
        .map_err(|e| e.to_string())
}

/// §1.14: the canonical mechanism registry lives in the specification.
pub const SPEC_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/architecture/Baseline_2.9.md"
);

/// §1.14: observations must match the canonical mechanism registry and explicit target.
pub fn read(args: &[String]) -> Result<(Vec<MechanismSpec>, RuntimeObservations), String> {
    let target = parse_target_args(args)?;
    let text = std::fs::read_to_string(SPEC_PATH)
        .map_err(|_| "cannot read canonical mechanism registry")?;
    let specs = parse_registry(&text)?;
    let dsn = std::env::var("HUMAUX_ADMIN_PG_DSN").map_err(|_| "missing HUMAUX_ADMIN_PG_DSN")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| "cannot start database runtime")?;
    let observations = runtime.block_on(async {
        // dep: PostgreSQL(role_admin) — opens the role_admin pool for the mechanism registry query
        let pool = connect_pool(&dsn)
            .await
            .map_err(|_| "cannot connect as read-only role_admin")?;
        read_target(&pool, &target)
            .await
            .map_err(|_| "cannot read runtime observation evidence")
    })?;
    Ok((specs, observations))
}

/// §4.4: missing observation evidence refuses a successful status receipt.
pub fn status(args: &[String]) -> i32 {
    match read(args) {
        Ok((specs, observations)) => {
            println!("{}", observations.render_json(&specs));
            i32::from(observations.cannot_establish(&specs))
        }
        Err(error) => {
            eprintln!("mechanism status: cannot_establish — {error}");
            1
        }
    }
}
