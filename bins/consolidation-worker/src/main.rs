//! `consolidation-worker::main` — `humaux-consolidation-worker` process entry (§4.2 minimal process set; §4.4 admin
//!   probe contract; §11.7/§11.8 T4.6+T4.7).
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-infra-cell, humaux-telemetry, tokio, uuid]; services=[HTTP(loopback),
//!   PostgreSQL(role_consolidation_worker), UDS(private-worker)]; env=[HUMAUX_CONSOLIDATION_WORKER_PG_POOL_MAX_CONNECTIONS, CARGO_PKG_VERSION,
//!   HUMAUX_BUILD_GIT_SHA, HUMAUX_BUILD_TIME, HUMAUX_CONSOLIDATION_WORKER_BATCH,
//!   HUMAUX_CONSOLIDATION_WORKER_CALL_TTL_SECS, HUMAUX_CONSOLIDATION_WORKER_DIAL_TIMEOUT_SECS,
//!   HUMAUX_CONSOLIDATION_WORKER_LEASE_SECS, HUMAUX_CONSOLIDATION_WORKER_MAX_ATTEMPTS,
//!   HUMAUX_CONSOLIDATION_WORKER_MAX_INPUTS, HUMAUX_CONSOLIDATION_WORKER_POLL_INTERVAL_SECS,
//!   HUMAUX_CONSOLIDATION_WORKER_RPC_SERVER_UID, HUMAUX_CONSOLIDATION_WORKER_RPC_SOCKET_PATH,
//!   HUMAUX_CONSOLIDATION_WORKER_SERVE_METRICS_ADDR];
//!   modules=[adapters::postgres, consolidation-worker::dsn, consolidation-worker::inference_client, domain::error, humaux-consolidation-worker, humaux-telemetry,
//!   infra-cell::uds, telemetry::metrics]
//! Called-by: [process(humaux-consolidation-worker)]
//! Invariants: [missing/invalid env or an unreachable role_consolidation_worker DSN exits non-zero before any claim;
//!   `--readyz` fails unless both PG and the private worker's inference socket answer one live round trip;
//!   `--serve` reads its own HUMAUX_CONSOLIDATION_WORKER_SERVE_METRICS_ADDR (required, loopback) and the one-shot
//!   modes open no listener; --metrics-families reads no configuration]
//! Spec: ADR-0036; ADR-0037; §11.6; ADR-0061 D-B; ADR-0061 E10; ADR-0066 D-D; ADR-0066 D-N; ADR-0066 D-O; §48.1; §78.1; ADR-0065 D-A/D-B; ADR-0061 D-D; ADR-0066 D-B/D-G; ADR-0100
//!
//! The actual orchestration ([`run_once`] and friends) lives
//! in `src/lib.rs` — see that module's doc comment for why: a binary-only crate has no target
//! `tests/*.rs` can link against, so splitting it out is what makes `tests/run_once_e2e.rs`
//! and `tests/consolidation_hop_e2e.rs` possible at all.
//!
//! Modes:
//! * no flag: usage on stderr, exit 2 (ADR-0066 D-N; before card 39 it ran the probe and exited 0).
//!   `--probe-connection`: the original Phase 4 typed-role probe, explicit only.
//! * `--version`: `humaux-consolidation-worker <version> git_sha=<40 hex> build_time=…`, exit 0; exit 2 when the
//!   build carries no sha (ADR-0066 D-D). `--serve` prints the start line first.
//! * `--run-once`: ONE bounded cross-tenant dispatch pass, then exit — including when there was
//!   nothing to claim (before ADR-0036 this flag looped forever on an env-pinned pair and never
//!   exited on an empty tenant, which is what the deployment report flagged).
//! * `--serve`: the same pass on `HUMAUX_CONSOLIDATION_WORKER_POLL_INTERVAL_SECS` until a
//!   termination signal arrives ([`Shutdown`]).
//! * `--readyz`: card 15 / ADR-0037 probe-based readiness — ONE live round trip to each
//!   dependency this process cannot work without, then exit. Tenant-free by construction
//!   (ADR-0036 left no tenant/domain/binding id in this environment): "can I claim at all",
//!   never "is tenant X's pair healthy". Uses no configuration key the process does not
//!   already need for `--serve`.
//!
//! ADR-0036 (card 14): there is no tenant id, reasoning domain, or route binding in this
//! binary's environment any more. `role_consolidation_worker`'s RLS session context is still set
//! per call from a caller-supplied tenant_id — which is exactly why "which tenants have pending
//! work" cannot be a plain query from this process — so discovery goes through the owner
//! SECURITY DEFINER `ops.claim_derived_work` (migration 0164), which is the ONE cross-tenant read
//! of `ops.jobs` in the workspace. Everything after the claim runs under the claimed job's own
//! tenant context through the ordinary repos, and the route binding is resolved per tenant
//! through the narrow 0147 resolver (`consolidate_repo::resolve_consolidate_binding`).
//!
//!
//! `build_rollup` is [`humaux_consolidation_worker::build_rollup`]: the private worker's typed
//! JSON reply parsed fail-closed against this run's own materialized `(memory_id, evidence_id)`
//! pairs (`humaux_adapters::consolidation_reasoner::parse_rollup_output`, shared with the
//! private worker). §11.6's guard holds by construction — the closure still has no DB
//! capability and can only pick sources from ids the run itself recorded.
//!
//! Card 34 / ADR-0061 D-B: `--serve` opens a loopback ops listener (`/metrics`, `/status`). No §41.2 family is
//! counted in this process yet, so `/metrics` is empty and Prometheus' `up` is the resident liveness signal (E10).

use std::env;
use std::process::ExitCode;
use std::time::Duration;

use humaux_adapters::postgres::ConsolidationDbPool;
use humaux_consolidation_worker::{
    DispatchConfig, dispatch_pass, inference_client::UdsInferenceClient,
};
use humaux_domain::error::ErrorCode;
use humaux_telemetry::metrics::{OpsListener, parse_ops_addr, process_routes, serve_loopback};
use humaux_telemetry::{ModeFailure, start_line, version_mode};
use uuid::Uuid;

fn required(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("missing required configuration: {name}"))
}

fn parse<T: std::str::FromStr>(name: &str) -> Result<T, String> {
    required(name)?
        .parse()
        .map_err(|_| format!("invalid configuration: {name}"))
}

fn usage() -> &'static str {
    "usage: humaux-consolidation-worker (--probe-connection | --readyz | --run-once | --serve | --metrics-families | --version)"
}

/// §78.1 / ADR-0061 D-B: `--serve`'s own ops listener address (loopback only, no default).
const SERVE_METRICS_ADDR: &str = "HUMAUX_CONSOLIDATION_WORKER_SERVE_METRICS_ADDR";

const STAGES: [&str; 1] = ["consolidation_dispatch"];

async fn dispatch_iteration(
    work: impl std::future::Future<
        Output = Result<
            humaux_consolidation_worker::DispatchReport,
            humaux_consolidation_worker::DispatchError,
        >,
    >,
) -> Result<humaux_consolidation_worker::DispatchReport, humaux_consolidation_worker::DispatchError>
{
    use humaux_telemetry::metrics::{stage_recorded, stage_started};
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64()
    };
    stage_started(STAGES[0], now());
    let result = work.await;
    let (error, counts) = match &result {
        Ok(r) => (r.last_error, [u64::from(r.claimed), u64::from(r.published)]),
        Err(e) => (
            Some(match e {
                humaux_consolidation_worker::DispatchError::Config(_) => ErrorCode::InvalidInput,
                humaux_consolidation_worker::DispatchError::Jobs(_) => {
                    ErrorCode::DependencyUnavailable
                }
            }),
            [0, 0],
        ),
    };
    stage_recorded(STAGES[0], now(), error, counts);
    result
}

/// §39 / ADR-0061: the closed dispatch stage, shared by both metrics routes.
fn render_metrics(out: &mut String) {
    humaux_telemetry::metrics::render_stage_liveness(out, &STAGES);
}

/// Binds `--serve`'s loopback ops listener (ADR-0061 D-B). The handle must live as long as the mode: dropping it
/// closes the port.
fn ops_listener() -> Result<OpsListener, String> {
    let addr = parse_ops_addr(&required(SERVE_METRICS_ADDR)?)
        .map_err(|reason| format!("invalid configuration: {SERVE_METRICS_ADDR}: {reason}"))?;
    let routes = process_routes(
        "humaux-consolidation-worker",
        "serve",
        env!("CARGO_PKG_VERSION"),
        option_env!("HUMAUX_BUILD_GIT_SHA"),
        render_metrics,
    );
    // dep: HTTP(loopback) — --serve's /metrics + /status listener
    serve_loopback(SERVE_METRICS_ADDR, addr, routes).map_err(|e| e.to_string())
}

const BIN: &str = "humaux-consolidation-worker";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const GIT_SHA: Option<&str> = option_env!("HUMAUX_BUILD_GIT_SHA");

/// ADR-0066 D-O: the role_consolidation_worker DSN under its `HUMAUX_` name (or the deprecated alias, with one WARN).
fn pg_dsn() -> Result<String, String> {
    let (dsn, warn) = humaux_consolidation_worker::dsn::resolve(|k| env::var(k).ok())?;
    if let Some(warn) = warn {
        eprintln!("{warn}");
    }
    Ok(dsn)
}

// §48.1 / ADR-0065 D-A/D-B: all process entry points share one validated ceiling.
async fn connect_pool(dsn: &str) -> Result<ConsolidationDbPool, String> {
    let raw = std::env::var("HUMAUX_CONSOLIDATION_WORKER_PG_POOL_MAX_CONNECTIONS");
    let raw = match raw {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(_) => {
            return Err("invalid HUMAUX_CONSOLIDATION_WORKER_PG_POOL_MAX_CONNECTIONS".to_owned());
        }
    };
    let settings = humaux_adapters::postgres::load_pool_settings(raw.as_deref())?;
    // dep: PostgreSQL(role_consolidation_worker) — sized process pool; role identity checked before use
    ConsolidationDbPool::connect_with(dsn, &settings)
        .await
        .map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    // ADR-0066 D-N: exactly one mode argument; none (formerly the probe, exit 0) or more is usage, exit 2.
    if args.len() != 1 {
        eprintln!("{BIN}: {}", usage());
        return ExitCode::from(2);
    }
    match args[0].as_str() {
        "--probe-connection" => probe_connection().await,
        "--version" => version_mode(BIN, VERSION, GIT_SHA, option_env!("HUMAUX_BUILD_TIME")),
        // ADR-0061 D-C: before any configuration is read.
        "--metrics-families" => {
            let mut out = String::new();
            render_metrics(&mut out);
            print!("{out}");
            ExitCode::SUCCESS
        }
        "--readyz" => match readyz().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(missing) => {
                eprintln!("{BIN}: not ready — missing object: {missing}");
                ExitCode::from(2)
            }
        },
        mode @ ("--run-once" | "--serve") => {
            let resident = mode == "--serve";
            // ADR-0066 D-D: the resident mode's first line names the build it runs.
            if resident {
                eprintln!("{}", start_line(BIN, "serve", VERSION, GIT_SHA));
            }
            // ADR-0066 D-N: a failure marked runtime (database down, a failed pass) exits 1, configuration 2.
            match dispatch_mode(resident).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(failure) => {
                    eprintln!("{BIN}: {failure}");
                    failure.exit_code()
                }
            }
        }
        _ => {
            eprintln!("{BIN}: {}", usage());
            ExitCode::from(2)
        }
    }
}

/// `--probe-connection`: the original Phase 4 typed-role probe, now an explicit mode only (ADR-0066 D-N): connected
/// ⇒ 0, a missing / conflicting DSN ⇒ 2, a failed connect ⇒ 1.
async fn probe_connection() -> ExitCode {
    let dsn = match pg_dsn() {
        Ok(dsn) => dsn,
        Err(error) => {
            eprintln!("{BIN}: {error}");
            return ExitCode::from(2);
        }
    };
    // dep: PostgreSQL(role_consolidation_worker) — role-scoped pool call
    match connect_pool(&dsn).await {
        Ok(_pool) => {
            println!("{BIN}: connected as role_consolidation_worker");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{BIN}: {e}");
            ExitCode::FAILURE
        }
    }
}

/// ADR-0036 `--run-once` (one bounded pass, then exit — `claimed == 0` exits zero promptly
/// instead of spinning) / `--serve` (the same pass on
/// `HUMAUX_CONSOLIDATION_WORKER_POLL_INTERVAL_SECS` until the process is killed).
async fn dispatch_mode(resident: bool) -> Result<(), ModeFailure> {
    // ADR-0061 D-B: only the resident mode is scraped; `--run-once` opens no listener.
    let _ops = if resident {
        Some(ops_listener()?)
    } else {
        None
    };
    let dsn = pg_dsn()?;
    let socket_path = required("HUMAUX_CONSOLIDATION_WORKER_RPC_SOCKET_PATH")?;
    // ADR-0066 D-L: the private worker's uid; every dial refuses any other serving uid.
    let server_uid = parse::<u32>("HUMAUX_CONSOLIDATION_WORKER_RPC_SERVER_UID")?;
    let call_ttl = Duration::from_secs(parse::<u64>("HUMAUX_CONSOLIDATION_WORKER_CALL_TTL_SECS")?);
    let dial_timeout = Duration::from_secs(parse::<u64>(
        "HUMAUX_CONSOLIDATION_WORKER_DIAL_TIMEOUT_SECS",
    )?);
    let config = DispatchConfig {
        // Per-process owner: every terminal transition is fenced on it plus the claim's
        // `attempt`, so two resident workers never both settle one job.
        lease_owner: format!("humaux-consolidation-worker/{}", Uuid::now_v7()),
        lease_seconds: parse::<u64>("HUMAUX_CONSOLIDATION_WORKER_LEASE_SECS")? as f64,
        batch: parse::<i64>("HUMAUX_CONSOLIDATION_WORKER_BATCH")?,
        max_inputs: parse::<i64>("HUMAUX_CONSOLIDATION_WORKER_MAX_INPUTS")?,
        max_attempts: parse::<i32>("HUMAUX_CONSOLIDATION_WORKER_MAX_ATTEMPTS")?,
    };
    config
        .validate()
        .map_err(|field| format!("invalid configuration: HUMAUX_CONSOLIDATION_WORKER_{field}"))?;
    let poll_interval = if resident {
        Some(Duration::from_secs(parse::<u64>(
            "HUMAUX_CONSOLIDATION_WORKER_POLL_INTERVAL_SECS",
        )?))
    } else {
        None
    };

    // dep: PostgreSQL(role_consolidation_worker) — role-scoped pool call
    let pool = connect_pool(&dsn).await.map_err(|e| {
        ModeFailure::runtime(format!(
            "consolidation worker database role connection failed: {e}"
        ))
    })?;
    let mut shutdown = Shutdown::install().map_err(ModeFailure::runtime)?;

    loop {
        let report = dispatch_iteration(dispatch_pass(
            &pool,
            |tenant_id, run_id| {
                UdsInferenceClient::new(
                    &pool,
                    socket_path.clone(),
                    server_uid,
                    tenant_id,
                    call_ttl,
                    dial_timeout,
                    run_id,
                )
            },
            &config,
        ))
        .await;
        match report {
            Ok(report) => println!(
                "humaux-consolidation-worker: dispatch pass claimed={} published={} no_output={} stale={} not_ready={} deferred={} dead={} lost_lease={}",
                report.claimed,
                report.published,
                report.no_output,
                report.stale_input,
                report.not_ready,
                report.deferred,
                report.dead,
                report.lost_lease
            ),
            // Resident mode: one failed pass (a DB blip) is logged and retried on the next poll;
            // `--run-once` surfaces it as the exit status.
            Err(error) if poll_interval.is_some() => {
                eprintln!("humaux-consolidation-worker: dispatch pass failed: {error}")
            }
            Err(error) => {
                return Err(ModeFailure::runtime(format!(
                    "dispatch pass failed: {error}"
                )));
            }
        }
        let Some(interval) = poll_interval else {
            return Ok(());
        };
        // Card 15 / ADR-0037: the signal is only ever observed BETWEEN passes. A pass settles
        // every job it claimed before it returns (card 14's leases), so exiting here can never
        // leave a job PROCESSING with a live lease that only expiry could free — whereas
        // cancelling a pass mid-flight could. The cost is that shutdown latency is bounded by
        // one pass, not by the signal: the supervisor's grace period must exceed one pass
        // (docs/ops/supervision.md).
        tokio::select! {
            () = tokio::time::sleep(interval) => {}
            () = shutdown.recv() => {
                eprintln!("humaux-consolidation-worker: signal received between passes, exiting");
                return Ok(());
            }
        }
    }
}

/// SIGTERM/Ctrl-C, as one awaitable. Both handlers are installed HERE, before the first pass —
/// which is the whole point of the type. `tokio::signal::ctrl_c()` cannot be used for the SIGINT
/// half: it is an `async fn` whose body registers the handler on its FIRST POLL, and the first
/// poll only happens inside [`Self::recv`], i.e. after a pass has already returned. A Ctrl-C
/// during that first pass would then hit SIGINT's default disposition and kill the process
/// mid-pass, leaving exactly the `ops.jobs` row `PROCESSING` with a live lease this card
/// forbids. Registering `SignalKind::interrupt()` eagerly, next to `terminate`, is what makes
/// the doc claim true for both signals.
struct Shutdown {
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
}

impl Shutdown {
    fn install() -> Result<Self, String> {
        Ok(Self {
            #[cfg(unix)]
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|e| format!("cannot install the SIGTERM handler: {e}"))?,
            #[cfg(unix)]
            interrupt: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .map_err(|e| format!("cannot install the SIGINT handler: {e}"))?,
        })
    }

    async fn recv(&mut self) {
        #[cfg(unix)]
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// `--readyz`: one live round trip per dependency, in start order (a dependency that is down
/// is named, never collapsed into a bare non-zero exit — §4.4 坑5 applied to readiness).
///
/// 1. `role_consolidation_worker` connects AND `current_user` matches (§6.2.3 assertion E) —
///    which is also the only "can I claim" statement this process can make without actually
///    claiming: `ops.claim_derived_work` is a SECURITY DEFINER *write* (migration 0164), so
///    calling it as a probe would take a real job off the queue and hand it to a process that
///    is about to exit. Connectivity + role identity is the readable half; the callable half is
///    proven by the first real pass.
/// 2. The private worker's UDS peer accepts a connection and is served by the registered uid (ADR-0066 D-L) —
///    the §11.8 hop every claimed USER_REASONING job must make. Dialled and immediately dropped: no request is sent.
async fn readyz() -> Result<(), String> {
    let dsn = pg_dsn()?;
    // dep: PostgreSQL(role_consolidation_worker) — role-scoped pool call
    connect_pool(&dsn)
        .await
        .map_err(|e| format!("PostgreSQL as role_consolidation_worker ({e})"))?;
    let socket_path = required("HUMAUX_CONSOLIDATION_WORKER_RPC_SOCKET_PATH")?;
    let server_uid = parse::<u32>("HUMAUX_CONSOLIDATION_WORKER_RPC_SERVER_UID")?;
    // dep: UDS(private-worker) — readyz dials the private worker's inference RPC socket, verified (ADR-0066 D-L)
    humaux_infra_cell::uds::connect_verified(&socket_path, server_uid)
        .await
        .map_err(|e| format!("the private worker's inference RPC socket at {socket_path} ({e})"))?;
    println!(
        "humaux-consolidation-worker: ready db=role_consolidation_worker rpc_peer={socket_path}"
    );
    Ok(())
}

#[cfg(test)]
mod stage_witness {
    use super::*;
    #[tokio::test]
    async fn stage_iteration_exports_exact_set() {
        let report = humaux_consolidation_worker::DispatchReport {
            last_error: Some(ErrorCode::ProviderPermanent),
            ..Default::default()
        };
        dispatch_iteration(async { Ok(report) }).await.unwrap();
        let mut out = String::new();
        render_metrics(&mut out);
        let stages: Vec<_> = out
            .lines()
            .filter(|l| l.starts_with("stage_last_run_timestamp_seconds{"))
            .map(|l| l.split(' ').next().unwrap())
            .collect();
        assert_eq!(
            stages,
            ["stage_last_run_timestamp_seconds{stage=\"consolidation_dispatch\"}"]
        );
        assert_eq!(stages.len(), 1);
        assert_eq!(
            out.lines().find(|l| l.starts_with("stage_state{")).unwrap(),
            "stage_state{stage=\"consolidation_dispatch\"} 3"
        );
    }
}
