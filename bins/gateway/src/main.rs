//! `gateway::main` — `humaux-gateway` 进程入口（最小必要进程集见 §4.2；admin 探针契约见 §4.4）。
//! Depends-on: crates=[axum, humaux-telemetry, tokio]; services=[HTTP(loopback)]; env=[CARGO_PKG_VERSION,
//!   HUMAUX_BUILD_GIT_SHA, HUMAUX_BUILD_TIME, HUMAUX_GATEWAY_BIND_ADDR]; modules=[gateway::bootstrap,
//!   gateway::admission, gateway::auth_pages, gateway::billing_webhook, gateway::oauth_http, gateway::guard, gateway::status, humaux-telemetry, telemetry::metrics]
//! Called-by: [process(humaux-gateway)]
//! Invariants: [/readyz flips to 503 and the accept loop keeps draining for DRAIN_ANNOUNCE_WINDOW before closing, so a k8s readinessProbe never sees ECONNREFUSED confused with a crash; the ops listener stays up through the drain window and closes after it; `--metrics-families` and `--version` read no configuration; `--readyz` / `--livez` read only HUMAUX_GATEWAY_BIND_ADDR; no argument = serve, any other argument = usage and exit 2; a configuration error exits 2, a runtime failure 1 (ADR-0066 D-N)]
//! Spec: Baseline §4.2; §4.4; §67.2; ADR-0037; ADR-0061 D-B; ADR-0061 D-F; ADR-0065 D-C; ADR-0066 D-D; ADR-0066 D-N; ADR-0125
//!
//! ## Supervision surface (card 15, ADR-0037)
//!
//! Two unauthenticated GET routes a supervisor/load balancer can poll, merged onto the MCP
//! router:
//!
//! | route | 200 means | 503 means |
//! |---|---|---|
//! | `/livez` | this process is running and its accept loop is alive | — (a dead process refuses the connection) |
//! | `/readyz` | bootstrap completed, this process is still accepting new work, and the last readiness snapshot (PG, the retrieval RPC round trip, Qdrant; refreshed every `HUMAUX_GATEWAY_READINESS_REFRESH_SECONDS`) is all pass/not_applicable and ≤ 2 intervals old | body `{"status": "not_ready" \| "stale" \| "draining"}` — never a dependency name; the loopback `/status` names it (ADR-0061 D-F) |
//!
//! The 503 is only a real answer if a supervisor can still *reach* it. A k8s
//! `readinessProbe.httpGet` opens a FRESH TCP connection on every poll, so flipping readiness to
//! false and closing the accept loop in the same instant would hand every such supervisor
//! ECONNREFUSED — indistinguishable from a crash, which is the one distinction this route
//! exists to make. [`DRAIN_ANNOUNCE_WINDOW`] is the gap between the two events, and it is the
//! reason the 503 branch is reachable at all.
//!
//! `/readyz` returning 200 is a real statement: [`GatewayBootstrap::build`] connected the
//! `role_gateway` pool and verified `current_user` (§6.2.3 assertion E), and the cached snapshot
//! (`gateway::status`) says every hard dependency answered a real round trip within the last two
//! refresh intervals (ADR-0061 D-F, OPS-8: before card 34 it was 200 forever after boot). A
//! process that failed boot never serves this route at all — the connection is refused, which is
//! the honest "not ready" (§4.4 坑5 in HTTP form: *unreachable* and *reachable-but-unhealthy* must
//! not be the same answer). `/metrics` and `/status` are NOT on this listener: they live on the
//! loopback ops listener `HUMAUX_GATEWAY_METRICS_ADDR` (ADR-0061 D-B, E5), because this one sits
//! behind the reverse proxy.
//!
//! **Why these two are outside `native_request_boundary`**: they carry no tenant data, no
//! config fingerprint, and no state mutation — a constant token and a status code — so the
//! boundary's Host/Origin allowlist (DNS-rebinding protection for the MCP surface) has nothing
//! to protect here, while a supervisor probing over the pod IP has no Host header the allowlist
//! could be configured to accept. Anything that would report *what* this process is (version,
//! fingerprint, tenant counts) belongs behind the boundary or in `humaux-admin q`, not here.
//!
//! ## Auth surface (M02-7, ADR-0125)
//!
//! When `HUMAUX_GATEWAY_AUTH_SURFACE_ENABLED` is true the `/auth/*` routes are merged onto the MCP router BEFORE
//! admission wraps it, so they share the body bound, the concurrency cap and the queue; the pre-auth IP tier is
//! their own `/auth/*` layer, not the MCP boundary's. With the switch off no `/auth/*` route exists.

use std::future::IntoFuture;
use std::{error::Error, net::SocketAddr, process::ExitCode, sync::Arc, time::Duration};

use axum::{Router, http::StatusCode, routing::get};
use humaux_gateway::{
    auth_pages, billing_webhook,
    bootstrap::GatewayBootstrap,
    guard::GuardMetrics,
    oauth_http,
    status::{METRICS_ADDR_KEY, Readiness, Verdict, render_metrics},
};
use humaux_telemetry::metrics::{Routes, serve_loopback};
use humaux_telemetry::{probe_http, start_line, version_mode};

/// How long the process keeps accepting connections AFTER readiness has gone false, so a
/// supervisor that dials a new connection per poll actually observes `503 draining` instead of
/// the ECONNREFUSED it cannot tell from a crash. Must exceed one readiness poll period; the
/// supervisor's SIGTERM→SIGKILL grace must exceed it + the body-read bound B + the admission wait W + the handler and
/// finalize timeouts (ADR-0065 D-C; docs/ops/supervision.md §3).
// ponytail: one constant, not a config key — every `HUMAUX_GATEWAY_*` key is declared in
// `bootstrap::registry()` and feeds the config fingerprint, and a drain window is not a
// fingerprint input. Promote it there if a deployment's readiness period ever exceeds 5s.
const DRAIN_ANNOUNCE_WINDOW: Duration = Duration::from_secs(5);

/// `/livez` + `/readyz`. The readiness verdict is read from the cached snapshot (never a
/// dependency call per request), and the body is a status word only (ADR-0061 D-F).
fn supervision_routes(readiness: Arc<Readiness>) -> Router {
    Router::new()
        .route("/livez", get(async || (StatusCode::OK, "live\n")))
        .route(
            "/readyz",
            get(async move || {
                let verdict = readiness.verdict();
                let code = if verdict == Verdict::Ready {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                };
                (
                    code,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    format!("{{\"status\":\"{}\"}}\n", verdict.as_str()),
                )
            }),
        )
}

const BIN: &str = "humaux-gateway";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const GIT_SHA: Option<&str> = option_env!("HUMAUX_BUILD_GIT_SHA");
/// ADR-0066 D-D: the probe modes dial the public listener the supervision routes live on.
const BIND_ADDR_KEY: &str = "HUMAUX_GATEWAY_BIND_ADDR";

fn usage() -> &'static str {
    "usage: humaux-gateway [--metrics-families | --version | --readyz | --livez] (no argument = serve)"
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        // ADR-0061 D-C: the zero-state exposition, before any configuration is read (D-H reads it).
        ["--metrics-families"] => {
            print!("{}", render_metrics(&GuardMetrics::default()));
            ExitCode::SUCCESS
        }
        ["--version"] => version_mode(BIN, VERSION, GIT_SHA, option_env!("HUMAUX_BUILD_TIME")),
        // ADR-0066 D-D: the compose healthchecks (no shell, no curl in the image).
        [mode @ ("--readyz" | "--livez")] => {
            let path = if *mode == "--readyz" {
                "/readyz"
            } else {
                "/livez"
            };
            probe_http(
                BIND_ADDR_KEY,
                std::env::var(BIND_ADDR_KEY).ok().as_deref(),
                path,
            )
        }
        [] => {
            eprintln!("{}", start_line(BIN, "serve", VERSION, GIT_SHA));
            // ADR-0066 D-N: a configuration error is an operator's to fix (2); anything after it is runtime (1).
            let bootstrap = match GatewayBootstrap::load_from_env() {
                Ok(bootstrap) => bootstrap,
                Err(error) => {
                    eprintln!("{BIN}: {error}");
                    return ExitCode::from(2);
                }
            };
            match serve(bootstrap).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("{BIN}: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!("{BIN}: {}", usage());
            ExitCode::from(2)
        }
    }
}

async fn serve(bootstrap: GatewayBootstrap) -> Result<(), Box<dyn Error>> {
    let started = std::time::SystemTime::now();
    let mut runtime = bootstrap.build().await?;
    let refresh = runtime.readiness_refresh();
    let probe = runtime
        .take_readiness_probe()
        .ok_or("readiness probe already taken")?;
    // ADR-0061 D-F: the first snapshot exists before anything accepts, so there is no "unknown".
    let readiness = Arc::new(Readiness::new(probe.check(refresh).await, refresh));
    readiness.spawn_refresh(probe);

    let (guard, for_status, config) = (
        runtime.guard(),
        Arc::clone(&readiness),
        runtime.effective_config().clone(),
    );
    // dep: HTTP(loopback) — the ops listener serving /metrics and /status (ADR-0061 D-B)
    let ops = serve_loopback(
        METRICS_ADDR_KEY,
        runtime.metrics_addr(),
        Routes {
            metrics: Box::new(move || Ok(render_metrics(guard.metrics()))),
            status: Box::new(move || Ok(for_status.status_json(started, &config))),
        },
    )?;
    let listener = tokio::net::TcpListener::bind(runtime.bind_addr()).await?;
    // ADR-0125: the /auth/* pages, when the switch is on, join the MCP router so admission wraps both.
    let mut mcp = runtime.adapter().router();
    if let Some(config) = runtime.take_auth_pages() {
        mcp = mcp.merge(auth_pages::router(runtime.guard(), config));
        if let Some(config) = runtime.take_oauth_http() {
            mcp = mcp.merge(oauth_http::router(runtime.guard(), config));
        }
    }
    // ADR-0065 D-C: admission wraps the MCP router only; /livez and /readyz are merged outside it.
    let app = billing_webhook::compose(
        mcp,
        supervision_routes(readiness.clone()),
        runtime.admission(),
        runtime.guard(),
        runtime.take_billing_webhook(),
    );

    // Both handlers are installed before `axum::serve` exists: `tokio::signal::ctrl_c()` only
    // registers SIGINT on the shutdown future's first poll (inside `serve`), so a Ctrl-C landing
    // before that poll would hit SIGINT's default disposition and kill the process undrained.
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    #[cfg(unix)]
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let shutdown = async move {
        #[cfg(unix)]
        tokio::select! {
            _ = interrupt.recv() => {},
            _ = terminate.recv() => {},
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
        // Readiness goes false FIRST, and the accept loop stays open for `DRAIN_ANNOUNCE_WINDOW`
        // afterwards. Returning from this future is what stops axum accepting, so without the
        // wait the two events are simultaneous and a supervisor that opens a new connection per
        // poll (the k8s `readinessProbe.httpGet` this route is written for) could only ever get
        // ECONNREFUSED — never the 503 that says "draining, do not restart me".
        readiness.stop_accepting();
        eprintln!(
            "humaux-gateway: signal received, /readyz now 503, accepting for {}s more",
            DRAIN_ANNOUNCE_WINDOW.as_secs()
        );
        tokio::time::sleep(DRAIN_ANNOUNCE_WINDOW).await;
        // ADR-0061 D-B: metrics stay scrapable through the drain, so the drain itself is visible.
        drop(ops);
        eprintln!("humaux-gateway: drain window elapsed, closing the accept loop");
    };

    eprintln!(
        "humaux-gateway listening on {} ops={} config_fingerprint={}",
        listener.local_addr()?,
        runtime.metrics_addr(),
        runtime.config_fingerprint()
    );
    tokio::select! {
        result = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(shutdown).into_future() => { result?; },
        result = runtime.watch_session_lock() => { result.map_err(|code| std::io::Error::other(code.as_str()))?; },
    }
    Ok(())
}
