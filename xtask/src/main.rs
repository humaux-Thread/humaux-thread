//! `xtask::main` — cargo xtask entry point: dispatches every gate subcommand.
//! Depends-on: crates=[humaux-telemetry]; services=[]; env=[CARGO_BIN_NAME, CARGO_PKG_VERSION, HUMAUX_BUILD_GIT_SHA, HUMAUX_BUILD_TIME]; modules=[humaux-telemetry, xtask::architecture_check, xtask::benchset_declaration, xtask::card_version, xtask::config_check, xtask::contract_impact, xtask::dep_map, xtask::direction_table, xtask::dod_check, xtask::e2e_onboard, xtask::e2e_seed, xtask::gate_registry, xtask::gate_truth, xtask::known_red, xtask::load, xtask::load_open, xtask::mechanism_registry, xtask::member, xtask::metrics_registry, xtask::migrate, xtask::migration_rehearsal, xtask::phase, xtask::projection_serve, xtask::r4_fault_manifest, xtask::rls_check, xtask::schedule_register, xtask::serial_lane, xtask::soak, xtask::threshold_shape]
//! Called-by: [process(cargo-xtask)]
//! Invariants: [unknown subcommand exits 2 with the usage string; `--version` is the shared telemetry line (first token `xtask`); every subcommand module is registered in both mod list and dispatch match]
//! Spec: Baseline §78; ADR-0051
//!
//! `cargo xtask` — 工程门禁统一入口（§78：复杂 gate 不散落 bash，走 xtask）。
//!
//! 子命令与闸的对应：architecture-check(G80-1/2/3/22…) · mechanism-registry(G80-10)
//! · migration-rehearsal(G80-37) · metrics-registry(G80-6) · contract-impact(G80-42)
//! · config-check(G80-41) · rls-check(§48.2) · gate-truth(§79.2, ADR-0050 D-C) · dep-map(ADR-0051) · deploy-env(ADR-0066 D-R (a), §78.1)。判据正文以家章为唯一真源。

mod architecture_check;
mod benchset_declaration;
mod card_version;
mod config_check;
mod contract_impact;
mod dep_map;
mod direction_table;
mod dod_check;
mod e2e_onboard;
mod e2e_seed;
mod gate_registry;
mod gate_truth;
mod known_red;
mod load;
mod load_open;
mod mechanism_registry;
mod member;
mod metrics_registry;
mod migrate;
mod migration_rehearsal;
mod phase;
mod projection_serve;
mod r4_fault_manifest;
mod rls_check;
mod schedule_register;
mod serial_lane;
mod soak;
mod threshold_shape;

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    // ADR-0066 D-S / D-R: the loadgen image's entrypoint is this binary, and `deploy-check --release` compares the
    // first token and the sha of its `--version` line with the release manifest (`binary=xtask`), exactly as for
    // every other image (review P1, 2026-10-08: without this arm R2 stopped on the A5 node).
    if args.len() == 2 && args[1] == "--version" {
        return humaux_telemetry::version_mode(
            env!("CARGO_BIN_NAME"),
            env!("CARGO_PKG_VERSION"),
            option_env!("HUMAUX_BUILD_GIT_SHA"),
            option_env!("HUMAUX_BUILD_TIME"),
        );
    }
    let code = match args.get(1).map(String::as_str) {
        Some("architecture-check") => architecture_check::run(&args[2..]),
        Some("mechanism-registry") => mechanism_registry::run(&args[2..]),
        Some("migration-rehearsal") => migration_rehearsal::run(&args[2..]),
        Some("metrics-registry") => metrics_registry::run(&args[2..]),
        Some("contract-impact") => contract_impact::run(&args[2..]),
        Some("config-check") => config_check::run(&args[2..]),
        Some("rls-check") => rls_check::run(&args[2..]),
        Some("schedule-register") => schedule_register::run(&args[2..]),
        Some("threshold-shape") => threshold_shape::run(&args[2..]),
        Some("benchset-declaration") => benchset_declaration::run(&args[2..]),
        Some("gate-registry") => gate_registry::run(&args[2..]),
        Some("dod-check") => dod_check::run(&args[2..]),
        Some("phase-check") => phase::run(&args[2..]),
        Some("r4-fault-manifest") => r4_fault_manifest::run(&args[2..]),
        Some("direction-table") => direction_table::run(&args[2..]),
        Some("card-version") => card_version::run(&args[2..]),
        Some("migrate") => migrate::run(&args[2..]),
        Some("e2e-seed") => e2e_seed::run(&args[2..]),
        Some("e2e-onboard") => e2e_onboard::run(&args[2..]),
        Some("member") => member::run(&args[2..]),
        Some("projection-serve") => projection_serve::run(&args[2..]),
        Some("serial-lane") => serial_lane::run(&args[2..]),
        Some("soak") => soak::run(&args[2..]),
        Some("load") => load::run(&args[2..]),
        Some("load-open") => load_open::run(&args[2..]),
        Some("gate-truth") => gate_truth::run(&args[2..]),
        Some("known-red") => known_red::run(&args[2..]),
        Some("dep-map") => dep_map::run(&args[2..]),
        Some("deploy-env") => dep_map::run_deploy_env(&args[2..]),
        _ => {
            eprintln!(
                "usage: cargo xtask <architecture-check|mechanism-registry|migration-rehearsal|metrics-registry|contract-impact|config-check|rls-check|schedule-register|threshold-shape|benchset-declaration|gate-registry|dod-check|phase-check|r4-fault-manifest|direction-table|card-version|migrate|e2e-seed|e2e-onboard|member|projection-serve|serial-lane|soak|load|load-open|gate-truth|known-red|dep-map|deploy-env>"
            );
            2
        }
    };
    std::process::ExitCode::from(u8::try_from(code).unwrap_or(1))
}
