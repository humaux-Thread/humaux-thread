//! `xtask::member` — `cargo xtask member`: a thin delegation to `humaux_maintenance::member` (ADR-0066 D-Q).
//! Depends-on: crates=[humaux-maintenance]; services=[]; env=[]; modules=[maintenance::member]
//! Called-by: [xtask::main]
//! Invariants: [same subcommands, flags and `HUMAUX_MAINTENANCE_PG_DSN` principal as `humaux-maintenance member`]
//! Spec: Baseline §6.3; ADR-0066 D-Q

/// `cargo xtask member <invite|activate|suspend|remove|set-role> <flags>`.
pub fn run(args: &[String]) -> i32 {
    humaux_maintenance::member::run(args)
}
