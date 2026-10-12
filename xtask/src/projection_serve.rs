//! `xtask::projection_serve` — `cargo xtask projection-serve`: a thin delegation to
//!   `humaux_maintenance::projection_serve` (ADR-0066 D-Q).
//! Depends-on: crates=[humaux-maintenance]; services=[]; env=[]; modules=[maintenance::projection_serve]
//! Called-by: [xtask::main]
//! Invariants: [same flags and the same `HUMAUX_MAINTENANCE_PG_DSN` principal as `humaux-maintenance projection serve`]
//! Spec: Baseline §16.2; ADR-0066 D-Q

/// `cargo xtask projection-serve <flags>`.
pub fn run(args: &[String]) -> i32 {
    humaux_maintenance::projection_serve::run(args)
}
