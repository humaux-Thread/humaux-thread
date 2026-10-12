//! `humaux-maintenance` — the library half of `humaux-maintenance`: the routine operator ops moved out of xtask so a
//!   production node runs them from the release image with no toolchain (`migrate`, `rls-check`, `projection serve`,
//!   `member`), the shared manifest parser, and the `deploy-check` release-gate modes.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: [crate(xtask)]
//! Invariants: [xtask reaches these modules only through their `run` entry points and the shared consts/types; the
//!   `throwaway` test support compiles only for this crate's tests and the `test-support` feature]
//! Spec: Baseline §4.2; §46; §48.2; ADR-0066 D-Q, D-R
//!
//! ADR-0066 D-Q: one lib target beside `main.rs` (cargo auto-detects it), not a new crate — the moved code has
//! exactly two callers, this binary and xtask's thin delegations.

pub mod deploy_check;
pub mod member;
pub mod migrate;
pub mod migration_manifest;
pub mod projection_serve;
pub mod rls_check;
pub mod switch_visible;
#[cfg(any(test, feature = "test-support"))]
pub mod throwaway;
