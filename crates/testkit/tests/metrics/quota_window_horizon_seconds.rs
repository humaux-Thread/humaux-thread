// witness: family=quota_window_horizon_seconds labels=-
//! `testkit::tests::metrics::quota_window_horizon_seconds` — Metric Witness for `quota_window_horizon_seconds` (§80.2
//!   W-side; registry row §41.2 「QUOTA_RENEWAL 任务每次租户门调用收尾 · 1」; consumer §42 QuotaWindowRenewalMissing).
//! Depends-on: crates=[humaux-domain]; services=[]; env=[]; modules=[adapters::quota_repo, domain::ids]
//! Called-by: []
//! Invariants: [drives the family's one `.set()` (`quota_repo::record_quota_window_horizon`, called by
//!   `quota_repo::renew_period` after each committed QUOTA_RENEWAL tenant call) and asserts the sample is the smallest recorded
//!   horizon minus the render time; a `None` horizon drops that tenant; nothing recorded means no sample]
//! Spec: Baseline §41.2; §42; §80.2; ADR-0072 D-D
//!
//! The horizon `quota_repo::renew_period` records is asserted equal to the successor window's end against PostgreSQL
//! by `crates/adapters/tests/quota_and_rate.rs` (`quota_window_renews_before_period_end`), and the daemon's `/metrics`
//! sample by `bins/maintenance/tests/serve.rs` (`quota_renewal_publishes_the_horizon_gauge`). Compiled and run
//! standalone by `cargo xtask metrics-registry` (`run_witness_probe`).

use humaux_adapters::quota_repo::{quota_window_horizon_seconds, record_quota_window_horizon};
use humaux_domain::ids::TenantId;

/// The sample is the renewing tenant closest to its last window end, measured at render time; a tenant that stops
/// renewing leaves the family, and an empty family has no sample (never a made-up 0 that would fire the alert).
#[test]
fn smallest_horizon_minus_now_and_dropped_tenants_leave() {
    let (near, far) = (TenantId::new(), TenantId::new());
    assert_eq!(quota_window_horizon_seconds(1_000), None);
    record_quota_window_horizon(far, Some(9_000));
    record_quota_window_horizon(near, Some(5_000));
    assert_eq!(quota_window_horizon_seconds(1_000), Some(4_000));
    assert_eq!(quota_window_horizon_seconds(6_000), Some(-1_000), "past due reads negative");
    record_quota_window_horizon(near, None);
    assert_eq!(quota_window_horizon_seconds(1_000), Some(8_000));
    record_quota_window_horizon(far, None);
    assert_eq!(quota_window_horizon_seconds(1_000), None);
}
