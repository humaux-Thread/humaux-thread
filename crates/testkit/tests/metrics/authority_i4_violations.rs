// witness: family=authority_i4_violations labels=-
//! `testkit::tests::metrics::authority_i4_violations` — Metric Witness for `authority_i4_violations` (§80.2 W-side;
//!   registry row §41.2 「§65 `authority superseded_by consistency scan` 收尾 `.set()` · 1」; consumer §42
//!   AuthorityI4Violation).
//! Depends-on: crates=[]; services=[]; env=[]; modules=[adapters::maintenance_repo]
//! Called-by: []
//! Invariants: [drives the family's one `.set()` (`maintenance_repo::set_authority_i4_violations`, called by
//!   `maintenance::serve` once at the end of each successful AUTHORITY_I4 run) and asserts the exact value, 0 included;
//!   drives the reset and asserts the family has no value at all afterwards, never 0 or the last count]
//! Spec: Baseline §41.2; §42; §65; §80.2; ADR-0123 D3
//!
//! The real scan's counts (0 on a compliant fixture, 1 after the CHECK is dropped and a violating row is inserted) are
//! asserted against PostgreSQL by `bins/maintenance/tests/i4_scan.rs`. Compiled and run standalone by
//! `cargo xtask metrics-registry` (`run_witness_probe`).

use humaux_adapters::maintenance_repo::{
    authority_i4_violations, reset_authority_i4_violations, set_authority_i4_violations,
};

/// A set publishes the exact count (a clean scan is a real 0); a reset removes the sample, so a failed scan is never
/// read as clean (§41.2: absent, not 0).
#[test]
fn set_publishes_the_count_and_reset_removes_the_sample() {
    assert_eq!(authority_i4_violations(), None, "no sample before the first run");
    set_authority_i4_violations(0);
    assert_eq!(authority_i4_violations(), Some(0));
    set_authority_i4_violations(3);
    assert_eq!(authority_i4_violations(), Some(3));
    reset_authority_i4_violations();
    assert_eq!(authority_i4_violations(), None, "a failed run renders no sample");
}
