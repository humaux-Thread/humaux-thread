// witness: family=dns_pin_deferred_total labels=-
//! `testkit::tests::metrics::dns_pin_deferred_total` — Metric Witness for `dns_pin_deferred_total`
//!   (§80.2 W-side; registry row §41.2 「§11.4 distill RETRY settle with class TRANSPORT while a DNS pin is configured
//!   · 1」; consumer §42 DnsPinDeferred).
//! Depends-on: crates=[humaux-telemetry]; services=[]; env=[]; modules=[telemetry::metrics]
//! Called-by: []
//! Invariants: [drives the family's one emit (`telemetry::metrics::count_dns_pin_deferred`, called by
//!   `private-worker::distill` only for a TRANSPORT retry while a pin is configured) and asserts the exact delta and the
//!   rendered sample, never mere presence]
//! Spec: Baseline §41.2; §42; §80.2; ADR-0061 D-A; ADR-0066 D-P
//!
//! The encoder seeds a never-incremented counter at 0 (ADR-0061 D-A), so presence proves nothing: this asserts the
//! increment. The pin condition itself is proven by `private-worker distill::tests::transport_retry_with_pins_counts_
//! dns_pin_deferred` and its `no_pins_no_count` twin. Compiled and run standalone by `cargo xtask metrics-registry`
//! (`run_witness_probe`).

use humaux_telemetry::metrics::{
    count_dns_pin_deferred, dns_pin_deferred_total, families, write_family,
};

/// One deferral adds exactly 1, and the exposition the private worker renders carries the unlabelled sample.
#[test]
fn each_deferral_adds_exactly_one_and_renders() {
    let before = dns_pin_deferred_total();
    count_dns_pin_deferred();
    assert_eq!(
        dns_pin_deferred_total(),
        before + 1,
        "dns_pin_deferred_total must grow by one per TRANSPORT deferral under a pin (§41.2, ADR-0066 D-P)"
    );
    let mut out = String::new();
    #[expect(
        clippy::cast_precision_loss,
        reason = "a process-local deferral count stays far below 2^52"
    )]
    let value = dns_pin_deferred_total() as f64;
    write_family(&mut out, &families::DNS_PIN_DEFERRED_TOTAL, &[(&[], value)]);
    assert!(out.contains("# TYPE dns_pin_deferred_total counter\n"), "{out}");
    let line = out
        .lines()
        .find(|l| l.starts_with("dns_pin_deferred_total "))
        .unwrap_or_else(|| panic!("no unlabelled dns_pin_deferred_total sample in {out}"));
    let sample: f64 = line.rsplit(' ').next().and_then(|v| v.parse().ok()).expect("a sample value");
    assert!(sample >= 1.0, "{line}");
}
