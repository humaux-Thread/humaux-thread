//! `billing-worker::tests::mode_gate` — startup and destination contract (§71.2).
//! Depends-on: crates=[]; services=[subprocess(humaux-billing-worker)];
//!   env=[CARGO_BIN_EXE_humaux-billing-worker, HUMAUX_BILLING_PROVIDER_MODE, HUMAUX_BILLING_CREEM_TEST_BASE_URL]; modules=[billing-worker::mode]
//! Called-by: [cargo-test]
//! Invariants: [child environments are isolated; no network or credentials]
//! Spec: Baseline §71.2; §79

use humaux_billing_worker::mode::BillingMode;

fn start(mode: Option<&str>, base: Option<&str>) -> std::process::Output {
    // dep: subprocess(humaux-billing-worker) — §71.2 isolated startup environment
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_humaux-billing-worker"));
    command.env_clear();
    if let Some(mode) = mode {
        command.env("HUMAUX_BILLING_PROVIDER_MODE", mode);
    }
    if let Some(base) = base {
        command.env("HUMAUX_BILLING_CREEM_TEST_BASE_URL", base);
    }
    command.output().unwrap()
}

#[test]
fn unset_mode_is_refused_and_names_variable() {
    let output = start(None, None);
    assert_eq!(output.status.code(), Some(1), "unset mode must be refused");
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "HUMAUX_BILLING_PROVIDER_MODE must be fake or test"
    );
}

#[test]
fn explicit_modes_and_destination_sets() {
    for mode in ["live", "other", "", "FAKE"] {
        assert_eq!(start(Some(mode), None).status.code(), Some(1));
    }
    assert_eq!(start(Some("test"), None).status.code(), Some(1));
    for base in [
        "https://api.creem.io",
        "http://test-api.creem.io",
        "https://other.invalid",
    ] {
        assert_eq!(start(Some("test"), Some(base)).status.code(), Some(1));
    }
    for (name, base, hosts) in [
        ("fake", None, vec!["127.0.0.1"]),
        (
            "test",
            Some("https://test-api.creem.io"),
            vec!["test-api.creem.io"],
        ),
    ] {
        let output = start(Some(name), base);
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, format!("{name}\n").as_bytes());
        let mode = BillingMode::parse(Some(name), base).unwrap();
        assert_eq!(
            mode.allowed_hosts(Some("http://127.0.0.1:1234")).unwrap(),
            hosts
        );
    }
    let fake = BillingMode::parse(Some("fake"), None).unwrap();
    for base in [
        None,
        Some("https://api.creem.io"),
        Some("http://other.invalid"),
        Some("http://127.0.0.2:1234"),
    ] {
        assert_eq!(
            fake.allowed_hosts(base).err().as_deref(),
            Some("fake billing requires an explicit loopback base URL")
        );
    }
    for (base, host) in [
        ("http://localhost:1234", "localhost"),
        ("http://[::1]:1234", "[::1]"),
    ] {
        assert_eq!(fake.allowed_hosts(Some(base)).unwrap(), vec![host]);
    }
    let test = BillingMode::parse(Some("test"), Some("https://test-api.creem.io/")).unwrap();
    assert_eq!(test.allowed_hosts(None).unwrap(), vec!["test-api.creem.io"]);
}
