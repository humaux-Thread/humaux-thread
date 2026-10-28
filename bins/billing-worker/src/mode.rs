//! `billing-worker::mode` — fail-closed non-live startup (§71.2).
//! Depends-on: crates=[]; services=[];
//!   env=[HUMAUX_BILLING_PROVIDER_MODE, HUMAUX_BILLING_CREEM_TEST_BASE_URL]; modules=[]
//! Called-by: [billing-worker::main, tests]
//! Invariants: [no implicit mode; production host refused; fake destinations supplied explicitly]
//! Spec: Baseline §71.2; §78.1

/// §71.2: startup configuration cannot represent live billing.
pub struct BillingMode {
    name: &'static str,
}

impl BillingMode {
    /// §71.2: the process environment is authoritative; neither variable has a default.
    pub fn from_env() -> Result<Self, String> {
        Self::parse(
            std::env::var("HUMAUX_BILLING_PROVIDER_MODE")
                .ok()
                .as_deref(),
            std::env::var("HUMAUX_BILLING_CREEM_TEST_BASE_URL")
                .ok()
                .as_deref(),
        )
    }

    /// §71.2: only the test API origin is valid for test mode.
    pub fn parse(mode: Option<&str>, test_base_url: Option<&str>) -> Result<Self, String> {
        let name = match mode {
            Some("fake") => "fake",
            Some("test") => "test",
            _ => return Err("HUMAUX_BILLING_PROVIDER_MODE must be fake or test".into()),
        };
        if name == "test" && test_base_url != Some("https://test-api.creem.io") {
            return Err("HUMAUX_BILLING_CREEM_TEST_BASE_URL must use the test API origin".into());
        }
        Ok(Self { name })
    }

    /// §71.2: startup output exposes the mode name alone.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// §71.2: fake destinations have no default and must be loopback HTTP doubles.
    pub fn allowed_hosts(&self, fake_base_url: Option<&str>) -> Result<Vec<String>, String> {
        if self.name == "test" {
            return Ok(vec!["test-api.creem.io".into()]);
        }
        // §71.2: fake doubles use explicit IPv4 socket addresses, never DNS or userinfo.
        let authority = fake_base_url
            .and_then(|s| s.strip_prefix("http://"))
            .and_then(|s| s.split('/').next())
            .unwrap_or("");
        let addr = authority
            .parse::<std::net::SocketAddrV4>()
            .map_err(|_| "fake billing requires an explicit loopback base URL")?;
        if !addr.ip().is_loopback() {
            return Err("fake billing requires an explicit loopback base URL".into());
        }
        Ok(vec![addr.ip().to_string()])
    }
}
