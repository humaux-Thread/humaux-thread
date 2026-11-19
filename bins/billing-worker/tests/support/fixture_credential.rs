//! `billing-worker::tests::support::fixture_credential` — public credential fixtures.
//! Depends-on: crates=[async-trait, humaux-domain, humaux-infra-egress]; services=[]; env=[]; modules=[domain::error, infra-egress::http]
//! Called-by: [billing-worker::tests::cancel, billing-worker::tests::fetch, billing-worker::tests::process]
//! Invariants: [test assembly only; no environment access]
//! Spec: Baseline §79.4
use humaux_domain::error::ErrorCode;
use humaux_infra_egress::http::{EgressSecret, RetrievalCredentialSource};

/// §79.4: injectable test source, never reads a real key.
pub struct FixtureCredential(
    /// §79.4: public fixture material only.
    pub &'static str,
);
#[async_trait::async_trait]
impl RetrievalCredentialSource for FixtureCredential {
    async fn credential(&self) -> Result<EgressSecret, ErrorCode> {
        Ok(EgressSecret::new(self.0.into()))
    }
}
