//! `private-worker::tests::support::distill_lane` — the key-free Distill harness the private-worker E2E tests share:
//!   the R3 admission lane seed for `PRIVATE_DISTILL_TEXT`, the canned-reply `FakeProvider`, its route map and the
//!   dispatch config.
//! Depends-on: crates=[async-trait, humaux-adapters, humaux-testkit, postgres, uuid];
//!   services=[PostgreSQL(owner) r=[control.processor_models] w=[control.credentials, control.processor_models,
//!   control.provider_accounts, control.provider_endpoints, control.reasoning_credential_bindings,
//!   control.reasoning_profiles, control.reasoning_route_bindings, control.reasoning_route_candidates,
//!   control.reasoning_route_policies, ops.reasoning_account_health_observations,
//!   ops.reasoning_provider_health_observations]]; env=[]; modules=[adapters::byok, adapters::contribution_reasoner,
//!   adapters::disclosure, adapters::jobs, adapters::reasoning_route_admission, private-worker::distill,
//!   private-worker::tests::support::live_minimax, humaux-testkit]
//! Called-by: [humaux-private-worker, private-worker::distill_stale_tests, private-worker::tests::distill_hop_e2e, private-worker::tests::m29_attribution_e2e]
//! Invariants: [test-only, included by #[path] next to `support/live_minimax.rs`; the provider answers in call order
//!   and panics past its last reply, so an unexpected extra call is never silent; the lane matches the descriptor
//!   exactly, as `provider_matches_admission` requires]
//! Spec: ADR-0058; ADR-0059 D-D; ADR-0060
//!
//! Moved out of `distill_hop_e2e.rs` (M29 T07) so a second test drives the same lane and provider instead of a copy.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use humaux_adapters::byok::{
    PrivateInferenceContext, ReasoningProviderDescriptor, ReasoningProviderError,
    StructuredReasoningRequest, StructuredReasoningResponse, TokenUsage, UserReasoningProvider,
    VisionReasoningRequest, VisionReasoningResponse,
};
use humaux_adapters::contribution_reasoner::ContributionReasonerConfig;
use humaux_adapters::disclosure::DeletionCapability;
use humaux_adapters::jobs;
use humaux_adapters::reasoning_route_admission::ReasoningAdmissionLocator;
use humaux_private_worker::distill::DistillDispatchConfig;
use postgres::Client;
use uuid::Uuid;

use crate::live_minimax::{MINIMAX_CHAT_URL, descriptor};

/// The egress processor every seeded endpoint names; [`routes`] serves only it.
pub const EGRESS_PROCESSOR_ID: Uuid = Uuid::from_u128(0x2016);
/// The seeded endpoint's processing region.
pub const REGION: &str = "cn-shanghai";
/// The seeded endpoint's service tier.
pub const SERVICE_TIER: &str = "standard";
/// The route purpose Distill admits under.
pub const PURPOSE_DB: &str = "PRIVATE_DISTILL_TEXT";
/// ADR-0058 D-T: a §72.3 budget no test in this file reaches (the budget gate has its own test,
/// distill_dispatch_v2 T21).
pub const TEST_BUDGET: jobs::DistillCallBudget = jobs::DistillCallBudget {
    window_seconds: 60.0,
    max_calls: 10_000,
};

/// A real login DSN for `role` on the admin DSN's database.
pub fn dsn_as_role(admin_dsn: &str, role: &str) -> String {
    // ADR-0059 D-D: a real login as `role`, its password from HUMAUX_ROLE_PASSWORD_<SUFFIX>.
    humaux_testkit::role_login_dsn(admin_dsn, role, |name| std::env::var(name).ok())
        .unwrap_or_else(|missing| panic!("missing object: {missing} (ADR-0059 D-D)"))
}

/// ADR-0060 D-B: every admitted route goes to `provider`, unless its recipient is not this
/// deployment's (the deny-only check the private worker's route mapping holds, §11.2.5).
pub fn routes<P: UserReasoningProvider + 'static>(
    provider: &Arc<P>,
) -> impl Fn(&ReasoningAdmissionLocator) -> Result<Arc<dyn UserReasoningProvider>, &'static str>
+ Send
+ Sync
+ use<P> {
    let provider = Arc::clone(provider);
    move |route| {
        if route.egress_processor_id.0 == EGRESS_PROCESSOR_ID {
            Ok(Arc::clone(&provider) as Arc<dyn UserReasoningProvider>)
        } else {
            Err("EGRESS_PROCESSOR_NOT_ALLOWED")
        }
    }
}

/// The reasoner config the dispatcher takes (Distill ignores its prompt fields).
pub fn contribution_config() -> ContributionReasonerConfig {
    ContributionReasonerConfig {
        permit_ttl: Duration::from_secs(30),
        deletion_capability: DeletionCapability::Unknown,
        // Contribution-path prompt config only; Distill takes prompt/schema/budget from
        // `distill_prompt_contract()` and ignores these three.
        system_prompt: "s".to_string(),
        json_schema: "{}".to_string(),
        max_output_tokens: 64,
    }
}

/// exactly (`provider_matches_admission` compares provider id / model / revision / endpoint).
/// A reply string starting with this prefix is returned as a provider `RetryWait` (429/5xx)
/// instead of a body.
pub const FAKE_RETRY_WAIT: &str = "ERR:retry_wait";

pub struct FakeProvider {
    descriptor: ReasoningProviderDescriptor,
    replies: Mutex<Vec<String>>,
    calls: Mutex<u32>,
    /// The `json_schema` of every request, in call order (the rendered menu the model saw).
    schemas: Mutex<Vec<String>>,
}

impl FakeProvider {
    pub fn new(replies: Vec<&str>) -> Arc<Self> {
        Arc::new(Self {
            descriptor: descriptor(),
            replies: Mutex::new(replies.into_iter().rev().map(str::to_owned).collect()),
            calls: Mutex::new(0),
            schemas: Mutex::new(Vec::new()),
        })
    }

    pub fn calls(&self) -> u32 {
        *self.calls.lock().expect("calls")
    }

    pub fn schemas(&self) -> Vec<String> {
        self.schemas.lock().expect("schemas").clone()
    }
}

#[async_trait]
impl UserReasoningProvider for FakeProvider {
    fn descriptor(&self) -> &ReasoningProviderDescriptor {
        &self.descriptor
    }

    fn endpoint_ref(&self) -> &str {
        MINIMAX_CHAT_URL
    }

    fn model_revision(&self) -> Option<&str> {
        self.descriptor.model_revision.as_deref()
    }

    async fn complete_structured(
        &self,
        _context: &PrivateInferenceContext,
        request: StructuredReasoningRequest,
    ) -> Result<StructuredReasoningResponse, ReasoningProviderError> {
        *self.calls.lock().expect("calls") += 1;
        self.schemas
            .lock()
            .expect("schemas")
            .push(request.json_schema);
        let json = self
            .replies
            .lock()
            .expect("replies")
            .pop()
            .expect("fake provider has a reply for every call");
        if json == FAKE_RETRY_WAIT {
            return Err(ReasoningProviderError::RetryWait { retry_after: None });
        }
        Ok(StructuredReasoningResponse {
            json,
            usage: TokenUsage::default(),
            channel_fallback: false,
        })
    }

    async fn analyze_vision(
        &self,
        _context: &PrivateInferenceContext,
        _request: VisionReasoningRequest,
    ) -> Result<VisionReasoningResponse, ReasoningProviderError> {
        unreachable!("distill never calls vision")
    }
}

/// ADR-0058 D-K config with one seat (the fake provider serves replies in call order).
pub fn dispatch_config(lease_owner: &str, lease_seconds: f64) -> DistillDispatchConfig {
    DistillDispatchConfig {
        lease_owner: lease_owner.to_owned(),
        lease_seconds,
        in_flight: 1,
        hard_deadline_seconds: 2.0 * (5.0 + lease_seconds),
        http_timeout_seconds: 5.0,
        not_ready_park_seconds: 600.0,
        max_attempts: 5,
        budget: TEST_BUDGET,
        health_renew_seconds: 1800,
        dns_pins_configured: false,
    }
}

/// Seeds the full R3 admission lane for `PRIVATE_DISTILL_TEXT` over the MiniMax descriptor in `tenant_id`, owned by
/// `user_id` and bound to `reasoning_domain_id` (mirrors consolidation_hop_e2e::setup_db); `label` names the
/// credential locator.
#[allow(clippy::too_many_lines)] // one linear owner-role seed of the lane
pub fn seed_admission_lane(
    admin: &mut Client,
    tenant_id: Uuid,
    user_id: Uuid,
    reasoning_domain_id: Uuid,
    label: &str,
) {
    let suffix = Uuid::now_v7();
    let credential: Uuid = admin
        .query_one(
            "INSERT INTO control.credentials(tenant_id,purpose,openbao_ref) VALUES($1,'USER_REASONING',$2) RETURNING credential_id",
            &[&tenant_id, &format!("openbao://{label}/{suffix}")],
        )
        .expect("credential locator")
        .get(0);
    let d = descriptor();
    // ADR-0060 D-C / E5: catalog row, Profile and provider declare one capability set; the
    // descriptor's revision is that set's label, so it never meets the frozen NULL-revision row.
    let caps: Vec<&str> = d.capabilities.iter().map(|c| c.as_str()).collect();
    admin
        .execute(
            "INSERT INTO control.processor_models(processor_id,provider_model_id,model_revision,capabilities,status,catalog_observed_at) \
             VALUES($1,$2,$3,$4,'ACTIVE',clock_timestamp()) ON CONFLICT DO NOTHING",
            &[&d.provider_id, &d.model_id, &d.model_revision, &caps],
        )
        .expect("processor model");
    let processor_model_id: Uuid = admin
        .query_one(
            "SELECT processor_model_id FROM control.processor_models \
             WHERE processor_id=$1 AND provider_model_id=$2 AND model_revision IS NOT DISTINCT FROM $3 AND status='ACTIVE'",
            &[&d.provider_id, &d.model_id, &d.model_revision],
        )
        .expect("processor model id")
        .get(0);
    let account_hash = suffix.as_bytes().repeat(2);
    let account: Uuid = admin
        .query_one(
            "INSERT INTO control.provider_accounts(tenant_id,owner_user_id,processor_id,external_account_ref_hash) VALUES($1,$2,$3,$4) RETURNING provider_account_id",
            &[&tenant_id, &user_id, &d.provider_id, &account_hash],
        )
        .expect("provider account")
        .get(0);
    admin
        .execute(
            "INSERT INTO control.reasoning_credential_bindings(credential_ref,tenant_id,owner_user_id,provider_account_id,processor_id) VALUES($1,$2,$3,$4,$5)",
            &[&credential, &tenant_id, &user_id, &account, &d.provider_id],
        )
        .expect("credential binding");
    let endpoint: Uuid = admin
        .query_one(
            "INSERT INTO control.provider_endpoints(tenant_id,provider_account_id,region,service_tier,endpoint_ref,egress_processor_id) VALUES($1,$2,$3,$4,$5,$6) RETURNING endpoint_id",
            &[&tenant_id, &account, &REGION, &SERVICE_TIER, &MINIMAX_CHAT_URL, &EGRESS_PROCESSOR_ID],
        )
        .expect("provider endpoint")
        .get(0);
    let profile: Uuid = admin
        .query_one(
            "INSERT INTO control.reasoning_profiles(tenant_id,owner_user_id,provider_account_id,endpoint_id,processor_model_id,credential_ref,billing_account_id,default_billing_instrument_id,capabilities,processing_region) VALUES($1,$2,$3,$4,$5,$6,NULL,NULL,$8,$7) RETURNING profile_id",
            &[&tenant_id, &user_id, &account, &endpoint, &processor_model_id, &credential, &REGION, &caps],
        )
        .expect("reasoning profile")
        .get(0);
    let policy: Uuid = admin
        .query_one(
            "INSERT INTO control.reasoning_route_policies(tenant_id,policy_owner_user_id,purpose) VALUES($1,$2,$3) RETURNING route_policy_id",
            &[&tenant_id, &user_id, &PURPOSE_DB],
        )
        .expect("route policy")
        .get(0);
    admin
        .execute(
            "INSERT INTO control.reasoning_route_candidates(tenant_id,route_policy_id,route_policy_version,profile_id,profile_version,priority) VALUES($1,$2,1,$3,1,0)",
            &[&tenant_id, &policy, &profile],
        )
        .expect("pinned candidate");
    admin
        .execute(
            "UPDATE control.reasoning_route_policies SET lifecycle_state='SHADOW' WHERE route_policy_id=$1 AND policy_version=1",
            &[&policy],
        )
        .expect("shadow policy");
    admin
        .execute(
            "UPDATE control.reasoning_route_policies SET lifecycle_state='SERVING' WHERE route_policy_id=$1 AND policy_version=1",
            &[&policy],
        )
        .expect("serving policy");
    admin
        .execute(
            "INSERT INTO control.reasoning_route_bindings(tenant_id,reasoning_domain_id,purpose,route_policy_id,route_policy_version) VALUES($1,$2,$3,$4,1)",
            &[&tenant_id, &reasoning_domain_id, &PURPOSE_DB, &policy],
        )
        .expect("route binding");
    admin
        .execute(
            "INSERT INTO ops.reasoning_provider_health_observations(tenant_id,processor_id,processor_model_id,provider_model_id,model_revision,provider_endpoint_id,endpoint_ref,region,service_tier,source_kind,reason_code,verdict,observed_at,valid_until) \
             VALUES($1,$2,$3,$4,$9,$5,$6,$7,$8,'TEST',NULL,'HEALTHY',clock_timestamp()-interval '1 second',clock_timestamp()+interval '30 minutes')",
            &[&tenant_id, &d.provider_id, &processor_model_id, &d.model_id, &endpoint, &MINIMAX_CHAT_URL, &REGION, &SERVICE_TIER, &d.model_revision],
        )
        .expect("provider health observation");
    admin
        .execute(
            "INSERT INTO ops.reasoning_account_health_observations(tenant_id,provider_account_id,credential_ref,billing_account_id,billing_instrument_id,source_kind,reason_code,account_verdict,credential_verdict,billing_account_verdict,billing_instrument_verdict,observed_at,valid_until) \
             VALUES($1,$2,$3,NULL,NULL,'TEST',NULL,'HEALTHY','VALID',NULL,NULL,clock_timestamp()-interval '1 second',clock_timestamp()+interval '30 minutes')",
            &[&tenant_id, &account, &credential],
        )
        .expect("account health observation");
}
