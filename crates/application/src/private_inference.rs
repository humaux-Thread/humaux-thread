//! `application::private_inference` — Private inference RPC lifecycle.
//! Depends-on: crates=[async-trait, tokio, uuid]; services=[]; env=[]; modules=[]
//! Called-by: [private-worker::inference_rpc, adapters::private_inference_rpc]
//! Invariants: [only a fresh claim executes; persistence stays in the PG adapter]
//! Spec: Baseline §11.8; ADR-0130 step 5

use async_trait::async_trait;
use uuid::Uuid;

/// A freshly claimed registration — every field the private worker needs to rebuild a
/// `SealedPrivateReasoningRequest` without trusting anything the RPC body itself asserted.
#[derive(Debug, Clone)]
pub struct ClaimedRegistration {
    pub tenant_id: Uuid,
    pub reasoning_domain_id: Uuid,
    pub binding_id: Uuid,
    pub binding_version: i64,
    pub purpose: String,
    pub input_manifest_hash: Vec<u8>,
    /// Persisted consolidation run identity; absent for other purposes.
    pub consolidation_run_id: Option<Uuid>,
}

/// A previously completed call's stored outcome, replayed verbatim on a duplicate `call_id`
/// (§11.8/ADR-0012 "idempotency by call_id" — zero provider calls on replay).
#[derive(Debug, Clone)]
pub struct StoredOutcome {
    pub outcome: String,
    pub response_output_bytes: Option<Vec<u8>>,
    pub response_output_sha256: Option<Vec<u8>>,
    pub response_provider_trace: Option<String>,
    pub response_model_call_id: Option<Uuid>,
    pub response_failure_message: Option<String>,
}

/// Private inference claim outcomes — mirrors
/// `retrieval_embedding_rpc::ClaimOutcome` one for one.
pub enum ClaimOutcome {
    NotFound,
    Expired,
    AlreadyClaimed,
    Replay(StoredOutcome),
    Claimed(ClaimedRegistration),
}

/// The outcome to persist once a claimed call has actually run.
pub enum FinishOutcome {
    Completed {
        output_bytes: Vec<u8>,
        output_sha256: [u8; 32],
        provider_trace: String,
        model_call_id: Uuid,
    },
    Failed {
        message: String,
    },
}

/// PG lifecycle boundary; each operation retains its original transaction.
#[async_trait]
pub trait PrivateInferenceCallsPort: Sync {
    /// Claims the authoritative registration, never trusting RPC fields as call data.
    async fn claim(&self, call_id: Uuid, tenant_hint: Uuid) -> Result<ClaimOutcome, String>;
    /// Persists the actual execution outcome.
    async fn finish(
        &self,
        call_id: Uuid,
        tenant_id: Uuid,
        outcome: FinishOutcome,
    ) -> Result<(), String>;
}

/// A worker execution and its persistence evidence.
pub struct InferenceExecution<T> {
    /// Transport response, kept opaque to application.
    pub response: T,
    /// Outcome persisted by the PG adapter.
    pub finish: FinishOutcome,
    /// Admitted static route fields for the existing finish log.
    pub route: Option<String>,
}

/// Existing purpose dispatch remains injected by the worker (SHARED-CONTRACT pending).
pub trait PrivateInferenceExecutionPort: Sync {
    /// Transport response produced by the worker.
    type Response: Send;
    /// Executes using only the claimed registration.
    fn infer(
        &self,
        call_id: Uuid,
        registration: &ClaimedRegistration,
    ) -> impl std::future::Future<Output = InferenceExecution<Self::Response>> + Send;
}

/// Lifecycle result; the transport owns its existing status/envelope mapping.
pub enum InferenceOutcome<T> {
    /// Missing or inaccessible call.
    NotFound,
    /// Expired registration.
    Expired,
    /// Another worker already claimed the call.
    Busy,
    /// Stored terminal response; no inference occurs.
    Replay(StoredOutcome),
    /// Fresh inference response, even when finish persistence fails (§11.8).
    Executed(T),
}

/// Runs the existing claim/execution/finish sequence without changing transaction boundaries.
pub async fn execute<P: PrivateInferenceCallsPort, E: PrivateInferenceExecutionPort>(
    calls: &P,
    executor: &E,
    call_id: Uuid,
    tenant_hint: Uuid,
) -> InferenceOutcome<E::Response> {
    let registration = match calls.claim(call_id, tenant_hint).await {
        Err(_) | Ok(ClaimOutcome::NotFound) => return InferenceOutcome::NotFound,
        Ok(ClaimOutcome::Expired) => return InferenceOutcome::Expired,
        Ok(ClaimOutcome::AlreadyClaimed) => return InferenceOutcome::Busy,
        Ok(ClaimOutcome::Replay(stored)) => return InferenceOutcome::Replay(stored),
        Ok(ClaimOutcome::Claimed(registration)) => registration,
    };
    let execution = executor.infer(call_id, &registration).await;
    let outcome = match &execution.finish {
        FinishOutcome::Completed { .. } => "COMPLETED",
        FinishOutcome::Failed { .. } => "FAILED",
    };
    if let Err(error) = calls
        .finish(call_id, registration.tenant_id, execution.finish)
        .await
    {
        eprintln!(
            "private_inference_rpc: finish() failed to persist call outcome for {call_id}: {error} (row stuck CLAIMED until TTL expiry)"
        );
    }
    eprintln!(
        "humaux-private-worker: rpc call={} tenant={} purpose={} {} outcome={}",
        call_id,
        registration.tenant_id,
        registration.purpose,
        execution.route.as_deref().unwrap_or("route=-"),
        outcome
    );
    InferenceOutcome::Executed(execution.response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Calls {
        claim: Mutex<Option<Result<ClaimOutcome, String>>>,
        events: Mutex<Vec<&'static str>>,
        finish_fails: bool,
    }
    #[async_trait]
    impl PrivateInferenceCallsPort for Calls {
        async fn claim(&self, _: Uuid, _: Uuid) -> Result<ClaimOutcome, String> {
            self.events.lock().unwrap().push("claim");
            self.claim.lock().unwrap().take().unwrap()
        }
        async fn finish(
            &self,
            _: Uuid,
            tenant: Uuid,
            outcome: FinishOutcome,
        ) -> Result<(), String> {
            assert_eq!(tenant, Uuid::from_u128(42));
            assert!(
                matches!(outcome, FinishOutcome::Failed { message } if message == "PROVIDER_ERROR")
            );
            self.events.lock().unwrap().push("finish");
            if self.finish_fails {
                Err("db unavailable".into())
            } else {
                Ok(())
            }
        }
    }
    struct Executor<'a>(&'a Calls);
    impl PrivateInferenceExecutionPort for Executor<'_> {
        type Response = &'static str;
        async fn infer(
            &self,
            _: Uuid,
            registration: &ClaimedRegistration,
        ) -> InferenceExecution<Self::Response> {
            assert_eq!(registration.tenant_id, Uuid::from_u128(42));
            assert_eq!(registration.purpose, "Distill");
            self.0.events.lock().unwrap().push("infer");
            InferenceExecution {
                response: "original response",
                finish: FinishOutcome::Failed {
                    message: "PROVIDER_ERROR".into(),
                },
                route: None,
            }
        }
    }
    fn calls(claim: Result<ClaimOutcome, String>, finish_fails: bool) -> Calls {
        Calls {
            claim: Mutex::new(Some(claim)),
            events: Mutex::new(Vec::new()),
            finish_fails,
        }
    }
    #[tokio::test]
    async fn nonfresh_claims_never_infer_or_finish() {
        for (claim, expected) in [
            (Err("db error".into()), "missing"),
            (Ok(ClaimOutcome::NotFound), "missing"),
            (Ok(ClaimOutcome::Expired), "expired"),
            (Ok(ClaimOutcome::AlreadyClaimed), "busy"),
            (
                Ok(ClaimOutcome::Replay(StoredOutcome {
                    outcome: "FAILED".into(),
                    response_output_bytes: None,
                    response_output_sha256: None,
                    response_provider_trace: None,
                    response_model_call_id: None,
                    response_failure_message: Some("exact stored failure".into()),
                })),
                "replay",
            ),
        ] {
            let calls = calls(claim, false);
            let result = execute(&calls, &Executor(&calls), Uuid::nil(), Uuid::nil()).await;
            let actual = match result {
                InferenceOutcome::NotFound => "missing",
                InferenceOutcome::Expired => "expired",
                InferenceOutcome::Busy => "busy",
                InferenceOutcome::Replay(row) => {
                    assert_eq!(
                        row.response_failure_message.as_deref(),
                        Some("exact stored failure")
                    );
                    "replay"
                }
                InferenceOutcome::Executed(_) => panic!("nonfresh call executed"),
            };
            assert_eq!(actual, expected);
            assert_eq!(*calls.events.lock().unwrap(), ["claim"]);
        }
    }
    #[tokio::test]
    async fn fresh_claim_executes_once_and_preserves_response_on_finish_failure() {
        for finish_fails in [false, true] {
            let calls = calls(
                Ok(ClaimOutcome::Claimed(ClaimedRegistration {
                    tenant_id: Uuid::from_u128(42),
                    reasoning_domain_id: Uuid::nil(),
                    binding_id: Uuid::nil(),
                    binding_version: 1,
                    purpose: "Distill".into(),
                    input_manifest_hash: vec![0; 32],
                    consolidation_run_id: None,
                })),
                finish_fails,
            );
            assert!(matches!(
                execute(&calls, &Executor(&calls), Uuid::nil(), Uuid::nil()).await,
                InferenceOutcome::Executed("original response")
            ));
            assert_eq!(*calls.events.lock().unwrap(), ["claim", "infer", "finish"]);
        }
    }
}
