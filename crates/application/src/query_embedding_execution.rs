//! `application::query_embedding_execution` — registered query embedding execution.
//! Depends-on: crates=[async-trait, tokio, uuid]; services=[]; env=[]; modules=[]
//! Called-by: [retrieval-worker::rpc, adapters::retrieval_embedding_rpc]
//! Invariants: [replay/busy never dispatch; claim and completion transactions belong to the adapter]
//! Spec: ADR-0012; ADR-0130 D2/D7

use async_trait::async_trait;
use uuid::Uuid;

/// A freshly claimed registration — every field the worker needs to re-derive an
/// `AuthorizationScope` and build a `RetrievalQueryCallContext` without trusting anything the
/// RPC body itself asserted about identity.
#[derive(Debug, Clone)]
pub struct ClaimedRegistration {
    pub tenant_id: Uuid,
    pub principal_id: Uuid,
    pub user_id: Uuid,
    pub workspace_id: Uuid,
    pub request_id: Uuid,
    pub logical_call_id: Uuid,
    pub attempt_no: i32,
    pub profile_fingerprint: String,
}

/// A previously completed call's stored outcome, replayed verbatim on a duplicate `call_id`
/// (ADR-0012 §2 "idempotency by call_id" — zero provider calls on replay).
#[derive(Debug, Clone)]
pub struct StoredOutcome {
    pub outcome: String,
    pub response_vector: Option<Vec<f32>>,
    pub response_provider_id: Option<String>,
    pub response_model_id: Option<String>,
    pub response_model_revision: Option<String>,
    pub response_dimension: Option<u32>,
    pub response_failure_code: Option<String>,
}

/// The registration claim's three-way branch — every distinct
/// action the RPC handler must take, named explicitly so a caller cannot mistake "already
/// claimed by someone else" for "freshly claimed by me".
pub enum ClaimOutcome {
    NotFound,
    Expired,
    /// `query_sha256` in the RPC body did not match the registration — ADR-0012 §2 "409, zero
    /// side effects": the row is left completely untouched (no claim).
    QueryMismatch,
    /// `claimed_at` is set but `completed_at` is not — a concurrent delivery or a
    /// crash-after-dispatch-before-persist. ADR-0012 §2: `Unavailable(WorkerBusy)`, zero
    /// provider calls, no further row mutation.
    AlreadyClaimed,
    Replay(StoredOutcome),
    Claimed(ClaimedRegistration),
}

/// Persistence conversation for a registered embedding call; each method owns its complete transaction.
#[async_trait]
pub trait QueryEmbeddingCalls: Send + Sync {
    /// Adapter failure, retained for the worker's existing logging/error mapping.
    type Error: Send;
    /// Atomically inspect and claim the registered call (ADR-0012 §2).
    async fn claim(
        &self,
        call_id: Uuid,
        tenant_hint: Uuid,
        query_sha256: [u8; 32],
    ) -> Result<ClaimOutcome, Self::Error>;
    /// Persist a completed outcome without changing provider/disclosure transaction ownership.
    async fn finish(
        &self,
        call_id: Uuid,
        tenant_id: Uuid,
        outcome: StoredOutcome,
    ) -> Result<(), Self::Error>;
}

/// Worker-local sealing and purpose-bound embedding dispatch (ADR-0056 D-C).
#[async_trait]
pub trait QueryEmbeddingExecutor: Send + Sync {
    /// Execute exactly once for a freshly claimed registration.
    async fn embed(
        &self,
        call_id: Uuid,
        query: &str,
        registration: &ClaimedRegistration,
    ) -> StoredOutcome;
}

/// Completion persistence failure is observable while the embedding reply remains unchanged.
pub struct ExecutionResult<E> {
    /// Claim refusal, replay, or the freshly executed reply represented as a replayable outcome.
    pub outcome: ClaimOutcome,
    /// The original worker logs this failure with the registered tenant identity.
    pub finish_error: Option<(Uuid, E)>,
}

/// Claim → execute → finish; never redispatch a replay or an ambiguous in-flight claim.
pub async fn execute<P: QueryEmbeddingCalls, E: QueryEmbeddingExecutor>(
    calls: &P,
    executor: &E,
    call_id: Uuid,
    tenant_hint: Uuid,
    query_sha256: [u8; 32],
    query: &str,
) -> Result<ExecutionResult<P::Error>, P::Error> {
    let claim = calls.claim(call_id, tenant_hint, query_sha256).await?;
    let ClaimOutcome::Claimed(registration) = claim else {
        return Ok(ExecutionResult {
            outcome: claim,
            finish_error: None,
        });
    };
    let outcome = executor.embed(call_id, query, &registration).await;
    let finish_error = calls
        .finish(call_id, registration.tenant_id, outcome.clone())
        .await
        .err()
        .map(|error| (registration.tenant_id, error));
    Ok(ExecutionResult {
        outcome: ClaimOutcome::Replay(outcome),
        finish_error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    struct Calls(Mutex<Option<ClaimOutcome>>, AtomicUsize, bool);
    fn stored() -> StoredOutcome {
        StoredOutcome {
            outcome: "UNAVAILABLE".into(),
            response_vector: None,
            response_provider_id: None,
            response_model_id: None,
            response_model_revision: None,
            response_dimension: None,
            response_failure_code: Some("TEST".into()),
        }
    }
    #[async_trait]
    impl QueryEmbeddingCalls for Calls {
        type Error = ();
        async fn claim(&self, _: Uuid, _: Uuid, _: [u8; 32]) -> Result<ClaimOutcome, ()> {
            Ok(self.0.lock().unwrap().take().unwrap())
        }
        async fn finish(&self, _: Uuid, _: Uuid, outcome: StoredOutcome) -> Result<(), ()> {
            assert_eq!(outcome.response_failure_code.as_deref(), Some("TEST"));
            self.1.fetch_add(1, Ordering::SeqCst);
            if self.2 { Err(()) } else { Ok(()) }
        }
    }
    struct Executor(AtomicUsize);
    #[async_trait]
    impl QueryEmbeddingExecutor for Executor {
        async fn embed(&self, _: Uuid, _: &str, _: &ClaimedRegistration) -> StoredOutcome {
            self.0.fetch_add(1, Ordering::SeqCst);
            stored()
        }
    }
    #[tokio::test]
    async fn replay_busy_and_refusals_never_dispatch_or_finish() {
        for outcome in [
            ClaimOutcome::NotFound,
            ClaimOutcome::Expired,
            ClaimOutcome::QueryMismatch,
            ClaimOutcome::AlreadyClaimed,
            ClaimOutcome::Replay(stored()),
        ] {
            let expected = std::mem::discriminant(&outcome);
            let calls = Calls(Mutex::new(Some(outcome)), AtomicUsize::new(0), false);
            let executor = Executor(AtomicUsize::new(0));
            let result = execute(
                &calls,
                &executor,
                Uuid::nil(),
                Uuid::nil(),
                [0; 32],
                "query",
            )
            .await
            .unwrap();
            assert_eq!(std::mem::discriminant(&result.outcome), expected);
            assert!(result.finish_error.is_none());
            assert_eq!(executor.0.load(Ordering::SeqCst), 0);
            assert_eq!(calls.1.load(Ordering::SeqCst), 0);
        }
    }
    #[tokio::test]
    async fn fresh_claim_executes_once_and_retains_reply_when_finish_fails() {
        for fail in [false, true] {
            let registration = ClaimedRegistration {
                tenant_id: Uuid::nil(),
                principal_id: Uuid::nil(),
                user_id: Uuid::nil(),
                workspace_id: Uuid::nil(),
                request_id: Uuid::nil(),
                logical_call_id: Uuid::nil(),
                attempt_no: 1,
                profile_fingerprint: "profile".into(),
            };
            let calls = Calls(
                Mutex::new(Some(ClaimOutcome::Claimed(registration))),
                AtomicUsize::new(0),
                fail,
            );
            let executor = Executor(AtomicUsize::new(0));
            let result = execute(
                &calls,
                &executor,
                Uuid::nil(),
                Uuid::nil(),
                [0; 32],
                "query",
            )
            .await
            .unwrap();
            let ClaimOutcome::Replay(reply) = result.outcome else {
                panic!("completed reply")
            };
            assert_eq!(reply.response_failure_code.as_deref(), Some("TEST"));
            assert_eq!(result.finish_error.is_some(), fail);
            assert_eq!(executor.0.load(Ordering::SeqCst), 1);
            assert_eq!(calls.1.load(Ordering::SeqCst), 1);
        }
    }
}
