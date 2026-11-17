//! `application::projection_execution` — resident/one-shot projection worker orchestration and boot verification (ADR-0130).
//! Depends-on: crates=[async-trait, humaux-domain, humaux-projection, tokio]; services=[]; env=[]; modules=[domain::error, domain::ticket_family, projection::note_chunks]
//! Called-by: [adapters::projection_worker, retrieval-worker::main, tests]
//! Invariants: [no pass runs until embedding fingerprint binding and card profile policy both pass; fingerprint or policy refusal exits configuration-refused, never retried; resident mode logs DB/pass outages and waits for next poll or shutdown between passes]
//! Spec: Baseline §15.1; §17.4; ADR-0037; ADR-0052 D-F; ADR-0064 D-C; ADR-0068 D-I; ADR-0130

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use humaux_domain::error::ErrorCode;
use humaux_domain::ticket_family::TicketFamily;
use humaux_projection::note_chunks::{NoteChunkPolicy, UnknownNoteChunkProfile};

/// ADR-0064 D-C: the one line a fingerprint refusal prints (exit 2, never retried).
pub const BOOT_REFUSED: &str = "boot refused: fingerprint_mismatch: HUMAUX_RETRIEVAL_WORKER_EMBEDDING_VERSION is bound \
                            to another model fingerprint (ADR-0064 D-C)";

/// ADR-0052 D-E backoff: the n-th transient failure waits `min(base * 2^(n-1), max)` seconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BackoffConfig {
    pub base_secs: f64,
    pub max_secs: f64,
}

/// One projection pass's validated configuration knobs (ADR-0052 D-F).
#[derive(Debug, Clone, PartialEq)]
pub struct PassConfig {
    pub family: TicketFamily,
    pub lease_owner: String,
    pub lease_secs: f64,
    pub batch: i64,
    pub per_tenant_cap: i64,
    pub max_attempts: i32,
    pub backoff: BackoffConfig,
}

/// Counters produced by one claimed projection pass (ADR-0052 D-F).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PassOutcome {
    pub last_error: Option<ErrorCode>,
    pub claimed: u64,
    pub done: u64,
    pub skipped: u64,
    pub failed: u64,
    pub retried: u64,
    pub refunded: u64,
    pub pending: u64,
    pub lost_lease: u64,
    pub placement_missing: u64,
    pub placement_invalid: u64,
    pub claim_ms: u64,
}

/// Embedding model identity inputs used for ADR-0064 D-C fingerprint binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintInputs {
    pub provider: String,
    pub model_id: String,
    pub model_revision: String,
}

/// Worker execution outcome differentiating configuration refusals (exit 2) from runtime outages (exit 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerOutcome {
    ConfigFailed(String),
    Runtime(String),
}

/// ADR-0068 D-I, the boot check of the binary's own projection: `None` when the row exists and its hash (NULL
/// included) names a profile this build knows; otherwise the refusal line (exit 2, an operator must change
/// something). A missing row is refused here, never read as legacy: migration 0238 seeds the serving projection's
/// row, so its absence is a broken deployment, and a worker that guessed would build slots the ledger does not count.
pub fn note_chunk_policy_refusal(row: Option<Option<&str>>) -> Option<String> {
    match row {
        None => Some(
            "boot refused: card_profile_policy_missing: the projection has no card profile policy row \
             (ADR-0068 D-I)"
                .to_owned(),
        ),
        Some(hash) => NoteChunkPolicy::from_profile_hash(hash).err().map(
            |UnknownNoteChunkProfile(hash)| {
                format!(
                    "boot refused: card_profile_policy_unknown: note chunk profile {hash:?} is not \
                     a profile this build knows (ADR-0068 D-I)"
                )
            },
        ),
    }
}

/// Outbound port for projection boot verification and claimed-pass execution.
#[async_trait]
pub trait ProjectionWorkerPort: Send + Sync {
    /// ADR-0064 D-C: bind `HUMAUX_RETRIEVAL_WORKER_EMBEDDING_VERSION` to the configured model fingerprint.
    /// `Ok(None)` = bound; `Ok(Some(err))` = transient DB error; `Err(WorkerOutcome::ConfigFailed(_))` = refused.
    async fn bind_embedding_fingerprint(
        &self,
        family: TicketFamily,
        inputs: &FingerprintInputs,
    ) -> Result<Option<String>, WorkerOutcome>;

    /// ADR-0068 D-I: verify the projection's `card_profile_policies` row exists and names a known profile.
    /// `Ok(None)` = valid; `Ok(Some(err))` = transient DB error; `Err(WorkerOutcome::ConfigFailed(_))` = refused.
    async fn check_card_profile_policy(
        &self,
        family: TicketFamily,
    ) -> Result<Option<String>, WorkerOutcome>;

    /// ADR-0052 D-F: execute one claimed projection pass.
    async fn run_claimed_pass(&self, config: &PassConfig) -> Result<PassOutcome, ErrorCode>;
}

/// Process-level runtime hooks (lazy adapter connection, stage instrumentation, logging, shutdown/poll sleep).
#[async_trait]
pub trait ProjectionRuntimePort: Send + Sync {
    /// Connect lazily to the DB pool / embedding provider and return the port + fingerprint inputs.
    async fn connect(&self) -> Result<(Arc<dyn ProjectionWorkerPort>, FingerprintInputs), String>;

    /// Execute one pass wrapped in the process's stage liveness telemetry.
    async fn run_instrumented_pass(
        &self,
        worker: &dyn ProjectionWorkerPort,
        pass: &PassConfig,
    ) -> Result<PassOutcome, ErrorCode>;

    /// Emit one completed pass line.
    fn on_pass_ok(&self, outcome: &PassOutcome);

    /// Emit one transient pass/connection error line.
    fn on_pass_error(&self, message: &str);

    /// Wait for the poll interval or a shutdown signal. Returns `false` when shutdown was received.
    async fn wait_for_next_poll_or_shutdown(&mut self, poll_interval: Duration) -> bool;
}

/// The two boot refusals that need the database: the label's fingerprint binding, then the
/// projection's card profile policy.
pub async fn boot_checks(
    worker: &dyn ProjectionWorkerPort,
    inputs: &FingerprintInputs,
    family: TicketFamily,
) -> Result<Option<String>, WorkerOutcome> {
    match worker.bind_embedding_fingerprint(family, inputs).await? {
        None => worker.check_card_profile_policy(family).await,
        retry => Ok(retry),
    }
}

/// Resident (`--serve`) and one-shot (`--run-once`) projection worker orchestration (ADR-0052 D-F).
pub async fn run_projection_worker<R: ProjectionRuntimePort>(
    runtime: &mut R,
    pass: &PassConfig,
    poll_interval: Duration,
    resident: bool,
) -> Result<(), WorkerOutcome> {
    let mut worker: Option<Arc<dyn ProjectionWorkerPort>> = None;
    loop {
        if worker.is_none() {
            match runtime.connect().await {
                Ok((connected, fingerprint_inputs)) => {
                    match boot_checks(connected.as_ref(), &fingerprint_inputs, pass.family).await? {
                        None => worker = Some(connected),
                        Some(error) if resident => runtime.on_pass_error(&error),
                        Some(error) => return Err(WorkerOutcome::Runtime(error)),
                    }
                }
                Err(error) if resident => runtime.on_pass_error(&error),
                Err(error) => return Err(WorkerOutcome::Runtime(error)),
            }
        }
        if let Some(connected) = &worker {
            match runtime
                .run_instrumented_pass(connected.as_ref(), pass)
                .await
            {
                Ok(outcome) => runtime.on_pass_ok(&outcome),
                Err(error) if resident => runtime.on_pass_error(&error.to_string()),
                Err(error) => {
                    return Err(WorkerOutcome::Runtime(format!(
                        "projection pass failed: {error}"
                    )));
                }
            }
        }
        if !resident {
            return Ok(());
        }
        if !runtime.wait_for_next_poll_or_shutdown(poll_interval).await {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct StubWorker {
        bind_results: Mutex<VecDeque<Result<Option<String>, WorkerOutcome>>>,
        policy_results: Mutex<VecDeque<Result<Option<String>, WorkerOutcome>>>,
        pass_results: Mutex<VecDeque<Result<PassOutcome, ErrorCode>>>,
        policy_calls: AtomicUsize,
        pass_calls: AtomicUsize,
    }

    impl StubWorker {
        fn new(
            bind_results: Vec<Result<Option<String>, WorkerOutcome>>,
            policy_results: Vec<Result<Option<String>, WorkerOutcome>>,
            pass_results: Vec<Result<PassOutcome, ErrorCode>>,
        ) -> Self {
            Self {
                bind_results: Mutex::new(bind_results.into()),
                policy_results: Mutex::new(policy_results.into()),
                pass_results: Mutex::new(pass_results.into()),
                policy_calls: AtomicUsize::new(0),
                pass_calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl ProjectionWorkerPort for StubWorker {
        async fn bind_embedding_fingerprint(
            &self,
            _family: TicketFamily,
            _inputs: &FingerprintInputs,
        ) -> Result<Option<String>, WorkerOutcome> {
            self.bind_results.lock().unwrap().pop_front().unwrap()
        }

        async fn check_card_profile_policy(
            &self,
            _family: TicketFamily,
        ) -> Result<Option<String>, WorkerOutcome> {
            self.policy_calls.fetch_add(1, Ordering::SeqCst);
            self.policy_results.lock().unwrap().pop_front().unwrap()
        }

        async fn run_claimed_pass(&self, _config: &PassConfig) -> Result<PassOutcome, ErrorCode> {
            self.pass_calls.fetch_add(1, Ordering::SeqCst);
            self.pass_results.lock().unwrap().pop_front().unwrap()
        }
    }

    struct MockRuntime {
        connects: Mutex<VecDeque<Result<Arc<dyn ProjectionWorkerPort>, String>>>,
        polls_before_shutdown: usize,
        ok_logs: Mutex<Vec<PassOutcome>>,
        err_logs: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl ProjectionRuntimePort for MockRuntime {
        async fn connect(
            &self,
        ) -> Result<(Arc<dyn ProjectionWorkerPort>, FingerprintInputs), String> {
            let worker = self.connects.lock().unwrap().pop_front().unwrap()?;
            Ok((worker, sample_inputs()))
        }

        async fn run_instrumented_pass(
            &self,
            worker: &dyn ProjectionWorkerPort,
            pass: &PassConfig,
        ) -> Result<PassOutcome, ErrorCode> {
            worker.run_claimed_pass(pass).await
        }

        fn on_pass_ok(&self, outcome: &PassOutcome) {
            self.ok_logs.lock().unwrap().push(*outcome);
        }

        fn on_pass_error(&self, message: &str) {
            self.err_logs.lock().unwrap().push(message.to_owned());
        }

        async fn wait_for_next_poll_or_shutdown(&mut self, _poll_interval: Duration) -> bool {
            if self.polls_before_shutdown == 0 {
                return false;
            }
            self.polls_before_shutdown -= 1;
            true
        }
    }

    fn sample_inputs() -> FingerprintInputs {
        FingerprintInputs {
            provider: "dashscope".to_owned(),
            model_id: "text-embedding-v4".to_owned(),
            model_revision: "2026-08".to_owned(),
        }
    }

    fn sample_pass() -> PassConfig {
        PassConfig {
            family: TicketFamily::PrivateMemory,
            lease_owner: "humaux-retrieval-worker/test".to_owned(),
            lease_secs: 60.0,
            batch: 16,
            per_tenant_cap: 8,
            max_attempts: 6,
            backoff: BackoffConfig {
                base_secs: 30.0,
                max_secs: 300.0,
            },
        }
    }

    #[tokio::test]
    async fn boot_checks_refuses_fingerprint_mismatch_without_calling_policy() {
        let worker = StubWorker::new(
            vec![Err(WorkerOutcome::ConfigFailed(BOOT_REFUSED.to_owned()))],
            vec![],
            vec![],
        );
        let err = boot_checks(&worker, &sample_inputs(), TicketFamily::PrivateMemory)
            .await
            .expect_err("fingerprint refusal");
        assert_eq!(err, WorkerOutcome::ConfigFailed(BOOT_REFUSED.to_owned()));
        assert_eq!(worker.policy_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn boot_checks_defers_policy_check_on_transient_fingerprint_error() {
        let worker = StubWorker::new(
            vec![Ok(Some("fingerprint binding: db down".to_owned()))],
            vec![],
            vec![],
        );
        let retry = boot_checks(&worker, &sample_inputs(), TicketFamily::PrivateMemory)
            .await
            .expect("transient error is Ok(Some)");
        assert_eq!(retry.as_deref(), Some("fingerprint binding: db down"));
        assert_eq!(worker.policy_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn resident_worker_survives_transient_outages_and_runs_pass_after_recovery() {
        let worker = Arc::new(StubWorker::new(
            vec![Ok(None)],
            vec![Ok(None)],
            vec![
                Err(ErrorCode::DependencyUnavailable),
                Ok(PassOutcome {
                    claimed: 2,
                    done: 2,
                    ..Default::default()
                }),
            ],
        ));
        let mut runtime = MockRuntime {
            connects: Mutex::new(VecDeque::from(vec![
                Err("db unreachable".to_owned()),
                Ok(worker.clone() as Arc<dyn ProjectionWorkerPort>),
            ])),
            polls_before_shutdown: 2,
            ok_logs: Mutex::new(Vec::new()),
            err_logs: Mutex::new(Vec::new()),
        };
        run_projection_worker(&mut runtime, &sample_pass(), Duration::from_secs(1), true)
            .await
            .expect("resident worker stops cleanly on shutdown");
        assert_eq!(worker.pass_calls.load(Ordering::SeqCst), 2);
        assert_eq!(runtime.err_logs.lock().unwrap().len(), 2);
        assert_eq!(runtime.ok_logs.lock().unwrap().len(), 1);
        assert_eq!(runtime.ok_logs.lock().unwrap()[0].done, 2);
    }

    #[tokio::test]
    async fn one_shot_worker_fails_runtime_on_connect_or_pass_error() {
        let mut runtime = MockRuntime {
            connects: Mutex::new(VecDeque::from(vec![Err("db unreachable".to_owned())])),
            polls_before_shutdown: 0,
            ok_logs: Mutex::new(Vec::new()),
            err_logs: Mutex::new(Vec::new()),
        };
        let err =
            run_projection_worker(&mut runtime, &sample_pass(), Duration::from_secs(1), false)
                .await
                .expect_err("one-shot fails on connect error");
        assert_eq!(err, WorkerOutcome::Runtime("db unreachable".to_owned()));
    }

    #[tokio::test]
    async fn resident_worker_exits_config_failed_on_policy_refusal() {
        let worker = Arc::new(StubWorker::new(
            vec![Ok(None)],
            vec![Err(WorkerOutcome::ConfigFailed(
                note_chunk_policy_refusal(None).unwrap(),
            ))],
            vec![],
        ));
        let mut runtime = MockRuntime {
            connects: Mutex::new(VecDeque::from(vec![Ok(
                worker.clone() as Arc<dyn ProjectionWorkerPort>
            )])),
            polls_before_shutdown: 5,
            ok_logs: Mutex::new(Vec::new()),
            err_logs: Mutex::new(Vec::new()),
        };
        let err = run_projection_worker(&mut runtime, &sample_pass(), Duration::from_secs(1), true)
            .await
            .expect_err("policy refusal exits config failed even in resident mode");
        assert!(
            matches!(err, WorkerOutcome::ConfigFailed(msg) if msg.contains("card_profile_policy_missing"))
        );
        assert_eq!(worker.pass_calls.load(Ordering::SeqCst), 0);
    }
}
