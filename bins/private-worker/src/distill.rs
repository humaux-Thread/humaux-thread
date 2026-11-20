//! `private-worker::distill` — The Distill hop (§15.5 / §16.1.1 / §10.1, ADR-0016): accepted Evidence → 0..N
//!   `private.memory_records`, owned by this process because §6.2.2 already gives `role_private_worker` both the
//!   provider capability and the only INSERT on `memory_records`/`memory_evidence` (no RPC needed, contrast
//!   ADR-0015's Consolidate hop). Dispatch is ADR-0058's: one `DERIVED_DISTILL` job = one Evidence, claimed through
//!   the four provider slots, worked by at most IN_FLIGHT seats of one task.
//! Depends-on: crates=[humaux-adapters, humaux-application, humaux-domain, humaux-telemetry, serde_json, tokio, uuid]; services=[]; env=[HUMAUX_PRIVATE_WORKER_CANDIDATE_TTL_SECONDS]; modules=[application::distill_execution, domain::error, private-worker::stages, telemetry::metrics]
//! Called-by: [private-worker::main, private-worker::route_providers, tests]
//! Invariants: [a candidate over the §10.1 origin-bound ceiling is rejected, never downgraded; one job = one Evidence
//!   and a job only takes its own Evidence's outbox row; at most IN_FLIGHT seats per process and four bound slots
//!   across all processes; a lost lease never drops an in-flight call; the deadline cuts only the HTTP future; an
//!   attempt is an admitted provider request; DEAD only with its outbox row FAILED in the same transaction; a
//!   refused retry settles as its exhausted budget; memories, run completion, job settle and outbox flip commit in
//!   one generation-fenced transaction; only a fence refusal is a lost lease, an escaped error is ERROR (ADR-0058
//!   R3); an invalid inferred affect drops the reply's affects, never its memories (R1); a drain names why it stopped,
//!   no_slot or no_work (R5); a route whose credential reference is not in the worker's key map is NOT_READY
//!   CREDENTIAL_NOT_MAPPED before any ledger row or provider call (refused by its route instance, ADR-0060 D-B);
//!   a route parked for its health is NOT_READY ROUTE_HEALTH_STALE / ROUTE_HEALTH_DENIED; a SUCCEEDED call renews
//!   its route's health near expiry and a provider 401 records the credential INVALID (ruling E3); a RETRY settle
//!   with class TRANSPORT counts `dns_pin_deferred_total` only while a DNS pin is configured (ADR-0066 D-P)]
//! Spec: Baseline §16.1.1; §10.1; ADR-0016; §15.7; §67.2; §11; §11.2.5; ADR-0058; ADR-0059; ADR-0060 D-B; ADR-0060 D-M;
//!   ADR-0060 E3; §41.2; ADR-0066 D-P; ADR-0124
//!
//! One job (ADR-0058 D-C): take the job's own outbox row, (a) check the Evidence still names the
//! job's reasoning domain, resolve the admitted Distill route, load the Evidence, record the
//! §16.1.1 processing run (fingerprint first — before any bytes leave), (b) reserve the ledger and
//! disclosure rows, ask `ops.begin_call` to admit the request (the attempt is counted there), send
//! it, (c) parse fail-closed, authorize each candidate against §10.1's origin-bound ceiling —
//! over-ceiling candidates are rejected with a reason and never downgraded — and commit the job
//! settle (first, generation-fenced), the surviving memories, the run's completion and the outbox
//! DONE flip in ONE transaction (idempotency, ADR-0016 D5 / ADR-0058 D-E).
//!
//! Settles (ADR-0058 D-D/D-F/D-H): anything before the first admitted request is NOT_READY (backs
//! off, parks as WAITING_KEY past the park age, never spends an attempt) — including a request the
//! tenant's §72.3 budget refused (`PROVIDER_BUDGET`, D-T); a DB/reasoning error after an admitted
//! request settles one fenced RETRY in a fresh transaction (D-E); a provider 401 parks as
//! WAITING_KEY and reverts its attempt (§11); any other failed call is RETRY with the capped
//! backoff, or DEAD with its class once `max_attempts` calls were spent — DEAD always flips the
//! outbox row FAILED in the same transaction, so the ticket ends as `distill_failed` and the
//! tenant's later rows keep flowing (§15.7). Input-bound rejections (Evidence gone) settle the
//! outbox FAILED and the job DONE.
//!
//! Tickets: remember already issued the `projection.stream_log` row for this Evidence; once the
//! outbox row is DONE the retrieval worker resolves it through `memory_evidence` (or settles it
//! as a no-op when the answer was "nothing memorable", `projection_worker` D6).

use crate::stages::STAGES;
use humaux_application::distill_execution::{
    self as execution, Dispatcher, DistillClaim, DistillLease, DistillPorts, JobOutcome, Settled,
    payload_identity, stage_class,
};
pub use humaux_application::distill_execution::{
    DistillDispatchConfig, DistillDispatchReport, DistillError, DrainStop, PROVIDER_SLOTS,
};
use humaux_domain::error::ErrorCode;
use humaux_telemetry::metrics::count_dns_pin_deferred;
use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::Duration;
use tokio::time::Instant;
async fn seat_iteration(
    work: impl Future<Output = (Result<Settled, DistillError>, u32)>,
) -> Result<Settled, DistillError> {
    use humaux_telemetry::metrics::{stage_recorded, stage_started};
    stage_started(STAGES[0], stage_now());
    let (result, output) = work.await;
    let error = match &result {
        Ok(s) => s.error.or_else(|| s.class.map(stage_class)),
        Err(DistillError::Config(code)) => Some(*code),
        Err(e) => Some(stage_class(e.class())),
    };
    stage_recorded(STAGES[0], stage_now(), error, [1, u64::from(output)]);
    result
}
async fn lease_iteration<T>(
    work: impl Future<Output = Result<Option<T>, DistillError>>,
) -> Result<Option<T>, DistillError> {
    use humaux_telemetry::metrics::{stage_recorded, stage_started};
    stage_started(STAGES[1], stage_now());
    let result = work.await;
    let error = match &result {
        Ok(Some(_)) => None,
        Ok(None) => Some(ErrorCode::Conflict),
        Err(_) => Some(ErrorCode::DependencyUnavailable),
    };
    stage_recorded(
        STAGES[1],
        stage_now(),
        error,
        [1, u64::from(matches!(result, Ok(Some(_))))],
    );
    result
}
fn stage_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
fn count_dns_pin_deferral(settled: &Settled, dns_pins_configured: bool) {
    if dns_pins_configured
        && settled.outcome == JobOutcome::Retry
        && settled.class == Some(TRANSPORT_CLASS)
    {
        count_dns_pin_deferred();
    }
}
const TRANSPORT_CLASS: &str = "TRANSPORT";
#[derive(Clone, Copy)]
enum Mode<'a> {
    Drain,
    Serve {
        poll: Duration,
        shutdown: &'a AtomicBool,
    },
}
const EXECUTION_UNCERTAIN: &str = "EXECUTION_UNCERTAIN";
/// Drain the currently claimable Distill jobs through application ports.
pub async fn dispatch_pass<R: DistillPorts>(
    runtime: &R,
    dispatch: &DistillDispatchConfig,
) -> Result<DistillDispatchReport, DistillError> {
    run_seats(runtime, dispatch, Mode::Drain).await
}

/// `--distill-serve`: the same seats, resident. A seat sleeps `poll` only after its own claim
/// came back empty ("skip the poll sleep while work exists"); `shutdown` stops every seat after
/// the job it holds.
pub async fn dispatch_serve<R: DistillPorts>(
    runtime: &R,
    dispatch: &DistillDispatchConfig,
    poll: Duration,
    shutdown: &AtomicBool,
) -> Result<DistillDispatchReport, DistillError> {
    run_seats(runtime, dispatch, Mode::Serve { poll, shutdown }).await
}

async fn run_seats<R: DistillPorts>(
    runtime: &R,
    dispatch: &DistillDispatchConfig,
    mode: Mode<'_>,
) -> Result<DistillDispatchReport, DistillError> {
    dispatch.validate().map_err(DistillError::Config)?;
    // ponytail: the sqlx default pool (10) covers two connections per seat plus a claim for the
    // `PROVIDER_SLOTS` seats `validate` allows (ADR-0058 L7 / R2); upgrade: size the pool from
    // IN_FLIGHT in adapters::postgres.
    let dispatcher = Dispatcher {
        runtime,
        dispatch,
        sleep_until: |deadline| Box::pin(tokio::time::sleep_until(Instant::from_std(deadline))),
        retry_jitter: execution::sample_retry_jitter,
    };
    let seats: Vec<SeatFuture<'_>> = (0..dispatch.in_flight)
        .map(|_| Box::pin(seat(&dispatcher, mode)) as SeatFuture<'_>)
        .collect();
    let mut report = DistillDispatchReport::default();
    let mut first_error = None;
    for result in join_all(seats).await {
        match result {
            Ok(seat_report) => report.add(seat_report),
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(report),
    }
}

/// One seat's future, as [`join_all`] polls it.
type SeatFuture<'a> =
    Pin<Box<dyn Future<Output = Result<DistillDispatchReport, DistillError>> + 'a>>;

/// Polls every seat in this one task until all are done.
// ponytail: one task polls all seats — no CPU parallelism, and a panic in one job ends the
// dispatcher (ADR-0058 L6). Upgrade: a JoinSet of spawned seats once the provider is an `Arc`.
async fn join_all<T>(mut futures: Vec<Pin<Box<dyn Future<Output = T> + '_>>>) -> Vec<T> {
    let mut results: Vec<Option<T>> = futures.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (future, result) in futures.iter_mut().zip(results.iter_mut()) {
            if result.is_none() {
                match future.as_mut().poll(cx) {
                    Poll::Ready(value) => *result = Some(value),
                    Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
    results.into_iter().flatten().collect()
}

/// One seat: claim one job, run it, claim again at once.
async fn seat<R: DistillPorts>(
    dispatcher: &Dispatcher<'_, R>,
    mode: Mode<'_>,
) -> Result<DistillDispatchReport, DistillError> {
    let dispatch = dispatcher.dispatch;
    let mut report = DistillDispatchReport::default();
    loop {
        if let Mode::Serve { shutdown, .. } = mode
            && shutdown.load(Ordering::SeqCst)
        {
            return Ok(report);
        }
        // ADR-0058 D-J: taken before the claim call, so the local deadline is never later than
        // the claim's `hard_deadline` (no cross-clock comparison).
        let local_deadline =
            Instant::now() + Duration::from_secs_f64(dispatch.hard_deadline_seconds);
        let claimed = dispatcher.runtime.claim(dispatch).await;
        match (claimed, mode) {
            (Ok(Some(claim)), _) => {
                report.claimed += 1;
                run_claimed(dispatcher, &claim, local_deadline, &mut report).await;
            }
            (Ok(None), Mode::Drain) => {
                // ADR-0058 R5: read right after the empty claim, so the reason is that claim's.
                let all_bound = dispatcher.runtime.all_slots_bound().await?;
                report.stopped = Some(if all_bound {
                    DrainStop::NoSlot
                } else {
                    DrainStop::NoWork
                });
                return Ok(report);
            }
            (Err(error), Mode::Drain) => return Err(error),
            (Ok(None), Mode::Serve { poll, shutdown }) => idle(poll, shutdown).await,
            (Err(error), Mode::Serve { poll, shutdown }) => {
                eprintln!("humaux-private-worker: distill claim failed: {error}");
                idle(poll, shutdown).await;
            }
        }
    }
}

/// Sleeps `poll`, waking early on shutdown.
// ponytail: checks the flag every 100 ms (no tokio `sync` feature here, ADR-0058 D-J); a Notify
// replaces the tick if the feature is ever enabled.
async fn idle(poll: Duration, shutdown: &AtomicBool) {
    const SHUTDOWN_TICK: Duration = Duration::from_millis(100);
    let until = Instant::now() + poll;
    while !shutdown.load(Ordering::SeqCst) {
        let now = Instant::now();
        if now >= until {
            return;
        }
        tokio::time::sleep((until - now).min(SHUTDOWN_TICK)).await;
    }
}

// §39: keep the seat's recording wrapper within the §78.3 function-size gate.
fn log_reclaimed(claim: &DistillClaim, max_attempts: i32) {
    if claim.last_error_class.as_deref() == Some(EXECUTION_UNCERTAIN) {
        // Main-line ruling E1: one line per T6 re-queue, naming the call whose outcome stayed
        // unknown — the resend is never silent.
        eprintln!(
            "humaux-private-worker: distill job={} tenant={} gen={} re-claimed after EXECUTION_UNCERTAIN (T6) uncertain_model_call_id={} attempt={}/{}",
            claim.job_id,
            claim.tenant_id,
            claim.claim_generation,
            claim
                .dispatch_model_call_id
                .map_or_else(|| "-".to_owned(), |id| id.to_string()),
            claim.attempt,
            max_attempts,
        );
    }
}

/// One claimed job: its work and its own heartbeat, polled together (ADR-0058 D-J), then the job
/// line. A lost lease does not drop the work: it runs to its end (bounded by the HTTP cutoff) so
/// the call is still ledgered, and its settle is refused by the generation fence.
async fn run_claimed<R: DistillPorts>(
    dispatcher: &Dispatcher<'_, R>,
    claim: &DistillClaim,
    local_deadline: Instant,
    report: &mut DistillDispatchReport,
) {
    let dispatch = dispatcher.dispatch;
    let lease = DistillLease::of(claim, &dispatch.lease_owner);
    log_reclaimed(claim, dispatch.max_attempts);
    let lost = Cell::new(false);
    let mut attempt = claim.attempt;
    // ADR-0060 D-M: the admitted route's fields once the read leg admitted one.
    let mut route = String::from("route=-");
    let heartbeat = async {
        let period = Duration::from_secs_f64(dispatch.lease_seconds / 3.0);
        loop {
            tokio::time::sleep(period).await;
            match lease_iteration(dispatcher.runtime.renew(&lease, dispatch.lease_seconds)).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    lost.set(true);
                    std::future::pending::<()>().await;
                }
                // Transient: the next tick retries; the lease outlives two missed ticks.
                Err(error) => {
                    eprintln!(
                        "humaux-private-worker: distill job={} heartbeat failed: {error}",
                        claim.job_id
                    );
                }
            }
        }
    };
    let work = seat_iteration(async {
        let before = report.memories;
        let result = execution::work_job(
            dispatcher,
            claim,
            &lease,
            local_deadline.into_std(),
            &mut attempt,
            &mut route,
            report,
        )
        .await;
        (result, report.memories - before)
    });
    let settled = tokio::select! {
        biased;
        settled = work => settled,
        () = heartbeat => unreachable!("the heartbeat never completes"),
    };
    let settled = match settled {
        Ok(settled) => settled,
        Err(error) => {
            eprintln!(
                "humaux-private-worker: distill job={} failed: {error}",
                claim.job_id
            );
            Settled::new(JobOutcome::Error, Some(error.class()))
        }
    };
    match settled.outcome {
        JobOutcome::Done => report.completed += 1,
        JobOutcome::Failed => report.failed += 1,
        JobOutcome::Retry => {
            report.deferred += 1;
            count_dns_pin_deferral(&settled, dispatch.dns_pins_configured);
        }
        JobOutcome::NotReady => report.not_ready += 1,
        JobOutcome::Parked => report.parked += 1,
        JobOutcome::Dead => {
            report.dead += 1;
            report.failed += 1;
        }
        JobOutcome::LeaseLost => report.lost_lease += 1,
        JobOutcome::Error => report.errors += 1,
        JobOutcome::Unknown => report.unknown += 1,
    }
    // A renew that lost the race with this job's own committed settle is not a lost lease.
    if lost.get() && matches!(settled.outcome, JobOutcome::LeaseLost | JobOutcome::Unknown) {
        report.heartbeat_lost += 1;
    }
    eprintln!(
        "humaux-private-worker: distill job={} tenant={} {route} evidence={} gen={} outcome={} attempt={}/{} error_class={} next_retry_s={} channel_fallback={}",
        claim.job_id,
        claim.tenant_id,
        payload_identity(&claim.payload).map_or_else(|| "-".to_owned(), |(_, e)| e.to_string()),
        claim.claim_generation,
        settled.outcome.as_str(),
        attempt,
        dispatch.max_attempts,
        settled.class.unwrap_or("-"),
        settled
            .next_retry_seconds
            .map_or_else(|| "-".to_owned(), |s| format!("{s:.0}")),
        u8::from(settled.channel_fallback),
    );
}

/// Resolve the existing fail-closed candidate TTL only when persistence rejects a candidate (§78.1).
pub fn candidate_ttl_seconds() -> Result<i64, ErrorCode> {
    let raw = std::env::var("HUMAUX_PRIVATE_WORKER_CANDIDATE_TTL_SECONDS")
        .map_err(|_| ErrorCode::InvalidInput)?;
    let seconds: i64 = raw.trim().parse().map_err(|_| ErrorCode::InvalidInput)?;
    if seconds <= 0 {
        return Err(ErrorCode::InvalidInput);
    }
    Ok(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use humaux_adapters::{byok::ReasoningProviderError, jobs};
    use humaux_application::distill_execution::*;
    use humaux_domain::{authority::CandidateRejection, error::ErrorCode};
    use uuid::Uuid;

    fn config() -> DistillDispatchConfig {
        DistillDispatchConfig {
            lease_owner: "worker-a".into(),
            lease_seconds: 30.0,
            in_flight: 4,
            hard_deadline_seconds: 300.0,
            http_timeout_seconds: 120.0,
            not_ready_park_seconds: 600.0,
            max_attempts: 5,
            budget: jobs::DistillCallBudget {
                window_seconds: 60.0,
                max_calls: 120,
            },
            health_renew_seconds: 1800,
            dns_pins_configured: false,
        }
    }

    /// ADR-0058 D-K — fault: weaken the bound to `http_timeout + lease`.
    #[test]
    fn config_rejects_a_hard_deadline_that_cannot_hold_a_call_and_its_reask() {
        let ok = config();
        assert!(
            ok.validate().is_ok(),
            "2 × (120 + 30) = 300 is exactly enough"
        );
        let short = DistillDispatchConfig {
            hard_deadline_seconds: 2.0 * (120.0 + 30.0) - 1.0,
            ..ok.clone()
        };
        assert!(short.validate().is_err());
        for bad in [
            DistillDispatchConfig {
                in_flight: 0,
                ..ok.clone()
            },
            DistillDispatchConfig {
                lease_seconds: 0.0,
                ..ok.clone()
            },
            DistillDispatchConfig {
                max_attempts: 0,
                ..ok.clone()
            },
            DistillDispatchConfig {
                not_ready_park_seconds: 0.0,
                ..ok.clone()
            },
            DistillDispatchConfig {
                lease_owner: " ".into(),
                ..ok.clone()
            },
            DistillDispatchConfig {
                budget: jobs::DistillCallBudget {
                    window_seconds: 0.0,
                    max_calls: 120,
                },
                ..ok.clone()
            },
            DistillDispatchConfig {
                budget: jobs::DistillCallBudget {
                    window_seconds: 60.0,
                    max_calls: 0,
                },
                ..ok.clone()
            },
            DistillDispatchConfig {
                health_renew_seconds: 0,
                ..ok.clone()
            },
        ] {
            assert!(bad.validate().is_err());
        }
    }

    /// ADR-0058 R2 — fault: accept `in_flight = 5`. A seat past the seeded slot rows can never
    /// hold a slot.
    #[test]
    fn in_flight_is_bounded_by_the_seeded_slot_rows() {
        for in_flight in 1..=PROVIDER_SLOTS {
            let ok = DistillDispatchConfig {
                in_flight,
                ..config()
            };
            assert!(ok.validate().is_ok(), "in_flight={in_flight}");
        }
        for in_flight in [0, PROVIDER_SLOTS + 1] {
            let bad = DistillDispatchConfig {
                in_flight,
                ..config()
            };
            assert_eq!(
                bad.validate(),
                Err(ErrorCode::InvalidInput),
                "in_flight={in_flight}"
            );
        }
    }

    /// Card 24 review P1: a counter `add` forgets is structurally zero on the only line
    /// production prints.
    #[test]
    fn add_folds_every_counter() {
        let one = DistillDispatchReport {
            claimed: 1,
            completed: 1,
            failed: 1,
            not_ready: 1,
            parked: 1,
            deferred: 1,
            dead: 1,
            lost_lease: 1,
            errors: 1,
            heartbeat_lost: 1,
            attempts: 1,
            unknown: 1,
            memories: 1,
            rejected: 1,
            empty_retries: 1,
            malformed_retries: 1,
            affects_dropped: 1,
            channel_fallback: 1,
            stopped: Some(DrainStop::NoWork),
        };
        let mut total = DistillDispatchReport::default();
        total.add(one);
        total.add(DistillDispatchReport {
            stopped: Some(DrainStop::NoSlot),
            ..one
        });
        total.add(one);
        let line = total.summary_line();
        assert_eq!(line.matches("=3").count(), 18, "{line}");
        assert!(
            line.ends_with(" stopped=no_slot"),
            "the worse seat reason wins: {line}"
        );
    }

    #[test]
    fn payload_identity_needs_both_ids() {
        let d = Uuid::from_u128(1);
        let e = Uuid::from_u128(2);
        let payload =
            serde_json::json!({"reasoning_domain_id": d.to_string(), "evidence_id": e.to_string()});
        assert_eq!(payload_identity(&payload), Some((d, e)));
        assert_eq!(
            payload_identity(&serde_json::json!({"evidence_id": e.to_string()})),
            None
        );
        assert_eq!(payload_identity(&serde_json::json!({})), None);
    }

    #[test]
    fn memory_content_carries_the_card_fields() {
        let content = memory_content("New services must expose a health endpoint.");
        assert_eq!(
            content["key_claim"],
            "New services must expose a health endpoint."
        );
        assert_eq!(
            content["title"],
            "New services must expose a health endpoint."
        );
        let long = memory_content(&"x".repeat(200));
        assert_eq!(long["title"].as_str().map(str::len), Some(80));
    }

    #[test]
    fn rejection_reasons_match_the_metrics_registry_labels() {
        assert_eq!(
            rejection_reason(CandidateRejection::OriginAuthorityCeiling),
            "origin_authority_ceiling"
        );
        assert_eq!(
            rejection_reason(CandidateRejection::UntrustedInstruction),
            "untrusted_instruction"
        );
    }

    // ADR-0066 D-P: the counter is process-global, so the two tests that read its delta take turns.
    static DNS_PIN_COUNTER: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn transport_retry_with_pins_counts_dns_pin_deferred() {
        let _turn = DNS_PIN_COUNTER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(
            TRANSPORT_CLASS,
            ReasoningProviderError::Transport(String::new()).class()
        );
        let before = humaux_telemetry::metrics::dns_pin_deferred_total();
        count_dns_pin_deferral(
            &Settled::new(JobOutcome::Retry, Some(TRANSPORT_CLASS)),
            true,
        );
        assert_eq!(
            humaux_telemetry::metrics::dns_pin_deferred_total(),
            before + 1,
            "a TRANSPORT retry while a pin is configured is one deferral (ADR-0066 D-P)"
        );
        // Neither another class nor another settle of a TRANSPORT failure is a deferral.
        for settled in [
            Settled::new(JobOutcome::Retry, Some("RETRY_WAIT")),
            Settled::new(JobOutcome::Retry, None),
            Settled::new(JobOutcome::Dead, Some(TRANSPORT_CLASS)),
            Settled::new(JobOutcome::NotReady, Some(TRANSPORT_CLASS)),
        ] {
            count_dns_pin_deferral(&settled, true);
        }
        assert_eq!(
            humaux_telemetry::metrics::dns_pin_deferred_total(),
            before + 1
        );
    }

    #[test]
    fn no_pins_no_count() {
        let _turn = DNS_PIN_COUNTER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = humaux_telemetry::metrics::dns_pin_deferred_total();
        count_dns_pin_deferral(
            &Settled::new(JobOutcome::Retry, Some(TRANSPORT_CLASS)),
            false,
        );
        assert_eq!(
            humaux_telemetry::metrics::dns_pin_deferred_total(),
            before,
            "without a configured pin a TRANSPORT retry is no DNS pin deferral (ADR-0066 D-P)"
        );
    }
}

#[cfg(test)]
mod stage_witness {
    use super::*;
    #[test]
    fn settlement_preserves_lease_loss_over_origin_class() {
        for error in [
            DistillError::StaleInput,
            DistillError::Config(ErrorCode::Internal),
        ] {
            let mut lost = Settled::new(JobOutcome::LeaseLost, None);
            lost.record_origin_error(&error);
            assert_eq!(lost.error, Some(ErrorCode::Conflict));
            let mut done = Settled::new(JobOutcome::Done, None);
            done.record_origin_error(&error);
            assert_eq!(
                done.error,
                Some(match error {
                    DistillError::Config(code) => code,
                    other => stage_class(other.class()),
                })
            );
        }
    }

    #[tokio::test]
    async fn stage_iteration_exports_exact_set() {
        seat_iteration(async { (Ok(Settled::new(JobOutcome::LeaseLost, None)), 0) })
            .await
            .unwrap();
        let mut lost = String::new();
        humaux_telemetry::metrics::render_stage_liveness(&mut lost, &STAGES);
        assert_eq!(
            lost.lines()
                .filter(|l| l.starts_with("stage_last_success_timestamp_seconds{")
                    || l.starts_with("stage_last_error_class{"))
                .collect::<Vec<_>>(),
            [
                "stage_last_success_timestamp_seconds{stage=\"distill_seat\"} 0",
                "stage_last_success_timestamp_seconds{stage=\"distill_lease_renewal\"} 0",
                "stage_last_error_class{stage=\"distill_seat\"} 17",
                "stage_last_error_class{stage=\"distill_lease_renewal\"} 0",
            ]
        );
        seat_iteration(async { (Ok(Settled::new(JobOutcome::Done, None)), 1) })
            .await
            .unwrap();
        lease_iteration(async { Ok(Some(())) }).await.unwrap();
        let mut out = String::new();
        humaux_telemetry::metrics::render_stage_liveness(&mut out, &STAGES);
        let stages: Vec<_> = out
            .lines()
            .filter(|l| l.starts_with("stage_output_count{"))
            .collect();
        assert_eq!(stages.len(), 2);
        assert_eq!(
            stages,
            [
                "stage_output_count{stage=\"distill_seat\"} 1",
                "stage_output_count{stage=\"distill_lease_renewal\"} 1"
            ]
        );
    }
}
