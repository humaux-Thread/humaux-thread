//! `application::knowledge_backup::drill_projection` — run-scoped rebuild and receipt decisions (ADR-0064 D-N(g)).
//! Depends-on: crates=[serde_json, uuid]; services=[]; env=[]; modules=[application::knowledge_backup]
//! Called-by: [maintenance::bootstrap, maintenance::drill]
//! Invariants: [only equivalent restored streams can close; an unsettled generation stays open]
//! Spec: ADR-0064 D-E, D-N(g); ADR-0130 D2

use std::future::Future;
use std::time::Duration;

use serde_json::{Value, json};
use uuid::Uuid;

/// Projection operations for the disposable restore. The adapter owns the run and verifier handles.
pub trait DrillProjectionPort {
    /// Original retrieval error.
    type Error: std::fmt::Display;
    /// A stream selected under one restored tenant.
    type Stream;
    /// Open generation and its boundary.
    type Run;
    /// Verifier result, including the fields required to close at H2.
    type Report;

    /// List a tenant's restored streams.
    fn streams(&self, tenant: Uuid)
    -> impl Future<Output = Result<Vec<Self::Stream>, Self::Error>>;
    /// Return legacy count or the original precheck refusal.
    fn precheck(
        &self,
        stream: &Self::Stream,
    ) -> impl Future<Output = Result<Result<i64, Value>, Self::Error>>;
    /// Open or resume a run.
    fn open(&self, stream: &Self::Stream) -> impl Future<Output = Result<Self::Run, Self::Error>>;
    /// Ensure the stream's collection at its pinned dimension.
    fn ensure_collection(
        &self,
        stream: &Self::Stream,
    ) -> impl Future<Output = Result<(), Self::Error>>;
    /// Issue stored-vector tickets only.
    fn issue(
        &self,
        stream: &Self::Stream,
        run: &Self::Run,
    ) -> impl Future<Output = Result<i64, Self::Error>>;
    /// Wait using the closed worker restricted to this run.
    fn wait(
        &self,
        stream: &Self::Stream,
        run: &Self::Run,
        timeout: Duration,
    ) -> impl Future<Output = Result<bool, Self::Error>>;
    /// Verify the settled generation with its orphan step.
    fn verify_run(
        &self,
        stream: &Self::Stream,
        run: &Self::Run,
    ) -> impl Future<Output = Result<(Self::Report, u64), Self::Error>>;
    /// Obtain evidence of a generation still in flight.
    fn verify_stream(
        &self,
        stream: &Self::Stream,
        run: &Self::Run,
    ) -> impl Future<Output = Result<Self::Report, Self::Error>>;
    /// Close at the checked boundary, preserving the named refusal.
    fn close(
        &self,
        stream: &Self::Stream,
        run: &Self::Run,
        report: &Self::Report,
    ) -> impl Future<Output = Result<Result<(), String>, Self::Error>>;
    /// The identifiers used in the receipt.
    fn identity(run: &Self::Run) -> (Uuid, i32);
    /// Project the verifier's equivalence verdict.
    fn equivalent(report: &Self::Report) -> bool;
    /// The evidence persisted at close.
    fn evidence(report: &mut Self::Report) -> &mut Value;
    /// The number of attempts at the closed provider face.
    fn provider_calls(&self) -> u64;
}

/// Rebuild one restored stream without embedding (D-E steps 1–7).
async fn rebuild_one<P: DrillProjectionPort>(
    port: &P,
    stream: &P::Stream,
    wait: Duration,
) -> Result<(bool, Value), P::Error> {
    if let Err(receipt) = port.precheck(stream).await? {
        return Ok((false, receipt));
    }
    let run = port.open(stream).await?;
    port.ensure_collection(stream).await?;
    let issued = port.issue(stream, &run).await?;
    let settled = port.wait(stream, &run, wait).await?;
    let (mut report, orphans) = if settled {
        port.verify_run(stream, &run).await?
    } else {
        let mut report = port.verify_stream(stream, &run).await?;
        P::evidence(&mut report)["verdict"] = json!("cannot_establish");
        (report, 0)
    };
    let mut equivalent = settled && P::equivalent(&report);
    let (id, generation) = P::identity(&run);
    let evidence = P::evidence(&mut report);
    evidence["run_id"] = json!(id.to_string());
    evidence["generation"] = json!(generation);
    evidence["issued"] = json!(issued);
    evidence["orphans_deleted"] = json!(orphans);
    if equivalent {
        match port.close(stream, &run, &report).await? {
            Ok(()) => P::evidence(&mut report)["closed"] = json!(true),
            Err(reason) => {
                equivalent = false;
                let evidence = P::evidence(&mut report);
                evidence["verdict"] = json!("cannot_establish");
                evidence["close_refused"] = json!(reason);
            }
        }
    }
    Ok((equivalent, P::evidence(&mut report).take()))
}

/// The rebuild's sums over every stream report (D-N(g) evidence and receipt columns).
#[derive(Default)]
pub struct Totals {
    streams: Vec<Value>,
    equivalent: bool,
    points: i64,
    legacy: i64,
    orphans: i64,
    unprojected: i64,
    pending: i64,
    provider_calls: u64,
}

impl Totals {
    fn add(&mut self, equivalent: bool, report: Value) {
        let n = |k: &str| report[k].as_i64().unwrap_or(0);
        self.equivalent &= equivalent;
        self.points += n("points");
        self.legacy += n("legacy_points_without_vector");
        self.orphans += n("orphans_deleted");
        self.unprojected += report["excluded"]["without_stored_vector"]
            .as_i64()
            .unwrap_or(0);
        self.pending += report["excluded"]["distill_pending"].as_i64().unwrap_or(0);
        self.streams.push(report);
    }
}

impl Totals {
    /// Neutral receipt before the first stream is examined.
    pub fn empty() -> Self {
        Self {
            equivalent: true,
            ..Self::default()
        }
    }

    /// Apply D-N(g) evidence to the final receipt and its JSON projection.
    pub fn record(self, receipt: &mut super::DrillReceipt) -> Value {
        receipt.rebuild_equivalent = Some(self.equivalent);
        receipt.rebuild_points = Some(self.points);
        receipt.legacy_points_without_vector = Some(self.legacy);
        receipt.unprojected_at_target = Some(self.unprojected);
        receipt.provider_calls = Some(i64::try_from(self.provider_calls).unwrap_or(i64::MAX));
        json!({
            "streams": self.streams,
            "equivalent": self.equivalent,
            "points": self.points,
            "orphans_deleted": self.orphans,
            "distill_pending_inputs": self.pending,
            "unprojected_at_target": self.unprojected,
            "provider_calls": self.provider_calls,
        })
    }
}

/// Process tenants and streams in source order, stopping at the first technical failure.
pub async fn rebuild<P: DrillProjectionPort>(
    port: &P,
    tenants: &[Uuid],
    wait: Duration,
) -> Result<Totals, String> {
    let mut totals = Totals::empty();
    for tenant in tenants {
        for stream in port
            .streams(*tenant)
            .await
            .map_err(|e| format!("infra:streams: {e}"))?
        {
            let (equivalent, report) = rebuild_one(port, &stream, wait)
                .await
                .map_err(|e| format!("infra:rebuild: {e}"))?;
            totals.add(equivalent, report);
        }
    }
    totals.provider_calls = port.provider_calls();
    Ok(totals)
}
