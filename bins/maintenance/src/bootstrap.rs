//! `maintenance::bootstrap` — Wires maintenance operator adapters from process configuration (ADR-0130 D2).
//! Depends-on: crates=[humaux-adapters, humaux-application, humaux-domain, serde_json, tokio, uuid]; services=[]; env=[HUMAUX_MAINTENANCE_EMBEDDING_DIMENSION, HUMAUX_MAINTENANCE_PRIVATE_MEMORY_COLLECTION, HUMAUX_MAINTENANCE_QDRANT_CIDR,
//!   HUMAUX_MAINTENANCE_QDRANT_HOST, HUMAUX_MAINTENANCE_QDRANT_PORT]; modules=[adapters::maintenance_repo, adapters::postgres, adapters::projection_worker, adapters::provisioning, adapters::qdrant, adapters::reasoning_route_onboarding, adapters::rebuild,
//!   adapters::stream_repo, application::knowledge_backup::drill_projection, application::operator_provisioning, application::reasoning_route_admin,
//!   domain::egress, maintenance::main]
//! Called-by: [maintenance::drill, maintenance::main, maintenance::rebuild_cli]
//! Invariants: [construction only; the application ports drive all operations]
//! Spec: ADR-0053; ADR-0130 D2 / SLICE-15c

use humaux_adapters::maintenance_repo;
use humaux_adapters::postgres::{MaintenanceDbPool, RetrievalWorkerDbPool};
use humaux_adapters::projection_worker::{PassConfig, SharedProjectionDeps};
use humaux_adapters::provisioning::{self, ProvisioningError};
use humaux_adapters::provisioning::{QdrantFace, WorkspaceActivationAdapter};
use humaux_adapters::qdrant::RetrievalFamily;
use humaux_adapters::reasoning_route_onboarding::ReasoningRouteAdapter;
use humaux_adapters::rebuild::{
    self, NoProviderEmbedder, RebuildDeps, ScannerPin, Stream, Verdict, WorkerLabel,
};
use humaux_adapters::stream_repo::{Backoff, ClaimFamily};
use humaux_application::knowledge_backup::drill_projection::DrillProjectionPort;
use humaux_application::operator_provisioning::{
    CollectionProvisioningPort, WorkspaceActivationPort,
};
use humaux_domain::egress::ProcessorId;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use humaux_application::reasoning_route_admin::ReasoningRoutePort;
use serde_json::Value;

use crate::{Result, env, env_parsed};

/// The Qdrant face and the collection/dimension every onboarding step uses.
pub(super) struct Qdrant {
    face: QdrantFace,
    pub(super) collection: String,
    pub(super) dimension: u32,
}

pub(super) fn qdrant() -> Result<Qdrant> {
    let face = QdrantFace::new(
        &env("HUMAUX_MAINTENANCE_QDRANT_HOST")?,
        env_parsed("HUMAUX_MAINTENANCE_QDRANT_PORT")?,
        &env("HUMAUX_MAINTENANCE_QDRANT_CIDR")?,
    )?;
    Ok(Qdrant {
        face,
        collection: env("HUMAUX_MAINTENANCE_PRIVATE_MEMORY_COLLECTION")?,
        dimension: env_parsed("HUMAUX_MAINTENANCE_EMBEDDING_DIMENSION")?,
    })
}
impl Qdrant {
    pub(super) fn collection_port(&self) -> &impl CollectionProvisioningPort {
        &self.face
    }

    pub(super) fn activation_port<'a>(
        &'a self,
        pool: &'a MaintenanceDbPool,
    ) -> impl WorkspaceActivationPort + 'a {
        WorkspaceActivationAdapter::new(pool, &self.face)
    }
}

/// Binds the reasoning route port without opening another connection.
pub(super) fn reasoning_routes(
    pool: &MaintenanceDbPool,
) -> impl ReasoningRoutePort<Extras = Value> + '_ {
    ReasoningRouteAdapter::new(pool)
}

/// D-M: the drill's egress identity. The closed no-provider deps never disclose anything, so no ledger row carries it.
const DRILL_PROCESSOR: Uuid = Uuid::from_u128(0x0c37_d211_0000_0000_0000_0000_0000_0001);
/// The drill's in-process pass: one claimer, its own run's tickets only (D-N(g)).
// ponytail: fixed knobs (issue/claim batch 50, lease 60 s, 3 attempts, 1–2 s backoff, 50 ms between passes) — the
// run-scoped pass has no competitor, so they only bound a stuck pass; read the worker's keys if a drill ever
// shares its tickets with a resident worker.
const PASS_BATCH: i32 = 50;
const PASS_LEASE_SECS: f64 = 60.0;
const PASS_MAX_ATTEMPTS: i32 = 3;
const PASS_BACKOFF_SECS: (f64, f64) = (1.0, 2.0);
const PASS_PAUSE: Duration = Duration::from_millis(50);

/// The drill's in-process pass (D-N(g)): the private-memory claim (`TicketFamily::ALL` has one member) under a
/// lease owner naming the drill.
pub(super) fn pass_config(id: Uuid) -> Option<PassConfig> {
    Some(PassConfig {
        claim: ClaimFamily::of(RetrievalFamily::PrivateMemoryV1)?,
        lease_owner: format!("humaux-maintenance-drill/{id}"),
        lease_secs: PASS_LEASE_SECS,
        batch: i64::from(PASS_BATCH),
        per_tenant_cap: i64::from(PASS_BATCH),
        max_attempts: PASS_MAX_ATTEMPTS,
        backoff: Backoff {
            base_secs: PASS_BACKOFF_SECS.0,
            max_secs: PASS_BACKOFF_SECS.1,
        },
    })
}

/// Restored worker label and its loopback-only Qdrant client.
pub(super) struct DrillTarget {
    worker: WorkerLabel,
    face: QdrantFace,
}

pub(super) fn drill_target(
    worker: WorkerLabel,
    port: u16,
) -> std::result::Result<DrillTarget, ProvisioningError> {
    Ok(DrillTarget {
        worker,
        face: QdrantFace::new("127.0.0.1", port, "127.0.0.1/32")?,
    })
}

impl DrillTarget {
    pub(super) async fn collections(&self) -> std::result::Result<Vec<String>, ProvisioningError> {
        rebuild::collection_names(&self.face).await
    }

    pub(super) fn closed_pass(
        &self,
        pool: RetrievalWorkerDbPool,
        port: u16,
        scanner: ScannerPin,
        label: &str,
    ) -> std::result::Result<(SharedProjectionDeps, Arc<NoProviderEmbedder>), ProvisioningError>
    {
        rebuild::drill_closed_deps(
            pool,
            port,
            &scanner,
            label,
            self.worker.dimension,
            ProcessorId(DRILL_PROCESSOR),
            Arc::new(|period| Box::pin(tokio::time::sleep(period))),
        )
        .map(rebuild::drill_projection_deps)
    }

    pub(super) fn projection<'a>(
        &'a self,
        maintenance: &'a MaintenanceDbPool,
        reader: &'a RetrievalWorkerDbPool,
        pass: (SharedProjectionDeps, Arc<NoProviderEmbedder>),
        cfg: PassConfig,
    ) -> impl DrillProjectionPort<Error = ProvisioningError> + 'a {
        Projection {
            deps: RebuildDeps {
                maintenance,
                reader,
                qdrant: &self.face,
                worker: &self.worker,
            },
            shared: pass.0,
            provider: pass.1,
            cfg,
        }
    }
}

pub(super) fn scanner_pin(executable: String, version: String, sha256: String) -> ScannerPin {
    ScannerPin {
        executable: executable.into(),
        version,
        sha256,
    }
}

pub(super) async fn drill_worker(
    pool: &MaintenanceDbPool,
    label: &str,
) -> std::result::Result<WorkerLabel, ProvisioningError> {
    rebuild::worker_label(pool, label).await
}

pub(super) async fn drill_tenants(
    pool: &MaintenanceDbPool,
) -> std::result::Result<Vec<Uuid>, ProvisioningError> {
    rebuild::all_tenants(pool, tenant_page_reader()).await
}

pub(super) fn tenant_page_reader() -> rebuild::TenantPageReadPort {
    |pool, after, limit| {
        Box::pin(async move { Ok(maintenance_repo::tenant_page(pool, after, limit).await?) })
    }
}

struct Projection<'a> {
    deps: RebuildDeps<'a>,
    shared: SharedProjectionDeps,
    provider: Arc<NoProviderEmbedder>,
    cfg: PassConfig,
}

impl DrillProjectionPort for Projection<'_> {
    type Error = ProvisioningError;
    type Stream = Stream;
    type Run = rebuild::Run;
    type Report = rebuild::Report;
    async fn streams(&self, tenant: Uuid) -> std::result::Result<Vec<Stream>, Self::Error> {
        rebuild::streams(self.deps.maintenance, tenant, None).await
    }
    async fn precheck(
        &self,
        stream: &Stream,
    ) -> std::result::Result<std::result::Result<i64, Value>, Self::Error> {
        rebuild::precheck(&self.deps, stream, None).await
    }
    async fn open(&self, stream: &Stream) -> std::result::Result<Self::Run, Self::Error> {
        rebuild::open_run(&self.deps, stream).await
    }
    async fn ensure_collection(&self, stream: &Stream) -> std::result::Result<(), Self::Error> {
        provisioning::ensure_collection(
            self.deps.qdrant,
            &stream.collection,
            self.deps.worker.dimension,
        )
        .await
        .map(|_| ())
    }
    async fn issue(
        &self,
        stream: &Stream,
        run: &Self::Run,
    ) -> std::result::Result<i64, Self::Error> {
        rebuild::issue_tickets(&self.deps, stream, run, PASS_BATCH, true).await
    }
    async fn wait(
        &self,
        stream: &Stream,
        run: &Self::Run,
        timeout: Duration,
    ) -> std::result::Result<bool, Self::Error> {
        rebuild::wait_drill_generation(
            &self.deps,
            stream,
            run,
            &self.shared,
            &self.cfg,
            timeout,
            PASS_PAUSE,
        )
        .await
    }
    async fn verify_run(
        &self,
        stream: &Stream,
        run: &Self::Run,
    ) -> std::result::Result<(Self::Report, u64), Self::Error> {
        rebuild::verify_run(&self.deps, stream, run, true).await
    }
    async fn verify_stream(
        &self,
        stream: &Stream,
        run: &Self::Run,
    ) -> std::result::Result<Self::Report, Self::Error> {
        rebuild::verify_stream(&self.deps, stream, Some(run.run_id), true).await
    }
    async fn close(
        &self,
        stream: &Stream,
        run: &Self::Run,
        report: &Self::Report,
    ) -> std::result::Result<std::result::Result<(), String>, Self::Error> {
        match rebuild::close_run(&self.deps, stream, run, report).await {
            Ok(()) => Ok(Ok(())),
            Err(ProvisioningError::Refused(reason)) => Ok(Err(reason)),
            Err(
                e @ (ProvisioningError::Db(_)
                | ProvisioningError::Qdrant(_)
                | ProvisioningError::InvalidInput(_)),
            ) => Err(e),
        }
    }
    fn identity(run: &Self::Run) -> (Uuid, i32) {
        (run.run_id, run.generation)
    }
    fn equivalent(report: &Self::Report) -> bool {
        report.verdict == Verdict::Equivalent
    }
    fn evidence(report: &mut Self::Report) -> &mut Value {
        &mut report.json
    }
    fn provider_calls(&self) -> u64 {
        self.provider.attempts()
    }
}
