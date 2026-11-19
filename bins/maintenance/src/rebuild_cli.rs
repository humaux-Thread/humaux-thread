//! `maintenance::rebuild_cli` — the one-shot arms `projection rebuild`, `projection verify` (ADR-0064 D-E, D-F) and
//!   `projection backfill-memory-id` (ADR-0068 40d-2a): flag parsing, the two pools and the Qdrant face, the
//!   per-stream loop and the one JSON receipt. Every step and every verdict lives in `adapters::rebuild`.
//! Depends-on: crates=[humaux-adapters, humaux-application, serde_json, tokio]; services=[PostgreSQL(role_maintenance),
//!   PostgreSQL(role_retrieval_worker), Qdrant(*)]; env=[HUMAUX_MAINTENANCE_PG_DSN, HUMAUX_MAINTENANCE_QDRANT_CIDR,
//!   HUMAUX_MAINTENANCE_QDRANT_HOST, HUMAUX_MAINTENANCE_QDRANT_PORT, HUMAUX_RETRIEVAL_WORKER_EMBEDDING_VERSION,
//!   HUMAUX_RETRIEVAL_WORKER_PG_DSN]; modules=[adapters::postgres, adapters::rebuild, application::projection_maintenance, maintenance::bootstrap, maintenance::main]
//! Called-by: [maintenance::main]
//! Invariants: [every flag is required with no default except the D-G consent `--allow-reembed` (§78.1); flags are
//!   parsed before any connection (a missing flag is exit 2 with nothing read); exactly one receipt object per stream
//!   in `streams`; exit 0 only when every stream closed (rebuild) or reads (verify) `equivalent`, 3 when any stream
//!   was refused, 1 otherwise; backfill-memory-id exits 0 when no stream has a stray, 3 when any has or none matched, 1 on an error;
//!   `verify` writes nothing; the worker's label, its DSN and the Qdrant face are read
//!   under their own names (the card-35 peer-key precedent), never copied into a maintenance key]
//! Spec: Baseline §16.2; §44; §78.1; ADR-0053 D-F; ADR-0064 D-E; ADR-0064 D-F; ADR-0064 D-G; ADR-0068
//!
//! Why the retrieval worker's DSN: X and the E4 payloads are what the projector builds, and only
//! `role_retrieval_worker` sees every memory of a tenant (0140); `role_maintenance`'s view is narrowed by the
//! visibility and subject policies (0012/0155). See `adapters::rebuild`'s module doc.

use std::time::Duration;

use humaux_adapters::postgres::RetrievalWorkerDbPool;
use humaux_application::projection_maintenance::{
    self as rebuild, ProjectionMaintenancePort, RebuildOptions, Scope, StreamOutcome, Verdict,
};
use serde_json::{Value, json};

use crate::{Args, Failure, Output, Result, env, env_parsed, pool};

/// The worker's label, read under its own name (ADR-0064 D-E step 1).
const WORKER_LABEL: &str = "HUMAUX_RETRIEVAL_WORKER_EMBEDDING_VERSION";
/// The projector's DSN, read under its own name (module doc).
const WORKER_DSN: &str = "HUMAUX_RETRIEVAL_WORKER_PG_DSN";

/// ADR-0064 D-E step 5: the poll step inside the operator's `--wait-seconds` bound while the resident retrieval
/// worker projects the generation (not a schedule; the bound is the operator's).
const POLL: Duration = Duration::from_secs(1);

fn scope(args: &Args) -> Result<Scope> {
    let all = args.0.iter().any(|a| a == "--all");
    match (all, args.get("--tenant")) {
        (true, None) if args.get("--workspace").is_none() => Ok(Scope::All),
        (false, Some(_)) => Ok(Scope::One {
            tenant: args.parsed("--tenant")?,
            workspace: match args.get("--workspace") {
                Some(_) => Some(args.parsed("--workspace")?),
                None => None,
            },
        }),
        _ => Err(Failure::Usage(
            "exactly one of --tenant <uuid> [--workspace <uuid>] or --all".to_owned(),
        )),
    }
}

async fn wiring() -> Result<impl ProjectionMaintenancePort<Error: Into<crate::ProvisioningError>>> {
    let maintenance = pool().await?;
    // dep: PostgreSQL(role_retrieval_worker) — the projector-view reads of the verifier
    let reader = RetrievalWorkerDbPool::connect(&env(WORKER_DSN)?)
        .await
        .map_err(|e| Failure::Infra(format!("connect {WORKER_DSN}: {e}")))?;
    // dep: PostgreSQL(role_maintenance) — the projection maintenance port
    // dep: Qdrant(*) — the operator face assembled inside the adapter
    Ok(humaux_adapters::rebuild::maintenance_port(
        maintenance,
        reader,
        crate::bootstrap::tenant_page_reader(),
        &env("HUMAUX_MAINTENANCE_QDRANT_HOST")?,
        env_parsed("HUMAUX_MAINTENANCE_QDRANT_PORT")?,
        &env("HUMAUX_MAINTENANCE_QDRANT_CIDR")?,
        &env(WORKER_LABEL)?,
    )
    .await?)
}

/// The receipt over every stream object: exit 3 if any refused, 1 if any other was not `equivalent`.
fn receipt(command: &str, outcomes: Vec<StreamOutcome>) -> Output {
    let refused = outcomes.iter().any(|o| o.refused);
    let failed = outcomes
        .iter()
        .any(|o| !o.refused && o.verdict != Verdict::Equivalent);
    let streams: Vec<Value> = outcomes.into_iter().map(|o| o.receipt).collect();
    let mut output = Output::ok(json!({
        "command": command,
        "outcome": if refused { "refused" } else if failed { "not_equivalent" } else { "equivalent" },
        "streams": streams,
    }));
    output.refused = refused;
    output.failed = failed;
    output
}

/// `projection rebuild (--tenant <uuid> [--workspace <uuid>] | --all) --batch <n> --wait-seconds <n>
/// [--allow-reembed <max_points>]` (ADR-0064 D-E).
pub(crate) async fn rebuild(args: &Args) -> Result<Output> {
    let scope = scope(args)?;
    let batch: i32 = args.parsed("--batch")?;
    let wait = Duration::from_secs(args.parsed("--wait-seconds")?);
    if batch <= 0 {
        return Err(Failure::Usage("--batch: must be > 0".to_owned()));
    }
    let allow_reembed: Option<u64> = match args.get("--allow-reembed") {
        Some(_) => Some(args.parsed("--allow-reembed")?),
        None => None,
    };
    let wiring = wiring().await?;
    let pump = || -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(tokio::time::sleep(POLL))
    };
    let opts = RebuildOptions {
        batch,
        wait,
        allow_reembed,
        require_stored_vector: false,
        pump: &pump,
    };
    let mut outcomes = Vec::new();
    for stream in rebuild::streams(&wiring, &scope).await? {
        outcomes.push(rebuild::rebuild(&wiring, &stream, &opts).await?);
    }
    Ok(receipt("projection rebuild", outcomes))
}

/// `projection verify (--tenant <uuid> [--workspace <uuid>] | --all)` (ADR-0064 D-F, read-only).
pub(crate) async fn verify(args: &Args) -> Result<Output> {
    let scope = scope(args)?;
    let wiring = wiring().await?;
    let mut outcomes = Vec::new();
    for stream in rebuild::streams(&wiring, &scope).await? {
        outcomes.push(rebuild::verify(&wiring, &stream).await?);
    }
    Ok(receipt("projection verify", outcomes))
}

/// `projection backfill-memory-id (--tenant <uuid> [--workspace <uuid>] | --all)` (ADR-0068 40d-2a): writes the
/// registry's `memory_id` on every registered point of each stream. Exit 0 when no stream has a stray, 3 when any
/// has (named in its object, left unpatched) or when the scope matched no stream (nothing was backfilled, so the
/// switch gate must not read it as done), 1 on an error.
pub(crate) async fn backfill_memory_id(args: &Args) -> Result<Output> {
    let scope = scope(args)?;
    let wiring = wiring().await?;
    let mut streams = Vec::new();
    let mut strays = 0;
    for stream in rebuild::streams(&wiring, &scope).await? {
        let report = rebuild::backfill(&wiring, &stream).await?;
        strays += report.strays;
        streams.push(report.json);
    }
    let outcome = match (streams.is_empty(), strays > 0) {
        (true, _) => "no_streams",
        (false, true) => "strays",
        (false, false) => "backfilled",
    };
    let mut output = Output::ok(json!({
        "command": "projection backfill-memory-id",
        "outcome": outcome,
        "streams": streams,
    }));
    output.refused = outcome != "backfilled";
    Ok(output)
}
