//! `application::projection_maintenance` — projection rebuild/verification boundary (ADR-0130 step 7).
//! Depends-on: crates=[async-trait, humaux-projection, serde_json, uuid]; services=[]; env=[]; modules=[projection::stream]
//! Called-by: [adapters::rebuild, maintenance::rebuild_cli]
//! Invariants: [adapter retains generation transactions; no serving switch or job lease changes]
//! Spec: §16.3; ADR-0064 D-E/D-F; ADR-0068

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use humaux_projection::stream::StreamKey;
use serde_json::Value;
use uuid::Uuid;

/// Operator-selected tenant/workspace scope.
pub enum Scope {
    /// One tenant, optionally narrowed to a workspace.
    One {
        tenant: Uuid,
        workspace: Option<Uuid>,
    },
    /// Every tenant.
    All,
}

/// Stream identity and its placement collection.
pub struct Stream {
    /// Trusted projector stream key.
    pub key: StreamKey,
    /// Placement collection.
    pub collection: String,
}

/// Closed rebuild verdict set (0233 CHECK).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// All comparisons hold.
    Equivalent,
    /// A comparison failed.
    NotEquivalent,
    /// Explicit re-embedding consent is required.
    ReEmbedRequired,
    /// Completion cannot be established.
    CannotEstablish,
}

/// Per-stream operator receipt.
pub struct StreamOutcome {
    /// Verified verdict.
    pub verdict: Verdict,
    /// Whether the operation was refused.
    pub refused: bool,
    /// Original receipt, unchanged.
    pub receipt: Value,
}

/// Work performed while generation tickets settle.
pub type Pump<'a> = dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> + Sync + 'a;

/// Explicit operator bounds, without defaults (§78.1).
pub struct RebuildOptions<'p, 'a> {
    /// Ticket batch size.
    pub batch: i32,
    /// Maximum wait.
    pub wait: Duration,
    /// Explicit legacy re-embedding consent.
    pub allow_reembed: Option<u64>,
    /// Stored-vector-only mode.
    pub require_stored_vector: bool,
    /// Poll callback.
    pub pump: &'p Pump<'a>,
}

/// Backfill receipt and refusal count.
pub struct BackfillReport {
    /// Original receipt.
    pub json: Value,
    /// Unregistered points, left untouched.
    pub strays: u64,
}

/// Whole projection maintenance operations; SQL and transaction ownership stay in the adapter.
#[async_trait::async_trait]
pub trait ProjectionMaintenancePort: Send + Sync {
    /// Preserve the original operator error classification.
    type Error: Send;
    /// Resolve the requested serving streams.
    async fn streams(&self, scope: &Scope) -> Result<Vec<Stream>, Self::Error>;
    /// Rebuild one stream with the existing generation protocol.
    async fn rebuild(
        &self,
        stream: &Stream,
        options: &RebuildOptions<'_, '_>,
    ) -> Result<StreamOutcome, Self::Error>;
    /// Compare PG and projection without writing.
    async fn verify(&self, stream: &Stream) -> Result<StreamOutcome, Self::Error>;
    /// Backfill registered memory identifiers.
    async fn backfill(&self, stream: &Stream) -> Result<BackfillReport, Self::Error>;
}

/// Resolve scope through the projection maintenance boundary.
/// # Errors
/// Preserves adapter errors.
pub async fn streams<P: ProjectionMaintenancePort>(
    port: &P,
    scope: &Scope,
) -> Result<Vec<Stream>, P::Error> {
    port.streams(scope).await
}

/// Rebuild one stream (ADR-0064 D-E).
/// # Errors
/// Preserves adapter errors.
pub async fn rebuild<P: ProjectionMaintenancePort>(
    port: &P,
    stream: &Stream,
    options: &RebuildOptions<'_, '_>,
) -> Result<StreamOutcome, P::Error> {
    port.rebuild(stream, options).await
}

/// Verify one stream (ADR-0064 D-F).
/// # Errors
/// Preserves adapter errors.
pub async fn verify<P: ProjectionMaintenancePort>(
    port: &P,
    stream: &Stream,
) -> Result<StreamOutcome, P::Error> {
    port.verify(stream).await
}

/// Backfill registered memory identifiers (ADR-0068).
/// # Errors
/// Preserves adapter errors.
pub async fn backfill<P: ProjectionMaintenancePort>(
    port: &P,
    stream: &Stream,
) -> Result<BackfillReport, P::Error> {
    port.backfill(stream).await
}
