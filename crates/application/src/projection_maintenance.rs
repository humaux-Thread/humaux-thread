//! `application::projection_maintenance` — projection rebuild/verification and serving-switch boundary (ADR-0130 step 7).
//! Depends-on: crates=[async-trait, humaux-domain, humaux-projection, serde_json, uuid]; services=[]; env=[]; modules=[domain::ids, projection::serving, projection::stream]
//! Called-by: [adapters::rebuild, adapters::retrieve, adapters::serving_repo, maintenance::projection_serve, maintenance::rebuild_cli, maintenance::switch_visible]
//! Invariants: [adapter retains generation and serving-switch transactions; no serving switch or job lease changes]
//! Spec: §15.2; §16.3; ADR-0057 D-C; ADR-0064 D-E/D-F; ADR-0068

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use humaux_domain::ids::{TenantId, WorkspaceId};
use humaux_projection::serving::{ContinuationVerdict, StreamFamily, SwitchRejection};
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

/// [`switch_projection_version`]'s result: either §16.3's three criteria all held and the
/// atomic `UPDATE` committed, or at least one failed and the DB was never touched (§16.3 "任一
/// 为假直接拒绝，不存在『人工判断可以上』的分支" — there is no partial-write state between
/// these two, `Rejected` carries the complete failing-criteria set from `evaluate_switch`, not
/// a per-criterion retry).
#[must_use = "Rejected/TargetVersionMissing mean the switch did NOT happen — silently \
              discarding this hides a real switch failure behind an apparent success"]
#[derive(Debug, PartialEq, Eq)]
pub enum SwitchOutcome {
    /// The atomic switch committed; `new_version` is now the family's sole `serving` row, the
    /// previously-serving row is retired (`serving = false`, row still present as a rollback
    /// target, §16.3).
    Switched,
    /// At least one of §16.3's three criteria failed — carries every failing reason
    /// (`humaux_projection::serving::SwitchRejection`), not just the first.
    Rejected(Vec<SwitchRejection>),
    /// §16.3's three criteria all held, but `new_version` names no row in
    /// `projection.stream_checkpoints` for this family (typo'd version, a shadow row that was
    /// never created, or one deleted concurrently) — the clear-`UPDATE` of the previously
    /// `serving` row is never committed in this case, so the family keeps its prior `serving`
    /// row untouched rather than ending up with zero `serving` rows. Distinct from `Rejected`:
    /// the criteria genuinely held, the target row just does not exist.
    TargetVersionMissing,
}

/// Candidate stream version inputs for the §16.3 ops visible count (ADR-0057 D-C).
pub struct VisibleStreamCandidate<'a> {
    /// The candidate family's tenant.
    pub tenant: TenantId,
    /// The candidate family's workspace (`scope_id`) — the worker stamps it on every point.
    pub workspace: WorkspaceId,
    /// The tenant's §17.3 collection.
    pub collection: &'a str,
    /// The version being promoted — §16.3's `visible(shadow)` side.
    pub candidate_version: &'a str,
    pub candidate_tombstoned: &'a [i64],
    /// The family's current `serving` version, or `None` for an ADR-0017 first activation
    /// (nothing to compare against; `evaluate_switch` accepts a lone shadow read-back there).
    pub serving_version: Option<&'a str>,
    pub serving_tombstoned: &'a [i64],
}

/// §16.3 criterion ①'s `(visible_shadow, visible_serving)` pair, each side tagged with the
/// `projection_version` it was counted against — the exact shape
/// `projection::serving::SwitchCriteria` takes.
pub type VisiblePair = (Option<(String, u64)>, Option<(String, u64)>);

/// Outbound port for the §16.3 visibility-free stream count (ADR-0057 D-C).
#[async_trait::async_trait]
pub trait VisibleStreamCountPort: Send + Sync {
    /// Count all non-tombstoned points for one stream version in Qdrant; `None` if unavailable or empty version.
    async fn count_stream_version(
        &self,
        collection: &str,
        tenant: TenantId,
        workspace: WorkspaceId,
        version: &str,
        tombstoned_seqs: &[i64],
    ) -> Option<u64>;
}

/// §16.3 criterion ①'s two inputs, tagged with the version each was counted against.
pub async fn visible_pair<P: VisibleStreamCountPort + ?Sized>(
    port: &P,
    c: &VisibleStreamCandidate<'_>,
) -> VisiblePair {
    let shadow = port
        .count_stream_version(
            c.collection,
            c.tenant,
            c.workspace,
            c.candidate_version,
            c.candidate_tombstoned,
        )
        .await
        .map(|n| (c.candidate_version.to_string(), n));
    let serving = match c.serving_version {
        Some(v) => port
            .count_stream_version(c.collection, c.tenant, c.workspace, v, c.serving_tombstoned)
            .await
            .map(|n| (v.to_string(), n)),
        None => None,
    };
    (shadow, serving)
}

/// Outbound port for `projection-serve` (§15.2 audited retirement and §16.3 atomic switch).
#[async_trait::async_trait]
pub trait ProjectionServePort: Send + Sync {
    /// Adapter error type.
    type Error: fmt::Display + fmt::Debug + Send;

    /// §15.2 audited retirement (`FAILED -> RETIRED_FAILED`) for an error class on a stream key.
    async fn retire_failed(&self, key: &StreamKey, error_class: &str) -> Result<Vec<i64>, String>;

    /// §16.3 non-discretionary atomic serving switch.
    async fn switch_projection_version(
        &self,
        family: &StreamFamily,
        new_version: &str,
        visible_shadow: Option<(String, u64)>,
        visible_serving: Option<(String, u64)>,
        continuation: ContinuationVerdict,
    ) -> Result<SwitchOutcome, Self::Error>;
}

/// §15.2 audited retirement use case.
/// # Errors
/// Preserves adapter error message.
pub async fn retire_failed<P: ProjectionServePort>(
    port: &P,
    key: &StreamKey,
    error_class: &str,
) -> Result<Vec<i64>, String> {
    port.retire_failed(key, error_class).await
}

/// §16.3 non-discretionary serving switch use case.
/// # Errors
/// Preserves adapter errors.
pub async fn switch_projection_version<P: ProjectionServePort>(
    port: &P,
    family: &StreamFamily,
    new_version: &str,
    visible_shadow: Option<(String, u64)>,
    visible_serving: Option<(String, u64)>,
    continuation: ContinuationVerdict,
) -> Result<SwitchOutcome, P::Error> {
    port.switch_projection_version(
        family,
        new_version,
        visible_shadow,
        visible_serving,
        continuation,
    )
    .await
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
