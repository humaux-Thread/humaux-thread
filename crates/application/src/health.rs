//! `application::health` — read-only operations health sampling boundary (ADR-0130 D2/D5).
//! Depends-on: crates=[async-trait, humaux-domain, time]; services=[]; env=[]; modules=[domain::ticket_family]
//! Called-by: [adapters::health, admin::probe, maintenance::health_serve, tests]
//! Invariants: [one aggregate read; database watermark preserved; no job claim, lease or restore writes]
//! Spec: §41.2; §78.2; ADR-0061 D-D; ADR-0130 D2/D5

use humaux_domain::ticket_family::TicketFamily;
use time::OffsetDateTime;

/// Finalized reservation outcomes in the operational sampling contract (§78.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalizedOutcome {
    /// Successfully finalized reservation.
    Success,
    /// Failed reservation.
    Failed,
    /// Denied reservation.
    Denied,
}

/// Read-only operational aggregates and their database-clock watermark (ADR-0061 D-D).
#[derive(Debug, Clone, PartialEq)]
pub struct ObservedHealth {
    /// The database `now()` the sample was taken at; the next call's `since` (the finalized watermark).
    pub as_of: OffsetDateTime,
    /// `ops.jobs` rows in PENDING.
    pub jobs_pending: u64,
    /// `ops.jobs` rows in PROCESSING.
    pub jobs_processing: u64,
    /// `ops.jobs` rows in WAITING_KEY.
    pub jobs_waiting_key: u64,
    /// `ops.jobs` rows in DEAD.
    pub jobs_dead: u64,
    /// Seconds since the oldest PENDING job was created, 0 when none.
    pub oldest_pending_age_seconds: f64,
    /// Σ `issued_highwater - projection_highwater` over every stream.
    pub projection_lag_events: u64,
    /// `projection.processing_gaps` rows per ticket family (families with no gap are absent).
    pub processing_gaps: Vec<(TicketFamily, u64)>,
    /// Open reservations reserved ≤ 10 s ago.
    pub reserved_le_10s: u64,
    /// Open reservations reserved > 10 s and ≤ 60 s ago.
    pub reserved_le_60s: u64,
    /// Open reservations reserved > 60 s ago (§53.5 INV-3).
    pub reserved_gt_60s: u64,
    /// Rows with `since < finalized_at <= as_of`, per outcome (outcomes with none are absent).
    pub finalized_since: Vec<(FinalizedOutcome, u64)>,
    /// ACTIVE tenants with an API key used in the last 24 hours, counted per tenant (M22-2).
    pub tenants_active_1d: u64,
    /// The same over the last 168 hours (7 days).
    pub tenants_active_7d: u64,
}

/// Aggregate health read; database details and decoding stay inside the adapter.
#[async_trait::async_trait]
pub trait HealthSnapshotPort: Send + Sync {
    /// Read aggregates finalized after `since`, retaining the database `as_of` watermark.
    async fn read_health(&self, since: OffsetDateTime) -> Result<ObservedHealth, String>;
}

/// Sample operational health once; the resident entry owns timeout, publication and freshness.
///
/// # Errors
/// Returns the adapter's original operator-facing read failure text (ADR-0061 D-D).
pub async fn sample(
    port: &dyn HealthSnapshotPort,
    since: OffsetDateTime,
) -> Result<ObservedHealth, String> {
    port.read_health(since).await
}

/// One stream family's rows of `ops.admin_probe_snapshot()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFamilyLag {
    /// The family the `(domain, projection_kind)` pair names.
    pub family: TicketFamily,
    /// `projection.stream_checkpoints` rows of the family.
    pub streams: u64,
    /// Rows with `projection_highwater < issued_highwater`.
    pub lagging: u64,
    /// Σ `issued_highwater - projection_highwater`.
    pub lag_total: u64,
    /// max `issued_highwater - projection_highwater`.
    pub lag_max: u64,
}

/// One `ops.admin_probe_snapshot()` row: the §4.4 `stream.watermark` / `outbox.backlog` / `jobs.stuck` inputs.
#[derive(Debug, Clone, PartialEq)]
pub struct AdminProbeSample {
    /// The database `now()` of the read.
    pub as_of: OffsetDateTime,
    /// Per stream family (families with no checkpoint row are absent).
    pub streams: Vec<StreamFamilyLag>,
    /// `ops.outbox` rows.
    pub outbox_total: u64,
    /// `ops.outbox` rows in PENDING or PROCESSING.
    pub outbox_undelivered: u64,
    /// Seconds since the oldest undelivered row was created; `None` when nothing is undelivered.
    pub outbox_oldest_undelivered_age_seconds: Option<f64>,
    /// `ops.jobs` rows.
    pub jobs_total: u64,
    /// PROCESSING rows whose lease has expired.
    pub jobs_stuck: u64,
    /// PROCESSING rows still inside their lease.
    pub jobs_in_lease: u64,
    /// `pg_get_functiondef` of `ops.admin_probe_snapshot()` as deployed when the row was read: the statement the
    /// three DB probes actually ran, so §4.4's `scope_hash` changes with any forward migration that redefines it
    /// (ADR-0061 review-fix 3, F3).
    pub definition: String,
}

/// Cross-tenant aggregates read through the dedicated §4.4 admin snapshot.
#[async_trait::async_trait]
pub trait AdminProbeSnapshotPort: Send + Sync {
    /// Fetch one snapshot with the statement definition used for scope hashing.
    async fn admin_probe_snapshot(&self) -> Result<AdminProbeSample, String>;
}
