//! `application::partition_retention` — operator use cases for partition lifecycle and retention.
//! Depends-on: crates=[async-trait, serde, time, uuid]; services=[]; env=[]; modules=[application::scheduler]
//! Called-by: [adapters::maintenance_repo, maintenance::bootstrap, maintenance::retention, tests]
//! Invariants: [the authorized adapter owns cutoff, lock, export, drop and audit transaction semantics]
//! Spec: §48.1; §77; ADR-0063 D-F/D-I

use std::path::Path;
use std::time::Duration;

use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::scheduler::PartitionTable;

/// `retention approve`'s receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApproveReceipt {
    /// The new policy row.
    pub policy_id: Uuid,
    /// Its revision: the table_key's next one.
    pub policy_revision: i32,
    /// The `RETENTION_POLICY_APPROVED` §77 row.
    pub audit_event_id: Uuid,
}

/// One leaf `retention create-partitions` created.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CreatedLeaf {
    /// Its table_key.
    pub table_key: &'static str,
    /// Its UTC month start (RFC 3339).
    pub month_start: String,
}

/// `retention create-partitions`' receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CreatePartitionsReceipt {
    /// The leaves this run created (empty: the horizon was already closed, nothing written, no audit row).
    pub created: Vec<CreatedLeaf>,
    /// The `PARTITIONS_CREATED` §77 row when something was created.
    pub audit_event_id: Option<Uuid>,
}

/// One `retention execute` request (ADR-0063 D-I): ids are the only selectors; no table or leaf name is accepted.
#[derive(Debug, Clone)]
pub struct DropRequest<'a> {
    /// The approved policy (must be its table_key's latest, effective, not keep-forever revision).
    pub policy_id: Uuid,
    /// The one leaf to drop; `None` only with `dry_run` (the due-leaf listing).
    pub registry_id: Option<Uuid>,
    /// Where the pre-drop COPY export is written (required, no default).
    pub export_dir: &'a Path,
    /// `lock_timeout` of the whole transaction.
    pub lock_timeout: Duration,
    /// Print what would happen, then roll back.
    pub dry_run: bool,
}

/// A leaf as `control.partition_drop_check` saw it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckedLeaf {
    /// Its registry row.
    pub registry_id: Uuid,
    /// Its schema-qualified name.
    pub leaf: String,
    /// RFC 3339 UTC; `None` = MINVALUE.
    pub lower_bound: Option<String>,
    /// RFC 3339 UTC.
    pub upper_bound: String,
    /// Its row count.
    pub row_count: i64,
}

/// One due leaf of a `--dry-run` listing with its `partition_drop_check` verdict (`ok` or the refusal code).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DueLeaf {
    /// The leaf.
    #[serde(flatten)]
    pub leaf: CheckedLeaf,
    /// `ok` or the refusal code.
    pub verdict: String,
}

/// A drop receipt: the registry row's receipt columns plus what the run executed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DropReceipt {
    /// The leaf that was dropped.
    #[serde(flatten)]
    pub leaf: CheckedLeaf,
    /// The policy it was dropped under.
    pub policy_id: Uuid,
    /// That policy's revision.
    pub policy_revision: i32,
    /// The export file.
    pub export_path: String,
    /// Its sha256 (lowercase hex).
    pub export_sha256: String,
    /// The statements `control.partition_drop` executed (empty when read back from the registry).
    pub statements: Vec<String>,
    /// The `PARTITION_DROPPED` §77 row (`None` when read back from the registry).
    pub audit_event_id: Option<Uuid>,
}

/// What one `retention execute` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropOutcome {
    /// `--dry-run` without `--registry-id`: the due leaves (every attached leaf of the policy's table whose verdict
    /// is not `not_due`), each checked under its own savepoint; nothing written.
    Listed(Vec<DueLeaf>),
    /// `--dry-run --registry-id`: the check passed; the exact statements and the export path a run would use.
    DryRun {
        /// The checked leaf.
        leaf: CheckedLeaf,
        /// `control.partition_drop_statements`, the builder `partition_drop` executes.
        statements: Vec<String>,
        /// The export file a run would write.
        export_path: String,
    },
    /// Exported, detached, dropped, receipted and audited in one transaction.
    Dropped(DropReceipt),
    /// The named row was already DROPPED: its stored receipt (D-I; never the next month).
    AlreadyDropped(DropReceipt),
}

/// Operator evidence carried to the retention audit.
pub struct RetentionAdmin<'a> {
    pub actor: &'a str,
    pub reason: &'a str,
    pub ticket: &'a str,
    pub trace_id: &'a str,
    pub step_up_auth_context: &'a str,
}

/// Whole retention operations; the adapter retains the owner check and the transaction.
#[async_trait::async_trait(?Send)]
pub trait PartitionRetentionPort {
    /// Original operator refusal or infrastructure error.
    type Error;

    /// Write a policy revision and its audit.
    async fn approve_policy(
        &self,
        table: PartitionTable,
        months: Option<i32>,
        effective_at: OffsetDateTime,
        timeout: Duration,
        admin: RetentionAdmin<'_>,
    ) -> Result<ApproveReceipt, Self::Error>;

    /// Extend the partition horizon and audit the changes.
    async fn extend_horizon(
        &self,
        months_ahead: i32,
        timeout: Duration,
        admin: RetentionAdmin<'_>,
    ) -> Result<CreatePartitionsReceipt, Self::Error>;

    /// Check, preview or execute the named partition drop.
    async fn execute_retention(
        &self,
        request: &DropRequest<'_>,
        admin: RetentionAdmin<'_>,
    ) -> Result<DropOutcome, Self::Error>;
}

/// Approve a retention policy. Returns the original adapter error on failure.
pub async fn approve<P: PartitionRetentionPort>(
    port: &P,
    table: PartitionTable,
    months: Option<i32>,
    effective_at: OffsetDateTime,
    timeout: Duration,
    admin: RetentionAdmin<'_>,
) -> Result<ApproveReceipt, P::Error> {
    port.approve_policy(table, months, effective_at, timeout, admin)
        .await
}

/// Extend the horizon. Returns the original adapter error on failure.
pub async fn create_partitions<P: PartitionRetentionPort>(
    port: &P,
    months_ahead: i32,
    timeout: Duration,
    admin: RetentionAdmin<'_>,
) -> Result<CreatePartitionsReceipt, P::Error> {
    port.extend_horizon(months_ahead, timeout, admin).await
}

/// Run retention. Returns the original adapter error on failure.
pub async fn execute<P: PartitionRetentionPort>(
    port: &P,
    request: &DropRequest<'_>,
    admin: RetentionAdmin<'_>,
) -> Result<DropOutcome, P::Error> {
    port.execute_retention(request, admin).await
}
