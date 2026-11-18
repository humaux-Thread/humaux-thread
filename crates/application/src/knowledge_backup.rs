//! `application::knowledge_backup` — backup verification receipts and read-only status facts (ADR-0064, ADR-0130).
//! Depends-on: crates=[async-trait, time, uuid]; services=[]; env=[]; modules=[]
//! Called-by: [adapters::maintenance_repo, maintenance::backup]
//! Invariants: [each verification appends one receipt; status observes one read-only snapshot]
//! Spec: §44; ADR-0064 D-J, D-V

use time::OffsetDateTime;
use uuid::Uuid;

/// One `ops.backup_receipts` row as a backup arm writes it. The arm CLAIMS `VERIFIED` by leaving `failure` empty;
/// the table refuses the claim unless verify exited 0 and the verified manifest is the label's first-verified one
/// (`backup_receipts_verified_derived`, FK to `ops.backup_sets`) and the row is shaped (`backup_receipts_shape`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackupReceipt {
    /// pgBackRest's set label; `None` for a refusal before any write (10.11 A).
    pub backup_label: Option<String>,
    /// The set's start / stop as pgBackRest's `info` reports them.
    pub backup_started_at: Option<OffsetDateTime>,
    /// See `backup_started_at`.
    pub backup_stopped_at: Option<OffsetDateTime>,
    /// sha256 of the set's `backup.manifest` pulled back now with `repo-get`.
    pub manifest_sha256: Option<Vec<u8>>,
    /// `pgbackrest verify --set` exit code; `None` when verify did not run.
    pub verify_exit: Option<i32>,
    /// The manifest sha256 this verification proved: set only when every verify step passed.
    pub verified_manifest_sha256: Option<Vec<u8>>,
    /// The named failure; `None` claims VERIFIED.
    pub failure: Option<String>,
    /// Live `du -sk` of the repository (backup arms only; D-K reads the newest non-NULL one).
    pub repo_bytes: Option<i64>,
    /// Live `df -Pk` free bytes of the repository filesystem.
    pub repo_free_bytes: Option<i64>,
    /// The set's repository size from `info` (`backup[].info.repository.size`, spike SP-11).
    pub set_repo_bytes: Option<i64>,
    /// `HUMAUX_MAINTENANCE_BACKUP_REPO_MAX_BYTES` as the arm used it (10.11 C: the daemon reads no budget key).
    pub repo_max_bytes: Option<i64>,
    /// `HUMAUX_MAINTENANCE_BACKUP_MIN_FREE_BYTES` as the arm used it.
    pub min_free_bytes: Option<i64>,
    /// The D-V estimate the budget precheck used.
    pub estimate_bytes: Option<i64>,
}

/// The latest verification verdict of one backup set (the newest receipt under its label).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetVerdict {
    /// pgBackRest's set label.
    pub label: String,
    /// The newest receipt of the label is VERIFIED.
    pub verified: bool,
    /// The set's start as the receipt recorded it.
    pub started_at: Option<OffsetDateTime>,
    /// The set's stop as the receipt recorded it.
    pub stopped_at: Option<OffsetDateTime>,
}

/// What `backup status` reads from the database, in one READ ONLY snapshot (status writes nothing, T-J4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupStatusFacts {
    /// Every labelled set's latest verdict (D-K's `latest` CTE: `DISTINCT ON (backup_label)`, newest first).
    pub sets: Vec<SetVerdict>,
    /// The oldest `ops.wal_archive_failures` row newer than the newest VERIFIED start (10.11 D's `v`): the latch.
    pub latched_since: Option<OffsetDateTime>,
    /// The newest `ops.wal_archive_failures` row (the PITR window starts after it, 10.11 E).
    pub newest_failure: Option<OffsetDateTime>,
    /// `pg_stat_archiver.last_failed_time` when it is newer than `last_archived_time`: failing right now.
    pub failing_now_since: Option<OffsetDateTime>,
}

/// Append-only receipt storage and the operator's read-only status snapshot.
#[async_trait::async_trait(?Send)]
pub trait BackupEvidencePort {
    /// Preserve database errors, including rejected verification claims.
    type Error;

    /// Append the claimed outcome and let the database enforce the verified manifest binding.
    async fn append_receipt(&self, receipt: &BackupReceipt) -> Result<Uuid, Self::Error>;

    /// Read all status facts in the adapter's read-only transaction.
    async fn status_snapshot(&self) -> Result<BackupStatusFacts, Self::Error>;
}

/// Record one backup attempt (§44, ADR-0064 D-J).
pub async fn record_receipt<P: BackupEvidencePort>(
    port: &P,
    receipt: &BackupReceipt,
) -> Result<Uuid, P::Error> {
    port.append_receipt(receipt).await
}

/// Obtain the facts used by the operator's status report (ADR-0064 10.11 E).
pub async fn read_status<P: BackupEvidencePort>(port: &P) -> Result<BackupStatusFacts, P::Error> {
    port.status_snapshot().await
}
