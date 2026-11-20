//! `adapters::knowledge_backup_repo` — Owns the PostgreSQL backup and restore evidence writes.
//! Depends-on: crates=[humaux-application, sqlx, time]; services=[PostgreSQL(role_maintenance)
//!   r=[ops.backup_receipts, ops.restore_drills, ops.wal_archive_failures]
//!   w=[ops.backup_receipts, ops.backup_sets, ops.restore_drills, ops.restore_witnesses, ops.wal_archive_failures]]; env=[];
//!   modules=[adapters::postgres, application::knowledge_backup]
//! Called-by: [adapters::maintenance_repo]
//! Invariants: [receipt and set writes are append-only; the source witness commits before its WAL file is sampled;
//!   DR evidence reads and latches the same observation in one PostgreSQL statement]
//! Spec: ADR-0064 D-J; ADR-0064 D-K; ADR-0064 D-L; ADR-0064 D-O; ADR-0064 D-V; §44

use humaux_application::knowledge_backup::{
    BackupReceipt, DrEvidence, DrillReceipt, MeasuredBudget,
};
use sqlx::{Row, types::Uuid};
use time::OffsetDateTime;

use crate::postgres::MaintenanceDbPool;

/// ADR-0064 D-V: the next set's estimate is the newest VERIFIED set's repository bytes × 1.25, kept as the exact
/// ratio 5/4. One definition for the backup arm's precheck and the daemon's headroom.
pub const ESTIMATE_RATIO: (i64, i64) = (5, 4);

/// [`ESTIMATE_RATIO`] applied to one set's repository bytes.
pub const fn estimate_from_set_bytes(set_repo_bytes: i64) -> i64 {
    set_repo_bytes * ESTIMATE_RATIO.0 / ESTIMATE_RATIO.1
}

/// Appends one receipt (`backup_type` is always `full` in card 37, D-V); returns its id. A VERIFIED claim the table
/// refuses comes back as the database error (23514 / 23503), never as a quietly FAILED row.
pub async fn insert_backup_receipt(
    pool: &MaintenanceDbPool,
    receipt: &BackupReceipt,
) -> Result<Uuid, sqlx::Error> {
    let outcome = if receipt.failure.is_none() {
        "VERIFIED"
    } else {
        "FAILED"
    };
    // dep: PostgreSQL(role_maintenance) — ops.backup_receipts INSERT (0234)
    sqlx::query_scalar(
        "INSERT INTO ops.backup_receipts (backup_label, backup_type, backup_started_at, backup_stopped_at, \
           manifest_sha256, verify_exit, verified_manifest_sha256, outcome, failure, repo_bytes, repo_free_bytes, \
           set_repo_bytes, repo_max_bytes, min_free_bytes, estimate_bytes) \
         VALUES ($1, 'full', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING receipt_id",
    )
    .bind(&receipt.backup_label)
    .bind(receipt.backup_started_at)
    .bind(receipt.backup_stopped_at)
    .bind(&receipt.manifest_sha256)
    .bind(receipt.verify_exit)
    .bind(&receipt.verified_manifest_sha256)
    .bind(outcome)
    .bind(&receipt.failure)
    .bind(receipt.repo_bytes)
    .bind(receipt.repo_free_bytes)
    .bind(receipt.set_repo_bytes)
    .bind(receipt.repo_max_bytes)
    .bind(receipt.min_free_bytes)
    .bind(receipt.estimate_bytes)
    .fetch_one(pool.pool())
    .await
}

/// ADR-0064 D-J step 2: records `manifest_sha256` as `label`'s identity after its first clean verification; a later
/// call for the same label writes nothing (the first verification stays the identity).
pub async fn bind_backup_set(
    pool: &MaintenanceDbPool,
    label: &str,
    manifest_sha256: &[u8],
) -> Result<(), sqlx::Error> {
    // dep: PostgreSQL(role_maintenance) — ops.backup_sets INSERT (0234)
    sqlx::query(
        "INSERT INTO ops.backup_sets (backup_label, manifest_sha256) VALUES ($1, $2) \
         ON CONFLICT (backup_label) DO NOTHING",
    )
    .bind(label)
    .bind(manifest_sha256)
    .execute(pool.pool())
    .await
    .map(|_| ())
}

/// ADR-0064 10.11 D: the DR_EVIDENCE statement. `last_failed` / `last_archived` override `pg_stat_archiver`'s two
/// columns and exist only for T-K3' (a dev cluster with archiving off cannot fail an archive); production binds
/// `None, None`. A latch row is written when a failure is newer than the newest VERIFIED start `v` and no row since
/// `v` exists ("any failure since the newest VERIFIED start", so a queue-max drop that PostgreSQL counts as archived
/// stays latched); it resolves only when a VERIFIED full starts after it.
pub async fn read_and_latch_dr_evidence(
    pool: &MaintenanceDbPool,
    last_failed: Option<OffsetDateTime>,
    last_archived: Option<OffsetDateTime>,
) -> Result<DrEvidence, sqlx::Error> {
    // dep: PostgreSQL(role_maintenance) — ops.backup_receipts + ops.restore_drills + pg_stat_archiver SELECT,
    // ops.wal_archive_failures SELECT/INSERT (0234), one statement
    let row = sqlx::query(
        "WITH latest AS ( \
           SELECT DISTINCT ON (backup_label) outcome, backup_stopped_at FROM ops.backup_receipts \
           WHERE backup_label IS NOT NULL ORDER BY backup_label, recorded_at DESC), \
         v AS (SELECT coalesce(max(backup_started_at), '-infinity'::timestamptz) AS v \
               FROM ops.backup_receipts WHERE outcome = 'VERIFIED'), \
         a AS (SELECT coalesce($1::timestamptz, last_failed_time) AS last_failed_time, \
                      coalesce($2::timestamptz, last_archived_time) AS last_archived_time FROM pg_stat_archiver), \
         ins AS (INSERT INTO ops.wal_archive_failures (observed_at) \
                 SELECT clock_timestamp() FROM a, v \
                 WHERE a.last_failed_time > v.v \
                   AND NOT EXISTS (SELECT 1 FROM ops.wal_archive_failures f WHERE f.observed_at > v.v) \
                 RETURNING observed_at), \
         measured AS (SELECT repo_bytes, repo_max_bytes, min_free_bytes, estimate_bytes FROM ops.backup_receipts \
                      WHERE repo_bytes IS NOT NULL ORDER BY recorded_at DESC LIMIT 1) \
         SELECT (SELECT extract(epoch FROM max(backup_stopped_at))::float8 FROM latest WHERE outcome = 'VERIFIED'), \
                (SELECT extract(epoch FROM max(finished_at))::float8 FROM ops.restore_drills WHERE succeeded), \
                m.repo_bytes, m.repo_max_bytes, m.min_free_bytes, m.estimate_bytes, \
                (SELECT set_repo_bytes FROM ops.backup_receipts \
                  WHERE outcome = 'VERIFIED' AND set_repo_bytes IS NOT NULL ORDER BY recorded_at DESC LIMIT 1), \
                EXISTS (SELECT 1 FROM ins) \
                OR EXISTS (SELECT 1 FROM ops.wal_archive_failures, v WHERE observed_at > v.v) \
                OR coalesce((SELECT a.last_failed_time > coalesce(a.last_archived_time, '-infinity'::timestamptz) \
                             FROM a), false) \
         FROM (SELECT 1) one LEFT JOIN measured m ON true",
    )
    .bind(last_failed)
    .bind(last_archived)
    .fetch_one(pool.pool())
    .await?;
    let repo_bytes: Option<i64> = row.try_get(2)?;
    let verified_set: Option<i64> = row.try_get(6)?;
    let budget = match repo_bytes {
        Some(repo_bytes) => Some(MeasuredBudget {
            repo_bytes,
            repo_max_bytes: row.try_get(3)?,
            min_free_bytes: row.try_get(4)?,
            estimate_bytes: verified_set
                .map(estimate_from_set_bytes)
                .or(row.try_get(5)?),
        }),
        None => None,
    };
    Ok(DrEvidence {
        backup_last_success: row.try_get(0)?,
        restore_drill_last_success: row.try_get(1)?,
        budget,
        wal_archive_failing: row.try_get(7)?,
    })
}

/// ADR-0064 D-L step 2: one committed witness row (`kind` 'A' or 'B'); its `written_at` and the WAL file the
/// insert position is in after the commit (`pg_walfile_name(pg_current_wal_insert_lsn())`).
pub async fn write_restore_witness(
    pool: &MaintenanceDbPool,
    drill_id: Uuid,
    kind: &str,
) -> Result<(OffsetDateTime, String), sqlx::Error> {
    // dep: PostgreSQL(role_maintenance) — ops.restore_witnesses INSERT (0234)
    let written: OffsetDateTime = sqlx::query_scalar(
        "INSERT INTO ops.restore_witnesses (drill_id, kind) VALUES ($1, $2) RETURNING written_at",
    )
    .bind(drill_id)
    .bind(kind)
    .fetch_one(pool.pool())
    .await?;
    // dep: PostgreSQL(role_maintenance) — WAL position after the commit (PUBLIC functions)
    let walfile: String = sqlx::query_scalar("SELECT pg_walfile_name(pg_current_wal_insert_lsn())")
        .fetch_one(pool.pool())
        .await?;
    Ok((written, walfile))
}

/// ADR-0064 D-O step 9: the receipt, written AFTER destroy (residue known). A success claim the table refuses comes
/// back as the database error (23514), never as a quietly failed row.
pub async fn insert_drill_receipt(
    pool: &MaintenanceDbPool,
    r: &DrillReceipt,
) -> Result<bool, sqlx::Error> {
    // dep: PostgreSQL(role_maintenance) — ops.restore_drills INSERT (0234)
    sqlx::query_scalar(
        "INSERT INTO ops.restore_drills (restore_drill_id, succeeded, backup_label, backup_manifest_sha256, \
           target_time, started_at, finished_at, manifest_matches, witness_a_present, witness_b_absent, \
           server_version_matches, migrations_drift, rls_unforced, isolation_violations, isolation_pairs, \
           payload_digest_mismatches, provider_calls, drill_archiver_attempts, rebuild_equivalent, rebuild_points, \
           legacy_points_without_vector, unprojected_at_target, restored_in_flight, residue, rto_seconds, \
           phase_seconds, failure, repo_intact) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, \
           $23, $24, $25::float8::numeric, $26, $27, $28) RETURNING succeeded",
    )
    .bind(r.drill_id)
    .bind(r.failure.is_none())
    .bind(&r.backup_label)
    .bind(&r.backup_manifest_sha256)
    .bind(r.target_time)
    .bind(r.started_at)
    .bind(r.finished_at)
    .bind(r.manifest_matches)
    .bind(r.witness_a_present)
    .bind(r.witness_b_absent)
    .bind(r.server_version_matches)
    .bind(r.migrations_drift)
    .bind(r.rls_unforced)
    .bind(r.isolation_violations)
    .bind(r.isolation_pairs)
    .bind(r.payload_digest_mismatches)
    .bind(r.provider_calls)
    .bind(r.drill_archiver_attempts)
    .bind(r.rebuild_equivalent)
    .bind(r.rebuild_points)
    .bind(r.legacy_points_without_vector)
    .bind(r.unprojected_at_target)
    .bind(&r.restored_in_flight)
    .bind(r.residue)
    .bind(r.rto_seconds)
    .bind(&r.phase_seconds)
    .bind(&r.failure)
    .bind(r.repo_intact)
    .fetch_one(pool.pool())
    .await
}
