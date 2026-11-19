//! `adapters::outbox_repo` — M09 writes for public dispatch and Distill outbox rows.
//! Depends-on: crates=[sqlx]; services=[PostgreSQL(any) w=[ops.outbox]]; env=[]; modules=[]
//! Called-by: [adapters::distill_repo, adapters::postgres]
//! Invariants: [the caller owns the transaction and acquires its business locks before these writes]
//! Spec: Baseline §12; §13; §14; ADR-0058 D-C/D-E

use sqlx::{postgres::PgRow, types::Uuid, types::time::OffsetDateTime};

/// The event claimed by Distill.
pub(crate) const EVIDENCE_ACCEPTED: &str = "EVIDENCE_ACCEPTED";

type Txn<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

/// An outbox target is either a release or the anonymous identity and its envelope digest.
pub(crate) enum PublicTarget {
    Release(Uuid),
    Anonymous {
        source_id: Uuid,
        envelope_sha256: Vec<u8>,
    },
}

/// Writes the outbox event for an explicit private release in its caller's transaction.
pub(crate) async fn enqueue_explicit_release(
    txn: &mut Txn<'_>,
    tenant_id: Uuid,
    commit_seq: i64,
    release_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO ops.outbox (tenant_id, commit_seq, event_type, contribution_release_id) \
         VALUES ($1, $2, 'PUBLIC_RELEASE', $3)",
    )
    .bind(tenant_id)
    .bind(commit_seq)
    .bind(release_id)
    .execute(&mut **txn)
    .await?;

    Ok(())
}

/// Writes the ordinary or anonymous confirmation event in the release transaction.
pub(crate) async fn enqueue_confirmed_release(
    txn: &mut Txn<'_>,
    tenant_id: Uuid,
    seq: i64,
    target: PublicTarget,
) -> Result<(), sqlx::Error> {
    match target {
        PublicTarget::Anonymous {
            source_id: anonymous_source_id,
            envelope_sha256,
        } => {
            sqlx::query(
                "INSERT INTO ops.outbox(tenant_id,commit_seq,event_type,anonymous_source_id,candidate_envelope_sha256,anonymous_source_revision) \
                 VALUES($1,$2,'PUBLIC_ANONYMOUS_RELEASE',$3,$4,1)",
            )
            .bind(tenant_id)
            .bind(seq)
            .bind(anonymous_source_id)
            .bind(envelope_sha256)
            .execute(&mut **txn)
            .await?;
        }
        PublicTarget::Release(id) => {
            sqlx::query(
                "INSERT INTO ops.outbox(tenant_id,commit_seq,event_type,contribution_release_id) \
                 VALUES($1,$2,'PUBLIC_RELEASE',$3)",
            )
            .bind(tenant_id)
            .bind(seq)
            .bind(id)
            .execute(&mut **txn)
            .await?;
        }
    }
    Ok(())
}

/// Writes the ordinary or anonymous revocation event after the release transition.
pub(crate) async fn enqueue_public_revoke(
    txn: &mut Txn<'_>,
    tenant_id: Uuid,
    commit_seq: i64,
    target: PublicTarget,
) -> Result<(), sqlx::Error> {
    match target {
        PublicTarget::Anonymous {
            source_id: anonymous_source_id,
            envelope_sha256,
        } => {
            sqlx::query(
            "INSERT INTO ops.outbox(tenant_id,commit_seq,event_type,anonymous_source_id,candidate_envelope_sha256,anonymous_source_revision) \
             VALUES($1,$2,'PUBLIC_ANONYMOUS_REVOKE',$3,$4,2)",
        )
        .bind(tenant_id)
        .bind(commit_seq)
        .bind(anonymous_source_id)
        .bind(envelope_sha256)
        .execute(&mut **txn)
        .await?;
        }
        PublicTarget::Release(release_id) => {
            sqlx::query(
                "INSERT INTO ops.outbox(tenant_id,commit_seq,event_type,contribution_release_id) \
             VALUES($1,$2,'PUBLIC_REVOKE',$3)",
            )
            .bind(tenant_id)
            .bind(commit_seq)
            .bind(release_id)
            .execute(&mut **txn)
            .await?;
        }
    }
    Ok(())
}

/// Claims the job's Evidence event after the caller locks its generation-fenced job row.
pub(crate) async fn take_distill_outbox(
    txn: &mut Txn<'_>,
    tenant_id: Uuid,
    evidence_id: Uuid,
    lease_owner: &str,
    hold_until: OffsetDateTime,
) -> Result<Option<PgRow>, sqlx::Error> {
    // Served by outbox_tenant_evidence_idx (tenant_id, evidence_id).
    sqlx::query(
        "UPDATE ops.outbox \
         SET status = 'PROCESSING', lease_owner = $4, lease_expires_at = $5 \
         WHERE tenant_id = $1 AND event_type = $2 AND evidence_id = $3 \
           AND status IN ('PENDING', 'PROCESSING') \
         RETURNING outbox_id, evidence_id, commit_seq, stream_seq",
    )
    .bind(tenant_id)
    .bind(EVIDENCE_ACCEPTED)
    .bind(evidence_id)
    .bind(lease_owner)
    .bind(hold_until)
    .fetch_optional(&mut **txn)
    .await
}

/// Distill retries release the lease and keep the previous processed timestamp.
pub(crate) enum DistillOutboxOutcome {
    Done,
    Failed,
    Pending,
}

/// Settles the claimed Evidence event after the caller applies the generation fence.
pub(crate) async fn settle_distill_outbox(
    txn: &mut Txn<'_>,
    outbox_id: Uuid,
    lease_owner: &str,
    settle: DistillOutboxOutcome,
) -> Result<bool, sqlx::Error> {
    let (status, processed) = match settle {
        DistillOutboxOutcome::Done => ("DONE", true),
        DistillOutboxOutcome::Failed => ("FAILED", true),
        DistillOutboxOutcome::Pending => ("PENDING", false),
    };
    let result = sqlx::query(
        "UPDATE ops.outbox \
         SET status = $2, processed_at = CASE WHEN $4 THEN now() ELSE processed_at END, \
             lease_owner = NULL, lease_expires_at = NULL \
         WHERE outbox_id = $1 AND status = 'PROCESSING' AND lease_owner = $3",
    )
    .bind(outbox_id)
    .bind(status)
    .bind(lease_owner)
    .bind(processed)
    .execute(&mut **txn)
    .await?;
    Ok(result.rows_affected() == 1)
}
