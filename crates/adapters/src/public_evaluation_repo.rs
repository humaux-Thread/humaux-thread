//! `adapters::public_evaluation_repo` — M20's PostgreSQL writer for manual trust receipts.
//! Depends-on: crates=[sqlx]; services=[PostgreSQL(any) r=[control.public_moderator_grants]
//!   w=[public.claim_trust_evaluation_sources, public.claim_trust_evaluations, public.poisoning_signals]]; env=[]; modules=[]
//! Called-by: [public-pool::public_repo]
//! Invariants: [the caller holds the evaluation locks and commits the receipt, roots, signals,
//!   claim revision, and outbox together]
//! Spec: Baseline §12.6; ADR-0130 D4

use sqlx::types::Uuid;

type Txn<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

/// The reviewed claim revision and its immutable trust assessment.
pub struct ClaimTrustReceipt<'a> {
    pub evaluation_id: Uuid,
    pub claim_id: Uuid,
    pub object_revision: i64,
    pub body_sha256: &'a [u8],
    pub policy_version: &'a str,
    pub moderation_state: &'a str,
    pub evaluator_user_id: Uuid,
    pub rationale: &'a str,
    pub support_count: i32,
    pub independent_support_count: i32,
    pub trusted_source_count: Option<i32>,
    pub identity_incomplete: bool,
    pub contradiction_count: i32,
    pub checks_complete: bool,
}

/// Records the receipt in the transaction that locked the reviewed claim and roots.
pub async fn record_claim_trust_receipt_in_txn(
    txn: &mut Txn<'_>,
    receipt: &ClaimTrustReceipt<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO public.claim_trust_evaluations( \
           evaluation_id,claim_id,object_revision,body_sha256,policy_version,moderation_state,evaluator_user_id, \
           evaluator_grant_version,rationale,support_count,independent_support_count, \
           trusted_source_count,identity_incomplete,contradiction_count,checks_complete) \
         SELECT $1,$2,$3,$4,$5,$6,$7,g.grant_version,$8,$9,$10,$11,$12,$13,$14 \
         FROM (SELECT 1) x LEFT JOIN control.public_moderator_grants g \
           ON g.user_id=$7 AND g.enabled",
    )
    .bind(receipt.evaluation_id)
    .bind(receipt.claim_id)
    .bind(receipt.object_revision)
    .bind(receipt.body_sha256)
    .bind(receipt.policy_version)
    .bind(receipt.moderation_state)
    .bind(receipt.evaluator_user_id)
    .bind(receipt.rationale)
    .bind(receipt.support_count)
    .bind(receipt.independent_support_count)
    .bind(receipt.trusted_source_count)
    .bind(receipt.identity_incomplete)
    .bind(receipt.contradiction_count)
    .bind(receipt.checks_complete)
    .execute(&mut **txn)
    .await?;
    Ok(())
}

/// Attaches one root from the locked graph to the evaluation receipt.
pub async fn record_claim_trust_root_in_txn(
    txn: &mut Txn<'_>,
    evaluation_id: Uuid,
    root_source_id: Uuid,
    source_content_hash: &str,
    release_id: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO public.claim_trust_evaluation_sources( \
              evaluation_id,root_source_id,source_content_hash,contribution_release_id) \
             VALUES($1,$2,$3,$4)",
    )
    .bind(evaluation_id)
    .bind(root_source_id)
    .bind(source_content_hash)
    .bind(release_id)
    .execute(&mut **txn)
    .await?;
    Ok(())
}

/// Records one poisoning check outcome for the evaluation receipt.
pub async fn record_poisoning_signal_in_txn(
    txn: &mut Txn<'_>,
    evaluation_id: Uuid,
    signal: &str,
    version: &str,
    detected: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO public.poisoning_signals(evaluation_id,signal_code,check_version,detected) \
         VALUES($1,$2,$3,$4)",
    )
    .bind(evaluation_id)
    .bind(signal)
    .bind(version)
    .bind(detected)
    .execute(&mut **txn)
    .await?;
    Ok(())
}
