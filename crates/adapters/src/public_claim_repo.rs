//! `adapters::public_claim_repo` — PostgreSQL owner commands for public claim and synthesis writes.
//! Depends-on: crates=[serde_json, sqlx]; services=[PostgreSQL(any) w=[public.claims,
//!   public.provenance_edges, public.source_closure, public.sources, public.syntheses]]; env=[]; modules=[]
//! Called-by: [public-pool::public_repo]
//! Invariants: [the caller retains the locks and commits graph, moderation, and outbox writes together]
//! Spec: Baseline §12.6; ADR-0130 D4

use serde_json::Value;
use sqlx::types::Uuid;

type Txn<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

/// Provenance fields read from the locked and validated intake release.
pub struct IntakeSource {
    /// Publisher recorded by the release.
    pub publisher: Option<String>,
    /// Hex-encoded hash of the validated release bytes.
    pub content_hash: String,
    /// Source license recorded by the release.
    pub source_license: Option<String>,
    /// Legal basis recorded by the release.
    pub rights_basis: String,
    /// Redistribution policy recorded by the release.
    pub redistribution_policy: Option<String>,
    /// Active release backing this source.
    pub release_id: Uuid,
}

/// Inserts an initial staged claim after the caller locks its active release.
pub async fn create_intake_claim_in_txn(
    txn: &mut Txn<'_>,
    body: &Value,
    release_id: Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO public.claims(content, moderation_state, intake_release_id) \
         VALUES($1,'PUBLIC_STAGING',$2) \
         ON CONFLICT (intake_release_id) WHERE intake_release_id IS NOT NULL DO NOTHING \
         RETURNING claim_id",
    )
    .bind(body)
    .bind(release_id)
    .fetch_optional(&mut **txn)
    .await
}

/// Inserts the verified release source in the same transaction as the staged claim.
pub async fn create_intake_source_in_txn(
    txn: &mut Txn<'_>,
    source: IntakeSource,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO public.sources(source_type,publisher,content_hash,source_license,rights_basis, \
             redistribution_policy,trust_class,contribution_release_id) \
         VALUES('USER_CONTRIBUTION',$1,$2,$3,$4,$5,'UNDER_REVIEW',$6) RETURNING source_id",
    )
    .bind(source.publisher)
    .bind(source.content_hash)
    .bind(source.source_license)
    .bind(source.rights_basis)
    .bind(source.redistribution_policy)
    .bind(source.release_id)
    .fetch_one(&mut **txn)
    .await
}

/// Links the staged claim to its source, records its root and advances it to review.
pub async fn record_intake_provenance_in_txn(
    txn: &mut Txn<'_>,
    claim_id: Uuid,
    source_id: Uuid,
) -> Result<i64, sqlx::Error> {
    sqlx::query("INSERT INTO public.provenance_edges(claim_id,source_id) VALUES($1,$2)")
        .bind(claim_id)
        .bind(source_id)
        .execute(&mut **txn)
        .await?;
    sqlx::query(
        "INSERT INTO public.source_closure(claim_id,root_source_id,depth,is_current) \
         VALUES($1,$2,1,true)",
    )
    .bind(claim_id)
    .bind(source_id)
    .execute(&mut **txn)
    .await?;
    sqlx::query_scalar(
        "UPDATE public.claims SET moderation_state='UNDER_REVIEW',object_revision=object_revision+1 \
         WHERE claim_id=$1 RETURNING object_revision",
    )
    .bind(claim_id)
    .fetch_one(&mut **txn)
    .await
}

/// Applies the trust receipt to the locked claim revision.
pub async fn apply_claim_evaluation_in_txn(
    txn: &mut Txn<'_>,
    claim_id: Uuid,
    evaluation_id: Uuid,
    moderation_state: &str,
    next_revision: i64,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE public.claims SET current_evaluation_id=$2, moderation_state=$3, \
             object_revision=$4 WHERE claim_id=$1 RETURNING object_revision",
    )
    .bind(claim_id)
    .bind(evaluation_id)
    .bind(moderation_state)
    .bind(next_revision)
    .fetch_one(&mut **txn)
    .await
}

/// Clears the claim's current receipt if its release revocation changes its state.
pub async fn apply_claim_revocation_in_txn(
    txn: &mut Txn<'_>,
    claim_id: Uuid,
    state: &str,
) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE public.claims SET moderation_state=$2,current_evaluation_id=NULL, \
                object_revision=object_revision+1 WHERE claim_id=$1 \
                AND (moderation_state IS DISTINCT FROM $2 OR current_evaluation_id IS NOT NULL) \
                RETURNING object_revision",
    )
    .bind(claim_id)
    .bind(state)
    .fetch_optional(&mut **txn)
    .await
}

/// Clears the synthesis's current receipt if its release revocation changes its state.
pub async fn apply_synthesis_revocation_in_txn(
    txn: &mut Txn<'_>,
    synthesis_id: Uuid,
    state: &str,
) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE public.syntheses SET moderation_state=$2,current_evaluation_id=NULL, \
                object_revision=object_revision+1 WHERE synthesis_id=$1 \
                AND (moderation_state IS DISTINCT FROM $2 OR current_evaluation_id IS NOT NULL) \
                RETURNING object_revision",
    )
    .bind(synthesis_id)
    .bind(state)
    .fetch_optional(&mut **txn)
    .await
}
