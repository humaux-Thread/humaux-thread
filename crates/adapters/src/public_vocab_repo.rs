//! `adapters::public_vocab_repo` — M20's PostgreSQL writer for controlled vocabulary.
//! Depends-on: crates=[sqlx]; services=[PostgreSQL(role_public_worker)
//!   w=[public.concepts, public.concept_labels, public.concept_relations]]; env=[]; modules=[]
//! Called-by: [public-pool::vocab]
//! Invariants: [the loader validates and locks the snapshot before the first write;
//!   concept, label and relation writes participate in the caller's one transaction]
//! Spec: Baseline §12.3; ADR-0089 D-E; ADR-0130 D4

type Txn<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

/// Upsert a validated concept in the locked vocabulary transaction.
pub async fn upsert_concept_in_txn(
    tx: &mut Txn<'_>,
    id: &str,
    facet: &str,
    status: &str,
    replaced_by: Option<&str>,
    definition: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO public.concepts (concept_id,facet,status,replaced_by,definition) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (concept_id) DO UPDATE SET status=EXCLUDED.status,replaced_by=EXCLUDED.replaced_by,definition=EXCLUDED.definition")
        .bind(id).bind(facet).bind(status).bind(replaced_by).bind(definition)
        .execute(&mut **tx).await?;
    Ok(())
}

/// Update the preferred label, reporting whether the natural key already existed.
pub async fn update_preferred_label_in_txn(
    tx: &mut Txn<'_>,
    id: &str,
    lang: &str,
    label: &str,
) -> Result<bool, sqlx::Error> {
    let updated = sqlx::query(
        "UPDATE public.concept_labels SET label=$3 WHERE concept_id=$1 AND lang=$2 AND kind='PREF'",
    )
    .bind(id)
    .bind(lang)
    .bind(label)
    .execute(&mut **tx)
    .await?;
    Ok(updated.rows_affected() != 0)
}

/// Add a preferred or alternative label in the locked vocabulary transaction.
pub async fn insert_label_in_txn(
    tx: &mut Txn<'_>,
    id: &str,
    facet: &str,
    lang: &str,
    kind: &str,
    label: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO public.concept_labels (concept_id,facet,lang,kind,label) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (concept_id,lang,kind,label) DO NOTHING")
        .bind(id).bind(facet).bind(lang).bind(kind).bind(label)
        .execute(&mut **tx).await?;
    Ok(())
}

/// Add a validated relation in the locked vocabulary transaction.
pub async fn insert_relation_in_txn(
    tx: &mut Txn<'_>,
    from: &str,
    to: &str,
    kind: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO public.concept_relations (from_id,to_id,kind) VALUES ($1,$2,$3) ON CONFLICT (from_id,to_id,kind) DO NOTHING")
        .bind(from).bind(to).bind(kind)
        .execute(&mut **tx).await?;
    Ok(())
}
