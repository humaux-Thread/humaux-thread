//! Public vocabulary's only idempotent write door (§12.3, ADR-0089 D-E).
//! Depends-on: crates=[humaux-adapters, humaux-domain, sqlx]; services=[PostgreSQL(role_public_worker)
//!   r=[public.concepts, public.concept_labels, public.concept_relations]
//!   w=[public.concepts, public.concept_labels, public.concept_relations]]; env=[];
//!   modules=[adapters::postgres, domain::error, public-pool::vocab::model]
//! Called-by: [tests]
//! Invariants: [no deletes; removed ids and facets fail atomically; only PublicWorkerDbPool writes]
//! Spec: Baseline §12.3; §52; §78.2; ADR-0089 D-E

/// Pure public-plane vocabulary types; shared with the offline gate (§78.2).
pub mod model;

use humaux_adapters::postgres::PublicWorkerDbPool;
use humaux_domain::error::ErrorCode;
use model::Vocabulary;
use sqlx::Row;

type Txn<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

/// Apply the PR-reviewed source and id lock atomically; missing persisted ids are errors (ADR-0089 D-E).
/// Existing labels/relations must remain represented: the loader never silently keeps stale rows.
pub async fn apply(pool: &PublicWorkerDbPool, source: &str, lock: &str) -> Result<(), ErrorCode> {
    let vocab = Vocabulary::parse(source, lock).map_err(|_| ErrorCode::InvalidInput)?;
    let mut tx = pool.raw_pool().begin().await.map_err(db_error)?;
    // §12.3: one vocabulary snapshot; concurrent loaders cannot race the removal checks.
    sqlx::query("LOCK TABLE public.concepts, public.concept_labels, public.concept_relations IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *tx).await.map_err(db_error)?;
    reject_removed(&mut tx, &vocab).await?;
    sqlx::query("SET CONSTRAINTS ALL DEFERRED")
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    for c in &vocab.concepts {
        sqlx::query("INSERT INTO public.concepts (concept_id,facet,status,replaced_by,definition) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (concept_id) DO UPDATE SET status=EXCLUDED.status,replaced_by=EXCLUDED.replaced_by,definition=EXCLUDED.definition")
            .bind(&c.id).bind(c.facet.as_str()).bind(c.status.as_str()).bind(&c.replaced_by).bind(&c.definition)
            .execute(&mut *tx).await.map_err(db_error)?;
    }
    for c in &vocab.concepts {
        for l in &c.labels {
            sqlx::query("INSERT INTO public.concept_labels (concept_id,facet,lang,kind,label) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (concept_id,lang,kind,label) DO NOTHING")
                .bind(&c.id).bind(c.facet.as_str()).bind(&l.lang).bind(l.kind.as_str()).bind(&l.label)
                .execute(&mut *tx).await.map_err(db_error)?;
        }
    }
    for r in &vocab.relations {
        sqlx::query("INSERT INTO public.concept_relations (from_id,to_id,kind) VALUES ($1,$2,$3) ON CONFLICT (from_id,to_id,kind) DO NOTHING")
            .bind(&r.from).bind(&r.to).bind(r.kind.as_str())
            .execute(&mut *tx).await.map_err(db_error)?;
    }
    tx.commit().await.map_err(db_error)
}

async fn reject_removed(tx: &mut Txn<'_>, vocab: &Vocabulary) -> Result<(), ErrorCode> {
    let rows = sqlx::query("SELECT concept_id,facet FROM public.concepts")
        .fetch_all(&mut **tx)
        .await
        .map_err(db_error)?;
    for row in rows {
        let id: String = row.get("concept_id");
        let facet: String = row.get("facet");
        if !vocab
            .concepts
            .iter()
            .any(|c| c.id == id && c.facet.as_str() == facet)
        {
            return Err(ErrorCode::InvalidInput);
        }
    }
    let rows = sqlx::query("SELECT concept_id,lang,kind,label FROM public.concept_labels")
        .fetch_all(&mut **tx)
        .await
        .map_err(db_error)?;
    for row in rows {
        let id: String = row.get("concept_id");
        let lang: String = row.get("lang");
        let kind: String = row.get("kind");
        let label: String = row.get("label");
        if !vocab.concepts.iter().any(|c| {
            c.id == id
                && c.labels
                    .iter()
                    .any(|l| l.lang == lang && l.kind.as_str() == kind && l.label == label)
        }) {
            return Err(ErrorCode::InvalidInput);
        }
    }
    let rows = sqlx::query("SELECT from_id,to_id,kind FROM public.concept_relations")
        .fetch_all(&mut **tx)
        .await
        .map_err(db_error)?;
    for row in rows {
        let from: String = row.get("from_id");
        let to: String = row.get("to_id");
        let kind: String = row.get("kind");
        if !vocab
            .relations
            .iter()
            .any(|r| r.from == from && r.to == to && r.kind.as_str() == kind)
        {
            return Err(ErrorCode::InvalidInput);
        }
    }
    Ok(())
}
fn db_error(error: sqlx::Error) -> ErrorCode {
    match error {
        sqlx::Error::Database(ref e)
            if matches!(e.code().as_deref(), Some("23503" | "23505" | "23514")) =>
        {
            ErrorCode::InvalidInput
        }
        _ => ErrorCode::DependencyUnavailable,
    }
}
