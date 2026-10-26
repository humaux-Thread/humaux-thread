//! `public-pool::vocab` — Public vocabulary's only idempotent write door (§12.3, ADR-0089 D-E).
//! Depends-on: crates=[humaux-adapters, humaux-domain, sqlx]; services=[PostgreSQL(role_public_worker)
//!   r=[public.concepts, public.concept_labels, public.concept_relations]
//!   w=[public.concepts, public.concept_labels, public.concept_relations]]; env=[];
//!   modules=[adapters::postgres, domain::error, public-pool::vocab::model]
//! Called-by: [tests]
//! Invariants: [only concept ids are append-only; definitions and PREF labels upsert by natural key; persisted ALT labels, relations and facets are never removed here; only PublicWorkerDbPool writes]
//! Spec: Baseline §12.3; §52; §78.2; ADR-0089 D-E

/// Pure public-plane vocabulary types; shared with the offline gate (§78.2).
pub mod model;

use humaux_adapters::postgres::PublicWorkerDbPool;
use humaux_domain::error::ErrorCode;
use model::{LabelKind, Vocabulary};
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet};

type Txn<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

/// Loader rejection: an existing [`ErrorCode`] plus a sub-reason naming the offending concept (§52, §12.3).
/// A struct, not a third error enum (§52).
#[derive(Debug, PartialEq, Eq)]
pub struct ApplyError {
    /// Terminal code surfaced to the operator.
    pub code: ErrorCode,
    /// Sub-reason; names the concept (or relation) that was rejected.
    pub reason: String,
}

impl ApplyError {
    fn invalid(reason: String) -> Self {
        Self {
            code: ErrorCode::InvalidInput,
            reason,
        }
    }
}

/// Apply the PR-reviewed source and id lock atomically (ADR-0089 D-E, §12.3).
/// Concept ids are append-only; labels, definitions and relations are added or edited through this one door.
// ponytail: the worker role has no DELETE, so removing a persisted ALT label, language or relation is rejected
// with "removal needs a migration"; upgrade path = a dedicated delete door with its own grant and ADR.
pub async fn apply(pool: &PublicWorkerDbPool, source: &str, lock: &str) -> Result<(), ApplyError> {
    let vocab = Vocabulary::parse(source, lock).map_err(|e| ApplyError::invalid(e.join("; ")))?;
    // dep: PostgreSQL(role_public_worker) — §12.3 serialised public vocabulary snapshot.
    let mut tx = pool.raw_pool().begin().await.map_err(db_error)?;
    // §12.3: one vocabulary snapshot; concurrent loaders cannot race the removal checks.
    sqlx::query("LOCK TABLE public.concepts, public.concept_labels, public.concept_relations IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *tx).await.map_err(db_error)?;
    reject_removed_concepts(&mut tx, &vocab).await?;
    reject_removed_labels(&mut tx, &vocab).await?;
    reject_removed_relations(&mut tx, &vocab).await?;
    sqlx::query("SET CONSTRAINTS ALL DEFERRED")
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    upsert_concepts(&mut tx, &vocab).await?;
    upsert_labels(&mut tx, &vocab).await?;
    upsert_relations(&mut tx, &vocab).await?;
    tx.commit().await.map_err(db_error)
}

async fn upsert_concepts(tx: &mut Txn<'_>, vocab: &Vocabulary) -> Result<(), ApplyError> {
    for c in &vocab.concepts {
        sqlx::query("INSERT INTO public.concepts (concept_id,facet,status,replaced_by,definition) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (concept_id) DO UPDATE SET status=EXCLUDED.status,replaced_by=EXCLUDED.replaced_by,definition=EXCLUDED.definition")
            .bind(&c.id).bind(c.facet.as_str()).bind(c.status.as_str()).bind(&c.replaced_by).bind(&c.definition)
            .execute(&mut **tx).await.map_err(db_error)?;
    }
    Ok(())
}

/// PREFs first: a PREF edit is an UPDATE on its natural key (concept_id, lang, 'PREF') and frees the old text
/// before any ALT insert can collide with it on the facet-unique index (§12.3).
async fn upsert_labels(tx: &mut Txn<'_>, vocab: &Vocabulary) -> Result<(), ApplyError> {
    for c in &vocab.concepts {
        for l in c.labels.iter().filter(|l| l.kind == LabelKind::Pref) {
            let updated = sqlx::query("UPDATE public.concept_labels SET label=$3 WHERE concept_id=$1 AND lang=$2 AND kind='PREF'")
                .bind(&c.id).bind(&l.lang).bind(&l.label)
                .execute(&mut **tx).await.map_err(db_error)?;
            if updated.rows_affected() == 0 {
                insert_label(tx, &c.id, c.facet.as_str(), &l.lang, l.kind, &l.label).await?;
            }
        }
    }
    for c in &vocab.concepts {
        for l in c.labels.iter().filter(|l| l.kind == LabelKind::Alt) {
            insert_label(tx, &c.id, c.facet.as_str(), &l.lang, l.kind, &l.label).await?;
        }
    }
    Ok(())
}

async fn insert_label(
    tx: &mut Txn<'_>,
    id: &str,
    facet: &str,
    lang: &str,
    kind: LabelKind,
    label: &str,
) -> Result<(), ApplyError> {
    sqlx::query("INSERT INTO public.concept_labels (concept_id,facet,lang,kind,label) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (concept_id,lang,kind,label) DO NOTHING")
        .bind(id).bind(facet).bind(lang).bind(kind.as_str()).bind(label)
        .execute(&mut **tx).await.map_err(db_error)?;
    Ok(())
}

async fn upsert_relations(tx: &mut Txn<'_>, vocab: &Vocabulary) -> Result<(), ApplyError> {
    for r in &vocab.relations {
        sqlx::query("INSERT INTO public.concept_relations (from_id,to_id,kind) VALUES ($1,$2,$3) ON CONFLICT (from_id,to_id,kind) DO NOTHING")
            .bind(&r.from).bind(&r.to).bind(r.kind.as_str())
            .execute(&mut **tx).await.map_err(db_error)?;
    }
    Ok(())
}

async fn reject_removed_concepts(tx: &mut Txn<'_>, vocab: &Vocabulary) -> Result<(), ApplyError> {
    let wanted: BTreeMap<&str, &str> = vocab
        .concepts
        .iter()
        .map(|c| (c.id.as_str(), c.facet.as_str()))
        .collect();
    let rows = sqlx::query("SELECT concept_id,facet FROM public.concepts ORDER BY concept_id")
        .fetch_all(&mut **tx)
        .await
        .map_err(db_error)?;
    for row in rows {
        let id: String = row.get("concept_id");
        let facet: String = row.get("facet");
        match wanted.get(id.as_str()) {
            None => {
                return Err(ApplyError::invalid(format!(
                    "{id}: persisted concept id removed or renamed; ids are append-only"
                )));
            }
            Some(f) if *f != facet => {
                return Err(ApplyError::invalid(format!(
                    "{id}: facet change needs a migration"
                )));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

async fn reject_removed_labels(tx: &mut Txn<'_>, vocab: &Vocabulary) -> Result<(), ApplyError> {
    let mut alts = BTreeSet::new();
    let mut pref_langs = BTreeSet::new();
    for c in &vocab.concepts {
        for l in &c.labels {
            match l.kind {
                LabelKind::Pref => {
                    pref_langs.insert((c.id.as_str(), l.lang.as_str()));
                }
                LabelKind::Alt => {
                    alts.insert((c.id.as_str(), l.lang.as_str(), l.label.as_str()));
                }
            }
        }
    }
    let rows = sqlx::query("SELECT concept_id,lang,kind,label FROM public.concept_labels ORDER BY concept_id,lang,kind,label")
        .fetch_all(&mut **tx)
        .await
        .map_err(db_error)?;
    for row in rows {
        let id: String = row.get("concept_id");
        let lang: String = row.get("lang");
        let kind: String = row.get("kind");
        let label: String = row.get("label");
        if kind == LabelKind::Pref.as_str() {
            if !pref_langs.contains(&(id.as_str(), lang.as_str())) {
                return Err(ApplyError::invalid(format!(
                    "{id}: PREF label language '{lang}' removal needs a migration"
                )));
            }
        } else if !alts.contains(&(id.as_str(), lang.as_str(), label.as_str())) {
            return Err(ApplyError::invalid(format!(
                "{id}: ALT label '{label}' ({lang}) removal needs a migration"
            )));
        }
    }
    Ok(())
}

async fn reject_removed_relations(tx: &mut Txn<'_>, vocab: &Vocabulary) -> Result<(), ApplyError> {
    let wanted: BTreeSet<_> = vocab
        .relations
        .iter()
        .map(|r| (r.from.as_str(), r.to.as_str(), r.kind.as_str()))
        .collect();
    let rows = sqlx::query(
        "SELECT from_id,to_id,kind FROM public.concept_relations ORDER BY from_id,to_id,kind",
    )
    .fetch_all(&mut **tx)
    .await
    .map_err(db_error)?;
    for row in rows {
        let from: String = row.get("from_id");
        let to: String = row.get("to_id");
        let kind: String = row.get("kind");
        if !wanted.contains(&(from.as_str(), to.as_str(), kind.as_str())) {
            return Err(ApplyError::invalid(format!(
                "{from} -> {to}: {kind} relation removal needs a migration"
            )));
        }
    }
    Ok(())
}

fn db_error(error: sqlx::Error) -> ApplyError {
    match error {
        sqlx::Error::Database(ref e)
            if matches!(e.code().as_deref(), Some("23503" | "23505" | "23514")) =>
        {
            ApplyError::invalid(format!(
                "database constraint {} rejected the vocabulary",
                e.constraint().unwrap_or("unknown")
            ))
        }
        _ => ApplyError {
            code: ErrorCode::DependencyUnavailable,
            reason: "database unavailable".into(),
        },
    }
}
