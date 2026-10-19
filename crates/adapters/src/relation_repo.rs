//! `adapters::relation_repo` — SQL half of the §6.1.4 relation kernel (ADR-0078 D-C, M29 T05): the one revision
//!   writer and the one current-revision reader for every relation pair.
//! Depends-on: crates=[humaux-domain, sqlx]; services=[PostgreSQL(role_gateway)
//!   r=[private.project_subject_relations, private.project_task_relations, private.subject_relations]
//!   w=[private.project_subject_relations, private.project_task_relations, private.subject_relations]]; env=[];
//!   modules=[domain::error, domain::identity, domain::relation]
//! Called-by: [tests]
//! Invariants: [one implementation for all pairs (the pair selects the table, nothing else differs); a write is
//!   exactly one INSERT of revision = expected_revision + 1 in the caller's transaction; the tenant is the session's
//!   humaux.tenant_id, the same value RLS checks]
//! Spec: Baseline §6.1.4; §52; ADR-0078 D-C
//!
//! Both functions run in the caller's transaction under its role and RLS: the caller has already installed the
//! authorization context (`humaux.tenant_id`). Whitelist, contiguity and edge immutability are enforced once, by the
//! migration-0249 guard trigger, and surface here as [`ErrorCode`]s.

use std::ops::Bound;

use humaux_domain::error::ErrorCode;
use humaux_domain::relation::{
    DecidedBy, ModelRef, RelationEdge, RelationId, RelationKind, RelationPair, Timestamp, Validity,
};
use sqlx::Row;
use sqlx::types::Uuid;

type Txn<'c> = sqlx::Transaction<'c, sqlx::Postgres>;

/// Constraint name the 0249 guard raises when `expected_revision` is ahead of the relation's current revision.
const REVISION_CONTIGUOUS: &str = "relation_revision_contiguous";

/// One stored revision of a relation (§6.1.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationRevision {
    /// The relation this revision belongs to.
    pub relation_id: RelationId,
    /// 1-based revision number; the highest one is the current state.
    pub revision: i64,
    /// The relation's edge (identical in every revision).
    pub edge: RelationEdge,
    /// Valid time; empty = retracted.
    pub valid: Validity,
    /// Who decided this revision.
    pub decided_by: DecidedBy,
    /// Provenance only, never authority.
    pub proposed_by: Option<ModelRef>,
    /// Factual evidence.
    pub factual_evidence_ids: Vec<Uuid>,
    /// Authorisation evidence, kept apart from the factual evidence.
    pub authorization_evidence_id: Uuid,
}

fn table(pair: RelationPair) -> &'static str {
    match pair {
        RelationPair::ProjectTask => "private.project_task_relations",
        RelationPair::ProjectSubject => "private.project_subject_relations",
        RelationPair::SubjectSubject => "private.subject_relations",
    }
}

/// §52 mapping for the kernel's statements. A lost race (PK) and a stale-ahead `expected_revision` are both
/// `CONFLICT`: the caller re-reads the current revision. An unknown, invisible or foreign-tenant endpoint
/// (FK / guard, both 23503), a non-whitelisted triple and an edge change are `INVALID_INPUT`, with no existence
/// oracle between "missing" and "another tenant's".
fn db_error(error: sqlx::Error) -> ErrorCode {
    match error {
        sqlx::Error::Database(ref db) => match (db.code().as_deref(), db.constraint()) {
            (Some("23505"), _) | (Some("23514"), Some(REVISION_CONTIGUOUS)) => ErrorCode::Conflict,
            (Some("23503" | "23514"), _) => ErrorCode::InvalidInput,
            (Some("42501"), _) => ErrorCode::Forbidden,
            _ => ErrorCode::Internal,
        },
        _ => ErrorCode::DependencyUnavailable,
    }
}

/// §6.1.4 ③ CAS write: appends revision `expected_revision + 1` of `relation_id` (`expected_revision = 0` creates
/// the relation). Returns the new revision number. A concurrent writer with the same `expected_revision` loses on
/// the primary key; both a lost race and an `expected_revision` that is not the current revision are `CONFLICT`.
#[allow(clippy::too_many_arguments)] // ADR-0078 D-C: the revision columns, one argument each.
pub async fn append_revision(
    txn: &mut Txn<'_>,
    edge: &RelationEdge,
    relation_id: RelationId,
    expected_revision: i64,
    valid: &Validity,
    decided_by: &DecidedBy,
    proposed_by: Option<&ModelRef>,
    factual_evidence_ids: &[Uuid],
    authorization_evidence_id: Uuid,
) -> Result<i64, ErrorCode> {
    if expected_revision < 0 {
        return Err(ErrorCode::InvalidInput);
    }
    let revision = expected_revision
        .checked_add(1)
        .ok_or(ErrorCode::InvalidInput)?;
    let (starts, ends): (Vec<i64>, Vec<Option<i64>>) = valid.segments().iter().copied().unzip();
    // Exact µs -> timestamptz: whole seconds through to_timestamp, the remainder as an interval (no float rounding).
    let sql = format!(
        "INSERT INTO {} (tenant_id, relation_id, revision, src_id, dst_id, relation_kind, valid, decided_by, \
         proposed_by, factual_evidence_ids, authorization_evidence_id) \
         VALUES (NULLIF(current_setting('humaux.tenant_id', true), '')::uuid, $1, $2, $3, $4, $5, \
         (SELECT coalesce(range_agg(tstzrange( \
            to_timestamp(s / 1000000) + (s % 1000000) * interval '1 microsecond', \
            to_timestamp(e / 1000000) + (e % 1000000) * interval '1 microsecond', '[)')), '{{}}') \
            FROM unnest($6::bigint[], $7::bigint[]) AS v(s, e)), \
         $8, $9, $10, $11)",
        table(edge.kind.pair())
    );
    sqlx::query(&sql)
        .bind(relation_id.0)
        .bind(revision)
        .bind(edge.src_id)
        .bind(edge.dst_id)
        .bind(edge.kind.as_str())
        .bind(starts)
        .bind(ends)
        .bind(decided_by.to_wire())
        .bind(proposed_by.map(ModelRef::to_wire))
        .bind(factual_evidence_ids)
        .bind(authorization_evidence_id)
        .execute(&mut **txn)
        .await
        .map_err(db_error)?;
    Ok(revision)
}

/// §6.1.4 ①: the current state of `relation_id` in `pair` (its highest revision) under the caller's tenant, or
/// `None` when the relation does not exist or is not visible. A stored value this module cannot parse is
/// `INTERNAL`.
pub async fn current_revision(
    txn: &mut Txn<'_>,
    pair: RelationPair,
    relation_id: RelationId,
) -> Result<Option<RelationRevision>, ErrorCode> {
    let sql = format!(
        "SELECT r.revision, r.src_id, r.dst_id, r.relation_kind, r.decided_by, r.proposed_by, \
                r.factual_evidence_ids, r.authorization_evidence_id, \
                array(SELECT (extract(epoch FROM lower(x)) * 1000000)::bigint FROM unnest(r.valid) x \
                      ORDER BY lower(x)) AS starts, \
                array(SELECT (extract(epoch FROM upper(x)) * 1000000)::bigint FROM unnest(r.valid) x \
                      ORDER BY lower(x)) AS ends \
           FROM {} r \
          WHERE r.tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid \
            AND r.relation_id = $1 \
          ORDER BY r.revision DESC LIMIT 1",
        table(pair)
    );
    let Some(row) = sqlx::query(&sql)
        .bind(relation_id.0)
        .fetch_optional(&mut **txn)
        .await
        .map_err(db_error)?
    else {
        return Ok(None);
    };
    let read = |_: sqlx::Error| ErrorCode::Internal;
    let kind: String = row.try_get("relation_kind").map_err(read)?;
    let decided_by: String = row.try_get("decided_by").map_err(read)?;
    let proposed_by: Option<String> = row.try_get("proposed_by").map_err(read)?;
    let starts: Vec<i64> = row.try_get("starts").map_err(read)?;
    let ends: Vec<Option<i64>> = row.try_get("ends").map_err(read)?;
    let ranges: Vec<_> = starts
        .into_iter()
        .zip(ends)
        .map(|(s, e)| {
            (
                Bound::Included(Timestamp::Micros(s)),
                e.map_or(Bound::Unbounded, |e| Bound::Excluded(Timestamp::Micros(e))),
            )
        })
        .collect();
    Ok(Some(RelationRevision {
        relation_id,
        revision: row.try_get("revision").map_err(read)?,
        edge: RelationEdge {
            src_id: row.try_get("src_id").map_err(read)?,
            kind: RelationKind::parse(&kind).ok_or(ErrorCode::Internal)?,
            dst_id: row.try_get("dst_id").map_err(read)?,
        },
        valid: Validity::new(&ranges).map_err(|_| ErrorCode::Internal)?,
        decided_by: DecidedBy::parse(&decided_by).ok_or(ErrorCode::Internal)?,
        proposed_by: match proposed_by {
            Some(p) => Some(ModelRef::parse(&p).ok_or(ErrorCode::Internal)?),
            None => None,
        },
        factual_evidence_ids: row.try_get("factual_evidence_ids").map_err(read)?,
        authorization_evidence_id: row.try_get("authorization_evidence_id").map_err(read)?,
    }))
}
