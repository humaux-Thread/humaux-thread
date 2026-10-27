//! `adapters::exact_census` — §22.1 EXACT enumeration census: the physical IO behind `completeness::CensusResult`.
//! Depends-on: crates=[humaux-domain, humaux-projection, humaux-retrieval, sqlx]; services=[PostgreSQL(any) r=[ops.outbox, private.evidence_objects, private.memory_evidence, private.memory_records, private.memory_subjects, projection.stream_log, public.pool] x=[private.memory_in_project]]; env=[]; modules=[adapters::context_repo, adapters::postgres, adapters::read_gate, adapters::read_materialize, domain::continuity, domain::error, domain::identity, domain::ids, projection::stream, retrieval::completeness, retrieval::predicate_registry]
//! Called-by: [adapters::context_repo, tests]
//! Invariants: [total, returned items and the probe snapshot come from ONE REPEATABLE READ transaction (§22.1); total
//!   is its own count(*), never the recall length; a census failure is trigger 4 (Internal), never a guessed total;
//!   the project axis (ADR-0110 D-F) is the one conjunct here that names private.memory_in_project, appended as the
//!   same text with the same bind to the count, items and secret statements and absent (no placeholder, no bind) when
//!   the call names no project; this module never reads private.memory_projects or its live view; a project the
//!   caller cannot see, or that does not exist, yields total 0 under the predicate's invoker rights and the caller's
//!   RLS, and the census never learns why]
//! Spec: Baseline §22.4; §22.1; §23.4; §23.1; §60; ADR-0062 D-K; ADR-0067 D-G, D-J2; ADR-0078 D-D; ADR-0110 D-F
//!
//! Split of responsibilities (frozen by the pure crates' own docs):
//! - `retrieval::predicate_registry` validates rows but "does not import sqlx or issue any
//!   query itself" — the census IO lives here.
//! - `retrieval::planner::decide` adjudicates §22.4 triggers 1–3 (no registry row / columns
//!   unindexed / scope not enumerable) from two caller-supplied probe snapshots — produced
//!   here by [`probe_predicate_inputs`].
//! - This module observes only trigger 4 (the census itself failing) plus the §22.1 readout
//!   when it succeeds; `classify()` stays the sole class constructor.
//!
//! §22.1's three disciplines, each landing on one concrete choice below:
//! - "`total` 必须来自 `SELECT count(*) FROM <enumerable_scope> AND <sql_predicate>`，与返回
//!   项取**同一事务快照**" ⇒ one `REPEATABLE READ` transaction for all three statements
//!   (`context_repo::fetch_frozen`'s recipe).
//! - "禁止用召回条数冒充 `total`" ⇒ `total` is its own `count(*)`, never derived from the
//!   returned id list; `ExactEnumeration::new` additionally rejects any overrun.
//! - "`excluded_secret` … > 0 时 `coverage` 相应扣减，不许静默少给" ⇒ secret-linked rows stay
//!   in `total`, leave `returned`, and are counted by their own third statement.
//!
//! §23.4's deletion-tour requirement ("被 tombstone 的那 10 条一次都不许出现在 `items` 里 ——
//! 包括第 5 步物理 purge 还没跑的那些采样点") is why every statement carries the tombstone
//! overlay: a memory whose evidence's stream entry is `TOMBSTONED` leaves the EXACT channel
//! (denominator *and* items) the moment `retention::tombstone` commits — same one-predicate-
//! two-faces overlay §23.1② freezes, joined here via `private.memory_evidence` →
//! `ops.outbox(evidence_id → stream_seq)` → `projection.stream_log(state)` under the caller's
//! [`StreamKey`] (`ops.outbox` is written in the same transaction as the seq issuance, §60, so
//! the mapping shares the write's atomicity).
//!
//! ADR-0110 D-F project axis: `project_id: Some(p)` narrows the universe of the count, the items and the secret
//! statements to memories with a live link to `p`, decided only by `private.memory_in_project` (migration 0282,
//! invoker rights, `role_gateway` EXECUTE), so the M29 reader arm stays the single read path (xtask
//! `m29_attribution_reader`, G-M29-7). A memory with no live link at all is outside every project universe: it is
//! neither counted nor returned, and never guessed into one (N09 R3). The candidate pass does not carry the axis; the
//! three readout statements decide membership from one shared text.

use std::collections::BTreeSet;

use humaux_domain::continuity::ProjectId;
use humaux_domain::error::ErrorCode;
use humaux_domain::identity::AuthorizationScope;
use humaux_domain::ids::WorkspaceId;
use humaux_projection::stream::StreamKey;
use humaux_retrieval::completeness::{CensusResult, ExactEnumeration};
use humaux_retrieval::predicate_registry::PredicateEntry;
use sqlx::types::Uuid;
use sqlx::{Acquire, Row};

use crate::context_repo::set_authorization_local;
use crate::postgres::RuntimeDbPool;
use crate::read_gate::{NoteEnumerationFilter, readable_memory_ids};
use crate::read_materialize::GateReadable;
use crate::read_materialize::Lifecycle;

type Txn<'c> = sqlx::Transaction<'c, sqlx::Postgres>;

/// The `FROM` face of an `enumerable_scope` fragment, split into probe-able parts.
/// `None` = the fragment does not parse as `schema.table WHERE …` — which is §22.4 trigger 3's
/// shape (a mixed/foreign-domain scope has no single probe-able table), so the caller simply
/// leaves it out of `enumerable_scopes` and `decide()` refuses it.
fn scope_table(scope: &str) -> Option<(&str, &str)> {
    let from = scope.split(" WHERE ").next()?.trim();
    let (schema, table) = from.split_once('.')?;
    let ident = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    };
    (ident(schema) && ident(table)).then_some((schema, table))
}

/// Builds `decide()`'s two probe snapshots (§20.2 rule 3, both conjuncts) for one candidate
/// predicate — probed from the live catalogs, never hardcoded (ADR-0006's probing discipline).
///
/// A required column counts as indexed if some index on the scope table carries it either as
/// a key column **or** inside its partial-index predicate: `migrations/0078`'s
/// `idx_memory_records_rejected_decisions_v1` puts `memory_type`/`superseded_at` in the
/// `WHERE` clause and only `visibility_workspace_id` in the key — an indkey-only probe would
/// report the registry's own seeded predicate unenumerable (a probe that fails its one real
/// positive is measuring nothing).
///
/// # Errors
/// [`ErrorCode::Internal`] when the catalog probe itself cannot run.
pub async fn probe_predicate_inputs(
    pool: &RuntimeDbPool,
    entry: &PredicateEntry,
) -> Result<(BTreeSet<String>, BTreeSet<String>), ErrorCode> {
    // dep: PostgreSQL(any) — opens a PostgreSQL transaction
    let mut txn = pool.pool().begin().await.map_err(|_| ErrorCode::Internal)?;

    let mut indexed: BTreeSet<String> = BTreeSet::new();
    let mut scopes: BTreeSet<String> = BTreeSet::new();

    if let Some((schema, table)) = scope_table(entry.enumerable_scope()) {
        let table_exists: bool = sqlx::query(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
             WHERE table_schema = $1 AND table_name = $2)",
        )
        .bind(schema)
        .bind(table)
        .fetch_one(&mut *txn)
        .await
        .map_err(|_| ErrorCode::Internal)?
        .try_get(0)
        .map_err(|_| ErrorCode::Internal)?;

        if table_exists {
            scopes.insert(entry.enumerable_scope().to_string());
            for col in entry.required_columns() {
                let covered: bool = sqlx::query(
                    "SELECT EXISTS ( \
                       SELECT 1 FROM pg_index i \
                       JOIN pg_class c ON c.oid = i.indrelid \
                       JOIN pg_namespace n ON n.oid = c.relnamespace \
                       WHERE n.nspname = $1 AND c.relname = $2 \
                         AND ( \
                           EXISTS (SELECT 1 FROM pg_attribute a \
                                   WHERE a.attrelid = c.oid \
                                     AND a.attnum = ANY(i.indkey) \
                                     AND a.attname = $3) \
                           OR COALESCE(pg_get_expr(i.indpred, i.indrelid), '') \
                              ~ ('\\m' || $3 || '\\M') \
                         ) \
                     )",
                )
                .bind(schema)
                .bind(table)
                .bind(col)
                .fetch_one(&mut *txn)
                .await
                .map_err(|_| ErrorCode::Internal)?
                .try_get(0)
                .map_err(|_| ErrorCode::Internal)?;
                if covered {
                    indexed.insert(col.clone());
                }
            }
        }
    }

    txn.commit().await.map_err(|_| ErrorCode::Internal)?;
    Ok((indexed, scopes))
}

/// [`exact_enumerate`]'s return: the census verdict plus the returned item ids (sorted by
/// `memory_id` — a deterministic order so two runs over the same snapshot compare bytewise).
#[derive(Debug, Clone, PartialEq)]
pub struct ExactCensusOutcome {
    pub census: CensusResult,
    /// Empty whenever `census` is not `enumerated` — a failed census returns no items
    /// (§22.4: the count that survives is `known_lower_bound`, carried inside the
    /// enumeration when one exists, never a bare id list).
    pub returned_ids: Vec<Uuid>,
}

/// §23.1② overlay, EXACT-channel face (see module doc): scoped to one [`StreamKey`] via `$3..$7` (the registry's
/// post-0079 `enumerable_scope` already claims `$1` = tenant and `$2` = workspace).
///
/// ADR-0071 D-A: uncorrelated — the stream's tombstoned memories are one set the planner hashes once (`NOT IN` over a
/// `NOT NULL` key is the exact anti-join); `ob.tenant_id = $1` holds because the scope fixes
/// `memory_records.tenant_id = $1`. Bounded by the stream, which the census scans whole anyway.
const NOT_TOMBSTONED: &str = "memory_records.memory_id NOT IN ( \
   SELECT me.memory_id FROM private.memory_evidence me \
   JOIN ops.outbox ob ON ob.evidence_id = me.evidence_id AND ob.tenant_id = $1 \
   JOIN projection.stream_log sl \
     ON sl.tenant_id = ob.tenant_id AND sl.scope_kind = $3 AND sl.scope_id = $4 \
    AND sl.domain = $5 AND sl.projection_kind = $6 AND sl.projection_version = $7 \
    AND sl.commit_seq = ob.commit_seq \
   WHERE sl.state = 'TOMBSTONED')";

/// The registry path's lifecycle: final materialization only exposes active, unsuperseded memory rows, and EXACT must
/// not report identifiers that the read path will reject after this snapshot. Bound through the same
/// [`Lifecycle::sql`] fragment as `memory.enumerate`'s selection (ADR-0067 D-J2), with the archive axis not
/// consulted, exactly as the pre-40c-2 `status = 'active' AND superseded_by IS NULL` text.
const ACTIVE_FINAL: Lifecycle = Lifecycle::ACTIVE_FINAL;

/// The candidate universe has already passed read_gate's sole source-visibility authority.
const AUTHORIZED_CANDIDATE: &str = "memory_records.memory_id = ANY($8)";

/// §6.1.3 (ADR-0028 D-D) subject axis, EXACT-channel face: the bound uuid being NULL means
/// "not subject-scoped". `{n}` is the placeholder number, filled by [`subject_scoped`] — the
/// candidate statement binds it as `$8` and the three readout statements as `$9`, so the
/// one fragment cannot hardcode a single `$k` (a mismatch there would silently compare the
/// subject id against an id array).
///
/// It rides inside the census's own WHERE, never as a post-filter, for the same reason
/// `context_repo`'s manifest query carries it inline: a subject-scoped page whose denominator
/// was counted unscoped would report a `coverage` for a universe it never enumerated.
const SUBJECT_SCOPED: &str = "(${n}::uuid IS NULL OR EXISTS ( \
   SELECT 1 FROM private.memory_subjects ms \
   WHERE ms.tenant_id = memory_records.tenant_id \
     AND ms.memory_id = memory_records.memory_id AND ms.subject_id = ${n}))";

fn subject_scoped(placeholder: u8) -> String {
    SUBJECT_SCOPED.replace("{n}", &placeholder.to_string())
}

/// ADR-0062 D-K segment axis, EXACT-channel face: a later manifest segment of `memory.enumerate` counts only
/// `memory_id < bound` (NULL = the first segment, the whole universe). Same placeholder rule as [`SUBJECT_SCOPED`]:
/// the candidate statement binds it as `$9`, the three readout statements as `$10`.
const BEFORE_BOUNDED: &str = "(${n}::uuid IS NULL OR memory_records.memory_id < ${n})";

fn before_bounded(placeholder: u8) -> String {
    BEFORE_BOUNDED.replace("{n}", &placeholder.to_string())
}

/// ADR-0110 D-F project axis, EXACT-channel face: the one place in the workspace's census code that names
/// `private.memory_in_project` (migration 0282), which reads the live attribution view, so a revoked link is outside
/// the project universe and the M29 reader arm stays the single read path. `$1` is the tenant (the
/// `enumerable_scope` contract); `{n}` is the project placeholder, filled by [`project_scoped`].
const IN_PROJECT: &str = "private.memory_in_project($1, memory_records.memory_id, ${n}::uuid)";

/// ` AND ` + [`IN_PROJECT`] for a project-scoped call and the empty string otherwise. Unlike the `NULL`-guarded
/// axes above, an absent project leaves no placeholder in the text, so a project-less census runs byte for byte the
/// SQL it ran before ADR-0110 D-F; statement and bind agree through [`bind_project`].
fn project_scoped(project: Option<ProjectId>, placeholder: u8) -> String {
    project.map_or_else(String::new, |_| {
        format!(
            " AND {}",
            IN_PROJECT.replace("{n}", &placeholder.to_string())
        )
    })
}

/// Binds [`project_scoped`]'s one value after whatever `query` already bound; `None` binds nothing, because the
/// statement then has no placeholder for it.
fn bind_project<'q>(
    query: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    project: Option<ProjectId>,
) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
    match project {
        Some(project) => query.bind(project.0),
        None => query,
    }
}

/// ADR-0067 D-G note axes, both faces: `note_kind` ∈ the bound `text[]` of wire strings, then `occurred_at` in the
/// half-open window `[since, until)`. A NULL bind means "axis absent"; a row with NULL `occurred_at` fails either bound
/// (`NULL >= x` is not true), so it is outside every bounded window. Same placeholder rule as [`SUBJECT_SCOPED`].
const NOTE_KIND_IN: &str = "(${n}::text[] IS NULL OR memory_records.note_kind = ANY(${n}))";
const OCCURRED_SINCE: &str = "(${n}::timestamptz IS NULL OR memory_records.occurred_at >= ${n})";
const OCCURRED_UNTIL: &str = "(${n}::timestamptz IS NULL OR memory_records.occurred_at < ${n})";
/// ADR-0067 D-J2: an exact match on the version's note (NULL = any note or none).
const NOTE_ID_IS: &str = "(${n}::uuid IS NULL OR memory_records.note_id = ${n})";

/// The note-axis conjuncts on placeholders `first ..= first + 5` — kinds, since, until, note_id, then the D-J2
/// lifecycle's statuses and archive mode ([`Lifecycle::sql`]) — the one text both `context_repo`'s manifest candidate
/// query and every census statement run (§22.1 one predicate, two faces). [`bind_note_axes`] binds them in this order.
pub(crate) fn note_axes(first: u8) -> String {
    format!(
        "{} AND {} AND {} AND {} AND {}",
        NOTE_KIND_IN.replace("{n}", &first.to_string()),
        OCCURRED_SINCE.replace("{n}", &(first + 1).to_string()),
        OCCURRED_UNTIL.replace("{n}", &(first + 2).to_string()),
        NOTE_ID_IS.replace("{n}", &(first + 3).to_string()),
        Lifecycle::sql("memory_records", first + 4),
    )
}

/// Binds [`note_axes`]' six values, in its placeholder order, after whatever `query` already bound.
pub(crate) fn bind_note_axes<'q>(
    query: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    notes: &NoteEnumerationFilter,
) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
    query
        .bind(notes.kind_wires())
        .bind(notes.occurred_since)
        .bind(notes.occurred_until)
        .bind(notes.note_id)
        .bind(notes.lifecycle.status_wires())
        .bind(notes.lifecycle.archive_wire())
}

/// §18/§22.1 `SECRET_MATERIAL` linkage: a memory whose evidence chain carries secret material
/// is excluded from `returned` and counted by `excluded_secret`. ADR-0071 D-A: an uncorrelated set (hashed once),
/// bounded by the authorized ids `$8` every readout statement binds; `memory_evidence.memory_id` is `NOT NULL`, so
/// `NOT ( … IN … )` is the exact negation.
const SECRET_LINKED: &str = "memory_records.memory_id IN ( \
   SELECT me2.memory_id FROM private.memory_evidence me2 \
   JOIN private.evidence_objects eo ON eo.evidence_id = me2.evidence_id \
   WHERE me2.memory_id = ANY($8) AND eo.data_class = 'SECRET_MATERIAL')";

/// The readout statements' binds: `$1..$7` tenant, workspace, stream key; `$8` authorized ids; `$9` subject; `$10`
/// segment bound; `$11..$16` [`note_axes`]; `$17` the project, only when the call names one ([`project_scoped`]).
fn bind_readout<'q>(
    sql: &'q str,
    args: &CensusArgs<'q>,
) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
    bind_project(
        bind_note_axes(
            sqlx::query(sql)
                .bind(args.tenant_id)
                .bind(args.workspace_id)
                .bind(&args.stream.scope_kind)
                .bind(args.stream.scope_id)
                .bind(&args.stream.domain)
                .bind(&args.stream.projection_kind)
                .bind(&args.stream.projection_version)
                .bind(args.authorized_ids)
                .bind(args.subject_id)
                .bind(args.before_id),
            args.notes,
        ),
        args.project_id,
    )
}

async fn census_count(txn: &mut Txn<'_>, sql: &str, args: &CensusArgs<'_>) -> sqlx::Result<i64> {
    bind_readout(sql, args)
        .fetch_one(&mut **txn)
        .await?
        .try_get(0)
}

struct CensusArgs<'a> {
    tenant_id: Uuid,
    workspace_id: Uuid,
    stream: &'a StreamKey,
    authorized_ids: &'a [Uuid],
    subject_id: Option<Uuid>,
    before_id: Option<Uuid>,
    notes: &'a NoteEnumerationFilter,
    project_id: Option<ProjectId>,
}

// ponytail: the candidate pass carries no project axis (the three readout statements decide membership), so a
// project-scoped call still gates the whole stream's candidates through `readable_memory_ids`; bind the axis here
// too if E-M13-1 shows that pass over budget (ADR-0110 D-F)
struct CandidateQuery<'a> {
    authorization: &'a AuthorizationScope,
    workspace_id: WorkspaceId,
    stream: &'a StreamKey,
    scope: &'a str,
    predicate: &'a str,
    subject_id: Option<Uuid>,
    before_id: Option<Uuid>,
    notes: &'a NoteEnumerationFilter,
    readable: Option<&'a GateReadable>,
}

async fn authorized_candidate_ids(
    txn: &mut Txn<'_>,
    query: &CandidateQuery<'_>,
) -> Result<Vec<Uuid>, ErrorCode> {
    // $1 tenant, $2 workspace, $3..$7 stream key, $8 subject, $9 segment bound, $10..$15 `note_axes` (kinds, since,
    // until, note_id, then the ADR-0067 D-J2 lifecycle's statuses and archive mode).
    let candidates_sql = format!(
        "SELECT memory_id FROM {} AND ({}) AND {NOT_TOMBSTONED} AND {} AND {} \
         AND {} ORDER BY memory_id",
        query.scope,
        query.predicate,
        subject_scoped(8),
        before_bounded(9),
        note_axes(10),
    );
    let candidates: Vec<Uuid> = match bind_note_axes(
        sqlx::query(&candidates_sql)
            .bind(query.authorization.tenant_id().0)
            .bind(query.workspace_id.0)
            .bind(&query.stream.scope_kind)
            .bind(query.stream.scope_id)
            .bind(&query.stream.domain)
            .bind(&query.stream.projection_kind)
            .bind(&query.stream.projection_version)
            .bind(query.subject_id)
            .bind(query.before_id),
        query.notes,
    )
    .fetch_all(&mut **txn)
    .await
    {
        Ok(rows) => rows
            .iter()
            .map(|row| row.try_get::<Uuid, _>("memory_id"))
            .collect::<Result<_, _>>()
            .map_err(|_| ErrorCode::Internal)?,
        Err(_) => return Err(ErrorCode::Internal),
    };
    let mut authorized_ids: Vec<_> = match query.readable {
        Some(readable) => candidates
            .into_iter()
            .filter(|id| readable.contains(id))
            .collect(),
        None => readable_memory_ids(txn, query.authorization, &candidates)
            .await?
            .into_iter()
            .collect(),
    };
    authorized_ids.sort_unstable();
    Ok(authorized_ids)
}

/// The three readout statements of one census run. Each is built from the one `axes` text, so the count, the items
/// and the secret count cannot disagree on the universe they describe (§22.1 one predicate, several faces).
struct ReadoutSql {
    total: String,
    ids: String,
    secret: String,
}

fn readout_sql(scope: &str, predicate: &str, project: Option<ProjectId>) -> ReadoutSql {
    // `bind_readout`'s map: `$9` subject, `$10` segment bound, `$11..$16` `note_axes` (incl. the D-J2 lifecycle), then
    // `$17` the project when the call names one (ADR-0110 D-F).
    let axes = format!(
        "{} AND {} AND {}{}",
        subject_scoped(9),
        before_bounded(10),
        note_axes(11),
        project_scoped(project, 17)
    );
    ReadoutSql {
        total: format!(
            "SELECT count(*) FROM {scope} AND ({predicate}) AND {NOT_TOMBSTONED} \
             AND {AUTHORIZED_CANDIDATE} AND {axes}"
        ),
        ids: format!(
            "SELECT memory_id FROM {scope} AND ({predicate}) AND {NOT_TOMBSTONED} \
             AND {AUTHORIZED_CANDIDATE} AND {axes} AND NOT ({SECRET_LINKED}) ORDER BY memory_id"
        ),
        secret: format!(
            "SELECT count(*) FROM {scope} AND ({predicate}) AND {NOT_TOMBSTONED} \
             AND {AUTHORIZED_CANDIDATE} AND {axes} AND {SECRET_LINKED}"
        ),
    }
}

async fn census_readout(
    txn: &mut Txn<'_>,
    scope: &str,
    predicate: &str,
    args: &CensusArgs<'_>,
) -> Result<(i64, Vec<Uuid>, i64), ErrorCode> {
    let sql = readout_sql(scope, predicate, args.project_id);
    let total = census_count(txn, &sql.total, args)
        .await
        .map_err(|_| ErrorCode::Internal)?;

    let ids: Vec<Uuid> = bind_readout(&sql.ids, args)
        .fetch_all(&mut **txn)
        .await
        .map_err(|_| ErrorCode::Internal)?
        .iter()
        .map(|row| row.try_get::<Uuid, _>("memory_id"))
        .collect::<Result<_, _>>()
        .map_err(|_| ErrorCode::Internal)?;

    let excluded_secret = census_count(txn, &sql.secret, args)
        .await
        .map_err(|_| ErrorCode::Internal)?;
    Ok((total, ids, excluded_secret))
}

/// One §22.1 census run's inputs, independent of where the `enumerable_scope` /
/// `sql_predicate` fragments came from.
///
/// Both fragments are interpolated, not bound, so both callers must supply server-owned text —
/// a `control.retrieval_predicates` row (§50 typed config, CHECK-constrained, the
/// [`exact_enumerate`] path) or a `const` next to the query whose denominator it describes
/// (`read_gate`'s trusted `memory.enumerate` route, whose predicate id is frozen in
/// `domain::selection` and never reaches §20.2's surface-pattern planner). Caller input must
/// never reach these two fields.
pub struct CensusInputs<'a> {
    /// §22.0: the identity that rides on the wire with the readout; blank is unconstructible.
    pub predicate_id: &'a str,
    /// §22.1 "计 total 的 FROM + 租户过滤" — `$1` = tenant, `$2` = workspace.
    pub enumerable_scope: &'a str,
    pub sql_predicate: &'a str,
    /// Already narrowed to `workspace` by the caller; re-checked against `stream` below.
    pub authorization: &'a AuthorizationScope,
    pub workspace: WorkspaceId,
    pub stream: &'a StreamKey,
    /// §6.1.3 (ADR-0028 D-D): restrict the universe to memories linked to this subject.
    pub subject_id: Option<Uuid>,
    /// ADR-0062 D-K: restrict the universe to `memory_id < before_id` (a later manifest segment); `None` = whole.
    pub before_id: Option<Uuid>,
    /// ADR-0067 D-G / D-J2: the note axes (kinds, `occurred_at` window, note) and the lifecycle selection, bound on
    /// every statement; the default is "no note axis" under [`Lifecycle::CURRENT`].
    pub notes: &'a NoteEnumerationFilter,
    /// ADR-0110 D-F: restrict the universe to memories with a live link to this project, decided by
    /// `private.memory_in_project` on the count, items and secret statements alike; `None` = no project axis and the
    /// pre-D-F SQL text.
    pub project_id: Option<ProjectId>,
    /// ADR-0071 D-C: the shared final gate's `can_read` set, computed in this snapshot over a superset of this census's
    /// candidates (`memory.enumerate`'s mint: same scope and predicate without the stream overlay). The census narrows
    /// its own candidates by membership; `None` = run [`readable_memory_ids`] here. A candidate outside the set is
    /// dropped, so a mismatch shrinks the census and fails the mint's set-equality cross-check, never widens it.
    pub readable: Option<&'a GateReadable>,
}

/// §22.1 census inside a transaction the caller owns (isolation level and the RLS GUCs are
/// already installed — this function must run in the SAME snapshot as the items the readout
/// describes, which is the whole point of it not opening its own transaction).
///
/// Every statement runs inside a `SAVEPOINT`: a statement-level failure (§22.4 trigger 4)
/// aborts only the nested transaction, so the caller's outer transaction — which still has a
/// page, bodies and a ledger to read in this snapshot — survives to return a degraded
/// envelope instead of a transport error.
///
/// # Errors
/// [`ErrorCode::Forbidden`] when `stream` is not the caller's own workspace stream.
/// [`ErrorCode::Internal`] only when the savepoint itself cannot be opened or released.
pub(crate) async fn census_in_txn(
    txn: &mut Txn<'_>,
    inputs: &CensusInputs<'_>,
) -> Result<ExactCensusOutcome, ErrorCode> {
    if inputs.stream.tenant_id != inputs.authorization.tenant_id()
        || inputs.stream.scope_kind != "workspace"
        || inputs.stream.scope_id != inputs.workspace.0
    {
        return Err(ErrorCode::Forbidden);
    }
    // dep: PostgreSQL(any) — opens a PostgreSQL transaction
    let mut sp = txn.begin().await.map_err(|_| ErrorCode::Internal)?;
    let readout = census_readout_in_savepoint(&mut sp, inputs).await;
    match readout {
        Ok(readout) => {
            sp.commit().await.map_err(|_| ErrorCode::Internal)?;
            Ok(readout)
        }
        // The savepoint is rolled back (not committed) so the outer transaction is usable
        // again even when the failing statement aborted this nested one.
        Err(()) => {
            let _ = sp.rollback().await;
            Ok(ExactCensusOutcome {
                census: CensusResult::failed(),
                returned_ids: Vec::new(),
            })
        }
    }
}

/// The three §22.1 statements plus the authorized-candidate narrowing. `Err(())` = §22.4
/// trigger 4 (this census cannot be established), never a transport error to propagate.
async fn census_readout_in_savepoint(
    sp: &mut Txn<'_>,
    inputs: &CensusInputs<'_>,
) -> Result<ExactCensusOutcome, ()> {
    let candidate_query = CandidateQuery {
        authorization: inputs.authorization,
        workspace_id: inputs.workspace,
        stream: inputs.stream,
        scope: inputs.enumerable_scope,
        predicate: inputs.sql_predicate,
        subject_id: inputs.subject_id,
        before_id: inputs.before_id,
        notes: inputs.notes,
        readable: inputs.readable,
    };
    let authorized_ids = authorized_candidate_ids(sp, &candidate_query)
        .await
        .map_err(|_| ())?;
    let args = CensusArgs {
        tenant_id: inputs.authorization.tenant_id().0,
        workspace_id: inputs.workspace.0,
        stream: inputs.stream,
        authorized_ids: &authorized_ids,
        subject_id: inputs.subject_id,
        before_id: inputs.before_id,
        notes: inputs.notes,
        project_id: inputs.project_id,
    };
    let (total, ids, excluded_secret) =
        census_readout(sp, inputs.enumerable_scope, inputs.sql_predicate, &args)
            .await
            .map_err(|_| ())?;

    // Negative counts cannot come out of count(*); the casts below are shape-only.
    let total = u64::try_from(total).map_err(|_| ())?;
    let excluded = u64::try_from(excluded_secret).map_err(|_| ())?;
    let returned = ids.len() as u64;
    // The constructor refusing our own readout means the three statements disagree beyond what
    // one snapshot allows — that *is* a failed census (§22.4 trigger 4), not a transport error.
    // ponytail: unresolved count not reported until the recall.list(project) wire card names its field (ADR-0110 D-F)
    let enumeration =
        ExactEnumeration::new(inputs.predicate_id, total, returned, excluded).map_err(|_| ())?;
    Ok(ExactCensusOutcome {
        census: CensusResult::enumerated(enumeration),
        returned_ids: ids,
    })
}

/// Runs the §22.1 census for one already-established registry predicate (the caller has run
/// [`probe_predicate_inputs`] → `decide()` and got `PlannerDecision::Enumerate`; running this
/// for an unestablished predicate measures nothing the classifier will ever consume).
///
/// This is [`exact_enumerate_in_project`] with no project axis; see there for the transaction and error contract.
///
/// # Errors
/// As [`exact_enumerate_in_project`].
pub async fn exact_enumerate(
    pool: &RuntimeDbPool,
    entry: &PredicateEntry,
    authorization: &AuthorizationScope,
    requested_workspace: WorkspaceId,
    stream: &StreamKey,
) -> Result<ExactCensusOutcome, ErrorCode> {
    exact_enumerate_in_project(
        pool,
        entry,
        authorization,
        requested_workspace,
        stream,
        None,
    )
    .await
}

/// [`exact_enumerate`] with the ADR-0110 D-F project axis: `Some(project)` counts and returns only the memories of the
/// registry universe that have a live link to `project` (`private.memory_in_project`), on the count and the items
/// statements of the same snapshot, so `returned_ids` is a subset of the counted `total` universe by construction
/// (§22.1 one predicate, two faces). A memory with no live link is outside every project universe and is neither
/// counted nor returned. `None` is the project-less census, whose SQL and results are those of [`exact_enumerate`].
///
/// One `REPEATABLE READ READ ONLY` transaction first establishes the raw scope/predicate
/// candidate ids, passes them through `read_gate::readable_memory_ids` (the sole backing
/// source-visibility authority), then performs independent total, returned-id, and
/// excluded-secret statements over the resulting authorized candidate universe.
///
/// The registry fragments (`enumerable_scope` / `sql_predicate`) are interpolated, not bound:
/// they are §50 typed config from `control.retrieval_predicates` (operator-written,
/// fail-loud-validated, CHECK-constrained), not caller input — same trust boundary as the
/// migration files themselves. The project id is bound, never interpolated.
///
/// # Errors
/// [`ErrorCode::Internal`] only when the transaction itself cannot be opened/committed. A
/// statement-level failure inside the census (e.g. a predicate referencing a column the
/// snapshot does not have) is §22.4 trigger 4 — returned as `Ok` with
/// [`CensusResult::failed`], so `classify()` renders it `cannot_establish/census_failed`
/// instead of this adapter swallowing the verdict into a transport error. A project the caller cannot see yields
/// `total` 0, not an error.
pub async fn exact_enumerate_in_project(
    pool: &RuntimeDbPool,
    entry: &PredicateEntry,
    authorization: &AuthorizationScope,
    requested_workspace: WorkspaceId,
    stream: &StreamKey,
    project_id: Option<ProjectId>,
) -> Result<ExactCensusOutcome, ErrorCode> {
    let authorization = authorization.narrow(requested_workspace)?;
    // dep: PostgreSQL(any) — opens a PostgreSQL transaction
    let mut txn = pool.pool().begin().await.map_err(|_| ErrorCode::Internal)?;
    // 必须是本事务第一条语句：隔离级在第一个取快照的语句之后就改不了了（context_repo 同款）。
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *txn)
        .await
        .map_err(|_| ErrorCode::Internal)?;
    set_authorization_local(&mut txn, &authorization).await?;

    // ADR-0067 D-J2: the registry path keeps `ACTIVE_FINAL` and no note axis.
    let registry_axes = NoteEnumerationFilter {
        lifecycle: ACTIVE_FINAL,
        ..NoteEnumerationFilter::default()
    };
    let outcome = census_in_txn(
        &mut txn,
        &CensusInputs {
            predicate_id: entry.predicate_id(),
            enumerable_scope: entry.enumerable_scope(),
            sql_predicate: entry.sql_predicate(),
            authorization: &authorization,
            workspace: requested_workspace,
            stream,
            subject_id: None,
            before_id: None,
            notes: &registry_axes,
            project_id,
            readable: None,
        },
    )
    .await;
    match outcome {
        Ok(outcome) => {
            txn.commit().await.map_err(|_| ErrorCode::Internal)?;
            Ok(outcome)
        }
        Err(error) => {
            // Commit rather than roll back: the transaction only read.
            let _ = txn.commit().await;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AUTHORIZED_CANDIDATE, NOT_TOMBSTONED, ProjectId, SECRET_LINKED, before_bounded, note_axes,
        project_scoped, readout_sql, scope_table, subject_scoped,
    };

    const SCOPE: &str = "private.memory_records WHERE memory_records.tenant_id = $1";
    const CALL: &str = "private.memory_in_project($1, memory_records.memory_id, $17::uuid)";

    /// ADR-0110 D-F: a project-less census runs the SQL it ran before the project axis existed. The expected text is
    /// that earlier recipe spelled out, so touching the `None` path (a placeholder, a guard, a space) is red.
    #[test]
    fn project_less_readout_sql_is_the_pre_d_f_text() {
        let subject = format!(
            "{} AND {} AND {}",
            subject_scoped(9),
            before_bounded(10),
            note_axes(11)
        );
        let got = readout_sql(SCOPE, "true", None);
        let head = format!(
            "FROM {SCOPE} AND (true) AND {NOT_TOMBSTONED} AND {AUTHORIZED_CANDIDATE} AND {subject}"
        );
        assert_eq!(got.total, format!("SELECT count(*) {head}"));
        assert_eq!(
            got.ids,
            format!("SELECT memory_id {head} AND NOT ({SECRET_LINKED}) ORDER BY memory_id")
        );
        assert_eq!(
            got.secret,
            format!("SELECT count(*) {head} AND {SECRET_LINKED}")
        );
        assert_eq!(project_scoped(None, 17), "");
    }

    /// ADR-0110 D-F: the count, the items and the secret statements carry the identical project conjunct (so items stay
    /// inside the counted universe), and it names the predicate, never the attribution table or its live view.
    #[test]
    fn project_axis_is_one_predicate_call_on_all_three_statements() {
        let project = ProjectId::new();
        assert_eq!(project_scoped(Some(project), 17), format!(" AND {CALL}"));
        let got = readout_sql(SCOPE, "true", Some(project));
        for (face, sql) in [
            ("total", &got.total),
            ("ids", &got.ids),
            ("secret", &got.secret),
        ] {
            assert_eq!(sql.matches(CALL).count(), 1, "{face}: one project conjunct");
            assert!(
                !sql.contains("memory_projects"),
                "{face}: no attribution read"
            );
        }
    }

    #[test]
    fn scope_table_parses_the_registry_shape_and_rejects_mixed_scopes() {
        assert_eq!(
            scope_table("private.memory_records WHERE visibility_workspace_id = $1"),
            Some(("private", "memory_records"))
        );
        // §22.4 trigger 3's shape: a mixed private+public enumeration has no single probe-able
        // table face — the parser refuses, so `decide()` never sees it as established.
        assert_eq!(
            scope_table("private.memory_records JOIN public.pool USING (x) WHERE y = $1"),
            None
        );
        assert_eq!(scope_table("no_schema_qualifier WHERE x = $1"), None);
        assert_eq!(
            scope_table("private.memory_records; DROP TABLE x WHERE a = $1"),
            None
        );
    }
}
