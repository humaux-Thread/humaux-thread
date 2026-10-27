//! `adapters::coord_task_repo` — M18's task→project authority: the one writer of `coord.tasks.project_id`, which in the
//!   same transaction closes and opens the Project CONTAINS Task revisions that mirror it (ADR-0102 D-A, D-C).
//! Depends-on: crates=[humaux-domain, sqlx]; services=[PostgreSQL(role_gateway) r=[private.project_task_relations]
//!   w=[coord.tasks, coord.workspace_unfiled_projects] x=[private.declared_project_visible,
//!   private.register_continuity_project]]; env=[]; modules=[adapters::relation_repo, domain::continuity,
//!   domain::coordination, domain::error, domain::identity, domain::ids, domain::relation]
//! Called-by: [adapters::coord_repo, tests]
//! Invariants: [coord.tasks.project_id is written only here: the INSERT by insert_task_in_txn, the UPDATE by
//!   set_task_project_in_txn; that UPDATE closes the old CONTAINS edge's valid and opens the new one in the same
//!   transaction, both at one DB-clock instant read after the task row lock, so the edges never overlap and never leave
//!   a gap; every CONTAINS revision goes through relation_repo::append_contains_revision from one call site (xtask
//!   m18_task_project_sole_writer); an Unfiled project carries no CONTAINS edge (N09 R3, never a default); provenance
//!   (decided_by, factual and authorization Evidence) is the caller's, this module mints none; every rejection is an
//!   existing ErrorCode]
//! Spec: Baseline §6.1.4; §30; §52; ADR-0078 D-C; ADR-0101 D-B; ADR-0102 D-A; ADR-0102 D-C; ADR-0102 D-D
//!
//! Both doors run in the caller's transaction, under the caller's role (`role_gateway`) and RLS: the caller has already
//! installed `humaux.tenant_id` and `humaux.user_id` (`coord_repo::submit` does, through `set_authorization_local`),
//! owns COMMIT, and runs at READ COMMITTED.
//!
//! The Unfiled project of a workspace is the marker row of `coord.workspace_unfiled_projects` (0289), registered lazily
//! through `private.register_continuity_project` (the project row plus its 15 facet slots, 0136) by the first task
//! submit of that workspace.
//!
//! Rejections (§52, no new variant):
//! - a submit scope that does not hold exactly one workspace: [`ErrorCode::InvalidInput`];
//! - a target project that is unknown, another tenant's, outside the scope's workspaces or ARCHIVED, and an absent
//!   task: [`ErrorCode::NotFound`] (0254 ②: one answer for all of them, no existence oracle);
//! - a relation write the kernel refuses (0249, 0253): [`ErrorCode::InvalidInput`] / [`ErrorCode::Conflict`];
//! - PG failure: [`ErrorCode::DependencyUnavailable`].

use std::ops::Bound;

use humaux_domain::continuity::ProjectId;
use humaux_domain::coordination::TaskState;
use humaux_domain::error::ErrorCode;
use humaux_domain::identity::AuthorizationScope;
use humaux_domain::ids::{TaskId, WorkspaceId};
use humaux_domain::relation::{
    DecidedBy, RawRange, RelationEdge, RelationId, RelationKind, RelationPair, Timestamp, Validity,
};
use sqlx::types::Uuid;

use crate::relation_repo::{self, Provenance};

type Txn<'c> = sqlx::Transaction<'c, sqlx::Postgres>;

/// ADR-0102 D-D: the title of every workspace's Unfiled project. Identity is the marker row, never this text.
const UNFILED_TITLE: &str = "Unfiled";

/// §52 mapping for this module's statements: a lost race or serialization failure is `CONFLICT`, a refused value
/// (FK, CHECK, invalid argument) is `INVALID_INPUT`, a refused context is `FORBIDDEN`.
fn db_error(error: sqlx::Error) -> ErrorCode {
    match error
        .as_database_error()
        .and_then(|db| db.code())
        .as_deref()
    {
        Some("23505" | "40001" | "40P01") => ErrorCode::Conflict,
        Some("23503" | "23514" | "22023") => ErrorCode::InvalidInput,
        Some("42501") => ErrorCode::Forbidden,
        _ => ErrorCode::DependencyUnavailable,
    }
}

/// The only workspace of `scope`. A submit names no project, so the scope the guard admitted (narrowed to the
/// credential's bound workspace or the request's) is the only thing that places the task; zero or several is
/// `INVALID_INPUT`, never a guess.
fn sole_workspace(scope: &AuthorizationScope) -> Result<WorkspaceId, ErrorCode> {
    let mut workspaces = scope.allowed_workspace_ids().iter();
    match (workspaces.next(), workspaces.next()) {
        (Some(only), None) => Ok(*only),
        _ => Err(ErrorCode::InvalidInput),
    }
}

/// ADR-0102 D-D: the Unfiled project of the scope's only workspace, registered on first use. The registration (project
/// row, 15 facet slots) and the marker row are written in the caller's transaction, so a rolled-back submit leaves
/// neither. A transaction-scoped advisory lock keyed by (tenant, workspace) makes two first submits of one workspace
/// take turns: the second one's fresh statement then sees the committed marker.
pub(crate) async fn unfiled_project_in_txn(
    txn: &mut Txn<'_>,
    scope: &AuthorizationScope,
) -> Result<ProjectId, ErrorCode> {
    let workspace = sole_workspace(scope)?.0;
    let tenant = scope.tenant_id().0;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("unfiled-project:{tenant}:{workspace}"))
        .execute(&mut **txn)
        .await
        .map_err(db_error)?;
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT project_id FROM coord.workspace_unfiled_projects WHERE tenant_id = $1 AND workspace_id = $2",
    )
    .bind(tenant)
    .bind(workspace)
    .fetch_optional(&mut **txn)
    .await
    .map_err(db_error)?;
    if let Some(project) = existing {
        return Ok(ProjectId(project));
    }
    // 0136: the registration door asserts the continuity GUCs against its own arguments.
    sqlx::query(
        "SELECT set_config('humaux.workspace_id', $1, true), set_config('humaux.principal_id', $2, true)",
    )
    .bind(workspace.to_string())
    .bind(scope.principal().0.to_string())
    .execute(&mut **txn)
    .await
    .map_err(db_error)?;
    let project = ProjectId::new();
    sqlx::query("SELECT private.register_continuity_project($1, $2, $3, $4, $5, $6)")
        .bind(tenant)
        .bind(workspace)
        .bind(project.0)
        .bind(scope.principal().0)
        .bind(scope.user_id().map(|user| user.0))
        .bind(UNFILED_TITLE)
        .execute(&mut **txn)
        .await
        .map_err(db_error)?;
    sqlx::query(
        "INSERT INTO coord.workspace_unfiled_projects (tenant_id, workspace_id, project_id) VALUES ($1, $2, $3)",
    )
    .bind(tenant)
    .bind(workspace)
    .bind(project.0)
    .execute(&mut **txn)
    .await
    .map_err(db_error)?;
    Ok(project)
}

/// Inserts a task in `SUBMITTED` (§30.1) under the scope's tenant in `project`, carrying the wire's `description`
/// (ADR-0078 Q10). The one `INSERT` of `coord.tasks` (ADR-0102 D-A); a task born in a non-Unfiled project would also need
/// its CONTAINS edge, so `coord_repo::submit` only ever passes the Unfiled project of [`unfiled_project_in_txn`].
pub(crate) async fn insert_task_in_txn(
    txn: &mut Txn<'_>,
    scope: &AuthorizationScope,
    title: &str,
    description: &str,
    project: ProjectId,
) -> Result<TaskId, ErrorCode> {
    let task_id: Uuid = sqlx::query_scalar(
        "INSERT INTO coord.tasks (tenant_id, title, description, state, project_id) VALUES ($1, $2, $3, $4, $5) \
         RETURNING task_id",
    )
    .bind(scope.tenant_id().0)
    .bind(title)
    .bind(description)
    .bind(TaskState::Submitted.as_db_str())
    .bind(project.0)
    .fetch_one(&mut **txn)
    .await
    .map_err(db_error)?;
    Ok(TaskId(task_id))
}

/// One CONTAINS segment as the raw range [`Validity::new`] validates.
fn range((start, end): (i64, Option<i64>)) -> RawRange {
    (
        Bound::Included(Timestamp::Micros(start)),
        end.map_or(Bound::Unbounded, |end| {
            Bound::Excluded(Timestamp::Micros(end))
        }),
    )
}

/// The `project CONTAINS task` edge.
fn contains_edge(project: Uuid, task: TaskId) -> RelationEdge {
    RelationEdge {
        src_id: project,
        kind: RelationKind::Contains,
        dst_id: task.0,
    }
}

/// Whether `project` is a workspace's Unfiled project (the marker row, ADR-0102 D-D).
async fn is_unfiled(txn: &mut Txn<'_>, tenant: Uuid, project: Uuid) -> Result<bool, ErrorCode> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM coord.workspace_unfiled_projects WHERE tenant_id = $1 AND project_id = $2)",
    )
    .bind(tenant)
    .bind(project)
    .fetch_one(&mut **txn)
    .await
    .map_err(db_error)
}

/// The relation id of `project CONTAINS task`: the edge's revision-1 row is unique (0252), so an edge keeps one id for
/// life and moving a task back to a project reopens the same relation.
async fn contains_relation(
    txn: &mut Txn<'_>,
    tenant: Uuid,
    project: Uuid,
    task: TaskId,
) -> Result<Option<RelationId>, ErrorCode> {
    let relation: Option<Uuid> = sqlx::query_scalar(
        "SELECT relation_id FROM private.project_task_relations \
         WHERE tenant_id = $1 AND src_id = $2 AND dst_id = $3 AND relation_kind = $4 AND revision = 1",
    )
    .bind(tenant)
    .bind(project)
    .bind(task.0)
    .bind(RelationKind::Contains.as_str())
    .fetch_optional(&mut **txn)
    .await
    .map_err(db_error)?;
    Ok(relation.map(RelationId))
}

/// The one call of `relation_repo::append_contains_revision` (ADR-0102 D-C: xtask `m18_task_project_sole_writer` asserts
/// `== 1`), shared by the close and the open step.
async fn append_edge(
    txn: &mut Txn<'_>,
    edge: &RelationEdge,
    relation: RelationId,
    expected_revision: i64,
    valid: &Validity,
    provenance: &Provenance<'_>,
) -> Result<(), ErrorCode> {
    relation_repo::append_contains_revision(
        txn,
        edge,
        relation,
        expected_revision,
        valid,
        provenance,
    )
    .await
    .map(|_revision| ())
}

/// Step 4: ends the open segment of the old edge at `at`. A project without an edge (a legacy row) or an edge with no
/// open segment has nothing to close; the move itself then re-establishes the invariant on the new side.
async fn close_edge(
    txn: &mut Txn<'_>,
    tenant: Uuid,
    project: Uuid,
    task: TaskId,
    at: i64,
    provenance: &Provenance<'_>,
) -> Result<(), ErrorCode> {
    let Some(relation) = contains_relation(txn, tenant, project, task).await? else {
        return Ok(());
    };
    let current = relation_repo::current_revision(txn, RelationPair::ProjectTask, relation)
        .await?
        .ok_or(ErrorCode::Internal)?;
    let segments = current.valid.segments();
    if segments.iter().all(|&(_, end)| end.is_some()) {
        return Ok(());
    }
    // An open segment that starts at or after `at` would end empty or reversed: it is dropped, not closed.
    let ranges: Vec<RawRange> = segments
        .iter()
        .filter_map(|&(start, end)| match end {
            None if start >= at => None,
            None => Some(range((start, Some(at)))),
            Some(_) => Some(range((start, end))),
        })
        .collect();
    let valid = Validity::new(&ranges)?;
    append_edge(
        txn,
        &contains_edge(project, task),
        relation,
        current.revision,
        &valid,
        provenance,
    )
    .await
}

/// Step 5: opens `[at, ∞)` on the new edge, as a further revision of the edge's own relation when it exists (a task
/// that came back to this project) and as relation revision 1 otherwise.
async fn open_edge(
    txn: &mut Txn<'_>,
    tenant: Uuid,
    project: Uuid,
    task: TaskId,
    at: i64,
    provenance: &Provenance<'_>,
) -> Result<(), ErrorCode> {
    let (relation, expected_revision, mut ranges) =
        if let Some(relation) = contains_relation(txn, tenant, project, task).await? {
            let current = relation_repo::current_revision(txn, RelationPair::ProjectTask, relation)
                .await?
                .ok_or(ErrorCode::Internal)?;
            let ranges: Vec<RawRange> = current
                .valid
                .segments()
                .iter()
                .copied()
                .map(range)
                .collect();
            (relation, current.revision, ranges)
        } else {
            (RelationId::new(), 0, Vec::new())
        };
    ranges.push(range((at, None)));
    let valid = Validity::new(&ranges)?;
    append_edge(
        txn,
        &contains_edge(project, task),
        relation,
        expected_revision,
        &valid,
        provenance,
    )
    .await
}

/// ADR-0102 D-A: moves `task` to `project`. Writes `coord.tasks.project_id` and, in this one transaction, ends the old
/// project's CONTAINS edge and opens the new one's at the same DB-clock instant `t`, so A3 attribution
/// (`valid @> occurred_at`, 0252) reads the old project before `t` and the new one from `t`. The caller owns COMMIT;
/// provenance (`decided_by`, `factual_evidence_ids`, `authorization_evidence_id`) passes through to the relation
/// kernel unchanged and this door mints no Evidence (0253).
///
/// In order:
/// 1. `project` must pass `private.declared_project_visible` for the scope's workspaces, else `NOT_FOUND` (an ARCHIVED
///    project fails it too, 0254 ②);
/// 2. the task row is read `FOR UPDATE`; a task already in `project` is `Ok` and nothing is written;
/// 3. `t` is one `clock_timestamp()` read after the lock: the close's upper bound and the open's lower bound;
/// 4. the old edge's open segment ends at `t` (skipped when the old project is an Unfiled project);
/// 5. the new edge is opened at `t` (skipped when `project` is an Unfiled project: Unfiled carries no CONTAINS);
/// 6. the column is updated.
///
/// Two concurrent moves of one task take turns on the row lock, and the second one reads the project the first
/// committed, so a task never has two open CONTAINS edges. Visibility of the old project is not checked: leaving a
/// project widens nothing.
// ponytail: no topology guard until parent_task_id has a writer (ADR-0101 D-B); take TOPOLOGY_GUARD_CLASS then.
pub async fn set_task_project_in_txn(
    txn: &mut Txn<'_>,
    scope: &AuthorizationScope,
    task: TaskId,
    project: ProjectId,
    decided_by: &DecidedBy,
    factual_evidence_ids: &[Uuid],
    authorization_evidence_id: Uuid,
) -> Result<(), ErrorCode> {
    let tenant = scope.tenant_id().0;
    let workspaces: Vec<Uuid> = scope
        .allowed_workspace_ids()
        .iter()
        .map(|workspace| workspace.0)
        .collect();
    let visible: bool = sqlx::query_scalar("SELECT private.declared_project_visible($1, $2, $3)")
        .bind(tenant)
        .bind(project.0)
        .bind(workspaces)
        .fetch_one(&mut **txn)
        .await
        .map_err(db_error)?;
    if !visible {
        return Err(ErrorCode::NotFound);
    }
    let current: Uuid = sqlx::query_scalar(
        "SELECT project_id FROM coord.tasks WHERE tenant_id = $1 AND task_id = $2 FOR UPDATE",
    )
    .bind(tenant)
    .bind(task.0)
    .fetch_optional(&mut **txn)
    .await
    .map_err(db_error)?
    .ok_or(ErrorCode::NotFound)?;
    if current == project.0 {
        return Ok(());
    }
    let at: i64 =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp()) * 1000000)::bigint")
            .fetch_one(&mut **txn)
            .await
            .map_err(db_error)?;
    let provenance = Provenance {
        decided_by,
        proposed_by: None,
        factual_evidence_ids,
        authorization_evidence_id,
    };
    if !is_unfiled(txn, tenant, current).await? {
        close_edge(txn, tenant, current, task, at, &provenance).await?;
    }
    if !is_unfiled(txn, tenant, project.0).await? {
        open_edge(txn, tenant, project.0, task, at, &provenance).await?;
    }
    sqlx::query("UPDATE coord.tasks SET project_id = $3 WHERE tenant_id = $1 AND task_id = $2")
        .bind(tenant)
        .bind(task.0)
        .bind(project.0)
        .execute(&mut **txn)
        .await
        .map_err(db_error)?;
    Ok(())
}
