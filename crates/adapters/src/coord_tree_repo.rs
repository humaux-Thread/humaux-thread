//! `adapters::coord_tree_repo` — M18 tree reads and the sole runtime parent move.
//! Depends-on: crates=[humaux-contracts, humaux-domain, sqlx, uuid]; services=[PostgreSQL(role_gateway) x=[private.project_ancestors, private.project_subtree, private.project_move]]; env=[HUMAUX_COORD_PROJECT_MAX_DEPTH]; modules=[contracts::config_registry, domain::continuity, domain::error, domain::identity, domain::project_tree]
//! Called-by: [tests]
//! Invariants: [ADR-0101 guest columns only; SQL guard precedes fresh reads; registry ACLs stay closed; §78.1 depth comes from typed config]
//! Spec: Baseline §30; §50; §78.1; ADR-0101 D-A; ADR-0101 D-B

use humaux_contracts::config_registry::{ConfigEntry, read_env_var};
use humaux_domain::{
    continuity::ProjectId, error::ErrorCode, identity::AuthorizationScope,
    project_tree::ProjectKind,
};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

/// ADR-0101 D-B: task-graph edits must use this same advisory-lock class, hashed by PostgreSQL.
pub const TOPOLOGY_GUARD_CLASS: &str = "coord.tree";

/// §50: the deployment config entry for `coord.project_max_depth` (root depth is one).
pub fn config_registry() -> [ConfigEntry; 1] {
    [ConfigEntry {
        name: "HUMAUX_COORD_PROJECT_MAX_DEPTH".to_owned(),
        type_name: "positive i32".to_owned(),
        default: Some("8".to_owned()),
        scope: "deployment".to_owned(),
        secret: false,
        reloadability: "static".to_owned(),
        owner_module: "adapters.coord_tree_repo".to_owned(),
    }]
}

/// One authorized registry row; archived projects never appear (0254).
#[derive(Debug, PartialEq, Eq)]
pub struct TreeProject {
    /// Registry identity.
    pub project_id: ProjectId,
    /// The one ownership parent, if any.
    pub parent_id: Option<ProjectId>,
    /// Workspace proven visible by the door.
    pub workspace_id: Uuid,
    /// Closed hierarchy kind.
    pub kind: ProjectKind,
    /// CAS version, incremented by each successful move.
    pub version: i64,
}

fn workspaces(scope: &AuthorizationScope) -> Vec<Uuid> {
    scope
        .allowed_workspace_ids()
        .iter()
        .map(|id| id.0)
        .collect()
}

fn db_error(error: sqlx::Error) -> ErrorCode {
    match error
        .as_database_error()
        .and_then(|db| db.code())
        .as_deref()
    {
        Some("40001") => ErrorCode::Conflict,
        Some("23514" | "23503" | "42501" | "22023" | "25001") => ErrorCode::InvalidInput,
        _ => ErrorCode::DependencyUnavailable,
    }
}

async fn read(
    tx: &mut Transaction<'_, Postgres>,
    scope: &AuthorizationScope,
    project: ProjectId,
    sql: &str,
) -> Result<Vec<TreeProject>, ErrorCode> {
    sqlx::query(sql)
        .bind(scope.tenant_id().0)
        .bind(project.0)
        .bind(workspaces(scope))
        .fetch_all(&mut **tx)
        .await
        .map_err(db_error)?
        .into_iter()
        .map(|row| {
            Ok(TreeProject {
                project_id: ProjectId(row.get("project_id")),
                parent_id: row.get::<Option<Uuid>, _>("parent_id").map(ProjectId),
                workspace_id: row.get("workspace_id"),
                kind: ProjectKind::from_db_str(row.get("kind"))
                    .ok_or(ErrorCode::CannotEstablishCompleteness)?,
                version: row.get("version"),
            })
        })
        .collect()
}

/// ADR-0101 D-A: includes the visible start and its visible ancestors; invisible start means zero rows.
pub async fn ancestors_in_txn(
    tx: &mut Transaction<'_, Postgres>,
    scope: &AuthorizationScope,
    project: ProjectId,
) -> Result<Vec<TreeProject>, ErrorCode> {
    read(
        tx,
        scope,
        project,
        "SELECT * FROM private.project_ancestors($1,$2,$3)",
    )
    .await
}

/// ADR-0101 D-A: includes the visible start and its visible descendants, each checked through 0254.
pub async fn subtree_in_txn(
    tx: &mut Transaction<'_, Postgres>,
    scope: &AuthorizationScope,
    project: ProjectId,
) -> Result<Vec<TreeProject>, ErrorCode> {
    // ponytail: recursive CTE; consider a closure accelerator when depth-8 subtree p95 exceeds its budget.
    read(
        tx,
        scope,
        project,
        "SELECT * FROM private.project_subtree($1,$2,$3)",
    )
    .await
}

/// ADR-0101 D-B: the caller installs the authenticated tenant/principal/user GUCs and owns COMMIT.
/// Cycle/depth refusals are `InvalidInput`, stale CAS is `Conflict`, invisible endpoints are `NotFound`.
pub async fn move_in_txn(
    tx: &mut Transaction<'_, Postgres>,
    scope: &AuthorizationScope,
    project: ProjectId,
    parent: Option<ProjectId>,
    expected_version: i64,
) -> Result<i64, ErrorCode> {
    let [entry] = config_registry();
    let raw = read_env_var(&entry.name)
        .or(entry.default)
        .ok_or(ErrorCode::InvalidInput)?;
    let depth: i32 = raw.parse().map_err(|_| ErrorCode::InvalidInput)?;
    if depth < 1 {
        return Err(ErrorCode::InvalidInput);
    }
    sqlx::query("SELECT set_config('coord.project_max_depth',$1,true)")
        .bind(depth.to_string())
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
    sqlx::query_scalar::<_, Option<i64>>("SELECT private.project_move($1,$2,$3,$4,$5,$6,$7)")
        .bind(scope.tenant_id().0)
        .bind(project.0)
        .bind(parent.map(|id| id.0))
        .bind(expected_version)
        .bind(workspaces(scope))
        .bind(scope.principal().0)
        .bind(scope.user_id().map(|id| id.0))
        .fetch_one(&mut **tx)
        .await
        .map_err(db_error)?
        .ok_or(ErrorCode::NotFound)
}
