//! `adapters::project_rollup` — M14 channel attributes and query-time project references.
//! Depends-on: crates=[humaux-domain, serde, serde_json, sqlx, uuid]; services=[PostgreSQL(role_gateway) x=[private.read_project_rollup, private.set_project_channel]]; env=[]; modules=[domain::continuity, domain::error, domain::identity, domain::subject]
//! Called-by: [tests]
//! Invariants: [§25.3.1 child authorization precedes title, reference and count disclosure; ADR-0095 D-C references never copy bodies into a parent]
//! Spec: Baseline §6.1.4; §25.3.1; ADR-0095 D-B; ADR-0095 D-C

use std::str::FromStr;

use humaux_domain::{
    continuity::{ContinuityFacetKind, ProjectId},
    error::ErrorCode,
    identity::AuthorizationScope,
    subject::SubjectId,
};
use serde::Deserialize;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// ADR-0095's existing registry endpoints; Project→Project nesting remains M29-g2.
#[derive(Debug, Clone, Copy)]
pub enum RollupTarget {
    /// One authorized registry project.
    Project(ProjectId),
    /// Projects serving this BRAND subject.
    Brand(SubjectId),
    /// Projects serving this BUSINESS or a BRAND it owns.
    Business(SubjectId),
}

impl RollupTarget {
    fn parts(self) -> (Uuid, &'static str) {
        match self {
            Self::Project(id) => (id.0, "PROJECT"),
            Self::Brand(id) => (id.0, "BRAND"),
            Self::Business(id) => (id.0, "BUSINESS"),
        }
    }
}

/// An immutable published reference, not a claim about the source's current truth (§25.3.1).
#[derive(Debug, PartialEq, Eq)]
pub struct FacetPin {
    /// One of the closed source-backed facet kinds.
    pub kind: ContinuityFacetKind,
    /// Exact immutable storage version identity.
    pub version_id: Uuid,
    /// Exact version number, never a floating latest pointer.
    pub version: i64,
}

/// Only authorized children contribute to this reference census (ADR-0095 D-C).
#[derive(Debug)]
pub struct RollupChild {
    /// Authorized project identity.
    pub project_id: ProjectId,
    /// Title disclosed only after the child's own workspace check.
    pub title: String,
    /// Optional platform slug; absence never excludes a project.
    pub channel_key: Option<String>,
    /// Published references; no source bodies or derived summaries.
    pub facets: Vec<FacetPin>,
    /// Closed source-backed denominator from §25.3.1.
    pub source_facet_count: usize,
}

/// A complete visible-child census or an error, never a truncated total.
#[derive(Debug)]
pub struct ProjectRollup {
    /// Count after child visibility filtering, including zero.
    pub visible_count: usize,
    /// Deterministically ordered by project identity.
    pub children: Vec<RollupChild>,
}

#[derive(Deserialize)]
struct RawPin {
    kind: String,
    version_id: Uuid,
    version: i64,
}

#[derive(Deserialize)]
struct RawChild {
    project_id: Uuid,
    title: String,
    channel_key: Option<String>,
    facets: Vec<RawPin>,
}

#[derive(Deserialize)]
struct RawRollup {
    visible_count: usize,
    children: Vec<RawChild>,
}

fn child(raw: RawChild) -> Result<RollupChild, ErrorCode> {
    let facets = raw
        .facets
        .into_iter()
        .map(|pin| {
            Ok(FacetPin {
                kind: ContinuityFacetKind::from_str(&pin.kind)
                    .map_err(|_| ErrorCode::CannotEstablishCompleteness)?,
                version_id: pin.version_id,
                version: pin.version,
            })
        })
        .collect::<Result<Vec<_>, ErrorCode>>()?;
    Ok(RollupChild {
        project_id: ProjectId(raw.project_id),
        title: raw.title,
        channel_key: raw.channel_key,
        facets,
        source_facet_count: ContinuityFacetKind::ALL.len(),
    })
}

fn workspaces(scope: &AuthorizationScope) -> Vec<Uuid> {
    scope
        .allowed_workspace_ids()
        .iter()
        .map(|id| id.0)
        .collect()
}

/// §25.3.1: caller owns the transaction and installs the authenticated tenant GUC, as for
/// `declared_project_visible`; the door additionally checks each child's authorized workspace.
pub async fn read_in_txn(
    tx: &mut Transaction<'_, Postgres>,
    scope: &AuthorizationScope,
    target: RollupTarget,
) -> Result<ProjectRollup, ErrorCode> {
    let (id, kind) = target.parts();
    let value: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT private.read_project_rollup($1,$2,$3,$4)")
            .bind(scope.tenant_id().0)
            .bind(id)
            .bind(kind)
            .bind(workspaces(scope))
            .fetch_one(&mut **tx)
            .await
            .map_err(|_| ErrorCode::DependencyUnavailable)?;
    let raw: RawRollup = serde_json::from_value(value.ok_or(ErrorCode::NotFound)?)
        .map_err(|_| ErrorCode::CannotEstablishCompleteness)?;
    // ponytail: ADR-0095 D-C bounds visible children at 64; upgrade to pagination when reached.
    if raw.visible_count > 64 {
        return Err(ErrorCode::CannotEstablishCompleteness);
    }
    Ok(ProjectRollup {
        visible_count: raw.visible_count,
        children: raw
            .children
            .into_iter()
            .map(child)
            .collect::<Result<_, _>>()?,
    })
}

/// ADR-0095 D-B: assigns one platform slug only to an authorized ACTIVE project.
/// Unknown and unauthorized projects share `NOT_FOUND`; malformed slugs are `INVALID_INPUT`.
pub async fn set_channel_in_txn(
    tx: &mut Transaction<'_, Postgres>,
    scope: &AuthorizationScope,
    project: ProjectId,
    channel: &str,
) -> Result<(), ErrorCode> {
    let written: bool = sqlx::query_scalar("SELECT private.set_project_channel($1,$2,$3,$4)")
        .bind(scope.tenant_id().0)
        .bind(project.0)
        .bind(workspaces(scope))
        .bind(channel)
        .fetch_one(&mut **tx)
        .await
        .map_err(|error| {
            if error
                .as_database_error()
                .and_then(|db| db.code())
                .as_deref()
                == Some("23514")
            {
                ErrorCode::InvalidInput
            } else {
                ErrorCode::DependencyUnavailable
            }
        })?;
    if written {
        Ok(())
    } else {
        Err(ErrorCode::NotFound)
    }
}
