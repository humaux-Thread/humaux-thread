//! `adapters::attribution_repo` — M29's implementation of M07's attribution port: rungs A1 (the Evidence's declared
//!   project) and A3 (the verified task run's CONTAINS projects) of the §6.1.4 memory → project ladder; and the one
//!   reader of a memory's live attribution (M29 T07).
//! Depends-on: crates=[async-trait, humaux-domain, sqlx]; services=[PostgreSQL(any) r=[coord.task_runs,
//!   private.evidence_objects, private.evidence_projects, private.evidence_task_runs, private.memory_projects_live,
//!   private.project_task_relations] w=[private.memory_projects]]; env=[]; modules=[adapters::memory_repo,
//!   domain::attribution, domain::authority, domain::continuity, domain::relation]
//! Called-by: [gateway::bootstrap, private-worker::distill, tests]
//! Invariants: [runs only through the door's single port call, in the caller's transaction, under the caller's role
//!   and RLS; every row is deterministic (N09 R1) and carries its rule and decision Evidence (N09 R6); no rung holding
//!   writes nothing, never a default or a most-recent guess (N09 R3); imports no provider, inference, embedding or
//!   HTTP code (xtask G-N09-1); the reader reads only `private.memory_projects_live`, and it is the one non-test
//!   reader of that view (xtask m29_attribution_reader)]
//! Spec: Baseline §6.1.4; §78.2; ADR-0078
//!
//! Both rungs read the Memory's attribution Evidence, which the door resolves from
//! [`crate::memory_repo::AttributionSource`]: the PRIMARY Evidence, or a confirmed candidate's source Evidence. They
//! never copy its task-run carrier. An Evidence the caller cannot see under RLS grounds nothing, so the Memory stays
//! unresolved.
//!
//! Rollups are not Memories: they live in `private.memory_rollups`, never reach the door, and stay unattributed in the
//! first slice. A3' (`correction@1`) is the M29 supersede trigger's (T06b), not this port's.

use humaux_domain::attribution::{self, ProjectLink, RuleId, SourceKind};
use humaux_domain::authority::{EvidenceId, MemoryId};
use humaux_domain::continuity::ProjectId;
use humaux_domain::relation::RelationKind;
use sqlx::types::Uuid;

use crate::memory_repo::MemoryAttribution;

/// The M29 attribution ladder (A1, then A3). Stateless: each composition root holds one and lends it to the door.
#[derive(Debug, Clone, Copy)]
pub struct AttributionLadder;

/// A1 (ADR-0078 D-D): every project the attribution Evidence declares becomes a `DECLARED` / `declared@1` row whose
/// decision Evidence is that Evidence.
const A1_DECLARED: &str = "INSERT INTO private.memory_projects \
       (tenant_id, memory_id, project_id, relation, source_kind, rule_id_ver, decision_evidence_id) \
     SELECT ep.tenant_id, $2, ep.project_id, 'ATTRIBUTED_TO', $4, $5, ep.evidence_id \
       FROM private.evidence_projects ep \
      WHERE ep.tenant_id = $1 AND ep.evidence_id = $3 \
        AND ep.source_kind = $4";

/// A3 (ADR-0078 D-D): the attribution Evidence's verified task run (`evidence_task_runs`, T04c) names a task; every project
/// whose current relation to that task (the highest revision per `relation_id`, §6.1.4 ①) is CONTAINS and valid at the
/// Evidence's `occurred_at` becomes an `INHERITED` / `task_run@1` row. REFERENCES never counts. N09 R3: an Evidence
/// without `occurred_at` has no occurrence time to test, so A3 does not hold and nothing is written (unresolved). A
/// project A1 already wrote keeps its A1 row (the lower rung wins; the conflict target is the primary key). The row
/// records its ground, the task and the `occurred_at` tested (0255 ⑥): a relation correction revokes by them without
/// reading the Evidence again.
const A3_TASK_RUN: &str = "INSERT INTO private.memory_projects \
       (tenant_id, memory_id, project_id, relation, source_kind, rule_id_ver, decision_evidence_id, \
        derived_task_id, derived_occurred_at) \
     SELECT etr.tenant_id, $2, cur.src_id, 'ATTRIBUTED_TO', $4, $5, etr.evidence_id, tr.task_id, e.occurred_at \
       FROM private.evidence_task_runs etr \
       JOIN private.evidence_objects e ON e.tenant_id = etr.tenant_id AND e.evidence_id = etr.evidence_id \
       JOIN coord.task_runs tr ON tr.tenant_id = etr.tenant_id AND tr.task_run_id = etr.task_run_id \
       JOIN LATERAL ( \
         SELECT DISTINCT ON (ptr.relation_id) ptr.src_id, ptr.relation_kind, ptr.valid \
           FROM private.project_task_relations ptr \
          WHERE ptr.tenant_id = tr.tenant_id AND ptr.dst_id = tr.task_id \
          ORDER BY ptr.relation_id, ptr.revision DESC) cur ON true \
      WHERE etr.tenant_id = $1 AND etr.evidence_id = $3 \
        AND cur.relation_kind = $6 \
        AND e.occurred_at IS NOT NULL AND cur.valid @> e.occurred_at \
     ON CONFLICT (tenant_id, memory_id, project_id) DO NOTHING";

#[async_trait::async_trait]
impl MemoryAttribution for AttributionLadder {
    async fn link_memory_projects(
        &self,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant_id: Uuid,
        memory_id: Uuid,
        evidence_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(A1_DECLARED)
            .bind(tenant_id)
            .bind(memory_id)
            .bind(evidence_id)
            .bind(SourceKind::Declared.as_str())
            .bind(RuleId::Declared1.as_str())
            .execute(&mut **txn)
            .await?;
        sqlx::query(A3_TASK_RUN)
            .bind(tenant_id)
            .bind(memory_id)
            .bind(evidence_id)
            .bind(SourceKind::Inherited.as_str())
            .bind(RuleId::TaskRun1.as_str())
            .bind(RelationKind::Contains.as_str())
            .execute(&mut **txn)
            .await?;
        Ok(())
    }
}

/// The live links of one memory (ADR-0078 D-D reader, design v0.2 §15.8). It reads only `private.memory_projects_live`,
/// the one home of "exists and is not revoked" (migration 0255 ②), never the table.
const READ_LIVE: &str = "SELECT project_id, source_kind, rule_id_ver, decision_evidence_id, inherited_from_memory_id \
       FROM private.memory_projects_live \
      WHERE tenant_id = $1 AND memory_id = $2 \
      ORDER BY project_id";

/// One row of [`READ_LIVE`].
type LiveRow = (Uuid, String, String, Uuid, Option<Uuid>);

/// The attribution the read path reports for `memory_id` (REQ §3.4): its live links, ordered by project, or
/// [`attribution::MemoryAttribution::Unresolved`] when it has none.
///
/// A memory that never had a link and one whose every link was revoked both read `Unresolved`: REQ §3.4 reports
/// "unresolved" and does not tell the two apart. A memory the caller cannot see under RLS reads the same.
///
/// Runs in the caller's transaction, under the caller's role and RLS: the view is `security_invoker`, and
/// `role_gateway` is the one role holding SELECT on it (§6.2.2), so the caller installs `humaux.tenant_id` and
/// `humaux.user_id` first. No wire or MCP surface reads it yet (design v0.2 §15.8).
///
/// # Errors
/// The `sqlx` error of the read. A `source_kind` or `rule_id_ver` outside the Rust closed sets is a column decode
/// error (§78.2), never a default.
pub async fn read_memory_attribution(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    memory_id: Uuid,
) -> Result<attribution::MemoryAttribution, sqlx::Error> {
    let rows: Vec<LiveRow> = sqlx::query_as(READ_LIVE)
        .bind(tenant_id)
        .bind(memory_id)
        .fetch_all(&mut **txn)
        .await?;
    let links = rows
        .into_iter()
        .map(|(project, kind, rule, decision, from)| {
            Ok(ProjectLink {
                project_id: ProjectId(project),
                source_kind: SourceKind::parse(&kind)
                    .ok_or_else(|| outside_closed_set("source_kind", &kind))?,
                rule_id_ver: RuleId::parse(&rule)
                    .ok_or_else(|| outside_closed_set("rule_id_ver", &rule))?,
                decision_evidence_id: EvidenceId(decision),
                inherited_from_memory_id: from.map(MemoryId),
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    Ok(if links.is_empty() {
        attribution::MemoryAttribution::Unresolved
    } else {
        attribution::MemoryAttribution::Resolved(links)
    })
}

fn outside_closed_set(column: &str, value: &str) -> sqlx::Error {
    sqlx::Error::ColumnDecode {
        index: column.to_owned(),
        source: format!("{value:?} is outside the Rust closed set (§78.2)").into(),
    }
}
