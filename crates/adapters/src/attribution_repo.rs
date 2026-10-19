//! `adapters::attribution_repo` — M29's implementation of M07's attribution port: rungs A1 (the Evidence's declared
//!   project) and A3 (the verified task run's CONTAINS projects) of the §6.1.4 memory → project ladder.
//! Depends-on: crates=[async-trait, humaux-domain, sqlx]; services=[PostgreSQL(any) r=[coord.task_runs,
//!   private.evidence_objects, private.evidence_projects, private.evidence_task_runs, private.project_task_relations]
//!   w=[private.memory_projects]]; env=[]; modules=[adapters::memory_repo, domain::attribution, domain::relation]
//! Called-by: [gateway::bootstrap, private-worker::distill, tests]
//! Invariants: [runs only through the door's single port call, in the caller's transaction, under the caller's role
//!   and RLS; every row is deterministic (N09 R1) and carries its rule and decision Evidence (N09 R6); no rung holding
//!   writes nothing, never a default or a most-recent guess (N09 R3); imports no provider, inference, embedding or
//!   HTTP code (xtask G-N09-1)]
//! Spec: Baseline §6.1.4; §78.2; ADR-0078
//!
//! Rollups are not Memories: they live in `private.memory_rollups`, never reach the door, and stay unattributed in the
//! first slice. A3' (`correction@1`) is the M29 supersede trigger's (T06b), not this port's.

use humaux_domain::attribution::{RuleId, SourceKind};
use humaux_domain::relation::RelationKind;
use sqlx::types::Uuid;

use crate::memory_repo::MemoryAttribution;

/// The M29 attribution ladder (A1, then A3). Stateless: each composition root holds one and lends it to the door.
#[derive(Debug, Clone, Copy)]
pub struct AttributionLadder;

/// A1 (ADR-0078 D-D): every project the PRIMARY Evidence declares becomes a `DECLARED` / `declared@1` row whose
/// decision Evidence is that Evidence.
const A1_DECLARED: &str = "INSERT INTO private.memory_projects \
       (tenant_id, memory_id, project_id, relation, source_kind, rule_id_ver, decision_evidence_id) \
     SELECT ep.tenant_id, $2, ep.project_id, 'ATTRIBUTED_TO', $4, $5, ep.evidence_id \
       FROM (SELECT DISTINCT ON (tenant_id) tenant_id, $3::uuid AS evidence_id, src_id AS project_id, $4::text AS source_kind FROM private.project_task_relations ORDER BY tenant_id, recorded_at DESC) ep \
      WHERE ep.tenant_id = $1 AND ep.evidence_id = $3 \
        AND ep.source_kind = $4";

/// A3 (ADR-0078 D-D): the PRIMARY Evidence's verified task run (`evidence_task_runs`, T04c) names a task; every project
/// whose current relation to that task (the highest revision per `relation_id`, §6.1.4 ①) is CONTAINS and valid at the
/// Evidence's `occurred_at` becomes an `INHERITED` / `task_run@1` row. REFERENCES never counts. N09 R3: an Evidence
/// without `occurred_at` has no occurrence time to test, so A3 does not hold and nothing is written (unresolved). A
/// project A1 already wrote keeps its A1 row (the lower rung wins; the conflict target is the primary key).
const A3_TASK_RUN: &str = "INSERT INTO private.memory_projects \
       (tenant_id, memory_id, project_id, relation, source_kind, rule_id_ver, decision_evidence_id) \
     SELECT etr.tenant_id, $2, cur.src_id, 'ATTRIBUTED_TO', $4, $5, etr.evidence_id \
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
        AND e.occurred_at IS NOT NULL \
        AND cur.valid @> e.occurred_at \
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
