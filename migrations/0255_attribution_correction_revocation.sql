-- §6.1.4 / ADR-0078 D-D (card M29 T06b; design v0.2 §15.7; §46 forward-fix, EXPAND_CONTRACT, number 0255): A3'
-- correction inheritance, revocation on a project_task relation correction, revocation down the inheritance chain,
-- and the one read-path rule "a link exists and is not revoked".
--   memory_projects.inherited_from_memory_id   the A3' ancestry column (NULL on every A1 / A3 row)
--   memory_projects.derived_task_id, derived_occurred_at   the A3 ground (NULL on every A1 / A3' row)
--   private.memory_projects_live               security_invoker view: memory_projects minus revoked links
--   private.memory_projects_on_supersede()     A3', invoker trigger on memory_records (0154 rule ③ shape)
--   private.revoke_attributions_on_relation_correction()   G-M29-6, owner definer trigger on project_task_relations
--   private.revoke_inherited_attributions()    transitive revocation, owner definer trigger on the revocation table
--
-- Invariants:
--   ① every correction@1 row names its source and nothing else does: CHECK (rule_id_ver = 'correction@1') =
--     (inherited_from_memory_id IS NOT NULL), and a composite NO ACTION FK (tenant_id, inherited_from_memory_id,
--     project_id) -> memory_projects' own primary key pins that the ancestor row exists. decision_evidence_id stays
--     the memory's own attribution Evidence (design v0.2 §15.4): for A3' that is the correction event's
--     correction_evidence_id (design v0.2 §15.7 revision 2), the correction itself; the ancestry runs through the new
--     column.
--   ② "exists and is not revoked" lives only in memory_projects_live. The A3' function and both revocation
--     functions read the view, never the table. The view is security_invoker, so a reader gets exactly the RLS of
--     both tables under its own role.
--   ③ A3' keys on the transition, not on where the successor came from (design v0.2 §15.7 revision 2): the updated
--     row's lifecycle head (ops.memory_lifecycle_events, event_id = NEW.lifecycle_head_event_id) is op SUPERSEDE,
--     reason USER_CORRECTION, memory_id = NEW.memory_id and replacement_memory_id = NEW.superseded_by. Only
--     correct_atomically's arbiter UPDATE stamps such a head, in the same statement that sets superseded_by and only
--     WHERE status = 'active' (memory_governance_repo.rs:1800); 0 rows is CONFLICT and rolls the successor back.
--     memory.supersede stamps EXPLICIT_SUPERSEDE, even onto a correction-born successor; a restore's deactivation of
--     the correction's successor (memory_governance_repo.rs:947) and a note supersede (note_repo.rs:148) leave the
--     head stale, and no stale head is an unrestored SUPERSEDE of that memory (every reactivation stamps RESTORE). So
--     all of those inherit nothing. correction_evidence_id is NOT NULL on every USER_CORRECTION event its one writer
--     appends (memory_governance_repo.rs:1778-1784); a NULL would fail decision_evidence_id's NOT NULL (23502),
--     never a silent gap. role_gateway, the one role that fires this trigger (0011:300), SELECTs the event table
--     (0149:86); private_worker holds no UPDATE on superseded_by.
--   ④ revocation happens in the correcting transaction, at exactly one site per cause: a CONTAINS revision > 1 on
--     project_task_relations revokes the live task_run@1 rows its edge derived (derived_task_id = dst_id) whose
--     recorded occurrence time the new valid no longer contains ('{}' revokes all); a revocation row revokes the live
--     rows inherited from that (memory, project). declared@1 rows never depend on a relation and are never revoked
--     here.
--   ⑤ both revocation functions are owner SECURITY DEFINER with search_path = pg_catalog and no EXECUTE grant (a
--     trigger function's EXECUTE is checked at CREATE TRIGGER, not when it fires): under the caller's RLS another
--     user's private memory would hide its wrong attribution from the revocation (design v0.2 §15.7). Each first
--     refuses a row whose tenant is not the session tenant (42501), so owner rights never reach another tenant
--     (the 0253 pin); the view then filters to that tenant under the owner's RLS as well.
--   ⑥ every task_run@1 row carries the ground A3 decided on, and nothing else does: CHECK (rule_id_ver = 'task_run@1')
--     = (derived_task_id IS NOT NULL AND derived_occurred_at IS NOT NULL), both NULL or both set, and a composite NO
--     ACTION FK (tenant_id, derived_task_id) -> coord.tasks. A3 (adapters::attribution_repo) writes the task and
--     the Evidence's occurred_at it already joined (PROV wasDerivedFrom, recorded at derivation). So the
--     relation-correction revocation reads memory_projects_live only and never the Evidence tables:
--     evidence_objects' policy has no owner arm (0163:20-40, §6.1.1), so an owner definer cannot see another user's
--     USER_PRIVATE Evidence, while memory_records' policy has one (design v0.2 §15.7 amendment, 2026-10-20). A later
--     hidden or purged Evidence no longer changes what a relation correction revokes.
--
-- Why ADD COLUMN is safe on an immutable table (0252 ②): the immutability trigger is a BEFORE UPDATE OR DELETE row
-- trigger and ALTER TABLE fires no row trigger; a nullable column without a default is a catalog-only change, so no
-- row is rewritten. inherited_from_memory_id reads NULL on every existing row, which is its correct value (nothing
-- wrote correction@1 before this card).
--
-- Backfill of the A3 ground (⑥): every existing task_run@1 row gets derived_task_id / derived_occurred_at from the
-- join A3 decided on: its decision Evidence's evidence_task_runs carrier -> coord.task_runs.task_id, and that
-- Evidence's occurred_at (non-NULL on every A3 row, N09 R3). One carrier per Evidence (evidence_task_runs_pkey), so
-- the subquery yields at most one row. The migrator is the superuser principal (maintenance::migrate,
-- HUMAUX_MIGRATOR_PG_DSN, ADR-0066 L-13), and RLS, FORCE included, never applies to a superuser, so every tenant's
-- and every user's Evidence is visible. memory_projects_immutable (0252 ②) rejects every UPDATE and fires for a
-- superuser too, so it is disabled around this one UPDATE and re-enabled before the constraints are added (the
-- postcheck pins it enabled). The UPDATE restates each row's ground and changes no attribution (memory, project,
-- rule, decision Evidence). The CHECK and both FKs are added after it, so they are VALID; a row it could not ground
-- (a non-superuser runner sees no Evidence) violates the CHECK and aborts the migration, never a silent gap.
--
-- ponytail: a correction and a relation correction committing concurrently in two transactions can race: A3' may
--   copy a link the other transaction is revoking, and the transitive revocation cannot see the uncommitted
--   successor. Upgrade: A3' reads the ancestor rows FOR SHARE and the revocation side takes them FOR UPDATE.
-- ponytail: widening a relation's validity backfills nothing: memory_projects is immutable per memory version
--   (ADR-0078 D-D), so a memory that missed A3 under the old window stays unresolved.
--
-- Locks, all held until COMMIT: ADD COLUMN and ADD CONSTRAINT ... CHECK take ACCESS EXCLUSIVE on memory_projects (the
-- CHECKs scan it once), so the backfill UPDATE and the DISABLE / ENABLE TRIGGER pair (SHARE ROW EXCLUSIVE) run under
-- a lock no other session can pass: nobody writes the table or sees the trigger disabled; ADD CONSTRAINT ... FOREIGN
-- KEY takes SHARE ROW EXCLUSIVE on memory_projects (self-reference) and on coord.tasks, which blocks task submits for
-- the rest of this transaction, and scans memory_projects; CREATE INDEX takes SHARE on it; each CREATE TRIGGER takes
-- SHARE ROW EXCLUSIVE on memory_records, project_task_relations and memory_project_revocations, which blocks
-- memory.correct / memory.supersede / memory.restore and relation writes for the rest of this migration's
-- transaction. memory_projects is small.

ALTER TABLE private.memory_projects
  ADD COLUMN inherited_from_memory_id uuid,
  ADD COLUMN derived_task_id uuid,
  ADD COLUMN derived_occurred_at timestamptz;

-- ⑥ backfill (header). adapters::tests::memory_attribution runs this UPDATE verbatim.
ALTER TABLE private.memory_projects DISABLE TRIGGER memory_projects_immutable;
UPDATE private.memory_projects mp
   SET (derived_task_id, derived_occurred_at) =
       (SELECT tr.task_id, e.occurred_at
          FROM private.evidence_task_runs etr
          JOIN coord.task_runs tr ON tr.tenant_id = etr.tenant_id AND tr.task_run_id = etr.task_run_id
          JOIN private.evidence_objects e ON e.tenant_id = etr.tenant_id AND e.evidence_id = etr.evidence_id
         WHERE etr.tenant_id = mp.tenant_id AND etr.evidence_id = mp.decision_evidence_id)
 WHERE mp.rule_id_ver = 'task_run@1';
ALTER TABLE private.memory_projects ENABLE TRIGGER memory_projects_immutable;

ALTER TABLE private.memory_projects
  ADD CONSTRAINT memory_projects_inherited_from_fkey FOREIGN KEY (tenant_id, inherited_from_memory_id, project_id)
    REFERENCES private.memory_projects (tenant_id, memory_id, project_id),
  ADD CONSTRAINT memory_projects_inherited_from_iff_correction
    CHECK ((rule_id_ver = 'correction@1') = (inherited_from_memory_id IS NOT NULL)),
  ADD CONSTRAINT memory_projects_derived_task_fkey FOREIGN KEY (tenant_id, derived_task_id)
    REFERENCES coord.tasks (tenant_id, task_id),
  ADD CONSTRAINT memory_projects_derived_iff_task_run
    CHECK ((rule_id_ver = 'task_run@1') = (derived_task_id IS NOT NULL AND derived_occurred_at IS NOT NULL)
           AND (derived_task_id IS NULL) = (derived_occurred_at IS NULL));
-- The FK's referencing-side lookup path, and the transitive revocation's probe.
CREATE INDEX memory_projects_inherited_from_idx
  ON private.memory_projects (tenant_id, inherited_from_memory_id, project_id)
  WHERE inherited_from_memory_id IS NOT NULL;

-- ② the only spelling of "exists and is not revoked".
CREATE VIEW private.memory_projects_live WITH (security_invoker = true) AS
  SELECT mp.tenant_id, mp.memory_id, mp.project_id, mp.relation, mp.source_kind, mp.rule_id_ver,
         mp.decision_evidence_id, mp.inherited_from_memory_id, mp.derived_task_id, mp.derived_occurred_at,
         mp.recorded_at
    FROM private.memory_projects mp
   WHERE NOT EXISTS (SELECT 1 FROM private.memory_project_revocations r
                      WHERE r.tenant_id = mp.tenant_id AND r.memory_id = mp.memory_id
                        AND r.project_id = mp.project_id);
ALTER VIEW private.memory_projects_live OWNER TO role_migration_owner;
REVOKE ALL ON private.memory_projects_live
  FROM PUBLIC, role_gateway, role_private_worker, role_consolidation_worker, role_public_worker,
       role_retrieval_worker, role_batch_issuer, role_maintenance, role_admin;
-- role_gateway is the one role that UPDATEs memory_records.superseded_by (0011), so the one role that runs the A3'
-- trigger with invoker rights (§6.2.2). The definers read the view as its owner.
GRANT SELECT ON private.memory_projects_live TO role_gateway;

-- ③ A3' (G-M29-5(b)). Invoker rights, as 0154's memory_subjects_on_supersede.
CREATE FUNCTION private.memory_projects_on_supersede() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog
AS $$
BEGIN
  INSERT INTO private.memory_projects
    (tenant_id, memory_id, project_id, relation, source_kind, rule_id_ver, decision_evidence_id,
     inherited_from_memory_id)
  SELECT l.tenant_id, NEW.superseded_by, l.project_id, 'ATTRIBUTED_TO', 'INHERITED', 'correction@1',
         ev.correction_evidence_id, l.memory_id
    FROM ops.memory_lifecycle_events ev
    JOIN private.memory_projects_live l ON l.tenant_id = NEW.tenant_id AND l.memory_id = NEW.memory_id
   WHERE ev.event_id = NEW.lifecycle_head_event_id
     AND ev.op = 'SUPERSEDE'
     AND ev.reason_code = 'USER_CORRECTION'
     AND ev.memory_id = NEW.memory_id
  ON CONFLICT DO NOTHING;
  RETURN NULL;
END;
$$;
ALTER FUNCTION private.memory_projects_on_supersede() OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION private.memory_projects_on_supersede() FROM PUBLIC;
CREATE TRIGGER memory_projects_on_supersede
  AFTER UPDATE OF superseded_by ON private.memory_records
  FOR EACH ROW
  WHEN (NEW.superseded_by IS NOT NULL AND NEW.superseded_by IS DISTINCT FROM OLD.superseded_by)
  EXECUTE FUNCTION private.memory_projects_on_supersede();

-- ④ G-M29-6: the one relation-correction revocation site. It reads the view only (⑥: never the Evidence tables).
-- revoked_by takes decided_by verbatim (0252 gave both the same closed format).
CREATE FUNCTION private.revoke_attributions_on_relation_correction() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM NULLIF(current_setting('humaux.tenant_id', true), '')::uuid THEN
    RAISE EXCEPTION '%: row tenant is not the session tenant', TG_TABLE_NAME USING ERRCODE = '42501';
  END IF;
  INSERT INTO private.memory_project_revocations (tenant_id, memory_id, project_id, revoked_by, reason)
  SELECT l.tenant_id, l.memory_id, l.project_id, NEW.decided_by,
         'project_task_relations:' || NEW.relation_id || '@' || NEW.revision
    FROM private.memory_projects_live l
   WHERE l.tenant_id = NEW.tenant_id
     AND l.project_id = NEW.src_id
     AND l.rule_id_ver = 'task_run@1'
     AND l.derived_task_id = NEW.dst_id
     AND NOT (NEW.valid @> l.derived_occurred_at);
  RETURN NULL;
END;
$$;
ALTER FUNCTION private.revoke_attributions_on_relation_correction() OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION private.revoke_attributions_on_relation_correction() FROM PUBLIC;
CREATE TRIGGER project_task_relations_revoke_attributions
  AFTER INSERT ON private.project_task_relations
  FOR EACH ROW
  WHEN (NEW.revision > 1 AND NEW.relation_kind = 'CONTAINS')
  EXECUTE FUNCTION private.revoke_attributions_on_relation_correction();

-- Transitive revocation: an inherited link loses its ground with its ancestor (PROV wasInvalidatedBy along
-- wasDerivedFrom). Its own INSERT fires this trigger again, one level per correction in the chain; it ends because
-- each (memory, project) is revoked at most once (the revocation PK, and the view hides a revoked row).
-- ponytail: recursion depth = the correction-chain length, as nested plpgsql trigger calls, so the ceiling is
--   max_stack_depth (54001 aborts the correcting transaction). Upgrade: one INSERT over an iterative closure
--   (WITH RECURSIVE along inherited_from_memory_id) and no self-firing.
CREATE FUNCTION private.revoke_inherited_attributions() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM NULLIF(current_setting('humaux.tenant_id', true), '')::uuid THEN
    RAISE EXCEPTION '%: row tenant is not the session tenant', TG_TABLE_NAME USING ERRCODE = '42501';
  END IF;
  INSERT INTO private.memory_project_revocations (tenant_id, memory_id, project_id, revoked_by, reason)
  SELECT l.tenant_id, l.memory_id, l.project_id, NEW.revoked_by, NEW.reason
    FROM private.memory_projects_live l
   WHERE l.tenant_id = NEW.tenant_id
     AND l.inherited_from_memory_id = NEW.memory_id
     AND l.project_id = NEW.project_id;
  RETURN NULL;
END;
$$;
ALTER FUNCTION private.revoke_inherited_attributions() OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION private.revoke_inherited_attributions() FROM PUBLIC;
CREATE TRIGGER memory_project_revocations_follow_inheritance
  AFTER INSERT ON private.memory_project_revocations
  FOR EACH ROW
  EXECUTE FUNCTION private.revoke_inherited_attributions();

COMMENT ON COLUMN private.memory_projects.inherited_from_memory_id IS
  '§6.1.4 A3'' ancestry (ADR-0078 D-D): the predecessor whose live row this correction@1 row copies; NULL on every other row. M29 T06b.';
COMMENT ON COLUMN private.memory_projects.derived_task_id IS
  '§6.1.4 A3 ground (ADR-0078 D-D): the task whose CONTAINS relation this task_run@1 row was derived from; NULL on every other row. M29 T06b.';
COMMENT ON COLUMN private.memory_projects.derived_occurred_at IS
  '§6.1.4 A3 ground (ADR-0078 D-D): the decision Evidence''s occurred_at the CONTAINS validity was tested at; NULL on every row that is not task_run@1. M29 T06b.';
COMMENT ON VIEW private.memory_projects_live IS
  '§6.1.4 (ADR-0078 D-D): memory_projects rows with no revocation row, the only place the "exists and is not revoked" rule lives. security_invoker. M29 T06b.';
COMMENT ON FUNCTION private.memory_projects_on_supersede() IS
  '§6.1.4 A3'' (ADR-0078 D-D, Q9; design v0.2 §15.7 revision 2): when the updated row''s lifecycle head is the SUPERSEDE / USER_CORRECTION of this memory into NEW.superseded_by, the successor inherits its live rows as INHERITED / correction@1, decided by the event''s correction_evidence_id. Invoker. M29 T06b.';
COMMENT ON FUNCTION private.revoke_attributions_on_relation_correction() IS
  '§6.1.4 G-M29-6 (ADR-0078 D-D): a CONTAINS correction revokes, in its own transaction, the live task_run@1 rows its edge derived whose recorded occurrence time leaves the new valid; reads the view only. Owner definer, session-tenant pin. M29 T06b.';
COMMENT ON FUNCTION private.revoke_inherited_attributions() IS
  '§6.1.4 (ADR-0078 D-D): a revocation revokes the live rows inherited from the same (memory, project), recursively. Owner definer, session-tenant pin. M29 T06b.';
