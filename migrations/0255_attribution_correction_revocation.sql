-- §6.1.4 / ADR-0078 D-D (card M29 T06b; design v0.2 §15.7; §46 forward-fix, EXPAND_CONTRACT, number 0255): A3'
-- correction inheritance, revocation on a project_task relation correction, revocation down the inheritance chain,
-- and the one read-path rule "a link exists and is not revoked".
--   memory_projects.inherited_from_memory_id   the A3' ancestry column (NULL on every A1 / A3 row)
--   private.memory_projects_live               security_invoker view: memory_projects minus revoked links
--   private.memory_projects_on_supersede()     A3', invoker trigger on memory_records (0154 rule ③ shape)
--   private.revoke_attributions_on_relation_correction()   G-M29-6, owner definer trigger on project_task_relations
--   private.revoke_inherited_attributions()    transitive revocation, owner definer trigger on the revocation table
--
-- Invariants:
--   ① every correction@1 row names its source and nothing else does: CHECK (rule_id_ver = 'correction@1') =
--     (inherited_from_memory_id IS NOT NULL), and a composite NO ACTION FK (tenant_id, inherited_from_memory_id,
--     project_id) -> memory_projects' own primary key pins that the ancestor row exists. decision_evidence_id stays
--     the memory's own attribution Evidence (design v0.2 §15.4): for A3' that is the successor's PRIMARY Evidence,
--     the correction itself; the ancestry runs through the new column.
--   ② "exists and is not revoked" lives only in memory_projects_live. The A3' function and both revocation
--     functions read the view, never the table. The view is security_invoker, so a reader gets exactly the RLS of
--     both tables under its own role.
--   ③ A3' is §6.1.3 rule 3b's predicate on the updated row (prev := NEW): prev.superseded_by is the successor (the
--     WHEN clause) AND the successor's PRIMARY Evidence is a USER_CORRECTION event (0154:246-256). memory.supersede
--     (a non-correction successor) and memory.restore (the successor is the original, whose PRIMARY Evidence is
--     not a correction; and in a correction-of-a-correction chain it already holds every project the replacement
--     could carry, so ON CONFLICT leaves it unchanged) inherit nothing. correct_atomically sets superseded_by only
--     in its arbiter UPDATE ... WHERE status = 'active' (memory_governance_repo.rs:1800); 0 rows is CONFLICT and
--     rolls the successor back, so a correction the arbiter does not make current inherits nothing.
--   ④ revocation happens in the correcting transaction, at exactly one site per cause: a CONTAINS revision > 1 on
--     project_task_relations revokes the live task_run@1 rows its edge derived whose Evidence occurrence time the
--     new valid no longer contains ('{}' revokes all); a revocation row revokes the live rows inherited from that
--     (memory, project). declared@1 rows never depend on a relation and are never revoked here.
--   ⑤ both revocation functions are owner SECURITY DEFINER with search_path = pg_catalog and no EXECUTE grant (a
--     trigger function's EXECUTE is checked at CREATE TRIGGER, not when it fires): under the caller's RLS another
--     user's private memory would hide its wrong attribution from the revocation (design v0.2 §15.7). Each first
--     refuses a row whose tenant is not the session tenant (42501), so owner rights never reach another tenant
--     (the 0253 pin); the view then filters to that tenant under the owner's RLS as well.
--
-- Why ADD COLUMN is safe on an immutable table (0252 ②): the immutability trigger is a BEFORE UPDATE OR DELETE row
-- trigger and ALTER TABLE fires no row trigger; a nullable column without a default is a catalog-only change, so no
-- row is rewritten; every existing row reads NULL, which is its correct value (nothing wrote correction@1 before
-- this card, so the CHECK validates every existing row).
--
-- ponytail: a correction and a relation correction committing concurrently in two transactions can race: A3' may
--   copy a link the other transaction is revoking, and the transitive revocation cannot see the uncommitted
--   successor. Upgrade: A3' reads the ancestor rows FOR SHARE and the revocation side takes them FOR UPDATE.
-- ponytail: widening a relation's validity backfills nothing: memory_projects is immutable per memory version
--   (ADR-0078 D-D), so a memory that missed A3 under the old window stays unresolved.
-- ponytail: the owner reads the decision Evidence and its task-run carrier through their RLS, and
--   evidence_objects_tenant_and_visibility has no owner arm (§6.1.1): a derived row whose decision Evidence the
--   correcting session cannot see (another user's USER_PRIVATE Evidence) is not revoked. The definer covers a private
--   memory whose decision Evidence the session can see (memory.confirm of a USER_PRIVATE candidate from a shared
--   Evidence). Upgrade: an owner read arm on evidence_objects, which is a §6.1.1 ruling this card does not own.
--
-- Locks, all held until COMMIT: ADD COLUMN and ADD CONSTRAINT ... CHECK take ACCESS EXCLUSIVE on memory_projects (the
-- CHECK scans it once); ADD CONSTRAINT ... FOREIGN KEY takes SHARE ROW EXCLUSIVE on it (self-reference) and scans it;
-- CREATE INDEX takes SHARE on it; each CREATE TRIGGER takes SHARE ROW EXCLUSIVE on memory_records,
-- project_task_relations and memory_project_revocations, which blocks memory.correct / memory.supersede /
-- memory.restore and relation writes for the rest of this migration's transaction. memory_projects is small.

ALTER TABLE private.memory_projects ADD COLUMN inherited_from_memory_id uuid;
ALTER TABLE private.memory_projects
  ADD CONSTRAINT memory_projects_inherited_from_fkey FOREIGN KEY (tenant_id, inherited_from_memory_id, project_id)
    REFERENCES private.memory_projects (tenant_id, memory_id, project_id),
  ADD CONSTRAINT memory_projects_inherited_from_iff_correction
    CHECK ((rule_id_ver = 'correction@1') = (inherited_from_memory_id IS NOT NULL));
-- The FK's referencing-side lookup path, and the transitive revocation's probe.
CREATE INDEX memory_projects_inherited_from_idx
  ON private.memory_projects (tenant_id, inherited_from_memory_id, project_id)
  WHERE inherited_from_memory_id IS NOT NULL;

-- ② the only spelling of "exists and is not revoked".
CREATE VIEW private.memory_projects_live WITH (security_invoker = true) AS
  SELECT mp.tenant_id, mp.memory_id, mp.project_id, mp.relation, mp.source_kind, mp.rule_id_ver,
         mp.decision_evidence_id, mp.inherited_from_memory_id, mp.recorded_at
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
  SELECT l.tenant_id, NEW.superseded_by, l.project_id, 'ATTRIBUTED_TO', 'INHERITED', 'correction@1', me.evidence_id,
         l.memory_id
    FROM private.memory_projects_live l
    JOIN private.memory_evidence me ON me.memory_id = NEW.superseded_by AND me.role = 'PRIMARY'
    JOIN private.events ev ON ev.event_id = me.evidence_id
   WHERE l.tenant_id = NEW.tenant_id AND l.memory_id = NEW.memory_id
     AND ev.event_kind = 'USER_CORRECTION'
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

-- ④ G-M29-6: the one relation-correction revocation site. revoked_by takes decided_by verbatim (0252 gave both the
-- same closed format).
CREATE FUNCTION private.revoke_attributions_on_relation_correction() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog
AS $$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM NULLIF(current_setting('humaux.tenant_id', true), '')::uuid THEN
    RAISE EXCEPTION '%: row tenant is not the session tenant', TG_TABLE_NAME USING ERRCODE = '42501';
  END IF;
  INSERT INTO private.memory_project_revocations (tenant_id, memory_id, project_id, revoked_by, reason)
  SELECT l.tenant_id, l.memory_id, l.project_id, NEW.decided_by,
         'project_task_relations:' || NEW.relation_id || '@' || NEW.revision
    FROM private.memory_projects_live l
    JOIN private.evidence_task_runs etr ON etr.tenant_id = l.tenant_id AND etr.evidence_id = l.decision_evidence_id
    JOIN coord.task_runs tr ON tr.tenant_id = etr.tenant_id AND tr.task_run_id = etr.task_run_id
    JOIN private.evidence_objects e ON e.tenant_id = l.tenant_id AND e.evidence_id = l.decision_evidence_id
   WHERE l.tenant_id = NEW.tenant_id
     AND l.project_id = NEW.src_id
     AND l.rule_id_ver = 'task_run@1'
     AND tr.task_id = NEW.dst_id
     AND NOT (NEW.valid @> e.occurred_at);
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
COMMENT ON VIEW private.memory_projects_live IS
  '§6.1.4 (ADR-0078 D-D): memory_projects rows with no revocation row, the only place the "exists and is not revoked" rule lives. security_invoker. M29 T06b.';
COMMENT ON FUNCTION private.memory_projects_on_supersede() IS
  '§6.1.4 A3'' (ADR-0078 D-D, Q9): a USER_CORRECTION successor inherits its predecessor''s live rows as INHERITED / correction@1 at the arbiter UPDATE of superseded_by. Invoker. M29 T06b.';
COMMENT ON FUNCTION private.revoke_attributions_on_relation_correction() IS
  '§6.1.4 G-M29-6 (ADR-0078 D-D): a CONTAINS correction revokes, in its own transaction, the live task_run@1 rows its edge derived whose Evidence occurrence time leaves the new valid. Owner definer, session-tenant pin. M29 T06b.';
COMMENT ON FUNCTION private.revoke_inherited_attributions() IS
  '§6.1.4 (ADR-0078 D-D): a revocation revokes the live rows inherited from the same (memory, project), recursively. Owner definer, session-tenant pin. M29 T06b.';
