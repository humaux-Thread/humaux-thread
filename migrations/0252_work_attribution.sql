-- §6.1.4 / ADR-0078 D-D (card M29 T06a; §46 forward-fix, EXPAND_CONTRACT, first free number after 0251): the work
-- attribution tables, plus two fixes to the 0249 relation kernel (issue #92 items 4 and 5, design v0.2 §15.2).
--   private.evidence_projects            write-side carrier: a project declared on an Evidence (writer: T06c)
--   private.memory_projects              the attribution source of truth, immutable per memory version
--   private.memory_project_revocations   append-only; a link counts only while it exists and is not revoked
-- The Rust half: humaux_domain::attribution (SourceKind, RuleId) + humaux_adapters::attribution_repo (rungs A1 and A3
-- behind M07's attribution port at the Memory INSERT door). §78.2 reconciliation: adapters::tests::memory_attribution.
--
-- Invariants:
--   ① source_kind is exactly humaux_domain::attribution::SourceKind {DECLARED, EXTERNAL_KEY, INHERITED}: no
--     model-derived value (N09 R2). rule_id_ver is exactly RuleId {declared@1, task_run@1, correction@1}; every
--     memory_projects row carries it and its decision_evidence_id (N09 R6). correction@1 is written by T06b (A3').
--   ② memory_projects and memory_project_revocations are immutable: an owner BEFORE UPDATE OR DELETE trigger rejects
--     both (0156 / 0249 technique), and no role holds UPDATE or DELETE. Every FK is NO ACTION, so no cascade ever
--     reaches the trigger; fixture purge runs as replica.
--   ③ every FK is composite with the tenant leg (RI bypasses RLS).
--   ④ FORCE RLS on all three in the 0154 form: the NULLIF tenant clause (0246) AND the parent row's EXISTS (the
--     Evidence for evidence_projects, the Memory for the other two), so a child row is visible only where its parent
--     is.
--   ⑤ #92 item 5: one relation_id per edge. A partial UNIQUE (tenant_id, src_id, dst_id, relation_kind) WHERE
--     revision = 1 on each 0249 table; not a temporal key, so 0249's ⑧ is unaffected.
--   ⑥ #92 item 4: relation_revision_guard raises 42501 first when NEW.tenant_id IS NULL (a missing tenant context is
--     FORBIDDEN, never the retryable CONFLICT); the rest of its body is 0249's byte for byte.
--
-- Locks: each CREATE UNIQUE INDEX holds SHARE on its relation table while it builds (writes wait); the tables are
-- small. The FKs in CREATE TABLE take SHARE ROW EXCLUSIVE on evidence_objects, memory_records and continuity_projects
-- until COMMIT, which blocks Evidence and Memory INSERTs for the rest of this migration's transaction.

CREATE TABLE private.evidence_projects (
  tenant_id   uuid NOT NULL,
  evidence_id uuid NOT NULL,
  project_id  uuid NOT NULL,
  source_kind text NOT NULL CONSTRAINT evidence_projects_source_kind_check
    CHECK (source_kind IN ('DECLARED', 'EXTERNAL_KEY', 'INHERITED')),
  CONSTRAINT evidence_projects_pkey PRIMARY KEY (tenant_id, evidence_id, project_id),
  CONSTRAINT evidence_projects_evidence_fkey FOREIGN KEY (tenant_id, evidence_id)
    REFERENCES private.evidence_objects (tenant_id, evidence_id),
  CONSTRAINT evidence_projects_project_fkey FOREIGN KEY (tenant_id, project_id)
    REFERENCES private.continuity_projects (tenant_id, project_id)
);

CREATE TABLE private.memory_projects (
  tenant_id            uuid NOT NULL,
  memory_id            uuid NOT NULL,
  project_id           uuid NOT NULL,
  relation             text NOT NULL CONSTRAINT memory_projects_relation_check CHECK (relation = 'ATTRIBUTED_TO'),
  source_kind          text NOT NULL CONSTRAINT memory_projects_source_kind_check
    CHECK (source_kind IN ('DECLARED', 'EXTERNAL_KEY', 'INHERITED', 'MODEL_GUESS')),
  rule_id_ver          text NOT NULL CONSTRAINT memory_projects_rule_id_ver_check
    CHECK (rule_id_ver IN ('declared@1', 'task_run@1', 'correction@1')),
  decision_evidence_id uuid NOT NULL,
  recorded_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT memory_projects_pkey PRIMARY KEY (tenant_id, memory_id, project_id),
  CONSTRAINT memory_projects_memory_fkey FOREIGN KEY (tenant_id, memory_id)
    REFERENCES private.memory_records (tenant_id, memory_id),
  CONSTRAINT memory_projects_project_fkey FOREIGN KEY (tenant_id, project_id)
    REFERENCES private.continuity_projects (tenant_id, project_id),
  CONSTRAINT memory_projects_decision_evidence_fkey FOREIGN KEY (tenant_id, decision_evidence_id)
    REFERENCES private.evidence_objects (tenant_id, evidence_id)
);

-- revoked_by has relation_kernel decided_by's closed format (0249 ⑦): a rule or a principal, never free text.
CREATE TABLE private.memory_project_revocations (
  tenant_id   uuid NOT NULL,
  memory_id   uuid NOT NULL,
  project_id  uuid NOT NULL,
  revoked_by  text NOT NULL CONSTRAINT memory_project_revocations_revoked_by_format CHECK (revoked_by ~
    '^(rule:[a-z0-9_]+@[0-9]+|principal:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$'),
  reason      text NOT NULL CONSTRAINT memory_project_revocations_reason_present CHECK (reason <> ''),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT memory_project_revocations_pkey PRIMARY KEY (tenant_id, memory_id, project_id),
  CONSTRAINT memory_project_revocations_link_fkey FOREIGN KEY (tenant_id, memory_id, project_id)
    REFERENCES private.memory_projects (tenant_id, memory_id, project_id)
);

-- FK lookup paths for the referenced side (each PK leads with the child's own parent).
CREATE INDEX evidence_projects_project_idx ON private.evidence_projects (tenant_id, project_id);
CREATE INDEX memory_projects_project_idx ON private.memory_projects (tenant_id, project_id);
CREATE INDEX memory_projects_decision_evidence_idx ON private.memory_projects (tenant_id, decision_evidence_id);

-- ② same technique as 0249's reject_relation_revision_change, one function for both immutable tables.
CREATE FUNCTION private.reject_memory_project_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION '%: attribution rows are immutable; append a revocation instead', TG_TABLE_NAME
    USING ERRCODE = '23514';
END;
$$;
ALTER FUNCTION private.reject_memory_project_change() OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION private.reject_memory_project_change() FROM PUBLIC;
CREATE TRIGGER memory_projects_immutable BEFORE UPDATE OR DELETE ON private.memory_projects
  FOR EACH ROW EXECUTE FUNCTION private.reject_memory_project_change();
CREATE TRIGGER memory_project_revocations_append_only BEFORE UPDATE OR DELETE ON private.memory_project_revocations
  FOR EACH ROW EXECUTE FUNCTION private.reject_memory_project_change();

-- ④ the 0154 form, NULLIF-hardened.
ALTER TABLE private.evidence_projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.evidence_projects FORCE ROW LEVEL SECURITY;
CREATE POLICY evidence_projects_tenant_and_parent ON private.evidence_projects
  USING (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid
         AND EXISTS (SELECT 1 FROM private.evidence_objects e
                     WHERE e.evidence_id = evidence_projects.evidence_id
                       AND e.tenant_id = evidence_projects.tenant_id))
  WITH CHECK (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid
         AND EXISTS (SELECT 1 FROM private.evidence_objects e
                     WHERE e.evidence_id = evidence_projects.evidence_id
                       AND e.tenant_id = evidence_projects.tenant_id));

ALTER TABLE private.memory_projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.memory_projects FORCE ROW LEVEL SECURITY;
CREATE POLICY memory_projects_tenant_and_parent ON private.memory_projects
  USING (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid
         AND EXISTS (SELECT 1 FROM private.memory_records mr
                     WHERE mr.memory_id = memory_projects.memory_id
                       AND mr.tenant_id = memory_projects.tenant_id))
  WITH CHECK (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid
         AND EXISTS (SELECT 1 FROM private.memory_records mr
                     WHERE mr.memory_id = memory_projects.memory_id
                       AND mr.tenant_id = memory_projects.tenant_id));

ALTER TABLE private.memory_project_revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.memory_project_revocations FORCE ROW LEVEL SECURITY;
CREATE POLICY memory_project_revocations_tenant_and_parent ON private.memory_project_revocations
  USING (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid
         AND EXISTS (SELECT 1 FROM private.memory_records mr
                     WHERE mr.memory_id = memory_project_revocations.memory_id
                       AND mr.tenant_id = memory_project_revocations.tenant_id))
  WITH CHECK (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid
         AND EXISTS (SELECT 1 FROM private.memory_records mr
                     WHERE mr.memory_id = memory_project_revocations.memory_id
                       AND mr.tenant_id = memory_project_revocations.tenant_id));

-- Owner + NAMED §6.2.2 grants. The door (adapters::memory_repo::insert_memory_in_txn) runs under role_gateway
-- (memory.confirm, memory.correct, memory.note_put) and role_private_worker (the Distill hop); its A1/A3 statements
-- read evidence_projects, evidence_task_runs, coord.task_runs (0011 already grants SELECT on coord.* to both),
-- project_task_relations and evidence_objects, and insert memory_projects. Nobody holds UPDATE or DELETE.
ALTER TABLE private.evidence_projects OWNER TO role_migration_owner;
ALTER TABLE private.memory_projects OWNER TO role_migration_owner;
ALTER TABLE private.memory_project_revocations OWNER TO role_migration_owner;
REVOKE ALL ON private.evidence_projects, private.memory_projects, private.memory_project_revocations
  FROM PUBLIC, role_gateway, role_private_worker, role_consolidation_worker, role_public_worker,
       role_retrieval_worker, role_batch_issuer, role_maintenance, role_admin;
GRANT SELECT         ON private.evidence_projects TO role_gateway, role_private_worker;
GRANT SELECT, INSERT ON private.memory_projects TO role_gateway, role_private_worker;
GRANT SELECT         ON private.memory_project_revocations TO role_gateway, role_private_worker;
GRANT SELECT         ON private.evidence_task_runs TO role_private_worker;
GRANT SELECT         ON private.project_task_relations TO role_private_worker;

-- ⑤ #92 item 5.
CREATE UNIQUE INDEX project_task_relations_one_relation_per_edge
  ON private.project_task_relations (tenant_id, src_id, dst_id, relation_kind) WHERE revision = 1;
CREATE UNIQUE INDEX project_subject_relations_one_relation_per_edge
  ON private.project_subject_relations (tenant_id, src_id, dst_id, relation_kind) WHERE revision = 1;
CREATE UNIQUE INDEX subject_relations_one_relation_per_edge
  ON private.subject_relations (tenant_id, src_id, dst_id, relation_kind) WHERE revision = 1;

-- ⑥ #92 item 4: one new first statement; everything else is 0249's body. CREATE OR REPLACE keeps owner and ACL.
CREATE OR REPLACE FUNCTION private.relation_revision_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog
AS $$
DECLARE
  v_src_kind text := TG_ARGV[0];
  v_dst_kind text := TG_ARGV[1];
  v_prev_src uuid;
  v_prev_dst uuid;
  v_prev_kind text;
  v_rows bigint;
BEGIN
  IF NEW.tenant_id IS NULL THEN RAISE EXCEPTION '%: no tenant context', TG_TABLE_NAME USING ERRCODE = '42501'; END IF;
  IF TG_ARGV[0] = 'SUBJECT' THEN
    SELECT s.kind INTO v_src_kind FROM private.subjects s
     WHERE s.tenant_id = NEW.tenant_id AND s.subject_id = NEW.src_id;
  END IF;
  IF TG_ARGV[1] = 'SUBJECT' THEN
    SELECT s.kind INTO v_dst_kind FROM private.subjects s
     WHERE s.tenant_id = NEW.tenant_id AND s.subject_id = NEW.dst_id;
  END IF;
  IF v_src_kind IS NULL OR v_dst_kind IS NULL THEN
    RAISE EXCEPTION '%: relation endpoint not found', TG_TABLE_NAME USING ERRCODE = '23503';
  END IF;
  IF NOT private.relation_triple_allowed(v_src_kind, NEW.relation_kind, v_dst_kind) THEN
    RAISE EXCEPTION '%: (%, %, %) is not a whitelisted relation triple',
      TG_TABLE_NAME, v_src_kind, NEW.relation_kind, v_dst_kind
      USING ERRCODE = '23514', CONSTRAINT = 'relation_whitelist';
  END IF;
  IF NEW.revision > 1 THEN
    EXECUTE format('SELECT src_id, dst_id, relation_kind FROM %I.%I '
                   'WHERE tenant_id = $1 AND relation_id = $2 AND revision = $3',
                   TG_TABLE_SCHEMA, TG_TABLE_NAME)
       INTO v_prev_src, v_prev_dst, v_prev_kind
      USING NEW.tenant_id, NEW.relation_id, NEW.revision - 1;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows = 0 THEN
      RAISE EXCEPTION '%: revision % of relation % has no predecessor', TG_TABLE_NAME, NEW.revision, NEW.relation_id
        USING ERRCODE = '23514', CONSTRAINT = 'relation_revision_contiguous';
    END IF;
    IF (v_prev_src, v_prev_dst, v_prev_kind) IS DISTINCT FROM (NEW.src_id, NEW.dst_id, NEW.relation_kind) THEN
      RAISE EXCEPTION '%: a revision may not change the edge of relation %', TG_TABLE_NAME, NEW.relation_id
        USING ERRCODE = '23514', CONSTRAINT = 'relation_edge_immutable';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

COMMENT ON TABLE private.evidence_projects IS
  '§6.1.4 write-side project declaration on an Evidence (ADR-0078 D-D A1), written with the Evidence in remember.put''s transaction (writer: T06c). M29 T06a.';
COMMENT ON TABLE private.memory_projects IS
  '§6.1.4 memory -> project attribution, the source of truth (ADR-0078 D-D). Immutable; a link counts only while it is not revoked. Written by the M07 attribution port at the Memory INSERT door (A1, A3) and the M29 supersede trigger (A3''). M29 T06a.';
COMMENT ON TABLE private.memory_project_revocations IS
  '§6.1.4 append-only revocation of a memory_projects row (ADR-0078 D-D, N09 R6 bulk revocation). Writer: T06b. M29 T06a.';
