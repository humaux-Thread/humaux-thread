-- §6.1.4 / ADR-0078 D-C (card M29 T05; §46 forward-fix, EXPAND_CONTRACT, first free number after 0248): the relation
-- kernel. One SQL template (the DO block below) creates the three first-slice revision tables
--   private.project_task_relations     Project -CONTAINS|REFERENCES-> Task
--   private.project_subject_relations  Project -TARGETS|SERVES-> Subject
--   private.subject_relations          Subject -OWNED_BY|PART_OF-> Subject
-- with one shape, one CHECK function, one whitelist function and one guard trigger function. The Rust half is
-- humaux_domain::relation (closed sets, WHITELIST, Validity) + humaux_adapters::relation_repo (the one revision
-- writer / current-revision reader); the §78.2 reconciliation is adapters::tests::relation_kernel.
--
-- Invariants (§6.1.4 ①-⑧):
--   ① append-only: an owner BEFORE UPDATE OR DELETE trigger rejects both, and no non-owner role holds UPDATE or
--     DELETE. FKs are NO ACTION, so no cascade ever reaches the trigger; fixture purge runs as replica.
--   ② retraction = a revision whose valid is '{}'.
--   ③ CAS: a write inserts revision = expected_revision + 1. The PK (tenant_id, relation_id, revision) rejects the
--     loser of a race (23505); the guard rejects a revision whose predecessor is missing (expected_revision ahead
--     of the current one) and a revision that changes the edge (src_id, dst_id, relation_kind) of its relation.
--   ④ private.relation_valid_shape: every range of valid is [) with a finite lower bound and a finite or omitted
--     upper bound; explicit +-infinity is rejected (tstzrange has no canonical form, PG-RT).
--   ⑤ private.relation_triple_allowed mirrors humaux_domain::relation::WHITELIST. It is called by the guard, not
--     by a CHECK, because a subject endpoint's kind lives on its private.subjects row.
--   ⑥ every FK is composite with the tenant leg (RI bypasses RLS). continuity_projects and coord.tasks gain the
--     constrained-redundancy UNIQUE (tenant_id, id) for that, as 0153 did for subjects.
--   ⑦ decided_by / proposed_by have closed formats; factual and authorisation evidence are separate columns.
--   ⑧ no temporal key, no btree_gist, no EXCLUDE (ADR-0078 D-C defers them).
--
-- Locks: the two ADD UNIQUE build an index under SHARE on continuity_projects / coord.tasks (writes wait for the
-- build); both tables are small registries.

ALTER TABLE private.continuity_projects
  ADD CONSTRAINT continuity_projects_tenant_project_key UNIQUE (tenant_id, project_id);
ALTER TABLE coord.tasks
  ADD CONSTRAINT tasks_tenant_task_key UNIQUE (tenant_id, task_id);

-- §6.1.4 ④. '{}' has no range, so bool_and is NULL and the coalesce admits it (retraction).
CREATE FUNCTION private.relation_valid_shape(valid tstzmultirange) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path = pg_catalog
AS $$
  SELECT coalesce(bool_and(lower_inc(r) AND NOT upper_inc(r)
                           AND NOT lower_inf(r) AND isfinite(lower(r))
                           AND (upper_inf(r) OR isfinite(upper(r)))), true)
    FROM unnest(valid) AS r
$$;

-- §6.1.4 ⑤: the DB mirror of humaux_domain::relation::WHITELIST (ADR-0078 D-C first-slice table). PROJECT / TASK
-- name the endpoint class of a project / task id; a subject endpoint is its private.subjects.kind.
CREATE FUNCTION private.relation_triple_allowed(src_kind text, relation_kind text, dst_kind text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path = pg_catalog
AS $$
  SELECT (src_kind, relation_kind, dst_kind) IN (VALUES
    ('PROJECT', 'CONTAINS', 'TASK'),
    ('PROJECT', 'REFERENCES', 'TASK'),
    ('PROJECT', 'TARGETS', 'WEBSITE'),
    ('PROJECT', 'TARGETS', 'PRODUCT'),
    ('PROJECT', 'TARGETS', 'BRAND'),
    ('PROJECT', 'TARGETS', 'CHANNEL_ACCOUNT'),
    ('PROJECT', 'SERVES', 'BUSINESS'),
    ('PROJECT', 'SERVES', 'BRAND'),
    ('WEBSITE', 'OWNED_BY', 'BRAND'),
    ('PRODUCT', 'OWNED_BY', 'BRAND'),
    ('BRAND', 'OWNED_BY', 'BUSINESS'),
    ('PRODUCT', 'PART_OF', 'PRODUCT'))
$$;

-- BEFORE INSERT guard shared by the three tables. TG_ARGV[0] / [1] = endpoint class of src_id / dst_id (PROJECT,
-- TASK or SUBJECT). Invoker rights: a subject the caller cannot see under RLS reads exactly like a missing one
-- (23503, the FK's own code), so the guard is no existence oracle either.
CREATE FUNCTION private.relation_revision_guard() RETURNS trigger
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

-- §6.1.4 ①: same technique as 0156's memory_affects_immutable, widened to DELETE (no cascade reaches these rows).
CREATE FUNCTION private.reject_relation_revision_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION '%: relation revisions are append-only; append a new revision instead', TG_TABLE_NAME
    USING ERRCODE = '23514';
END;
$$;

ALTER FUNCTION private.relation_valid_shape(tstzmultirange) OWNER TO role_migration_owner;
ALTER FUNCTION private.relation_triple_allowed(text, text, text) OWNER TO role_migration_owner;
ALTER FUNCTION private.relation_revision_guard() OWNER TO role_migration_owner;
ALTER FUNCTION private.reject_relation_revision_change() OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION private.relation_valid_shape(tstzmultirange) FROM PUBLIC;
REVOKE ALL ON FUNCTION private.relation_triple_allowed(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION private.relation_revision_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION private.reject_relation_revision_change() FROM PUBLIC;
-- The CHECK and the guard run with the inserting role's rights, so the one INSERT holder needs EXECUTE.
GRANT EXECUTE ON FUNCTION private.relation_valid_shape(tstzmultirange) TO role_gateway;
GRANT EXECUTE ON FUNCTION private.relation_triple_allowed(text, text, text) TO role_gateway;

-- The one template. Per pair: table, src endpoint class + FK target, dst endpoint class + FK target, relation kinds.
DO $template$
DECLARE
  p record;
BEGIN
  FOR p IN SELECT * FROM (VALUES
    ('project_task_relations', 'PROJECT', 'private.continuity_projects (tenant_id, project_id)',
     'TASK', 'coord.tasks (tenant_id, task_id)', $$'CONTAINS', 'REFERENCES'$$),
    ('project_subject_relations', 'PROJECT', 'private.continuity_projects (tenant_id, project_id)',
     'SUBJECT', 'private.subjects (tenant_id, subject_id)', $$'TARGETS', 'SERVES'$$),
    ('subject_relations', 'SUBJECT', 'private.subjects (tenant_id, subject_id)',
     'SUBJECT', 'private.subjects (tenant_id, subject_id)', $$'OWNED_BY', 'PART_OF'$$)
  ) AS v(tbl, src_class, src_ref, dst_class, dst_ref, kinds)
  LOOP
    EXECUTE format($ddl$
      CREATE TABLE private.%1$I (
        tenant_id uuid NOT NULL,
        relation_id uuid NOT NULL CONSTRAINT %1$s_relation_id_v7 CHECK (uuid_extract_version(relation_id) = 7),
        revision bigint NOT NULL CONSTRAINT %1$s_revision_positive CHECK (revision >= 1),
        src_id uuid NOT NULL,
        dst_id uuid NOT NULL,
        relation_kind text NOT NULL CONSTRAINT %1$s_relation_kind_check CHECK (relation_kind IN (%2$s)),
        valid tstzmultirange NOT NULL CONSTRAINT %1$s_valid_shape CHECK (private.relation_valid_shape(valid)),
        decided_by text NOT NULL CONSTRAINT %1$s_decided_by_format CHECK (decided_by ~
          '^(rule:[a-z0-9_]+@[0-9]+|principal:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$'),
        proposed_by text CONSTRAINT %1$s_proposed_by_format CHECK (proposed_by ~
          '^model:[A-Za-z0-9._/-]+@[A-Za-z0-9._-]+$'),
        factual_evidence_ids uuid[] NOT NULL
          CONSTRAINT %1$s_factual_evidence_no_null CHECK (array_position(factual_evidence_ids, NULL) IS NULL),
        authorization_evidence_id uuid NOT NULL,
        recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
        CONSTRAINT %1$s_pkey PRIMARY KEY (tenant_id, relation_id, revision),
        CONSTRAINT %1$s_src_fkey FOREIGN KEY (tenant_id, src_id) REFERENCES %3$s,
        CONSTRAINT %1$s_dst_fkey FOREIGN KEY (tenant_id, dst_id) REFERENCES %4$s
      )$ddl$, p.tbl, p.kinds, p.src_ref, p.dst_ref);
    -- FK lookup paths for the referenced side (the PK leads with relation_id, not the endpoints).
    EXECUTE format('CREATE INDEX %1$s_src_idx ON private.%1$I (tenant_id, src_id)', p.tbl);
    EXECUTE format('CREATE INDEX %1$s_dst_idx ON private.%1$I (tenant_id, dst_id)', p.tbl);
    EXECUTE format('CREATE TRIGGER %1$s_guard BEFORE INSERT ON private.%1$I '
                   'FOR EACH ROW EXECUTE FUNCTION private.relation_revision_guard(%2$L, %3$L)',
                   p.tbl, p.src_class, p.dst_class);
    EXECUTE format('CREATE TRIGGER %1$s_append_only BEFORE UPDATE OR DELETE ON private.%1$I '
                   'FOR EACH ROW EXECUTE FUNCTION private.reject_relation_revision_change()', p.tbl);
    -- §62 tenant clause, NULLIF-hardened (0246).
    EXECUTE format('ALTER TABLE private.%I ENABLE ROW LEVEL SECURITY', p.tbl);
    EXECUTE format('ALTER TABLE private.%I FORCE ROW LEVEL SECURITY', p.tbl);
    EXECUTE format($pol$
      CREATE POLICY %1$s_tenant_isolation ON private.%1$I
        USING (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid)
        WITH CHECK (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid)$pol$, p.tbl);
    -- Owner + NAMED §6.2.2 grants: gateway writes (CAS = INSERT) and reads, maintenance reads; nobody holds UPDATE
    -- or DELETE.
    EXECUTE format('ALTER TABLE private.%I OWNER TO role_migration_owner', p.tbl);
    EXECUTE format('REVOKE ALL ON private.%I FROM PUBLIC, role_gateway, role_private_worker, '
                   'role_consolidation_worker, role_public_worker, role_retrieval_worker, role_batch_issuer, '
                   'role_maintenance, role_admin', p.tbl);
    EXECUTE format('GRANT SELECT, INSERT ON private.%I TO role_gateway', p.tbl);
    EXECUTE format('GRANT SELECT ON private.%I TO role_maintenance', p.tbl);
    EXECUTE format('COMMENT ON TABLE private.%I IS %L', p.tbl,
                   '§6.1.4 relation kernel (ADR-0078 D-C): append-only revisions of ' || p.src_class || ' -> '
                   || p.dst_class || ' relations; current state = highest revision per relation_id; '
                   || 'valid ''{}'' = retracted. M29 T05.');
  END LOOP;
END
$template$;
