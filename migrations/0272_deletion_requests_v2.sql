-- §46 forward-fix (EXPAND_CONTRACT, M19-2, ADR-0092 D-A): control.deletion_requests becomes one row per REQUEST (v2) and the
-- frozen closure moves to the new control.deletion_targets (Baseline §37; module design M19 D1, D2, D3).
--
--   control.deletion_requests  v1 was one row per (tenant, §15.1 stream key, stream_seq). v2 drops the four stream-key columns
--                              (domain, projection_kind, projection_version, stream_seq; the UNIQUE over them goes with them),
--                              narrows scope_kind to the five scopes (MEMORY | EVIDENCE_CLOSURE | SUBJECT | DOCUMENT | TENANT)
--                              and adds requested_by, manifest_hash (sha-256 over the canonical sorted target list), the
--                              nullable confirm_token_id (bound by M19-3a) and logical_deleted_at (set by M19-3a's accept txn).
--   control.deletion_targets   (request_id, kind, id): the closure frozen at preview time. kind is MEMORY | EVIDENCE in this
--                              migration; SUBJECT / DOCUMENT / TENANT closures widen the CHECK when their fns exist.
--
-- v1 holds no rows in any database (the pipeline had no caller). The migration refuses a database that does, with the exact
-- message below, instead of inventing a mapping from a stream key to a target.
--
-- Writes (§6.2.1): no runtime role holds INSERT, UPDATE or DELETE on either table. The one new write path is the owner
-- SECURITY DEFINER door control.deletion_request_freeze (EXECUTE role_gateway only, search_path = pg_catalog, pg_temp as in 0268);
-- it takes (scope_kind, scope roots) and nothing else the caller could forge: it computes the targets and manifest_hash itself
-- (the closure is the explicit roots plus every Memory with ANY memory_evidence input among them, whole; never the generic
-- DERIVED_FROM closure, ADR-0092 D-A / ADR-0079 D-J) under a tenant-only predicate, independent of the caller's visibility, and
-- takes requested_by from the session (humaux.user_id). Every root must exist in the session tenant and be readable by the
-- caller under the §6.1.1 visibility rule (the SQL home of read_gate::visibility_readable, private.visibility_allowed), else the
-- door refuses with SQLSTATE P0002 and a machine-readable reason. A partial UNIQUE index over the open request makes a
-- concurrent duplicate freeze return the existing request_id. The door is not a purge: physical deletion stays with M19-5's
-- purge door (D3).
--
-- Owner role_migration_owner is NOBYPASSRLS: memory_records carries a cluster-wide owner arm (0163), so every Memory read below
-- filters on the session tenant explicitly; evidence_objects has no owner arm, so the root check reads it under the caller's
-- visibility (and re-applies private.visibility_allowed so other owner policies cannot widen it).
-- ponytail: the Memory-root check omits the §6.1.3 subject term (private.memory_subject_visibility_ok is tenant-wide today),
-- upgrade when per-subject ACLs land.
-- deletion_targets is a §6.2.2 named table: SELECT for role_gateway (the preview reads the frozen closure) and role_maintenance
-- (the executor), nothing for any other role; tenant_id is carried for FORCE RLS and tied to the request by a composite FK.

-- Without BYPASSRLS this errors on the FORCE RLS table instead of counting the 0 rows RLS would show.
SELECT set_config('row_security', 'off', true);

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM control.deletion_requests) THEN
    RAISE EXCEPTION '0272: control.deletion_requests holds v1 per-seq rows; M19 D1 requires 0 rows, refusing to migrate'
      USING ERRCODE = 'check_violation';
  END IF;
END
$$;
SELECT set_config('row_security', 'on', true);

ALTER TABLE control.deletion_requests
  DROP COLUMN domain,
  DROP COLUMN projection_kind,
  DROP COLUMN projection_version,
  DROP COLUMN stream_seq;

ALTER TABLE control.deletion_requests
  ADD CONSTRAINT deletion_requests_scope_kind_check
    CHECK (scope_kind IN ('MEMORY', 'EVIDENCE_CLOSURE', 'SUBJECT', 'DOCUMENT', 'TENANT')),
  ADD COLUMN requested_by       uuid        NOT NULL REFERENCES control.users(user_id),
  ADD COLUMN manifest_hash      bytea       NOT NULL CHECK (octet_length(manifest_hash) = 32),
  ADD COLUMN confirm_token_id   uuid,
  ADD COLUMN logical_deleted_at timestamptz;

COMMENT ON TABLE control.deletion_requests IS
  '§37 / ADR-0092 D-A deletion request v2: one row per request (scope_kind, scope_id), closure frozen in control.deletion_targets, '
  'manifest_hash = sha-256 over the canonical sorted (kind, id) target list.';

-- One open request per (scope, requester, closure): the door's ON CONFLICT arbiter, so two concurrent freezes of the same
-- scope end with one row.
CREATE UNIQUE INDEX deletion_requests_open_manifest_uq ON control.deletion_requests
  (tenant_id, scope_kind, scope_id, requested_by, manifest_hash) WHERE state = 'REQUESTED';

CREATE TABLE control.deletion_targets (
  request_id uuid NOT NULL,
  tenant_id  uuid NOT NULL REFERENCES control.tenants(tenant_id),
  kind       text NOT NULL CHECK (kind IN ('MEMORY', 'EVIDENCE')),
  id         uuid NOT NULL,
  PRIMARY KEY (request_id, kind, id),
  FOREIGN KEY (request_id, tenant_id) REFERENCES control.deletion_requests (deletion_request_id, tenant_id)
);

COMMENT ON TABLE control.deletion_targets IS
  'ADR-0092 D-A: the closure frozen at preview time. Written only by control.deletion_request_freeze; ids only, no content.';

ALTER TABLE control.deletion_targets OWNER TO role_migration_owner;
ALTER TABLE control.deletion_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE control.deletion_targets FORCE ROW LEVEL SECURITY;

CREATE POLICY deletion_targets_tenant_isolation ON control.deletion_targets
USING (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid)
WITH CHECK (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid);

REVOKE ALL ON TABLE control.deletion_targets
FROM
  PUBLIC,
  role_private_worker,
  role_consolidation_worker,
  role_public_worker,
  role_retrieval_worker,
  role_batch_issuer,
  role_admin,
  role_gateway,
  role_maintenance,
  role_health_reader;
GRANT SELECT ON control.deletion_targets TO role_gateway, role_maintenance;

CREATE FUNCTION control.deletion_request_freeze(
  p_tenant_id  uuid,
  p_scope_kind text,
  p_roots      uuid[]
) RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_user       uuid := NULLIF(current_setting('humaux.user_id', true), '')::uuid;
  v_roots      uuid[];
  v_kinds      text[];
  v_ids        uuid[];
  v_hash       bytea;
  v_request_id uuid;
BEGIN
  IF p_tenant_id IS DISTINCT FROM NULLIF(current_setting('humaux.tenant_id', true), '')::uuid THEN
    RAISE EXCEPTION 'deletion_request_freeze: tenant argument differs from the session tenant (§6.2)'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF v_user IS NULL OR v_user = '00000000-0000-0000-0000-000000000000'::uuid THEN
    RAISE EXCEPTION 'deletion_request_freeze: the session carries no user (humaux.user_id; requested_by comes from the session)'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF p_scope_kind IS NULL OR p_scope_kind NOT IN ('MEMORY', 'EVIDENCE_CLOSURE') THEN
    RAISE EXCEPTION 'deletion_request_freeze: scope % has no closure fn yet', p_scope_kind
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF p_roots IS NULL OR array_position(p_roots, NULL) IS NOT NULL THEN
    RAISE EXCEPTION 'deletion_request_freeze: roots must be a non-null list of ids'
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  v_roots := ARRAY(SELECT DISTINCT r FROM unnest(p_roots) AS r ORDER BY r);
  IF coalesce(cardinality(v_roots), 0) = 0 OR (p_scope_kind = 'MEMORY' AND cardinality(v_roots) <> 1) THEN
    RAISE EXCEPTION 'deletion_request_freeze: MEMORY takes exactly one root, EVIDENCE_CLOSURE at least one'
      USING ERRCODE = 'invalid_parameter_value';
  END IF;

  IF p_scope_kind = 'MEMORY' THEN
    -- §8.6: the Memory is readable and every backing Evidence row is readable too; a Memory with no backing row fails closed.
    IF NOT EXISTS (
      SELECT 1 FROM private.memory_records m
       WHERE m.tenant_id = p_tenant_id AND m.memory_id = v_roots[1]
         AND private.visibility_allowed(m.visibility_class, true, m.visibility_user_id = v_user,
               EXISTS (SELECT 1 FROM control.workspace_memberships wm
                        WHERE wm.tenant_id = m.tenant_id AND wm.workspace_id = m.visibility_workspace_id
                          AND wm.user_id = v_user AND wm.state = 'ACTIVE'))
         AND EXISTS (SELECT 1 FROM private.memory_evidence me WHERE me.memory_id = m.memory_id)
         AND NOT EXISTS (
           SELECT 1 FROM private.memory_evidence me
             LEFT JOIN private.evidence_objects eo
               ON eo.evidence_id = me.evidence_id AND eo.tenant_id = p_tenant_id
              AND private.visibility_allowed(eo.visibility_class, true, eo.visibility_user_id = v_user,
                    EXISTS (SELECT 1 FROM control.workspace_memberships wm
                             WHERE wm.tenant_id = eo.tenant_id AND wm.workspace_id = eo.visibility_workspace_id
                               AND wm.user_id = v_user AND wm.state = 'ACTIVE'))
            WHERE me.memory_id = m.memory_id AND eo.evidence_id IS NULL)
    ) THEN
      RAISE EXCEPTION 'deletion_request_freeze: NOT_FOUND root_unreadable' USING ERRCODE = 'no_data_found';
    END IF;
    v_kinds := ARRAY['MEMORY'];
    v_ids := v_roots;
  ELSE
    IF (SELECT count(*) FROM private.evidence_objects eo
         WHERE eo.tenant_id = p_tenant_id AND eo.evidence_id = ANY (v_roots)
           AND private.visibility_allowed(eo.visibility_class, true, eo.visibility_user_id = v_user,
                 EXISTS (SELECT 1 FROM control.workspace_memberships wm
                          WHERE wm.tenant_id = eo.tenant_id AND wm.workspace_id = eo.visibility_workspace_id
                            AND wm.user_id = v_user AND wm.state = 'ACTIVE'))) <> cardinality(v_roots) THEN
      RAISE EXCEPTION 'deletion_request_freeze: NOT_FOUND root_unreadable' USING ERRCODE = 'no_data_found';
    END IF;
    SELECT array_agg(t.kind), array_agg(t.id) INTO v_kinds, v_ids
      FROM (SELECT 'EVIDENCE'::text AS kind, r AS id FROM unnest(v_roots) AS r
            UNION
            SELECT 'MEMORY'::text, me.memory_id
              FROM private.memory_evidence me
              JOIN private.memory_records m ON m.memory_id = me.memory_id AND m.tenant_id = p_tenant_id
             WHERE me.evidence_id = ANY (v_roots)) t;
  END IF;

  -- Canonical encoding of humaux_application::forget::manifest_hash: domain line, then sorted (kind, 0x00, 16 id bytes).
  v_hash := sha256(
    convert_to('humaux.deletion.manifest.v1' || chr(10), 'UTF8')
    || coalesce((SELECT string_agg(convert_to(t.kind, 'UTF8') || '\x00'::bytea || uuid_send(t.id), ''::bytea
                                   ORDER BY t.kind COLLATE "C", t.id)
                   FROM unnest(v_kinds, v_ids) AS t(kind, id)), ''::bytea));

  INSERT INTO control.deletion_requests (tenant_id, scope_kind, scope_id, requested_by, manifest_hash)
  VALUES (p_tenant_id, p_scope_kind, v_roots[1], v_user, v_hash)
  ON CONFLICT (tenant_id, scope_kind, scope_id, requested_by, manifest_hash) WHERE state = 'REQUESTED' DO NOTHING
  RETURNING deletion_request_id INTO v_request_id;

  IF v_request_id IS NULL THEN
    SELECT r.deletion_request_id INTO v_request_id
      FROM control.deletion_requests r
     WHERE r.tenant_id = p_tenant_id AND r.scope_kind = p_scope_kind AND r.scope_id = v_roots[1]
       AND r.requested_by = v_user AND r.manifest_hash = v_hash AND r.state = 'REQUESTED';
    IF v_request_id IS NULL THEN
      RAISE EXCEPTION 'deletion_request_freeze: the open request moved on while freezing, retry'
        USING ERRCODE = 'serialization_failure';
    END IF;
    RETURN v_request_id;
  END IF;

  INSERT INTO control.deletion_targets (request_id, tenant_id, kind, id)
  SELECT v_request_id, p_tenant_id, t.kind, t.id
    FROM unnest(v_kinds, v_ids) AS t(kind, id);

  RETURN v_request_id;
END;
$$;

COMMENT ON FUNCTION control.deletion_request_freeze(uuid, text, uuid[]) IS
  'ADR-0092 D-A: records one deletion request and its frozen target list. Takes (scope_kind, roots) only: computes the closure '
  'and manifest_hash itself, requested_by from the session, refuses an unreadable root with P0002. Idempotent for an open '
  'request with the same (tenant, scope, requester, manifest). Not a purge.';

ALTER FUNCTION control.deletion_request_freeze(uuid, text, uuid[]) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION control.deletion_request_freeze(uuid, text, uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.deletion_request_freeze(uuid, text, uuid[]) TO role_gateway;
