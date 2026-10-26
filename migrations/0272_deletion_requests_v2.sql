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
-- it checks the caller's tenant GUC against its argument and is idempotent for one (tenant, scope, requester, manifest). The
-- door is not a purge: physical deletion stays with M19-5's purge door (D3).
-- deletion_targets is a §6.2.2 named table: SELECT for role_gateway (the preview reads the frozen closure) and role_maintenance
-- (the executor), nothing for any other role; tenant_id is carried for FORCE RLS and tied to the request by a composite FK.

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM control.deletion_requests) THEN
    RAISE EXCEPTION '0272: control.deletion_requests holds v1 per-seq rows; M19 D1 requires 0 rows, refusing to migrate'
      USING ERRCODE = 'check_violation';
  END IF;
END
$$;

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
  p_tenant_id     uuid,
  p_scope_kind    text,
  p_scope_id      uuid,
  p_requested_by  uuid,
  p_manifest_hash bytea,
  p_kinds         text[],
  p_ids           uuid[]
) RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_request_id uuid;
BEGIN
  IF p_tenant_id IS DISTINCT FROM NULLIF(current_setting('humaux.tenant_id', true), '')::uuid THEN
    RAISE EXCEPTION 'deletion_request_freeze: tenant argument differs from the session tenant (§6.2)'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF cardinality(p_kinds) IS DISTINCT FROM cardinality(p_ids) THEN
    RAISE EXCEPTION 'deletion_request_freeze: kinds and ids differ in length'
      USING ERRCODE = 'invalid_parameter_value';
  END IF;

  SELECT r.deletion_request_id INTO v_request_id
    FROM control.deletion_requests r
   WHERE r.tenant_id = p_tenant_id AND r.scope_kind = p_scope_kind AND r.scope_id = p_scope_id
     AND r.requested_by = p_requested_by AND r.manifest_hash = p_manifest_hash AND r.state = 'REQUESTED'
   LIMIT 1;
  IF FOUND THEN
    RETURN v_request_id;
  END IF;

  INSERT INTO control.deletion_requests (tenant_id, scope_kind, scope_id, requested_by, manifest_hash)
  VALUES (p_tenant_id, p_scope_kind, p_scope_id, p_requested_by, p_manifest_hash)
  RETURNING deletion_request_id INTO v_request_id;

  INSERT INTO control.deletion_targets (request_id, tenant_id, kind, id)
  SELECT v_request_id, p_tenant_id, t.kind, t.id
    FROM unnest(p_kinds, p_ids) AS t(kind, id)
  ON CONFLICT DO NOTHING;

  RETURN v_request_id;
END;
$$;

COMMENT ON FUNCTION control.deletion_request_freeze(uuid, text, uuid, uuid, bytea, text[], uuid[]) IS
  'ADR-0092 D-A: records one deletion request and its frozen target list in one statement sequence. Idempotent for an open '
  'request with the same (tenant, scope, requester, manifest). Not a purge.';

ALTER FUNCTION control.deletion_request_freeze(uuid, text, uuid, uuid, bytea, text[], uuid[]) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION control.deletion_request_freeze(uuid, text, uuid, uuid, bytea, text[], uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.deletion_request_freeze(uuid, text, uuid, uuid, bytea, text[], uuid[]) TO role_gateway;
