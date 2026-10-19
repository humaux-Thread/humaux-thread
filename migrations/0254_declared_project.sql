-- ADR-0078 D-D rung A1 / Baseline §6.1.4 (card M29 T06c; §46 forward-fix, EXPAND_CONTRACT): the server-side
-- resolution of a `remember.put` `project_id`, and the gateway's INSERT on the write-side carrier
-- private.evidence_projects (0252).
--
-- Invariants:
--   ① one narrow reader: private.declared_project_visible answers one boolean, "this project exists in this tenant,
--     is ACTIVE and lives in a workspace the caller is authorized for". No runtime role can read
--     private.continuity_projects (0136 grants nothing), so the reader is owner SECURITY DEFINER with
--     search_path=pg_catalog and EXECUTE for role_gateway only, as 0137's read_continuity_project_storage_v1.
--     p_authorized_workspace_ids is the same input 0137 receives: the request's AuthorizationScope workspace set.
--   ② unknown, another tenant's, archived and not-visible projects are all `false`, one answer, so the caller
--     (adapters::remember::resolve_declared_project_in_txn) maps them to one INVALID_INPUT and the response is not an
--     existence oracle. ARCHIVED is refused like 0136's publish and 0137's read, the two existing project doors.
--   ③ the tenant argument must be the transaction's humaux.tenant_id GUC (42501 otherwise), so a caller cannot ask
--     about another tenant through the definer's RLS bypass.
--   ④ one writer of evidence_projects: remember.put's receipt transaction, after ① passed in that same
--     transaction; xtask G-T06c-3 pins the one INSERT statement (adapters::remember::insert_evidence_project_in_txn,
--     pub(crate)), and the grant below is the DB backstop. Nobody holds UPDATE or DELETE.
--
-- The predicates of ① are not pinned by the postcheck: G-T06c-1 and G-T06c-2 (bins/gateway/tests/mcp_gateway.rs,
-- crates/adapters/tests/memory_attribution.rs) seed a decoy each predicate alone excludes, so a dropped predicate is a
-- red test instead of a failed migration.
--
-- Locks: CREATE FUNCTION and GRANT take no table lock beyond the catalog rows they write.

CREATE FUNCTION private.declared_project_visible(
  p_tenant_id uuid,
  p_project_id uuid,
  p_authorized_workspace_ids uuid[]
) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path TO pg_catalog
AS $$
BEGIN
  IF p_tenant_id IS DISTINCT FROM NULLIF(current_setting('humaux.tenant_id', true), '')::uuid THEN
    RAISE EXCEPTION 'declared project resolved outside the transaction tenant' USING ERRCODE = '42501';
  END IF;
  RETURN EXISTS (
    SELECT 1 FROM private.continuity_projects project
     WHERE p_tenant_id IS NOT NULL
       AND project.project_id = p_project_id
       AND project.lifecycle_state = 'ACTIVE'
       AND project.workspace_id = ANY(p_authorized_workspace_ids));
END;
$$;

ALTER FUNCTION private.declared_project_visible(uuid, uuid, uuid[]) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION private.declared_project_visible(uuid, uuid, uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.declared_project_visible(uuid, uuid, uuid[]) TO role_gateway;

GRANT INSERT ON private.evidence_projects TO role_gateway;

COMMENT ON FUNCTION private.declared_project_visible(uuid, uuid, uuid[]) IS
  'ADR-0078 D-D A1: true only for an ACTIVE project of p_tenant_id (= humaux.tenant_id) in one of the caller''s authorized workspaces; every other case is one false (INVALID_INPUT, no existence oracle).';
