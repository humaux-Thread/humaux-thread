-- §6.1.4 / ADR-0078 D-D amendment, ADR-0110 D-F (card M29-g1, M13 note D7; §46 forward-fix, EXPAND_CONTRACT, number
-- 0282): the one SQL-side read of the live attribution view.
--   private.memory_in_project(tenant, memory, project)   does this memory have a live link to this project?
--
-- "Exists and is not revoked" lives only in private.memory_projects_live (0255 ②), so the predicate reads that view and
-- never the base table. A memory with no live row (no link at all, or every link revoked) is outside the project
-- universe and answers false, never a guess (N09 R3). The census that will call it (M13-7, recall.list project axis)
-- keeps the M29 reader the single read path (xtask G-M29-7 keeps this function the single SQL-side read, in this file).
--
-- Invoker rights, as 0256's private.is_correction_transition: the view is security_invoker, so the caller gets exactly
-- the RLS of both tables under its own role, and a tenant argument other than the session tenant finds no row. The one
-- SELECT holder of the view is role_gateway (0255 ②, the census runs on RuntimeDbPool), so it is the one EXECUTE holder;
-- no other role gets a grant. LANGUAGE sql with a pinned search_path is never inlined, so that SELECT privilege is
-- checked when the function runs.
-- ponytail: one PK probe per census row because the pinned search_path stops inlining; inline (drop the SET, keep full
--   qualification) if E-M13-1 shows the census over budget.
--
-- Locks: CREATE OR REPLACE FUNCTION locks no table.

CREATE OR REPLACE FUNCTION private.memory_in_project(p_tenant_id uuid, p_memory_id uuid, p_project_id uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog
AS $$
  SELECT EXISTS (SELECT 1
                   FROM private.memory_projects_live l
                  WHERE l.tenant_id = p_tenant_id
                    AND l.memory_id = p_memory_id
                    AND l.project_id = p_project_id)
$$;
ALTER FUNCTION private.memory_in_project(uuid, uuid, uuid) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION private.memory_in_project(uuid, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.memory_in_project(uuid, uuid, uuid) TO role_gateway;

COMMENT ON FUNCTION private.memory_in_project(uuid, uuid, uuid) IS
  '§6.1.4 / ADR-0110 D-F (migration 0282, M13 note D7): true when the memory has a live (existing, unrevoked) link to the '
  'project in the tenant. The one SQL-side read of the live attribution view; an unresolved memory answers false. '
  'Invoker, STABLE, EXECUTE role_gateway only.';
