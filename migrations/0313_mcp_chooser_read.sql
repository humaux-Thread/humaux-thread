-- ADR-0137 U1: either NULL rule dimension is a wildcard. Keep the 0312 writer and uniqueness.
ALTER TABLE control.mcp_connection_rules ALTER COLUMN client_id DROP NOT NULL;

COMMENT ON TABLE control.mcp_connection_rules IS
  'ADR-0137: NULL rule workspace or client matches every value in that dimension. Active ALLOW and DENY may coexist.';

-- ADR-0137 U1–U3. Ordinals give the adapter one decision for every input.
CREATE FUNCTION control.read_mcp_chooser_decisions(
  p_user_id uuid,
  p_client_id text,
  p_tenants uuid[],
  p_workspaces uuid[]
) RETURNS TABLE (candidate_no bigint, allowed boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog
SET humaux.tenant_id = ''
AS $$
DECLARE
  v_tenant uuid;
  v_policy_enabled boolean;
  v_groups_restricted boolean;
  v_group_allowed boolean;
BEGIN
  -- The tenant lock also orders absent rows; the subsequent statements need a fresh snapshot.
  IF current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'MCP chooser requires read committed' USING ERRCODE = '25000';
  END IF;
  IF p_user_id IS NULL OR p_client_id IS NULL OR p_client_id = ''
     OR p_tenants IS NULL OR p_workspaces IS NULL
     OR cardinality(p_tenants) <> cardinality(p_workspaces)
     OR cardinality(p_tenants) > 256 OR array_position(p_tenants, NULL) IS NOT NULL THEN
    RAISE EXCEPTION 'invalid MCP chooser candidates' USING ERRCODE = '22023';
  END IF;

  FOR v_tenant IN SELECT DISTINCT id FROM unnest(p_tenants) AS t(id) ORDER BY id
  LOOP
    PERFORM set_config('humaux.tenant_id', v_tenant::text, true);
    PERFORM 1 FROM control.tenants t
     WHERE t.tenant_id = v_tenant AND t.state = 'ACTIVE'
     FOR SHARE;
    v_group_allowed := FOUND;
    v_policy_enabled := false;

    IF v_group_allowed THEN
      SELECT p.policy_enabled, p.groups_restricted INTO v_policy_enabled, v_groups_restricted
        FROM control.mcp_connection_policies p
       WHERE p.tenant_id = v_tenant
       FOR SHARE;
      -- A successful read with no row adds no restriction.
      IF NOT FOUND THEN
        v_policy_enabled := false;
      ELSIF v_groups_restricted THEN
        WITH allowed_groups AS MATERIALIZED (
          SELECT g.group_id FROM control.mcp_groups g
           WHERE g.tenant_id = v_tenant AND g.allowed
           FOR SHARE
        ), memberships AS MATERIALIZED (
          SELECT m.group_id, m.active FROM control.mcp_group_members m
            JOIN allowed_groups g USING (group_id)
           WHERE m.tenant_id = v_tenant AND m.user_id = p_user_id
           FOR SHARE OF m
        )
        SELECT count(*) FILTER (WHERE m.active) > 0 INTO v_group_allowed
          FROM allowed_groups g LEFT JOIN memberships m USING (group_id);
      END IF;
    END IF;

    RETURN QUERY
    WITH candidates AS MATERIALIZED (
      SELECT c.workspace_id, c.ord FROM unnest(p_tenants, p_workspaces)
        WITH ORDINALITY AS c(tenant_id, workspace_id, ord)
       WHERE c.tenant_id = v_tenant
    ), matching_rules AS MATERIALIZED (
      SELECT c.ord, r.effect FROM control.mcp_connection_rules r
        JOIN candidates c ON r.workspace_id IS NULL OR r.workspace_id = c.workspace_id
       WHERE v_group_allowed AND v_policy_enabled AND r.tenant_id = v_tenant AND r.active
         AND (r.client_id IS NULL OR r.client_id = p_client_id)
       FOR SHARE OF r
    ), effects AS (
      SELECT r.ord, bool_or(r.effect = 'ALLOW') AS permits, bool_or(r.effect = 'DENY') AS denies
        FROM matching_rules r GROUP BY r.ord
    )
    SELECT c.ord, v_group_allowed AND
           (NOT v_policy_enabled OR (COALESCE(e.permits, false) AND NOT COALESCE(e.denies, false)))
      FROM candidates c LEFT JOIN effects e ON e.ord = c.ord;
  END LOOP;
END;
$$;

ALTER FUNCTION control.read_mcp_chooser_decisions(uuid, text, uuid[], uuid[]) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION control.read_mcp_chooser_decisions(uuid, text, uuid[], uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.read_mcp_chooser_decisions(uuid, text, uuid[], uuid[]) TO role_gateway;

COMMENT ON FUNCTION control.read_mcp_chooser_decisions(uuid, text, uuid[], uuid[]) IS
  'ADR-0137 policy and allowed-group decision for each trusted candidate ordinal. '
  'READ COMMITTED, shared tenant guard before reading and locking decision rows.';
