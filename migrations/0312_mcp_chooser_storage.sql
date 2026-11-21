-- ADR-0137 U1–U3: identity_access owns policy, rules, allowed flags and group membership.
CREATE TYPE control.mcp_policy_effect AS ENUM ('ALLOW', 'DENY');
ALTER TYPE control.mcp_policy_effect OWNER TO role_migration_owner;
REVOKE ALL ON TYPE control.mcp_policy_effect FROM PUBLIC;

CREATE TABLE control.mcp_connection_policies (
  tenant_id uuid PRIMARY KEY REFERENCES control.tenants(tenant_id) ON DELETE CASCADE,
  policy_enabled boolean NOT NULL,
  groups_restricted boolean NOT NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0)
);

CREATE TABLE control.mcp_connection_rules (
  tenant_id uuid NOT NULL REFERENCES control.tenants(tenant_id) ON DELETE CASCADE,
  workspace_id uuid,
  client_id text NOT NULL CHECK (client_id <> ''),
  effect control.mcp_policy_effect NOT NULL,
  active boolean NOT NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  UNIQUE NULLS NOT DISTINCT (tenant_id, workspace_id, client_id, effect),
  FOREIGN KEY (tenant_id, workspace_id)
    REFERENCES control.workspaces(tenant_id, workspace_id) ON DELETE CASCADE
);

CREATE TABLE control.mcp_groups (
  tenant_id uuid NOT NULL REFERENCES control.tenants(tenant_id) ON DELETE CASCADE,
  group_id uuid NOT NULL,
  allowed boolean NOT NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  PRIMARY KEY (tenant_id, group_id)
);

CREATE TABLE control.mcp_group_members (
  tenant_id uuid NOT NULL,
  group_id uuid NOT NULL,
  user_id uuid NOT NULL,
  active boolean NOT NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  PRIMARY KEY (tenant_id, group_id, user_id),
  FOREIGN KEY (tenant_id, group_id) REFERENCES control.mcp_groups(tenant_id, group_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, user_id) REFERENCES control.memberships(tenant_id, user_id) ON DELETE CASCADE
);

DO $$
DECLARE
  v_table text;
BEGIN
  FOREACH v_table IN ARRAY ARRAY[
    'mcp_connection_policies', 'mcp_connection_rules', 'mcp_groups', 'mcp_group_members'
  ]
  LOOP
    EXECUTE format('ALTER TABLE control.%I OWNER TO role_migration_owner', v_table);
    EXECUTE format('ALTER TABLE control.%I ENABLE ROW LEVEL SECURITY', v_table);
    EXECUTE format('ALTER TABLE control.%I FORCE ROW LEVEL SECURITY', v_table);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON control.%I
        USING (tenant_id = NULLIF(current_setting(''humaux.tenant_id'', true), '''')::uuid)
        WITH CHECK (tenant_id = NULLIF(current_setting(''humaux.tenant_id'', true), '''')::uuid)',
      v_table
    );
    EXECUTE format(
      'REVOKE ALL ON control.%I FROM PUBLIC, role_gateway, role_private_worker,
        role_consolidation_worker, role_public_worker, role_retrieval_worker,
        role_batch_issuer, role_maintenance, role_admin', v_table
    );
  END LOOP;
END;
$$;

-- Acquire the tenant guard before any write, including first configuration. Readers
-- take FOR SHARE on this same tenant row before locking and reading the decision rows.
-- Configuration is disabled and rules/members withdrawn in place so versions survive revocation.
CREATE FUNCTION control.write_mcp_chooser_settings(
  p_actor_tenant uuid,
  p_actor_user uuid,
  p_tenant_id uuid,
  p_action text,
  p_values jsonb
) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
SET humaux.tenant_id = ''
AS $$
DECLARE
  v_version bigint;
BEGIN
  IF p_actor_tenant IS DISTINCT FROM p_tenant_id THEN
    RETURN NULL;
  END IF;
  PERFORM set_config('humaux.tenant_id', p_actor_tenant::text, true);

  PERFORM 1 FROM control.tenants
    WHERE tenant_id = p_tenant_id AND state = 'ACTIVE'
    FOR NO KEY UPDATE;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  PERFORM 1 FROM control.memberships m
    JOIN control.users u USING (user_id)
   WHERE m.tenant_id = p_actor_tenant AND u.user_id = p_actor_user
     AND m.state = 'ACTIVE' AND u.state = 'ACTIVE'
     AND m.role IN ('OWNER', 'ADMIN')
   FOR SHARE OF m, u;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  PERFORM set_config('humaux.tenant_id', p_tenant_id::text, true);
  CASE p_action
    WHEN 'configure' THEN
      INSERT INTO control.mcp_connection_policies AS policy (tenant_id, policy_enabled, groups_restricted)
      VALUES (p_tenant_id, (p_values->>'policy_enabled')::boolean, (p_values->>'groups_restricted')::boolean)
      ON CONFLICT (tenant_id) DO UPDATE
        SET policy_enabled = EXCLUDED.policy_enabled, groups_restricted = EXCLUDED.groups_restricted,
            version = policy.version + 1
      RETURNING version INTO v_version;
    WHEN 'rule' THEN
      INSERT INTO control.mcp_connection_rules AS rule (tenant_id, workspace_id, client_id, effect, active)
      VALUES (p_tenant_id, (p_values->>'workspace_id')::uuid, p_values->>'client_id',
              (p_values->>'effect')::control.mcp_policy_effect, (p_values->>'active')::boolean)
      ON CONFLICT (tenant_id, workspace_id, client_id, effect) DO UPDATE
        SET active = EXCLUDED.active, version = rule.version + 1
      RETURNING version INTO v_version;
    WHEN 'group' THEN
      INSERT INTO control.mcp_groups AS grp (tenant_id, group_id, allowed)
      VALUES (p_tenant_id, (p_values->>'group_id')::uuid, (p_values->>'allowed')::boolean)
      ON CONFLICT (tenant_id, group_id) DO UPDATE
        SET allowed = EXCLUDED.allowed, version = grp.version + 1
      RETURNING version INTO v_version;
    WHEN 'member' THEN
      INSERT INTO control.mcp_group_members AS member (tenant_id, group_id, user_id, active)
      VALUES (p_tenant_id, (p_values->>'group_id')::uuid,
              (p_values->>'user_id')::uuid, (p_values->>'active')::boolean)
      ON CONFLICT (tenant_id, group_id, user_id) DO UPDATE
        SET active = EXCLUDED.active, version = member.version + 1
      RETURNING version INTO v_version;
    ELSE
      RAISE EXCEPTION 'unknown MCP chooser settings action' USING ERRCODE = '22023';
  END CASE;
  RETURN v_version;
END;
$$;

ALTER FUNCTION control.write_mcp_chooser_settings(uuid, uuid, uuid, text, jsonb) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION control.write_mcp_chooser_settings(uuid, uuid, uuid, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.write_mcp_chooser_settings(uuid, uuid, uuid, text, jsonb) TO role_gateway;

COMMENT ON FUNCTION control.write_mcp_chooser_settings(uuid, uuid, uuid, text, jsonb) IS
  'ADR-0137: sole runtime writer, taking authenticated actor scope from the gateway. '
  'Lock control.tenants by target tenant FOR NO KEY UPDATE before changing any decision row.';
COMMENT ON TABLE control.mcp_connection_policies IS
  'ADR-0137: an absent row or false policy_enabled adds no rules; groups_restricted enables the allowed-group condition.';
COMMENT ON TABLE control.mcp_connection_rules IS
  'ADR-0137: NULL workspace means the exact tenant-level target. Active ALLOW and DENY may coexist.';
COMMENT ON TABLE control.mcp_groups IS
  'ADR-0137: allowed marks the tenant groups selected for the allowed-group condition.';
COMMENT ON TABLE control.mcp_group_members IS
  'ADR-0137: versioned tenant-local membership. Only active rows contribute to group membership.';
