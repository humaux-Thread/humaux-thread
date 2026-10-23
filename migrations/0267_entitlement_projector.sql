-- §76 / M04-2 (card M04-2; §46 forward-fix, EXPAND_CONTRACT, number 0267): the entitlement projector becomes the only
-- writer of control.entitlement_snapshots (besides control.renew_quota_period's promotion of its own staged successor),
-- and onboarding grants a plan version instead of an operator-typed limit.
--
-- 1. control.entitlement_grants (raw per-source facts, §76 "运行时不读取散落的 ... 表计算权限") leaves the `control.*`
--    domain default: no non-owner role reads or writes it. Its two readers are owner definers: the projector's grants
--    door below and control.onboard_tenant, its only writer today.
-- 2. control.entitlement_grants_for_projection(tenant) hands the projector one tenant's grant rows; the projection
--    itself stays in Rust (application::entitlement::project) and nowhere else.
-- 3. control.write_entitlement_snapshot(...) stores the projector's output: an unchanged `effective` writes nothing,
--    a changed one passes through 0245's stale-successor trigger.
-- 4. control.onboard_tenant swaps `p_plan_limit bigint` for `p_plan_key text, p_plan_version integer`: the version must
--    be offered (published, not retired) and carry a per-period window entitlement; the tenant gets one PLAN grant per
--    template key (value verbatim, the per-period one with the onboarding period) and NO snapshot: the caller runs the
--    projector in the same transaction (adapters::entitlement_repo::recompute_in_txn).
--
-- Every function is owned by role_migration_owner, SECURITY DEFINER, `SET search_path = pg_catalog`, REVOKE ALL FROM
-- PUBLIC, EXECUTE to role_maintenance only. The two projector doors assert the caller's tenant GUC (the 0176 lesson: an
-- owner door never becomes a cross-tenant door) and take the issuer's `quota-window:` advisory lock so a recompute and
-- a renewal for one tenant serialize. No table is created and no row is rewritten.

REVOKE ALL ON TABLE control.entitlement_grants FROM
  PUBLIC,
  role_gateway,
  role_private_worker,
  role_consolidation_worker,
  role_public_worker,
  role_retrieval_worker,
  role_batch_issuer,
  role_admin,
  role_maintenance;

-- One tenant's grant rows, every state (the projector decides which are active). Ordered, so the projector's input is
-- deterministic.
CREATE FUNCTION control.entitlement_grants_for_projection(p_tenant_id uuid)
RETURNS TABLE (
  out_grant_id uuid,
  out_source text,
  out_feature text,
  out_value jsonb,
  out_valid_from timestamptz,
  out_valid_until timestamptz,
  out_priority integer,
  out_revoked_at timestamptz
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF p_tenant_id IS NULL OR p_tenant_id = '00000000-0000-0000-0000-000000000000'::uuid
     OR p_tenant_id IS DISTINCT FROM NULLIF(pg_catalog.current_setting('humaux.tenant_id', true), '')::uuid THEN
    RAISE EXCEPTION 'invalid entitlement scope' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
    SELECT g.grant_id, g.source, g.feature, g.value, g.valid_from, g.valid_until, g.priority, g.revoked_at
      FROM control.entitlement_grants g
     WHERE g.tenant_id = p_tenant_id
     ORDER BY g.grant_id;
END;
$$;

-- Stores one projection. Returns true when `effective` changed (or the row was created), false when the stored
-- `effective` already equals it: the recompute is idempotent and a no-op leaves computed_at (the quota issuer's
-- issued_snapshot_at) alone. Only the grant ids may move on a no-op, as audit metadata.
CREATE FUNCTION control.write_entitlement_snapshot(
  p_tenant_id uuid,
  p_effective jsonb,
  p_source_grant_ids uuid[],
  p_computed_at timestamptz
) RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_lock_key constant text := 'mcp.billable_operations.per_period';
  v_old jsonb;
BEGIN
  IF p_tenant_id IS NULL OR p_tenant_id = '00000000-0000-0000-0000-000000000000'::uuid
     OR p_tenant_id IS DISTINCT FROM NULLIF(pg_catalog.current_setting('humaux.tenant_id', true), '')::uuid THEN
    RAISE EXCEPTION 'invalid entitlement scope' USING ERRCODE = '42501';
  END IF;
  IF p_effective IS NULL OR pg_catalog.jsonb_typeof(p_effective) IS DISTINCT FROM 'object'
     OR p_source_grant_ids IS NULL OR p_computed_at IS NULL OR NOT pg_catalog.isfinite(p_computed_at) THEN
    RAISE EXCEPTION 'invalid entitlement snapshot' USING ERRCODE = '22023';
  END IF;
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('quota-window:' || p_tenant_id::text || ':' || v_lock_key, 0));

  SELECT s.effective INTO v_old FROM control.entitlement_snapshots s WHERE s.tenant_id = p_tenant_id FOR UPDATE;
  IF NOT FOUND THEN
    INSERT INTO control.entitlement_snapshots (tenant_id, effective, source_grant_ids, computed_at)
    VALUES (p_tenant_id, p_effective, p_source_grant_ids, p_computed_at);
    RETURN true;
  END IF;
  IF v_old IS NOT DISTINCT FROM p_effective THEN
    UPDATE control.entitlement_snapshots s
       SET source_grant_ids = p_source_grant_ids
     WHERE s.tenant_id = p_tenant_id AND s.source_grant_ids IS DISTINCT FROM p_source_grant_ids;
    RETURN false;
  END IF;
  UPDATE control.entitlement_snapshots s
     SET effective = p_effective, source_grant_ids = p_source_grant_ids, computed_at = p_computed_at
   WHERE s.tenant_id = p_tenant_id;
  RETURN true;
END;
$$;

-- 0186's onboard_tenant, replaced: same flow and refusals, plus the plan version. The old signature is dropped (its only
-- callers move in this card), so no second onboarding door and no second snapshot writer remain.
DROP FUNCTION control.onboard_tenant(text, uuid, text, text, bigint, timestamptz, timestamptz, text, text, bigint, bigint, text[]);

CREATE FUNCTION control.onboard_tenant(
  p_name text,
  p_owner_user uuid,
  p_workspace_name text,
  p_reasoning_domain_name text,
  p_plan_key text,
  p_plan_version integer,
  p_period_start timestamptz,
  p_period_end timestamptz,
  p_provider_id text,
  p_region text,
  p_tenant_tpm bigint,
  p_tenant_rpm bigint,
  p_families text[]
) RETURNS TABLE (tenant_id uuid, workspace_id uuid, reasoning_domain_id uuid, created boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
#variable_conflict use_column
DECLARE
  v_period_key constant text := 'mcp.billable_operations.per_period';
  v_tenant uuid := uuidv7();
  v_inserted uuid;
  v_ws uuid;
  v_rd uuid;
  v_plan_version uuid;
  v_template jsonb;
BEGIN
  IF p_name IS NULL OR length(p_name) NOT BETWEEN 1 AND 128 OR p_owner_user IS NULL
     OR p_workspace_name IS NULL OR length(p_workspace_name) NOT BETWEEN 1 AND 128
     OR p_reasoning_domain_name IS NULL OR length(p_reasoning_domain_name) NOT BETWEEN 1 AND 128
     OR p_plan_key IS NULL OR length(p_plan_key) = 0 OR p_plan_version IS NULL OR p_plan_version <= 0
     OR p_period_start IS NULL OR p_period_end IS NULL OR p_period_end <= p_period_start
     OR p_provider_id IS NULL OR length(p_provider_id) = 0
     OR p_region IS NULL OR length(p_region) = 0
     OR p_tenant_tpm IS NULL OR p_tenant_tpm <= 0 OR p_tenant_rpm IS NULL OR p_tenant_rpm <= 0
     OR p_families IS NULL OR cardinality(p_families) = 0 OR cardinality(p_families) % 3 <> 0 THEN
    RAISE EXCEPTION 'invalid onboarding request' USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM control.retrieval_provider_admission_limits l
                  WHERE l.provider_id = p_provider_id AND l.tenant_id IS NULL AND l.region IS NULL
                    AND l.purpose IS NULL AND l.effective_to IS NULL)
     OR NOT EXISTS (SELECT 1 FROM control.retrieval_provider_admission_limits l
                     WHERE l.provider_id = p_provider_id AND l.tenant_id IS NULL
                       AND l.region = p_region AND l.purpose IS NULL AND l.effective_to IS NULL) THEN
    RAISE EXCEPTION 'deployment_admission_missing' USING ERRCODE = '55000';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM control.users u WHERE u.user_id = p_owner_user AND u.state = 'ACTIVE') THEN
    RAISE EXCEPTION 'owner_not_active' USING ERRCODE = '55000';
  END IF;

  PERFORM set_config('humaux.tenant_id', v_tenant::text, true);
  INSERT INTO control.tenants AS t (tenant_id, name, state, onboarding_name)
  VALUES (v_tenant, p_name, 'ACTIVE', p_name)
  ON CONFLICT (onboarding_name) DO NOTHING
  RETURNING t.tenant_id INTO v_inserted;

  IF v_inserted IS NULL THEN
    SELECT t.tenant_id INTO v_tenant FROM control.tenants t WHERE t.onboarding_name = p_name;
    PERFORM set_config('humaux.tenant_id', v_tenant::text, true);
    IF NOT EXISTS (SELECT 1 FROM control.memberships m
                    WHERE m.tenant_id = v_tenant AND m.user_id = p_owner_user
                      AND m.role = 'OWNER' AND m.state = 'ACTIVE') THEN
      RAISE EXCEPTION 'onboarding_name_taken' USING ERRCODE = '55000';
    END IF;
    SELECT w.workspace_id INTO v_ws FROM control.workspaces w
     WHERE w.tenant_id = v_tenant AND w.name = p_workspace_name AND w.lifecycle <> 'LEGACY';
    IF v_ws IS NULL THEN
      RAISE EXCEPTION 'workspace_name_mismatch' USING ERRCODE = '55000';
    END IF;
    SELECT d.reasoning_domain_id INTO v_rd FROM control.private_reasoning_domains d
     WHERE d.tenant_id = v_tenant AND d.name = p_reasoning_domain_name
     ORDER BY d.created_at LIMIT 1;
    RETURN QUERY SELECT v_tenant, v_ws, v_rd, false;
    RETURN;
  END IF;

  -- §71.1: a plan version is offered once published and until retired; a draft or a retired one is never granted.
  SELECT v.plan_version_id, v.entitlement_template INTO v_plan_version, v_template
    FROM control.plan_versions v JOIN control.plans p ON p.plan_id = v.plan_id
   WHERE p.plan_key = p_plan_key AND v.version = p_plan_version
     AND v.valid_from IS NOT NULL AND v.valid_from <= pg_catalog.clock_timestamp() AND v.retired_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'plan_version_not_offered' USING ERRCODE = '55000';
  END IF;
  -- The window issuer needs a per-period object it can read a limit and a period kind from.
  IF jsonb_typeof(v_template -> v_period_key) IS DISTINCT FROM 'object' THEN
    RAISE EXCEPTION 'plan_version_without_period_quota' USING ERRCODE = '55000';
  END IF;

  INSERT INTO control.memberships (tenant_id, user_id, role, state)
  VALUES (v_tenant, p_owner_user, 'OWNER', 'ACTIVE');
  INSERT INTO control.private_reasoning_domains AS d (tenant_id, name, owner_user_id, status)
  VALUES (v_tenant, p_reasoning_domain_name, p_owner_user, 'ACTIVE')
  RETURNING d.reasoning_domain_id INTO v_rd;
  -- §76: the plan is a set of PLAN grants and nothing else; the snapshot is the projector's to write.
  INSERT INTO control.entitlement_grants (tenant_id, source, source_ref_id, feature, value, valid_from, priority)
  SELECT v_tenant, 'PLAN', v_plan_version, e.feature,
         CASE WHEN e.feature = v_period_key
              THEN e.value || jsonb_build_object(
                     'period_start', to_char(p_period_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
                     'period_end', to_char(p_period_end AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))
              ELSE e.value END,
         pg_catalog.clock_timestamp(), 0
    FROM jsonb_each(v_template) AS e(feature, value);
  PERFORM control.ensure_admission_tier(p_provider_id, NULL, v_tenant, NULL, p_tenant_tpm, p_tenant_rpm);
  PERFORM control.ensure_admission_tier(p_provider_id, NULL, v_tenant, 'RETRIEVAL_EMBEDDING', p_tenant_tpm, p_tenant_rpm);
  PERFORM control.ensure_admission_tier(p_provider_id, NULL, v_tenant, 'RETRIEVAL_RERANK', p_tenant_tpm, p_tenant_rpm);
  SELECT o.workspace_id INTO v_ws
    FROM control.onboard_workspace(v_tenant, p_workspace_name, p_owner_user, p_families) o;
  RETURN QUERY SELECT v_tenant, v_ws, v_rd, true;
END;
$$;

ALTER FUNCTION control.entitlement_grants_for_projection(uuid) OWNER TO role_migration_owner;
ALTER FUNCTION control.write_entitlement_snapshot(uuid, jsonb, uuid[], timestamptz) OWNER TO role_migration_owner;
ALTER FUNCTION control.onboard_tenant(text, uuid, text, text, text, integer, timestamptz, timestamptz, text, text, bigint, bigint, text[]) OWNER TO role_migration_owner;

REVOKE ALL ON FUNCTION control.entitlement_grants_for_projection(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.write_entitlement_snapshot(uuid, jsonb, uuid[], timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.onboard_tenant(text, uuid, text, text, text, integer, timestamptz, timestamptz, text, text, bigint, bigint, text[]) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION control.entitlement_grants_for_projection(uuid) TO role_maintenance;
GRANT EXECUTE ON FUNCTION control.write_entitlement_snapshot(uuid, jsonb, uuid[], timestamptz) TO role_maintenance;
GRANT EXECUTE ON FUNCTION control.onboard_tenant(text, uuid, text, text, text, integer, timestamptz, timestamptz, text, text, bigint, bigint, text[]) TO role_maintenance;

COMMENT ON FUNCTION control.entitlement_grants_for_projection(uuid) IS
  'M04 D3 / §76: one tenant''s entitlement_grants rows for the projector (application::entitlement::project). The only '
  'read path to the raw grants; caller GUC must name the tenant. Owner definer, EXECUTE role_maintenance only.';
COMMENT ON FUNCTION control.write_entitlement_snapshot(uuid, jsonb, uuid[], timestamptz) IS
  'M04 D3 / §76: stores the projector''s output (adapters::entitlement_repo). Sole snapshot writer besides '
  'control.renew_quota_period; true when `effective` changed, false for an identical recompute. Owner definer, EXECUTE '
  'role_maintenance only.';
