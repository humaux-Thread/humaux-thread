-- §72.2.1 / ADR-0072 (card W0; §46 forward-fix, EXPAND_CONTRACT, first free number after 0244): quota-period
-- renewal. Before a renewing tenant's period ends, one owner door stages the next period on the snapshot row
-- (`successor`, in force from `successor_from`) and issues its quota window, so the request plane reads a current
-- period and finds a window across the boundary with no maintenance call at the boundary itself.
--
-- The door is owned by role_migration_owner, SECURITY DEFINER, `SET search_path = pg_catalog` with every name
-- qualified, `TimeZone = UTC` (period arithmetic and the RFC3339 spelling never depend on the caller's session),
-- REVOKE ALL FROM PUBLIC, EXECUTE to role_maintenance only (§6.2.2). Like control.issue_quota_window (0113) it
-- asserts the caller's tenant GUC, takes the same `quota-window:` advisory lock, and reads the clock from PG.
-- No role, table or grant is added; the touched tables stay FORCE RLS.

-- ADR-0072 D-A: the staged next period. `successor` is a whole `effective` object (the current one with the BMO
-- period boundaries moved); readers use it once `successor_from <= clock_timestamp()`, and the door promotes it.
ALTER TABLE control.entitlement_snapshots
  ADD COLUMN successor jsonb,
  ADD COLUMN successor_from timestamptz,
  ADD CONSTRAINT entitlement_snapshot_successor CHECK (
    (successor IS NULL) = (successor_from IS NULL)
    AND (successor IS NULL OR (jsonb_typeof(successor) = 'object' AND isfinite(successor_from)))
  );

COMMENT ON COLUMN control.entitlement_snapshots.successor IS
  'ADR-0072 D-A: the next period''s effective object, in force from successor_from; written only by '
  'control.renew_quota_period.';

-- ADR-0072 D-B..D-D: one tenant's renewal step. Returns how many successor periods this call staged (0 on a rerun,
-- while one is pending, or for a tenant that does not renew) and the end of the tenant's latest BMO window (NULL when
-- the tenant does not renew: not ACTIVE, no snapshot, or no BMO entitlement).
CREATE FUNCTION control.renew_quota_period(
  p_tenant_id uuid,
  p_entitlement_key text,
  p_lead interval,
  p_subscription_period interval,
  p_limit integer
) RETURNS TABLE (staged integer, horizon timestamptz)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
SET TimeZone = 'UTC'
AS $$
DECLARE
  v_key constant text := 'mcp.billable_operations.per_period';
  v_rfc3339 constant text := '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$';
  v_now timestamptz;
  v_effective jsonb;
  v_successor jsonb;
  v_successor_from timestamptz;
  v_computed_at timestamptz;
  v_policy jsonb;
  v_start timestamptz;
  v_end timestamptz;
  v_next timestamptz;
  v_staged integer := 0;
BEGIN
  -- 0176 lesson: an owner door never becomes a cross-tenant door; the caller's GUC must name the tenant.
  IF p_tenant_id IS NULL OR p_tenant_id = '00000000-0000-0000-0000-000000000000'::uuid
     OR p_entitlement_key IS DISTINCT FROM v_key
     OR p_tenant_id IS DISTINCT FROM NULLIF(pg_catalog.current_setting('humaux.tenant_id', true), '')::uuid THEN
    RAISE EXCEPTION 'invalid quota renewal scope' USING ERRCODE = '42501';
  END IF;
  IF p_lead IS NULL OR p_lead < interval '0' OR p_subscription_period IS NULL
     OR p_subscription_period <= interval '0' OR p_limit IS NULL OR p_limit <= 0 THEN
    RAISE EXCEPTION 'invalid quota renewal request' USING ERRCODE = '22023';
  END IF;
  -- §72.2.1: the issuer's lock key, so a renewal and an issue for one tenant serialize.
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('quota-window:' || p_tenant_id::text || ':' || p_entitlement_key, 0));
  v_now := pg_catalog.clock_timestamp();

  -- ADR-0072 D-B: only an ACTIVE tenant renews (§71.2 subscription states do not exist in the schema yet).
  IF NOT EXISTS (SELECT 1 FROM control.tenants t WHERE t.tenant_id = p_tenant_id AND t.state = 'ACTIVE') THEN
    RETURN QUERY SELECT 0, NULL::timestamptz;
    RETURN;
  END IF;

  LOOP
    SELECT s.effective, s.successor, s.successor_from, s.computed_at
      INTO v_effective, v_successor, v_successor_from, v_computed_at
      FROM control.entitlement_snapshots s
     WHERE s.tenant_id = p_tenant_id
       FOR UPDATE;
    IF NOT FOUND OR v_effective -> v_key IS NULL THEN
      RETURN QUERY SELECT v_staged, NULL::timestamptz;
      RETURN;
    END IF;

    -- ADR-0072 D-A: a successor whose time has come replaces the current period.
    IF v_successor_from IS NOT NULL AND v_successor_from <= v_now THEN
      UPDATE control.entitlement_snapshots s
         SET effective = s.successor, successor = NULL, successor_from = NULL, computed_at = v_now
       WHERE s.tenant_id = p_tenant_id;
      CONTINUE;
    END IF;
    EXIT WHEN v_successor IS NOT NULL OR v_staged >= p_limit;

    -- §72.2.1: the shape control.issue_quota_window validates; a malformed policy fails closed.
    v_policy := v_effective -> v_key;
    IF jsonb_typeof(v_policy) IS DISTINCT FROM 'object'
       OR jsonb_typeof(v_policy -> 'limit') IS DISTINCT FROM 'number'
       OR (v_policy ->> 'limit') !~ '^[0-9]+$'
       OR (v_policy ->> 'period') IS NULL
       OR (v_policy ->> 'period') NOT IN ('calendar_month', 'subscription_period')
       OR (v_policy ->> 'period_start') IS NULL OR (v_policy ->> 'period_end') IS NULL
       OR (v_policy ->> 'period_start') !~ v_rfc3339 OR (v_policy ->> 'period_end') !~ v_rfc3339 THEN
      RAISE EXCEPTION 'missing or invalid projected quota policy' USING ERRCODE = '22023';
    END IF;
    v_start := (v_policy ->> 'period_start')::timestamptz;
    v_end := (v_policy ->> 'period_end')::timestamptz;
    IF NOT isfinite(v_start) OR NOT isfinite(v_end) OR v_start >= v_end THEN
      RAISE EXCEPTION 'quota policy has an invalid period' USING ERRCODE = '22023';
    END IF;
    EXIT WHEN v_now < v_end - p_lead;

    -- ADR-0072 D-B: contiguous with the current period; `calendar_month` ends at the next UTC month start, a
    -- `subscription_period` lasts the configured interval.
    v_next := CASE v_policy ->> 'period'
                WHEN 'calendar_month' THEN date_trunc('month', v_end) + interval '1 month'
                ELSE v_end + p_subscription_period
              END;
    IF EXISTS (SELECT 1 FROM control.quota_windows w
                WHERE w.tenant_id = p_tenant_id AND w.entitlement_key = v_key
                  AND w.window_start < v_next AND w.window_end > v_end
                  AND (w.window_start, w.window_end) IS DISTINCT FROM (v_end, v_next)) THEN
      RAISE EXCEPTION 'overlapping quota period' USING ERRCODE = '23514';
    END IF;
    -- §72.2.1: the limit comes from the projected snapshot; an already issued identical window is kept as is.
    INSERT INTO control.quota_windows
      (tenant_id, entitlement_key, window_start, window_end, hard_limit, issued_snapshot_at)
    VALUES (p_tenant_id, v_key, v_end, v_next, (v_policy ->> 'limit')::bigint, v_computed_at)
    ON CONFLICT (tenant_id, entitlement_key, window_start) DO NOTHING;
    -- Microsecond RFC3339 so the parsed boundary equals the window boundary exactly.
    UPDATE control.entitlement_snapshots s
       SET successor = jsonb_set(s.effective, ARRAY[v_key], v_policy || jsonb_build_object(
             'period_start', to_char(v_end AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
             'period_end', to_char(v_next AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))),
           successor_from = v_end
     WHERE s.tenant_id = p_tenant_id;
    v_staged := v_staged + 1;
  END LOOP;

  RETURN QUERY
    SELECT v_staged,
           coalesce((SELECT max(w.window_end) FROM control.quota_windows w
                      WHERE w.tenant_id = p_tenant_id AND w.entitlement_key = v_key), v_now);
END;
$$;

ALTER FUNCTION control.renew_quota_period(uuid, text, interval, interval, integer) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION control.renew_quota_period(uuid, text, interval, interval, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.renew_quota_period(uuid, text, interval, interval, integer) TO role_maintenance;
