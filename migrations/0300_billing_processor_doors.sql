-- §71.3 / §76, M04-11a: owner doors; lead ruling 2026-10-29. No table privileges or snapshot writes.
CREATE UNIQUE INDEX subscription_events_provider_event_unique
  ON control.subscription_events (source_provider, source_event_id);

CREATE FUNCTION control.billing_inbox_claim(p_limit integer)
RETURNS SETOF control.billing_inbox
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  IF p_limit IS NULL OR p_limit <= 0 THEN
    RAISE EXCEPTION 'invalid claim limit' USING ERRCODE = '22023';
  END IF;
  -- ponytail: §71.3 claim seq scan grows with retained inbox history; add a partial index on received_at WHERE status='RECEIVED' when claim latency grows.
  RETURN QUERY SELECT i.* FROM control.billing_inbox i WHERE i.status = 'RECEIVED'
    ORDER BY i.received_at, i.provider, i.event_id LIMIT p_limit FOR UPDATE SKIP LOCKED;
END;
$$;

CREATE FUNCTION control.billing_inbox_settle(p_provider text, p_event_id text, p_status text, p_error_class text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  IF p_status IS NULL OR p_status NOT IN ('PROCESSED', 'FAILED')
     OR (p_status = 'FAILED' AND p_error_class IS NULL)
     OR (p_status = 'PROCESSED' AND p_error_class IS NOT NULL) THEN
    RAISE EXCEPTION 'invalid settlement' USING ERRCODE = '22023';
  END IF;
  UPDATE control.billing_inbox SET status = p_status, error_class = p_error_class, processed_at = clock_timestamp()
    WHERE provider = p_provider AND event_id = p_event_id AND status = 'RECEIVED';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'inbox is not RECEIVED' USING ERRCODE = '22023';
  END IF;
  RETURN true;
END;
$$;

CREATE FUNCTION control.billing_apply_subscription(
  p_tenant uuid, p_provider text, p_event_id text, p_subscription_ref text,
  p_plan_version uuid, p_free_plan_version uuid, p_state text,
  p_period_start timestamptz, p_period_end timestamptz, p_observed_at timestamptz
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_id uuid;
  v_old text;
  v_now timestamptz;
  v_template jsonb;
  v_paid boolean;
  v_version uuid;
BEGIN
  IF p_tenant IS NULL OR p_tenant = '00000000-0000-0000-0000-000000000000'::uuid
     OR p_tenant IS DISTINCT FROM NULLIF(current_setting('humaux.tenant_id', true), '')::uuid THEN
    RAISE EXCEPTION 'invalid billing scope' USING ERRCODE = '42501';
  END IF;
  IF p_provider IS NULL OR p_event_id IS NULL OR length(p_event_id) = 0
     OR p_subscription_ref IS NULL OR length(p_subscription_ref) = 0
     OR p_state IS NULL OR p_period_start IS NULL OR p_period_end IS NULL
     OR NOT isfinite(p_period_start) OR NOT isfinite(p_period_end) OR p_period_end <= p_period_start
     OR p_observed_at IS NULL OR NOT isfinite(p_observed_at) THEN
    RAISE EXCEPTION 'invalid billing application' USING ERRCODE = '22023';
  END IF;
  -- §71.3: serialize a provider event before any projection mutation; the UNIQUE key also crosses tenant RLS.
  PERFORM pg_advisory_xact_lock(hashtextextended('billing-event:' || p_provider || ':' || p_event_id, 0));
  IF EXISTS (SELECT 1 FROM control.subscription_events
              WHERE source_provider = p_provider AND source_event_id = p_event_id) THEN
    RETURN false;
  END IF;
  -- §76 / 0267: grants, recompute and quota renewal share this transaction lock.
  PERFORM pg_advisory_xact_lock(hashtextextended('quota-window:' || p_tenant::text || ':mcp.billable_operations.per_period', 0));
  v_now := clock_timestamp();
  v_paid := p_state IN ('ACTIVE', 'CANCEL_AT_PERIOD_END') AND p_period_end > v_now;
  v_version := CASE WHEN v_paid THEN p_plan_version ELSE p_free_plan_version END;
  SELECT entitlement_template INTO v_template FROM control.plan_versions WHERE plan_version_id = v_version;
  IF NOT FOUND OR p_plan_version IS NULL THEN
    RAISE EXCEPTION 'missing plan version' USING ERRCODE = '22023';
  END IF;
  SELECT subscription_id, state INTO v_id, v_old FROM control.subscriptions
    WHERE provider = p_provider AND provider_subscription_ref = p_subscription_ref FOR UPDATE;
  INSERT INTO control.subscriptions AS s
    (tenant_id, provider, provider_subscription_ref, plan_version_id, state, current_period_start, current_period_end)
  VALUES (p_tenant, p_provider, p_subscription_ref, p_plan_version, p_state, p_period_start, p_period_end)
  ON CONFLICT (provider, provider_subscription_ref) DO UPDATE
    SET plan_version_id = EXCLUDED.plan_version_id, state = EXCLUDED.state,
        current_period_start = EXCLUDED.current_period_start, current_period_end = EXCLUDED.current_period_end,
        updated_at = v_now
    WHERE s.tenant_id = p_tenant
  RETURNING subscription_id INTO v_id;
  IF v_id IS NULL THEN
    RAISE EXCEPTION 'subscription tenant mismatch' USING ERRCODE = '42501';
  END IF;
  INSERT INTO control.subscription_events
    (tenant_id, subscription_id, from_state, to_state, source_provider, source_event_id, observed_at)
  VALUES (p_tenant, v_id, v_old, p_state, p_provider, p_event_id, p_observed_at);
  -- D13(h): failed payment has no grace. Other sources remain the projector's input (§76).
  UPDATE control.entitlement_grants SET revoked_at = v_now,
      valid_until = CASE WHEN valid_from < v_now AND (valid_until IS NULL OR valid_until > v_now)
                         THEN v_now ELSE valid_until END
    WHERE tenant_id = p_tenant AND source = 'PLAN' AND revoked_at IS NULL;
  INSERT INTO control.entitlement_grants
    (tenant_id, source, source_ref_id, feature, value, valid_from, valid_until, priority)
  SELECT p_tenant, 'PLAN', v_version, e.key,
    CASE WHEN e.key = 'mcp.billable_operations.per_period' THEN e.value || jsonb_build_object(
      'period_start', to_char(p_period_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
      'period_end', to_char(p_period_end AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')) ELSE e.value END,
    v_now, CASE WHEN v_paid THEN p_period_end ELSE NULL END, 0
    FROM jsonb_each(v_template) e;
  RETURN true;
END;
$$;

ALTER FUNCTION control.billing_inbox_claim(integer) OWNER TO role_migration_owner;
ALTER FUNCTION control.billing_inbox_settle(text,text,text,text) OWNER TO role_migration_owner;
ALTER FUNCTION control.billing_apply_subscription(uuid,text,text,text,uuid,uuid,text,timestamptz,timestamptz,timestamptz) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION control.billing_inbox_claim(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.billing_inbox_settle(text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.billing_apply_subscription(uuid,text,text,text,uuid,uuid,text,timestamptz,timestamptz,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.billing_inbox_claim(integer) TO role_maintenance;
GRANT EXECUTE ON FUNCTION control.billing_inbox_settle(text,text,text,text) TO role_maintenance;
GRANT EXECUTE ON FUNCTION control.billing_apply_subscription(uuid,text,text,text,uuid,uuid,text,timestamptz,timestamptz,timestamptz) TO role_maintenance;
