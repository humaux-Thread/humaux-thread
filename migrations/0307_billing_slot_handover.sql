-- §71.3 / §76: narrow slot observation and atomic local handover.
CREATE FUNCTION control.billing_slot_observe(
  p_tenant uuid, p_provider text, p_event_id text, p_new_ref text,
  p_period_start timestamptz, p_period_end timestamptz
) RETURNS TABLE(replay boolean, old_id uuid, old_provider text, old_ref text, old_state text, reversed_b boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  IF p_tenant IS NULL OR p_tenant = '00000000-0000-0000-0000-000000000000'::uuid
     OR p_tenant IS DISTINCT FROM NULLIF(current_setting('humaux.tenant_id', true), '')::uuid THEN
    RAISE EXCEPTION 'invalid billing scope' USING ERRCODE = '42501';
  END IF;
  IF p_provider IS DISTINCT FROM 'creem' OR p_event_id IS NULL OR length(p_event_id) = 0
     OR p_new_ref IS NULL OR length(p_new_ref) = 0 OR p_period_start IS NULL OR p_period_end IS NULL
     OR NOT isfinite(p_period_start) OR NOT isfinite(p_period_end) OR p_period_end <= p_period_start THEN
    RAISE EXCEPTION 'invalid slot observation' USING ERRCODE = '22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('billing-event:' || p_provider || ':' || p_event_id, 0));
  PERFORM pg_advisory_xact_lock(hashtextextended('quota-window:' || p_tenant::text || ':mcp.billable_operations.per_period', 0));
  replay := EXISTS (SELECT 1 FROM control.subscription_events e
    WHERE e.source_provider = p_provider AND e.source_event_id = p_event_id);
  reversed_b := EXISTS (SELECT 1 FROM control.billing_payments p JOIN control.billing_inbox i
    ON i.provider = p.provider AND i.object_id = p.provider_txn_ref
    AND i.event_type = CASE p.kind WHEN 'REFUND' THEN 'refund.created' WHEN 'CHARGEBACK' THEN 'dispute.created' END
    WHERE p.tenant_id = p_tenant AND p.provider = p_provider AND p.kind IN ('REFUND','CHARGEBACK')
      AND p.period_start = p_period_start AND p.period_end = p_period_end
      AND coalesce(i.payload #>> '{object,subscription,id}',
        CASE WHEN jsonb_typeof(i.payload #> '{object,subscription}') = 'string' THEN i.payload #>> '{object,subscription}' END,
        i.payload #>> '{object,transaction,subscription,id}', i.payload #>> '{object,transaction,subscription}') = p_new_ref);
  SELECT s.subscription_id, s.provider, s.provider_subscription_ref, s.state
    INTO old_id, old_provider, old_ref, old_state FROM control.subscriptions s
    WHERE s.tenant_id = p_tenant AND s.state <> 'CANCELED' AND s.provider_subscription_ref <> p_new_ref;
  RETURN NEXT;
END;
$$;

CREATE FUNCTION control.billing_handover_subscription(
  p_tenant uuid, p_provider text, p_event_id text, p_old_id uuid, p_old_state text,
  p_new_ref text, p_plan_version uuid, p_free_plan_version uuid,
  p_period_start timestamptz, p_period_end timestamptz, p_observed_at timestamptz
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_slot record;
  v_old control.subscriptions%ROWTYPE;
  v_now timestamptz;
BEGIN
  SELECT * INTO v_slot FROM control.billing_slot_observe(p_tenant, p_provider, p_event_id, p_new_ref, p_period_start, p_period_end);
  IF p_old_id IS NULL OR p_old_state IS NULL OR p_plan_version IS NULL OR p_free_plan_version IS NULL
     OR p_observed_at IS NULL OR NOT isfinite(p_observed_at) THEN
    RAISE EXCEPTION 'invalid handover' USING ERRCODE = '22023';
  END IF;
  IF v_slot.replay THEN RETURN false; END IF;
  IF v_slot.reversed_b OR v_slot.old_id IS DISTINCT FROM p_old_id
     OR v_slot.old_provider IS DISTINCT FROM p_provider OR v_slot.old_state IS DISTINCT FROM p_old_state
     THEN
    RAISE EXCEPTION 'slot changed or ineligible' USING ERRCODE = '23505';
  END IF;
  SELECT * INTO v_old FROM control.subscriptions s WHERE s.tenant_id = p_tenant
    AND s.subscription_id = p_old_id FOR UPDATE;
  IF NOT FOUND OR v_old.state IS DISTINCT FROM p_old_state OR v_old.provider IS DISTINCT FROM p_provider
     OR v_old.provider_subscription_ref = p_new_ref THEN
    RAISE EXCEPTION 'slot changed' USING ERRCODE = '23505';
  END IF;
  v_now := clock_timestamp();
  UPDATE control.subscriptions SET state = 'CANCELED', updated_at = v_now
    WHERE tenant_id = p_tenant AND subscription_id = p_old_id;
  UPDATE control.entitlement_grants SET revoked_at = v_now,
    valid_until = CASE WHEN valid_from < v_now AND (valid_until IS NULL OR valid_until > v_now)
                       THEN v_now ELSE valid_until END
    WHERE tenant_id = p_tenant AND source = 'PLAN' AND source_ref_id = p_old_id AND revoked_at IS NULL;
  INSERT INTO control.subscription_events
    (tenant_id, subscription_id, from_state, to_state, source_provider, source_event_id, observed_at)
    VALUES (p_tenant, p_old_id, p_old_state, 'CANCELED', NULL, NULL, p_observed_at);
  RETURN control.billing_apply_subscription(p_tenant, p_provider, p_event_id, p_new_ref,
    p_plan_version, p_free_plan_version, 'ACTIVE', p_period_start, p_period_end, p_observed_at);
END;
$$;

ALTER FUNCTION control.billing_slot_observe(uuid,text,text,text,timestamptz,timestamptz) OWNER TO role_migration_owner;
ALTER FUNCTION control.billing_handover_subscription(uuid,text,text,uuid,text,text,uuid,uuid,timestamptz,timestamptz,timestamptz) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION control.billing_slot_observe(uuid,text,text,text,timestamptz,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.billing_handover_subscription(uuid,text,text,uuid,text,text,uuid,uuid,timestamptz,timestamptz,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.billing_slot_observe(uuid,text,text,text,timestamptz,timestamptz) TO role_maintenance;
GRANT EXECUTE ON FUNCTION control.billing_handover_subscription(uuid,text,text,uuid,text,text,uuid,uuid,timestamptz,timestamptz,timestamptz) TO role_maintenance;
COMMENT ON TABLE control.subscription_events IS
  'M04 D7: append-only applied subscription state facts. A non-NULL source pair identifies the originating provider event. '
  'A NULL pair records reconciliation or a same-transaction processor-derived local handover termination; '
  'a scheduled local early termination does not assert a provider canceled observation.';
