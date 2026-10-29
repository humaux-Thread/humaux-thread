-- §71.3 / §76, M04-11b: append-only money; 0300 remains the subscription/grant writer.
CREATE FUNCTION control.billing_append_payment(
  p_tenant uuid, p_provider text, p_event_id text, p_subscription_ref text, p_plan_version uuid, p_free_plan_version uuid,
  p_txn_ref text, p_kind text, p_amount bigint, p_currency text,
  p_period_start timestamptz, p_period_end timestamptz,
  p_current_start timestamptz, p_current_end timestamptz, p_occurred_at timestamptz
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  IF p_tenant IS NULL OR p_tenant = '00000000-0000-0000-0000-000000000000'::uuid
     OR p_tenant IS DISTINCT FROM NULLIF(current_setting('humaux.tenant_id', true), '')::uuid THEN
    RAISE EXCEPTION 'invalid billing scope' USING ERRCODE = '42501';
  END IF;
  IF p_event_id IS NULL OR length(p_event_id) = 0 OR p_subscription_ref IS NULL OR length(p_subscription_ref) = 0
     OR p_txn_ref IS NULL OR length(p_txn_ref) = 0 OR p_period_start IS NULL OR p_period_end IS NULL
     OR NOT isfinite(p_period_start) OR NOT isfinite(p_period_end) OR p_period_end <= p_period_start
     OR p_current_start IS NULL OR p_current_end IS NULL OR p_plan_version IS NULL
     OR NOT isfinite(p_current_start) OR NOT isfinite(p_current_end) OR p_current_end <= p_current_start
     OR p_occurred_at IS NULL OR NOT isfinite(p_occurred_at) THEN
    RAISE EXCEPTION 'invalid payment facts' USING ERRCODE = '22023';
  END IF;
  -- §76: lock order matches 0300 (event, quota, subscription), including concurrent reversals.
  PERFORM pg_advisory_xact_lock(hashtextextended('billing-event:' || p_provider || ':' || p_event_id, 0));
  PERFORM pg_advisory_xact_lock(hashtextextended('quota-window:' || p_tenant::text || ':mcp.billable_operations.per_period', 0));
  INSERT INTO control.billing_payments
    (tenant_id, provider, provider_txn_ref, kind, amount_cents, currency, period_start, period_end, occurred_at)
  VALUES (p_tenant, p_provider, p_txn_ref, p_kind, p_amount, p_currency, p_period_start, p_period_end, p_occurred_at)
  ON CONFLICT (provider, provider_txn_ref, kind) DO NOTHING;
  IF NOT FOUND THEN
    RETURN false;
  END IF;
  -- D13b / §71.3: fetched current-period facts also initialize a subscription when its reversal arrives first.
  IF p_kind IN ('REFUND', 'CHARGEBACK')
     AND p_current_start = p_period_start AND p_current_end = p_period_end THEN
    PERFORM control.billing_apply_subscription(p_tenant, p_provider, p_event_id, p_subscription_ref,
      p_plan_version, p_free_plan_version, 'CANCELED', p_period_start, p_period_end, p_occurred_at);
  END IF;
  RETURN true;
END;
$$;
ALTER FUNCTION control.billing_append_payment(uuid,text,text,text,uuid,uuid,text,text,bigint,text,timestamptz,timestamptz,timestamptz,timestamptz,timestamptz) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION control.billing_append_payment(uuid,text,text,text,uuid,uuid,text,text,bigint,text,timestamptz,timestamptz,timestamptz,timestamptz,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.billing_append_payment(uuid,text,text,text,uuid,uuid,text,text,bigint,text,timestamptz,timestamptz,timestamptz,timestamptz,timestamptz) TO role_maintenance;
