-- Return only stamps written by this statement so each gateway claim can be resolved independently.
CREATE FUNCTION control.api_key_touch_last_used_batch_rows(p_ids uuid[], p_interval_seconds integer)
RETURNS TABLE (api_key_id uuid, last_used_at timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_now timestamptz := statement_timestamp();
BEGIN
  IF p_ids IS NULL OR p_interval_seconds IS NULL OR p_interval_seconds < 60 THEN
    RAISE EXCEPTION 'invalid_credential_touch_batch' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
  UPDATE control.api_keys AS k
     SET last_used_at = v_now
   WHERE k.api_key_id = ANY(p_ids)
     AND (k.last_used_at IS NULL
          OR k.last_used_at <= v_now - make_interval(secs => p_interval_seconds))
  RETURNING k.api_key_id, k.last_used_at;
END;
$$;
ALTER FUNCTION control.api_key_touch_last_used_batch_rows(uuid[], integer) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION control.api_key_touch_last_used_batch_rows(uuid[], integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.api_key_touch_last_used_batch_rows(uuid[], integer) TO role_gateway;

-- Retain the count-returning door, with its existing owner and grants, for older gateways.
CREATE OR REPLACE FUNCTION control.api_key_touch_last_used_batch(p_ids uuid[], p_interval_seconds integer)
RETURNS bigint
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT count(*) FROM control.api_key_touch_last_used_batch_rows($1, $2);
$$;
