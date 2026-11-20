-- M02-10c / RFC 8252 §7.3: accept port variation only on an explicitly registered HTTP loopback literal.
-- Keep the same role_gateway-only door and store the request URI verbatim for token exchange.
-- The row lock prevents a concurrent registry update from changing the checked callback before code issuance.

CREATE OR REPLACE FUNCTION control.oauth_code_issue(
  p_code_hash bytea,
  p_client_id text,
  p_redirect_uri text,
  p_pkce_challenge text,
  p_resource text,
  p_user_id uuid,
  p_tenant_id uuid,
  p_workspace_id uuid,
  p_scopes text[],
  p_ttl_seconds integer
)
RETURNS timestamptz
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_expires_at timestamptz;
  v_requested text[];
  -- Captures the byte-exact host, numeric port and raw suffix. Only the port is ignored.
  v_loopback constant text := $re$\Ahttp://(localhost|127\.0\.0\.1|\[::1\])(?::([0-9]{1,5}))?([/?][^#[:space:][:cntrl:]\\]*)?\Z$re$;
BEGIN
  IF p_ttl_seconds <= 0 THEN
    RAISE EXCEPTION 'oauth code policy out of range' USING ERRCODE = '22023';
  END IF;

  v_requested := regexp_match(p_redirect_uri, v_loopback COLLATE "C");
  PERFORM 1 FROM control.oauth_client_registrations r
   WHERE r.client_id = p_client_id AND r.disabled_at IS NULL
     AND (p_redirect_uri COLLATE "C" = ANY (r.redirect_uris) OR (
         v_requested IS NOT NULL
         AND coalesce(v_requested[2]::integer, 80) BETWEEN 1 AND 65535
         AND EXISTS (
           SELECT FROM unnest(r.redirect_uris) AS registered(uri)
           CROSS JOIN LATERAL regexp_match(registered.uri, v_loopback COLLATE "C") AS matched(parts)
           WHERE matched.parts[1] COLLATE "C" = v_requested[1]
             AND matched.parts[3] COLLATE "C" IS NOT DISTINCT FROM v_requested[3]
             AND coalesce(matched.parts[2]::integer, 80) BETWEEN 1 AND 65535
         )
     ))
   FOR SHARE OF r;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  INSERT INTO control.oauth_authorization_codes
    (code_hash, client_id, redirect_uri, pkce_challenge, resource, user_id, tenant_id, workspace_id, scopes, expires_at)
  VALUES
    (p_code_hash, p_client_id, p_redirect_uri, p_pkce_challenge, p_resource, p_user_id, p_tenant_id, p_workspace_id,
     p_scopes, now() + make_interval(secs => p_ttl_seconds))
  RETURNING expires_at INTO v_expires_at;
  RETURN v_expires_at;
END;
$$;

-- The quota ignores expired and disabled rows without deleting registry or authorization history.
ALTER TABLE control.oauth_client_registrations
  ADD COLUMN dcr_source_tag bytea
  CHECK (dcr_source_tag IS NULL OR (kind = 'DCR' AND octet_length(dcr_source_tag) = 32));

CREATE INDEX oauth_grants_client_idx ON control.oauth_grants (client_id);
CREATE INDEX oauth_dcr_active_created_idx ON control.oauth_client_registrations (created_at)
  WHERE kind = 'DCR' AND disabled_at IS NULL;

CREATE FUNCTION control.oauth_dcr_register(
  p_client_id text,
  p_redirect_uris text[],
  p_metadata jsonb,
  p_source_tags bytea[],
  p_max_unused bigint,
  p_max_unused_per_ip bigint,
  p_unused_ttl_seconds integer
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_now timestamptz;
  v_occupied bigint;
  v_source_occupied bigint;
BEGIN
  IF coalesce(p_max_unused, 0) <= 0 OR coalesce(p_max_unused_per_ip, 0) <= 0
     OR coalesce(p_unused_ttl_seconds, 0) <= 0
     OR coalesce(octet_length(p_source_tags[1]), 0) <> 32 THEN
    RAISE EXCEPTION 'invalid OAuth registration quota' USING ERRCODE = '22023';
  END IF;

  -- The lock serializes counting and inserting, so gateways see the preceding committed admission.
  PERFORM pg_advisory_xact_lock(hashtextextended('oauth_dcr_register', 0));
  v_now := clock_timestamp();
  SELECT count(*), count(*) FILTER (WHERE occupied.dcr_source_tag = ANY(p_source_tags))
    INTO v_occupied, v_source_occupied
    FROM (
      SELECT r.dcr_source_tag FROM control.oauth_client_registrations r
      WHERE r.kind = 'DCR'
        AND r.disabled_at IS NULL
        AND r.created_at > v_now - make_interval(secs => p_unused_ttl_seconds)
        AND NOT EXISTS (SELECT FROM control.oauth_grants g WHERE g.client_id = r.client_id)
      LIMIT p_max_unused
    ) AS occupied;
  IF v_occupied >= p_max_unused OR v_source_occupied >= p_max_unused_per_ip THEN
    RETURN false;
  END IF;

  INSERT INTO control.oauth_client_registrations
    (client_id, kind, redirect_uris, metadata, dcr_source_tag, created_at)
  VALUES (p_client_id, 'DCR', p_redirect_uris, p_metadata, p_source_tags[1], v_now);
  RETURN true;
END;
$$;

ALTER FUNCTION control.oauth_dcr_register(text,text[],jsonb,bytea[],bigint,bigint,integer) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION control.oauth_dcr_register(text,text[],jsonb,bytea[],bigint,bigint,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.oauth_dcr_register(text,text[],jsonb,bytea[],bigint,bigint,integer) TO role_gateway;
