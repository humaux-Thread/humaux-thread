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

-- DCR abuse budget. Code exchange releases a slot by creating a grant; refresh/revocation do not reopen it.
CREATE INDEX oauth_grants_client_idx ON control.oauth_grants (client_id);

CREATE FUNCTION control.oauth_dcr_register(
  p_client_id text,
  p_redirect_uris text[],
  p_metadata jsonb,
  p_max_unused bigint
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF p_max_unused IS NULL OR p_max_unused <= 0 THEN
    RAISE EXCEPTION 'invalid OAuth registration quota' USING ERRCODE = '22023';
  END IF;

  -- Serialize across gateway callers. The following statement sees the prior insertion after an advisory-lock wait.
  PERFORM pg_advisory_xact_lock(hashtextextended('oauth_dcr_register', 0));
  IF (SELECT count(*) FROM (
          SELECT FROM control.oauth_client_registrations r
          WHERE r.kind = 'DCR'
            AND NOT EXISTS (SELECT FROM control.oauth_grants g WHERE g.client_id = r.client_id)
          LIMIT p_max_unused
      ) AS unused_clients) >= p_max_unused THEN
    RETURN false;
  END IF;

  INSERT INTO control.oauth_client_registrations (client_id, kind, redirect_uris, metadata)
  VALUES (p_client_id, 'DCR', p_redirect_uris, p_metadata);
  RETURN true;
END;
$$;

ALTER FUNCTION control.oauth_dcr_register(text,text[],jsonb,bigint) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION control.oauth_dcr_register(text,text[],jsonb,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.oauth_dcr_register(text,text[],jsonb,bigint) TO role_gateway;
