-- M02-10b, Baseline §33 / §73.6: bounded consent facts and client-bound RFC 7009 revocation.
CREATE FUNCTION control.oauth_consent_tenants(p_user_id uuid)
RETURNS SETOF uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
AS $$
  SELECT m.tenant_id
    FROM control.memberships m
    JOIN control.users u ON u.user_id = m.user_id
    JOIN control.tenants t ON t.tenant_id = m.tenant_id
   WHERE m.user_id = p_user_id AND m.state = 'ACTIVE'
     AND u.state = 'ACTIVE' AND t.state = 'ACTIVE'
   ORDER BY m.tenant_id
   LIMIT 2;
$$;

CREATE FUNCTION control.oauth_refresh_grant(p_hash bytea, p_client_id text)
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
AS $$
  SELECT g.grant_id
    FROM control.oauth_refresh_tokens r
    JOIN control.oauth_grants g ON g.grant_id = r.grant_id
    JOIN control.oauth_client_registrations c ON c.client_id = g.client_id
   WHERE r.token_hash = p_hash AND g.client_id = p_client_id AND c.disabled_at IS NULL;
$$;

ALTER FUNCTION control.oauth_consent_tenants(uuid) OWNER TO role_migration_owner;
ALTER FUNCTION control.oauth_refresh_grant(bytea, text) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION control.oauth_consent_tenants(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.oauth_refresh_grant(bytea, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.oauth_consent_tenants(uuid) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.oauth_refresh_grant(bytea, text) TO role_gateway;
