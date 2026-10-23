-- §46 forward-fix (EXPAND_CONTRACT, M02-8): OAuth 2.1 Authorization Server persistence (M02 D3, D4, D5; Baseline §6.2.1, §73.5,
-- §73.6, §77, §78.2). Four new control tables and nine owner SECURITY DEFINER doors; no existing table or row is touched.
--
--   control.oauth_client_registrations  one row per client_id; kind STATIC | DCR | CIMD | LEGACY (D5), allowed redirect URIs.
--   control.oauth_authorization_codes   one-time code, stored as a SHA-256 digest only; single use through used_at.
--   control.oauth_grants                one row per user/client/resource consent; revoked_at + the two epoch snapshots are
--                                       what every bearer call reads (D3).
--   control.oauth_refresh_tokens        opaque refresh token, stored as a SHA-256 digest only; single-use rotation inside a
--                                       family, at most one ACTIVE member per family (D4).
--
-- Raw codes and refresh tokens never reach the database: every door takes the digest. No access-token table exists (D3).
--
-- Least privilege (§6.2.1, SEC-1 / M02 D11): the four tables take 0011's `control.*` domain default (SELECT for every
-- runtime role), so this migration revokes it again from PUBLIC and from every non-owner role, role_gateway and
-- role_maintenance included. No runtime role holds any privilege on any of them; maintenance::rls_check names them in
-- NAMED_NO_NON_OWNER_GRANTS. The nine doors are the whole read and write path, EXECUTE role_gateway only, PUBLIC and every
-- other role refused, search_path = pg_catalog as in 0266.
--
-- RLS: codes and grants carry tenant_id, so §62 applies — ENABLE + FORCE + the tenant policy. The token endpoint has no
-- tenant GUC, so the doors run as the owner and each of the two tables admits that owner explicitly, as 0112 does for
-- control.api_keys. The refresh-token table carries no tenant_id and is reached through its grant.
--
-- Doors (all VOLATILE except the two lookups):
--   oauth_client_register / oauth_client_lookup
--   oauth_code_issue    stores a code for a live client whose redirect_uri is registered; NULL otherwise.
--   oauth_code_consume  one conditional UPDATE ... WHERE used_at IS NULL AND expires_at > now() ... RETURNING: of two
--                       concurrent exchanges of one code the loser re-evaluates the predicate after the winner commits and
--                       updates nothing. PKCE, client and resource comparison belong to the caller (M02-9).
--   oauth_grant_issue   creates the grant and its first refresh token in one statement sequence; the epoch snapshots are
--                       read here from the live user and tenant rows, never taken from the caller.
--   oauth_grant_lookup  the grant plus the live epochs, one indexed read per bearer call; the verdict is the caller's.
--   oauth_grant_revoke / oauth_refresh_family_revoke
--                       revoke the grant and every ACTIVE refresh token of it; ROTATED rows stay so a replay is still
--                       recognised as reuse.
--   oauth_refresh_rotate
--                       ROTATED when the presented token was ACTIVE, unexpired and its grant live (the old row becomes
--                       ROTATED and the next one is inserted in the same family); REUSE_DETECTED when it was already
--                       ROTATED (family and grant revoked, §D4); REJECTED otherwise.
-- Rotation and revocation of one grant serialize on a per-grant advisory lock, so a rotation cannot insert a live token under
-- a grant a concurrent revoke has just closed.
--
-- TTLs and the grant ceiling are arguments, never literals: the caller passes the §78.1 policy values.

CREATE TABLE control.oauth_client_registrations (
  client_id       text        PRIMARY KEY CHECK (length(client_id) > 0),
  kind            text        NOT NULL CHECK (kind IN ('STATIC', 'DCR', 'CIMD', 'LEGACY')),
  redirect_uris   text[]      NOT NULL CHECK (cardinality(redirect_uris) > 0),
  -- 8 KiB is the CIMD document bound of M02 D5, kept here so no registration path can store more.
  metadata        jsonb       NOT NULL DEFAULT '{}'::jsonb
                  CHECK (jsonb_typeof(metadata) = 'object' AND octet_length(metadata::text) <= 8192),
  cimd_fetched_at timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  disabled_at     timestamptz
);

CREATE TABLE control.oauth_authorization_codes (
  code_hash       bytea       PRIMARY KEY CHECK (octet_length(code_hash) = 32),
  client_id       text        NOT NULL REFERENCES control.oauth_client_registrations(client_id),
  redirect_uri    text        NOT NULL,
  pkce_challenge  text        NOT NULL CHECK (length(pkce_challenge) > 0),
  resource        text        NOT NULL,
  user_id         uuid        NOT NULL REFERENCES control.users(user_id),
  tenant_id       uuid        NOT NULL REFERENCES control.tenants(tenant_id),
  workspace_id    uuid        REFERENCES control.workspaces(workspace_id),
  scopes          text[]      NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL,
  used_at         timestamptz,
  CHECK (expires_at > created_at)
);

CREATE TABLE control.oauth_grants (
  grant_id              uuid        PRIMARY KEY DEFAULT uuidv7(),
  user_id               uuid        NOT NULL REFERENCES control.users(user_id),
  tenant_id             uuid        NOT NULL REFERENCES control.tenants(tenant_id),
  workspace_id          uuid        REFERENCES control.workspaces(workspace_id),
  client_id             text        NOT NULL REFERENCES control.oauth_client_registrations(client_id),
  resource              text        NOT NULL,
  scopes                text[]      NOT NULL,
  status                text        NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED')),
  issued_at             timestamptz NOT NULL DEFAULT now(),
  grant_max_expires_at  timestamptz NOT NULL,
  revoked_at            timestamptz,
  revoke_reason         text        CHECK (revoke_reason IN ('USER_REQUEST', 'REFRESH_REUSE', 'SECURITY_EPOCH', 'OPERATOR')),
  user_epoch_snapshot   bigint      NOT NULL,
  tenant_epoch_snapshot bigint      NOT NULL,
  last_used_at          timestamptz,
  CHECK (grant_max_expires_at > issued_at),
  CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL)),
  CHECK ((revoke_reason IS NOT NULL) = (revoked_at IS NOT NULL))
);

CREATE TABLE control.oauth_refresh_tokens (
  token_hash        bytea       PRIMARY KEY CHECK (octet_length(token_hash) = 32),
  family_id         uuid        NOT NULL,
  grant_id          uuid        NOT NULL REFERENCES control.oauth_grants(grant_id),
  status            text        NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'ROTATED', 'REVOKED')),
  issued_at         timestamptz NOT NULL DEFAULT now(),
  expires_at        timestamptz NOT NULL,
  rotated_at        timestamptz,
  reuse_detected_at timestamptz,
  CHECK (expires_at > issued_at),
  CHECK ((status = 'ROTATED') = (rotated_at IS NOT NULL))
);

CREATE INDEX oauth_authorization_codes_expires_idx ON control.oauth_authorization_codes (expires_at);
CREATE INDEX oauth_grants_user_idx ON control.oauth_grants (user_id);
CREATE INDEX oauth_refresh_tokens_grant_idx ON control.oauth_refresh_tokens (grant_id);
CREATE UNIQUE INDEX oauth_refresh_tokens_one_active_per_family_idx
  ON control.oauth_refresh_tokens (family_id) WHERE status = 'ACTIVE';

ALTER TABLE control.oauth_client_registrations OWNER TO role_migration_owner;
ALTER TABLE control.oauth_authorization_codes OWNER TO role_migration_owner;
ALTER TABLE control.oauth_grants OWNER TO role_migration_owner;
ALTER TABLE control.oauth_refresh_tokens OWNER TO role_migration_owner;

REVOKE ALL ON TABLE
  control.oauth_client_registrations,
  control.oauth_authorization_codes,
  control.oauth_grants,
  control.oauth_refresh_tokens
FROM
  PUBLIC,
  role_private_worker,
  role_consolidation_worker,
  role_public_worker,
  role_retrieval_worker,
  role_batch_issuer,
  role_admin,
  role_gateway,
  role_maintenance,
  role_health_reader;

ALTER TABLE control.oauth_authorization_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE control.oauth_authorization_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY oauth_authorization_codes_tenant_isolation ON control.oauth_authorization_codes
USING (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid)
WITH CHECK (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid);
CREATE POLICY oauth_authorization_codes_owner ON control.oauth_authorization_codes
  FOR ALL TO role_migration_owner
  USING (current_user = 'role_migration_owner')
  WITH CHECK (current_user = 'role_migration_owner');

ALTER TABLE control.oauth_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE control.oauth_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY oauth_grants_tenant_isolation ON control.oauth_grants
USING (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid)
WITH CHECK (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid);
CREATE POLICY oauth_grants_owner ON control.oauth_grants
  FOR ALL TO role_migration_owner
  USING (current_user = 'role_migration_owner')
  WITH CHECK (current_user = 'role_migration_owner');

COMMENT ON TABLE control.oauth_client_registrations IS
  'M02-8 / D5: OAuth client registry. kind is a closed set mirrored by adapters::oauth_repo::ClientKind (§78.2). No runtime role holds a privilege; doors only.';
COMMENT ON TABLE control.oauth_authorization_codes IS
  'M02-8 / D3: one-time authorization code, SHA-256 digest only, single use through used_at. No runtime role holds a privilege; doors only.';
COMMENT ON TABLE control.oauth_grants IS
  'M02-8 / D3, D4: one consent. status and revoke_reason are closed sets mirrored by adapters::oauth_repo (§78.2). No runtime role holds a privilege; doors only.';
COMMENT ON TABLE control.oauth_refresh_tokens IS
  'M02-8 / D4: opaque refresh token, SHA-256 digest only, single-use rotation inside a family. status is a closed set mirrored by adapters::oauth_repo::RefreshTokenStatus (§78.2). No runtime role holds a privilege; doors only.';

CREATE FUNCTION control.oauth_client_register(
  p_client_id text,
  p_kind text,
  p_redirect_uris text[],
  p_metadata jsonb,
  p_cimd_fetched_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_rows integer;
BEGIN
  INSERT INTO control.oauth_client_registrations AS r (client_id, kind, redirect_uris, metadata, cimd_fetched_at)
  VALUES (p_client_id, p_kind, p_redirect_uris, p_metadata, p_cimd_fetched_at)
  ON CONFLICT (client_id) DO UPDATE
     SET redirect_uris = EXCLUDED.redirect_uris,
         metadata = EXCLUDED.metadata,
         cimd_fetched_at = EXCLUDED.cimd_fetched_at
   WHERE r.kind = EXCLUDED.kind AND r.disabled_at IS NULL;
  GET DIAGNOSTICS v_rows = ROW_COUNT;
  RETURN v_rows = 1;
END;
$$;

CREATE FUNCTION control.oauth_client_lookup(p_client_id text)
RETURNS TABLE (
  out_kind text,
  out_redirect_uris text[],
  out_metadata jsonb,
  out_cimd_fetched_at timestamptz,
  out_disabled_at timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT r.kind, r.redirect_uris, r.metadata, r.cimd_fetched_at, r.disabled_at
    FROM control.oauth_client_registrations r
   WHERE r.client_id = p_client_id;
$$;

CREATE FUNCTION control.oauth_code_issue(
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
BEGIN
  IF p_ttl_seconds <= 0 THEN
    RAISE EXCEPTION 'oauth code policy out of range' USING ERRCODE = '22023';
  END IF;

  PERFORM 1 FROM control.oauth_client_registrations r
   WHERE r.client_id = p_client_id AND r.disabled_at IS NULL AND p_redirect_uri = ANY (r.redirect_uris);
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

CREATE FUNCTION control.oauth_code_consume(p_code_hash bytea)
RETURNS TABLE (
  out_client_id text,
  out_redirect_uri text,
  out_pkce_challenge text,
  out_resource text,
  out_user_id uuid,
  out_tenant_id uuid,
  out_workspace_id uuid,
  out_scopes text[]
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  UPDATE control.oauth_authorization_codes c
     SET used_at = now()
   WHERE c.code_hash = p_code_hash
     AND c.used_at IS NULL
     AND c.expires_at > now()
  RETURNING c.client_id, c.redirect_uri, c.pkce_challenge, c.resource, c.user_id, c.tenant_id, c.workspace_id, c.scopes;
$$;

CREATE FUNCTION control.oauth_grant_issue(
  p_user_id uuid,
  p_tenant_id uuid,
  p_workspace_id uuid,
  p_client_id text,
  p_resource text,
  p_scopes text[],
  p_refresh_hash bytea,
  p_refresh_ttl_seconds integer,
  p_grant_max_ttl_seconds integer
)
RETURNS TABLE (
  out_grant_id uuid,
  out_family_id uuid,
  out_refresh_expires_at timestamptz,
  out_grant_max_expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_user_epoch bigint;
  v_tenant_epoch bigint;
  v_grant_id uuid;
  v_max timestamptz;
  v_family uuid := gen_random_uuid();
  v_refresh_expires timestamptz;
BEGIN
  IF p_refresh_ttl_seconds <= 0 OR p_grant_max_ttl_seconds <= 0 THEN
    RAISE EXCEPTION 'oauth grant policy out of range' USING ERRCODE = '22023';
  END IF;

  PERFORM 1 FROM control.oauth_client_registrations r WHERE r.client_id = p_client_id AND r.disabled_at IS NULL;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  SELECT u.security_epoch INTO v_user_epoch FROM control.users u WHERE u.user_id = p_user_id AND u.state = 'ACTIVE';
  IF NOT FOUND THEN
    RETURN;
  END IF;
  SELECT t.security_epoch INTO v_tenant_epoch FROM control.tenants t WHERE t.tenant_id = p_tenant_id AND t.state = 'ACTIVE';
  IF NOT FOUND THEN
    RETURN;
  END IF;

  INSERT INTO control.oauth_grants
    (user_id, tenant_id, workspace_id, client_id, resource, scopes, grant_max_expires_at,
     user_epoch_snapshot, tenant_epoch_snapshot)
  VALUES
    (p_user_id, p_tenant_id, p_workspace_id, p_client_id, p_resource, p_scopes,
     now() + make_interval(secs => p_grant_max_ttl_seconds), v_user_epoch, v_tenant_epoch)
  RETURNING grant_id, grant_max_expires_at INTO v_grant_id, v_max;

  v_refresh_expires := least(now() + make_interval(secs => p_refresh_ttl_seconds), v_max);
  INSERT INTO control.oauth_refresh_tokens (token_hash, family_id, grant_id, expires_at)
  VALUES (p_refresh_hash, v_family, v_grant_id, v_refresh_expires);

  RETURN QUERY SELECT v_grant_id, v_family, v_refresh_expires, v_max;
END;
$$;

CREATE FUNCTION control.oauth_grant_lookup(p_grant_id uuid)
RETURNS TABLE (
  out_user_id uuid,
  out_tenant_id uuid,
  out_workspace_id uuid,
  out_client_id text,
  out_resource text,
  out_scopes text[],
  out_status text,
  out_issued_at timestamptz,
  out_grant_max_expires_at timestamptz,
  out_revoked_at timestamptz,
  out_user_epoch_snapshot bigint,
  out_tenant_epoch_snapshot bigint,
  out_live_user_epoch bigint,
  out_live_tenant_epoch bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT g.user_id, g.tenant_id, g.workspace_id, g.client_id, g.resource, g.scopes, g.status, g.issued_at,
         g.grant_max_expires_at, g.revoked_at, g.user_epoch_snapshot, g.tenant_epoch_snapshot,
         u.security_epoch, t.security_epoch
    FROM control.oauth_grants g
    JOIN control.users u ON u.user_id = g.user_id
    JOIN control.tenants t ON t.tenant_id = g.tenant_id
   WHERE g.grant_id = p_grant_id;
$$;

CREATE FUNCTION control.oauth_grant_revoke(p_grant_id uuid, p_reason text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_rows integer;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('oauth_grant:' || p_grant_id::text, 0));

  UPDATE control.oauth_grants g
     SET status = 'REVOKED', revoked_at = now(), revoke_reason = p_reason
   WHERE g.grant_id = p_grant_id AND g.status = 'ACTIVE';
  GET DIAGNOSTICS v_rows = ROW_COUNT;

  UPDATE control.oauth_refresh_tokens t SET status = 'REVOKED'
   WHERE t.grant_id = p_grant_id AND t.status = 'ACTIVE';

  RETURN v_rows = 1;
END;
$$;

CREATE FUNCTION control.oauth_refresh_family_revoke(p_family_id uuid, p_reason text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_grant_id uuid;
BEGIN
  SELECT t.grant_id INTO v_grant_id FROM control.oauth_refresh_tokens t WHERE t.family_id = p_family_id LIMIT 1;
  IF NOT FOUND THEN
    RETURN false;
  END IF;
  RETURN control.oauth_grant_revoke(v_grant_id, p_reason);
END;
$$;

CREATE FUNCTION control.oauth_refresh_rotate(p_old_hash bytea, p_new_hash bytea, p_ttl_seconds integer)
RETURNS TABLE (
  out_outcome text,
  out_grant_id uuid,
  out_family_id uuid,
  out_expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_grant_id uuid;
  v_family uuid;
  v_status text;
  v_max timestamptz;
  v_expires timestamptz;
BEGIN
  IF p_ttl_seconds <= 0 THEN
    RAISE EXCEPTION 'oauth refresh policy out of range' USING ERRCODE = '22023';
  END IF;

  SELECT t.grant_id INTO v_grant_id FROM control.oauth_refresh_tokens t WHERE t.token_hash = p_old_hash;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'REJECTED'::text, NULL::uuid, NULL::uuid, NULL::timestamptz;
    RETURN;
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended('oauth_grant:' || v_grant_id::text, 0));

  UPDATE control.oauth_refresh_tokens t
     SET status = 'ROTATED', rotated_at = now()
    FROM control.oauth_grants g
   WHERE t.token_hash = p_old_hash
     AND t.status = 'ACTIVE'
     AND t.expires_at > now()
     AND g.grant_id = t.grant_id
     AND g.status = 'ACTIVE'
     AND g.grant_max_expires_at > now()
  RETURNING t.family_id, g.grant_max_expires_at INTO v_family, v_max;

  IF FOUND THEN
    v_expires := least(now() + make_interval(secs => p_ttl_seconds), v_max);
    INSERT INTO control.oauth_refresh_tokens (token_hash, family_id, grant_id, expires_at)
    VALUES (p_new_hash, v_family, v_grant_id, v_expires);
    RETURN QUERY SELECT 'ROTATED'::text, v_grant_id, v_family, v_expires;
    RETURN;
  END IF;

  -- The lock above ordered us after any concurrent rotation of this grant, so this read sees its commit.
  SELECT t.status, t.family_id INTO v_status, v_family
    FROM control.oauth_refresh_tokens t WHERE t.token_hash = p_old_hash;
  IF v_status = 'ROTATED' THEN
    UPDATE control.oauth_refresh_tokens t
       SET reuse_detected_at = coalesce(t.reuse_detected_at, now())
     WHERE t.token_hash = p_old_hash;
    PERFORM control.oauth_grant_revoke(v_grant_id, 'REFRESH_REUSE');
    RETURN QUERY SELECT 'REUSE_DETECTED'::text, v_grant_id, v_family, NULL::timestamptz;
    RETURN;
  END IF;

  RETURN QUERY SELECT 'REJECTED'::text, NULL::uuid, NULL::uuid, NULL::timestamptz;
END;
$$;

ALTER FUNCTION control.oauth_client_register(text, text, text[], jsonb, timestamptz) OWNER TO role_migration_owner;
ALTER FUNCTION control.oauth_client_lookup(text) OWNER TO role_migration_owner;
ALTER FUNCTION control.oauth_code_issue(bytea, text, text, text, text, uuid, uuid, uuid, text[], integer) OWNER TO role_migration_owner;
ALTER FUNCTION control.oauth_code_consume(bytea) OWNER TO role_migration_owner;
ALTER FUNCTION control.oauth_grant_issue(uuid, uuid, uuid, text, text, text[], bytea, integer, integer) OWNER TO role_migration_owner;
ALTER FUNCTION control.oauth_grant_lookup(uuid) OWNER TO role_migration_owner;
ALTER FUNCTION control.oauth_grant_revoke(uuid, text) OWNER TO role_migration_owner;
ALTER FUNCTION control.oauth_refresh_family_revoke(uuid, text) OWNER TO role_migration_owner;
ALTER FUNCTION control.oauth_refresh_rotate(bytea, bytea, integer) OWNER TO role_migration_owner;

REVOKE ALL ON FUNCTION control.oauth_client_register(text, text, text[], jsonb, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.oauth_client_lookup(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.oauth_code_issue(bytea, text, text, text, text, uuid, uuid, uuid, text[], integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.oauth_code_consume(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.oauth_grant_issue(uuid, uuid, uuid, text, text, text[], bytea, integer, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.oauth_grant_lookup(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.oauth_grant_revoke(uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.oauth_refresh_family_revoke(uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.oauth_refresh_rotate(bytea, bytea, integer) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION control.oauth_client_register(text, text, text[], jsonb, timestamptz) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.oauth_client_lookup(text) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.oauth_code_issue(bytea, text, text, text, text, uuid, uuid, uuid, text[], integer) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.oauth_code_consume(bytea) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.oauth_grant_issue(uuid, uuid, uuid, text, text, text[], bytea, integer, integer) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.oauth_grant_lookup(uuid) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.oauth_grant_revoke(uuid, text) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.oauth_refresh_family_revoke(uuid, text) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.oauth_refresh_rotate(bytea, bytea, integer) TO role_gateway;

COMMENT ON FUNCTION control.oauth_code_consume(bytea) IS
  'M02-8 / D3: the single-use UPDATE ... WHERE used_at IS NULL ... RETURNING; a row only for the one caller that consumed a live code.';
COMMENT ON FUNCTION control.oauth_refresh_rotate(bytea, bytea, integer) IS
  'M02-8 / D4: ROTATED, REUSE_DETECTED (family and grant revoked) or REJECTED; the caller commits in every case.';
COMMENT ON FUNCTION control.oauth_grant_revoke(uuid, text) IS
  'M02-8 / D4: revokes the grant and every ACTIVE refresh token of it; true only for the call that closed an ACTIVE grant.';
