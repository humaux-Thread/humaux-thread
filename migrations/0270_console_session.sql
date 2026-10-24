-- §46 forward-fix (EXPAND_CONTRACT, M02-6): the console session (M02 D6, §73.6, §74.4). No new table and no new grant:
--   control.sessions  already holds token_hash (0040, bytea UNIQUE NOT NULL), session_epoch, expires_at, last_seen_at and
--                     revoked_at, and 0260 left role_gateway and role_maintenance SELECT only. token_hash is the SHA-256 of
--                     the 32-byte cookie secret (application::session::SecretDigest); the secret itself is never stored.
--
-- Four owner SECURITY DEFINER doors are the whole write path, EXECUTE role_gateway only, PUBLIC and every other role refused:
--   control.session_issue   one INSERT for a loginable user, pinning session_epoch to the user's security_epoch read under
--                           FOR SHARE, so a concurrent bump_user_security_epoch either precedes the snapshot or waits for it.
--   control.session_lookup  read-only: the row by digest joined with the user's CURRENT security_epoch, plus the database
--                           clock, so expiry and idle are judged on one clock. The verdict (epoch, expiry, idle, revoked)
--                           is application::session::verify, never SQL.
--   control.session_touch   last_seen_at = now(), only on a row that is unrevoked, unexpired and inside its idle window.
--   control.session_revoke  revoked_at = now(), idempotent.
--
-- TTLs are arguments, never literals: the caller passes the §78.1 policy values (AuthConfig::session_ttl / session_idle_ttl).
-- Nothing here records an auth_events row: the SESSION_CREATED event type is not in the auth_events CHECK list yet.

CREATE FUNCTION control.session_issue(p_user_id uuid, p_token_hash bytea, p_ttl_seconds integer)
RETURNS TABLE (out_session_id uuid, out_expires_at_unix double precision)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_epoch bigint;
  v_session_id uuid;
  v_expires_at timestamptz;
BEGIN
  IF p_ttl_seconds <= 0 OR octet_length(p_token_hash) <> 32 THEN
    RAISE EXCEPTION 'session policy or digest out of range' USING ERRCODE = '22023';
  END IF;

  SELECT u.security_epoch INTO v_epoch
    FROM control.users u
   WHERE u.user_id = p_user_id
     AND u.state IN ('PENDING_VERIFICATION', 'ACTIVE')
     FOR SHARE OF u;
  IF NOT FOUND THEN
    RETURN;
  END IF;

  INSERT INTO control.sessions (user_id, session_epoch, expires_at, token_hash)
  VALUES (p_user_id, v_epoch, now() + make_interval(secs => p_ttl_seconds), p_token_hash)
  RETURNING session_id, expires_at INTO v_session_id, v_expires_at;

  RETURN QUERY SELECT v_session_id, extract(epoch FROM v_expires_at)::double precision;
END;
$$;

CREATE FUNCTION control.session_lookup(p_token_hash bytea)
RETURNS TABLE (
  out_session_id uuid,
  out_user_id uuid,
  out_token_hash bytea,
  out_session_epoch bigint,
  out_current_epoch bigint,
  out_expires_at_unix double precision,
  out_last_seen_at_unix double precision,
  out_revoked_at_unix double precision,
  out_db_now_unix double precision
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT s.session_id, s.user_id, s.token_hash, s.session_epoch, u.security_epoch,
         extract(epoch FROM s.expires_at)::double precision,
         extract(epoch FROM s.last_seen_at)::double precision,
         extract(epoch FROM s.revoked_at)::double precision,
         extract(epoch FROM now())::double precision
    FROM control.sessions s
    JOIN control.users u ON u.user_id = s.user_id
   WHERE s.token_hash = p_token_hash
     AND u.state IN ('PENDING_VERIFICATION', 'ACTIVE');
$$;

CREATE FUNCTION control.session_touch(p_session_id uuid, p_idle_seconds integer)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF p_idle_seconds <= 0 THEN
    RAISE EXCEPTION 'session idle policy out of range' USING ERRCODE = '22023';
  END IF;
  UPDATE control.sessions s SET last_seen_at = now()
   WHERE s.session_id = p_session_id
     AND s.revoked_at IS NULL
     AND s.expires_at > now()
     AND s.last_seen_at > now() - make_interval(secs => p_idle_seconds);
  RETURN FOUND;
END;
$$;

CREATE FUNCTION control.session_revoke(p_session_id uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  UPDATE control.sessions s SET revoked_at = now()
   WHERE s.session_id = p_session_id AND s.revoked_at IS NULL;
  RETURN FOUND;
END;
$$;

ALTER FUNCTION control.session_issue(uuid, bytea, integer) OWNER TO role_migration_owner;
ALTER FUNCTION control.session_lookup(bytea) OWNER TO role_migration_owner;
ALTER FUNCTION control.session_touch(uuid, integer) OWNER TO role_migration_owner;
ALTER FUNCTION control.session_revoke(uuid) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION control.session_issue(uuid, bytea, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.session_lookup(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.session_touch(uuid, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.session_revoke(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.session_issue(uuid, bytea, integer) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.session_lookup(bytea) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.session_touch(uuid, integer) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.session_revoke(uuid) TO role_gateway;

COMMENT ON FUNCTION control.session_issue(uuid, bytea, integer) IS
  'M02-6 / §73.6: stores the SHA-256 of a fresh cookie secret for a loginable user, pinned to the user security_epoch read under FOR SHARE. No row = user not loginable.';
COMMENT ON FUNCTION control.session_lookup(bytea) IS
  'M02-6: the session row by digest with the user current security_epoch and the database clock; the liveness verdict is application::session::verify.';
COMMENT ON FUNCTION control.session_touch(uuid, integer) IS
  'M02-6: last_seen_at = now() on a live, unexpired, non-idle row only; true when a row moved.';
COMMENT ON FUNCTION control.session_revoke(uuid) IS
  'M02-6 / §74.4: revoked_at = now(), idempotent; true when a row moved.';
