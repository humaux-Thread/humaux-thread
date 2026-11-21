-- ADR-0137: enumerate live identity targets, with a sentinel instead of truncating.
CREATE FUNCTION control.oauth_chooser_identity_targets(p_session_id uuid)
RETURNS TABLE (out_tenant_id uuid, out_workspace_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
SET humaux.tenant_id = ''
SET humaux.user_id = ''
AS $$
DECLARE
  v_user uuid;
  v_tenant uuid;
  v_rows integer;
  v_count integer := 0;
BEGIN
  SELECT s.user_id INTO v_user FROM control.sessions s
    JOIN control.users u USING (user_id)
   WHERE s.session_id = p_session_id AND u.state = 'ACTIVE';
  IF NOT FOUND THEN
    RETURN;
  END IF;
  PERFORM set_config('humaux.user_id', v_user::text, true);
  FOR v_tenant IN
    SELECT m.tenant_id FROM control.memberships m
      JOIN control.tenants t USING (tenant_id)
     WHERE m.user_id = v_user AND m.state = 'ACTIVE' AND t.state = 'ACTIVE'
     ORDER BY m.tenant_id LIMIT 257
  LOOP
    PERFORM set_config('humaux.tenant_id', v_tenant::text, true);
    RETURN QUERY SELECT v_tenant, NULL::uuid;
    v_count := v_count + 1;
    RETURN QUERY
      SELECT v_tenant, w.workspace_id FROM control.workspace_memberships w
       WHERE w.tenant_id = v_tenant AND w.user_id = v_user AND w.state = 'ACTIVE'
       ORDER BY w.workspace_id LIMIT (257 - v_count);
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    v_count := v_count + v_rows;
    EXIT WHEN v_count >= 257;
  END LOOP;
END;
$$;

-- The caller already holds 0313's tenant guard. Lock admission rows until code commit.
CREATE FUNCTION control.oauth_chooser_lock_memberships(
  p_user_id uuid, p_tenant_id uuid, p_workspace_id uuid
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
SET humaux.tenant_id = ''
SET humaux.user_id = ''
AS $$
BEGIN
  PERFORM set_config('humaux.tenant_id', p_tenant_id::text, true);
  PERFORM set_config('humaux.user_id', p_user_id::text, true);
  PERFORM 1 FROM control.memberships m
   WHERE m.tenant_id = p_tenant_id AND m.user_id = p_user_id AND m.state = 'ACTIVE'
   FOR SHARE;
  IF NOT FOUND THEN
    RETURN false;
  END IF;
  IF p_workspace_id IS NOT NULL THEN
    PERFORM 1 FROM control.workspace_memberships w
     WHERE w.tenant_id = p_tenant_id AND w.workspace_id = p_workspace_id
       AND w.user_id = p_user_id AND w.state = 'ACTIVE'
     FOR SHARE;
    RETURN FOUND;
  END IF;
  RETURN true;
END;
$$;

-- The session verdict stays in application::session::verify. No cookie or digest is returned.
CREATE FUNCTION control.oauth_chooser_session_facts(p_session_id uuid, p_user_id uuid, p_lock boolean)
RETURNS TABLE (
  out_session_id uuid, out_user_id uuid, out_session_epoch bigint, out_current_epoch bigint,
  out_expires_at_unix double precision, out_last_seen_at_unix double precision,
  out_revoked_at_unix double precision, out_db_now_unix double precision
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $$
BEGIN
  IF p_lock THEN
    PERFORM 1 FROM control.users u WHERE u.user_id = p_user_id FOR SHARE;
    PERFORM 1 FROM control.sessions s
      WHERE s.session_id = p_session_id AND s.user_id = p_user_id FOR SHARE;
  END IF;
  RETURN QUERY
    SELECT s.session_id, s.user_id, s.session_epoch, u.security_epoch,
           extract(epoch FROM s.expires_at)::double precision,
           extract(epoch FROM s.last_seen_at)::double precision,
           extract(epoch FROM s.revoked_at)::double precision,
           extract(epoch FROM clock_timestamp())::double precision
      FROM control.sessions s JOIN control.users u USING (user_id)
     WHERE s.session_id = p_session_id AND s.user_id = p_user_id AND u.state = 'ACTIVE';
END;
$$;

ALTER FUNCTION control.oauth_chooser_identity_targets(uuid) OWNER TO role_migration_owner;
ALTER FUNCTION control.oauth_chooser_lock_memberships(uuid, uuid, uuid) OWNER TO role_migration_owner;
ALTER FUNCTION control.oauth_chooser_session_facts(uuid, uuid, boolean) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION control.oauth_chooser_identity_targets(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.oauth_chooser_lock_memberships(uuid, uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.oauth_chooser_session_facts(uuid, uuid, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.oauth_chooser_identity_targets(uuid) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.oauth_chooser_lock_memberships(uuid, uuid, uuid) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.oauth_chooser_session_facts(uuid, uuid, boolean) TO role_gateway;
