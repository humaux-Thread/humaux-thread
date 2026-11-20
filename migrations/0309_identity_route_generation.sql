-- ADR-0133: a routing stamp is independent of security_epoch and never authorizes a request.
ALTER TABLE control.tenants
  ADD COLUMN routing_revoke_epoch bigint NOT NULL DEFAULT 0 CHECK (routing_revoke_epoch >= 0);

-- Runtime roles gain no table grant. The trigger writes as the existing migration owner.
CREATE POLICY tenants_route_epoch_owner_update ON control.tenants
  FOR UPDATE TO role_migration_owner
  USING (current_user = 'role_migration_owner')
  WITH CHECK (current_user = 'role_migration_owner');

CREATE FUNCTION control.advance_credential_route_epoch()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_new_tenant uuid;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    v_new_tenant := NEW.tenant_id;
  END IF;
  -- Lock in tenant order if maintenance moves a binding across tenants.
  IF v_new_tenant IS NOT NULL AND v_new_tenant <> OLD.tenant_id THEN
    PERFORM 1 FROM control.tenants
     WHERE tenant_id IN (OLD.tenant_id, v_new_tenant)
     ORDER BY tenant_id FOR UPDATE;
  END IF;
  UPDATE control.tenants SET routing_revoke_epoch = routing_revoke_epoch + 1
   WHERE tenant_id IN (OLD.tenant_id, v_new_tenant);
  RETURN NULL;
END;
$$;
ALTER FUNCTION control.advance_credential_route_epoch() OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION control.advance_credential_route_epoch() FROM PUBLIC;

CREATE TRIGGER api_keys_route_epoch_update
AFTER UPDATE ON control.api_keys
FOR EACH ROW
WHEN (
  (OLD.api_key_id, OLD.tenant_id, OLD.prefix, OLD.status, OLD.expires_at, OLD.revoked_at,
   OLD.scopes, OLD.allowed_cidrs, OLD.authorization_version, OLD.user_id, OLD.workspace_id,
   OLD.tenant_security_epoch, OLD.user_security_epoch)
  IS DISTINCT FROM
  (NEW.api_key_id, NEW.tenant_id, NEW.prefix, NEW.status, NEW.expires_at, NEW.revoked_at,
   NEW.scopes, NEW.allowed_cidrs, NEW.authorization_version, NEW.user_id, NEW.workspace_id,
   NEW.tenant_security_epoch, NEW.user_security_epoch)
)
EXECUTE FUNCTION control.advance_credential_route_epoch();

CREATE TRIGGER api_keys_route_epoch_delete
AFTER DELETE ON control.api_keys
FOR EACH ROW EXECUTE FUNCTION control.advance_credential_route_epoch();

CREATE FUNCTION control.advance_tenant_route_epoch()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  NEW.routing_revoke_epoch := OLD.routing_revoke_epoch + 1;
  RETURN NEW;
END;
$$;
ALTER FUNCTION control.advance_tenant_route_epoch() OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION control.advance_tenant_route_epoch() FROM PUBLIC;

CREATE TRIGGER tenants_route_epoch_update
BEFORE UPDATE OF state, security_epoch ON control.tenants
FOR EACH ROW
WHEN ((OLD.state, OLD.security_epoch) IS DISTINCT FROM (NEW.state, NEW.security_epoch))
EXECUTE FUNCTION control.advance_tenant_route_epoch();

DROP FUNCTION control.api_key_lookup(text);

CREATE FUNCTION control.api_key_lookup(p_prefix text)
RETURNS TABLE (
  api_key_id uuid,
  tenant_id uuid,
  key_hash bytea,
  status text,
  allowed_cidrs cidr[],
  expires_at timestamptz,
  revoked_at timestamptz,
  scopes text[],
  authorization_version smallint,
  user_id uuid,
  workspace_id uuid,
  tenant_security_epoch bigint,
  user_security_epoch bigint,
  tenant_state text,
  live_tenant_security_epoch bigint,
  user_state text,
  live_user_security_epoch bigint,
  membership_state text,
  routing_revoke_epoch bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, control
AS $$
  SELECT
    k.api_key_id,
    k.tenant_id,
    k.key_hash,
    k.status,
    k.allowed_cidrs,
    k.expires_at,
    k.revoked_at,
    k.scopes,
    k.authorization_version,
    k.user_id,
    k.workspace_id,
    k.tenant_security_epoch,
    k.user_security_epoch,
    t.state,
    t.security_epoch,
    u.state,
    u.security_epoch,
    m.state,
    t.routing_revoke_epoch
  FROM control.api_keys AS k
  JOIN control.tenants AS t ON t.tenant_id = k.tenant_id
  LEFT JOIN control.users AS u ON u.user_id = k.user_id
  LEFT JOIN control.memberships AS m
    ON m.tenant_id = k.tenant_id AND m.user_id = k.user_id
  WHERE k.prefix = p_prefix;
$$;

ALTER FUNCTION control.api_key_lookup(text) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION control.api_key_lookup(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.api_key_lookup(text) TO role_gateway;

COMMENT ON FUNCTION control.api_key_lookup(text) IS
  '§73.5.1 and ADR-0133: the gateway-only live binding and its route generation share one statement snapshot.';

-- Keep the single-ID door for interval=0 deployments. Batch callers use only a trusted interval.
CREATE FUNCTION control.api_key_touch_last_used_batch(p_ids uuid[], p_interval_seconds integer)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_now timestamptz := statement_timestamp();
  v_updated bigint;
BEGIN
  IF p_ids IS NULL OR p_interval_seconds IS NULL OR p_interval_seconds < 60 THEN
    RAISE EXCEPTION 'invalid_credential_touch_batch' USING ERRCODE = '22023';
  END IF;
  UPDATE control.api_keys
     SET last_used_at = v_now
   WHERE api_key_id = ANY(p_ids);
  GET DIAGNOSTICS v_updated = ROW_COUNT;
  RETURN v_updated;
END;
$$;
ALTER FUNCTION control.api_key_touch_last_used_batch(uuid[], integer) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION control.api_key_touch_last_used_batch(uuid[], integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.api_key_touch_last_used_batch(uuid[], integer) TO role_gateway;
