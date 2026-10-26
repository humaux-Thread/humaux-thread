-- ADR-0088 D-A..D-C / §12.1.1 (M20-4a): the versioned contribution notice, its append-only choice events, the AUTO successor
-- gated on a SHOWN notice, and the toggle. EXPAND_CONTRACT: two new tables and six owner doors; no existing row, column or
-- grant changes, and nothing here appends an AUTO policy for any existing tenant (the DB defaults stay DISABLED/MANUAL).
--
--   control.contribution_notices        platform rows (no tenant_id), written only by the migration owner; runtime roles read.
--   control.contribution_notice_events  append-only, FORCE RLS by tenant; rows are written only by the doors below.
--
-- "Current notice" is defined once, in control.current_contribution_notice(). The authorization predicate the sweep and the
-- finalize path call is defined once, in control.contribution_authorized(). Every door reads tenant and user from the
-- session (humaux.tenant_id / humaux.user_id) and takes neither as a parameter; contribution_authorized takes the tenant only
-- to assert it equals the session tenant (0176 lesson: an owner door must not become a cross-tenant door).
--
-- Refusals are SQLSTATE 55000 with the machine-readable reason as the message (0186 convention):
--   notice_version_not_current  the version is not control.current_contribution_notice()  -> CONFLICT / TARGET_NOT_CURRENT
--   notice_not_shown            toggle ON without a SHOWN for tenant+user on the current   -> CONFLICT / TRANSITION_NOT_ALLOWED
-- A missing session context is 42501.

CREATE TABLE control.contribution_notices (
  notice_version   integer     PRIMARY KEY CHECK (notice_version > 0),
  text_sha256      bytea       NOT NULL CHECK (octet_length(text_sha256) = 32),
  scope_categories text[]      NOT NULL CHECK (cardinality(scope_categories) > 0),
  licence_text     text        NOT NULL CHECK (licence_text = 'CC-BY-4.0'),
  licence_code     text        NOT NULL CHECK (licence_code = 'MIT'),
  published_at     timestamptz NOT NULL UNIQUE CHECK (isfinite(published_at))
);

COMMENT ON TABLE control.contribution_notices IS
  'ADR-0088 D-B: one row per published contribution notice version. A new category, sensitivity class or widened scope is a '
  'new version and re-gates every tenant until a SHOWN exists for it. The current version is the greatest published_at <= now() '
  '(control.current_contribution_notice()). Platform rows: written only by the migration owner.';

CREATE TABLE control.contribution_notice_events (
  event_id       uuid        PRIMARY KEY DEFAULT uuidv7(),
  tenant_id      uuid        NOT NULL REFERENCES control.tenants(tenant_id),
  user_id        uuid        NOT NULL REFERENCES control.users(user_id),
  notice_version integer     NOT NULL REFERENCES control.contribution_notices(notice_version),
  kind           text        NOT NULL
                 CHECK (kind IN ('SHOWN', 'ACKED', 'TOGGLED_ON', 'TOGGLED_OFF', 'WITHDRAW_ALL')),
  at             timestamptz NOT NULL DEFAULT clock_timestamp(),
  channel        text        NOT NULL CHECK (channel IN ('POPUP', 'CONSOLE', 'MCP'))
);

CREATE INDEX contribution_notice_events_tenant_shown_idx
  ON control.contribution_notice_events (tenant_id, notice_version)
  WHERE kind = 'SHOWN';

COMMENT ON TABLE control.contribution_notice_events IS
  'ADR-0088 D-B: append-only; every notice display, acknowledgement, toggle and withdrawal leaves a row. No UPDATE/DELETE grant '
  'to any role, and a trigger refuses UPDATE, DELETE and TRUNCATE (0032 / 0041 shape). Written only by the 0274 doors.';

ALTER TABLE control.contribution_notices OWNER TO role_migration_owner;
ALTER TABLE control.contribution_notice_events OWNER TO role_migration_owner;

ALTER TABLE control.contribution_notice_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE control.contribution_notice_events FORCE ROW LEVEL SECURITY;
CREATE POLICY contribution_notice_events_tenant ON control.contribution_notice_events
  USING (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid);

CREATE FUNCTION control.contribution_notice_events_reject_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'control.contribution_notice_events is append-only (ADR-0088 D-B) — % not permitted', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$;
ALTER FUNCTION control.contribution_notice_events_reject_mutation() OWNER TO role_migration_owner;

CREATE TRIGGER contribution_notice_events_reject_mutation
  BEFORE UPDATE OR DELETE ON control.contribution_notice_events
  FOR EACH ROW EXECUTE FUNCTION control.contribution_notice_events_reject_mutation();
CREATE TRIGGER contribution_notice_events_reject_truncate
  BEFORE TRUNCATE ON control.contribution_notice_events
  FOR EACH STATEMENT EXECUTE FUNCTION control.contribution_notice_events_reject_mutation();

-- §6.2.2: role_gateway reads both tables (events through the tenant policy); every other role and PUBLIC has nothing.
REVOKE ALL ON control.contribution_notices, control.contribution_notice_events
  FROM PUBLIC, role_gateway, role_private_worker, role_consolidation_worker, role_public_worker,
       role_retrieval_worker, role_batch_issuer, role_maintenance, role_admin;
GRANT SELECT ON control.contribution_notices, control.contribution_notice_events TO role_gateway;

-- The single definition of "current notice": the greatest published_at that is <= now().
CREATE FUNCTION control.current_contribution_notice() RETURNS integer
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT n.notice_version FROM control.contribution_notices n
   WHERE n.published_at <= now()
   ORDER BY n.published_at DESC
   LIMIT 1
$$;

-- The single authorization predicate (ADR-0088 D-A): current policy mode is AUTO and a SHOWN exists for the tenant on the
-- current notice version. A version bump flips it to false until a new SHOWN.
CREATE FUNCTION control.contribution_authorized(p_tenant_id uuid) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF p_tenant_id IS NULL
     OR p_tenant_id IS DISTINCT FROM NULLIF(current_setting('humaux.tenant_id', true), '')::uuid THEN
    RAISE EXCEPTION 'tenant_context_mismatch' USING ERRCODE = '42501';
  END IF;
  RETURN EXISTS (
    SELECT 1 FROM control.contribution_policies p
     WHERE p.tenant_id = p_tenant_id
       AND p.effective_to IS NULL
       AND p.contribution_mode = 'AUTO_AFTER_USER_DISTILLATION'
  ) AND EXISTS (
    SELECT 1 FROM control.contribution_notice_events e
     WHERE e.tenant_id = p_tenant_id
       AND e.kind = 'SHOWN'
       AND e.notice_version = control.current_contribution_notice()
  );
END;
$$;

-- Shared body of record_notice_shown / ack_notice: the version must be the current one.
CREATE FUNCTION control.append_notice_event(p_kind text, p_notice_version integer, p_channel text) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid := NULLIF(current_setting('humaux.tenant_id', true), '')::uuid;
  v_user uuid := NULLIF(current_setting('humaux.user_id', true), '')::uuid;
  v_event uuid;
BEGIN
  IF v_tenant IS NULL OR v_user IS NULL THEN
    RAISE EXCEPTION 'session_context_missing' USING ERRCODE = '42501';
  END IF;
  IF p_notice_version IS DISTINCT FROM control.current_contribution_notice() THEN
    RAISE EXCEPTION 'notice_version_not_current' USING ERRCODE = '55000';
  END IF;
  INSERT INTO control.contribution_notice_events (tenant_id, user_id, notice_version, kind, channel)
  VALUES (v_tenant, v_user, p_notice_version, p_kind, p_channel)
  RETURNING event_id INTO v_event;
  RETURN v_event;
END;
$$;

CREATE FUNCTION control.record_notice_shown(p_notice_version integer, p_channel text) RETURNS uuid
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$ SELECT control.append_notice_event('SHOWN', p_notice_version, p_channel) $$;

CREATE FUNCTION control.ack_notice(p_notice_version integer, p_channel text) RETURNS uuid
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$ SELECT control.append_notice_event('ACKED', p_notice_version, p_channel) $$;

-- ADR-0088 D-C: ON appends TOGGLED_ON and then the AUTO successor, only while a SHOWN exists for this tenant+user on the
-- current version; OFF appends TOGGLED_OFF and a DISABLED successor. Event and successor are one transaction. A tenant with no
-- policy row gets its first row (version 1) instead of a successor. A toggle to the mode the head already has appends the
-- event only. Returns the open head's policy_version after the call.
CREATE FUNCTION control.toggle_contribution(p_on boolean, p_channel text) RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid := NULLIF(current_setting('humaux.tenant_id', true), '')::uuid;
  v_user uuid := NULLIF(current_setting('humaux.user_id', true), '')::uuid;
  v_notice integer := control.current_contribution_notice();
  v_mode text;
  head control.contribution_policies;
BEGIN
  IF v_tenant IS NULL OR v_user IS NULL THEN
    RAISE EXCEPTION 'session_context_missing' USING ERRCODE = '42501';
  END IF;
  IF p_on IS NULL THEN
    RAISE EXCEPTION 'toggle_required' USING ERRCODE = '22023';
  END IF;
  IF v_notice IS NULL THEN
    RAISE EXCEPTION 'notice_version_not_current' USING ERRCODE = '55000';
  END IF;
  IF p_on AND NOT EXISTS (
    SELECT 1 FROM control.contribution_notice_events e
     WHERE e.tenant_id = v_tenant AND e.user_id = v_user
       AND e.notice_version = v_notice AND e.kind = 'SHOWN'
  ) THEN
    RAISE EXCEPTION 'notice_not_shown' USING ERRCODE = '55000';
  END IF;
  v_mode := CASE WHEN p_on THEN 'AUTO_AFTER_USER_DISTILLATION' ELSE 'DISABLED' END;
  INSERT INTO control.contribution_notice_events (tenant_id, user_id, notice_version, kind, channel)
  VALUES (v_tenant, v_user, v_notice, CASE WHEN p_on THEN 'TOGGLED_ON' ELSE 'TOGGLED_OFF' END, p_channel);

  SELECT * INTO head FROM control.contribution_policies
   WHERE tenant_id = v_tenant AND effective_to IS NULL;
  IF NOT FOUND THEN
    INSERT INTO control.contribution_policies (tenant_id, allow_public_contribution, policy_version, contribution_mode)
    VALUES (v_tenant, p_on, 1, v_mode);
    RETURN 1;
  END IF;
  IF head.contribution_mode = v_mode THEN
    RETURN head.policy_version;
  END IF;
  RETURN (control.append_contribution_policy_successor(
    v_tenant, head.policy_id, head.policy_version, p_on, v_mode, head.rights_basis, head.source_license,
    head.publisher, head.contributor_attestation, head.redistribution_policy)).policy_version;
END;
$$;

-- ADR-0088 D-A: the cloud onboarding default. Callable only by role_maintenance inside the onboarding transaction (the tenant
-- GUC is the caller's); core never calls it (G-M20-1). Writes version 1 only when the tenant has no policy row; the sweep still
-- selects nothing for the tenant until a SHOWN exists for the current notice (contribution_authorized).
CREATE FUNCTION control.apply_cloud_contribution_default() RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid := NULLIF(current_setting('humaux.tenant_id', true), '')::uuid;
BEGIN
  IF v_tenant IS NULL THEN
    RAISE EXCEPTION 'session_context_missing' USING ERRCODE = '42501';
  END IF;
  IF EXISTS (SELECT 1 FROM control.contribution_policies WHERE tenant_id = v_tenant) THEN
    RETURN false;
  END IF;
  INSERT INTO control.contribution_policies (tenant_id, allow_public_contribution, policy_version, contribution_mode)
  VALUES (v_tenant, true, 1, 'AUTO_AFTER_USER_DISTILLATION');
  RETURN true;
END;
$$;

ALTER FUNCTION control.current_contribution_notice() OWNER TO role_migration_owner;
ALTER FUNCTION control.contribution_authorized(uuid) OWNER TO role_migration_owner;
ALTER FUNCTION control.append_notice_event(text, integer, text) OWNER TO role_migration_owner;
ALTER FUNCTION control.record_notice_shown(integer, text) OWNER TO role_migration_owner;
ALTER FUNCTION control.ack_notice(integer, text) OWNER TO role_migration_owner;
ALTER FUNCTION control.toggle_contribution(boolean, text) OWNER TO role_migration_owner;
ALTER FUNCTION control.apply_cloud_contribution_default() OWNER TO role_migration_owner;

REVOKE ALL ON FUNCTION control.current_contribution_notice() FROM PUBLIC;
REVOKE ALL ON FUNCTION control.contribution_authorized(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.append_notice_event(text, integer, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.record_notice_shown(integer, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.ack_notice(integer, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.toggle_contribution(boolean, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.apply_cloud_contribution_default() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION control.current_contribution_notice() TO role_gateway, role_private_worker, role_public_worker;
GRANT EXECUTE ON FUNCTION control.contribution_authorized(uuid) TO role_gateway, role_private_worker, role_public_worker;
GRANT EXECUTE ON FUNCTION control.record_notice_shown(integer, text) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.ack_notice(integer, text) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.toggle_contribution(boolean, text) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.apply_cloud_contribution_default() TO role_maintenance;
