-- ADR-0088 D-A..D-C / §12.1.1 (M20-4a): the versioned contribution notice, its append-only choice events, the AUTO successor
-- gated on a SHOWN notice, and the toggle. EXPAND_CONTRACT: two new tables and eight owner doors; no existing row, column or
-- grant changes, and nothing here appends an AUTO policy for any existing tenant (the DB defaults stay DISABLED/MANUAL).
--
--   control.contribution_notices        platform rows (no tenant_id), written only by the migration owner; runtime roles read.
--   control.contribution_notice_events  append-only, FORCE RLS by tenant; rows are written only by the doors below.
--
-- "Current notice" is defined once, in control.current_contribution_notice(). The authorization predicate the sweep and the
-- finalize path call is defined once, in control.contribution_authorized(tenant, user): consent is per member, so a member's
-- memories are selectable only after that member's SHOWN on the current version. The doors read tenant and user from the
-- session (humaux.tenant_id / humaux.user_id) and take neither as a parameter; contribution_authorized takes the user (the
-- memory's author) and the tenant, the latter only to assert it equals the session tenant (0176 lesson: an owner door must
-- not become a cross-tenant door).
--
-- The tenant toggle (toggle_contribution) is OWNER-only in both directions: it writes the tenant-wide policy head. Every ACTIVE
-- member may additionally opt themselves out and back in (toggle_member_contribution: MEMBER-scope events only, no policy
-- write); a member's own OFF makes that member's memories unselectable, tenant ON stays OWNER-only (ADR-0088 D-A, D-C).
-- Opting out is never blocked for lack of a notice.
--
-- Refusals are SQLSTATE 55000 with the machine-readable reason as the message (0186 convention):
--   notice_version_not_current  the version is not control.current_contribution_notice()  -> CONFLICT / TARGET_NOT_CURRENT
--   notice_not_shown            toggle ON without a SHOWN for tenant+user on the current   -> CONFLICT / TRANSITION_NOT_ALLOWED
-- A missing session context, and a toggle by a session user who is not an ACTIVE OWNER of the tenant, are 42501 (-> FORBIDDEN).

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
  notice_version integer     REFERENCES control.contribution_notices(notice_version),
  kind           text        NOT NULL
                 CHECK (kind IN ('SHOWN', 'ACKED', 'TOGGLED_ON', 'TOGGLED_OFF', 'WITHDRAW_ALL')),
  at             timestamptz NOT NULL DEFAULT clock_timestamp(),
  channel        text        NOT NULL CHECK (channel IN ('POPUP', 'CONSOLE', 'MCP')),
  -- TENANT: the tenant-wide flow; MEMBER: a personal toggle that never touches the policy head.
  scope          text        NOT NULL DEFAULT 'TENANT',
  CONSTRAINT contribution_notice_events_scope_check CHECK (scope IN ('TENANT', 'MEMBER')),
  CONSTRAINT contribution_notice_events_scope_kind_check
    CHECK (scope = 'TENANT' OR kind IN ('TOGGLED_ON', 'TOGGLED_OFF')),
  -- Opting out must work before any notice is published; every other kind names the version it was recorded against.
  CONSTRAINT contribution_notice_events_version_check
    CHECK (notice_version IS NOT NULL OR kind IN ('TOGGLED_OFF', 'WITHDRAW_ALL'))
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

-- The single authorization predicate (ADR-0088 D-A), per member: the tenant's current policy mode is AUTO, p_user_id has a
-- SHOWN on the current notice version, and p_user_id's latest MEMBER-scope toggle event (if any) is not TOGGLED_OFF. A version bump flips it to false until each member shows again. The sweep and
-- finalize call it with the memory's author, so one member's SHOWN never authorizes another member's memories.
CREATE FUNCTION control.contribution_authorized(p_tenant_id uuid, p_user_id uuid) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF p_tenant_id IS NULL
     OR p_tenant_id IS DISTINCT FROM NULLIF(current_setting('humaux.tenant_id', true), '')::uuid THEN
    RAISE EXCEPTION 'tenant_context_mismatch' USING ERRCODE = '42501';
  END IF;
  IF p_user_id IS NULL THEN
    RETURN false;
  END IF;
  RETURN EXISTS (
    SELECT 1 FROM control.contribution_policies p
     WHERE p.tenant_id = p_tenant_id
       AND p.effective_to IS NULL
       AND p.contribution_mode = 'AUTO_AFTER_USER_DISTILLATION'
  ) AND EXISTS (
    SELECT 1 FROM control.contribution_notice_events e
     WHERE e.tenant_id = p_tenant_id
       AND e.user_id = p_user_id
       AND e.kind = 'SHOWN'
       AND e.notice_version = control.current_contribution_notice()
  ) AND NOT COALESCE((
    SELECT o.kind = 'TOGGLED_OFF' FROM control.contribution_notice_events o
     WHERE o.tenant_id = p_tenant_id
       AND o.user_id = p_user_id
       AND o.scope = 'MEMBER'
       AND o.kind IN ('TOGGLED_ON', 'TOGGLED_OFF')
     ORDER BY o.at DESC, o.event_id DESC
     LIMIT 1
  ), false);
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
-- Tenant level, OWNER-only in both directions: the session user must be an ACTIVE OWNER of the tenant (the 0273 membership
-- pattern); a member's personal opt-out is toggle_member_contribution. OFF never needs a notice: with none
-- published the event carries a NULL version (contribution_notice_events_version_check).
-- No lock is taken: a notice published between the SHOWN check and the successor insert is harmless, because
-- control.contribution_authorized re-reads the current version every time it is used and the new version re-gates.
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
  IF NOT EXISTS (
    SELECT 1 FROM control.memberships m
     WHERE m.tenant_id = v_tenant AND m.user_id = v_user
       AND m.state = 'ACTIVE' AND m.role = 'OWNER'
  ) THEN
    RAISE EXCEPTION 'toggle_owner_required' USING ERRCODE = '42501';
  END IF;
  IF p_on AND v_notice IS NULL THEN
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
  INSERT INTO control.contribution_notice_events (tenant_id, user_id, notice_version, kind, channel, scope)
  VALUES (v_tenant, v_user, v_notice, CASE WHEN p_on THEN 'TOGGLED_ON' ELSE 'TOGGLED_OFF' END, p_channel, 'TENANT');

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

-- ADR-0088 D-C, personal: an ACTIVE member (any role) records a MEMBER-scope TOGGLED_OFF / TOGGLED_ON for THEMSELVES and never
-- writes the policy head. OFF needs no notice (NULL version allowed); ON needs a published notice and a tenant policy that is
-- already AUTO, and re-opts in only that member (control.contribution_authorized still needs their SHOWN). Returns the event id.
CREATE FUNCTION control.toggle_member_contribution(p_on boolean, p_channel text) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid := NULLIF(current_setting('humaux.tenant_id', true), '')::uuid;
  v_user uuid := NULLIF(current_setting('humaux.user_id', true), '')::uuid;
  v_notice integer := control.current_contribution_notice();
  v_event uuid;
BEGIN
  IF v_tenant IS NULL OR v_user IS NULL THEN
    RAISE EXCEPTION 'session_context_missing' USING ERRCODE = '42501';
  END IF;
  IF p_on IS NULL THEN
    RAISE EXCEPTION 'toggle_required' USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM control.memberships m
     WHERE m.tenant_id = v_tenant AND m.user_id = v_user AND m.state = 'ACTIVE'
  ) THEN
    RAISE EXCEPTION 'toggle_member_required' USING ERRCODE = '42501';
  END IF;
  IF p_on AND v_notice IS NULL THEN
    RAISE EXCEPTION 'notice_version_not_current' USING ERRCODE = '55000';
  END IF;
  IF p_on AND NOT EXISTS (
    SELECT 1 FROM control.contribution_policies p
     WHERE p.tenant_id = v_tenant AND p.effective_to IS NULL
       AND p.contribution_mode = 'AUTO_AFTER_USER_DISTILLATION'
  ) THEN
    RAISE EXCEPTION 'tenant_policy_not_auto' USING ERRCODE = '55000';
  END IF;
  INSERT INTO control.contribution_notice_events (tenant_id, user_id, notice_version, kind, channel, scope)
  VALUES (v_tenant, v_user, v_notice, CASE WHEN p_on THEN 'TOGGLED_ON' ELSE 'TOGGLED_OFF' END, p_channel, 'MEMBER')
  RETURNING event_id INTO v_event;
  RETURN v_event;
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
ALTER FUNCTION control.contribution_authorized(uuid, uuid) OWNER TO role_migration_owner;
ALTER FUNCTION control.append_notice_event(text, integer, text) OWNER TO role_migration_owner;
ALTER FUNCTION control.record_notice_shown(integer, text) OWNER TO role_migration_owner;
ALTER FUNCTION control.ack_notice(integer, text) OWNER TO role_migration_owner;
ALTER FUNCTION control.toggle_contribution(boolean, text) OWNER TO role_migration_owner;
ALTER FUNCTION control.toggle_member_contribution(boolean, text) OWNER TO role_migration_owner;
ALTER FUNCTION control.apply_cloud_contribution_default() OWNER TO role_migration_owner;

REVOKE ALL ON FUNCTION control.current_contribution_notice() FROM PUBLIC;
REVOKE ALL ON FUNCTION control.contribution_authorized(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.append_notice_event(text, integer, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.record_notice_shown(integer, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.ack_notice(integer, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.toggle_contribution(boolean, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.toggle_member_contribution(boolean, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION control.apply_cloud_contribution_default() FROM PUBLIC;

-- The workers get EXECUTE on the two reads when the sweep (M20-6) and finalize (M20-4b) land and have a caller.
GRANT EXECUTE ON FUNCTION control.current_contribution_notice() TO role_gateway;
GRANT EXECUTE ON FUNCTION control.contribution_authorized(uuid, uuid) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.record_notice_shown(integer, text) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.ack_notice(integer, text) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.toggle_contribution(boolean, text) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.toggle_member_contribution(boolean, text) TO role_gateway;
GRANT EXECUTE ON FUNCTION control.apply_cloud_contribution_default() TO role_maintenance;
