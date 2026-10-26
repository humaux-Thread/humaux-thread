-- §37.2 / ADR-0092 D-B, D-C (M19-3a): the gateway-only owner accept door is the second TOMBSTONED exit,
-- limited to this request's frozen EVIDENCE targets. MEMORY targets use revoked + TOMBSTONE/USER_DELETE.
-- Amends 0233's comment "refuses it to the owner": its SECURITY INVOKER generation-follow trigger now also
-- follows the owner inside this door, under the session tenant and FORCE RLS. No runtime UPDATE grant changes.
-- 0167's existing guard branches remain byte-identical; the only added edge is the non-spoofable owner arm.
-- The request, roots and token are locked before writes. Root FOR UPDATE conflicts with memory_evidence FK
-- insertion's KEY SHARE, so closure recomputation after locking sees any completed link and fences new links.
-- Token, request and lifecycle writes roll back with any refusal. Scope/manifest binding uses the canonical
-- application::forget::confirmation_digest encoding (Baseline §33.10 rule 9). No physical deletion occurs.
-- Amends the 0163 memory_records WITH CHECK by one revoke-only role_migration_owner arm (ADR-0092 ruling 2: closure
-- Memories invisible to the accepter must still be revoked); see the ALTER POLICY below.

-- §46.1: FORCE RLS must never turn the cross-tenant precheck into a false zero (0272 pattern).
SELECT set_config('row_security', 'off', true);
DO $$
DECLARE
  invalid_operations bigint;
BEGIN
  SELECT count(*) INTO invalid_operations FROM control.confirm_tokens
   WHERE operation NOT IN ('memory.supersede','memory.pin','memory.unpin','memory.restore','memory.archive',
     'memory.unarchive','memory.correct','memory.confirm','memory.reject','memory.bind','memory.unbind',
     'memory.note_put','memory.forget','account.delete');
  IF invalid_operations <> 0 THEN
    RAISE EXCEPTION '0278: control.confirm_tokens has % rows outside the operation closed set; refusing migration',
      invalid_operations USING ERRCODE = 'check_violation';
  END IF;
END;
$$;
SELECT set_config('row_security', 'on', true);

ALTER TABLE control.confirm_tokens ADD CONSTRAINT confirm_tokens_operation_closed_set
  CHECK (operation IN ('memory.supersede','memory.pin','memory.unpin','memory.restore','memory.archive',
    'memory.unarchive','memory.correct','memory.confirm','memory.reject','memory.bind','memory.unbind',
    'memory.note_put','memory.forget','account.delete'));

CREATE OR REPLACE FUNCTION projection.stream_log_guard_state_transition() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  actor text := current_user;
  legal boolean := false;
BEGIN
  IF OLD.state = NEW.state THEN
    RETURN NEW;
  END IF;

  IF actor = 'role_private_worker' THEN
    -- §15.2 "Private processing transition", verbatim: "PROCESSING -> WAITING_KEY |
    -- RETRY_WAIT | FAILED | ISSUED(next reclaim) | next stage" — PROCESSING -> ISSUED is
    -- the next-reclaim edge, not a typo of WAITING_KEY/RETRY_WAIT -> ISSUED below.
    legal := (OLD.state, NEW.state) IN (
      ('ISSUED','PROCESSING'), ('PROCESSING','WAITING_KEY'), ('PROCESSING','RETRY_WAIT'),
      ('PROCESSING','FAILED'), ('PROCESSING','ISSUED'), ('WAITING_KEY','ISSUED'), ('RETRY_WAIT','ISSUED')
    );
  ELSIF actor = 'role_retrieval_worker' THEN
    -- §6.2.2 line, verbatim: "投影侧终态（ISSUED -> DONE | SKIPPED_BY_POLICY | FAILED）在
    -- role_retrieval_worker" — the parenthesised pair IS the full source-state set (ISSUED
    -- only), not a floor; PROCESSING/WAITING_KEY/RETRY_WAIT never settle straight to a
    -- terminal state through this role. RETIRED_FAILED is deliberately absent: the role that
    -- writes the failure does not get to settle it OK (0167 header).
    legal := OLD.state = 'ISSUED' AND NEW.state IN ('DONE','SKIPPED_BY_POLICY','FAILED');
  ELSIF actor = 'role_maintenance' THEN
    -- §15.2 sweep (ISSUED -> LOST) + §37.2 retention::tombstone (* -> TOMBSTONED).
    legal := (OLD.state = 'ISSUED' AND NEW.state = 'LOST') OR NEW.state = 'TOMBSTONED';
  ELSIF current_user = 'role_migration_owner' AND NEW.state = 'TOMBSTONED' AND OLD.state <> 'TOMBSTONED' THEN
    legal := true;
  ELSIF actor = 'role_migration_owner' THEN
    -- §15.2 amendment (0167): the audited retirement, reachable only through
    -- projection.retire_failed_ticket(...) below — the one owner-side edge on this table.
    legal := OLD.state = 'FAILED' AND NEW.state = 'RETIRED_FAILED';
  END IF;

  IF NOT legal THEN
    RAISE EXCEPTION 'illegal projection.stream_log state transition % -> % by role % (§6.2.2/§15.2)',
      OLD.state, NEW.state, actor
      USING ERRCODE = 'check_violation';
  END IF;

  -- 0007's CHECK requires settled_at IS NOT NULL exactly on the TERMINAL states (§15.2, widened
  -- by this migration to include RETIRED_FAILED). No role's §6.2.2 grant includes settled_at
  -- (role_private_worker's is column-limited to state,error_class — see §6.2.2 table) precisely
  -- because this owner trigger, not the caller's UPDATE, is the single writer of it: without
  -- this, the one PROCESSING -> FAILED edge role_private_worker is legally allowed to make above
  -- is un-satisfiable at the CHECK and the branch is dead in practice. COALESCE leaves an
  -- explicitly-supplied value alone (no other role currently supplies one), which is also what
  -- keeps a retirement from rewriting the original settlement time.
  IF NEW.state IN ('DONE','SKIPPED_BY_POLICY','FAILED','TOMBSTONED','RETIRED_FAILED') THEN
    NEW.settled_at := COALESCE(NEW.settled_at, now());
  END IF;

  RETURN NEW;
END;
$$;

-- ADR-0092 ruling 2 (M19-3a): the accept door must revoke every closure Memory, including ones its session user
-- cannot read. USING already has the cluster-scan owner arm (0163), so the door can lock and read them, but WITH CHECK had
-- no owner arm, so the owner-definer UPDATE of an invisible row failed with 42501. This amends the 0163 WITH CHECK by ONE
-- tenant-bounded, revoke-only owner arm: WITH CHECK sees only the NEW row, so an owner door can write an invisible row only
-- when it leaves it revoked, never keep it live with other content and never un-revoke it. USING and every existing WITH
-- CHECK branch are unchanged; there is no GUC arm.
ALTER POLICY memory_records_tenant_and_visibility ON private.memory_records
WITH CHECK (
  tenant_id = current_setting('humaux.tenant_id', true)::uuid
  AND (
    (current_user = 'role_private_worker'
     AND (visibility_class = 'TENANT_SHARED'
          OR (visibility_class = 'WORKSPACE_SHARED' AND visibility_workspace_id IS NOT NULL)
          OR (visibility_class = 'USER_PRIVATE' AND visibility_user_id IS NOT NULL)))
    OR (current_user = 'role_migration_owner' AND status = 'revoked')
    OR private.visibility_allowed(visibility_class, true,
         visibility_user_id = NULLIF(current_setting('humaux.user_id', true), '')::uuid,
         EXISTS (SELECT 1 FROM control.workspace_memberships wm
                 WHERE wm.tenant_id = memory_records.tenant_id
                   AND wm.workspace_id = memory_records.visibility_workspace_id
                   AND wm.user_id = NULLIF(current_setting('humaux.user_id', true), '')::uuid
                   AND wm.state = 'ACTIVE'))
  )
);

CREATE FUNCTION control.deletion_request_accept(
  p_request_id uuid, p_nonce_sha256 bytea, p_operation text, p_request_sha256 bytea,
  p_workspace_id uuid, p_principal_id uuid
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid := NULLIF(current_setting('humaux.tenant_id', true), '')::uuid;
  v_user uuid := NULLIF(current_setting('humaux.user_id', true), '')::uuid;
  v_request control.deletion_requests%ROWTYPE;
  v_token uuid;
  v_roots uuid[];
  v_kinds text[];
  v_ids uuid[];
  v_hash bytea;
  v_intent bytea;
  v_memory uuid;
  v_event uuid;
BEGIN
  IF v_tenant IS NULL OR v_user IS NULL OR v_user = '00000000-0000-0000-0000-000000000000'::uuid THEN
    RAISE EXCEPTION 'deletion_request_accept: no_session_identity' USING ERRCODE = 'insufficient_privilege';
  END IF;
  PERFORM control.assert_write_scope(p_principal_id, p_workspace_id);
  SELECT * INTO v_request FROM control.deletion_requests
   WHERE tenant_id = v_tenant AND deletion_request_id = p_request_id AND requested_by = v_user
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'deletion_request_accept: request_missing' USING ERRCODE = 'no_data_found';
  END IF;
  IF v_request.state <> 'REQUESTED' OR v_request.logical_deleted_at IS NOT NULL
     OR v_request.scope_kind NOT IN ('MEMORY', 'EVIDENCE_CLOSURE') THEN
    RAISE EXCEPTION 'deletion_request_accept: request_not_open' USING ERRCODE = 'serialization_failure';
  END IF;
  v_intent := sha256(convert_to('humaux.deletion.confirm.v1' || chr(10) || v_request.scope_kind, 'UTF8')
                     || '\x00'::bytea || v_request.manifest_hash);
  IF p_operation IS DISTINCT FROM 'memory.forget' OR p_request_sha256 IS DISTINCT FROM v_intent THEN
    RAISE EXCEPTION 'deletion_request_accept: confirmation_binding' USING ERRCODE = 'serialization_failure';
  END IF;
  SELECT confirm_token_id INTO v_token FROM control.confirm_tokens
   WHERE tenant_id = v_tenant AND user_id = v_user AND nonce_sha256 = p_nonce_sha256
     AND operation = p_operation AND target_id = p_request_id AND successor_id IS NULL
     AND workspace_id = p_workspace_id AND request_sha256 = v_intent
     AND consumed_at IS NULL AND expires_at > clock_timestamp()
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'deletion_request_accept: confirmation_binding' USING ERRCODE = 'serialization_failure';
  END IF;

  SELECT array_agg(id ORDER BY id) INTO v_roots FROM control.deletion_targets
   WHERE tenant_id = v_tenant AND request_id = p_request_id
     AND kind = CASE WHEN v_request.scope_kind = 'MEMORY' THEN 'MEMORY' ELSE 'EVIDENCE' END;
  IF v_request.scope_kind = 'MEMORY' THEN
    PERFORM m.memory_id FROM private.memory_records m
     WHERE m.tenant_id = v_tenant AND m.memory_id = ANY(v_roots) ORDER BY m.memory_id FOR UPDATE;
    SELECT array_agg('MEMORY'::text ORDER BY m.memory_id), array_agg(m.memory_id ORDER BY m.memory_id)
      INTO v_kinds, v_ids FROM private.memory_records m
     WHERE m.tenant_id = v_tenant AND m.memory_id = ANY(v_roots);
  ELSE
    PERFORM e.evidence_id FROM private.evidence_objects e
     WHERE e.tenant_id = v_tenant AND e.evidence_id = ANY(v_roots) ORDER BY e.evidence_id FOR UPDATE;
    PERFORM me.memory_id FROM private.memory_evidence me
     WHERE me.evidence_id = ANY(v_roots) ORDER BY me.memory_id, me.evidence_id FOR SHARE;
    SELECT array_agg(t.kind), array_agg(t.id) INTO v_kinds, v_ids
      FROM (SELECT 'EVIDENCE'::text AS kind, e.evidence_id AS id FROM private.evidence_objects e
             WHERE e.tenant_id = v_tenant AND e.evidence_id = ANY(v_roots)
            UNION
            SELECT 'MEMORY'::text, m.memory_id FROM private.memory_records m
              JOIN private.memory_evidence me ON me.memory_id = m.memory_id
             WHERE m.tenant_id = v_tenant AND me.evidence_id = ANY(v_roots)) t;
  END IF;
  v_hash := sha256(convert_to('humaux.deletion.manifest.v1' || chr(10), 'UTF8')
    || coalesce((SELECT string_agg(convert_to(t.kind, 'UTF8') || '\x00'::bytea || uuid_send(t.id), ''::bytea
                                   ORDER BY t.kind COLLATE "C", t.id)
                   FROM unnest(v_kinds, v_ids) AS t(kind, id)), ''::bytea));
  IF v_hash IS DISTINCT FROM v_request.manifest_hash THEN
    RAISE EXCEPTION 'deletion_request_accept: manifest_changed' USING ERRCODE = 'serialization_failure';
  END IF;
  PERFORM m.memory_id FROM private.memory_records m JOIN control.deletion_targets t ON t.id = m.memory_id
   WHERE t.tenant_id = v_tenant AND t.request_id = p_request_id AND t.kind = 'MEMORY'
     AND m.tenant_id = v_tenant ORDER BY m.memory_id FOR UPDATE OF m;

  UPDATE control.confirm_tokens SET consumed_at = clock_timestamp() WHERE confirm_token_id = v_token;
  UPDATE projection.stream_log s SET state = 'TOMBSTONED'
   WHERE s.tenant_id = v_tenant AND s.state <> 'TOMBSTONED'
     AND NOT EXISTS (SELECT 1 FROM projection.rebuild_tickets rt
                      WHERE (rt.tenant_id,rt.scope_kind,rt.scope_id,rt.domain,rt.projection_kind,rt.projection_version,rt.stream_seq)
                          = (s.tenant_id,s.scope_kind,s.scope_id,s.domain,s.projection_kind,s.projection_version,s.stream_seq))
     AND EXISTS (SELECT 1 FROM ops.outbox o JOIN control.deletion_targets t ON t.id = o.evidence_id
                  WHERE o.tenant_id = v_tenant AND o.commit_seq = s.commit_seq
                    AND t.tenant_id = v_tenant AND t.request_id = p_request_id AND t.kind = 'EVIDENCE');
  FOR v_memory IN SELECT id FROM control.deletion_targets
   WHERE tenant_id = v_tenant AND request_id = p_request_id AND kind = 'MEMORY' ORDER BY id
  LOOP
    v_event := ops.append_memory_lifecycle(v_tenant, 'MEMORY', v_memory, 'TOMBSTONE', 'USER_DELETE',
      p_principal_id, NULL, NULL, NULL, NULL, p_request_id::text || ':' || v_memory::text,
      encode(v_intent, 'hex'), NULL, NULL);
    IF v_event IS NULL THEN
      RAISE EXCEPTION 'deletion_request_accept: lifecycle_conflict' USING ERRCODE = 'serialization_failure';
    END IF;
    UPDATE private.memory_records SET status = 'revoked', superseded_by = NULL, lifecycle_head_event_id = v_event
     WHERE tenant_id = v_tenant AND memory_id = v_memory;
  END LOOP;
  UPDATE control.deletion_requests SET confirm_token_id = v_token, logical_deleted_at = clock_timestamp()
   WHERE tenant_id = v_tenant AND deletion_request_id = p_request_id;
END;
$$;
ALTER FUNCTION control.deletion_request_accept(uuid, bytea, text, bytea, uuid, uuid) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION control.deletion_request_accept(uuid, bytea, text, bytea, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.deletion_request_accept(uuid, bytea, text, bytea, uuid, uuid) TO role_gateway;
