-- ADR-0067 D3 / Baseline §8.5, §34.0.1 (card M06-3; §46 forward-fix, EXPAND_CONTRACT, number 0269): exact-duplicate
-- identity notes from different agents collapse onto one Memory.
--
-- Invariants:
--   ① D3's key is (tenant, owner, visibility scope, note_kind, body SHA-256) with an active head. A note row stores no
--      separate owner column: in this lane the owner leg is the visibility user (`USER_PRIVATE` visibility_user_id), and a
--      wider class is owned by its workspace/tenant scope, so the index is the D3 tuple over the columns the lane already
--      stores. The body digest is `private.identity_note_body_sha256(content)`, which is byte-identical to
--      `private.identity_note_materializations.body_sha256` for a note written by `note_put` (the M06-3 test asserts it).
--      The function exists because `convert_to` is not marked IMMUTABLE, so the expression cannot be indexed directly;
--      it is a pure `LANGUAGE sql` over `jsonb`/text (no relation read) and fixes the destination encoding to UTF8.
--   ② The index keys a note's FIRST version only (`note_id = memory_id`). A replacement version is a deliberate new version
--      and must not collide with the version it supersedes; the advisory lock in `operation_receipt` is the primary
--      serializer, this UNIQUE is the backstop against two concurrent creates (both are first versions).
--   ③ The partial predicate is an active, unarchived head: `status='active' AND archived_at IS NULL AND note_kind IS NOT
--      NULL AND note_id = memory_id`. A forgotten/archived note leaves the key, so its body may be written again.
--   ④ NULLS NOT DISTINCT: two `WORKSPACE_SHARED` notes have visibility_user_id NULL and must still collide on the same
--      workspace; plain UNIQUE treats NULLs as distinct and would never be a backstop for them.
--
--   ⑤ control.check_operation_receipt (0114, amended by 0265) requires the receipt's Evidence to name its own principal,
--      or to be a sourced Evidence owned by the receipt's user. A second agent's exact-duplicate note receipt points at the
--      FIRST agent's note Evidence, so the 0265 predicate refuses it. The amendment adds one OR: the same tenant has an
--      identity-note contract for that Evidence whose Memory is an active first-version note visible to the receipt's user
--      under the trigger's own invoker RLS (`memory_records` visibility policy + 0155/0163; `identity_note_materializations`
--      parent policy). No grant change beyond the new helper's EXECUTE for the two Memory writers.
--
-- Locks: CREATE UNIQUE INDEX holds SHARE on private.memory_records while it builds (Memory INSERTs wait); a duplicate key
-- aborts the migration, so the precheck refuses one first. Two claims are no more expensive than an ordinary Memory insert.

CREATE FUNCTION private.identity_note_body_sha256(p_content jsonb)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog
RETURN sha256(convert_to(p_content->>'key_claim', 'UTF8'));

ALTER FUNCTION private.identity_note_body_sha256(jsonb) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION private.identity_note_body_sha256(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.identity_note_body_sha256(jsonb) TO role_gateway, role_private_worker;

COMMENT ON FUNCTION private.identity_note_body_sha256(jsonb) IS
  'ADR-0067 D3 (M06-3): SHA-256 of a note Memory''s body text (content->>''key_claim''), immutable so the 0269 UNIQUE index can key it. Equals identity_note_materializations.body_sha256; destination encoding fixed to UTF8. Not a general-purpose hash door.';

CREATE UNIQUE INDEX memory_records_identity_note_exact_key
  ON private.memory_records (
    tenant_id,
    visibility_class,
    visibility_user_id,
    visibility_workspace_id,
    note_kind,
    private.identity_note_body_sha256(content)
  )
  NULLS NOT DISTINCT
  WHERE status = 'active' AND archived_at IS NULL AND note_kind IS NOT NULL AND note_id = memory_id;

COMMENT ON INDEX private.memory_records_identity_note_exact_key IS
  'ADR-0067 D3 (M06-3): one active first-version identity note per (tenant, visibility scope, note_kind, body SHA-256). The backstop of the note advisory lock in adapters::operation_receipt; a replacement head is excluded by note_id = memory_id.';

CREATE OR REPLACE FUNCTION control.check_operation_receipt() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, control, private, projection, ops
AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF OLD.evidence_id IS NOT NULL AND NEW.evidence_id IS NULL
       AND (to_jsonb(NEW) - 'evidence_id') = (to_jsonb(OLD) - 'evidence_id')
       AND NOT EXISTS (SELECT 1 FROM private.evidence_objects WHERE evidence_id=OLD.evidence_id) THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION 'operation receipts are immutable' USING ERRCODE='23514';
  END IF;
  NEW.committed_at := clock_timestamp();
  IF NEW.evidence_id IS NULL
     -- Retain scalar historical routing after workspace deletion. A lifetime FK
     -- would block that deletion; prove the current tenant/workspace at insertion.
     OR (NEW.scope_kind='workspace' AND NOT EXISTS (
       SELECT 1 FROM control.workspaces w
       WHERE w.tenant_id=NEW.tenant_id AND w.workspace_id=NEW.workspace_id
     ))
     OR COALESCE(NEW.user_id, '00000000-0000-0000-0000-000000000000'::uuid)
        IS DISTINCT FROM NULLIF(current_setting('humaux.user_id', true), '')::uuid
     OR NOT EXISTS (
       SELECT 1 FROM control.usage_reservations r
       WHERE r.reservation_id=NEW.reservation_id AND r.tenant_id=NEW.tenant_id
         AND r.principal_id=NEW.principal_id AND r.request_id=NEW.request_id
         AND r.operation=NEW.operation AND r.request_fingerprint=NEW.request_fingerprint
         AND r.status='CONSUMED' AND r.units=1 AND r.finished_at IS NOT NULL
     ) THEN
    RAISE EXCEPTION 'receipt requires the matching consumed reservation' USING ERRCODE='23514';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM private.evidence_objects e
    JOIN ops.outbox o ON o.tenant_id=e.tenant_id AND o.evidence_id=e.evidence_id
    JOIN projection.stream_log s ON s.tenant_id=o.tenant_id AND s.commit_seq=o.commit_seq
    WHERE e.evidence_id=NEW.evidence_id AND e.tenant_id=NEW.tenant_id
      AND ((e.origin_principal_id=NEW.principal_id AND e.origin_class='AuthenticatedAgent')
           OR EXISTS (SELECT 1 FROM private.evidence_sources src
                      WHERE src.tenant_id=e.tenant_id AND src.evidence_id=e.evidence_id
                        AND src.owner_user_id=NEW.user_id)
           OR EXISTS (SELECT 1 FROM private.identity_note_materializations n
                      JOIN private.memory_records m
                        ON m.tenant_id=n.tenant_id AND m.memory_id=n.output_memory_id
                      WHERE n.tenant_id=e.tenant_id AND n.evidence_id=e.evidence_id
                        AND m.note_kind IS NOT NULL AND m.note_id=m.memory_id
                        AND m.status='active' AND m.archived_at IS NULL))
      AND o.event_type='EVIDENCE_ACCEPTED' AND o.commit_seq=NEW.commit_seq
      AND s.scope_kind=NEW.scope_kind AND s.scope_id=NEW.scope_id AND s.domain=NEW.domain
      AND s.projection_kind=NEW.projection_kind AND s.projection_version=NEW.projection_version
      AND s.stream_seq=NEW.stream_seq AND s.state<>'TOMBSTONED'
  ) OR NOT EXISTS (
    SELECT 1 FROM control.audit_events a
    WHERE a.audit_event_id=NEW.audit_event_id AND a.tenant_id=NEW.tenant_id
      AND a.actor_id=NEW.principal_id::text AND a.action='MCP_REQUEST_FINISHED'
      AND a.resource_id=NEW.operation AND a.result='OK' AND a.request_id=NEW.request_id::text
  ) THEN
    RAISE EXCEPTION 'receipt requires matching committed business and audit references' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$;
