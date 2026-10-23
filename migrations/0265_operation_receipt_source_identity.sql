-- ADR-0098 D3 / Baseline §34.0.1, §8.7 (card M06-1b; §46 forward-fix, EXPAND_CONTRACT): amends
-- control.check_operation_receipt (0114) so a receipt may point at an Evidence its principal did not originate when that
-- Evidence carries a source identity owned by the receipt's user.
--
-- Invariants:
--   ① the 0114 predicate is kept verbatim (origin principal = receipt principal AND origin class AuthenticatedAgent); the
--     amendment is one OR beside it: an evidence_sources row for NEW's evidence whose owner_user_id = NEW.user_id, in the
--     same tenant. Every other clause of the trigger is unchanged.
--   ② the OR is what lets a second agent's dedupe-hit receipt (the Evidence names the first agent) and every Email, Chat
--     and Calendar write (origin class ExternalContent, ADR-0098 D2) be receipted. A NULL NEW.user_id matches no owner.
--   ③ the new read runs as the invoker under FORCE RLS on tenant AND owner (humaux.user_id, which the receipt check above
--     already pins to NEW.user_id), so no grant is added or widened.
--
-- CREATE OR REPLACE FUNCTION only: owner, EXECUTE revocation and the trigger binding of 0114 stay as they are; no table
-- is rewritten and no lock beyond the function's catalog row is taken.

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
                        AND src.owner_user_id=NEW.user_id))
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
