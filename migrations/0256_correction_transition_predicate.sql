-- §46 forward-fix (EXPAND_CONTRACT, number 0256): issue #109. "This supersede is a correction" has one SQL home,
-- private.is_correction_transition, and both inheritance sites key on it: §6.1.3 rule 3b (subjects, 0154) and §6.1.4 A3'
-- (projects, 0255).
--   private.is_correction_transition(event, memory, successor)   the five-leg predicate, invoker rights
--   private.memory_subjects_on_supersede()                       0154's trigger, now guarded by the predicate and the
--                                                                one site that copies links (rule 3b moved here)
--   private.link_memory_subjects(...)                            0154's hook minus rule 3b; rules 1, 2, 3a and the
--                                                                mentions are unchanged
--   private.memory_projects_on_supersede()                       0255's A3', its inline predicate replaced by a call
--
-- Defect (#109): 0154's rule 3b copied the links of EVERY row that points at the successor whenever the SUCCESSOR's
-- PRIMARY Evidence is a USER_CORRECTION event, so it keyed on where the successor came from, not on this transition.
-- memory.supersede(X -> correction-born M2) therefore gave M2 X's links, and a restore over a correction gave a
-- correction-born M1 the links of the successor it had just retired. §6.1.3 rule ③ says an explicit supersede never
-- inherits. Design v0.2 §15.7 revision 2 fixed the same defect for A3' inside 0255; this migration gives both sites
-- the one predicate.
--
-- ① The predicate. The row in ops.memory_lifecycle_events named by the updated row's lifecycle_head_event_id (the head
--   the arbiter UPDATE stamps in the same statement that sets superseded_by) is op SUPERSEDE, reason USER_CORRECTION,
--   memory_id = the updated row and replacement_memory_id = its new superseded_by. Only correct_atomically's arbiter
--   UPDATE stamps such a head (memory_governance_repo.rs:1802); memory.supersede stamps EXPLICIT_SUPERSEDE, a restore
--   stamps RESTORE on the memory it reactivates and leaves the retired successor's head stale, and a note supersede
--   stamps nothing, so none of them is a correction (0255 ③). A NULL head matches no row, so the answer is false.
--   Invoker rights, as both callers: role_gateway, the one role that UPDATEs superseded_by (0011:300), SELECTs the event
--   table (0149:86) and gets EXECUTE here; no other role runs either trigger. LANGUAGE sql with a pinned search_path is
--   never inlined, so the SELECT privilege is checked when the function runs.
-- ② Rule 3b is one INSERT, in the trigger, behind the predicate, and copies only from NEW.memory_id, the row whose
--   superseded_by changed. It cannot stay in link_memory_subjects: that hook runs under role_private_worker at the
--   Distill door, which has no SELECT on the event table (0149:83-88) and no EXECUTE on the predicate, and keying a
--   rule inside it on the transition would need both. At a door no row points at a fresh id, so removing rule 3b from
--   the hook changes no door; every other caller of the hook after a correction (correct_atomically's explicit
--   subjects) only re-ran an idempotent copy. The trigger then calls the hook for the successor, which finishes the
--   job as before: rule 3a and the mentions, including the inherited links, in the successor's own revision.
-- ③ A non-correction transition now does nothing here. Before, it re-ran rules 1-3a and the mentions for a successor
--   that was already fully linked, an idempotent no-op.
-- ④ A3' keeps its behaviour, invoker rights and its one correction@1 literal (rls-check "§6.1.4 A3' single site"); the
--   events join stays only to read correction_evidence_id.
--
-- Locks: CREATE FUNCTION / CREATE OR REPLACE FUNCTION lock no table; the swap is atomic with this transaction, so a
-- concurrent supersede runs the old bodies or the new ones, never a mix.

CREATE FUNCTION private.is_correction_transition(p_event_id uuid, p_memory_id uuid, p_successor uuid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog
AS $$
  SELECT EXISTS (SELECT 1
                   FROM ops.memory_lifecycle_events ev
                  WHERE ev.event_id = p_event_id
                    AND ev.op = 'SUPERSEDE'
                    AND ev.reason_code = 'USER_CORRECTION'
                    AND ev.memory_id = p_memory_id
                    AND ev.replacement_memory_id = p_successor)
$$;
ALTER FUNCTION private.is_correction_transition(uuid, uuid, uuid) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION private.is_correction_transition(uuid, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.is_correction_transition(uuid, uuid, uuid) TO role_gateway;

-- ② 0154's hook without rule 3b; the rest of the body, signature and attributes are 0154's, so CREATE OR REPLACE keeps
-- the owner and ACL.
CREATE OR REPLACE FUNCTION private.link_memory_subjects(
  p_tenant_id    uuid,
  p_memory_id    uuid,
  p_subject_ids  uuid[] DEFAULT NULL,
  p_source_kinds text[] DEFAULT NULL
) RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
  v_linked integer := 0;
  v_rows integer;
BEGIN
  IF (p_subject_ids IS NULL) <> (p_source_kinds IS NULL)
     OR coalesce(array_length(p_subject_ids, 1), 0) <> coalesce(array_length(p_source_kinds, 1), 0) THEN
    RAISE EXCEPTION 'link_memory_subjects: subject/source arrays must be parallel'
      USING ERRCODE = 'invalid_parameter_value';
  END IF;

  -- Rules 1/2 (explicit, already resolved by the caller under this tenant's RLS).
  IF p_subject_ids IS NOT NULL THEN
    INSERT INTO private.memory_subjects (tenant_id, memory_id, subject_id, relation, source_kind, confidence_bp)
    SELECT p_tenant_id, p_memory_id, s.id, 'ABOUT', s.kind, 10000
      FROM unnest(p_subject_ids, p_source_kinds) AS s(id, kind)
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    v_linked := v_linked + v_rows;
  END IF;

  -- Rule 3a: the PRIMARY Evidence's declarations (INHERITED — §6.1.3 ③).
  INSERT INTO private.memory_subjects (tenant_id, memory_id, subject_id, relation, source_kind, confidence_bp)
  SELECT DISTINCT es.tenant_id, p_memory_id, es.subject_id, 'ABOUT', 'INHERITED', 10000
    FROM private.memory_evidence me
    JOIN private.evidence_subjects es
      ON es.tenant_id = p_tenant_id AND es.evidence_id = me.evidence_id
   WHERE me.memory_id = p_memory_id AND me.role = 'PRIMARY'
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS v_rows = ROW_COUNT;
  v_linked := v_linked + v_rows;

  -- Mentions: first exact byte occurrence of display_name / any key value in the stored revision.
  INSERT INTO private.memory_subject_mentions
    (tenant_id, memory_id, subject_id, revision_sha256, span_start, span_end)
  SELECT p_tenant_id, p_memory_id, hit.subject_id, sha256(rev.body),
         hit.pos - 1, hit.pos - 1 + octet_length(hit.needle)
    FROM (SELECT convert_to(m.content::text, 'UTF8') AS body
            FROM private.memory_records m
           WHERE m.tenant_id = p_tenant_id AND m.memory_id = p_memory_id) rev,
         LATERAL (
           SELECT ms.subject_id, n.needle, position(n.needle IN rev.body) AS pos
             FROM private.memory_subjects ms
             JOIN LATERAL (
               SELECT convert_to(s.display_name, 'UTF8') AS needle
                 FROM private.subjects s
                WHERE s.tenant_id = p_tenant_id AND s.subject_id = ms.subject_id
               UNION
               SELECT convert_to(k.key_value, 'UTF8')
                 FROM private.subject_keys k
                WHERE k.tenant_id = p_tenant_id AND k.subject_id = ms.subject_id
             ) n ON octet_length(n.needle) > 0
            WHERE ms.tenant_id = p_tenant_id AND ms.memory_id = p_memory_id
         ) hit
   WHERE hit.pos > 0
  ON CONFLICT DO NOTHING;

  RETURN v_linked;
END;
$$;

-- ②③ Rule 3b, keyed on the transition. Attributes are 0154's (plpgsql, invoker, no SET).
CREATE OR REPLACE FUNCTION private.memory_subjects_on_supersede() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF private.is_correction_transition(NEW.lifecycle_head_event_id, NEW.memory_id, NEW.superseded_by) THEN
    INSERT INTO private.memory_subjects (tenant_id, memory_id, subject_id, relation, source_kind, confidence_bp)
    SELECT ms.tenant_id, NEW.superseded_by, ms.subject_id, ms.relation, 'INHERITED', ms.confidence_bp
      FROM private.memory_subjects ms
     WHERE ms.tenant_id = NEW.tenant_id AND ms.memory_id = NEW.memory_id
    ON CONFLICT DO NOTHING;
    PERFORM private.link_memory_subjects(NEW.tenant_id, NEW.superseded_by);
  END IF;
  RETURN NULL;
END;
$$;

-- ④ 0255's A3', the inline predicate as a call. Attributes are 0255's (plpgsql, invoker, search_path = pg_catalog).
CREATE OR REPLACE FUNCTION private.memory_projects_on_supersede() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog
AS $$
BEGIN
  INSERT INTO private.memory_projects
    (tenant_id, memory_id, project_id, relation, source_kind, rule_id_ver, decision_evidence_id,
     inherited_from_memory_id)
  SELECT l.tenant_id, NEW.superseded_by, l.project_id, 'ATTRIBUTED_TO', 'INHERITED', 'correction@1',
         ev.correction_evidence_id, l.memory_id
    FROM ops.memory_lifecycle_events ev
    JOIN private.memory_projects_live l ON l.tenant_id = NEW.tenant_id AND l.memory_id = NEW.memory_id
   WHERE ev.event_id = NEW.lifecycle_head_event_id
     AND private.is_correction_transition(NEW.lifecycle_head_event_id, NEW.memory_id, NEW.superseded_by)
  ON CONFLICT DO NOTHING;
  RETURN NULL;
END;
$$;

COMMENT ON FUNCTION private.is_correction_transition(uuid, uuid, uuid) IS
  '§6.1.3 rule ③ / §6.1.4 A3'' (issue #109, migration 0256): true when the lifecycle event p_event_id (the updated row''s '
  'lifecycle_head_event_id) is the SUPERSEDE / USER_CORRECTION of p_memory_id into p_successor. The one home of "this '
  'transition is a correction"; both inheritance triggers call it. Invoker, STABLE, EXECUTE role_gateway only.';
COMMENT ON FUNCTION private.link_memory_subjects(uuid, uuid, uuid[], text[]) IS
  '§6.1.3 deterministic resolve hook (ADR-0028, migration 0154; rule 3b moved to memory_subjects_on_supersede by 0256): '
  'explicit DECLARED/EXTERNAL_KEY links + PRIMARY-Evidence declarations (INHERITED) + byte-span mentions over '
  'sha256(convert_to(content::text)). SECURITY INVOKER, idempotent. Sole implementation; every memory writer calls it.';
COMMENT ON FUNCTION private.memory_subjects_on_supersede() IS
  '§6.1.3 rule 3b (ADR-0028 D-E, migration 0256): when private.is_correction_transition holds for the updated row, the '
  'successor inherits that row''s links as INHERITED, then the hook re-locates mentions in the successor''s revision. '
  'An explicit supersede or a restore does nothing. Invoker.';
