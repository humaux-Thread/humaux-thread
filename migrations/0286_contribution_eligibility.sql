-- ADR-0090 D-A / ADR-0088 D-A (card M20-5, gate G-M20-5; §46 forward-fix, EXPAND_CONTRACT, number 0286): the public-pool eligibility
-- predicate over the M07 closure, and the notice scope-category vocabulary it reads.
--
--   control.contribution_notices.scope_categories   CHECK: a subset of the six phase-1 unit-type names (ADR-0090 D-B).
--   private.contribution_unit_type(note_kind)       the one home of the kind -> unit-type map; NULL = no phase-1 unit type.
--   private.contribution_eligibility(tenant, memory) the one predicate; one closed verdict, the first failure in a fixed order.
--
-- Vocabulary (lead ruling, ADR-0088 amendment of M20-5): a notice's scope categories ARE the unit-type names. A new unit type
-- (PLAYBOOK, DATA in phase 2) is a new category and so a new notice version (ADR-0088 D-A), and it widens this CHECK in that
-- phase's migration. The table is platform data written only by the migration owner and is expected empty outside tests; the
-- manifest precheck refuses to run while a row would violate the CHECK.
--
-- Verdict order (ADR-0090 D-A; the SQL text is the wire, humaux_public_pool::eligibility::EligibilityVerdict is its Rust set):
--   NOT_FOUND -> NOT_ACTIVE -> KIND_NOT_MAPPED -> NO_NOTICE -> CATEGORY_NOT_IN_NOTICE -> NO_EVIDENCE -> DATA_CLASS -> AFFECT
--   -> PERSON_OR_CUSTOMER_LINK -> ELIGIBLE.
--
--   * Closure: every private.memory_evidence row of the memory, whatever its role (the all-backing-evidence closure of §8.6, M07
--     D5). A memory is as sensitive as its most sensitive Evidence: any closure Evidence above INTERNAL fails, and so does
--     Evidence whose class cannot be read (below).
--   * Active: the lifecycle the recall gate calls current (status 'active', which G59-4 ties to superseded_by IS NULL, and
--     archived_at IS NULL); revoked, expired, superseded and archived memories are NOT_ACTIVE.
--   * Affect: any affect row on the memory, or on any closure Evidence.
--   * Link: any subject link of the memory or of any closure Evidence to a PERSON subject, or to a subject holding the CUSTOMER
--     role. An ORGANISATION, BUSINESS, BRAND, PRODUCT or WEBSITE subject without that role is not a person link: reuse needs
--     entities (ADR-0090 D-A).
--   * Applicability is never a licence (ADR-0096 D-F): the body reads neither the applicability rows (0273) nor the project
--     attribution rows (0252, 0282). A pg_get_functiondef sentinel in crates/public-pool/tests/eligibility.rs pins that.
--
-- Rights. SECURITY DEFINER owned by role_migration_owner, search_path = pg_catalog, pg_temp. The memory row is read through
-- the owner arm of the memory_records policy (0163), but private.evidence_objects has no owner arm (0163:20-40), so an
-- Evidence row the session cannot see is UNKNOWN, never skipped: it reads as DATA_CLASS (fail closed, §7.5.1), because
-- dropping it would let a hidden SENSITIVE source vanish from the closure. The sweep (M20-6) must run each candidate under its
-- author's session. Owner rights never cross tenants (the 0255 pin, as control.contribution_authorized in 0274): the tenant
-- argument must equal the session tenant, else 42501; a memory of another tenant under the session tenant is NOT_FOUND, the
-- verdict of an absent id, so the predicate is no cross-tenant existence oracle.
--
-- Grants: EXECUTE for role_gateway and role_private_worker only (the existing contribution path, 0107). M20-6 adds its own grant
-- if its job runs under another role. No public role may execute it: role_public_worker, role_public_disclosure and
-- role_retrieval_worker never read private.* (module design M20 §7). The helper is called only by the predicate and has no grant.
--
-- Locks: ADD CONSTRAINT takes ACCESS EXCLUSIVE on the empty notices table for the length of one scan; CREATE FUNCTION locks no
-- table.

ALTER TABLE control.contribution_notices
  ADD CONSTRAINT contribution_notices_scope_categories_unit_types_check
  CHECK (scope_categories <@ ARRAY['FIX', 'DECISION', 'RESEARCH', 'USAGE', 'CHECKLIST', 'FAILURE_CASE']::text[]);

-- ponytail: three kinds mapped; USAGE/CHECKLIST/FAILURE_CASE need a source kind (M07/M15), add rows with a contract test
CREATE FUNCTION private.contribution_unit_type(p_note_kind text) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE
RETURN CASE p_note_kind
  WHEN 'fix' THEN 'FIX'
  WHEN 'decision' THEN 'DECISION'
  WHEN 'research' THEN 'RESEARCH'
END;

CREATE FUNCTION private.contribution_eligibility(p_tenant_id uuid, p_memory_id uuid) RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_status text;
  v_archived timestamptz;
  v_note_kind text;
  v_unit text;
  v_notice integer;
  v_closure uuid[];
BEGIN
  IF p_tenant_id IS NULL
     OR p_tenant_id IS DISTINCT FROM NULLIF(current_setting('humaux.tenant_id', true), '')::uuid THEN
    RAISE EXCEPTION 'tenant_context_mismatch' USING ERRCODE = '42501';
  END IF;

  SELECT m.status, m.archived_at, m.note_kind INTO v_status, v_archived, v_note_kind
    FROM private.memory_records m
   WHERE m.tenant_id = p_tenant_id AND m.memory_id = p_memory_id;
  IF NOT FOUND THEN
    RETURN 'NOT_FOUND';
  END IF;
  IF v_status <> 'active' OR v_archived IS NOT NULL THEN
    RETURN 'NOT_ACTIVE';
  END IF;

  v_unit := private.contribution_unit_type(v_note_kind);
  IF v_unit IS NULL THEN
    RETURN 'KIND_NOT_MAPPED';
  END IF;
  v_notice := control.current_contribution_notice();
  IF v_notice IS NULL THEN
    RETURN 'NO_NOTICE';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM control.contribution_notices n
                  WHERE n.notice_version = v_notice AND v_unit = ANY (n.scope_categories)) THEN
    RETURN 'CATEGORY_NOT_IN_NOTICE';
  END IF;

  SELECT coalesce(array_agg(me.evidence_id), ARRAY[]::uuid[]) INTO v_closure
    FROM private.memory_evidence me
   WHERE me.memory_id = p_memory_id;
  IF cardinality(v_closure) = 0 THEN
    RETURN 'NO_EVIDENCE';
  END IF;
  IF EXISTS (SELECT 1
               FROM unnest(v_closure) AS c(evidence_id)
               LEFT JOIN private.evidence_objects eo
                 ON eo.tenant_id = p_tenant_id AND eo.evidence_id = c.evidence_id
              WHERE eo.data_class IS NULL OR eo.data_class NOT IN ('PUBLIC', 'INTERNAL')) THEN
    RETURN 'DATA_CLASS';
  END IF;
  IF EXISTS (SELECT 1 FROM private.memory_affects a
              WHERE a.tenant_id = p_tenant_id AND a.memory_id = p_memory_id)
     OR EXISTS (SELECT 1 FROM private.evidence_affects ea
                 WHERE ea.tenant_id = p_tenant_id AND ea.evidence_id = ANY (v_closure)) THEN
    RETURN 'AFFECT';
  END IF;
  IF EXISTS (SELECT 1
               FROM (SELECT ms.subject_id FROM private.memory_subjects ms
                      WHERE ms.tenant_id = p_tenant_id AND ms.memory_id = p_memory_id
                     UNION
                     SELECT mm.subject_id FROM private.memory_subject_mentions mm
                      WHERE mm.tenant_id = p_tenant_id AND mm.memory_id = p_memory_id
                     UNION
                     SELECT es.subject_id FROM private.evidence_subjects es
                      WHERE es.tenant_id = p_tenant_id AND es.evidence_id = ANY (v_closure)) l
               JOIN private.subjects s
                 ON s.tenant_id = p_tenant_id AND s.subject_id = l.subject_id
              WHERE s.kind = 'PERSON'
                 OR EXISTS (SELECT 1 FROM private.subject_roles r
                             WHERE r.tenant_id = p_tenant_id AND r.subject_id = s.subject_id AND r.role = 'CUSTOMER')) THEN
    RETURN 'PERSON_OR_CUSTOMER_LINK';
  END IF;
  RETURN 'ELIGIBLE';
END;
$$;

ALTER FUNCTION private.contribution_unit_type(text) OWNER TO role_migration_owner;
ALTER FUNCTION private.contribution_eligibility(uuid, uuid) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION private.contribution_unit_type(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION private.contribution_eligibility(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.contribution_eligibility(uuid, uuid) TO role_gateway, role_private_worker;

COMMENT ON FUNCTION private.contribution_unit_type(text) IS
  'ADR-0090 D-A (migration 0286, M20-5): the one kind -> unit-type map of phase 1. fix -> FIX, decision -> DECISION, research -> RESEARCH; '
  'every other note kind and a non-note memory (NULL) -> NULL. Only the eligibility predicate calls it; no grant.';
COMMENT ON FUNCTION private.contribution_eligibility(uuid, uuid) IS
  'ADR-0090 D-A (migration 0286, M20-5, G-M20-5): the sole public-pool eligibility predicate over the M07 closure. One closed '
  'verdict, the first failure of NOT_FOUND, NOT_ACTIVE, KIND_NOT_MAPPED, NO_NOTICE, CATEGORY_NOT_IN_NOTICE, NO_EVIDENCE, DATA_CLASS, AFFECT, '
  'PERSON_OR_CUSTOMER_LINK, else ELIGIBLE. Applicability and attribution rows are never read (ADR-0096 D-F). Tenant argument must be the '
  'session tenant (42501). Owner SECURITY DEFINER, EXECUTE role_gateway and role_private_worker only.';
