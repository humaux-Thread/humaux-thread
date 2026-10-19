-- §6.1.4 / ADR-0078 D-C (card M29 T06d; §46 forward-fix, EXPAND_CONTRACT, number 0253): provenance integrity of the
-- three 0249 relation tables, closing the five 0249 gaps of design v0.2 §15.2 (with §15.5's ruling on principals).
-- One loop applies the per-table constraints; the shared guard and one new predicate carry the rest.
--
-- Invariants:
--   ① authorization_evidence_id is a real composite FK (tenant_id, authorization_evidence_id) ->
--     private.evidence_objects (tenant_id, evidence_id), NO ACTION like 0251's. RI bypasses RLS, so "exists" here is
--     existence in the tenant.
--   ② every factual_evidence_ids element is a distinct Evidence of the row's tenant: checked by the shared guard
--     with invoker rights under RLS, so "exists" there means "visible to the writer". A missing, foreign-tenant,
--     invisible or repeated id is 23503 (the FK's own code), which relation_repo maps to INVALID_INPUT.
--   ③ decided_by = 'principal:<uuid>' must resolve to a live member of the row's tenant: an ACTIVE
--     control.memberships row whose control.users row and control.tenants row are ACTIVE too (the
--     contribution_entry_repo liveness rule, design v0.2 §15.5). The uuid is that user (user session), or a key of
--     this tenant that is not revoked and is bound to that user (PAT; the gateway PrincipalId is the api_key_id); a
--     machine key (user_id NULL) resolves to no user and never decides. private.relation_principal_is_member answers
--     it as an owner SECURITY DEFINER (0137 / 0188 shape) so role_gateway needs no grant on control.*. Refusal is
--     23503. 'rule:' values are not checked here.
--   ④ authorization evidence is not also factual evidence: <pair>_authorization_not_factual CHECK.
--   ⑤ workspace visibility of both endpoints is the caller's job before append_revision (coord.tasks has no
--     workspace column); nothing here checks it.
--   The guard keeps 0252's body byte for byte (NULL-tenant line first) and adds ② and ③ right after that line.
--
-- ponytail: ② is a write-time check only; an Evidence later hidden or purged stays named in factual_evidence_ids
--   (no per-element FK). Upgrade: a factual-evidence link table with a real composite FK.
-- ponytail: ③ judges the decider's liveness at write time only; a member later revoked, removed or suspended leaves
--   the earlier revisions as they were (append-only). Upgrade: a read-side liveness re-check for any consumer that
--   needs "decided by a member who is live now".
--
-- Locks, all held until COMMIT: each ADD CONSTRAINT ... FOREIGN KEY takes SHARE ROW EXCLUSIVE on its relation table
-- and on private.evidence_objects, which blocks Evidence INSERTs (remember.put) for the rest of this migration's
-- transaction; each ADD CONSTRAINT ... CHECK takes ACCESS EXCLUSIVE on its relation table; each CREATE INDEX takes
-- SHARE on its relation table. The relation tables are small (no runtime writer yet).

-- ③ (design v0.2 §15.5). Owner rights read control.memberships / control.api_keys / control.tenants through 0112's
-- owner SELECT policies, which admit every tenant (control.users has no RLS), so the passed tenant must equal the session tenant (the 0186 header's 0176
-- lesson): otherwise false, never a cross-tenant membership oracle.
-- The key leg defines what a credential-id decider *means* (the key's user), not an access barrier: naming that
-- member's user id passes as well, so refusing a key here never keeps its user out.
-- ponytail: a key's liveness is revoked_at only; status and expires_at are not consulted. Upgrade: add them here
--   once a key can be expired or non-ACTIVE while revoked_at stays NULL and still reach the gateway.
CREATE FUNCTION private.relation_principal_is_member(p_tenant_id uuid, p_principal_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
AS $$
  SELECT coalesce(p_tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid, false)
     AND EXISTS (SELECT 1 FROM control.memberships m
                   JOIN control.users u ON u.user_id = m.user_id
                   JOIN control.tenants t ON t.tenant_id = m.tenant_id
                  WHERE m.tenant_id = p_tenant_id
                    AND m.state = 'ACTIVE'
                    AND t.state = 'ACTIVE'
                    AND m.user_id IN (SELECT p_principal_id
                                      UNION ALL
                                      SELECT k.user_id FROM control.api_keys k
                                       WHERE k.api_key_id = p_principal_id
                                         AND k.tenant_id = p_tenant_id
                                         AND k.revoked_at IS NULL))
$$;
ALTER FUNCTION private.relation_principal_is_member(uuid, uuid) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION private.relation_principal_is_member(uuid, uuid) FROM PUBLIC;
-- The guard runs with the inserting role's rights; role_gateway is the one INSERT holder (§6.2.2).
GRANT EXECUTE ON FUNCTION private.relation_principal_is_member(uuid, uuid) TO role_gateway;
COMMENT ON FUNCTION private.relation_principal_is_member(uuid, uuid) IS
  '§6.1.4 / design v0.2 §15.5: true iff p_tenant_id is the session tenant and p_principal_id (a user id, or a non-revoked api_key_id of that tenant) resolves to an ACTIVE user with an ACTIVE membership in it, the tenant being ACTIVE. Called by private.relation_revision_guard. M29 T06d.';

-- ② and ③ after 0252's NULL-tenant line; one new variable; everything else is 0252's body. CREATE OR REPLACE keeps
-- owner and ACL.
CREATE OR REPLACE FUNCTION private.relation_revision_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog
AS $$
DECLARE
  v_src_kind text := TG_ARGV[0];
  v_dst_kind text := TG_ARGV[1];
  v_prev_src uuid;
  v_prev_dst uuid;
  v_prev_kind text;
  v_rows bigint;
  v_principal uuid;
BEGIN
  IF NEW.tenant_id IS NULL THEN RAISE EXCEPTION '%: no tenant context', TG_TABLE_NAME USING ERRCODE = '42501'; END IF;
  IF (SELECT count(*) FROM private.evidence_objects e
       WHERE e.tenant_id = NEW.tenant_id AND e.evidence_id = ANY (NEW.factual_evidence_ids))
     <> cardinality(NEW.factual_evidence_ids) THEN
    RAISE EXCEPTION '%: factual evidence must be distinct Evidence visible in this tenant', TG_TABLE_NAME
      USING ERRCODE = '23503';
  END IF;
  -- The cast is its own statement, after pg_input_is_valid: a malformed uuid leaves v_principal NULL (refused below)
  -- instead of raising 22P02.
  IF NEW.decided_by LIKE 'principal:%' THEN
    IF pg_input_is_valid(substr(NEW.decided_by, 11), 'uuid') THEN
      v_principal := substr(NEW.decided_by, 11)::uuid;
    END IF;
    IF NOT private.relation_principal_is_member(NEW.tenant_id, v_principal) THEN
      RAISE EXCEPTION '%: decided_by is not a live member of this tenant', TG_TABLE_NAME USING ERRCODE = '23503';
    END IF;
  END IF;
  IF TG_ARGV[0] = 'SUBJECT' THEN
    SELECT s.kind INTO v_src_kind FROM private.subjects s
     WHERE s.tenant_id = NEW.tenant_id AND s.subject_id = NEW.src_id;
  END IF;
  IF TG_ARGV[1] = 'SUBJECT' THEN
    SELECT s.kind INTO v_dst_kind FROM private.subjects s
     WHERE s.tenant_id = NEW.tenant_id AND s.subject_id = NEW.dst_id;
  END IF;
  IF v_src_kind IS NULL OR v_dst_kind IS NULL THEN
    RAISE EXCEPTION '%: relation endpoint not found', TG_TABLE_NAME USING ERRCODE = '23503';
  END IF;
  IF NOT private.relation_triple_allowed(v_src_kind, NEW.relation_kind, v_dst_kind) THEN
    RAISE EXCEPTION '%: (%, %, %) is not a whitelisted relation triple',
      TG_TABLE_NAME, v_src_kind, NEW.relation_kind, v_dst_kind
      USING ERRCODE = '23514', CONSTRAINT = 'relation_whitelist';
  END IF;
  IF NEW.revision > 1 THEN
    EXECUTE format('SELECT src_id, dst_id, relation_kind FROM %I.%I '
                   'WHERE tenant_id = $1 AND relation_id = $2 AND revision = $3',
                   TG_TABLE_SCHEMA, TG_TABLE_NAME)
       INTO v_prev_src, v_prev_dst, v_prev_kind
      USING NEW.tenant_id, NEW.relation_id, NEW.revision - 1;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows = 0 THEN
      RAISE EXCEPTION '%: revision % of relation % has no predecessor', TG_TABLE_NAME, NEW.revision, NEW.relation_id
        USING ERRCODE = '23514', CONSTRAINT = 'relation_revision_contiguous';
    END IF;
    IF (v_prev_src, v_prev_dst, v_prev_kind) IS DISTINCT FROM (NEW.src_id, NEW.dst_id, NEW.relation_kind) THEN
      RAISE EXCEPTION '%: a revision may not change the edge of relation %', TG_TABLE_NAME, NEW.relation_id
        USING ERRCODE = '23514', CONSTRAINT = 'relation_edge_immutable';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

-- ① and ④, one loop over the three 0249 tables.
DO $provenance$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['project_task_relations', 'project_subject_relations', 'subject_relations'] LOOP
    EXECUTE format('ALTER TABLE private.%1$I ADD CONSTRAINT %1$s_authorization_evidence_fkey FOREIGN KEY (tenant_id, authorization_evidence_id) REFERENCES private.evidence_objects (tenant_id, evidence_id)', t);
    EXECUTE format('ALTER TABLE private.%1$I ADD CONSTRAINT %1$s_authorization_not_factual CHECK (NOT (authorization_evidence_id = ANY (factual_evidence_ids)))', t);
    -- The FK's referencing-side lookup path (as 0249 does for src / dst).
    EXECUTE format('CREATE INDEX %1$s_authorization_evidence_idx ON private.%1$I (tenant_id, authorization_evidence_id)', t);
  END LOOP;
END
$provenance$;
