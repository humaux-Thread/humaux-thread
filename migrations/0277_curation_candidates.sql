-- §6.1.4 / §11.6 / ADR-0113: candidate-only storage; acceptance never applies M07 verbs.
CREATE TABLE private.curation_candidates (
  candidate_id uuid PRIMARY KEY DEFAULT uuidv7(),
  tenant_id uuid NOT NULL REFERENCES control.tenants(tenant_id) ON DELETE CASCADE,
  workspace_id uuid NOT NULL,
  proposed_by text NOT NULL CHECK (proposed_by ~ '^(rule|model):[^@[:space:]]+@[^@[:space:]]+$'),
  kind text NOT NULL CONSTRAINT curation_candidate_kind CHECK (kind IN
    ('DUPLICATE_GROUP','CONTRADICTION','TEMPORAL_CHANGE','STALE','REPEATED_QUESTION',
     'RULE_PROPOSAL','LESSON_DRAFT','FOLLOW_UP_PLAN','PROFILE_SLOT')),
  payload_hash bytea NOT NULL CHECK (octet_length(payload_hash)=32),
  score double precision NOT NULL CHECK (score BETWEEN 0 AND 1),
  state text NOT NULL DEFAULT 'PROPOSED' CONSTRAINT curation_candidate_state
    CHECK (state IN ('PROPOSED','ACCEPTED','REJECTED','EXPIRED','STALE')),
  UNIQUE (tenant_id,workspace_id,candidate_id),
  FOREIGN KEY (tenant_id,workspace_id) REFERENCES control.workspaces(tenant_id,workspace_id) ON DELETE CASCADE
);
CREATE TABLE private.curation_candidate_targets (
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  candidate_id uuid NOT NULL,
  memory_id uuid NOT NULL,
  status_at_propose text NOT NULL,
  lifecycle_head_at_propose uuid,
  PRIMARY KEY (candidate_id,memory_id),
  FOREIGN KEY (tenant_id,workspace_id,candidate_id)
    REFERENCES private.curation_candidates(tenant_id,workspace_id,candidate_id) ON DELETE CASCADE
);
-- §6.2.2: both tables use the same tenant/workspace boundary and grant pattern.
ALTER TABLE private.curation_candidates OWNER TO role_migration_owner;
ALTER TABLE private.curation_candidate_targets OWNER TO role_migration_owner;
ALTER TABLE private.curation_candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.curation_candidates FORCE ROW LEVEL SECURITY;
ALTER TABLE private.curation_candidate_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.curation_candidate_targets FORCE ROW LEVEL SECURITY;
CREATE POLICY curation_candidates_scope ON private.curation_candidates
  USING (tenant_id=NULLIF(current_setting('humaux.tenant_id',true),'')::uuid
    AND workspace_id=NULLIF(current_setting('humaux.candidate_workspace_id',true),'')::uuid)
  WITH CHECK (tenant_id=NULLIF(current_setting('humaux.tenant_id',true),'')::uuid
    AND workspace_id=NULLIF(current_setting('humaux.candidate_workspace_id',true),'')::uuid);
CREATE POLICY curation_candidate_targets_scope ON private.curation_candidate_targets
  USING (tenant_id=NULLIF(current_setting('humaux.tenant_id',true),'')::uuid
    AND workspace_id=NULLIF(current_setting('humaux.candidate_workspace_id',true),'')::uuid)
  WITH CHECK (tenant_id=NULLIF(current_setting('humaux.tenant_id',true),'')::uuid
    AND workspace_id=NULLIF(current_setting('humaux.candidate_workspace_id',true),'')::uuid);
REVOKE ALL ON private.curation_candidates,private.curation_candidate_targets
  FROM PUBLIC,role_gateway,role_private_worker,role_consolidation_worker,role_public_worker,
       role_retrieval_worker,role_batch_issuer,role_maintenance,role_admin;
GRANT SELECT ON private.curation_candidates,private.curation_candidate_targets TO role_gateway;

-- §78.2: one SQL transition predicate, reconciled against the complete Rust Cartesian product.
CREATE FUNCTION private.curation_transition_allowed(p_from text,p_to text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
  SELECT p_from='PROPOSED' AND p_to IN ('ACCEPTED','REJECTED','EXPIRED')
$$;
ALTER FUNCTION private.curation_transition_allowed(text,text) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION private.curation_transition_allowed(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.curation_transition_allowed(text,text) TO role_gateway;

-- §6.1.4: session identity is authoritative; target revisions are captured under row locks.
CREATE FUNCTION private.propose_curation_candidate(p_key uuid,p_workspace uuid,p_proposed_by text,
  p_kind text,p_hash bytea,p_score double precision,p_targets uuid[]) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
  v_tenant uuid := NULLIF(current_setting('humaux.tenant_id',true),'')::uuid;
  v_user uuid := NULLIF(current_setting('humaux.user_id',true),'')::uuid;
  v_id uuid;
  v_target uuid;
  v_status text;
  v_head uuid;
BEGIN
  PERFORM control.assert_write_scope(p_key,p_workspace);
  PERFORM set_config('humaux.candidate_workspace_id',p_workspace::text,true);
  IF p_targets IS NULL OR cardinality(p_targets)=0 OR array_position(p_targets,NULL) IS NOT NULL
     OR cardinality(p_targets)<>(SELECT count(DISTINCT x) FROM unnest(p_targets) x) THEN
    RAISE EXCEPTION 'candidate_targets_invalid' USING ERRCODE='22023';
  END IF;
  INSERT INTO private.curation_candidates(tenant_id,workspace_id,proposed_by,kind,payload_hash,score)
    VALUES(v_tenant,p_workspace,p_proposed_by,p_kind,p_hash,p_score) RETURNING candidate_id INTO v_id;
  FOR v_target IN SELECT x FROM unnest(p_targets) x ORDER BY x LOOP
    SELECT m.status,m.lifecycle_head_event_id INTO v_status,v_head FROM private.memory_records m
      WHERE m.tenant_id=v_tenant AND m.memory_id=v_target
        AND private.visibility_allowed(m.visibility_class,true,m.visibility_user_id=v_user,
                                      m.visibility_workspace_id=p_workspace)
      FOR SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'candidate_target_unavailable' USING ERRCODE='42501';
    END IF;
    INSERT INTO private.curation_candidate_targets
      (tenant_id,workspace_id,candidate_id,memory_id,status_at_propose,lifecycle_head_at_propose)
      VALUES(v_tenant,p_workspace,v_id,v_target,v_status,v_head);
  END LOOP;
  RETURN v_id;
END;
$$;

-- §11.6: mismatch raises and rolls back everything; acceptance changes only candidate.state.
CREATE FUNCTION private.decide_curation_candidate(p_key uuid,p_workspace uuid,p_id uuid,
  p_hash bytea,p_state text) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
  v_tenant uuid := NULLIF(current_setting('humaux.tenant_id',true),'')::uuid;
  v_candidate private.curation_candidates%ROWTYPE;
  v_target private.curation_candidate_targets%ROWTYPE;
  v_memory private.memory_records%ROWTYPE;
BEGIN
  PERFORM control.assert_write_scope(p_key,p_workspace);
  PERFORM set_config('humaux.candidate_workspace_id',p_workspace::text,true);
  IF NOT EXISTS (SELECT 1 FROM control.api_keys k WHERE k.api_key_id=p_key
    AND k.tenant_id=v_tenant AND k.user_id=NULLIF(current_setting('humaux.user_id',true),'')::uuid) THEN
    RAISE EXCEPTION 'candidate_user_required' USING ERRCODE='42501';
  END IF;
  SELECT * INTO v_candidate FROM private.curation_candidates
    WHERE tenant_id=v_tenant AND workspace_id=p_workspace AND candidate_id=p_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'candidate_unavailable' USING ERRCODE='42501';
  END IF;
  IF NOT COALESCE(private.curation_transition_allowed(v_candidate.state,p_state),false) THEN
    RAISE EXCEPTION 'candidate_transition_invalid' USING ERRCODE='22023';
  END IF;
  IF p_state='ACCEPTED' THEN
    IF v_candidate.payload_hash IS DISTINCT FROM p_hash THEN
      RAISE EXCEPTION 'candidate_stale_payload' USING ERRCODE='40001';
    END IF;
    FOR v_target IN SELECT * FROM private.curation_candidate_targets
      WHERE candidate_id=p_id ORDER BY memory_id LOOP
      SELECT * INTO v_memory FROM private.memory_records
        WHERE tenant_id=v_tenant AND memory_id=v_target.memory_id
          AND private.visibility_allowed(visibility_class,true,
            visibility_user_id=NULLIF(current_setting('humaux.user_id',true),'')::uuid,
            visibility_workspace_id=p_workspace) FOR SHARE;
      IF NOT FOUND OR v_memory.status IS DISTINCT FROM v_target.status_at_propose
         OR NOT (v_memory.lifecycle_head_event_id IS NOT DISTINCT FROM v_target.lifecycle_head_at_propose) THEN
        RAISE EXCEPTION 'candidate_stale_target' USING ERRCODE='40001';
      END IF;
    END LOOP;
  END IF;
  UPDATE private.curation_candidates SET state=p_state WHERE candidate_id=p_id;
  RETURN p_state;
END;
$$;
ALTER FUNCTION private.propose_curation_candidate(uuid,uuid,text,text,bytea,double precision,uuid[]) OWNER TO role_migration_owner;
ALTER FUNCTION private.decide_curation_candidate(uuid,uuid,uuid,bytea,text) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION private.propose_curation_candidate(uuid,uuid,text,text,bytea,double precision,uuid[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION private.decide_curation_candidate(uuid,uuid,uuid,bytea,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.propose_curation_candidate(uuid,uuid,text,text,bytea,double precision,uuid[]) TO role_gateway;
GRANT EXECUTE ON FUNCTION private.decide_curation_candidate(uuid,uuid,uuid,bytea,text) TO role_gateway;
