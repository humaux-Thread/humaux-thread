-- §6.1.1 / §78.2; ADR-0096 D-A/D-B.1. Applicability never grants visibility.
CREATE TABLE private.memory_applicability (
  tenant_id uuid NOT NULL,
  memory_id uuid PRIMARY KEY,
  scope text NOT NULL CONSTRAINT memory_applicability_scope_check
    CHECK (scope IN ('PRODUCT_SPECIFIC','CHANNEL_GENERIC','UNIVERSAL')),
  product_subject_id uuid,
  channel_key text,
  qualifiers jsonb NOT NULL,
  status text NOT NULL CONSTRAINT memory_applicability_status_check
    CHECK (status IN ('PROPOSED','APPROVED','REJECTED')),
  assignment_method text CONSTRAINT memory_applicability_method_check
    CHECK (assignment_method IN ('OWNER_CONSOLE','AGENT_ON_OWNER_CHAT')),
  decision_evidence_id uuid,
  FOREIGN KEY (tenant_id,memory_id) REFERENCES private.memory_records(tenant_id,memory_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,product_subject_id) REFERENCES private.subjects(tenant_id,subject_id),
  FOREIGN KEY (tenant_id,decision_evidence_id) REFERENCES private.evidence_objects(tenant_id,evidence_id),
  CONSTRAINT memory_applicability_keys_check CHECK (
    (scope='PRODUCT_SPECIFIC' AND product_subject_id IS NOT NULL AND channel_key IS NULL)
    OR (scope='CHANNEL_GENERIC' AND product_subject_id IS NULL AND channel_key IS NOT NULL
        AND channel_key ~ '^[a-z0-9][a-z0-9_]*$')
    OR (scope='UNIVERSAL' AND product_subject_id IS NULL AND channel_key IS NULL)),
  CONSTRAINT memory_applicability_decision_check CHECK (
    (status='PROPOSED' AND assignment_method IS NULL AND decision_evidence_id IS NULL)
    OR (status IN ('APPROVED','REJECTED') AND assignment_method IS NOT NULL AND decision_evidence_id IS NOT NULL)),
  CONSTRAINT memory_applicability_qualifiers_check CHECK (
    jsonb_typeof(qualifiers)='object'
    AND qualifiers ?& ARRAY['implementation_languages','exclusions']
    AND qualifiers - ARRAY['implementation_languages','exclusions'] = '{}'::jsonb
    AND jsonb_typeof(qualifiers->'implementation_languages')='array'
    AND jsonb_typeof(qualifiers->'exclusions')='array'
    AND NOT jsonb_path_exists(qualifiers, '$.implementation_languages[*] ? (@.type() != "string")')
    AND NOT jsonb_path_exists(qualifiers, '$.exclusions[*] ? (@.type() != "string")'))
);
ALTER TABLE private.memory_applicability OWNER TO role_migration_owner;
ALTER TABLE private.memory_applicability ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.memory_applicability FORCE ROW LEVEL SECURITY;
CREATE POLICY memory_applicability_tenant ON private.memory_applicability
  USING (tenant_id=NULLIF(current_setting('humaux.tenant_id',true),'')::uuid)
  WITH CHECK (tenant_id=NULLIF(current_setting('humaux.tenant_id',true),'')::uuid);
REVOKE ALL ON private.memory_applicability FROM PUBLIC, role_gateway, role_private_worker,
  role_consolidation_worker, role_public_worker, role_retrieval_worker, role_batch_issuer,
  role_maintenance, role_admin;
GRANT SELECT ON private.memory_applicability TO role_gateway, role_maintenance;

-- §6.1.1: the existing write-scope door authenticates the API key in the same transaction.
CREATE FUNCTION private.propose_memory_applicability(
  p_api_key_id uuid, p_workspace_id uuid, p_memory_id uuid, p_scope text,
  p_product_subject_id uuid, p_channel_key text, p_qualifiers jsonb)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_tenant uuid := NULLIF(current_setting('humaux.tenant_id',true),'')::uuid;
BEGIN
  PERFORM control.assert_write_scope(p_api_key_id,p_workspace_id);
  PERFORM 1 FROM private.memory_records m WHERE m.tenant_id=v_tenant AND m.memory_id=p_memory_id
    AND private.visibility_allowed(m.visibility_class, true,
      m.visibility_user_id=NULLIF(current_setting('humaux.user_id',true),'')::uuid,
      m.visibility_workspace_id=p_workspace_id);
  IF NOT FOUND THEN
    RAISE EXCEPTION 'applicability_memory_unavailable' USING ERRCODE='42501';
  END IF;
  IF p_product_subject_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM private.subjects s WHERE s.tenant_id=v_tenant
      AND s.subject_id=p_product_subject_id AND s.kind IN ('PRODUCT','BRAND')) THEN
    RAISE EXCEPTION 'applicability_product_invalid' USING ERRCODE='22023';
  END IF;
  INSERT INTO private.memory_applicability
    (tenant_id,memory_id,scope,product_subject_id,channel_key,qualifiers,status)
  VALUES (v_tenant,p_memory_id,p_scope,p_product_subject_id,p_channel_key,p_qualifiers,'PROPOSED')
  ON CONFLICT (memory_id) DO UPDATE SET scope=EXCLUDED.scope,
    product_subject_id=EXCLUDED.product_subject_id,channel_key=EXCLUDED.channel_key,
    qualifiers=EXCLUDED.qualifiers,status='PROPOSED',assignment_method=NULL,decision_evidence_id=NULL
  WHERE memory_applicability.tenant_id=v_tenant
    AND memory_applicability.assignment_method IS DISTINCT FROM 'OWNER_CONSOLE';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'applicability_console_precedence' USING ERRCODE='42501';
  END IF;
  RETURN 'PROPOSED';
END;
$$;

-- ADR-0096 D-B.1: relayed instruction Evidence attests the key's authorship, not the owner's words.
CREATE FUNCTION private.decide_memory_applicability(
  p_api_key_id uuid, p_workspace_id uuid, p_memory_id uuid,
  p_decision_evidence_id uuid, p_assignment_method text, p_status text)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  v_tenant uuid := NULLIF(current_setting('humaux.tenant_id',true),'')::uuid;
  v_previous text;
BEGIN
  -- ponytail: console approval needs the M02-10/M26 session binding; M14-5b adds it
  IF p_assignment_method='OWNER_CONSOLE' THEN
    RAISE EXCEPTION 'applicability_console_unavailable' USING ERRCODE='42501';
  END IF;
  PERFORM control.assert_write_scope(p_api_key_id,p_workspace_id);
  IF p_assignment_method IS DISTINCT FROM 'AGENT_ON_OWNER_CHAT'
     OR p_status IS NULL OR p_status NOT IN ('APPROVED','REJECTED') THEN
    RAISE EXCEPTION 'applicability_decision_invalid' USING ERRCODE='22023';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM control.api_keys k JOIN control.memberships m
      ON m.tenant_id=k.tenant_id AND m.user_id=k.user_id
    WHERE k.api_key_id=p_api_key_id AND k.tenant_id=v_tenant
      AND m.state='ACTIVE' AND m.role='OWNER') THEN
    RAISE EXCEPTION 'applicability_owner_required' USING ERRCODE='42501';
  END IF;
  SELECT a.assignment_method INTO v_previous FROM private.memory_applicability a
    WHERE a.tenant_id=v_tenant AND a.memory_id=p_memory_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'applicability_proposal_required' USING ERRCODE='42501';
  END IF;
  IF v_previous='OWNER_CONSOLE' THEN
    RAISE EXCEPTION 'applicability_console_precedence' USING ERRCODE='42501';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM private.evidence_objects e
    WHERE e.tenant_id=v_tenant AND e.evidence_id=p_decision_evidence_id
      AND e.origin_class='AuthenticatedAgent' AND e.origin_principal_id=p_api_key_id) THEN
    RAISE EXCEPTION 'applicability_evidence_required' USING ERRCODE='42501';
  END IF;
  UPDATE private.memory_applicability SET status=p_status,
    assignment_method=p_assignment_method,decision_evidence_id=p_decision_evidence_id
    WHERE tenant_id=v_tenant AND memory_id=p_memory_id;
  RETURN p_status;
END;
$$;

ALTER FUNCTION private.propose_memory_applicability(uuid,uuid,uuid,text,uuid,text,jsonb) OWNER TO role_migration_owner;
ALTER FUNCTION private.decide_memory_applicability(uuid,uuid,uuid,uuid,text,text) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION private.propose_memory_applicability(uuid,uuid,uuid,text,uuid,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION private.decide_memory_applicability(uuid,uuid,uuid,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.propose_memory_applicability(uuid,uuid,uuid,text,uuid,text,jsonb) TO role_gateway;
GRANT EXECUTE ON FUNCTION private.decide_memory_applicability(uuid,uuid,uuid,uuid,text,text) TO role_gateway;
