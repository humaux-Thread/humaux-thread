-- §25.3.1 / ADR-0094 D-D: inherit the locked list version's immutable source basis.
-- ADR-0082 D-D: forward migration; 0136 and its legacy non-merge callers remain unchanged.
CREATE FUNCTION private.publish_continuity_facet(
  p_tenant_id uuid,p_workspace_id uuid,p_project_id uuid,p_principal_id uuid,
  p_user_id uuid,p_facet_kind text,p_expected_slot_version bigint,
  p_published_state text,p_body jsonb,
  p_memory_ids uuid[],p_memory_hashes bytea[],
  p_evidence_ids uuid[],p_evidence_hashes bytea[],p_inherit_sources boolean)
RETURNS TABLE(facet_version_id uuid,facet_version bigint,slot_version bigint,body_sha256 bytea)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path TO pg_catalog
SET humaux.continuity_publish TO '1' AS $$
DECLARE
  locked_version bigint;
  inherited_version_id uuid;
  new_version_id uuid := uuidv7();
  new_body_hash bytea := sha256(convert_to(p_body::text,'UTF8'));
  affected bigint;
  locked_source_count bigint;
  memory_count bigint := cardinality(p_memory_ids);
  evidence_count bigint := cardinality(p_evidence_ids);
BEGIN
  PERFORM private.assert_continuity_context(
    p_tenant_id,p_workspace_id,p_principal_id,p_user_id);
  IF p_inherit_sources IS NULL OR (p_inherit_sources AND p_facet_kind NOT IN (
      'DECISIONS','REJECTIONS','CONSTRAINTS','KNOWN_ISSUES','NEXT_ACTIONS','PROCEDURES','OUTCOMES'))
    OR p_project_id IS NULL OR p_facet_kind IS NULL OR p_expected_slot_version IS NULL
    OR p_published_state IS NULL OR p_body IS NULL OR p_expected_slot_version<0
    OR p_published_state NOT IN ('CURRENT','CONFLICTED') OR p_facet_kind NOT IN (
      'GOAL','CURRENT_STATE','DECISIONS','REJECTIONS','CONSTRAINTS','KNOWN_ISSUES',
      'NEXT_ACTIONS','ACTIVE_TASKS','RECENT_CHANGES','CODE','TESTS','CONFIG',
      'MIGRATIONS','PROCEDURES','OUTCOMES') THEN
    RAISE EXCEPTION 'invalid continuity publication scalar' USING ERRCODE='22023';
  END IF;
  IF p_memory_ids IS NULL OR p_memory_hashes IS NULL
    OR p_evidence_ids IS NULL OR p_evidence_hashes IS NULL
    OR memory_count<>cardinality(p_memory_hashes)
    OR evidence_count<>cardinality(p_evidence_hashes)
    OR memory_count+evidence_count=0
    OR (memory_count>0 AND (array_ndims(p_memory_ids)<>1 OR array_lower(p_memory_ids,1)<>1
      OR array_ndims(p_memory_hashes)<>1 OR array_lower(p_memory_hashes,1)<>1))
    OR (evidence_count>0 AND (array_ndims(p_evidence_ids)<>1 OR array_lower(p_evidence_ids,1)<>1
      OR array_ndims(p_evidence_hashes)<>1 OR array_lower(p_evidence_hashes,1)<>1))
    OR EXISTS (SELECT 1 FROM unnest(p_memory_ids,p_memory_hashes) source(id,hash)
      WHERE id IS NULL OR id='00000000-0000-0000-0000-000000000000'::uuid
        OR hash IS NULL OR octet_length(hash)<>32)
    OR EXISTS (SELECT 1 FROM unnest(p_evidence_ids,p_evidence_hashes) source(id,hash)
      WHERE id IS NULL OR id='00000000-0000-0000-0000-000000000000'::uuid
        OR hash IS NULL OR octet_length(hash)<>32)
    OR (SELECT count(*)<>count(DISTINCT id) FROM unnest(p_memory_ids) source(id))
    OR (SELECT count(*)<>count(DISTINCT id) FROM unnest(p_evidence_ids) source(id)) THEN
    RAISE EXCEPTION 'invalid continuity publication source arrays' USING ERRCODE='22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM private.continuity_projects project
    WHERE project.tenant_id=p_tenant_id AND project.workspace_id=p_workspace_id
      AND project.project_id=p_project_id AND project.lifecycle_state='ACTIVE') THEN
    RAISE EXCEPTION 'continuity project unavailable' USING ERRCODE='42501';
  END IF;
  SELECT slot.slot_version,slot.current_version_id INTO locked_version,inherited_version_id
    FROM private.continuity_facet_slots slot
    WHERE slot.tenant_id=p_tenant_id AND slot.workspace_id=p_workspace_id
      AND slot.project_id=p_project_id AND slot.facet_kind=p_facet_kind
    FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'continuity slot missing or corrupt' USING ERRCODE='P9I01';
  END IF;
  IF locked_version<>p_expected_slot_version THEN
    RAISE EXCEPTION 'continuity slot version conflict' USING ERRCODE='P9C01';
  END IF;
  SELECT count(*) INTO locked_source_count FROM (
    SELECT memory.memory_id FROM private.memory_records memory
      JOIN unnest(p_memory_ids,p_memory_hashes) source(id,hash)
        ON memory.tenant_id=p_tenant_id AND memory.memory_id=source.id
       AND memory.status='active'
       AND sha256(convert_to(memory.content::text,'UTF8'))=source.hash
       AND (memory.visibility_class='TENANT_SHARED'
         OR (memory.visibility_class='USER_PRIVATE' AND p_user_id IS NOT NULL
           AND memory.visibility_user_id=p_user_id)
         OR (memory.visibility_class='WORKSPACE_SHARED'
           AND memory.visibility_workspace_id=p_workspace_id))
      ORDER BY memory.memory_id FOR SHARE OF memory
  ) locked_memory;
  IF locked_source_count<>memory_count THEN
    RAISE EXCEPTION 'continuity memory source unavailable or changed' USING ERRCODE='23514';
  END IF;
  SELECT count(*) INTO locked_source_count FROM (
    SELECT evidence.evidence_id FROM private.evidence_objects evidence
      JOIN unnest(p_evidence_ids,p_evidence_hashes) source(id,hash)
        ON evidence.tenant_id=p_tenant_id AND evidence.evidence_id=source.id
       AND evidence.payload_sha256=source.hash
       AND (evidence.visibility_class='TENANT_SHARED'
         OR (evidence.visibility_class='USER_PRIVATE' AND p_user_id IS NOT NULL
           AND evidence.visibility_user_id=p_user_id)
         OR (evidence.visibility_class='WORKSPACE_SHARED'
           AND evidence.visibility_workspace_id=p_workspace_id))
      ORDER BY evidence.evidence_id FOR SHARE OF evidence
  ) locked_evidence;
  IF locked_source_count<>evidence_count THEN
    RAISE EXCEPTION 'continuity evidence source unavailable or changed' USING ERRCODE='23514';
  END IF;
  -- §25.3.1: overlapping ids cannot replace the stored basis with a different hash.
  IF p_inherit_sources AND (
    EXISTS (SELECT 1 FROM private.continuity_facet_memory_links link
      JOIN unnest(p_memory_ids,p_memory_hashes) source(id,hash) ON source.id=link.memory_id
      WHERE link.tenant_id=p_tenant_id AND link.workspace_id=p_workspace_id
        AND link.project_id=p_project_id AND link.facet_kind=p_facet_kind
        AND link.facet_version_id=inherited_version_id AND link.memory_sha256<>source.hash)
    OR EXISTS (SELECT 1 FROM private.continuity_facet_evidence_links link
      JOIN unnest(p_evidence_ids,p_evidence_hashes) source(id,hash) ON source.id=link.evidence_id
      WHERE link.tenant_id=p_tenant_id AND link.workspace_id=p_workspace_id
        AND link.project_id=p_project_id AND link.facet_kind=p_facet_kind
        AND link.facet_version_id=inherited_version_id AND link.evidence_sha256<>source.hash)) THEN
    RAISE EXCEPTION 'continuity inherited source hash conflict' USING ERRCODE='23514';
  END IF;
  INSERT INTO private.continuity_facet_versions(
    tenant_id,workspace_id,project_id,facet_kind,facet_version_id,facet_version,
    body,body_sha256,authored_by_principal_id)
  VALUES(p_tenant_id,p_workspace_id,p_project_id,p_facet_kind,new_version_id,
    p_expected_slot_version+1,p_body,new_body_hash,p_principal_id);
  INSERT INTO private.continuity_facet_memory_links(
    tenant_id,workspace_id,project_id,facet_kind,facet_version,facet_version_id,
    memory_id,memory_sha256)
  SELECT p_tenant_id,p_workspace_id,p_project_id,p_facet_kind,
    p_expected_slot_version+1,new_version_id,source.id,source.hash
  FROM (
    SELECT source.id,source.hash FROM unnest(p_memory_ids,p_memory_hashes) source(id,hash)
    UNION
    SELECT link.memory_id,link.memory_sha256 FROM private.continuity_facet_memory_links link
    WHERE p_inherit_sources AND link.tenant_id=p_tenant_id AND link.workspace_id=p_workspace_id
      AND link.project_id=p_project_id AND link.facet_kind=p_facet_kind
      AND link.facet_version_id=inherited_version_id
  ) source(id,hash);
  INSERT INTO private.continuity_facet_evidence_links(
    tenant_id,workspace_id,project_id,facet_kind,facet_version,facet_version_id,
    evidence_id,evidence_sha256)
  SELECT p_tenant_id,p_workspace_id,p_project_id,p_facet_kind,
    p_expected_slot_version+1,new_version_id,source.id,source.hash
  FROM (
    SELECT source.id,source.hash FROM unnest(p_evidence_ids,p_evidence_hashes) source(id,hash)
    UNION
    SELECT link.evidence_id,link.evidence_sha256 FROM private.continuity_facet_evidence_links link
    WHERE p_inherit_sources AND link.tenant_id=p_tenant_id AND link.workspace_id=p_workspace_id
      AND link.project_id=p_project_id AND link.facet_kind=p_facet_kind
      AND link.facet_version_id=inherited_version_id
  ) source(id,hash);
  UPDATE private.continuity_facet_slots slot SET
    slot_version=p_expected_slot_version+1,current_version_id=new_version_id,
    slot_state=p_published_state,updated_at=now()
  WHERE slot.tenant_id=p_tenant_id AND slot.workspace_id=p_workspace_id
    AND slot.project_id=p_project_id AND slot.facet_kind=p_facet_kind
    AND slot.slot_version=p_expected_slot_version;
  GET DIAGNOSTICS affected=ROW_COUNT;
  IF affected<>1 THEN
    RAISE EXCEPTION 'continuity slot CAS invariant failed' USING ERRCODE='P9I01';
  END IF;
  RETURN QUERY SELECT new_version_id,p_expected_slot_version+1,
    p_expected_slot_version+1,new_body_hash;
END
$$;

ALTER FUNCTION private.publish_continuity_facet(uuid,uuid,uuid,uuid,uuid,text,bigint,text,jsonb,uuid[],bytea[],uuid[],bytea[],boolean)
  OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION private.publish_continuity_facet(uuid,uuid,uuid,uuid,uuid,text,bigint,text,jsonb,uuid[],bytea[],uuid[],bytea[],boolean)
  FROM PUBLIC,role_admin,role_gateway,role_private_worker,role_consolidation_worker,
    role_public_worker,role_retrieval_worker,role_batch_issuer,role_maintenance;
GRANT EXECUTE ON FUNCTION private.publish_continuity_facet(uuid,uuid,uuid,uuid,uuid,text,bigint,text,jsonb,uuid[],bytea[],uuid[],bytea[],boolean) TO role_gateway;
