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
SET search_path TO pg_catalog AS $$
DECLARE
  locked_version bigint;
  inherited_version_id uuid;
  new_version_id uuid;
  new_facet_version bigint;
  new_slot_version bigint;
  new_body_hash bytea;
BEGIN
  PERFORM private.assert_continuity_context(
    p_tenant_id,p_workspace_id,p_principal_id,p_user_id);
  IF p_inherit_sources IS NULL OR (p_inherit_sources AND (p_facet_kind IS NULL
    OR p_facet_kind NOT IN ('DECISIONS','REJECTIONS','CONSTRAINTS','KNOWN_ISSUES',
      'NEXT_ACTIONS','PROCEDURES','OUTCOMES'))) THEN
    RAISE EXCEPTION 'invalid continuity merge mode' USING ERRCODE='22023';
  END IF;
  IF p_inherit_sources THEN
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
    -- §25.3.1: overlapping ids cannot replace the stored basis with a different hash.
    IF EXISTS (SELECT 1 FROM private.continuity_facet_memory_links link
        JOIN unnest(p_memory_ids,p_memory_hashes) source(id,hash) ON source.id=link.memory_id
        WHERE link.tenant_id=p_tenant_id AND link.workspace_id=p_workspace_id
          AND link.project_id=p_project_id AND link.facet_kind=p_facet_kind
          AND link.facet_version_id=inherited_version_id AND link.memory_sha256<>source.hash)
      OR EXISTS (SELECT 1 FROM private.continuity_facet_evidence_links link
        JOIN unnest(p_evidence_ids,p_evidence_hashes) source(id,hash) ON source.id=link.evidence_id
        WHERE link.tenant_id=p_tenant_id AND link.workspace_id=p_workspace_id
          AND link.project_id=p_project_id AND link.facet_kind=p_facet_kind
          AND link.facet_version_id=inherited_version_id AND link.evidence_sha256<>source.hash) THEN
      RAISE EXCEPTION 'continuity inherited source hash conflict' USING ERRCODE='23514';
    END IF;
  END IF;
  -- §25.3.1: the legacy function remains the sole caller validator, marker owner and CAS writer.
  SELECT published.facet_version_id,published.facet_version,published.slot_version,published.body_sha256
    INTO new_version_id,new_facet_version,new_slot_version,new_body_hash
    FROM private.publish_continuity_facet(
      p_tenant_id,p_workspace_id,p_project_id,p_principal_id,p_user_id,p_facet_kind,
      p_expected_slot_version,p_published_state,p_body,
      p_memory_ids,p_memory_hashes,p_evidence_ids,p_evidence_hashes) published;
  IF p_inherit_sources THEN
    -- §25.3.1: the slot lock spans the legacy call and both inherited link inserts.
    INSERT INTO private.continuity_facet_memory_links(
      tenant_id,workspace_id,project_id,facet_kind,facet_version,facet_version_id,
      memory_id,memory_sha256)
    SELECT p_tenant_id,p_workspace_id,p_project_id,p_facet_kind,
      new_facet_version,new_version_id,link.memory_id,link.memory_sha256
    FROM private.continuity_facet_memory_links link
    WHERE link.tenant_id=p_tenant_id AND link.workspace_id=p_workspace_id
      AND link.project_id=p_project_id AND link.facet_kind=p_facet_kind
      AND link.facet_version_id=inherited_version_id
      AND NOT EXISTS (SELECT 1 FROM private.continuity_facet_memory_links existing
        WHERE existing.tenant_id=p_tenant_id AND existing.facet_version_id=new_version_id
          AND existing.memory_id=link.memory_id);
    INSERT INTO private.continuity_facet_evidence_links(
      tenant_id,workspace_id,project_id,facet_kind,facet_version,facet_version_id,
      evidence_id,evidence_sha256)
    SELECT p_tenant_id,p_workspace_id,p_project_id,p_facet_kind,
      new_facet_version,new_version_id,link.evidence_id,link.evidence_sha256
    FROM private.continuity_facet_evidence_links link
    WHERE link.tenant_id=p_tenant_id AND link.workspace_id=p_workspace_id
      AND link.project_id=p_project_id AND link.facet_kind=p_facet_kind
      AND link.facet_version_id=inherited_version_id
      AND NOT EXISTS (SELECT 1 FROM private.continuity_facet_evidence_links existing
        WHERE existing.tenant_id=p_tenant_id AND existing.facet_version_id=new_version_id
          AND existing.evidence_id=link.evidence_id);
  END IF;
  RETURN QUERY SELECT new_version_id,new_facet_version,new_slot_version,new_body_hash;
END
$$;

ALTER FUNCTION private.publish_continuity_facet(uuid,uuid,uuid,uuid,uuid,text,bigint,text,jsonb,uuid[],bytea[],uuid[],bytea[],boolean)
  OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION private.publish_continuity_facet(uuid,uuid,uuid,uuid,uuid,text,bigint,text,jsonb,uuid[],bytea[],uuid[],bytea[],boolean)
  FROM PUBLIC,role_admin,role_gateway,role_private_worker,role_consolidation_worker,
    role_public_worker,role_retrieval_worker,role_batch_issuer,role_maintenance;
GRANT EXECUTE ON FUNCTION private.publish_continuity_facet(uuid,uuid,uuid,uuid,uuid,text,bigint,text,jsonb,uuid[],bytea[],uuid[],bytea[],boolean) TO role_gateway;
