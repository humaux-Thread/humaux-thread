-- §25.3.1 / ADR-0095 D-B–D-C (M14-4): channels are attributes, never a second hierarchy.
-- §46.1 EXPAND_CONTRACT: no existing row changes; no runtime direct table privileges.
CREATE TABLE private.project_channels (
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  channel_key text NOT NULL CHECK (channel_key ~ '^[a-z0-9]+(_[a-z0-9]+)*$'),
  PRIMARY KEY (tenant_id, project_id),
  FOREIGN KEY (tenant_id, project_id)
    REFERENCES private.continuity_projects (tenant_id, project_id)
);
ALTER TABLE private.project_channels OWNER TO role_migration_owner;
ALTER TABLE private.project_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.project_channels FORCE ROW LEVEL SECURITY;
CREATE POLICY project_channels_tenant ON private.project_channels
  USING (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid);
REVOKE ALL ON private.project_channels FROM PUBLIC, role_gateway, role_private_worker,
  role_consolidation_worker, role_public_worker, role_retrieval_worker, role_batch_issuer,
  role_maintenance, role_admin;

CREATE FUNCTION private.set_project_channel(
  p_tenant uuid, p_project uuid, p_workspaces uuid[], p_channel text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NOT private.declared_project_visible(p_tenant, p_project, p_workspaces) THEN
    RETURN false;
  END IF;
  INSERT INTO private.project_channels (tenant_id, project_id, channel_key)
    VALUES (p_tenant, p_project, p_channel)
    ON CONFLICT (tenant_id, project_id) DO UPDATE SET channel_key = EXCLUDED.channel_key;
  RETURN true;
END;
$$;

-- §6.1.4: latest revision first, then valid-time filtering; a retraction must not revive its predecessor.
-- §25.3.1: no body/source identity is returned; references identify immutable published versions only.
CREATE FUNCTION private.read_project_rollup(
  p_tenant uuid, p_target uuid, p_kind text, p_workspaces uuid[]
) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE result jsonb;
BEGIN
  IF p_tenant IS NULL OR p_tenant IS DISTINCT FROM
       NULLIF(current_setting('humaux.tenant_id', true), '')::uuid
     OR p_workspaces IS NULL OR array_position(p_workspaces, NULL) IS NOT NULL
     OR p_kind NOT IN ('PROJECT', 'BRAND', 'BUSINESS') THEN
    RAISE EXCEPTION 'invalid rollup authority context' USING ERRCODE = '42501';
  END IF;
  IF p_kind = 'PROJECT' THEN
    IF NOT private.declared_project_visible(p_tenant, p_target, p_workspaces) THEN
      RETURN NULL;
    END IF;
  ELSIF NOT EXISTS (SELECT 1 FROM private.subjects s
      WHERE s.tenant_id = p_tenant AND s.subject_id = p_target
        AND s.kind = p_kind AND s.merged_into IS NULL) THEN
    RETURN NULL;
  END IF;

  WITH project_edges AS (
    SELECT DISTINCT ON (r.relation_id) r.* FROM private.project_subject_relations r
      WHERE r.tenant_id = p_tenant ORDER BY r.relation_id, r.revision DESC
  ), subject_edges AS (
    SELECT DISTINCT ON (r.relation_id) r.* FROM private.subject_relations r
      WHERE r.tenant_id = p_tenant ORDER BY r.relation_id, r.revision DESC
  ), candidates AS (
    SELECT c.* FROM private.continuity_projects c
      WHERE c.tenant_id = p_tenant AND c.lifecycle_state = 'ACTIVE'
        AND ((p_kind = 'PROJECT' AND c.project_id = p_target)
          OR (p_kind <> 'PROJECT' AND EXISTS (SELECT 1 FROM project_edges r
            WHERE r.src_id = c.project_id AND r.relation_kind = 'SERVES' AND r.valid @> now()
              AND (r.dst_id = p_target OR (p_kind = 'BUSINESS' AND EXISTS (
                SELECT 1 FROM subject_edges b JOIN private.subjects brand
                  ON brand.tenant_id = p_tenant AND brand.subject_id = b.src_id
                  AND brand.kind = 'BRAND' AND brand.merged_into IS NULL
                WHERE b.src_id = r.dst_id AND b.dst_id = p_target
                  AND b.relation_kind = 'OWNED_BY' AND b.valid @> now()))))))
  ), visible AS (
    SELECT child.* FROM candidates child
      WHERE child.workspace_id = ANY(p_workspaces)
  ), bounded AS (
    SELECT * FROM visible ORDER BY project_id LIMIT 65
  )
  SELECT jsonb_build_object('visible_count', (SELECT count(*) FROM visible),
    'children', coalesce(jsonb_agg(jsonb_build_object(
      'project_id', child.project_id, 'title', child.title, 'channel_key', ch.channel_key,
      'facets', (SELECT coalesce(jsonb_agg(jsonb_build_object(
        'kind', slot.facet_kind, 'version_id', slot.current_version_id,
        'version', slot.slot_version) ORDER BY slot.facet_kind), '[]'::jsonb)
        FROM private.continuity_facet_slots slot
        WHERE slot.tenant_id = p_tenant AND slot.workspace_id = child.workspace_id
          AND slot.project_id = child.project_id AND slot.current_version_id IS NOT NULL)
    ) ORDER BY child.project_id), '[]'::jsonb)) INTO result
    FROM bounded child LEFT JOIN private.project_channels ch
      ON ch.tenant_id = p_tenant AND ch.project_id = child.project_id;
  RETURN result;
END;
$$;

ALTER FUNCTION private.set_project_channel(uuid, uuid, uuid[], text) OWNER TO role_migration_owner;
ALTER FUNCTION private.read_project_rollup(uuid, uuid, text, uuid[]) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION private.set_project_channel(uuid, uuid, uuid[], text) FROM PUBLIC;
REVOKE ALL ON FUNCTION private.read_project_rollup(uuid, uuid, text, uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.set_project_channel(uuid, uuid, uuid[], text) TO role_gateway;
GRANT EXECUTE ON FUNCTION private.read_project_rollup(uuid, uuid, text, uuid[]) TO role_gateway;
