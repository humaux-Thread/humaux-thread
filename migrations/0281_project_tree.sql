-- §30 / ADR-0101 D-A–D-C: M18 owns hierarchy columns, never the M29 registry identity.
ALTER TABLE private.continuity_projects
  ADD COLUMN parent_id uuid,
  ADD COLUMN kind text NOT NULL DEFAULT 'PROJECT'
    CONSTRAINT continuity_projects_kind_closed CHECK (kind IN ('BUSINESS_LINE','PROJECT','MODULE')),
  ADD COLUMN version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  ADD CONSTRAINT continuity_projects_tree_parent_fkey FOREIGN KEY (tenant_id,workspace_id,parent_id)
    REFERENCES private.continuity_projects(tenant_id,workspace_id,project_id);
CREATE INDEX continuity_projects_tree_children
  ON private.continuity_projects(tenant_id,parent_id);

CREATE TABLE private.project_facets (
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  kind text NOT NULL CONSTRAINT project_facets_kind_closed CHECK (kind IN ('CHANNEL','PLATFORM')),
  value text NOT NULL CHECK (value ~ '^[a-z0-9]+(_[a-z0-9]+)*$'),
  PRIMARY KEY (tenant_id,project_id,kind),
  FOREIGN KEY (tenant_id,project_id) REFERENCES private.continuity_projects(tenant_id,project_id)
);
ALTER TABLE private.project_facets OWNER TO role_migration_owner;
ALTER TABLE private.project_facets ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.project_facets FORCE ROW LEVEL SECURITY;
CREATE POLICY project_facets_tenant ON private.project_facets
  USING (tenant_id = NULLIF(current_setting('humaux.tenant_id',true),'')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('humaux.tenant_id',true),'')::uuid);
REVOKE ALL ON private.project_facets FROM PUBLIC, role_gateway, role_private_worker,
  role_consolidation_worker, role_public_worker, role_retrieval_worker, role_batch_issuer,
  role_maintenance, role_admin;

-- §46.1: copy under the migrator before replacing either door; a mismatch rolls back all DDL.
INSERT INTO private.project_facets(tenant_id,project_id,kind,value)
  SELECT tenant_id,project_id,'CHANNEL',channel_key FROM private.project_channels;
DO $$ BEGIN
  IF (SELECT count(*) FROM private.project_channels) <>
     (SELECT count(*) FROM private.project_facets WHERE kind='CHANNEL') THEN
    RAISE EXCEPTION 'project channel migration count mismatch';
  END IF;
END $$;

CREATE OR REPLACE FUNCTION private.set_project_channel(
  p_tenant uuid, p_project uuid, p_workspaces uuid[], p_channel text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NOT private.declared_project_visible(p_tenant, p_project, p_workspaces) THEN
    RETURN false;
  END IF;
  INSERT INTO private.project_facets (tenant_id, project_id, kind, value)
    VALUES (p_tenant, p_project, 'CHANNEL', p_channel)
    ON CONFLICT (tenant_id, project_id, kind) DO UPDATE SET value = EXCLUDED.value;
  RETURN true;
END;
$$;

-- §6.1.4: latest revision first, then valid-time filtering; a retraction must not revive its predecessor.
-- §25.3.1: no body/source identity is returned; references identify immutable published versions only.
CREATE OR REPLACE FUNCTION private.read_project_rollup(
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
      'project_id', child.project_id, 'title', child.title, 'channel_key', ch.value,
      'facets', (SELECT coalesce(jsonb_agg(jsonb_build_object(
        'kind', slot.facet_kind, 'version_id', slot.current_version_id,
        'version', slot.slot_version) ORDER BY slot.facet_kind), '[]'::jsonb)
        FROM private.continuity_facet_slots slot
        WHERE slot.tenant_id = p_tenant AND slot.workspace_id = child.workspace_id
          AND slot.project_id = child.project_id AND slot.current_version_id IS NOT NULL)
    ) ORDER BY child.project_id), '[]'::jsonb)) INTO result
    FROM bounded child LEFT JOIN private.project_facets ch
      ON ch.tenant_id = p_tenant AND ch.project_id = child.project_id AND ch.kind = 'CHANNEL';
  RETURN result;
END;
$$;

ALTER FUNCTION private.set_project_channel(uuid, uuid, uuid[], text) OWNER TO role_migration_owner;
ALTER FUNCTION private.read_project_rollup(uuid, uuid, text, uuid[]) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION private.set_project_channel(uuid, uuid, uuid[], text) FROM PUBLIC;
REVOKE ALL ON FUNCTION private.read_project_rollup(uuid, uuid, text, uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.set_project_channel(uuid, uuid, uuid[], text) TO role_gateway;
GRANT EXECUTE ON FUNCTION private.read_project_rollup(uuid, uuid, text, uuid[]) TO role_gateway;

DROP TABLE private.project_channels;

-- §6.1.1 / ADR-0101 D-A amended: owner access never widens caller visibility.
CREATE FUNCTION private.project_ancestors(p_tenant uuid,p_project uuid,p_workspaces uuid[])
RETURNS TABLE(project_id uuid,parent_id uuid,workspace_id uuid,kind text,version bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF p_tenant IS NULL OR p_tenant IS DISTINCT FROM
       NULLIF(current_setting('humaux.tenant_id',true),'')::uuid
    OR p_workspaces IS NULL OR array_position(p_workspaces,NULL) IS NOT NULL THEN
    RAISE EXCEPTION 'invalid tree authority context' USING ERRCODE='42501';
  END IF;
  RETURN QUERY WITH RECURSIVE tree AS (
    SELECT c.project_id,c.parent_id,c.workspace_id,c.kind,c.version
      FROM private.continuity_projects c WHERE c.tenant_id=p_tenant AND c.project_id=p_project
    UNION
    SELECT c.project_id,c.parent_id,c.workspace_id,c.kind,c.version
      FROM private.continuity_projects c JOIN tree ON c.project_id = tree.parent_id
      WHERE c.tenant_id=p_tenant
  ) SELECT tree.* FROM tree
    WHERE private.declared_project_visible(p_tenant,p_project,p_workspaces)
      AND private.declared_project_visible(p_tenant,tree.project_id,p_workspaces)
    ORDER BY tree.project_id;
END $$;
ALTER FUNCTION private.project_ancestors(uuid,uuid,uuid[]) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION private.project_ancestors(uuid,uuid,uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.project_ancestors(uuid,uuid,uuid[]) TO role_gateway;

-- §6.1.1 / ADR-0101 D-A amended: owner access never widens caller visibility.
CREATE FUNCTION private.project_subtree(p_tenant uuid,p_project uuid,p_workspaces uuid[])
RETURNS TABLE(project_id uuid,parent_id uuid,workspace_id uuid,kind text,version bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF p_tenant IS NULL OR p_tenant IS DISTINCT FROM
       NULLIF(current_setting('humaux.tenant_id',true),'')::uuid
    OR p_workspaces IS NULL OR array_position(p_workspaces,NULL) IS NOT NULL THEN
    RAISE EXCEPTION 'invalid tree authority context' USING ERRCODE='42501';
  END IF;
  RETURN QUERY WITH RECURSIVE tree AS (
    SELECT c.project_id,c.parent_id,c.workspace_id,c.kind,c.version
      FROM private.continuity_projects c WHERE c.tenant_id=p_tenant AND c.project_id=p_project
    UNION
    SELECT c.project_id,c.parent_id,c.workspace_id,c.kind,c.version
      FROM private.continuity_projects c JOIN tree ON c.parent_id = tree.project_id
      WHERE c.tenant_id=p_tenant
  ) SELECT tree.* FROM tree
    WHERE private.declared_project_visible(p_tenant,p_project,p_workspaces)
      AND private.declared_project_visible(p_tenant,tree.project_id,p_workspaces)
    ORDER BY tree.project_id;
END $$;
ALTER FUNCTION private.project_subtree(uuid,uuid,uuid[]) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION private.project_subtree(uuid,uuid,uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.project_subtree(uuid,uuid,uuid[]) TO role_gateway;

-- §30 / ADR-0101 D-B: VOLATILE PL/pgSQL statements obtain fresh READ COMMITTED snapshots after the guard.
CREATE FUNCTION private.project_move(
  p_tenant uuid,p_project uuid,p_parent uuid,p_expected_version bigint,p_workspaces uuid[],
  p_principal uuid,p_user uuid
) RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  current_version bigint;
  subtree_height integer;
  parent_depth integer;
  creates_cycle boolean;
  depth_limit integer;
BEGIN
  IF p_tenant IS NULL OR p_tenant IS DISTINCT FROM
       NULLIF(current_setting('humaux.tenant_id',true),'')::uuid
    OR p_principal IS NULL OR p_principal IS DISTINCT FROM
       NULLIF(current_setting('humaux.principal_id',true),'')::uuid
    OR p_user IS DISTINCT FROM NULLIF(NULLIF(current_setting('humaux.user_id',true),''),
         '00000000-0000-0000-0000-000000000000')::uuid
    OR p_workspaces IS NULL OR array_position(p_workspaces,NULL) IS NOT NULL THEN
    RAISE EXCEPTION 'invalid tree move authority context' USING ERRCODE='42501';
  END IF;
  IF current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'tree moves require fresh READ COMMITTED snapshots' USING ERRCODE='25001';
  END IF;
  -- ADR-0101 D-B: the class is shared with coord_tree_repo::TOPOLOGY_GUARD_CLASS.
  PERFORM pg_advisory_xact_lock(hashtext('coord-tree'),hashtext(p_tenant::text));
  IF NOT private.declared_project_visible(p_tenant,p_project,p_workspaces)
    OR (p_parent IS NOT NULL AND NOT private.declared_project_visible(p_tenant,p_parent,p_workspaces)) THEN
    RETURN NULL;
  END IF;
  SELECT c.version INTO current_version FROM private.continuity_projects c
    WHERE c.tenant_id=p_tenant AND c.project_id=p_project;
  IF p_expected_version IS DISTINCT FROM current_version THEN
    RAISE EXCEPTION 'project version conflict' USING ERRCODE='40001';
  END IF;
  WITH RECURSIVE children AS (
    SELECT c.project_id,1 AS depth FROM private.continuity_projects c
      WHERE c.tenant_id=p_tenant AND c.project_id=p_project
    UNION ALL
    SELECT c.project_id,children.depth+1 FROM private.continuity_projects c
      JOIN children ON c.parent_id=children.project_id WHERE c.tenant_id=p_tenant
  ) SELECT max(depth),coalesce(bool_or(project_id=p_parent),false)
    INTO subtree_height,creates_cycle FROM children;
  IF creates_cycle THEN
    RAISE EXCEPTION 'project move would create a cycle' USING ERRCODE='23514';
  END IF;
  WITH RECURSIVE parents AS (
    SELECT c.project_id,c.parent_id FROM private.continuity_projects c
      WHERE c.tenant_id=p_tenant AND c.project_id=p_parent
    UNION
    SELECT c.project_id,c.parent_id FROM private.continuity_projects c
      JOIN parents ON c.project_id=parents.parent_id WHERE c.tenant_id=p_tenant
  ) SELECT count(*)::integer INTO parent_depth FROM parents;
  -- ADR-0101 D-A: the caller installs the deployment's coord.project_max_depth as this transaction-local GUC.
  depth_limit := NULLIF(current_setting('humaux.project_max_depth',true),'')::integer;
  IF depth_limit IS NULL OR depth_limit < 1 THEN
    RAISE EXCEPTION 'missing or invalid project depth limit' USING ERRCODE='22023';
  END IF;
  IF parent_depth+subtree_height > depth_limit THEN
    RAISE EXCEPTION 'project depth exceeds the configured limit' USING ERRCODE='23514';
  END IF;
  UPDATE private.continuity_projects SET parent_id=p_parent,version=version+1,updated_at=clock_timestamp()
    WHERE tenant_id=p_tenant AND project_id=p_project RETURNING version INTO current_version;
  -- §77: control.audit_event_insert is the sole INSERT path for control.audit_events (0041).
  PERFORM control.audit_event_insert(uuidv7(),now(),p_tenant,'PRINCIPAL',p_principal::text,'PROJECT_MOVE',
    'PROJECT',p_project::text,'SUCCESS','','',NULL::inet,'',ARRAY[]::text[],'','',
    jsonb_build_object('parent_id',p_parent,'version',current_version));
  RETURN current_version;
END $$;
ALTER FUNCTION private.project_move(uuid,uuid,uuid,bigint,uuid[],uuid,uuid) OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION private.project_move(uuid,uuid,uuid,bigint,uuid[],uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.project_move(uuid,uuid,uuid,bigint,uuid[],uuid,uuid) TO role_gateway;
