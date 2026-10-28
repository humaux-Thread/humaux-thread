-- ADR-0102 D-A…D-D / Baseline §6.1.4, §30 (card M18-3a; §46 forward-fix, EXPAND_CONTRACT, number 0289): the task→project
-- authority. coord.tasks.project_id becomes the one writable task→project fact; the Project CONTAINS Task relation
-- (0249) stays the bitemporal mapping that A3 attribution reads (adapters::attribution_repo), written in the same
-- transaction by adapters::coord_task_repo::set_task_project_in_txn and by nothing else (D-A, D-C).
--
-- Invariants:
--   ① (a) project_id is a composite FK (tenant_id, project_id) -> private.continuity_projects (0249's UNIQUE
--     (tenant_id, project_id)), NO ACTION like every other tenant-leg FK of the relation kernel (RI bypasses RLS, so the
--     tenant leg is what keeps a task from naming another tenant's project).
--   ② (b) coord.workspace_unfiled_projects is the one marker of "this project is a workspace's Unfiled project": one row
--     per (tenant, workspace), one marker per project, the FK reaching the parent key of 0136:13 so the marked project
--     lives in the marked workspace. It is a table and not a project kind or a title match (ADR-0102 D-D, lead answer 1):
--     the tree kinds (0281) stay BUSINESS_LINE | PROJECT | MODULE and a title is user text. FORCE RLS with the §62 tenant
--     clause; role_gateway SELECTs it and INSERTs rows lazily (the first task submit of a workspace) and holds nothing
--     else, nobody holds UPDATE or DELETE.
--   ③ (c) backfill = the task's current CONTAINS: the highest revision of a relation is CONTAINS and its valid contains
--     now() (the A3 reading, 0252). Two current CONTAINS projects for one task are an ambiguity this migration refuses to
--     resolve (RAISE naming the count): ADR-0102 D-D has exactly one authority per task.
--   ④ (d) every remaining task takes the Unfiled project of its tenant's oldest workspace by (created_at,
--     workspace_id), which is deterministic, and coord.tasks RLS is tenant-only, so no read widens. A missing Unfiled is
--     created here with the canonical state private.register_continuity_project writes: the project row (title
--     'Unfiled', kind PROJECT by 0281's default) plus its 15 facet slots (0136:351-361). The slots are mandatory: a
--     retry of register_continuity_project on a project without exactly 15 slots raises "does not match canonical
--     registry state" (0136:343-347), so a slotless Unfiled could never be re-registered or published to.
--   ⑤ (e) no CONTAINS revision is written for a task backfilled into Unfiled, and this migration mints no Evidence: a
--     CONTAINS revision needs an authorization Evidence (0253 ①) that no migration can honestly claim. Unfiled therefore
--     attributes nothing (N09 R3, "never a default").
--   ⑥ (f) SET NOT NULL last, so a task this migration could not place aborts it instead of surviving unplaced.
--
-- The migrator is the superuser principal (maintenance::migrate, HUMAUX_MIGRATOR_PG_DSN, ADR-0066 L-13) and RLS, FORCE
-- included, never applies to it, so every tenant's relations, workspaces and tasks are visible and written here.
--
-- ponytail: a tenant with tasks and no workspace aborts the migration (nowhere to put its Unfiled). Upgrade: none
--   needed while control.onboard_tenant creates the first workspace with the tenant.
--
-- Locks, all held until COMMIT: ADD COLUMN is catalog-only; ADD CONSTRAINT ... FOREIGN KEY takes SHARE ROW EXCLUSIVE on
-- coord.tasks and private.continuity_projects (task submits and project registrations wait); CREATE INDEX takes SHARE on
-- coord.tasks; the backfill UPDATEs hold ROW EXCLUSIVE; SET NOT NULL scans coord.tasks under ACCESS EXCLUSIVE. Both
-- registries are small.

-- (a) the authority column, nullable until the backfill has placed every task.
ALTER TABLE coord.tasks ADD COLUMN project_id uuid;
ALTER TABLE coord.tasks
  ADD CONSTRAINT tasks_project_fkey FOREIGN KEY (tenant_id, project_id)
    REFERENCES private.continuity_projects (tenant_id, project_id);
CREATE INDEX tasks_tenant_project_idx ON coord.tasks (tenant_id, project_id);
COMMENT ON COLUMN coord.tasks.project_id IS
  'ADR-0102 D-A: the one writable task->project authority. Only adapters::coord_task_repo::set_task_project_in_txn writes it, and in the same transaction closes and opens the Project CONTAINS Task revisions.';

-- (b) the Unfiled marker.
CREATE TABLE coord.workspace_unfiled_projects (
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  project_id uuid NOT NULL,
  PRIMARY KEY (tenant_id, workspace_id),
  CONSTRAINT workspace_unfiled_projects_project_key UNIQUE (project_id),
  CONSTRAINT workspace_unfiled_projects_project_fkey FOREIGN KEY (tenant_id, workspace_id, project_id)
    REFERENCES private.continuity_projects (tenant_id, workspace_id, project_id)
);
ALTER TABLE coord.workspace_unfiled_projects OWNER TO role_migration_owner;
ALTER TABLE coord.workspace_unfiled_projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE coord.workspace_unfiled_projects FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_unfiled_projects_tenant_isolation ON coord.workspace_unfiled_projects
  USING (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid);
REVOKE ALL ON coord.workspace_unfiled_projects FROM PUBLIC, role_gateway, role_private_worker,
  role_consolidation_worker, role_public_worker, role_retrieval_worker, role_batch_issuer,
  role_maintenance, role_admin;
GRANT SELECT, INSERT ON coord.workspace_unfiled_projects TO role_gateway;
COMMENT ON TABLE coord.workspace_unfiled_projects IS
  'ADR-0102 D-D: the Unfiled project of a workspace (one row per workspace, one marker per project). Rows carry no CONTAINS revision; M18-3a.';

-- (c) backfill from the current CONTAINS, (d) Unfiled for the rest.
DO $backfill$
DECLARE
  ambiguous bigint;
  tenant uuid;
  workspace uuid;
  unfiled uuid;
BEGIN
  SELECT count(*) INTO ambiguous FROM (
    SELECT cur.tenant_id, cur.dst_id
      FROM (SELECT DISTINCT ON (r.tenant_id, r.relation_id) r.tenant_id, r.src_id, r.dst_id, r.relation_kind, r.valid
              FROM private.project_task_relations r
             ORDER BY r.tenant_id, r.relation_id, r.revision DESC) cur
     WHERE cur.relation_kind = 'CONTAINS' AND cur.valid @> now()
     GROUP BY cur.tenant_id, cur.dst_id
    HAVING count(*) > 1) multi;
  IF ambiguous > 0 THEN
    RAISE EXCEPTION 'ADR-0102 D-D backfill: % task(s) have more than one current CONTAINS project', ambiguous;
  END IF;

  UPDATE coord.tasks t
     SET project_id = cur.src_id
    FROM (SELECT DISTINCT ON (r.tenant_id, r.relation_id) r.tenant_id, r.src_id, r.dst_id, r.relation_kind, r.valid
            FROM private.project_task_relations r
           ORDER BY r.tenant_id, r.relation_id, r.revision DESC) cur
   WHERE cur.relation_kind = 'CONTAINS' AND cur.valid @> now()
     AND cur.tenant_id = t.tenant_id AND cur.dst_id = t.task_id;

  FOR tenant IN SELECT DISTINCT t.tenant_id FROM coord.tasks t WHERE t.project_id IS NULL ORDER BY t.tenant_id LOOP
    SELECT w.workspace_id INTO workspace FROM control.workspaces w
     WHERE w.tenant_id = tenant ORDER BY w.created_at, w.workspace_id LIMIT 1;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'ADR-0102 D-D backfill: tenant % has tasks and no workspace to hold their Unfiled project', tenant;
    END IF;
    unfiled := uuidv7();
    INSERT INTO private.continuity_projects (project_id, tenant_id, workspace_id, title)
      VALUES (unfiled, tenant, workspace, 'Unfiled');
    INSERT INTO private.continuity_facet_slots (tenant_id, workspace_id, project_id, facet_kind)
    SELECT tenant, workspace, unfiled, facet_kind
      FROM unnest(ARRAY[
        'GOAL','CURRENT_STATE','DECISIONS','REJECTIONS','CONSTRAINTS','KNOWN_ISSUES',
        'NEXT_ACTIONS','ACTIVE_TASKS','RECENT_CHANGES','CODE','TESTS','CONFIG',
        'MIGRATIONS','PROCEDURES','OUTCOMES']::text[]) AS facet_kind;
    INSERT INTO coord.workspace_unfiled_projects (tenant_id, workspace_id, project_id)
      VALUES (tenant, workspace, unfiled);
    UPDATE coord.tasks t SET project_id = unfiled WHERE t.tenant_id = tenant AND t.project_id IS NULL;
  END LOOP;
END
$backfill$;

-- (f) every task is placed.
ALTER TABLE coord.tasks ALTER COLUMN project_id SET NOT NULL;
