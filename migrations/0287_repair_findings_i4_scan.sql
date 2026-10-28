-- §46 (EXPAND_CONTRACT; card M21-2, number assigned by the lead: 0287). ADR-0123 D3 / U3, Baseline §59.1 I4 / G59-4, §65.
-- The daily I4 authority scan is report-only: it counts the rows that break `(status = 'superseded') = (superseded_by IS NOT
-- NULL)`, lists up to 100 of their memory_ids and records both; nothing here changes a row it reads (§65 "只报数，不 UPDATE").
--
--   ops.repair_findings        append-only report rows of the report-only §65 jobs (module design note M21 §4, C-M21-2).
--                              A cluster-level job (tenant_id NULL) is the only writer so far; a per-tenant job later writes
--                              its tenant's id. Same RLS shape as 0214 ops.maintenance_receipts (ENABLE + FORCE, one ALL
--                              policy on the NULLIF tenant clause), widened by the `tenant_id IS NULL` arm that 0077 / 0091
--                              use for system-wide rows: a cluster row has no tenant to equal. Grants: role_maintenance
--                              SELECT + INSERT, every other role nothing; nobody holds UPDATE or DELETE, so a finding, once
--                              written, is never edited or erased by a runtime role.
--   ops.i4_authority_scan()    the one I4 scan home. It REPLACES the count-only ops.i4_authority_consistency_scan() of 0004,
--                              which no code ever called and whose EXECUTE sat on PUBLIC by default (ADR-0123 U3). Owner
--                              SECURITY DEFINER with search_path = pg_catalog, pg_temp (as 0272, 0268): the daily job is
--                              cluster-wide and carries no tenant GUC, so it reads private.memory_records as
--                              role_migration_owner, the arm 0163 gave the USING clause of the table's policy. One statement
--                              returns the violating-row count and up to 100 ids ordered by memory_id. EXECUTE: role_maintenance.
--
-- The definer body holds no write statement of any kind (xtask architecture-check G-M21-3 reads it); a repair of production
-- rows stays an owner decision (ADR-0123 owner gates).

CREATE TABLE ops.repair_findings (
  repair_finding_id uuid        PRIMARY KEY DEFAULT uuidv7(),
  -- The exact §65 job name, the key of docs/architecture/schedule_register.toml.
  job               text        NOT NULL,
  ran_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
  -- NULL: a cluster-level job (the I4 scan reads every tenant in one pass).
  tenant_id         uuid,
  finding_count     bigint      NOT NULL CHECK (finding_count >= 0),
  -- A bounded sample of the violating ids, never the full list (ADR-0123 U3: count + at most 100 ids).
  sample_ids        uuid[]      NOT NULL CHECK (cardinality(sample_ids) <= 100),
  detail            jsonb       NOT NULL DEFAULT '{}'::jsonb
);

ALTER TABLE ops.repair_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.repair_findings FORCE ROW LEVEL SECURITY;
CREATE POLICY repair_findings_tenant_isolation ON ops.repair_findings
  USING (tenant_id IS NULL OR tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id IS NULL OR tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid);

-- §6.2.2 column ops.repair_findings (0214 recipe): re-own, revoke the ops-domain default, grant the two cells.
ALTER TABLE ops.repair_findings OWNER TO role_migration_owner;
REVOKE ALL ON ops.repair_findings
FROM PUBLIC, role_gateway, role_private_worker, role_consolidation_worker, role_public_worker,
  role_retrieval_worker, role_batch_issuer, role_maintenance, role_admin, role_health_reader;
GRANT SELECT, INSERT ON ops.repair_findings TO role_maintenance;

DROP FUNCTION ops.i4_authority_consistency_scan();

CREATE FUNCTION ops.i4_authority_scan()
RETURNS TABLE (finding_count bigint, sample_ids uuid[])
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  WITH v AS (
    SELECT m.memory_id
      FROM private.memory_records m
     WHERE (m.status = 'superseded') IS DISTINCT FROM (m.superseded_by IS NOT NULL)
  )
  SELECT (SELECT count(*) FROM v),
         coalesce((SELECT array_agg(s.memory_id ORDER BY s.memory_id)
                     FROM (SELECT memory_id FROM v ORDER BY memory_id LIMIT 100) s),
                  ARRAY[]::uuid[])
$$;
ALTER FUNCTION ops.i4_authority_scan() OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION ops.i4_authority_scan() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ops.i4_authority_scan() TO role_maintenance;

COMMENT ON TABLE ops.repair_findings IS
  'ADR-0123 D3: append-only report rows of the report-only §65 jobs; tenant_id NULL = a cluster-level job. role_maintenance SELECT + INSERT only.';
COMMENT ON FUNCTION ops.i4_authority_scan() IS
  '§59.1 I4 / §65: violating-row count of (status = superseded) <=> (superseded_by IS NOT NULL) plus up to 100 memory_ids; EXECUTE role_maintenance only; reads, never writes (ADR-0123 D3 / U3).';
