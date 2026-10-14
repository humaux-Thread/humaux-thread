-- §46 forward-fix (EXPAND_CONTRACT, first free number after 0241). Card 35b (ADR-0070): the §6.1.3 subject guard on
-- private.memory_records stops costing one SECURITY DEFINER call per row.
--
-- Why: the RESTRICTIVE policy memory_records_subject_visibility (0155) calls private.memory_subject_visibility_ok for
-- every row a gateway / maintenance read touches, and PostgreSQL never inlines a SECURITY DEFINER function, so a read
-- that scans 10 000 memories spends ~200 ms in that function alone (card 41's measurement: 199 of 218 ms) even though
-- nearly every memory has no subject link at all.
--
-- What:
--   1. private.memory_subject_presence(tenant_id, memory_id): one row per memory that has at least one
--      private.memory_subjects link. Written only by the trigger below (an INSERT on memory_subjects adds its memory;
--      ON CONFLICT DO NOTHING); a row goes away with its memory (FK ON DELETE CASCADE). It is never deleted when links
--      go away (links are insert-only at runtime; a subject deletion cascades them) — a stale presence row is the safe
--      direction: the full guard runs for that memory. The table has a tenant-only RLS policy and no memory_records
--      reference, so reading it from memory_records' policy has no cycle (the reason 0155 needed a definer at all).
--   2. The RESTRICTIVE policy becomes `tenant AND (NOT EXISTS presence OR memory_subject_visibility_ok(...))`. For a
--      memory without links the guard is true by construction, so the result never depends on which OR arm runs;
--      the planner evaluates the cheap hashed anti-join arm first (the call-count gate pins it). A memory with links
--      gets exactly the 0155 guard. The authorization truth table is unchanged.
--   3. Backfill from the existing links.
--
-- Locks: CREATE TABLE / TRIGGER and ALTER POLICY take brief catalog locks; the backfill reads memory_subjects once.

CREATE TABLE private.memory_subject_presence (
  tenant_id  uuid NOT NULL,
  memory_id  uuid NOT NULL,
  PRIMARY KEY (tenant_id, memory_id),
  CONSTRAINT memory_subject_presence_memory_fkey
    FOREIGN KEY (tenant_id, memory_id) REFERENCES private.memory_records (tenant_id, memory_id)
    ON DELETE CASCADE
);

ALTER TABLE private.memory_subject_presence OWNER TO role_migration_owner;
REVOKE ALL ON private.memory_subject_presence
  FROM PUBLIC, role_gateway, role_private_worker, role_consolidation_worker, role_public_worker,
       role_retrieval_worker, role_batch_issuer, role_maintenance, role_admin;
GRANT SELECT ON private.memory_subject_presence TO role_gateway, role_maintenance;

ALTER TABLE private.memory_subject_presence ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.memory_subject_presence FORCE ROW LEVEL SECURITY;
CREATE POLICY memory_subject_presence_tenant ON private.memory_subject_presence
  USING (tenant_id = current_setting('humaux.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('humaux.tenant_id', true)::uuid);
-- §73.5.1 / 0112: the trigger's SECURITY DEFINER still obeys FORCE RLS as role_migration_owner, and a link insert
-- need not carry humaux.tenant_id (a superuser or ops path bypasses memory_subjects' RLS). The index write is the
-- owner's alone — no runtime role holds INSERT — and the composite FK pins each row to its memory's tenant.
CREATE POLICY memory_subject_presence_owner_insert ON private.memory_subject_presence
  FOR INSERT TO role_migration_owner
  WITH CHECK (current_user = 'role_migration_owner');

COMMENT ON TABLE private.memory_subject_presence IS
  'Card 35b / ADR-0070: one row per memory with at least one private.memory_subjects link, maintained by the '
  'memory_subject_presence_on_insert trigger; read only by memory_records_subject_visibility to skip the per-row '
  'subject guard for unlinked memories. A stale row (links since cascaded away) only makes the guard run.';

CREATE FUNCTION private.memory_subject_presence_on_insert() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  INSERT INTO private.memory_subject_presence (tenant_id, memory_id)
  VALUES (NEW.tenant_id, NEW.memory_id)
  ON CONFLICT DO NOTHING;
  RETURN NULL;
END;
$$;

ALTER FUNCTION private.memory_subject_presence_on_insert() OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION private.memory_subject_presence_on_insert() FROM PUBLIC;

CREATE TRIGGER memory_subject_presence_on_insert
  AFTER INSERT ON private.memory_subjects
  FOR EACH ROW
  EXECUTE FUNCTION private.memory_subject_presence_on_insert();

INSERT INTO private.memory_subject_presence (tenant_id, memory_id)
SELECT DISTINCT ms.tenant_id, ms.memory_id FROM private.memory_subjects ms
ON CONFLICT DO NOTHING;

ALTER POLICY memory_records_subject_visibility ON private.memory_records
  USING (
    tenant_id = current_setting('humaux.tenant_id', true)::uuid
    AND (NOT EXISTS (SELECT 1 FROM private.memory_subject_presence p
                      WHERE p.tenant_id = memory_records.tenant_id
                        AND p.memory_id = memory_records.memory_id)
         OR private.memory_subject_visibility_ok(tenant_id, memory_id))
  );

COMMENT ON POLICY memory_records_subject_visibility ON private.memory_records IS
  '§6.1.3 / ADR-0029 (0155), set-based shortcut ADR-0070 (0242): AS RESTRICTIVE subject-visibility guard ANDed on top '
  'of memory_records_tenant_and_visibility for role_gateway/role_maintenance. A memory with no subject link '
  '(no private.memory_subject_presence row) passes without the per-row definer; one with links runs '
  'private.memory_subject_visibility_ok exactly as before.';
