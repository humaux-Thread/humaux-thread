-- §46 forward-fix (EXPAND_CONTRACT, first free number after 0235). ADR-0067 D-J as adjudicated (card 40c-1): note
-- identity and the confirmed replacement loop of memory.note_put.
--
--   1. private.memory_records.note_id — the note a version belongs to (= its first version's memory_id, no FK to that
--      root), NULL exactly when note_kind is NULL (CHECK). A new version may carry another note_kind; no version is ever
--      re-classified in place.
--   2. private.note_heads (tenant_id, note_id) -> head_memory_id: the note's lock anchor. A replacement takes its row
--      FOR UPDATE, CAS-checks head = supersedes, supersedes the old version in one guarded UPDATE and moves the head, all
--      in the memory.note_put receipt transaction. Composite FK to memory_records (tenant_id, memory_id) — 0104's UNIQUE —
--      cascading, as 0235's contract FK does. FORCE RLS = the tenant GUC only (see the policy's comment: the head's visibility
--      is the writer's final read gate, never an RLS EXISTS re-evaluated under a stale snapshot).
--   3. memory_records_one_active_note_version: at most one active version per (tenant, note) — an EXCLUDE checked at
--      COMMIT (DEFERRABLE INITIALLY DEFERRED: the new version is inserted active before the old one is superseded in the
--      same transaction), so a bypassed CAS still cannot leave two heads.
--   4. control.confirm_tokens.request_sha256 — the replacement intent digest H a memory.note_put token binds; NULL for
--      every other operation, and every consumer matches it with IS NOT DISTINCT FROM, so no other tool can spend a note
--      token (ADR-0018 extended).
--
-- DML, and why it is allowed here: every 40a note becomes a singleton (note_id = memory_id, head = itself) before the
-- CHECK is added. This is a forward-fix of a lane that has never been deployed (merge != go-live): the precheck refuses
-- to run if any note already has a supersession edge in or out, which is the only state a singleton backfill could
-- misdescribe. The statements touch note rows only.
--
-- Grants: role_gateway SELECT, INSERT, UPDATE(head_memory_id) (the receipt transaction; FOR UPDATE needs the column
-- UPDATE); role_maintenance SELECT; nobody else, nobody DELETE (the memory_records cascade is the only delete path).
-- control.confirm_tokens keeps its 0148 grants (table-level INSERT covers the new column). Owner role_migration_owner.

ALTER TABLE private.memory_records ADD COLUMN note_id uuid;

UPDATE private.memory_records SET note_id = memory_id WHERE note_kind IS NOT NULL;

ALTER TABLE private.memory_records
  ADD CONSTRAINT memory_records_note_id_iff_note_kind
    CHECK ((note_id IS NOT NULL) = (note_kind IS NOT NULL));

ALTER TABLE private.memory_records
  ADD CONSTRAINT memory_records_one_active_note_version
    EXCLUDE USING btree (tenant_id WITH =, note_id WITH =)
    WHERE (status = 'active' AND note_id IS NOT NULL)
    DEFERRABLE INITIALLY DEFERRED;

COMMENT ON COLUMN private.memory_records.note_id IS
  'ADR-0067 D-J: the note this version belongs to (its first version''s memory_id; no FK to that root). NULL exactly when note_kind is NULL. At most one active version per (tenant_id, note_id): memory_records_one_active_note_version.';

CREATE TABLE private.note_heads (
  tenant_id      uuid NOT NULL REFERENCES control.tenants(tenant_id) ON DELETE CASCADE,
  note_id        uuid NOT NULL,
  head_memory_id uuid NOT NULL,
  PRIMARY KEY (tenant_id, note_id),
  CONSTRAINT note_heads_head_fkey
    FOREIGN KEY (tenant_id, head_memory_id) REFERENCES private.memory_records (tenant_id, memory_id)
    ON DELETE CASCADE
);

INSERT INTO private.note_heads (tenant_id, note_id, head_memory_id)
SELECT tenant_id, note_id, memory_id FROM private.memory_records WHERE note_id IS NOT NULL;

ALTER TABLE private.note_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.note_heads FORCE ROW LEVEL SECURITY;
-- Tenant clause only. The head's visibility is the final read gate's, run by the writer in its own statement AFTER
-- the head row lock: an EXISTS on memory_records here would be re-evaluated (EvalPlanQual) under the locking
-- statement's original snapshot when a concurrent replacement moves the head, which cannot see the winner's new
-- version, so the loser would read "no such note" instead of STALE_NOTE_VERSION (G20). A head row carries no content.
CREATE POLICY note_heads_tenant ON private.note_heads
  USING (tenant_id = current_setting('humaux.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('humaux.tenant_id', true)::uuid);

ALTER TABLE private.note_heads OWNER TO role_migration_owner;

REVOKE ALL ON private.note_heads
  FROM PUBLIC, role_gateway, role_private_worker, role_consolidation_worker, role_public_worker,
       role_retrieval_worker, role_batch_issuer, role_maintenance, role_admin;

GRANT SELECT, INSERT ON private.note_heads TO role_gateway;
GRANT UPDATE (head_memory_id) ON private.note_heads TO role_gateway;
GRANT SELECT ON private.note_heads TO role_maintenance;

COMMENT ON TABLE private.note_heads IS
  'ADR-0067 D-J: one row per note, pointing at its current version; the lock anchor of a memory.note_put replacement (SELECT ... FOR UPDATE, CAS head = supersedes). Written only in the memory.note_put receipt transaction.';

ALTER TABLE control.confirm_tokens
  ADD COLUMN request_sha256 bytea CHECK (request_sha256 IS NULL OR octet_length(request_sha256) = 32);

COMMENT ON COLUMN control.confirm_tokens.request_sha256 IS
  'ADR-0067 D-J: the memory.note_put replacement intent digest H the token binds; NULL for every other operation. Matched by every consumer with IS NOT DISTINCT FROM.';
