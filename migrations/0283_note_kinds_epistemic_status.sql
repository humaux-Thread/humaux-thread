-- §46 forward-fix (EXPAND_CONTRACT, number assigned by the lead: 0283). ADR-0124 (M07-5, G-M07-6) amends ADR-0067 D-D:
--
--   1. private.memory_records.note_kind gains three kinds, event, plan and episode, all stored under memory_type NOTE
--      (note :54). Both 0235 CHECKs are replaced by their twelve-value versions under the same names:
--      memory_records_note_kind_check (the label set) and memory_records_note_kind_memory_type_check (the kind -> memory_type
--      binding). Every existing arm is kept byte for byte in meaning, so every existing row (note_kind NULL or one of the
--      nine) satisfies both. 0235 itself is never edited. humaux_domain::note::NoteKind carries the same twelve labels and
--      pairs; adapters::tests::facet_contract reconciles the two sets (§78.2, G-M07-6).
--   2. private.memory_records.epistemic_status text NOT NULL DEFAULT 'UNKNOWN' with a CHECK on four values. A Memory
--      written before this migration reads UNKNOWN by the default; there is no backfill. The Memory INSERT door
--      (adapters::memory_repo::insert_memory_in_txn) binds the status from the caller's producer. The column certifies no
--      truth and grants no authority: authority_class and the §10.1 ceilings are untouched and never read it.
--
-- Add-constraint style: plain ADD CONSTRAINT, as the newest memory_records CHECK migration on main (0236, the
-- note_id-iff-note_kind CHECK) does, not NOT VALID + VALIDATE as 0247 does for private.subjects. DROP and ADD of the two
-- CHECKs are one ALTER TABLE, so there is no window without a note_kind CHECK. The ADD validates every row once under
-- ACCESS EXCLUSIVE, the same cost class as 0235 and 0236 paid on this table; the ADD COLUMN with a constant default is a
-- catalog-only change on PostgreSQL 18, no row is rewritten.
--
-- Grants: none added or changed. role_gateway and role_private_worker hold table-level INSERT on private.memory_records
-- (0011), which covers the new column; nobody can UPDATE it (the column grants of 0011/0148/0149/0150 name other columns).
-- No DML; no policy, trigger or index is touched.
ALTER TABLE private.memory_records
  ADD COLUMN epistemic_status text NOT NULL DEFAULT 'UNKNOWN',
  ADD CONSTRAINT memory_records_epistemic_status_check
    CHECK (epistemic_status IN ('SOURCE_REPORTED','INTERPRETATION','DIRECT_OBSERVATION','UNKNOWN')),
  DROP CONSTRAINT memory_records_note_kind_check,
  DROP CONSTRAINT memory_records_note_kind_memory_type_check,
  ADD CONSTRAINT memory_records_note_kind_check
    CHECK (note_kind IS NULL OR note_kind IN
      ('rejected','decision','fix','problem','lesson','research','preference','state','note','event','plan','episode')),
  ADD CONSTRAINT memory_records_note_kind_memory_type_check
    CHECK (note_kind IS NULL
        OR (note_kind = 'rejected'   AND memory_type = 'REJECTION')
        OR (note_kind = 'decision'   AND memory_type = 'DECISION')
        OR (note_kind = 'fix'        AND memory_type = 'OUTCOME')
        OR (note_kind = 'problem'    AND memory_type = 'ISSUE')
        OR (note_kind = 'lesson'     AND memory_type = 'LESSON')
        OR (note_kind = 'research'   AND memory_type = 'NOTE')
        OR (note_kind = 'preference' AND memory_type = 'PREFERENCE')
        OR (note_kind = 'state'      AND memory_type = 'STATE')
        OR (note_kind = 'note'       AND memory_type = 'NOTE')
        OR (note_kind = 'event'      AND memory_type = 'NOTE')
        OR (note_kind = 'plan'       AND memory_type = 'NOTE')
        OR (note_kind = 'episode'    AND memory_type = 'NOTE'));

COMMENT ON COLUMN private.memory_records.epistemic_status IS
  'ADR-0124: how the text came to be: SOURCE_REPORTED (a source''s own assertion), INTERPRETATION (a model''s reading), DIRECT_OBSERVATION (a tool result; no writer yet), UNKNOWN (default; every Memory written before 0283). Set by the Memory INSERT door from the caller''s producer, never from the Evidence origin class. It certifies no truth and grants no authority; the §10.1 ceilings and authority_class are unchanged.';
