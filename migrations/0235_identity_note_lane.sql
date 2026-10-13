-- §46 forward-fix (EXPAND_CONTRACT, first free number after 0234). ADR-0067 (card 40a, memory.note_put): the verbatim
-- note lane's storage.
--
--   1. private.memory_records.note_kind — the author's classification of a note, NULL for every non-note Memory, a closed
--      nine-value CHECK, and a CHECK that binds each value to the memory_type it is stored under (D-D). The generated
--      `facet` (0172) is untouched; the Rust NoteKind is reconciled against both CHECKs and the facet by a contract test.
--   2. private.identity_note_materializations — the identity contract (D-B): one row per Evidence that is turned into
--      exactly one Memory by the gateway in the SAME transaction, with no LLM derivation. PK (tenant, evidence) so an
--      Evidence has at most one contract; UNIQUE (tenant, output_memory) so a Memory is the output of at most one.
--   3. private.memory_evidence gets a BEFORE INSERT trigger: a PRIMARY link from a contracted Evidence to any Memory but its
--      contract output is refused (G06). Ordinary Evidence is unaffected — no UNIQUE on memory_evidence.evidence_id (§8.5).
--   4. ops.enqueue_derived_distill_work() (0164) skips an Evidence that has a contract: the audit, stream and projection
--      events still flow, only semantic derivation is skipped. The split is by the persisted contract, never by
--      event_kind (that would reinterpret every historic MANUAL_NOTE and remember.put itself).
--   5. A BEFORE INSERT trigger on ops.outbox settles the EVIDENCE_ACCEPTED row of a contracted Evidence at birth (status
--      DONE): the Memory already exists, so there is nothing for distill to settle, and the projection claim (0176) holds a
--      ticket back while its EVIDENCE_ACCEPTED row is PENDING/PROCESSING. role_gateway's INSERT grant on ops.outbox is
--      column-level (no status), so the settle is the trigger's, not the writer's — no grant is added. It also covers a
--      replayed outbox insert.
--
-- RLS of the new table is evidence_affects' (0157): the tenant clause AND the parent Evidence's visibility through EXISTS.
-- A Memory carries its Evidence's visibility verbatim (distill_repo::insert_memory), so the contract is exactly as
-- visible as the note. Owner role_migration_owner; gateway SELECT+INSERT (the receipt transaction and the enqueue trigger
-- run under it), private worker + maintenance SELECT (the worker's pre-reservation re-check). Nobody holds UPDATE/DELETE.
-- No DML; no existing policy or grant is altered.

ALTER TABLE private.memory_records ADD COLUMN note_kind text;

ALTER TABLE private.memory_records
  ADD CONSTRAINT memory_records_note_kind_check
    CHECK (note_kind IS NULL OR note_kind IN
      ('rejected','decision','fix','problem','lesson','research','preference','state','note')),
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
        OR (note_kind = 'note'       AND memory_type = 'NOTE'));

COMMENT ON COLUMN private.memory_records.note_kind IS
  'ADR-0067 D-D: the author''s classification of a verbatim note (memory.note_put); NULL for every other Memory. It certifies no truth and decides no authority. Bound to memory_type by memory_records_note_kind_memory_type_check.';

CREATE TABLE private.identity_note_materializations (
  tenant_id        uuid NOT NULL REFERENCES control.tenants(tenant_id) ON DELETE CASCADE,
  evidence_id      uuid NOT NULL,
  strategy         text NOT NULL CHECK (strategy = 'identity_note_v1'),
  output_memory_id uuid NOT NULL,
  body_sha256      bytea NOT NULL CHECK (octet_length(body_sha256) = 32),
  policy_version   text NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 64),
  created_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, evidence_id),
  CONSTRAINT identity_note_materializations_output_key UNIQUE (tenant_id, output_memory_id),
  CONSTRAINT identity_note_materializations_evidence_fkey
    FOREIGN KEY (tenant_id, evidence_id) REFERENCES private.evidence_objects (tenant_id, evidence_id)
    ON DELETE CASCADE,
  CONSTRAINT identity_note_materializations_output_fkey
    FOREIGN KEY (tenant_id, output_memory_id) REFERENCES private.memory_records (tenant_id, memory_id)
    ON DELETE CASCADE
);

ALTER TABLE private.identity_note_materializations ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.identity_note_materializations FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_note_materializations_tenant_and_parent ON private.identity_note_materializations
  USING (tenant_id = current_setting('humaux.tenant_id', true)::uuid
         AND EXISTS (SELECT 1 FROM private.evidence_objects e
                     WHERE e.evidence_id = identity_note_materializations.evidence_id
                       AND e.tenant_id = identity_note_materializations.tenant_id))
  WITH CHECK (tenant_id = current_setting('humaux.tenant_id', true)::uuid
         AND EXISTS (SELECT 1 FROM private.evidence_objects e
                     WHERE e.evidence_id = identity_note_materializations.evidence_id
                       AND e.tenant_id = identity_note_materializations.tenant_id));

ALTER TABLE private.identity_note_materializations OWNER TO role_migration_owner;

REVOKE ALL ON private.identity_note_materializations
  FROM PUBLIC, role_gateway, role_private_worker, role_consolidation_worker, role_public_worker,
       role_retrieval_worker, role_batch_issuer, role_maintenance, role_admin;

GRANT SELECT, INSERT ON private.identity_note_materializations TO role_gateway;
GRANT SELECT         ON private.identity_note_materializations TO role_private_worker, role_maintenance;

COMMENT ON TABLE private.identity_note_materializations IS
  'ADR-0067 D-B identity contract: this Evidence is materialised by the gateway as exactly one Memory (output_memory_id) in the same transaction, with no LLM derivation. Written once, never updated.';

-- G06: a contracted Evidence has exactly one PRIMARY output. SECURITY INVOKER: the check sees the contract only when the
-- inserting session can see the Evidence (the contract's policy delegates to the Evidence's visibility). Every writer of a
-- PRIMARY link today (distill for its own Evidence, note_put for the Evidence it just wrote) can; a session linking a
-- Memory to an Evidence it cannot see is not a path that exists — ponytail: owner-run (SECURITY DEFINER) check if one
-- ever does (PR #7 independent review P2-4).
CREATE FUNCTION private.identity_note_single_output() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM private.identity_note_materializations c
              WHERE c.evidence_id = NEW.evidence_id AND c.output_memory_id <> NEW.memory_id) THEN
    RAISE EXCEPTION 'identity-contract Evidence has exactly one output Memory (ADR-0067 D-B)'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
ALTER FUNCTION private.identity_note_single_output() OWNER TO role_migration_owner;

CREATE TRIGGER identity_note_single_output
  BEFORE INSERT ON private.memory_evidence
  FOR EACH ROW
  WHEN (NEW.role = 'PRIMARY')
  EXECUTE FUNCTION private.identity_note_single_output();

CREATE FUNCTION ops.settle_identity_note_outbox() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM private.identity_note_materializations c
              WHERE c.tenant_id = NEW.tenant_id AND c.evidence_id = NEW.evidence_id) THEN
    NEW.status := 'DONE';
    NEW.processed_at := now();
  END IF;
  RETURN NEW;
END;
$$;
ALTER FUNCTION ops.settle_identity_note_outbox() OWNER TO role_migration_owner;

CREATE TRIGGER identity_note_outbox_settled
  BEFORE INSERT ON ops.outbox
  FOR EACH ROW
  WHEN (NEW.event_type = 'EVIDENCE_ACCEPTED')
  EXECUTE FUNCTION ops.settle_identity_note_outbox();

-- D-B: 0164's enqueue function, verbatim, plus the contract skip. The DERIVED_DISTILL job and everything it reserves
-- (provider slot, tenant scheduler turn, budget) simply never exist for a contracted Evidence.
CREATE OR REPLACE FUNCTION ops.enqueue_derived_distill_work()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE domain_id uuid;
BEGIN
  IF NEW.evidence_id IS NULL THEN
    RETURN NULL;
  END IF;
  IF EXISTS (SELECT 1 FROM private.identity_note_materializations c
              WHERE c.tenant_id = NEW.tenant_id AND c.evidence_id = NEW.evidence_id) THEN
    RETURN NULL;
  END IF;
  SELECT e.reasoning_domain_id INTO domain_id
  FROM private.evidence_objects e
  WHERE e.evidence_id = NEW.evidence_id AND e.tenant_id = NEW.tenant_id;
  IF domain_id IS NULL THEN
    RETURN NULL;
  END IF;
  INSERT INTO ops.jobs (tenant_id, job_type, status, next_retry_at, idempotency_key, payload)
  VALUES (NEW.tenant_id, 'DERIVED_DISTILL', 'PENDING', clock_timestamp(),
          'derived-work:DERIVED_DISTILL:' || NEW.evidence_id::text,
          jsonb_build_object('schema_version', 1,
                             'reasoning_domain_id', domain_id::text,
                             'evidence_id', NEW.evidence_id::text))
  ON CONFLICT (idempotency_key) DO NOTHING;
  RETURN NULL;
END;
$$;

-- D-B / D-I: 0164's consolidate enqueue, verbatim, plus a note skip. A note's PRIMARY link enqueues no
-- DERIVED_CONSOLIDATE job (that job calls the LLM: the card's zero-provider gate covers every generative call a note
-- causes). The test is the Memory's note_kind — set only by memory.note_put — not the identity contract, because the
-- gateway inserts the Memory and its PRIMARY link before the contract row. A later ordinary memory in the same domain
-- still enqueues a pass, and that pass may read notes as inputs; the note itself never triggers one.
CREATE OR REPLACE FUNCTION ops.enqueue_derived_consolidate_work()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE tenant uuid; domain_id uuid;
BEGIN
  SELECT mr.tenant_id, e.reasoning_domain_id INTO tenant, domain_id
  FROM private.memory_records mr
  JOIN private.evidence_objects e
    ON e.evidence_id = NEW.evidence_id AND e.tenant_id = mr.tenant_id
  WHERE mr.memory_id = NEW.memory_id AND mr.note_kind IS NULL;
  IF tenant IS NULL OR domain_id IS NULL THEN
    RETURN NULL;
  END IF;
  INSERT INTO ops.jobs (tenant_id, job_type, status, next_retry_at, idempotency_key, payload)
  VALUES (tenant, 'DERIVED_CONSOLIDATE', 'PENDING', clock_timestamp(),
          'derived-work:DERIVED_CONSOLIDATE:' || NEW.memory_id::text,
          jsonb_build_object('schema_version', 1,
                             'reasoning_domain_id', domain_id::text,
                             'memory_id', NEW.memory_id::text))
  ON CONFLICT (idempotency_key) DO NOTHING;
  RETURN NULL;
END;
$$;
