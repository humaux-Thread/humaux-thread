-- §30.2 / design v0.2 §15 T04c (card M29 T04c; §46 forward-fix, EXPAND_CONTRACT): private.evidence_task_runs, the
-- carrier that binds one Evidence to the task run whose lease verified its write. ADR-0078 D-D's A3 rung (T06) reads
-- it; a write without a verified run has no row, so it never inherits (ADR-0078 T04: "a write after lease expiry does
-- not inherit").
--
-- Invariants:
--   ① one writer: remember.put's receipt transaction, after adapters::coord_repo::verify_task_run passed in that same
--     transaction (adapters::remember::insert_evidence_task_run_in_txn; xtask G-T04c-3 pins the statement to one site).
--   ② one run per Evidence: PK (tenant_id, evidence_id).
--   ③ immutable: no role holds UPDATE or DELETE; every FK is NO ACTION, so nothing cascades into or out of a row.
--   ④ every FK is composite with the tenant leg (RI bypasses RLS). coord.task_runs gains the constrained-redundancy
--     UNIQUE (tenant_id, task_run_id) for that, as 0104 did for evidence_objects and 0249 for coord.tasks.
--   ⑤ FORCE RLS with the §62 tenant clause, NULLIF-hardened (0246).
--
-- Locks: the ADD UNIQUE builds an index under SHARE on coord.task_runs (writes wait for the build); the table is small.

ALTER TABLE coord.task_runs
  ADD CONSTRAINT task_runs_tenant_run_key UNIQUE (tenant_id, task_run_id);

CREATE TABLE private.evidence_task_runs (
  tenant_id     uuid        NOT NULL,
  evidence_id   uuid        NOT NULL,
  task_run_id   uuid        NOT NULL,
  fencing_token bigint      NOT NULL CONSTRAINT evidence_task_runs_fencing_token_positive CHECK (fencing_token > 0),
  verified_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT evidence_task_runs_pkey PRIMARY KEY (tenant_id, evidence_id),
  CONSTRAINT evidence_task_runs_evidence_fkey FOREIGN KEY (tenant_id, evidence_id)
    REFERENCES private.evidence_objects (tenant_id, evidence_id),
  CONSTRAINT evidence_task_runs_task_run_fkey FOREIGN KEY (tenant_id, task_run_id)
    REFERENCES coord.task_runs (tenant_id, task_run_id)
);

-- T06's A3 joins from the run side; also keeps the task_run FK's referencing-side check off a sequential scan.
CREATE INDEX evidence_task_runs_task_run_idx ON private.evidence_task_runs (tenant_id, task_run_id);

ALTER TABLE private.evidence_task_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.evidence_task_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY evidence_task_runs_tenant_isolation ON private.evidence_task_runs
  USING (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('humaux.tenant_id', true), '')::uuid);

-- Owner + NAMED §6.2.2 grants: the gateway writes (INSERT) and reads; nobody holds UPDATE or DELETE.
ALTER TABLE private.evidence_task_runs OWNER TO role_migration_owner;
REVOKE ALL ON private.evidence_task_runs FROM PUBLIC, role_gateway, role_private_worker, role_consolidation_worker,
  role_public_worker, role_retrieval_worker, role_batch_issuer, role_maintenance, role_admin;
GRANT SELECT, INSERT ON private.evidence_task_runs TO role_gateway;

COMMENT ON TABLE private.evidence_task_runs IS
  '§30.2 / design v0.2 §15 T04c: the task run whose lease verified this Evidence''s remember.put, written in that transaction after coord_repo::verify_task_run passed. One row per Evidence, immutable. Read by ADR-0078 D-D A3 (T06). M29 T04c.';
