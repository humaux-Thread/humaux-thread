-- M29 T04a (§30.1, §30.2): task state and task-run lease on the 0009 coord skeleton.
--
-- coord.tasks gains the §30.1 state closed set and `fencing_seq`, the per-task counter every claim
-- increments; coord.task_runs gains the §30.2 lease triple. A run's `fencing_token` is the task's
-- `fencing_seq` at the claim that opened it, so "token == the task's current fencing_seq" is the
-- whole stale-writer test (adapters::coord_repo::verify_task_run).
--
-- Expand-only: added columns (defaulted or NULL), CHECKs that every existing row satisfies, one
-- partial unique index. `ADD COLUMN ... DEFAULT` stores the default for every existing task, so
-- each one reads SUBMITTED with fencing_seq 0 without an UPDATE. coord.tasks and coord.task_runs
-- already carry ENABLE + FORCE RLS and the §62 tenant policy (0012, NULLIF since 0246) and
-- role_gateway already holds SELECT, INSERT, UPDATE on every coord table (0011, §6.2.1): no policy,
-- role or grant changes here.

-- §30.1 closed set. adapters/tests/coord_task_run.rs reconciles these labels with
-- humaux_domain::coordination::TaskState (§78.2).
ALTER TABLE coord.tasks
  ADD COLUMN state text NOT NULL DEFAULT 'SUBMITTED'
    CONSTRAINT tasks_state_check CHECK (state IN (
      'SUBMITTED', 'CLAIMED', 'WORKING', 'BLOCKED', 'COMPLETED', 'FAILED', 'CANCELLED')),
  ADD COLUMN fencing_seq bigint NOT NULL DEFAULT 0
    CONSTRAINT tasks_fencing_seq_nonnegative CHECK (fencing_seq >= 0);

COMMENT ON COLUMN coord.tasks.fencing_seq IS
  '§30.2: incremented by every claim; the claim''s new value is the run''s fencing_token. A token below this value belongs to a superseded run.';

-- §30.2 lease. `lease_owner` is the authenticated principal (AuthorizationScope::principal), never a
-- client-supplied name. The three columns are set together or not at all: 0009-era runs carry no
-- lease and are never verifiable.
ALTER TABLE coord.task_runs
  ADD COLUMN lease_owner uuid,
  ADD COLUMN lease_expires_at timestamptz,
  ADD COLUMN fencing_token bigint,
  ADD CONSTRAINT task_runs_lease_shape CHECK (
    (lease_owner IS NULL) = (lease_expires_at IS NULL)
    AND (lease_owner IS NULL) = (fencing_token IS NULL)
    AND (fencing_token IS NULL OR fencing_token > 0)
  );

-- At most one open leased run per task: a claim closes the previous run before it opens its own.
CREATE UNIQUE INDEX task_runs_one_open_lease_per_task
  ON coord.task_runs (task_id)
  WHERE finished_at IS NULL AND fencing_token IS NOT NULL;
