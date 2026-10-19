-- M29 T04b (§30.2, ADR-0078 Q10): the two free-text fields coordinate.task_submit / task_complete / task_fail carry on
-- the wire. `coord.tasks.description` is the task's brief; `coord.task_runs.outcome_summary` is the closing run's report.
--
-- Expand-only: two nullable columns. Rows written before this migration have neither, so both stay NULL; a CHECK that
-- is NULL on NULL accepts them. The length bounds equal contracts/mcp/coordinate.schema.json minLength / maxLength
-- (1..8192) so the database refuses what the wire contract already refuses. coord.tasks and coord.task_runs keep the
-- ENABLE + FORCE RLS and tenant policy of 0012 / 0246, and role_gateway keeps its table-level SELECT, INSERT, UPDATE
-- (0011): no policy, role or grant changes here.

ALTER TABLE coord.tasks
  ADD COLUMN description text
    CONSTRAINT tasks_description_length CHECK (char_length(description) BETWEEN 1 AND 8192);

ALTER TABLE coord.task_runs
  ADD COLUMN outcome_summary text
    CONSTRAINT task_runs_outcome_summary_length CHECK (char_length(outcome_summary) BETWEEN 1 AND 8192);
