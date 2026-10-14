-- §46 (REVERSIBLE, transaction = "none"; card 35b-ii, ADR-0071 D-A). Serves the tombstoned exclusion set of the
-- shared final read gate (read_materialize) and the census overlay (exact_census::NOT_TOMBSTONED): with it the set
-- costs one probe per TOMBSTONED stream row of the tenant (joined to ops.outbox on its (tenant_id, commit_seq) key),
-- never a scan of the tenant's stream log.
--
-- ONE statement, outside any transaction block (ADR-0052 D-G); failure and rollback as 0243. The predicate is a planner
-- hint: if it stopped matching, the set falls back to a scan — slower, never a different set.
CREATE INDEX CONCURRENTLY stream_log_tombstoned_idx
  ON projection.stream_log (tenant_id, commit_seq)
  WHERE state = 'TOMBSTONED';
