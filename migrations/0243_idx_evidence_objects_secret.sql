-- §46 (REVERSIBLE, transaction = "none"; card 35b-ii, ADR-0071 D-A). Serves the secret-backed exclusion set of the
-- shared final read gate (read_materialize) and the census (exact_census::SECRET_LINKED): with it the set costs one
-- probe per SECRET_MATERIAL evidence of the tenant, never a scan of the tenant's evidence.
--
-- ONE statement, run by `xtask migrate` outside any transaction block (CREATE INDEX CONCURRENTLY is illegal inside
-- one, ADR-0052 D-G). A failed build leaves an INVALID index, the rerun's precheck refuses by name, and the
-- manifest's rollback (DROP INDEX CONCURRENTLY IF EXISTS private.evidence_objects_secret_idx) is also the fix.
-- The predicate is a planner hint, not a definition: if it stopped matching, the set falls back to a scan — slower,
-- never a different set.
CREATE INDEX CONCURRENTLY evidence_objects_secret_idx
  ON private.evidence_objects (tenant_id, evidence_id)
  WHERE data_class = 'SECRET_MATERIAL';
