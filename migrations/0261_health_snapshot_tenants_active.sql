-- §46 forward-fix (EXPAND_CONTRACT, M22-2): ops.health_snapshot(timestamptz) gains two columns,
-- tenants_active_1d / tenants_active_7d, the §41.2 inputs of the M22 headroom rule (capacity per active tenant).
--
-- Definition: an ACTIVE tenant counts when one of its control.api_keys rows was used inside the window
-- (last_used_at, written by control.api_key_touch_last_used on every authenticated request, 0039). Counted
-- per distinct tenant, never per key; a key revoked after its use still shows the tenant active in the window; a
-- tenant in any other state (SUSPENDED, DELETED, ...) does not count.
--
-- Why a second definer: ADR-0061 D-D / rls_check `check_health_reader_boundary` pin role_health_reader to SELECT
-- on exactly five relations and one policy each, so this card does not grow that set. control.api_keys and
-- control.tenants already admit role_migration_owner across tenants (0112 `*_bootstrap_owner_select`, the same
-- door control.assert_write_scope uses, 0188), so the counts come from one owner-owned SECURITY DEFINER whose only
-- executor is role_health_reader, called from inside ops.health_snapshot. No policy, no table grant and no
-- executor of ops.health_snapshot changes.
--
-- The return shape of ops.health_snapshot changes, which CREATE OR REPLACE cannot do, so it is dropped and
-- re-created in this one transaction (0200 precedent): same name and argument, owner role_health_reader, SECURITY
-- DEFINER, pinned search_path, EXECUTE role_maintenance only. The 15 columns of 0210 keep their order and the two new
-- ones are appended.
--
-- Deploy order: apply this migration with `health serve` stopped, or restart it right after. A process that stayed
-- up may hold a cached prepared `SELECT * FROM ops.health_snapshot($1)`, which PostgreSQL rejects with "cached plan
-- must not change result type", so `/metrics` answers 503 until that connection is recycled (runbook, upgrade U4-U7).

-- Windows are fixed hours, not calendar days: the session time zone never moves them across a DST change.
-- ponytail: O(api_keys) scan per sample, no last_used_at index, because every authenticated request rewrites that
-- column and an index on it would end HOT updates on api_keys; add a partial index when keys exceed ~10^5.
CREATE FUNCTION ops.tenants_active_counts()
RETURNS TABLE (
  tenants_active_1d bigint,
  tenants_active_7d bigint
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $fn$
  SELECT count(DISTINCT k.tenant_id) FILTER (WHERE k.last_used_at > now() - interval '24 hours'),
         count(DISTINCT k.tenant_id)
    FROM control.api_keys k
    JOIN control.tenants t ON t.tenant_id = k.tenant_id
   WHERE t.state = 'ACTIVE'
     AND k.last_used_at > now() - interval '168 hours'
$fn$;

ALTER FUNCTION ops.tenants_active_counts() OWNER TO role_migration_owner;
REVOKE ALL ON FUNCTION ops.tenants_active_counts() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ops.tenants_active_counts() TO role_health_reader;

COMMENT ON FUNCTION ops.tenants_active_counts() IS
  'M22-2: distinct ACTIVE tenants with an api_keys row used within 24 h / 168 h. Owner definer reading through 0112''s '
  'owner SELECT policies; EXECUTE role_health_reader only, called by ops.health_snapshot.';

DROP FUNCTION ops.health_snapshot(timestamptz);

CREATE FUNCTION ops.health_snapshot(p_finalized_since timestamptz)
RETURNS TABLE (
  as_of timestamptz,
  jobs_pending bigint,
  jobs_processing bigint,
  jobs_waiting_key bigint,
  jobs_dead bigint,
  oldest_pending_age_seconds double precision,
  projection_lag_events bigint,
  gap_domains text[],
  gap_projection_kinds text[],
  gap_counts bigint[],
  reserved_le_10s bigint,
  reserved_le_60s bigint,
  reserved_gt_60s bigint,
  finalized_outcomes text[],
  finalized_counts bigint[],
  tenants_active_1d bigint,
  tenants_active_7d bigint
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, ops, projection
AS $fn$
  WITH jobs AS (
    SELECT count(*) FILTER (WHERE j.status = 'PENDING') AS pending,
           count(*) FILTER (WHERE j.status = 'PROCESSING') AS processing,
           count(*) FILTER (WHERE j.status = 'WAITING_KEY') AS waiting_key,
           count(*) FILTER (WHERE j.status = 'DEAD') AS dead,
           coalesce(extract(epoch FROM now() - min(j.created_at) FILTER (WHERE j.status = 'PENDING')), 0)
             ::double precision AS oldest_pending
      FROM ops.jobs j
     WHERE j.status IN ('PENDING', 'PROCESSING', 'WAITING_KEY', 'DEAD')
  ), lag AS (
    SELECT coalesce(sum(c.issued_highwater - c.projection_highwater), 0)::bigint AS events
      FROM projection.stream_checkpoints c
  ), gaps AS (
    SELECT coalesce(array_agg(g.domain ORDER BY g.domain, g.projection_kind), '{}') AS domains,
           coalesce(array_agg(g.projection_kind ORDER BY g.domain, g.projection_kind), '{}') AS kinds,
           coalesce(array_agg(g.n ORDER BY g.domain, g.projection_kind), '{}') AS counts
      FROM (SELECT p.domain, p.projection_kind, count(*) AS n
              FROM projection.processing_gaps p
             GROUP BY p.domain, p.projection_kind) g
  ), open_reservations AS (
    SELECT count(*) FILTER (WHERE now() - d.reserved_at <= interval '10 seconds') AS le_10s,
           count(*) FILTER (WHERE now() - d.reserved_at > interval '10 seconds'
                              AND now() - d.reserved_at <= interval '60 seconds') AS le_60s,
           count(*) FILTER (WHERE now() - d.reserved_at > interval '60 seconds') AS gt_60s
      FROM ops.data_disclosures d
     WHERE d.finalized_at IS NULL
  ), finalized AS (
    SELECT coalesce(array_agg(f.outcome ORDER BY f.outcome), '{}') AS outcomes,
           coalesce(array_agg(f.n ORDER BY f.outcome), '{}') AS counts
      FROM (SELECT d.outcome, count(*) AS n
              FROM ops.data_disclosures d
             WHERE d.finalized_at > p_finalized_since AND d.finalized_at <= now()
             GROUP BY d.outcome) f
  ), tenant_activity AS (
    SELECT a.tenants_active_1d AS active_1d, a.tenants_active_7d AS active_7d
      FROM ops.tenants_active_counts() a
  )
  SELECT now(), jobs.pending, jobs.processing, jobs.waiting_key, jobs.dead, jobs.oldest_pending, lag.events,
         gaps.domains, gaps.kinds, gaps.counts,
         open_reservations.le_10s, open_reservations.le_60s, open_reservations.gt_60s,
         finalized.outcomes, finalized.counts,
         tenant_activity.active_1d, tenant_activity.active_7d
    FROM jobs, lag, gaps, open_reservations, finalized, tenant_activity
$fn$;

ALTER FUNCTION ops.health_snapshot(timestamptz) OWNER TO role_health_reader;
REVOKE ALL ON FUNCTION ops.health_snapshot(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ops.health_snapshot(timestamptz) TO role_maintenance;
