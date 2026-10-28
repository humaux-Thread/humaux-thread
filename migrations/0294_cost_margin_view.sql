-- §19 / M04 D11: explicit cost periods; §76: no runtime access to raw revenue or this view.
ALTER TABLE ops.tenant_cost_events ALTER COLUMN period DROP DEFAULT;

CREATE VIEW ops.tenant_margin_v WITH (security_barrier = true) AS
WITH revenue AS (
  SELECT tenant_id, date_trunc('month', period_start AT TIME ZONE 'UTC')::date AS period,
    sum(CASE kind WHEN 'CHARGE' THEN amount_cents WHEN 'REFUND' THEN -amount_cents
      WHEN 'CHARGEBACK' THEN -amount_cents END)::bigint AS revenue_cents
  FROM control.billing_payments GROUP BY tenant_id, period
), cost AS (
  SELECT tenant_id, period, sum(estimated_cost::numeric) AS cost_usd
  FROM ops.tenant_cost_events GROUP BY tenant_id, period
)
SELECT coalesce(revenue.tenant_id, cost.tenant_id) AS tenant_id,
  coalesce(revenue.period, cost.period) AS period,
  coalesce(revenue.revenue_cents, 0::bigint) AS revenue_cents,
  coalesce(cost.cost_usd, 0::numeric) AS cost_usd,
  coalesce(revenue.revenue_cents, 0::bigint) / 100.0 - coalesce(cost.cost_usd, 0::numeric) AS margin_usd
FROM revenue FULL OUTER JOIN cost USING (tenant_id, period);

COMMENT ON VIEW ops.tenant_margin_v IS
  '§19 / M04 D11, D13(b): USD cost estimates (0096 has no currency; 0288 billing is USD-only). '
  'Revenue uses the UTC month of period_start; refunds and chargebacks subtract unsigned amounts. '
  'FORCE RLS on both sources limits the owner view to the session humaux.tenant_id; no cross-tenant read.';
ALTER VIEW ops.tenant_margin_v OWNER TO role_migration_owner;
REVOKE ALL ON TABLE ops.tenant_margin_v FROM PUBLIC, role_gateway, role_private_worker,
  role_consolidation_worker, role_public_worker, role_retrieval_worker, role_batch_issuer,
  role_admin, role_maintenance, role_health_reader;
