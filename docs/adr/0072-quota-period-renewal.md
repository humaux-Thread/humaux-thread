# ADR-0072 — Quota-period renewal: a staged successor period, issued before the current one ends

- Status: Accepted (2026-10-15). Card W0 (P0 before go-live; architecture audit E, §72.2.1 row "periodic issuance of
  the NEXT window").
- Relates to: Baseline §71, §72.2.1, §76, §6.2.2; ADR-0053 (onboarding, its L "renewal is card 35's `--serve` job");
  ADR-0062 (the resident daemon, D-C task set, D-S counters); migrations 0033 (snapshots), 0113 (issuer), 0186
  (onboarding).

## Context

Onboarding (`control.onboard_tenant`, 0186) writes one entitlement snapshot whose `mcp.billable_operations.per_period`
object carries `period_start` / `period_end`, and `quota_repo::issue_window` issues the one window for that period.
Nothing ever advanced either. At `period_end` the gateway's `quota_policy` refuses the non-current snapshot
(ENTITLEMENT_REQUIRED) and `reserve_bmo` finds no window (QUOTA_EXHAUSTED) for every call of the tenant until an
operator re-onboards. ADR-0053 assigned renewal to card 35's daemon; ADR-0062 did not deliver it, and the runbook hid
the gap with `--period-end 2099-01-01`.

The snapshot holds exactly one period and the guard requires `period_start <= now < period_end`, so advancing it early
breaks the current period and advancing it at the boundary leaves a gap of one daemon visit. The successor must exist
before the boundary and take effect at it without a maintenance call.

## Decision

- **D-A Staged successor on the snapshot row.** `control.entitlement_snapshots` gains `successor jsonb` and
  `successor_from timestamptz` (both NULL or both set, 0245). `successor` is the whole `effective` object with only the
  BMO period boundaries moved; `successor_from` is its `period_start`. `request_guard_repo::read_effective_entitlements`
  reads `successor` as `effective` once `successor_from <= clock_timestamp()` (one clock value for the switch and for
  `observed_at`); `quota_policy` is unchanged. Still one row per tenant and still the only read path (§76).
- **D-B The renewal rule.** `control.renew_quota_period(tenant, key, lead, subscription_period, limit)` — owner,
  SECURITY DEFINER, `search_path = pg_catalog`, `TimeZone = UTC`, EXECUTE to `role_maintenance` only, tenant GUC
  asserted, the issuer's `quota-window:` advisory lock — per call:
  1. renews only a tenant whose `control.tenants.state = 'ACTIVE'` that has a snapshot with the BMO key (anything else
     answers `(0, NULL)` and writes nothing);
  2. promotes a successor whose `successor_from <= now` (`effective := successor`, `computed_at := now`);
  3. when `now >= period_end - lead` and no successor is pending, stages the next period
     `[period_end, next_end)` — `calendar_month`: `next_end` = the next UTC month start; `subscription_period`:
     `period_end + subscription_period` — and inserts its `control.quota_windows` row with the snapshot's `limit`
     (`ON CONFLICT` on the window PK keeps an identical window; an overlapping window with other bounds is 23514);
  4. repeats 2–3 at most `limit` staged periods, so a daemon that was down catches up contiguously.
  Boundaries are written as microsecond RFC3339 so the parsed period equals the window bounds exactly. A rerun, a
  concurrent call (the lock serializes; the loser sees the pending successor) and every call while a successor is
  pending stage nothing.
- **D-C The resident task.** `humaux-maintenance --serve` gets the per-tenant D-C task `quota_renewal`
  (`MaintenanceTask::QuotaRenewal`, after `quota_reservations`), one door call per tenant through
  `quota_repo::renew_period`, counted by `maintenance_task_runs_total` / `maintenance_task_rows_total` (rows = staged
  periods). Registered keys, no code default (§78.1): `HUMAUX_MAINTENANCE_SERVE_QUOTA_RENEWAL_EVERY_SECONDS`,
  `…_QUOTA_RENEWAL_LIMIT`, `…_QUOTA_RENEWAL_LEAD_SECONDS` (> 0), `…_QUOTA_RENEWAL_SUBSCRIPTION_MONTHS` (> 0). Bundle
  values: every 300 s, limit 12, lead 14 days, 1 month. `sweep once` runs it like every task. Boot refuses a lead at
  or below the 7-day alert threshold (D-D), which would fire the alert every period before the successor is staged.
- **D-D Alert.** `quota_repo::renew_period` records each tenant's latest BMO `window_end` after the call commits
  (dropped when the tenant stops renewing; that call is the helper's one production caller, `EMIT_HELPERS` / D5);
  `quota_window_horizon_seconds` (§41.2, gauge, no label) renders the smallest of them minus the scrape time, so a
  renewal that stops running drifts toward the alert instead of holding a stale value; no sample until a renewing
  tenant was visited (`ABSENT_UNTIL_FIRST_RUN`; a failing call is `MaintenanceTaskFailing`). `QuotaWindowRenewalMissing`
  fires when `min(quota_window_horizon_seconds) < 7 days` for 30 m. The 14-day lead keeps a healthy tenant above it.
- **D-E Gate.** `crates/adapters/tests/quota_and_rate.rs::quota_window_renews_before_period_end` (live PG, request-guard
  lane): staging before the boundary, contiguity / length / limit, one successor under four concurrent calls and on
  rerun, the gateway's entitlement read and a reservation inside the successor after the boundary with no call in
  between, the horizon equal to the successor window's end, a changed `effective` dropping the successor and the
  re-stage carrying the new limit, promotion, a SUSPENDED tenant not renewed, no runtime EXECUTE.
  `bins/maintenance/tests/serve.rs::quota_renewal_publishes_the_horizon_gauge` proves the `/metrics` sample and
  `serve_refuses_a_renewal_lead_not_above_the_alert_threshold` the boot refusal. `rls-check`'s "ADR-0062 maintenance doors"
  pins the door's owner / definer / search_path / exact EXECUTE set. Promtool: two cases, mutations `renewal_lt`,
  `renewal_min`.

## Not chosen

- Advance the snapshot at the boundary only: a gap of up to one daemon visit (`EVERY` x page rotation) of
  ENTITLEMENT_REQUIRED per tenant per period.
- Relax the guard to accept an ended snapshot when a window covers now: breaks §72.2.1 "non-current fails closed".
- Derive the next period length from the current one: onboarding's first period starts at the onboarding second and
  ends at the operator's `--period-end`, a partial period; its length is not the plan's.
- A gateway-side issuer or a new role: rejected for §72.2.1 already (the issuer ruling), unchanged here.

## Limits

- L1 "Renewing" is `tenants.state = 'ACTIVE'`. The schema has no §71.2 subscription (no CANCEL_AT_PERIOD_END,
  PAST_DUE, GRACE): stopping renewal today means suspending the tenant, which also blocks it at once. Upgrade: the
  §71 subscription table, read by the door's first predicate.
- L2 One deployment-wide `subscription_period` length (months, UTC, PG month arithmetic on the previous end). An
  anchor on the 29th–31st does not hold: after the first shorter month the end lands on the 28th/29th and every
  later period keeps that day (Jan 31 → Feb 28 → Mar 28 …). Upgrade: store the anchor day on the snapshot and compute
  each end from it; per-plan period input from the §76 Projector. Only `subscription_period` has a producer
  (onboarding); the door's `calendar_month` branch has no producer and no test.
- L3 The successor copies `effective` at staging time. A BEFORE UPDATE trigger on `control.entitlement_snapshots`
  (0245) drops a pending successor whenever a statement changes `effective` without setting `successor`, and the next
  daemon visit re-stages it from the new `effective`, so a stale copy is never promoted over a lowered or revoked
  entitlement. The successor *window* already issued keeps its limit (window limits are immutable, §72.2.1): a limit
  change inside the lead takes effect one window later; a revoked feature or a removed BMO key still blocks at once
  through the online entitlement read.
- L4 An operator re-run of `onboard tenant` between `successor_from` and the next daemon visit fails in
  `issue_quota_window` (its snapshot is not current); rerun after the visit.
- L5 The gauge covers tenants this process visited since boot; after a restart it fills over one page rotation.
