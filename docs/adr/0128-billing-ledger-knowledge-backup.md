# ADR-0128 — Preserve billing ledger and grandfathered plan versions in knowledge backups

- Status: Accepted (lead ruling, 2026-10-28). Card M04-8b; authority: M04 D13(c), G-M04-20.
- Amends: M23 D1 / ADR-0121 D-A for the seven tables below only; Baseline §44 and §71 Plan Versioning.

## Context

The Creem API review recorded in M04 D13(c) (2026-10-28) found no historical refund, dispute or event-list API,
no date filter on transactions or transaction search, and undocumented retention. Pending webhook delivery is
not historical event replay. Creem therefore cannot rebuild our billing rows; M04 D9 reconciliation needs our
side of the ledger to survive a restore.

`deploy/plans/plan_catalogue.json` holds only the current catalogue. Grandfathered versions live only in
`control.plan_versions`: owner Q5 keeps an existing $5 subscriber on core for 12 months. A restored subscription
must reference its exact version, which the current values file cannot reconstruct. These tables are small.
`control.plans` joins by FK closure because `plan_versions.plan_id` references it NOT NULL (0262).

## Decision

Classify `control.plans`, `control.plan_versions`, `control.billing_customers`, `control.subscriptions`,
`control.subscription_events`, `control.billing_payments` and `control.billing_inbox` as KNOWLEDGE.
This amends M23 D1 for these seven tables only. Quota, credit and referral derived state stays EXCLUDED.
The other FK parent is already-KNOWLEDGE `control.tenants`; the 0262/0288 trigger functions inspect no other
tables. No `set_null` or trigger bypass is needed; ADR-0121's restore constraints remain in force.

## Consequences and evidence

G-M04-20 extends the existing G-M23-3b check with an exact seven-table pin; missing rows fail by name (§57.1).
Seeder static finding: 0262 `publish_plan_version` uses `(plan_id, version)` conflict handling and content comparison
to reuse matching restored rows with `created=false`. However, a published stored version plus `published:false`
raises 23505 ("a published version is never a draft again"). `plan_repo::seed` maps that to Conflict and rolls back
the entire call. All five committed placeholder versions have `published:false`. Reported only; no seeder fix here.

- Injected red: PENDING — `red/m04-8b-r1` excludes only `control.billing_inbox`; must fail naming that table.
- Green: this PR's CI, recorded in the PR body at its tested head; no local compilation or test evidence.
