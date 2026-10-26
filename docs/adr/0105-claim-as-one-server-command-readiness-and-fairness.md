# ADR-0105 — Claim is one server command: explicit modes, a fixed lock order, and readiness ordered inside the tenant

- Status: Accepted (2026-10-23). Card M18-0 (docs only, wave D, module M18), ADR-M18-e (this ADR). Content authority:
  module design note M18 §4 D8 and D9 (2026-10-23). This ADR records those decisions and re-decides none. Code lands
  in M18-5 (claim) and M18-13 (NEXT_READY ordering, locks, retirement); no migration, code or gate changes with this
  card.
- Amends: Baseline §30.2, by pointer only — the lease owner is the instance (ADR-0104), a fencing epoch is permanent,
  heartbeat/TTL start values change, a late heartbeat never revives, resource locks carry per-resource epochs, and
  storage re-rejects stale writes.
- Relates to: Baseline §30.2, §48, §72; ADR-0078 Q10; ADR-0103 (readiness rows); ADR-0104 (instance identity);
  ADR-0108 (execution roots and reservations); M03 D2 (the per-account DRR).

## Context

- Today `claim` takes an explicit `task_id` and `heartbeat` takes `task_run_id + fencing_token` as arguments;
  `lease_owner` is the principal (note §2 :20-22). The TTL default is 300 s (`bootstrap.rs:1153`).
- Incident 6: a bare claim took the oldest queued task, four times (lesson 2026-08-18; note §5 :118).
- A claim that checks readiness inside the same statement that writes the lease can hand the same task to two runs;
  a writer that checks only `now()` can accept an old epoch; a heartbeat that arrives late must not revive a dead run.
- Cross-account fairness is already M03's: one account is one tenant, and its per-account DRR runs at admission. M18
  needs only the ordering inside a tenant, and must never need `BYPASSRLS`.

## Decisions

### D-A Claim requires one of two explicit modes (note D8)

- The required mode is `task_id` or `NEXT_READY{role}`. There is no implicit "oldest" mode (lesson 2026-08-18).
- A bare claim is refused; the caller states which task it wants or which role it is ready to take.

### D-B The claim is one transaction with a fixed order (note D8)

- Steps: scope → admission (project quota, execution-root budget) → locks in the fixed order (graph guard only when
  the graph changes → execution root → task rows by id → task/resource leases → budget rows) → readiness re-check in a
  fresh statement on `clock_timestamp()` → end the expired run → `fencing_seq + 1` (permanent epoch, never reused) →
  run + lease + `run_inputs` snapshot → `coord.task_events` + `ops.outbox` + `control.operation_receipts`, all in the
  same transaction.
- `SKIP LOCKED` only scans candidates. Every write checks tenant + instance + task + run + epoch + unexpired + not
  cancelled + current plan/candidate.
- Start values (config): heartbeat 20 s, TTL 90 s (was 300), no-progress 30 min, spawn nesting 4. A duplicate heartbeat
  sequence returns the original result; a late heartbeat never revives a run.
- `coord.locks` is re-keyed `(tenant_id, resource)` with a per-resource epoch. Lock needs come from the plan, so
  omitting a lock in a request does not skip it; there is no lock tool among the 15 tools.
- External side effects carry no exactly-once claim (U8).

### D-C Fairness composes with M03; the tenant order is explicit (note D9)

- Cross-account fairness is M03's per-account DRR at admission (`application::scheduler::TenantFairQueue`, one account
  = one tenant). Agents pull, so M18 runs no global tenant round-robin and never needs `BYPASSRLS`.
- Inside a tenant, `NEXT_READY` orders by project-quota headroom → role (IMPLEMENT / REVIEW / RESEARCH / ROUTINE /
  COORDINATE) and priority → aging (`priority + floor(age / aging_step)`), with a reserved share per role.
- Rejected: a second DRR (M03 D2 already folds copies).

## Consequences

- Positive: two claims cannot open two runs for one task; an old epoch, an expired lease or a late heartbeat cannot
  write; the fairness order is explicit and testable; no `BYPASSRLS` is needed.
- Cost: a claim is roughly ten statements in one transaction; the tenant order is a server-side policy that must be
  re-measured as load grows.
- Neutral for this card: docs only; no table, migration, config key or wire format changes here.

## Gates

Planned, implementer-owned, tri-state (§57.1); none exists here.

| gate | owner card | test file | injected fault | expected red |
|---|---|---|---|---|
| G-M18-2 pool contamination | M18-5 | `crates/testkit/tests/fault/coord_pool.rs` | `SET` instead of `SET LOCAL` for the tenant GUC | the next transaction on the pooled connection reads tenant A |
| G-M18-9 double claim + mode | M18-5 | `crates/adapters/tests/coord_claim.rs` | read readiness in the claim statement; default mode | two runs open; a bare claim succeeds |
| G-M18-10 lease expiry while waiting for a lock | M18-5 | `crates/testkit/tests/fault/coord_lease_wait.rs` | omit `recheck_run_live_in_txn` | a write commits after expiry |
| G-M18-11 stale token / epoch reuse | M18-5 | `crates/adapters/tests/coord_claim.rs` | reset `fencing_seq` on reopen; compare with `now()` | an old-epoch write is accepted |
| G-M18-18 event atomicity + note CAS | M18-5 (event half; note half M18-7a) | `crates/adapters/tests/coord_events.rs` | event/outbox in a second transaction; last-writer-wins notes | a phase without an event; same-key concurrent patches both succeed |
| G-M18-23 fairness + capacity | M18-13 | `xtask load_open.rs` `coord_fairness` | FIFO `NEXT_READY`; drop aging | a role/project waits past the aging bound; 80 agents' heartbeats + 60 req/s bursts exceed the E-M18-2 budget |

Each needs its inject → red → fix → green record (§80.1) in its card; a missing database in CI is a failure, never
`not_applicable`.

## Owner-gated

None in this ADR. No production write, live key, email or money is involved; external side effects are out of scope
(U8).

## Open research

- E-M18-2 measures claim/heartbeat at 80 agents (4 heartbeats/s) plus 60 req/s bursts on the 4-vCPU node, and the
  advisory-guard wait time; it sets the TTL/heartbeat values and M18-13 (note §12 :223).
- U7: M26 may fold the 15 tools into fewer wire tools; the semantics here are fixed, the grouping is M26's (note §13
  :234).
- U8: no server dispatcher for external side effects is designed; outputs are recorded only, with no exactly-once
  claim (note §13 :235).

## Alternatives rejected

An implicit "oldest" claim; reading readiness inside the claim statement; `SKIP LOCKED` over the whole selection;
comparing the epoch with `now()`; reviving a run on a late heartbeat; a second DRR; a lock tool; an exactly-once
claim for external side effects.

## References

Module design note M18 §2, §4 D8–D9, §5 (incident 6), §9, §10, §11 (M18-5, M18-13), §12, §13; Baseline §30.2, §48,
§72; ADR-0078 Q10; ADR-0103; ADR-0104; ADR-0108; M03 D2.
