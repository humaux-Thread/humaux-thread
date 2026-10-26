# ADR-0108 — Spawn, execution roots and advisory budgets: one stable budget account across retries and hand-offs

- Status: Accepted (2026-10-23). Card M18-0 (docs only, wave D, module M18), ADR-M18-h (this ADR). Content authority:
  module design note M18 §4 D15 (2026-10-23). This ADR records that decision and re-decides none. Code lands in
  M18-12; no migration, code or gate changes with this card.
- Relates to: Baseline §30.2, §48, §72; ADR-0104 (instance and run identity); ADR-0105 (claim); ADR-0109 (retention);
  M04 (billing); M03 (admission); design note M18 §7 and §8.

## Context

- A retry, a hand-off or a rework creates a new run, but the work still belongs to one budget account; counting each
  retry as a fresh budget lets a task spend without bound.
- Incident 5: sub-agent outputs were not attached, and the parent had no record of what it had spawned (note §5 :117).
- The 80-agent load is real: the budget must be enforced by the server, while LLM turns, tokens, cost and tool calls
  are self-reported by the client and cannot meter money here (M04 owns billing).

## Decisions

### D-A Two roots with different lifetimes (note D15)

- `root_run_id` is the lineage: one work item's family of runs.
- `execution_root_id` is the stable budget account across retries, hand-offs and rework. A new run under the same
  execution root draws from the same reservation.

### D-B Spawn reserves before the child exists (note D15)

- `run_spawn` reserves a PENDING dispatch with a pre-allocated `planned_run_id`; the child's claim activates it.
- Siblings draw from the parent's reservation, so a parent cannot hand each child the full budget it holds.

### D-C The server enforces the hard bounds; the rest is reported (note D15)

- Server-enforced: spawn depth, dispatch count, concurrency, attempts and deadline.
- Reported and advisory, self-reported by the client: LLM turns, tokens, cost and tool calls. No real money is metered
  here; M04 owns billing.
- The parent close policy is CANCEL, WAIT or DETACH; it decides what happens to children when the parent closes.

## Consequences

- Positive: one budget account survives retries and hand-offs; a spawn cannot exceed depth or dispatch caps; a parent's
  close policy is explicit rather than implied.
- Cost: the PENDING dispatch is a placeholder until the child claims it, so stale reservations need the retention rules
  of ADR-0109; reported counters are honest only to the extent the client reports.
- Neutral for this card: docs only; no table, migration, config key or wire format changes here.

## Gates

Planned, implementer-owned, tri-state (§57.1); none exists here.

| gate | owner card | test file | injected fault | expected red |
|---|---|---|---|---|
| G-M18-12 parent cancel | M18-12 | `crates/adapters/tests/coord_spawn.rs` | ignore the close policy | children keep running after CANCEL |
| G-M18-16 budget bypass | M18-12 | `crates/adapters/tests/coord_spawn.rs` | siblings copy the full budget; skip the reservation | spawn depth 5 or a dispatch over the cap commits |

Each needs its inject → red → fix → green record (§80.1) in M18-12; a missing database in CI is a failure, never
`not_applicable`.

## Owner-gated

None in this ADR. No money is metered here, and no production write, live key or email is involved. A real budget
change is M04's, not this ADR's.

## Open research

- The nesting default of 4 and the concurrency/attempt start values are config values measured by E-M18-2 (note §12
  :223, §15 :247-248).
- The reported counters are advisory; an accounting use would be a different decision under M04.

## Alternatives rejected

Siblings copying the parent's full budget; skipping the reservation; metering real money in M18; an unbounded spawn
depth; an implicit close policy for children.

## References

Module design note M18 §2, §4 D15, §5 (incident 5), §7, §8, §11 (M18-12), §12, §15; Baseline §30.2, §48, §72;
ADR-0104; ADR-0105; ADR-0109; M03; M04.
