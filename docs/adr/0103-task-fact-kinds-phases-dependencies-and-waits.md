# ADR-0103 — Task fact: three kinds, five phases, a dependency DAG and waits that are not a state

- Status: Accepted (2026-10-23). Card M18-0 (docs only, wave D, module M18), ADR-M18-c (this ADR). Content authority:
  module design note M18 §4 D5 and D6 (2026-10-23). This ADR records those decisions and re-decides none. Code lands
  in M18-3 (task fact) and M18-4 (dependencies, waits, readiness); no migration, code or gate changes with this card.
- Amends: Baseline §30.1, by pointer only. The seven task states become five phases; waits are separate rows; a task
  may go `OPEN→DONE` only through the acceptance transaction (note D5 :57-61).
- Relates to: Baseline §30.1, §30.2, §48, §78.2; ADR-0078 Q10 (`task_claim` returns a new run), ADR-0080 D-C
  (acceptance), ADR-0102 (task→project), ADR-0106 (the gate vector), migration 0248.

## Context

- `0248` puts a seven-value `tasks.state` CHECK on `coord.tasks`: SUBMITTED, CLAIMED, WORKING, BLOCKED, COMPLETED,
  FAILED, CANCELLED (note §2 :17).
- There is no task kind, no parent task, no dependency row and no wait row; dependencies and outputs live in payload
  (note §3 :36-37). Incident 4: a SUBMITTED task could not complete without a claim, and there was no parent rollup.
- Incident 3: progress and ownership were two stores, so a fixed bug was still chased (note §5 :115).
- The task fact must therefore hold decomposition, the dependency DAG and phase, while failure and waiting are facts
  about a run or a wait, not phases that hide why a task is not moving.

## Decisions

### D-A Kinds and decomposition (note D5)

- `kind WORK|GROUP|MILESTONE`; `parent_task_id` where the parent must be `GROUP`; depth ≤ 8 (config).
- Only `WORK` enters the delivery denominator; `GROUP` and `MILESTONE` roll up but do not count as delivery units.
- A parent never mass-completes its children; each child reaches `DONE` on its own acceptance.

### D-B Five phases replace the seven states (note D5)

- The phase CHECK is `OPEN, IN_PROGRESS, IN_REVIEW, DONE, CANCELLED`. The DB and Rust keep the existing `CANCELLED`
  spelling of 0248 to avoid a §78.2 rename; the wire label is M26's.
- The row map is fixed: SUBMITTED→OPEN; CLAIMED/WORKING→IN_PROGRESS; BLOCKED→OPEN plus a HUMAN wait `legacy`;
  FAILED→OPEN, because failure lives on the run; COMPLETED→DONE **without** acceptance and never `accepted_valid`.
- `OPEN→DONE` is allowed only through the acceptance transaction: accept permission, no live run, a current sealed
  candidate, a frozen plan, and every gate, input and child valid. Failure is recorded on the run, not by returning
  the task to a hidden state.

### D-C Dependencies are rows and the cycle check is combined (note D5)

- `coord.task_dependencies` v1 means "prerequisite accepted ⇒ dependent may start", cross-project inside the tenant.
- The cycle check runs over the combined graph — dependencies ∪ `GROUP→child` waits — under the ADR-0101 D2 tenant
  guard. Checking dependencies alone would accept a child-waits-on-parent loop (G-M18-7).

### D-D Waits are rows, never `BLOCKED` (note D6)

- `coord.task_waits` stores HUMAN (owner, deadline, resolution Evidence), CI (provider, check, commit; released only
  by the trusted adapter) and RESOURCE.
- DEPENDENCY and BUDGET are derived in `coord.task_readiness_v`; they are never stored or hand-cleared.
- A timeout escalates through M22 and never succeeds. A long wait ends the run and releases the lease.

## Consequences

- Positive: one phase fact plus explicit waits, so a task that cannot move says why; the delivery denominator counts
  only WORK; the combined cycle check closes the child-waits-on-parent loop.
- Cost: the seven-state vocabulary and its wire labels change, so the contract test and M26 label mapping must move
  together; legacy rows need the explicit map above.
- Neutral for this card: docs only; no table, migration, config key or wire format changes here.

## Gates

Planned, implementer-owned, tri-state (§57.1); none exists here.

| gate | owner card | test file | injected fault | expected red |
|---|---|---|---|---|
| G-M18-7 combined cycle | M18-4 | `crates/adapters/tests/coord_graph.rs` | check dependencies only | a child-waits-on-parent loop is accepted |
| G-M18-24 enum contracts (§78.2) | M18-3 | `crates/adapters/tests/coord_task_run.rs` (extend) | add a Rust variant without a CHECK value | the phase, kind, wait, gate and outcome sets differ |

Each needs its inject → red → fix → green record (§80.1) in its card; a missing database in CI is a failure, never
`not_applicable`. The `OPEN→DONE` half is G-M18-8 in ADR-0106 (owner M18-11).

## Owner-gated

None in this ADR. The phase set, kinds and wait kinds are recorded decisions, not owner choices left open. No
production write, live key or email is involved.

## Open research

- The depth default of 8 and the wait deadlines are config start values (note §15 :247-248); E-M18-2 measures the
  claim/heartbeat load, not the task depth.
- U4: task estimates are mostly absent, so a critical path is UNKNOWN rather than guessed (ADR-0107).
- The CI wait is released only by a trusted adapter that does not exist yet (U2, ADR-0106).

## Alternatives rejected

The seven-state model; `BLOCKED` as a stored state that hides the blocker; dependencies in payload; a per-dependency
cycle check that ignores `GROUP→child` waits; mass-completing children from a parent.

## References

Module design note M18 §2, §3, §4 D5–D6, §5 (incidents 3 and 4), §9, §10, §11 (M18-3, M18-4); Baseline §30.1, §30.2,
§48, §78.2; ADR-0078 Q10; ADR-0080 D-C; ADR-0101; ADR-0102; ADR-0106; migration 0248.
