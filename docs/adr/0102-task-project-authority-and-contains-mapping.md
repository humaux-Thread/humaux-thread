# ADR-0102 — Task→project: `coord.tasks.project_id` is the one writable authority and `CONTAINS` is a same-transaction mapping

- Status: Accepted (2026-10-23). Card M18-0 (docs only, wave D, module M18), ADR-M18-b (this ADR). Content authority:
  module design note M18 §4 D4 (2026-10-23). This ADR records that decision and re-decides none. Code lands in M18-3;
  no migration, code or gate changes with this card.
- Relates to: Baseline §6.1.4 (work attribution), §30, §48, §78.6; ADR-0078 D-C (the relation kernel) and its A3
  attribution; ADR-0101 (the project tree); migrations 0249, 0252, 0255.

## Context

- `private.project_task_relations` (0249) holds Project —CONTAINS|REFERENCES→ Task, bitemporal with
  `valid tstzmultirange` and revisions (note §2 :26-27).
- A3 attribution (`attribution_repo.rs::A3_TASK_RUN`) joins the relation with `cur.valid @> e.occurred_at` at
  `remember.put` commit; relation corrections revoke by revision (0255) (note D4 :54-56).
- Dependencies live in payload (note §3 :37); a projection rebuilt from a current column would have no history and
  would lag the commit that reads it synchronously (note D4 :54-56).

## Decisions

### D-A One writable authority, one mapping transaction (note D4)

- `coord.tasks.project_id` is the sole writable task→project authority.
- Only `coord_task_repo::set_task_project_in_txn` writes it, and in the same transaction it closes the old
  `CONTAINS` revision's `valid` and opens the new one. No other writer and no second authority.

### D-B A rebuildable projection is rejected (note D4)

- A3 reads `valid @> occurred_at` synchronously at `remember.put` commit, and relation corrections revoke by revision
  (0255). A projection rebuilt from the current column has no history and lags the commit, so it cannot answer A3 at
  the moment the answer is required.
- Rejected: a rebuildable projection, and any design that makes the relation the writable authority.

### D-C Sole-caller gate on the relation door (note D4)

- `relation_repo` refuses a Project–Task `CONTAINS` write from any caller other than
  `set_task_project_in_txn`; the sole-caller gate asserts `== 1`, not `<= 1` (note D4 :55; §10 G-M18-6).
- `REFERENCES` remains a free business relation and is not gated this way.

### D-D Backfill, then `NOT NULL` (note D4)

- Existing tasks are backfilled from their current `CONTAINS` relation; a task with none lands in a per-workspace
  `Unfiled` project. `coord.tasks.project_id` then becomes `NOT NULL`.
- This is the migration's order (note D4 :56).

## Consequences

- Positive: the task row and the relation cannot disagree, because one transaction writes both; A3 keeps its
  revision-history semantics; a move cannot leave attribution on the old project.
- Cost: every project change goes through one function and one transaction; the backfill must resolve every existing
  task before `NOT NULL`.
- Boundaries: M18 may depend on M01, M02 (port), M03, M07, M08, M09, M29 and M14 (door only); M26, M14, M15, M02 and
  M25 call it, and no other module writes `coord.*` or the hierarchy columns; `project_task_relations` is written only
  through `relation_repo` (note §8 :157-159).
- Neutral for this card: docs only; no table, migration, config key or wire format changes here.

## Gates

Planned, implementer-owned, tri-state (§57.1); none exists here.

| gate | owner card | test file | injected fault | expected red |
|---|---|---|---|---|
| G-M18-6 CONTAINS mapping | M18-3 | `crates/adapters/tests/coord_task_project.rs` + the xtask sole-caller check | write `CONTAINS` through `relation_repo` directly; skip closing the old revision | the mapping differs from `tasks.project_id`; A3 attributes to the old project after a move |

The gate needs its inject → red → fix → green record (§80.1) in M18-3.

## Owner-gated

None in this ADR. Every write is to the owner's own task and project storage; no production write, live key or email
is involved.

## Open research

- None specific to this ADR. The hierarchy contract is ADR-0101; the relation kernel is ADR-0078 D-C and stays
  M29-owned.
- The `Unfiled` default is a migration detail for M18-3, not an open choice in the note.

## Alternatives rejected

A rebuildable projection from the current column; making the `CONTAINS` relation the writable authority.

## References

Module design note M18 §2, §3, §4 D4, §10, §11 (M18-3); Baseline §6.1.4, §30, §48; ADR-0078 D-C and A3; ADR-0101;
migrations 0249, 0252, 0255.
