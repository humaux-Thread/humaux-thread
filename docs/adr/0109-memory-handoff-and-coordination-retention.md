# ADR-0109 — Memory hand-off and coordination retention: acceptance files candidates, evidence is kept while referenced

- Status: Accepted (2026-10-23). Card M18-0 (docs only, wave D, module M18), ADR-M18-i (this ADR). Content authority:
  module design note M18 §4 D16 and D17, §9 (M15/M19 rows) and the owner's Q2 answer of 2026-10-23. This ADR records
  those decisions and re-decides none. Code lands in M18-14; no migration, code or gate changes with this card.
- Relates to: Baseline §48, §81; ADR-0063 (retention machinery); ADR-0092 (the purge catalog and deletion pipeline);
  ADR-0106 (acceptance and candidate Evidence); ADR-0108 (dispatches); M07 (canonical Memory doors); M09
  (`ops.jobs`); M14 (applicability); M15 (curation candidates); M19 (retention keys); M22 (notifications).

## Context

- Acceptance is the moment the system has evidence that a piece of work succeeded or failed; that Evidence is the only
  honest source for a lesson. Phase, holder, heartbeats, todos and retries are operational, not knowledge.
- Applicability (`EXACT|SUBTREE`) is an M14 column; M18 consumes it and does not own it (note D16 :104-105).
- Coordination data has different lifetimes: heartbeats are current state, progress events are diagnostic, and
  acceptances, candidates, outputs and Evidence are provenance. Incident 2's 2,392-element canvas shows what happens
  when everything is kept forever in one place (note §5 :114).
- The owner's Q2 answer of 2026-10-23 accepts the lead's retention defaults (note :254).

## Decisions

### D-A Acceptance enqueues a memory hand-off (note D16)

- The acceptance commit enqueues an M09 `ops.jobs` job that files M15 `curation_candidates`: LESSON_DRAFT, fix
  (symptom, root cause, mechanism, version, regression evidence), decisions and research, all from the candidate's
  Evidence.
- Canonical memory is written only through M15/M07. Phase, holder, heartbeats, todos and retries are never knowledge
  and never become a candidate.

### D-B Applicability is M14-owned (note D16, §9 M14 row)

- `EXACT|SUBTREE` is a `memory_applicability` column owned by M14 (ADR-0096). M18 does not write it and does not
  widen visibility.

### D-C Retention start values, with a purge-catalog row per new table (note D17)

- Heartbeats: current value only, in run columns; expiry diagnostics live in events.
- `COORD_PROGRESS_EVENTS` (run progress, raw run logs): 30 days. `COORD_DETAIL` (other events, waits, hand-offs):
  90 days or project term.
- Acceptances, gate decisions, candidates, outputs and Evidence: kept while referenced. `fencing_seq` epochs are kept
  forever. Notifications: 90 days (M19 Q2, M22).
- Archive is a view; deletion is retention. Every new coord table gets a purge-catalog row (C-M19-4), and a retention
  drop needs the M19 approval path.
- Amendments: M15's LESSON_DRAFT/fix candidates cite `coord.acceptances` ids; M19 exports tasks, runs, candidates,
  acceptances, notes and the legacy canvas (note §9 :167).

## Consequences

- Positive: a lesson has one evidenced origin and one canonical writer (M15/M07); provenance outlives the operational
  rows that produced it; every new table is visible to the purge catalog instead of silently escaping it.
- Cost: the hand-off job depends on M15's candidate table and M19's keys; deleting coordination detail cannot delete
  Evidence that is still referenced.
- Neutral for this card: docs only; no table, migration, config key or wire format changes here.

## Gates

Planned, implementer-owned, tri-state (§57.1); none exists here.

| gate | owner card | test file | injected fault | expected red |
|---|---|---|---|---|
| G-M18-22 retention vs provenance | M18-14 | `crates/adapters/tests/coord_retention.rs` | age-drop acceptances | a referenced acceptance or its Evidence is purged |

The gate needs its inject → red → fix → green record (§80.1) in M18-14; a missing database in CI is a failure, never
`not_applicable`.

## Owner-gated

- Q2 (answered 2026-10-23): progress and raw run logs 30 days, other coordination detail 90 days, evidence kept while
  referenced (note :254). The retention values are approved through M19's `retention approve`, not by M18.
- Until the approval path runs, nothing is age-dropped (the note's default before the answer).
- No production deletion, live key or email is involved in this card.

## Open research

- M15-1 (the candidate table) and M19-5 (the purge catalog) are not merged; M18-14 depends on both (note §11 :217).
- The retention keys (`COORD_PROGRESS_EVENTS`, `COORD_DETAIL`) are M19's register entries; M18 supplies the values and
  the per-table catalog rows.

## Alternatives rejected

Writing canonical memory directly from M18; treating phase, holder, heartbeats, todos or retries as knowledge; a
second candidate store beside M15's; age-dropping referenced acceptances or Evidence; making archive a delete.

## References

Module design note M18 §4 D16–D17, §5 (incident 2), §9 (M15/M19/M26 rows), §11 (M18-14), and the owner answers at
:252-255; Baseline §48, §81; ADR-0063; ADR-0092; ADR-0106; ADR-0108; M07; M09; M14; M15; M19; M22.
