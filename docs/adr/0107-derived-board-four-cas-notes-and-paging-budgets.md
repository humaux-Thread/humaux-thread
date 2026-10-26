# ADR-0107 — The canvas becomes a derived subtree board: four CAS notes, one `board_summary`, bounded pages

- Status: Accepted (2026-10-23). Card M18-0 (docs only, wave D, module M18), ADR-M18-g (this ADR). Content authority:
  module design note M18 §4 D13 and D14 (2026-10-23). This ADR records those decisions and re-decides none. Code lands
  in M18-7a, M18-7b and M18-8; no migration, code or gate changes with this card.
- Amends: Baseline §30.3, by pointer only — the free-form canvas becomes a derived board with four per-key CAS notes,
  the `canvas_elements` whole-element replace is retired, and the flow becomes acceptance → candidate Evidence → M15.
  The new §30.6 `board_summary` and paging budgets are recorded here.
- Relates to: Baseline §30.3, §30.6, §33.5 (output budget), §48; ADR-0092 (export includes the legacy canvas);
  ADR-0103 (phases); ADR-0106 (acceptance validity); M25 (legacy import); M26 (tools).

## Context

- Incident 2: one global canvas, 2,392 elements, no project and no archive; a read was cut at 16,000 characters in the
  middle of JSON (note §5 :114). Incident 3: progress and ownership drifted between two stores (note §5 :115).
- `coord.canvases` / `coord.canvas_elements` have no writer today, and `canvas_elements` has no `tenant_id` (note §2
  :15-16).
- The spec's §30.3 canvas lists `goal, todo, doing, done, blockers, next` and says a completed task flows
  Canvas/Handoff → Evidence → distillation (note §9 (d) :168).
- The board must be a view of the task facts, not a second store, or the drift of incident 3 returns.

## Decisions

### D-A The board is a derived subtree, never stored state (note D13)

- Regions: goal/context (notes), delivery (WORK `accepted_valid`), current work (live runs), waits, risks (lost
  heartbeat, no progress, legitimate wait, invalidated input, critical path UNKNOWN/STALE), milestones, recent
  outputs.
- Dragging a card calls a task command; the board itself is derived. It never stores its own copy of a phase or a
  count (G-M18-19).

### D-B Four notes with per-key CAS (note D13)

- Only `goal, context, decision_pending, next_focus` exist, in `coord.canvas_notes (tenant, project_id, note_key)`.
- Each key has its own CAS on `expected_version`; the same key with a stale version returns VERSION_CONFLICT through
  the existing `Conflict`, while other keys stay independent.
- The old `canvas_elements` whole-element replace is retired. `canvases` / `canvas_elements` become a read-only legacy
  archive: tenant leg added, `project_id NULL`, provenance `LEGACY_UNVERIFIED`; M25 imports, with no UPDATE/DELETE
  grant. An old "done" never becomes DONE.
- Rejected: CRDT (a central PostgreSQL store, and a CRDT cannot decide acceptance); the `{**cur, **inc}` element merge
  of §30.3.

### D-C `board_summary(project_id)` is one SQL statement (note D14)

- It reads `tasks.project_id ∈ subtree`, each task once, WORK only: total, active, archived, cancelled,
  `accepted_valid`, `invalidated`, denominator = total − cancelled, and a ratio or NULL at zero.
- Archived tasks stay in the denominator, so archiving never changes the ratio (G-M18-21).
- Parent-task and cross-project-goal rollups are separate entry points over DISTINCT ids; they are not parameters of
  the one board query.

### D-D Critical path is a projection with an explicit staleness (note D14)

- A DP over the dependency DAG lives in `coord.critical_path_projection` with `computed_at` and `graph_version`;
  it is STALE when the graph has moved, and UNKNOWN when an estimate is missing (U4).
- It is rebuilt per graph change; incremental computation is a later ceiling (note §15 :249).

### D-E Pages are bounded by whole records and a byte budget (note D14)

- Default page 50, maximum 100. Byte budget: 24 KiB default, 48 KiB hard cap over structuredContent + text +
  escaping + cursor + refs.
- Records are assembled whole, then count-limited; serialized JSON is **never** truncated. Large text becomes a
  summary plus `content_key` (`content_get`).
- A signed cursor binds tenant, scope, filter, sort, version and expiry; it is M18's own because MCP 2026-07-28
  pagination covers list methods only (verify #10).
- DONE leaves the active list after 30 days; counts stay.

## Consequences

- Positive: the board cannot drift from the task facts; one SQL statement serves the summary; a page can never be
  invalid JSON or a mid-record cut; notes have per-key isolation instead of last-writer-wins.
- Cost: the byte budget is enforced while assembling whole records, which caps a single record's size; the critical
  path needs estimates that mostly do not exist yet.
- Neutral for this card: docs only; no table, migration, config key or wire format changes here.

## Gates

Planned, implementer-owned, tri-state (§57.1); none exists here.

| gate | owner card | test file | injected fault | expected red |
|---|---|---|---|---|
| G-M18-19 canvas drift | M18-7a (STALE case M18-8) | `crates/adapters/tests/coord_board.rs` | board reads a stored copy | the board differs from the task facts after a phase change |
| G-M18-20 paging budgets | M18-7b | `crates/adapters/tests/coord_board.rs` | cut bytes after serialisation | with 2,392 tasks and multibyte text, a page exceeds 48 KiB or is invalid JSON |
| G-M18-21 archive ratio | M18-7a | `crates/adapters/tests/coord_board.rs` | exclude archived from the denominator | the ratio changes when a subtree is archived |

Each gate needs its inject → red → fix → green record (§80.1) in its card.

## Owner-gated

None in this ADR. No production write, live key or email is involved; the legacy import is M25's card and E-M18-3.

## Open research

- U4: estimates are mostly absent. Fallback: the critical path is UNKNOWN, the risk is shown, and it is never guessed
  (note §13 :231).
- E-M18-1 measures `board_summary` / `board_get` p95 on 2,392 synthetic tasks over a depth-8 subtree plus a dev copy of
  the legacy canvas; it sets the page defaults (note §12 :222).
- E-M18-3 measures the legacy import: byte-equal round trip and 0 rows counted DONE (note §12 :224).

## Alternatives rejected

A CRDT; the `{**cur, **inc}` element merge of §30.3; a stored board copy; whole-element replace; truncating
serialized JSON; more than the four note keys.

## References

Module design note M18 §2, §4 D13–D14, §5 (incidents 2 and 3), §9 (spec §30 row), §12, §13 (U4), §15; Baseline
§30.3, §30.6, §33.5, §48; ADR-0092; ADR-0103; ADR-0106; M25; M26.
