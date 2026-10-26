# ADR-0112 — M15 edition split: deterministic curation in core, LLM curation and reports in the cloud worker

- Status: Accepted (2026-10-26). Card M15-0 (docs only, wave D, module M15). ADR-M15-a (this ADR). Content authority:
  module design note M15, decision D1 (`module_design_M15.md:56-63`) and the producer column of its §5 output table
  (`:128-140`). This ADR records that decision and re-decides none of it. No code, migration, edition declaration or
  gate changes with this PR.
- Applies: ADR-0073 D-A to M15 (`docs/adr/0073-open-core-and-licence-timing.md:14-19`); the note's D1 opens "Edition
  split = ADR-0073 D-A" (note :56), so the boundary below is an application, not a new one.
- Relates to: Baseline §11.6 (consolidation may only propose), §57.1 (tri-state gates), §58 (workspace and member
  contract), §80.1 (inject → red → fix → green), §81 (the business model ADR-0073 supersedes); ADR-0074 (edition
  metadata, G-M01-1/G-M01-2, dependency direction); ADR-0078 D-D and ADR-0080 (the core candidates and knowledge
  products this split classifies).

## Context

- ADR-0073 D-A fixes the boundary (`0073:14-19`): the open-source core keeps memory write / recall / share / forget /
  recover, task coordination, deterministic curation, RLS, audit, backup/restore, the BYOK provider plane and local
  deployment; cloud-only is the public pool, LLM-driven curation and reports (session brief, digest email, gap/health
  report, rule distillation, cross-project lessons, repeated-question detection), the knowledge graph and cross-project
  reuse. D-B: cloud crates may depend on core, never the reverse, and every crate declares its edition (`0073:20-21`).
- M15's code is core today: `humaux-private-worker` and `humaux-consolidation-worker` both declare
  `edition = "core"` (`bins/private-worker/Cargo.toml:9`, `bins/consolidation-worker/Cargo.toml:9`), although the note
  records that ADR-0073 D-A makes LLM-driven curation and reports cloud-only (note :41-42). Most of the core half does
  not exist yet either: the rollup read path (:30-31), the automation-policy reader (:32-33), the §11.10 grounding
  detector and freshness (:34-35), the candidate table and its gate (:37); `domain::knowledge` is a five-line
  placeholder (:39). The split is therefore applied before the code it classifies; it migrates nothing.
- The BYOK provider hop already lives in the consolidation worker, and the deployment horizon is 4 vCPU (note :62-63),
  so a second process is a cost the note refuses.

## Decisions

### D-A Core keeps the deterministic path; the cloud edition takes the model and the reports

Core (note D1, `:56-58`): freshness classifier, exact-duplicate groups, stale-propagation detector, candidate table
and API, R10 counting and ladder, the ADR-0080 applications/acceptances/experience list, the automation-policy reader
and the rollup read path.

Cloud (`:58-60`): the consolidation worker's LLM rollups, the LLM proposals (contradiction labels, rule/lesson/
follow-up/profile drafts, §11.10 semantic revalidation) and the cloud reports ADR-0073 D-A names (gap/health report,
repeated-question detection).

B20b's reason for the core half is recorded with the decision: "OSS gets the full safety path with no generative
model" (`:57`).

The note's §5 producer column (`:131-140`), applied row by row (row 5, the session-start brief at `:135`, is an M14
product with no producer edition, so it is not listed): project/task state — M14 facets + M15 freshness/coverage core,
rollup summary cloud; person/customer profiles — M14 timeline view + `PROFILE_SLOT` candidates core, profile prose
rollup cloud; dedup / contradiction / stale — `DUPLICATE_GROUP` and `STALE` core, `CONTRADICTION` labels cloud;
cross-project lessons and reuse — experience list core (ADR-0080), `LESSON_DRAFT` cloud; reminders and follow-ups —
`FOLLOW_UP_PLAN` drafts cloud, delivery M22; gap/health report — cloud (D11); rules from repeated corrections — ladder
core (D9), rule text cloud; change digest email — M15 `DigestSection` impls cloud, delivery M22; repeated question /
storage — storage core, question cloud (D10).

### D-B One cloud process: the consolidation worker flips and hosts every cloud curation job

`humaux-consolidation-worker` moves to `edition = "cloud"` and hosts all cloud curation jobs in one process (note
:61-62). Card M15-8 performs the flip: `bins/consolidation-worker/Cargo.toml`,
`docs/architecture/module_ownership.toml`, dependency map (note :180). G-M01-2 enforces the direction (note :61;
ADR-0074 D-D), and the per-member edition declaration is checked by G-M01-1 (ADR-0074 D-C). The note names one crate;
no other member is flipped by M15 (`:61-62`).

## Consequences

- Positive: the open-source export keeps the full review and safety path with no generative model (note :57); the cloud
  products share one process with the BYOK hop they need (`:62-63`); the candidate table is core, so core deterministic
  passes and cloud LLM drafts write one surface (D3, `:71-75`).
- Cost: the flip is metadata only but needs a fresh red record (`:180`).
- Direction: M15 is layer L4, may depend on M01/M04/M05/M07/M08/M09, and may not depend on M10/M11 internals, M14+ or
  any cloud crate from core (note :165-166); consumers call M15, not the reverse (`:166`).
- Neutral: no manifest, module row, migration or gate changes here. M15-8 carries the flip.

## Gates

Planned, implementer-owned, tri-state (§57.1); no gate is added by this card:

- **G-M01-2** (existing; no new gate), owner card M15-8 (note :180). The note names the gate and the card but not the
  injection, so both come from ADR-0074 D-D: a `core` package gaining a dependency on a `cloud` package makes
  architecture-check fail, naming the edge (ADR-0074:60-61). The flip stays covered by G-M01-1's edition declaration
  (ADR-0074 D-C). A missing input in CI is a fail, never `not_applicable` (note :194, ADR-0050).

## Owner-gated (listed, not decided)

- Enabling cloud curation in production (note :237).
- Any live provider key use in the M15 experiments (note :236).
- First live send of a digest/report email (note :236-237, "M22 rule").
- Owner questions: none new (note :235). D4's "confirm or overrule" of audit decision D5 belongs to D4, not to D1.

## Open research

- X-M15-3 contradiction precision decides whether cloud contradiction proposals are default-on or opt-in and gates
  M15-14a (note :224); it is not decided here.
- The LLM daily budget per payer is UNKNOWN (note :231). The note's fallback is the B18 Q7 start values and only after
  the user sets a budget (D5, `:89-92`); this ADR records the fallback and sets no number.

## Alternatives rejected

LLM curation in core (ADR-0073; note :62); a new curation crate or process (4 vCPU; the BYOK hop already lives in the
consolidation worker, note :62-63).

## References

- Module design note M15: D1 (`module_design_M15.md:56-63`), §5 producer column (`:128-140`), §7 table ownership and
  layer (`:155-166`), card M15-8 (`:180`), §9 gate note (`:194`), §11 UNKNOWN (`:231`), §12 red lines (`:236-237`).
- ADR-0073 D-A, D-B, D-D; ADR-0074 D-A, D-C, D-D; ADR-0078 D-D; ADR-0080 D-A, D-G.
- Baseline §11.6, §57.1, §58, §80.1, §81.
