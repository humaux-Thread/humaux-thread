# ADR-0113 — M15 curation candidates: one table, nine kinds, five states, never in a formal read path

- Status: Accepted (2026-10-26). Card M15-0 (docs only, wave D, module M15). ADR-M15-b (this ADR). Content authority:
  module design note M15, decision D3 (`module_design_M15.md:71-80`), contract C-M15-1 (§6, `:145-146`), table
  ownership (§7, `:161`, `:165-166`) and gates (§9, `:198-199`); this ADR records that decision and re-decides none of
  it. No code, migration, enum or gate changes with this PR.
- Supplements: ADR-0078 D-D placement (`docs/adr/0078-work-attribution-axis.md:214-216`), which left the table to M29
  "later" (`:50-51`); M15 is its first consumer (note :77), and ADR-0078 D-D gains a one-line pointer here.
- Relates to: Baseline §6.1.4 (N09), §8.9 (recorded candidates), §11.6 (consolidation may only propose), §33.10 rule 9,
  §57.1, §78.2 (closed sets), §80.1; ADR-0018; ADR-0078 D-C/D-E (N09 R1, R2, R5) and Gates (G-N09-2); ADR-0080
  D-G; ADR-0073 D-A (the candidate path is core).

## Context

- ADR-0078 D-D deferred the table with a shape sketch — "a separate table with `proposed_by=model@ver`, score and
  state" — readable only through a candidate API, labelled when used, never counted, and formal only on an A1–A4
  condition or a user-confirmed concrete manifest (D-G) (`0078:214-216`); D-A placed it on M29's future list
  (`:50-51`). None of it exists: no table, no `candidate_repo`, no `xtask/` arm (note :37); `crates/domain/src/
  knowledge.rs` is a five-line placeholder (:39). The isolation rule is G-N09-2 (ADR-0078 Gates).
- The spec already assumes the table: §11.6's consolidation MUST NOT "silently mark a Memory superseded"
  (`Baseline_2.9.md:3262-3273`), and §8.9's experience list names "recorded conflict candidates (a record in an
  append-only candidate table, the §11.6 governance suggestion; empty while that table does not exist)"
  (`Baseline_2.9.md:2188`).
- M15 proposes on both sides of the split: deterministic passes (D2, note :64), `STALE` (D7, :102), `RULE_PROPOSAL`
  (D9, :110), repeated storage (D10, :116-117), `PROFILE_SLOT` from the M14 facet/timeline view (§5 row 2, :132), and
  the cloud LLM labels and drafts (D1, :59-60; §5 rows 3, 4, 6, 8, :133-138); consumers M14, M22, M26, M28, M29 A5
  (note :145-146). Those producers are the note's; this ADR records only the carrier.

## Decisions

### D-A One table with the deferred shape, owned by M15 in the core edition

`private.curation_candidates` is the single carrier (note D3, `:71-73`): `proposed_by` (`model@ver` | `rule@ver`),
`kind`, target ids and their revisions, `payload_hash`, score, and `state` (D-C). M15 owns it at L4 (note §7, `:161`,
`:165`), in the core edition: the candidate path is the OSS safety path with no generative model (D1, `:56-57`).
`proposed_by` is provenance only, never authority (`0078:88`); the note fixes the two prefixes and no more, so the
exact string form is the card's (note :243-244). Rejected: one table per kind (note :79).

### D-B Nine kinds in one closed set

`DUPLICATE_GROUP`, `CONTRADICTION`, `TEMPORAL_CHANGE`, `STALE`, `REPEATED_QUESTION`, `RULE_PROPOSAL`, `LESSON_DRAFT`,
`FOLLOW_UP_PLAN`, `PROFILE_SLOT` — exactly nine (note :73-75). `CONTRADICTION` carries a label from B17's seven (`:74`);
the note does not restate the seven and this ADR does not either, so the implementing card takes them from B17. The
kinds are a closed set: domain enum + DB CHECK + contract test (note :243-244), under §78.2.

### D-C Five states; accept is a user confirmation that runs the M07 verb

`state` is `PROPOSED | ACCEPTED | REJECTED | EXPIRED | STALE` (note :72-73). An accepted candidate is not an applied
change: "Accept = the user confirms a concrete manifest; the change runs through the M07 verb with its ADR-0018 token"
(note :76-77). The gate's expected red is exactly a change without one — "memory status changed without a confirm row"
(note :199). This is N09 R1 ground ④, "a current authorised confirmation of a concrete manifest" (ADR-0078 N09 R1),
and ADR-0080 D-G's "never silently promoted"; the note leaves the other four transitions unassigned.

### D-D Readable only through `candidate_repo`; never in a formal read path

C-M15-1 is `candidate_repo::{propose_in_txn, list, decide}` (note :145-146) and is the only reader and writer of the
table: "Readable only through `candidate_repo`; never in formal read paths, counts, rules or handoffs (G-N09-2)" (note
:75-76). No formal reader, count, prevention rule or handoff manifest may reference it (ADR-0078 N09 R2); the static arm
is G-M15-1 (Gates). M15 is L4 and its consumers call M15, never the table; M15 may not depend on M14+ or a cloud crate
from core (note :165-166).

### D-E Placement supplement: M15 owns the table, M29's A5 candidates become M15 consumers

ADR-0078 D-A's deferral to M29 (`0078:50-51`) is discharged here: the table is M15's, and M29's A5 candidates —
similarity, embeddings, Topic names, model inference (`0078:147`) — are one consumer of C-M15-1 (note :145-146). No
other ADR-0078 rule changes: N09, the A1–A4 rungs, D-D's reader and G-N09-2 stay as written.

## Consequences

- Positive: one candidate surface for core deterministic passes and cloud LLM drafts; the open-source edition keeps the
  full review path with no generative model (note :56-57); isolation is a static check, not a review promise.
- Cost: every producer pays a user confirmation before any change (ADR-0018, note :76-77); `EXPIRED` and `STALE` are
  not assigned by the note (D-C), and an accepted candidate changes nothing until the M07 verb commits (note :15-18).
- Neutral: no table, migration, enum, grant or gate lands here.

## Gates

Planned, implementer-owned, tri-state (§57.1); none exists here:

| gate | owner card | test file | injected fault | expected red |
|---|---|---|---|---|
| G-M15-1 candidate isolation (G-N09-2) | M15-1 | `xtask/src/architecture_check.rs` | join `curation_candidates` in `read_materialize` | architecture-check fails, naming the file |
| G-M15-2 candidate never applied | M15-1 | `crates/adapters/tests/candidates.rs` | `decide(ACCEPTED)` calls supersede without a token | memory status changed without a confirm row |

G-M15-1 is the xtask arm of the existing G-N09-2 rule (ADR-0078 Gates); the note records the rule as absent from
`xtask/` today (note :37) and assigns it to M15-1 (note :198). Each gate needs its inject → red → fix → green record
(§80.1); a missing database in CI is a fail, never `not_applicable` (note :194, ADR-0050).

## Owner-gated (listed, not decided)

- `REPEATED_QUESTION`'s window W waits on the owner's query-log retention answer: "retention row pending the owner"
  (note :40), and "M15-13's window value waits on owner Q1 of M19" (:192); the note's fallback is `W = min(30 d,
  query-log retention)` (`:229`).
- Otherwise none new: "Owner questions: none new" (note :235), and the red lines (:236-237) do not name this table. The
  accept authority is the user's own confirmation through ADR-0018 (note :76-77), not an owner gate.

## Open research

- `REPEATED_QUESTION`'s threshold k is UNKNOWN (note :225, :229); the note's fallback is k = 3 (`:229`). It gates the
  producer card M15-13, not the table's shape.
- Declared profile slots are UNKNOWN (note :230); the note's fallback is "the M14 facet slot set; person profile slots =
  B20 timeline fields only" (`:230`).
- Whether the accept manifest (target ids + revisions + `payload_hash`) is stored on the candidate row, and how
  `decide(ACCEPTED)` is made to require the confirm row, are implementation questions for M15-1; the note decides
  neither.
- The seven `CONTRADICTION` labels are B17 research input, not a repository closed set (note :74); the card that writes
  the kind takes them from B17 (note :243-244).

## Alternatives rejected

Auto-archive of exact duplicates (§11.6 "silently supersede"; two genuine identical messages are two events, B20 red
3); B17's conditional auto-supersede (ADR-0080 G-KNOW-7 and N09 outrank research); one table per kind (note :78-79).

## References

- Module design note M15: D3 (`module_design_M15.md:71-80`), C-M15-1 (`:145-146`), table ownership and layer
  (`:155-166`), card M15-1 (`:171`), §9 gates (`:194`, `:198-199`), §11 UNKNOWNs (`:225`, `:229-230`), §12 owner
  questions and red lines (`:235-237`), §13 maintenance note on kinds (`:243-244`).
- ADR-0078 D-A, D-C, D-D, D-E (N09 R1–R6), Gates (G-N09-2); ADR-0080 D-G; ADR-0018; ADR-0073 D-A. Baseline §6.1.4, §8.9,
  §11.6, §33.10 rule 9, §57.1, §78.2, §80.1.
