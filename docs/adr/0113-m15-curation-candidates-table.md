# ADR-0113 — M15 curation candidates: one table, nine kinds, five states, never in a formal read path

- Status: Accepted (2026-10-26). Card M15-0 (docs only, wave D, module M15). ADR-M15-b (this ADR). Content authority:
  module design note M15, decision D3 (`module_design_M15.md:71-80`), its contract C-M15-1 (§6, `:145-146`), its table
  ownership (§7, `:161`, `:165-166`) and its gates (§9, `:198-199`). This ADR records that decision and re-decides none
  of it. No code, migration, enum or gate changes with this PR.
- Supplements: ADR-0078 D-D — this ADR supplements ADR-0078 D-D placement (`docs/adr/0078-work-attribution-axis.md:214-216`).
  ADR-0078 D-A left the table to M29 "later" (`:50-51`); M15 is its first consumer and builds it (note :77). A pointer
  line is added to ADR-0078 D-D; no ADR-0078 rule is changed.
- Relates to: Baseline §6.1.4 (N09), §8.9 (application/acceptance records and recorded candidates), §11.6 (consolidation
  may only propose), §33.10 rule 9 (confirm tokens), §57.1 (tri-state gates), §78.2 (closed sets), §80.1 (inject → red →
  fix → green); ADR-0018 (confirm-token gate), ADR-0078 D-D (supplements ADR-0078 D-D placement), ADR-0078 D-C and D-E
  (N09 R1–R6, G-N09-2), ADR-0080 D-G (evolution operators), ADR-0073 D-A (the candidate path is core).

## Context

- ADR-0078 D-D deferred the table with a shape sketch — "a separate table with `proposed_by=model@ver`, score and
  state" — and with its rules: "readable only through a candidate API and labelled when used; never counted", and "a
  candidate becomes formal only when an A1–A4 condition appears, or when the user confirms a concrete manifest (D-G)"
  (`0078:214-216`). ADR-0078 D-A placed the table on M29's future list (`:50-51`), and named the isolation gate
  G-N09-2: authoritative read-path functions never reference the candidates table (`:322`). In the tree today no
  table, no `candidate_repo` and no `xtask/` arm exist (note :37); `crates/domain/src/knowledge.rs` is a five-line
  placeholder (:39).
- The spec already assumes the table: §11.6's consolidation MAY "emit governance suggestions" and MUST NOT "silently
  mark a Memory superseded" (`Baseline_2.9.md:3262-3273`), and §8.9's experience list names "recorded conflict
  candidates (a record in an append-only candidate table, the §11.6 governance suggestion; empty while that table does
  not exist)" (`Baseline_2.9.md:2188`). ADR-0080 D-G lists candidates as propose-and-label, "never silently promoted"
  (`docs/adr/0080-knowledge-applications-and-acceptance.md:210-230`); N09 R2 keeps similarity, embeddings, Topic names
  and model output candidate-only (`0078:230-231`), and R5 requires the independence test before a model-involved
  candidate becomes formal (`:235-236`).
- M15 produces proposals on both sides of the edition split: the deterministic passes (D2, note :64), the stale
  detector's `STALE` candidate (D7, :102), the ladder's `RULE_PROPOSAL` (D9, :110), repeated storage (D10, :116-117),
  `PROFILE_SLOT` from the M14 facet/timeline view (§5 row 2, :132), and in the cloud edition the LLM labels and drafts
  (D1, :59-60; §5 rows 3, 4, 6 and 8, :133-138). Those producers are the note's and are not re-decided here; this ADR
  records only the carrier. Consumers are already named: M14, M22, M26, M28 and M29 A5 (note :145-146).
- Why M15: it is the first consumer, and ADR-0078 deferred the table to its first consumer (note :77; `0078:50-51`).

## Decisions

### D-A One table with the deferred shape, owned by M15 in the core edition

`private.curation_candidates` is the single carrier (note D3, `:71-73`): `proposed_by` (`model@ver` | `rule@ver`),
`kind`, target ids and their revisions, `payload_hash`, score, and `state` (D-C below). M15 owns it at layer L4
(note §7, `:161`, `:165`), in the core edition: the candidate path is the OSS safety path with no generative model
(D1, `:56-57`). `proposed_by` is provenance only, never authority — the rule ADR-0078 D-C fixes for the same column in
the relation kernel (`0078:88`) and N09 R2 fixes for model output (`:230-231`).

The note fixes the two prefixes and no more; the exact string form is the card's, pinned by the same enum + DB CHECK +
contract test discipline as the kinds (note :243-244).

Rejected: one table per kind (note :79).

### D-B Nine kinds in one frozen closed set

`DUPLICATE_GROUP`, `CONTRADICTION`, `TEMPORAL_CHANGE`, `STALE`, `REPEATED_QUESTION`, `RULE_PROPOSAL`, `LESSON_DRAFT`,
`FOLLOW_UP_PLAN`, `PROFILE_SLOT` — exactly nine (note :73-75). `CONTRADICTION` carries a label from B17's seven
(`:74`); the note does not restate the seven and this ADR does not either, so the implementing card takes them from
B17 and pins them like the kind enum. The set is closed-set discipline: domain enum + DB CHECK + contract test
(note :243-244), under §78.2.

### D-C Five states; accept is a user confirmation that runs the M07 verb

`state` is `PROPOSED | ACCEPTED | REJECTED | EXPIRED | STALE` (note :72-73). An accepted candidate is not an applied
change: "Accept = the user confirms a concrete manifest; the change runs through the M07 verb with its ADR-0018 token"
(note :76-77). So the accept path is: the candidate carries a concrete manifest (target ids + revisions +
`payload_hash`); the user confirms that manifest; the M07 verb executes with an ADR-0018 confirm token; `decide(ACCEPTED)`
stores the acceptance only with that confirm row. The gate's expected red is exactly a change without one — "memory
status changed without a confirm row" (note :199). This is N09 R1 ground ④, "a current authorised confirmation of a
concrete manifest" (`0078:226-229`), and ADR-0080 D-G's "never silently promoted".

The note fixes the accept transition and does not assign the other four; the card pins them with the same CHECK and
contract test (note :243-244).

Rejected: auto-archive of exact duplicates (note :78; §11.6 "silently supersede", and two genuine identical messages are
two events, B20 red 3); B17's conditional auto-supersede (ADR-0080 G-KNOW-7 and N09 outrank research, note :79).

### D-D Readable only through `candidate_repo`; never in a formal read path

C-M15-1 is `candidate_repo::{propose_in_txn, list, decide}` (note :145-146) and it is the only reader and writer of the
table: "Readable only through `candidate_repo`; never in formal read paths, counts, rules or handoffs (G-N09-2)" (note
:75-76). No formal reader, no count, no prevention rule and no handoff manifest may reference it (N09 R2,
`0078:230-231`), and the static arm that keeps it so is G-M15-1 (Gates). M15 is L4 and its consumers call M15, never
the table; M15 may not depend on M14+ or on a cloud crate from core (note :165-166).

### D-E Placement supplement: M15 owns the table, M29's A5 candidates become M15 consumers

ADR-0078 D-A put the candidate table on M29's later list (`0078:50-51`). That is discharged here: the table is M15's,
and M29's A5 candidates — similarity, embeddings, Topic names, model inference (`0078:147`) — are one consumer of
C-M15-1 (note :145-146). Nothing else in ADR-0078 changes: N09, the A1–A4 rungs, D-D's reader and G-N09-2 stay as
written, and ADR-0078 carries a one-line pointer to this ADR.

## Consequences

- Positive: one candidate surface for core deterministic passes and cloud LLM drafts; the open-source edition keeps the
  full review path with no generative model (note :56-57); isolation is a static check, not a review promise.
- Cost: every producer pays a user confirmation before any change (ADR-0018, note :76-77); the transitions into
  `EXPIRED` and `STALE` are not assigned by the note (D-C above); the xtask arm must know the one legitimate access
  pair or it blocks the API itself.
- Never a second source of truth: an accepted candidate changes nothing until the M07 verb commits, and M15 never
  writes Memory or Evidence rows itself (note :15-18, :76-77).
- Neutral: no table, migration, enum, grant or gate lands here.

## Gates

Planned, implementer-owned, tri-state (§57.1); none exists here:

| gate | owner card | test file | injected fault | expected red |
|---|---|---|---|---|
| G-M15-1 candidate isolation (G-N09-2) | M15-1 | `xtask/src/architecture_check.rs` | join `curation_candidates` in `read_materialize` | architecture-check fails, naming the file |
| G-M15-2 candidate never applied | M15-1 | `crates/adapters/tests/candidates.rs` | `decide(ACCEPTED)` calls supersede without a token | memory status changed without a confirm row |

G-M15-1 is the xtask arm of the existing G-N09-2 rule (`0078:322`); the note records the rule as absent from `xtask/`
today (note :37) and assigns it to M15-1 (note :198). Each gate needs its inject → red → fix → green record in M15-1
(§80.1); a missing database in CI is a fail, never `not_applicable` (note :194, ADR-0050).

## Owner-gated (listed, not decided)

None new: the note's §12 records "Owner questions: none new" (note :235), and its red lines (:236-237) do not name this
table. The accept authority is the user's own confirmation through ADR-0018 (note :76-77), not an owner gate.

## Open research

- `REPEATED_QUESTION`'s thresholds k and W are UNKNOWN (note :229, :225); the note's fallback is k = 3 and
  W = min(30 d, query-log retention) (`:229`). They gate the producer card M15-13, not the table's shape.
- The seven `CONTRADICTION` labels are B17 research input, not yet a repository closed set (note :74); the card that
  writes the kind takes the seven from B17 (note :243-244).

## Alternatives rejected

Consolidated from D-A and D-C: auto-archive of exact duplicates (§11.6 "silently supersede"; two genuine identical
messages are two events, B20 red 3); B17's conditional auto-supersede (ADR-0080 G-KNOW-7 and N09 outrank research);
one table per kind (note :78-79).

## References

- Module design note M15: D3 (`module_design_M15.md:71-80`), C-M15-1 (`:145-146`), table ownership and layer
  (`:155-166`), card M15-1 (`:171`), §9 gates (`:194`, `:198-199`), §11 UNKNOWNs (`:225`, `:229`), §12 owner questions
  and red lines (`:235-237`), §13 maintenance note on kinds (`:243-244`).
- ADR-0078 D-A, D-C, D-D, D-E (N09 R1–R6, G-N09-2); ADR-0080 D-G; ADR-0018; ADR-0073 D-A.
- Baseline §6.1.4, §8.9, §11.6, §33.10 rule 9, §57.1, §78.2, §80.1.
