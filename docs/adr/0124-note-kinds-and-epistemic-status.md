# ADR-0124 — Note kinds event, plan and episode, and `epistemic_status` keyed on the producer

- Status: Accepted (2026-10-27, lead, under charter). Card M07-5 (wave B, module M07, `ADR-M07-d` in the note). Content
  authority: module design note M07: the PROPOSED contract (note :33-37), owned data (:52-55), D4 (:100-104), gate
  G-M07-6 (:148), card row (:161) and maintenance notes (:170-175); and the lead rulings of 2026-10-27 recorded in
  Humaux (rulings 1-6 and 4'). This ADR re-decides none of the note's decisions; D-B records one refinement of D4 and
  one deviation from note :35.
- Amends: ADR-0067 D-D (note kinds). ADR-0067 carries one pointer line; its frozen text is not rewritten.
- Relates to: ADR-0067 D-C (origin ceiling), ADR-0085 (canonical memory text), ADR-0030 (affect annotations),
  Baseline §8.5, §10.1, §78.2; M07-8 (episodes, pull-based).

## Context

- ADR-0067 D-D closed `note_kind` at nine values mapped onto `memory_type`. The note (D4) adds three kinds and an
  `epistemic_status` column; neither exists, so a Memory records who may speak for its text nowhere (note :100-104).
- `memory.note_put` has one origin: `AuthenticatedAgent`, server-fixed (ADR-0067 D-C; `note::authorize_note` builds its
  basis from that one class, `note_repo::materialize_in_txn` stamps it, and `operation_receipt` refuses any other
  `origin_class`). D4's sentence "user note -> SourceReported, agent extraction -> Interpretation" therefore cannot be
  keyed on the origin class: every note would be an agent's, and the user and tool-result arms could never fire. The
  first attempt at this card stopped on that, and the lead ruled the refinement in D-B.
- Four callers reach the Memory INSERT door `memory_repo::insert_memory_in_txn` in production code: `memory.note_put`,
  `memory.correct`, `memory.confirm`, and the Distill hop's write leg (through the alias `distill_repo::insert_memory`).
  Consolidate and affect annotation do not call it.

## Decisions

### D-A Three more note kinds, all stored under `NOTE`

`NoteKind` gains `Event`, `Plan` and `Episode` (wire and DB `event`, `plan`, `episode`), all bound to `memory_type NOTE`
(note :54). `event` is a fact about something that happened (email, chat, calendar); `plan` is a commitment (reminders
are M14/M22); `episode` is one attempt and how it went (its tables land with M07-8, note D6). The generated `facet` is
unchanged: `NOTE` maps to no facet (ADR-0045).

| note_kind | memory_type | facet |
|---|---|---|
| rejected, decision, fix, problem, lesson, research, preference, state, note | unchanged (ADR-0067 D-D) | unchanged |
| event | NOTE | NULL |
| plan | NOTE | NULL |
| episode | NOTE | NULL |

Migration 0283 replaces both 0235 CHECKs, `memory_records_note_kind_check` and
`memory_records_note_kind_memory_type_check`, with their twelve-value versions under the same names, in one
`ALTER TABLE` (DROP and ADD together, so there is no window without a CHECK). Every existing arm keeps its meaning, so
every existing row passes. 0235 is not edited. The add-constraint style is the plain `ADD CONSTRAINT` of the newest
`memory_records` CHECK migration on main (0236), not the `NOT VALID` + `VALIDATE` pair of 0247 (which targets
`private.subjects`); the manifest states the choice. `NoteKind::ALL` becomes `[Self; 12]` in table order: the nine
existing, then Event, Plan, Episode.

The published MCP contracts enumerate the kinds: `memory.note_put`'s `note_kind`, `memory.enumerate`'s `note_kinds`
filter (`maxItems` 9 -> 12, the number of distinct kinds) and the `note_kind` of a returned item
(`contracts/mcp/memory.schema.json` x2, `context.output.schema.json` x1) now list the twelve, in `NoteKind::ALL` order, as
`protocol::tests::note_kind_contract` requires. No other wire behaviour changes.

### D-B `epistemic_status`, set from the producer by one `match`

`domain::memory::EpistemicStatus` is `{ SourceReported, Interpretation, DirectObservation, Unknown }` with
`as_db_str` -> `SOURCE_REPORTED`, `INTERPRETATION`, `DIRECT_OBSERVATION`, `UNKNOWN` (PascalCase variants, upper-case DB
values, §78.2). Migration 0283 adds `private.memory_records.epistemic_status text NOT NULL DEFAULT 'UNKNOWN'` with a
CHECK on the four values and a column COMMENT citing this ADR. A Memory written before 0283 reads `UNKNOWN` by the
default; there is no backfill, because no source recorded how those texts came to be.

`NewMemory` gains `producer: MemoryProducer`, a closed enum defined in `memory_repo.rs` with exactly the callers there
are today. `insert_memory_in_txn` binds `epistemic_status(producer)`, the workspace's one `match` from producer to status:

| producer | caller | status | why |
|---|---|---|---|
| `NotePut` | `note_repo` (`memory.note_put`) | `SOURCE_REPORTED` | the caller's verbatim assertion (`representation` `verbatim_assertion`) |
| `Correction` | `memory_governance_repo` (`memory.correct`, origin `DirectUserInput`, `USER_CORRECTION`) | `SOURCE_REPORTED` | the text the user stated |
| `Distill` | `bins/private-worker` write leg | `INTERPRETATION` | model-produced text |
| `Confirm` | `distill_repo::confirm_candidate_atomically` (origin `UserConfirmed`) | `INTERPRETATION` | the text is the candidate's, model-produced; the user's confirmation lives in the origin and the authority, not here |

**Refinement of note D4.** The mapping keys on who produced the text, never on the Evidence origin class. D4's "user note"
is the `memory.note_put` lane. D4's "agent extraction / distill / affect -> Interpretation" is `Distill` and `Confirm`
today. D4's "tool result -> DirectObservation (narrow)" and "import -> SourceReported" have no caller yet.

**Deviation from note :35.** The note's contract line reads "`NewMemory` gains `epistemic: EpistemicStatus`". Callers
name a producer and never a status, so the mapping stays in one place (note :172: "one `match` in `memory_repo.rs`");
with a status field it would live in every caller.

**Not wired.** No variant exists for consolidate, affect annotation, tool results or import (M25): there is no caller for
any of them. One `// ponytail:` line at the `match` records the arms each of them will add with its first caller
(consolidate/affect -> Interpretation, tool result -> DirectObservation, import -> SourceReported). `DirectObservation`
has no writer today; its label is in the CHECK so that the first writer needs no migration. The `match` has no wildcard
arm, so a new producer does not compile until it is ruled on.

### D-C Epistemic status is independent of the ADR-0067 D-C origin ceiling

`epistemic_status` is a separate axis from the §10.1 origin-bound authority ceiling. It certifies no truth and grants no
authority: `authorize_note`, `StoredAuthority::authorize` and every other authority decision neither read nor write it,
and the `authority_class` a row stores is unchanged by this card. A `SOURCE_REPORTED` note written under the fixed
`AuthenticatedAgent` origin still stores at most `PrivateKnowledge`, and a model-written "user" still never elevates
authority (note D3, B22). So this card does not contradict ADR-0067 D-C. The column COMMENT says the same, and the
`memory_repo.rs` header carries it as an invariant.

No new error enum is added and no configuration is hard-coded (§52, §78.1).

## Contracts

- **C-1** `humaux_domain::note::NoteKind`: twelve variants, `ALL: [Self; 12]`, `wire`, `memory_type`.
- **C-2** `humaux_domain::memory::EpistemicStatus`: four variants, `ALL`, `as_db_str`.
- **C-3** `adapters::memory_repo::{MemoryProducer, NewMemory::producer}` and the `epistemic_status` match.
- **C-4** `migrations/0283_note_kinds_epistemic_status.{sql,manifest.toml}`.
- **C-5** `contracts/mcp/{memory,context.output}.schema.json`: the `note_kind` / `note_kinds` enums.

## Consequences

- Positive: three kinds the timeline and episode work needs (M07-8) without a new `memory_type` (note :100-104); every new
  Memory says whether its text is a source's own or a model's, with one mapping to change (note :172); legacy rows are
  honestly `UNKNOWN`.
- Cost: one `NOT NULL DEFAULT` column and a CHECK validation scan on `memory_records` (the cost class of 0235/0236); a
  required `producer` field on every `NewMemory` constructor; the MCP contract enums grow, so a client that validates
  `note_kind` against a pinned list of nine must update.
- Neutral: `authority_class`, visibility, projection, recall and the text view are unchanged; no reader consumes
  `epistemic_status` yet.

## Gates

Three-state (§57.1). G-M07-6 is the note's row (note :148); the producer assertions belong to the same card.

| gate | test | inject | expected red | red |
|---|---|---|---|---|
| G-M07-6 `EpistemicStatus` set | `crates/adapters/tests/facet_contract.rs::epistemic_status_equals_the_db_check_and_defaults_to_unknown` | a Rust variant without a CHECK value | the Rust and DB label sets differ | r1 |
| G-M07-6 `NoteKind` set and binding | `facet_contract.rs::note_kinds_and_their_memory_types_equal_the_db_checks` | a CHECK without `'episode'` | the Rust and DB label sets differ | r2 |
| 0283 postcheck, binding pairs | `migrations/0283_note_kinds_epistemic_status.manifest.toml` (run by `migrate`) | `event` bound to `DECISION` in the binding CHECK | the postcheck refuses the migration | r8 |
| `EpistemicStatus::ALL` complete | `crates/domain/src/memory.rs::tests::epistemic_status_all_lists_every_variant_and_labels_are_upper_snake` | a declared variant missing from `ALL` | `ALL.len()` differs from the declared variants | r9 |
| `NoteKind::ALL` complete | `crates/domain/src/note.rs::tests::note_kind_all_lists_every_variant_once` | a declared variant missing from `ALL` | `ALL.len()` differs from the declared variants | r10 |
| mapping, exhaustive | `memory_repo::tests::every_producer_maps_to_its_ruled_status` | map `NotePut` to `Interpretation` | the ruled status differs | r4 |
| `NotePut` row | `crates/adapters/tests/note_put.rs::g22_a_three_statement_note_is_one_memory_and_no_candidates` | map `NotePut` to `Interpretation` | the stored status differs | r4 |
| `Distill` row | `bins/private-worker/tests/distill_hop_e2e.rs::d12_a_tool_channel_reply_in_content_is_parsed_and_accepted_once` | map `Distill` to `SourceReported` | the stored status differs | r3 |
| `Correction` row | `crates/adapters/tests/memory_attribution.rs::g_m29_5b_correction_inherits_supersede_does_not` | map `Correction` to `Interpretation` | the stored status differs | r5 |
| `Confirm` row | `crates/adapters/tests/memory_attribution.rs::g_t06a_confirm_reads_the_source_evidence` | map `Confirm` to `SourceReported` | the stored status differs | r6 |
| published `note_kinds` `maxItems` | `crates/protocol/tests/note_kind_contract.rs` | `maxItems` other than `NoteKind::ALL.len()` | the contract differs from the domain | r7 |
| published enums | `crates/protocol/tests/note_kind_contract.rs` | a contract enum without a kind | the enum differs from `NoteKind::ALL` | not reddened by this card: the ADR-0067 D-D gate, unchanged but for the `maxItems` assertion above |

## Alternatives rejected

- `NewMemory.epistemic: EpistemicStatus` (note :35): any caller could name any status, and the mapping would be spelled in
  every caller instead of once.
- Mapping from `EvidenceOriginClass`: `memory.note_put` is always `AuthenticatedAgent`, so every note would read
  `INTERPRETATION` and D4's user and tool arms could never fire.
- `Emotion`, `Person` and `Customer` note kinds (note D4): affect annotations (ADR-0030) and subjects already carry them,
  and the B20 views read those tables.
- The full B20 temporal column set now (note D4): `occurred_at` and `effective_*` exist; the rest is added when a timeline
  consumer needs it.
- Backfilling legacy rows: it would invent a provenance nobody recorded; `UNKNOWN` is the truth.
- `NOT VALID` + `VALIDATE` for the CHECK replacement: 0236, the newest `memory_records` CHECK migration, adds plain; the
  table is scanned once either way.

## Red records

Each fault is injected on its own throwaway branch off the card's code head and run through `targeted.yml`; the branches
are deleted. Run ids and the failing lines are also in the card's PR description. r1-r3 were cut from `e2cb9afc` (code
identical to `ff508087`); r4-r10 from `19a1e7eb`, the head that adds the review fixes. The green records are the same
selectors on the unmutated card branch: run 40417588220 (`facet_contract`, `note_put`, `memory_attribution`: 8, 12 and 15
tests passed) and run 40417594268 (`distill_hop_e2e d12`: 1 passed) on `ff508087`; runs 40427289923 (`facet_contract`, 8
passed, the 0283 postcheck included), 40427294306 (`humaux-domain --lib`, 253 passed), 40427298968 (`note_kind_contract`),
40427303557 (`memory_repo` unit) and 40431055679 (`note_put`, `memory_attribution`) on `19a1e7eb`.

- r1, `red/m07-5-r1`, run 40419052345: `EpistemicStatus::Hypothesis` added to the enum, `ALL` and `as_db_str` with no CHECK
  value -> `facet_contract::epistemic_status_equals_the_db_check_and_defaults_to_unknown` red at
  `crates/adapters/tests/facet_contract.rs:393` (`epistemic_status: the DB literals and the Rust vocabulary drifted`, the
  Rust side holds `HYPOTHESIS`).
- r2, `red/m07-5-r2`, run 40419058622: `'episode'` dropped from the 0283 `memory_records_note_kind_check` list (and from the
  manifest postcheck, so `migrate` still passes) -> `facet_contract::note_kinds_and_their_memory_types_equal_the_db_checks`
  red at `crates/adapters/tests/facet_contract.rs:393` (`note_kind: ... drifted`, the DB side lacks `episode`).
- r3, `red/m07-5-r3`, run 40419064900: `MemoryProducer::Distill` mapped to `SourceReported` in `epistemic_status` ->
  `distill_hop_e2e::d12_a_tool_channel_reply_in_content_is_parsed_and_accepted_once` red at
  `bins/private-worker/tests/distill_hop_e2e.rs:2618` (left `SOURCE_REPORTED`, right `INTERPRETATION`).
- r4, `red/m07-5-r4`: `NotePut` mapped to `Interpretation`. Run 40431010428 (`note_put g22`) red at
  `crates/adapters/tests/note_put.rs:441` (`row.epistemic_status` is not `SOURCE_REPORTED`); run 40431015888
  (`memory_repo` unit test) red at `crates/adapters/src/memory_repo.rs:314` (`NotePut`).
- r5, `red/m07-5-r5`, run 40431020384: `Correction` mapped to `Interpretation` ->
  `memory_attribution::g_m29_5b_correction_inherits_supersede_does_not` red at
  `crates/adapters/tests/memory_attribution.rs:917`.
- r6, `red/m07-5-r6`, run 40431027338: `Confirm` mapped to `SourceReported` ->
  `memory_attribution::g_t06a_confirm_reads_the_source_evidence` red at
  `crates/adapters/tests/memory_attribution.rs:665`.
- r7, `red/m07-5-r7`, run 40431033896: `note_kinds` `maxItems` set back to 9 in `memory.schema.json` ->
  `note_kind_contract::every_published_note_kind_enum_is_the_domain_set` red at
  `crates/protocol/tests/note_kind_contract.rs:32`.
- r8, `red/m07-5-r8`, run 40431039184: `event` bound to `DECISION` in the 0283 binding CHECK, manifest unchanged -> the
  `migrate` step of the setup action stops with `0283_note_kinds_epistemic_status: postcheck refused the migration —
  returned false`; no test runs.
- r9, `red/m07-5-r9`, run 40431044383: `EpistemicStatus::Hypothesis` declared (with a label) but not listed in `ALL` ->
  `epistemic_status_all_lists_every_variant_and_labels_are_upper_snake` red at `crates/domain/src/memory.rs:285`.
- r10, `red/m07-5-r10`, run 40431050716: `NoteKind::Reminder` declared (with a label and a type) but not listed in `ALL` ->
  `note_kind_all_lists_every_variant_once` red at `crates/domain/src/note.rs:297`.

## References

Module design note M07 (note :33-37, :52-55, :100-104, :148, :161, :170-175); ADR-0067 D-C, D-D; ADR-0045; ADR-0030;
ADR-0085; Baseline §8.5, §10.1, §52, §57.1, §78.1, §78.2; migrations 0235, 0236, 0247, 0283.
