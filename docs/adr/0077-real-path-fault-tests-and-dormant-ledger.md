# ADR-0077 — Real-path fault tests for live DegradeCode variants and the dormant ledger

- Status: Accepted (2026-10-19). Card M01-3 (module design M01 D4, "ADR-M01-b").
- Relates to: Baseline §53.2 (the frozen 11 variants), §53.3 rule 2, §53.4 (every reason needs an injection test; a
  reason never triggered must not merge), §52.2; ADR-0055 D-C (`LANE_SUBSTITUTED`), ADR-0057 D-E (projection loss
  and lag); ADR-0074 (the neighbouring M01 gates and their red-record habit).

## Context
§53.3 rule 2 makes the number of fault test files equal to the number of `DegradeCode` variants. It does not ask what
a fault test drives. All 11 files in `crates/testkit/tests/fault/` called `abstain()` directly, so each proved that the
single exit increments its counter and returns the wire form (a fact `degrade.rs` already tests), and none proved that
production code reaches the exit. Only three variants have a production emit site, all in
`crates/retrieval/src/envelope.rs`: `ProjectionInvisibleLoss` (`build_projection_block`, A2), `ProjectionLag`
(`build_projection_block`, `.also(..)` after the A2 half) and `LaneSubstituted` (`dense_lane_substitution`).
Deleting any of the three production emits left every fault test green. That is the "never triggered, yet merged"
shape §53.4 forbids, with the rule-2 equality satisfied.

## Decision
- **D-A Real path.** A variant with a production emit site has a fault test that drives the production function
  that emits it, and the test file never names `abstain`. The three live tests use the smallest real inputs, no mock
  of the function under test (`humaux-retrieval` is a dev-dependency of `humaux-testkit`):
  - `projection_lag.rs`: `ledger::close` over one pending ticket aged 31 s, `build_projection_block` with a 30 s
    threshold; asserts the degradation list is exactly `[ProjectionLag]` and `current` keeps its frozen formula.
  - `projection_invisible_loss.rs`: the §53.4 registered readings (100 expected, 100 done, 0 deleted, 100 settled
    points) against `visible = 90`; asserts `[ProjectionInvisibleLoss]`, `current == false`, done and deleted unchanged.
    The Qdrant-level half of the registration (deleting 10 real points past `retention::tombstone`) needs the live
    index and stays with M13 (G80-5).
  - `lane_substituted.rs`: a temporal planner decision without `mode` through `dense_lane_substitution`, plus the §53.4
    negative control (an explicit `mode` moves nothing).
  All three still use `assert_fault_observed`, so the counter moves by exactly 1 and the wire form is checked as before.
- **D-B What counts as a production emit site.** A call of `abstain` or `.also` / `::also` (the one list
  `DEGRADE_EXIT_CALLEES`) in `crates/*/src` or `bins/*/src` (not the testkit), whose first argument is a path ending
  in a variant name, with comments and string/char literals masked and every `#[cfg(test)]` item of the file blanked.
  The path may be bare (`DegradeCode::V`), qualified (`humaux_telemetry::degrade::DegradeCode::V`), aliased
  (`use DegradeCode as C; C::V`) or glob-imported (`V`), and the callee may carry a turbofish. A variant that is only
  matched on, counted, listed in a slice or passed to another function is a reader, not an emitter. Line breaks
  inside the call are handled.
  *Fail closed (review W1).* An exit call whose first argument names no variant (a parameter, a local, an
  expression) cannot be attributed, so it is red and names `file:line`, instead of letting the variant it emits read
  as dormant. `crates/telemetry/src/degrade.rs` is exempt: `abstain(code, ..)` forwards its parameter by design.
- **D-C The dormant ledger.** `crates/testkit/tests/fault/dormant.toml` has one `[[dormant]]` row (`variant`,
  `owner`, `reason`) for each variant with no production emit site, and that variant keeps its synthetic test (the
  direct `abstain()` call). Owners: `RerankModelMismatch`, `RerankProviderTimeout`, `EmbedProviderTimeout` -> M11;
  `EgressDenied` -> M05; `GraphExpandCapped` -> M28; `CompletenessUnknown` -> M13; `StatePinMissing`,
  `StatePinAmbiguous` -> M14 (provisional, D-D). Shrink-only, in the style of the `known-red` ledger: a row for a
  variant that now has an emit site is red (the row must be deleted), a variant with neither an emit site nor a row is
  red (a new row is a reviewed diff line naming its owner card), a row naming no variant, a duplicate, an unknown key,
  a missing reason or an owner that is not `M<nn>[-<card>]` is red. Every run prints the live count and each row.
- **D-D `StatePin*` are retirement candidates.** `state_pin` appears nowhere in code or spec outside §53 (the
  fail-open narrative and the §53.2 list), so no card can be scheduled to emit `StatePinMissing` or `StatePinAmbiguous`.
  They stay in the frozen 11 and in the ledger under a provisional owner; the spec-maintenance ADR pass decides
  whether to retire both (which edits the §53.2 / §52.2 freeze, not this ADR) or to find an emitter.
- **D-E G-M01-4.** `cargo xtask architecture-check` sub-check "M01 D4 / G-M01-4", next to rule 2 in
  `xtask/src/architecture_check.rs`, red both ways: (a) a variant with an emit site whose fault test names a degrade
  exit, (b) a `dormant.toml` row for a variant that has one; plus (c) the unledgered dormant variant above. The pure
  comparator (`real_path_from`) takes the variant list, the emit sites, the unclassifiable exit calls, the fault
  sources, the text of `fault_main.rs` and the ledger text, so unit tests inject each fault. It has no
  `not_applicable` leg: the ledger and the tests come from the same card, so absence is a regression (§57.1 rule 2).
- **D-F One predicate for both sides (review B1).** The emit-site scan and the fault-test bypass check read the same
  `DEGRADE_EXIT_CALLEES` list (`abstain`, `also`) through the same finder, so an exit shape the scan recognises cannot
  slip past the bypass check. A fault test is red when it mentions `abstain` anywhere in code (import, call, function
  value) or calls `.also` / `::also`; the message names `file:line` and the callee. Before this, the bypass check
  knew only the identifier `abstain`, and `Outcome::clean(..).also(DegradeCode::ProjectionLag)` kept G-M01-4 green.
- **D-G Wiring (review W3).** Cargo discovers no file under `tests/fault/`; `crates/testkit/tests/fault_main.rs` pulls
  each in with `#[path = "fault/<stem>.rs"] mod <stem>;`. G-M01-4 requires that adjacent pair, in code (not in a
  comment, no `#[cfg]` between the two lines), for every fault file it reads. Deleting a `mod` line used to leave
  `fault_main` green with the test silently gone.

## Rejected
- Deleting the 8 dormant variants: §53.2 / §52.2 freeze the 11; the wire format and metric labels would churn twice.
- Keeping the synthetic tests as proof for live variants: §53.4 "a reason never triggered must not merge".
- A runtime label-cardinality count (D50): labels are the closed `&'static` set (ADR-0061 D-A gate), closed by
  construction.
- A `[[dormant_degrade]]` section in `xtask/known_red.toml` (M01 design D4 / M24 D4 sketch): the card keeps the
  ledger beside the tests it governs and evaluates it inside architecture-check; the ratchet rules are the same and
  `known-red` can adopt the section later without changing the rows.
- Resolving helper callees to find indirect emits: no such helper exists today. An exit through a helper that takes
  the code as a parameter is not missed any more, it is red (D-B fail closed).

## Ceilings (`ponytail:` in the code)
- The scan is text, not a parse (comments and literals are masked by a lexer-lite shared with
  `strip_block_comments`): an exit callee renamed by `use .. as`, passed as a function value or reached through a
  macro is not seen, and neither is a hand-built `Outcome { degradations: .. }`. The single construction point of
  `abstain` (§53.1) keeps those shapes out of the tree; upgrade to resolving the callee if one appears.
- A non-`DegradeCode` method that happens to be named `also` in production code reads as an unclassifiable exit and is
  red; rename it.
- `#[cfg(test)]` blanking matches braces after masking, so only a `;` inside a gated item's signature ends it early.
- The owner check validates the shape, not that the card exists (same as `known-red`).

## Red records
Each fault is injected on its own throwaway branch (`red/m01-3-*`) and run through `targeted.yml`; run ids and the
failing lines are in the card's PR description.
- r1: `projection_lag.rs` names `abstain` again -> G-M01-4 red (xtask test over the real tree).
- r2: a `dormant.toml` row for `ProjectionLag` -> G-M01-4 red (same test).
- r3: the production `.also(ProjectionLag)` removed from `build_projection_block` -> the `projection_lag` fault test
  is red, which proves the test is on the real path.
- Review round (PR #58), each on its own `red/m01-3-*` branch off the fix head:
  - B1-also: `projection_lag.rs` builds an outcome with `.also(DegradeCode::ProjectionLag)` -> G-M01-4 red.
  - W1: a qualified `abstain(humaux_telemetry::degrade::DegradeCode::EgressDenied, ..)` appended to `envelope.rs` ->
    G-M01-4 red (the dormant row is stale); the old scan missed it.
  - W2-loss / W2-lane: the `ProjectionInvisibleLoss` emit (`envelope.rs`, A2 branch of `projection_block_a2`) and the
    `LaneSubstituted` emit (`dense_lane_substitution`) removed one at a time -> the matching real-path fault test is
    red.
  - W3: the `lane_substituted` `#[path]` / `mod` pair deleted from `fault_main.rs` -> G-M01-4 red.
- Unit fixtures (`xtask`, `architecture_check::tests`): a live variant whose test names `abstain` and one that calls
  `.also`, a stale row, an unledgered dormant variant, the green shapes, malformed ledgers, the exit predicate over
  comments, strings and identifier boundaries, emit recognition across line breaks and for qualified, aliased,
  glob-imported, turbofish and path-qualified calls, fail-closed exit calls (parameter, local, UFCS, expression) with the
  `degrade.rs` exemption, exits quoted in strings, the literal masker, unwired fault files (absent, commented out,
  `#[cfg]`-gated, wrong path), readers/comments/prefix names skipped, every `#[cfg(test)]` item blanked, scratch
  trees that are green and then red for each of r1, r1b, r2, the static half of r3, W1 (qualified emit, parameter
  code) and W3, a positive control that the scanner finds the three known emitters on the real tree with nothing
  unclassified, and a source-count test that `run()` lists the gate once.

## Consequences
- A card that adds an emit site for a dormant variant changes three things in the same PR: the emit, the fault test
  (it now drives the new production function), and the deletion of the variant's row. Any one missing is red.
- A new `DegradeCode` variant is a §53.2 / §52.2 change; its card adds either an emit site with a real-path test or
  a ledger row naming the card that will.
- The ledger is visible in every architecture-check log, so its size is reviewed like `known-red`'s `rows: N`.
