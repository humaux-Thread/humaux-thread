# ADR-0111 — M13 freshness: a per-type policy annotation from Evidence time, never a score or a rank input

- Status: Accepted (2026-10-26). Card M13-1 (docs only, wave D, module M13); ADR-M13-b (this ADR). Content authority:
  module design note M13 §4 D4 (note `:69`–`:77`) and the unknowns that bound it (note `:159`–`:161`), with no owner
  question (note `:166`). This ADR records that decision and re-decides none of it. The code lands in M13-4a
  (`FreshnessPolicy`, pure classify, values file) and M13-4b (wiring); until then every statement about behaviour is
  **planned**.
- Amends: Baseline §21.5 — one-line pointer: freshness is a per-`MemoryType` policy annotation computed from the
  backing Evidence's `occurred_at`, is never a ranking input, and always travels with its `policy_id` and age.
- Relates to: §9 (time semantics), §21.5, §23.3 (the envelope's `freshness` block), §78.1 (no hard-coded business
  config), §78.3 (no clock in domain), §80.1; ADR-0110 (the frontier/totals decisions this annotation sits beside;
  freshness changes no total); design notes M01 (config-registry values file), M11 (ranking), M14 (brief, facet
  freshness), M15 (revalidation), M26 (wire); research B20 (policy defaults), B17, audit B67.

## Context

- Freshness is a literal today: `FreshnessClass::Unknown, latest_evidence_at: None` at `memory.rs:1049`,
  `recall.rs:1201` and `context.rs:410` (audit B67; note `:29`–`:30`). The §23.3 `freshness` block therefore always
  reports unknown.
- §21.5 requires freshness to be computed separately, forbids one uniform 7-day rule, and forbids collapsing
  similarity / relevance / association / completeness / temporal freshness / grounding state into one unexplainable
  score.
- No values file exists for thresholds (note `:104`). B20's defaults are available as starting values; B17 records
  that retrieval never advances `last_confirmed_at`; B20's `last_verified_at` columns have no writer until M15
  revalidation exists (note `:74`–`:77`).
- `occurred_at` coverage on legacy / imported Evidence is unknown (U3; note `:159`), so a missing input is a real
  state this decision must answer for.

## Decisions

### D-A The only input is the backing Evidence's `occurred_at` (note D4)

The per-item freshness input is only `occurred_at` of the Evidence behind the memory (§9); `now` is the snapshot's
database clock — the domain takes no clock (§78.3). A missing `occurred_at` yields `unknown`; `recorded_at` /
`updated_at` are never substituted (note `:69`–`:70`, U3 `:159`). Freshness is an annotation: it never changes rank
and never downgrades a completeness class (§21.5; note `:13`, gate G-M13-6 `:126`).

### D-B Policy per `MemoryType` in a config-registry values file (note D4)

Thresholds live in `config/freshness.toml` (§78.1), not in code and not in one global rule. Starting values are
B20's defaults (note `:70`–`:74`):

| `MemoryType` | aging after | stale after |
|---|---|---|
| State, Issue | 7 d | 30 d |
| Preference | 180 d | never |
| Lesson, Procedure | 90 d | 365 d |
| Fact, Reference | 365 d | not stated |
| Decision, Rejection, Constraint, Outcome, Note | no decay — reported `fresh` | — |

Rejected: one 7-day rule (§21.5 forbids it); a rank multiplier now (ranking is M11's and needs its own eval; §21.5
forbids one opaque score); B20's `last_verified_at` columns (no writer until M15 revalidation) (note `:76`–`:77`).

### D-C Per-item class plus an envelope summary (note D4)

Every item carries its own class; the envelope carries a summary — the worst item, and `unknown` when any item is
unknown and none is stale. `policy_id` and the age are always shown, so a reported `fresh` for a no-decay type is
explainable rather than a bare label (note `:72`–`:74`).

### D-D Reads and re-ingestion never move freshness (note D4)

Reads, re-embeds and dedup re-imports never move `latest_evidence_at` (B20 red 17; B17 "retrieval never advances
`last_confirmed_at`") (note `:74`–`:75`).

## Consequences

- Positive: the §23.3 `freshness` block stops being a literal; ageing becomes per type and explainable; changing a
  threshold is a config change with no card (note `:153`, `:174`).
- Cost: one join `memory_evidence → events.occurred_at` over the returned items (≤ 200), in the same transaction, no
  extra round trip (note `:115`). The B20 values are starting points informed by E-M13-2's distribution, not derived
  thresholds (note `:153`).
- Asks M11: a rank multiplier is not part of this policy; ranking it needs M11's own eval (note `:76`).
- Asks M15: B20's `last_verified_at` columns need a writer when revalidation lands (note `:77`).
- One classifier (lead ruling 2026-10-26, cross-note): the M15 note's D6 specifies the same §21.5 classifier
  (its contract C-M15-2, cards M15-2a/2b). This ADR's classifier is that contract; M13-4a/4b are its only
  implementation and wiring cards. M15-2a folds into M13-4a: M15 D6 start values that name an existing
  MemoryType become policy rows, and the others are listed open. M15-2b shrinks to the `last_verified_at` +
  `verification_evidence_id` guest columns, landing with their first writer. The classifier's input then becomes
  the later of the evidence `occurred_at` and `last_verified_at`. M15's G-M15-3 (crates/domain/tests/freshness.rs)
  is an alias of G-M13-5/6, not a second gate.
- Asks M14: facet freshness is the freshness of the facet's source memories (U4; note `:160`–`:161`).
- Asks M26: render `freshness.policy_id` and the age next to the class on the wire (note `:72`–`:74`).
- Neutral: nothing compiles or runs for this card; no migration, code or gate lands with it.

## Gates

Planned, implementer-owned, tri-state (§57.1); none exists here:

| gate | owner card | injected fault | expected red |
|---|---|---|---|
| G-M13-4 no freshness laundering | M13-4b | use `recorded_at` / `updated_at` as input | re-read / re-embed / dedup re-import changes `latest_evidence_at` |
| G-M13-5 policy from config | M13-4a | delete the State row; hard-code 7 d | missing-type check red; §78.1 literal scan red |
| G-M13-6 freshness ⟂ completeness (DOD-009) | M13-4a | downgrade class when an item is stale | an EXACT envelope with a stale item is no longer exact |

Each needs its inject → red → fix → green record (§80.1) in the implementing card; a missing database is a fail in
CI, never `not_applicable` (note `:118`).

## Owner-gated

None. The note records no owner question (note `:166`), no red-line item (note `:168`) and no research request
(note `:169`); E-M13-2 reads a dev copy only (note `:168`). The per-type policy is an engineering ruling under §21.5
and the cited research, recorded here and not re-decided.

## Open research

- **U3** `occurred_at` coverage on legacy / imported Evidence is unknown (note `:159`). Fallback: missing → `unknown`;
  never substitute `recorded_at`.
- **U4** §21.5 names STATE / ISSUE / NEXT_ACTION / ACTIVE_TASK; the last two are facets, not `MemoryType`s
  (note `:160`). Fallback: the policy is keyed by `MemoryType` only; facet freshness is the freshness of the facet's
  source memories (M14).
- **E-M13-2** measures the class distribution that informs the values (note `:153`); it decides no threshold and
  registers no gate.

## Alternatives rejected

One 7-day rule (§21.5 forbids it); a freshness rank multiplier now (M11's eval plus §21.5's one-opaque-score
prohibition); B20's `last_verified_at` columns before M15 revalidation; substituting `recorded_at` / `updated_at` for
a missing `occurred_at`.

## References

Module design note M13 §4 D4, §5, §8, §9, §10, §11 E-M13-2, §12, §13, §14; Baseline §9, §21.5, §23.3, §78.1,
§78.3, §80.1; ADR-0110; research B20, B17; audit B67.
