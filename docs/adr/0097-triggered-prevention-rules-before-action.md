# ADR-0097 — Mistakes surfaced before an action: the brief's rule list and `before_action`

- Status: Accepted (2026-10-23). Card M14-1 (docs only). Content authority: module design M14 §4 D6 and §5; the owner
  accepted the lead's defaults on 2026-10-22. The code lands in M14-8, which is **pull-based**: it waits for M07-9's
  trigger clauses and M15's rule activation. Until then the statements about behaviour are **planned**.
- Relates to: Baseline §25.4 (Mandatory lane), §52.1 (the two error sets), §57.1, §78.2, §78.6; ADR-0078 D-E (N09);
  design notes M07 D7 (trigger clauses and the closed action set), M15 (rule state, counts, escalation), M26
  (`review`), M27 (pre-tool hooks), M18 (tasks).
- M14 owns no trigger table and no receipt: M07 owns the clauses and action types, M15 owns `ACTIVE` rule state.

## Context

- M07-8 and M07-9 (episodes, mistake annotations, trigger clauses) are not on main; they are pull-based. Nothing
  surfaces a rule before an action today, so requirement R10 ("mistakes are not repeated") has no mechanism.
- The design note's two-surface answer (B20b) is the decision: a small deterministic rule list in the brief prefix, and
  one exact-lookup command before an action. Semantic recall is not enforcement.
- M18's task fact and M07's Evidence doors already provide the target identity and the final gate this path reads.

## Decision

### D-A Two surfaces only

- **(a) The brief prefix** lists the `ACTIVE` prevention rules for the resolved project or customer, at most 8, in a
  deterministic order. It is part of ADR-0093's prefix and inherits its byte-identity rules.
- **(b) `before_action(ActionIntent)`** answers one action. It is the only pre-action surface; M27's pre-tool hooks and
  M26's `review` consume it, and no second matcher exists.

### D-B Exact lookup, never semantic (M14 D6)

- The match is an exact posting lookup on `private.memory_trigger_clauses` (a B-tree index; no LLM and no embedding).
  The action type is a member of M07's closed set.
- Every backing Evidence passes the final gate before a rule is returned: a rule whose Evidence the caller cannot see
  is not returned, and its existence is not inferable from an ordering reason or a count.
- **All** `CHECK` rules up to 32 are returned. Over 32 the answer is `POLICY_OVERFLOW`: the action is held, never
  truncated to a top-k list and never cleared.
- At most 3 **advisory** warnings accompany the `CHECK` rules; the rest are counted, not silently dropped.
- The result is one closed set: `NO_MATCH`, `WARN`, `CHECK_REQUIRED`, `POLICY_UNAVAILABLE`, `UNCOVERED_ACTION`, and
  `NEEDS_TARGET_RESOLUTION` for a customer target with no resolved subject. It is a result on the command, not a third
  error enum (§52.1): an unavailable rule source is `POLICY_UNAVAILABLE`, a degraded answer the caller can see.
- A customer target is matched by its **resolved subject id only**; the matcher never falls back to a name match (N09
  R1–R3).

### D-C Read-only first slice

- No receipts, no rule events, no counts and no escalation in this slice. The design note prices them at about 5.18 M
  rows/day at 60 actions/s with no consumer; they land with M15's metrics card.
- `ACTIVE` state is M15's; M14 reads it and never writes it. A rule that is not `ACTIVE` is not surfaced.
- The command is read-only: one read transaction, no write, no outbox row.

### D-D Budget and failure

- One read transaction, at most 32 keys per action; the warmed target is p95 ≤ 30 ms (B20b's target, measured by
  E-M14-3).
- A missing rule table prints `not_applicable` and names `private.memory_trigger_clauses` (§57.1) until M07-9 lands;
  in CI, once the object is expected, a missing input is a failure, not `not_applicable`.
- The brief's rules section follows the same fallback (M14 U6): it prints `not_applicable` and the missing object, never
  an empty list that looks like "no rules".

## Rejected (from M14 D6)

- Semantic recall as enforcement: similarity cannot decide that a check is required (B20b).
- A nineteenth tool (`review.before_action` separately from `review`): the surfaces are consumers of one command
  (B20b).
- Receipts and rule events now: no consumer, and the volume is real; they land with M15's metrics card.

## Gates

| Gate | Planned test file | Injected fault | Expected red |
|---|---|---|---|
| G-M14-9 trigger matcher | `crates/adapters/tests/before_action.rs` | truncate to top-k; turn AND into OR on customer keys | an overflow is cleared; customer A's rule is shown for customer B |

No gate exists in this PR (docs only). G-M14-9 exists when M14-8 lands with its §80.1 inject → red → fix → green record.

## Open questions and owner-gated items

- M07-9 and M15 rule activation are **open and pull-based** (M14 U6); the fallback above is the honest answer until
  they land. E-M14-3 is open: p95 / p99 at 60 actions/s, warmed; M27 may recommend fail-closed hooks only if p95 ≤
  30 ms.
- Owner-gated: none in this ADR. The path is read-only and writes nothing; making a hook fail-closed is an M27
  recommendation gated by E-M14-3, not a decision taken here.

## Consequences

- A known mistake can stop an action without a model call, and a rule set too large to answer holds the action instead
  of pretending it passed.
- The customer boundary is an identity question, not a string match: an unresolved target never borrows another
  customer's rule.
- The surfaces stay read-only until M15 owns rule state and the metrics card owns the event volume.
