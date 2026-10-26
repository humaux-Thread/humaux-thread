# ADR-0106 — Acceptance is a gate vector over sealed candidates, with lineage independence and transitive invalidation

- Status: Accepted (2026-10-23; the lead ruling of 2026-10-23 is recorded in D-D). Card M18-0 (docs only, wave D,
  module M18), ADR-M18-f (this ADR). Content authority: module design note M18 §4 D10–D12 and the lead ruling at its
  end (note :257-265); this ADR records those decisions and re-decides none. Code lands in M18-9, M18-10 and M18-11;
  no migration, code or gate changes with this card.
- Amends: Baseline §30, by pointer only — the new §30.5 gate vector is recorded here.
- Relates to: Baseline §30.1, §30.5, §57.1, §78.2; ADR-0080 D-C (the acceptance store and the origin→verifier map);
  ADR-0103 (`OPEN→DONE`); ADR-0104 (lineage); ADR-0109 (memory hand-off); M07; M15 / T-KNOW-1 (verifier map); M26.

## Context

- `complete` is an agent self-report today (E0); there is no acceptance record on a task, and `coord.task_runs`
  carries only `outcome_summary` (note §3 :38; ADR-0080 :25-27).
- Incident 5: sub-agent outputs were not attached, so "overall progress" meant reading PRs by hand (note §5 :117).

## Decisions

### D-A The gate vector and its minimum policy (note D10)

- Gates: STRUCTURE (≈E1), USABILITY (≈E2), AUTOMATED_TEST (≈E3), INDEPENDENT_REVIEW (≈E4), ACCEPTANCE.
- AUTOMATED_TEST needs a trusted CI receipt bound to the candidate's exact commit, environment and check attempt.
- The minimum policy per kind/role is server-registered in `task_plan_revisions`. NOT_APPLICABLE needs a new plan
  revision with a reason and prints the missing object (§57.1); WAIVED never renders as PASS.
- Research tasks take STRUCTURE = sources + conclusion + counter-evidence, then review and acceptance.

### D-B A candidate is sealed, and a new commit is a new candidate (note D10)

- A candidate is `(task, plan revision, head SHA / manifest digest)`; a new commit is a new candidate. Candidates,
  sealed members, plan revisions, outputs and run inputs are `coord.{candidates, candidate_members,
  task_plan_revisions, outputs, run_inputs}` (note §8 :154-155).
- Member sets INPUT / CONTRIBUTOR / OUTPUT / CHILD are sealed: `members_digest` plus a trigger that rejects member
  writes after `sealed_at`.

### D-C The verifier is derived, never supplied (note D10)

- The verifier comes from the Evidence origin through ADR-0080 D-C's closed map — one function, shared with T-KNOW-1 —
  never from the caller; an agent reporting "CI passed" about itself is `AGENT_CHECK`, not CI.

### D-D One acceptance store: ADR-0080 D-C, not a second table (lead ruling, note :258-265)

- `gate_decisions` is **not** a new table (the ruling replaces the note's §6 proposal); the single store is
  `private.run_acceptances`, extended with `candidate_id`, bound to the sealed candidate, and `gate_kind` in
  {STRUCTURE, USABILITY, AUTOMATED_TEST, INDEPENDENT_REVIEW, ACCEPTANCE} as a criterion class (note :259-260).
- ADR-0080 D-C keeps the server-derived verifier, the `TrustedConnector` receipt whose `head_sha` is the run output,
  receipt-derived result/criterion for non-`AGENT_CHECK` verifiers, and INDEPENDENT_REVIEW's lineage check (D-E); M26
  exposes one operation, `record_acceptance`, under the task tool, and there is no separate `gate_record` (note
  :261-265).

### D-E Independence is contributor lineage (note D11)

- A reviewer instance is not in the CONTRIBUTOR set and is not a descendant of any contributor instance: lineage is
  `parent_instance_id` from spawn, so rename, restart or detach do not launder it. A shared pure-orchestrator ancestor
  is allowed; contributors are runs that reported outputs, never a model's self-report; principal inequality is
  checked but weak, so lineage is the binding test.

### D-F Transitive invalidation is computed, never stored (note D12)

- `coord.acceptance_validity_v` recurses over pinned INPUT/CHILD acceptances and is checked synchronously at claim,
  complete and board time; asynchronous messages only notify. B keeps its DONE history but counts as `invalidated`; C
  cannot consume B; REOPEN `IN_REVIEW→OPEN` keeps the budget root; a stored transitive flag is rejected (drift).

## Consequences

- Positive: one store, one verifier map, one operation; lineage and transitive validity are computed, so a green
  receipt cannot be borrowed across SHAs.
- Cost: a current candidate and frozen plan per acceptance; the recursive view stays within the board budget.

## Gates

Planned, implementer-owned, tri-state (§57.1); none exists here.

| gate | owner card | test file | injected fault | expected red |
|---|---|---|---|---|
| G-M18-8 direct completion | M18-11 | `crates/adapters/tests/coord_accept.rs` | allow `OPEN→DONE` with a live run / without a candidate | DONE without a sealed candidate or with a live run |
| G-M18-13 wrong-version evidence | M18-10 | `crates/adapters/tests/coord_gates.rs` | match a CI receipt by check name only | a receipt for another SHA passes AUTOMATED_TEST |
| G-M18-14 self-review laundering | M18-10 | `crates/adapters/tests/coord_independence.rs` | compare instance ids only (no lineage) | a restarted or child implementer passes INDEPENDENT_REVIEW |
| G-M18-15 late CI failure | M18-10 | `crates/adapters/tests/coord_gates.rs` | accept before the CI wait is released | an acceptance stands after a later FAIL on the same candidate |
| G-M18-17 transitive invalidation | M18-11 | `crates/adapters/tests/coord_accept.rs` | evaluate direct revocation only | C claims with B's invalidated acceptance as input |

G-M18-24's gate-kind set is owned by M18-3 and M18-9; each gate needs its inject → red → fix → green record (§80.1).

## Owner-gated

- Q1 (answered 2026-10-23): CI read-back goes through a read-only GitHub App created by the owner at go-live. Until
  then AUTOMATED_TEST stays PENDING or is confirmed by a human; an agent self-report never counts (note :253; U2).
- Q3 (answered 2026-10-23): ACCEPTANCE is recorded by an independent verifier agent for WORK and by the owner for
  MILESTONE (note :255); the server credential is a live key and stays owner-gated (U2 fallback).

## Open research

- U1: the batch-31 acceptance test CSV is not on disk; the gate wording in this ADR is the record (note §13 :227).
- U2: no trusted CI read-back connector exists yet. Fallback: AUTOMATED_TEST stays PENDING or is recorded by USER
  confirmation of a manifest; never an agent-reported PASS (note §13 :228-229).
- U6: T-KNOW-1 (the verifier map) is not merged. Whichever card lands first builds
  `domain::acceptance::verifier_for_origin`; the other consumes it, under a sole-definition gate (note §13 :233).
- Direct revocation: note D12 :86 stores it in `revoked_at`, but the ruling at :258-260 names `private.run_acceptances`
  and adds only `candidate_id` and `gate_kind`; where `revoked_at` lives is open.

## Alternatives rejected

A second acceptance table (`coord.gate_decisions`); a client-supplied verifier; a stored transitive invalidation
flag; accepting a CI receipt matched by check name only; principal equality alone as review independence.

## References

Module design note M18 §2, §4 D10–D12, §5 (incident 5), §6, §8, §9, §10, §11 (M18-9 to M18-11), §13 (U2, U6), and
the lead ruling at :257-265; Baseline §30.1, §30.5, §57.1, §78.2; ADR-0080 D-C; ADR-0103; ADR-0104; ADR-0109; M07;
M15 / T-KNOW-1; M26.
