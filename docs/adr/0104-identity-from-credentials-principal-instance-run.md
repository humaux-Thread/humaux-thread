# ADR-0104 — Identity from credentials: a principal, one instance per launch, one run per attempt

- Status: Accepted (2026-10-23). Card M18-0 (docs only, wave D, module M18), ADR-M18-d (this ADR). Content authority:
  module design note M18 §4 D7 and §9 (M02 row) (2026-10-23). This ADR records that decision and re-decides none. Code
  lands in M18-2 (and M18-5); no migration, code or gate changes with this card.
- Amends: Baseline §30.2, by pointer only (the lease owner becomes the instance). Amends M02 D7: the signed
  `context_ref` `Bind` gains an `agent_instance` leg. No M02 ADR exists in this tree, so the M02 amendment is recorded
  here; the M02 design note D7 remains the other side of the contract.
- Relates to: Baseline §30.2, §48, §78.2; ADR-0078 Q10 (its heartbeat/complete/fail token inputs conflict with note
  D7 :66 — see Open research); ADR-0105 (claim); design note M02 D7 and card M02-13.

## Context

- `coord_repo` sets `lease_owner = AuthorizationScope::principal`: one owner equals one principal for all 80 agents, so
  there is no per-agent identity (note §2 :20-22).
- `coord.agent_presence` is named in the spec but was never built (note §2 :29; §6 :135).
- Incident 1: a sub-agent used the orchestrator's `agent_id`, and its four-way progress element was overwritten (note
  §5 :113). The lesson of 2026-08-19 is that a client-supplied agent id is not identity (note D7 :67).

## Decisions

### D-A Three identity legs (note D7)

- `principal_id` comes from M02 (`Principal`).
- `agent_instance_id` identifies one launch, stored in `coord.agent_instances` (replacing the spec's
  `agent_presence`); `parent_instance_id` records spawn lineage.
- `run_id` identifies one attempt. One open run per instance.

### D-B The legs ride in the signed context reference (note D7)

- Instance and run legs ride in the M02 signed `context_ref` (`Bind`); a claim returns a run-bound reference, and
  `run_spawn` returns a child reference with a new instance and a restricted scope (note D7 :65-66; §9 M02 row :166).
- Tool inputs never carry `agent_id`, `run_id`, `principal` or `fencing_token` (note D7 :66; conflicts with ADR-0078 Q10, see Open research).

### D-C The lease owner is the instance; the principal authorises (note D7)

- `lease_owner` becomes the agent instance, while `principal_id` is kept for authorization. One open run per instance.
- Profile, model and display name are never identity. A rename, restart or detach does not launder an instance
  (ADR-0106 D-E applies the same lineage rule to review independence).

### D-D Amends M02 D7 (note §9 M02 row)

- The `context_ref` `Bind` gains `agent_instance`, minted by M18's `register_instance_in_txn`; the run leg is set by
  claim; spawn issues child references.
- Rejected: a client-supplied `agent_id` (incident 1; lesson 2026-08-19).

## Consequences

- Positive: two launches of the same principal cannot heartbeat or complete each other's runs; identity is checked
  from the credential and the signed reference, not from the request body.
- Cost: M18-2 depends on the M02-13 `context_ref` issuing; until it lands, M18-1/3/4/7a ship first (U5).
- Neutral for this card: docs only; no table, migration, config key or wire format changes here.

## Gates

Planned, implementer-owned, tri-state (§57.1); none exists here.

| gate | owner card | test file | injected fault | expected red |
|---|---|---|---|---|
| G-M18-3 identity reuse | M18-2 | `crates/adapters/tests/coord_identity.rs` | accept `agent_id` / `run_id` from tool input | a second instance heartbeats or completes the first's run |

The gate needs its inject → red → fix → green record (§80.1) in M18-2.

## Owner-gated

None in this ADR. No production write, live key or email is involved; the CI read-back credential is owner-gated under
ADR-0106.

## Open research

- U5: M02-13's `context_ref` is not merged. Fallback: M18-1/3/4/7a ship first; M18-2 and M18-5 wait for the M02 leg
  (note §13 :232).
- The instance table replaces a spec name (`agent_presence`) that was never built; the §30 pointer records the rename.
- ADR-0078 Q10: "`task_heartbeat`, `task_complete` and `task_fail` require `task_run_id` and `fencing_token` next to
  `task_id`". Note D7 :66: "Tool inputs never carry `agent_id`/`run_id`/`principal`/`fencing_token`". The two conflict;
  this ADR records both and decides neither.

## Alternatives rejected

A client-supplied `agent_id` (incident 1; lesson 2026-08-19); a lease owner fixed to the principal; model, profile or
display name as identity.

## References

Module design note M18 §2, §4 D7, §5 (incident 1), §9 (M02 row), §10, §11 (M18-2); Baseline §30.2, §48, §78.2;
ADR-0078 Q10; ADR-0105; ADR-0106; design note M02 D7 and card M02-13.
