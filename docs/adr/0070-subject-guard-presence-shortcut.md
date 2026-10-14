# ADR-0070 — The subject guard on `memory_records` runs only for memories that have subject links

- Status: Accepted (2026-10-14). Card 35b of delivery plan v2 (set-based subject visibility).
- Relates to: ADR-0029 / migration 0155 (the RESTRICTIVE subject guard), ADR-0069 (card 41's measurement that found
  the cost), Baseline §6.1.3, §6.2.2, §48.2.
- Research: web-GPT batch 13 (`research_gpt_batch13_rls_setbased.md`, conversation 6acf30ad), checked below, plus a
  CI cost split (throwaway branch `diag/35b-rls-cost`, targeted run 38533829956).

## Context

Every gateway or maintenance read of `private.memory_records` passes the RESTRICTIVE policy
`memory_records_subject_visibility`, which calls `private.memory_subject_visibility_ok(tenant_id, memory_id)` — a
`LANGUAGE sql STABLE SECURITY DEFINER SET search_path` function, so PostgreSQL never inlines it. A read whose filter is
not leakproof (`ILIKE`, card 41) cannot narrow the rows first, so the function runs for every row in scope.

The CI split over 10 000 memories of one tenant (best of three, CI PostgreSQL 18.6): the plain scan with `ILIKE` 9 ms;
the visibility + membership arm 3 ms (the membership `EXISTS` already runs as a hashed SubPlan, once); the subject
function alone 199 ms; the whole gateway read 218 ms. The plan shows the subject guard first in the row filter. So
~91% of the read is the subject guard — and nearly every memory has no subject link, for which the guard is true by
construction (`NOT EXISTS` over no links).

## Research check

- A SECURITY DEFINER SQL function is never inlined; neither is one with a `SET` clause, nor a body with a sublink.
  `STABLE` gives no per-argument memoization. Agrees with the measurement.
- Recommended there: a security-barrier view owned by the trusted owner doing the subject check as a set-based anti
  join. Also flagged: today's guard may be implied by integrity (composite FK to `private.subjects`, same tenant), and
  "no subject link" is a safe shortcut while the full check still runs when links exist.
- Rejected there and here: moving the subject check into the application (removes a database boundary, TOCTOU).

## Decision

- **D-A Presence index.** `private.memory_subject_presence(tenant_id, memory_id)`: one row per memory with at least
  one `private.memory_subjects` link, written only by the owner-defined trigger `memory_subject_presence_on_insert`
  (AFTER INSERT on `memory_subjects`, `ON CONFLICT DO NOTHING`), removed only with its memory (FK cascade). Links are
  insert-only at runtime; a subject deletion cascades them away and leaves a stale presence row, which is the safe
  direction (the full guard runs). No DELETE in the definer, so it is not a maintenance delete door. FORCE RLS with a
  tenant-only policy and no reference to `memory_records`, so reading it from `memory_records`' policy has no cycle.
- **D-B Policy.** `memory_records_subject_visibility` becomes
  `tenant AND (NOT EXISTS presence OR private.memory_subject_visibility_ok(tenant_id, memory_id))`. `OR` evaluates left
  to right, so an unlinked memory never calls the definer; a linked one runs exactly the 0155 guard. The truth table
  (no subject → pass; every subject readable → pass; any unreadable or missing subject → deny) is unchanged.
- **D-C Grants.** `SELECT` on the presence table to `role_gateway` and `role_maintenance` (the two roles the
  RESTRICTIVE policy applies to); every other non-owner cell `—` (§6.2.2 header and `rls_check` matrix).

## Rejected

- **The security-barrier view now.** It removes the definer from every read, but it is a second visibility
  surface every read lane would have to move onto, and the measured cost is entirely the unlinked majority. Revisit
  when per-subject ACLs make linked memories common (signal: the call count of the guard approaches the rows read).
- **A derived boolean on `memory_records`.** Updating `memory_records` from a link insert would bump its revision
  (`updated_at`, the projection registry's identity) and needs the row-update policy's visibility arm; a separate
  table needs neither.
- **Session-GUC arrays of visible ids.** Not a credential; stale across revocation.

## Gates

- `subject_guard_runs_only_for_linked_memories` (`bins/gateway/tests/mcp_gateway.rs`, real policies as
  `role_gateway`, `track_functions = 'all'`): over 2 002 memories the guard is called exactly twice (the two linked
  ones); a link to a real subject stays visible; a link to a missing subject is refused; the insert trigger records
  presence. The call count is deterministic, unlike a latency threshold.

## Declared limits

- **Stale presence after a subject deletion.** Costs a guard call for that memory, never a wrong answer.
- **Links written with triggers disabled** (`session_replication_role = replica`, superuser only) bypass the trigger;
  no runtime role can do it, and the migration backfill covers every link that existed before 0242.
- **Membership arm.** Already a hashed SubPlan (3 ms per 10 000 rows); left as is.
