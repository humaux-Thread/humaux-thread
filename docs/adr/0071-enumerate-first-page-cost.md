# ADR-0071 — `memory.enumerate`'s first page: JIT off, hashed exclusion sets, one evidence-visibility read

- Status: Accepted (2026-10-14). Card 35b-ii of delivery plan v2 (the card-35 E12 bar, moved to 35b).
- Relates to: ADR-0062 D-K (capped manifest, `enumerate_first_page_scales_with_a_capped_manifest`), ADR-0070 (35b-i,
  the subject guard), ADR-0041 D-G (census in the mint's snapshot), ADR-0065 D-B (pool startup options), ADR-0069
  D-D (the shared final read gate).

## Context

After 35b-i the 50 000-memory first page still took p95 5 529 ms on CI (debug build). A throwaway branch logged every
statement over 20 ms with `auto_explain` (`log_analyze`, nested statements) for one first page: ten statements, 6.7 s
in SQL, of which **5.2 s was JIT compilation** — each statement binds an id array of ~50 000 elements, the planner's
cost estimate lands far above `jit_above_cost`, and LLVM compiles plans that execute in tens of milliseconds. The rest
was the secret-backed and tombstoned exclusions running as correlated subplans once per candidate (≈450 000 buffer
hits each), and the census re-running the evidence-visibility read the mint's final gate had just done.

## Decision

- **D-A Exclusion sets, hashed once.** In the shared final gate (`read_materialize`) and in the census
  (`exact_census::SECRET_LINKED` / `NOT_TOMBSTONED`) the two exclusions are uncorrelated `NOT IN` / `IN` subqueries:
  the memories with a `SECRET_MATERIAL` evidence, and the memories with a `TOMBSTONED` stream row (the census's overlay
  stays scoped to its stream). `memory_evidence.memory_id` is `NOT NULL`, so `NOT IN` is the exact anti-join; the
  tenant legs bind `$1`, which the outer `tenant_id = $1` already fixes. Two partial indexes make each set cost one
  probe per excluded row instead of a tenant scan: `private.evidence_objects (tenant_id, evidence_id) WHERE data_class
  = 'SECRET_MATERIAL'` (0243) and `projection.stream_log (tenant_id, commit_seq) WHERE state = 'TOMBSTONED'` (0244),
  both `CREATE INDEX CONCURRENTLY`, the 0212 shape. Without them a 50-id page paid for the tenant-wide set (later pages
  48 → 58 ms); with them later pages are back at baseline.
- **D-B JIT off for every pool.** `adapters::postgres::open` starts every session with `-c jit=off` (a startup option
  beside the ADR-0065 timeouts, so it holds for every role, sized or not, with no server-config dependency). The
  workload is short OLTP reads and bounded scans; nothing here benefits from LLVM.
- **D-C One evidence-visibility read per mint.** `final_memory_ids_with_readable_in_txn` returns the gate's survivors
  and the `can_read` set it computed; `memory.enumerate`'s mint passes that set to its census
  (`CensusInputs::readable`), whose candidates are a subset of the mint's in the same REPEATABLE READ snapshot (same
  scope and predicate plus the stream overlay). A candidate outside the set is dropped, so a mismatch can only shrink
  the census and fail the mint's set-equality cross-check (§22.4 trigger 4) — never widen the universe. The registry
  census path (`exact_enumerate`) passes `None` and reads visibility itself, as before.

## Measurement (CI, PostgreSQL 18.6, 50 000 memories, 30 runs)

| build | change | first p50 / p95 ms | later p95 ms |
|---|---|---|---|
| debug | after 35b-i (run 38540992408) | 3 863 / 5 529 | 48.6 |
| debug | D-A sets only (run 38557127306) | 3 735 / 5 091 | 196.4 (JIT on the small pages) |
| debug | D-A + D-B (run 38557333229) | 2 382 / 2 405 | 58.0 |
| release | D-A + D-B (run 38558462430) | 1 337 / 1 346 | 52.2 |
| release | D-A (+ indexes) + D-B + D-C (run 38560225066) | 683 / 698 | 49.7 |

## Rejected

- **`ALTER ROLE … SET jit = off`** — ADR-0065 D-B keeps `pg_db_role_setting` empty; the startup option is the house
  shape.
- **Server-wide `jit = off` in the deployment's `postgresql.conf` only** — leaves CI, rehearsal and every throwaway
  database on the slow path, and a deployment that forgets it regresses silently.
- **Reusing the mint's final id list as the census total** — card 19 rejected deriving `total` from the manifest
  (§22.1); D-C reuses only the authorization set, the census still runs its own counts.

## Gates

- `every_pool_session_starts_with_jit_off` and `pool_settings_reach_the_session_as_client_settings` (now also pins
  `jit = off`, `source = client`), `adapters::postgres`.
- The exclusions keep their existing behavioural gates, each shown red against the rewritten clause:
  `final_materialize_excludes_secret_memory_source_and_marks_artifact_unavailable` and
  `revoked_memory_and_tombstoned_evidence_are_finally_filtered` (final gate), `all_cases_match_expected_readouts`
  (`exact_completeness_eval`, census secret and tombstone cases); D-C by
  `native_mcp_memory_enumeration_counts_in_the_page_snapshot` (an empty reused set fails the census).
- 0243 / 0244 manifests: postcheck requires the valid index with its predicate.

## Declared limits

- **The 300 ms bar is not met.** Release build p95 698 ms at 50k. What remains is mostly the evidence-visibility read
  (`readable_memory_ids`, ~258 ms): `memory_evidence`'s RLS policy re-checks the memory row (with its whole RLS stack)
  per evidence row, then each evidence row is probed — three index probes per memory. Removing that cost means
  changing how evidence visibility is evaluated (a policy or a precomputed per-memory summary), a security-boundary
  design of its own (card 35b-iii). `enumerate_scale`'s `floor_p95` (~305 ms) is measured on an owner connection with
  JIT on, so it overstates the true RLS floor (the census's equivalent scan runs in ~50 ms with JIT off); the floor's
  definition is kept for comparability with baseline B.
- **`NOT IN` and memory.** If an excluded set outgrows `work_mem` the planner falls back to a per-row subplan —
  slower, never a different set. Signal: a tenant with tens of thousands of secret-backed or tombstoned memories.
