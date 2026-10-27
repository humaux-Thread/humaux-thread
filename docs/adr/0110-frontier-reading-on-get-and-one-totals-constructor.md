# ADR-0110 — M13: `memory.get` reports the ledger frontier, and one totals constructor for the new surface

- Status: Accepted (2026-10-26). Card M13-1 (docs only, wave D, module M13); ADR-M13-a (this ADR). Content authority:
  module design note M13 §4 D1–D3 and D5–D8 — frontier, totals and the M13 envelope bookkeeping (D5–D8) (note
  `:49`–`:88`) — whose owner-questions section is empty (note `:166`). This ADR records those decisions and re-decides
  none of them. The code lands in M13-2a/2b/3/5/6/7/8; until then every statement about behaviour is **planned**.
- Amends: Baseline §23.3 — one-line pointer: get's `pipeline.projection` is a frontier reading, not the closure
  example; the closure shape stays for recall / context / enumerate.
- Relates to: §15.5, §22.0, §22.1, §22.2, §23.1②, §23.1④, §23.3, §25.3.1, §33.5, §57.1, §80.1; ADR-0041
  D-D (class ordering: a direct get is `cannot_establish/count_unknown`); ADR-0057 (A1/A2 on the point ledger);
  ADR-0078 D-D (the M29 attribution reader); design notes M09 D3 (contract C6), M10 (`visible`), M14 (brief), M26
  (wire), M29 (project axis); research B23 (get cost).

## Context

- get's `pipeline.projection` is the recall closure: `read_gate::materialize_memory_get_versioned` calls
  `close_ledger_in_txn`, and `gateway/src/memory.rs` calls `visible_index_count` (a Qdrant count) on every get
  (note `:24`–`:25`). Measured 2026-10-14: 119 ok calls/s, 20.3 ms PG CPU per call, of which
  `projection.stream_point_ledger` ≈ 6.8 ms, O(stream) (note `:26`). Both feed only the projection block; get's class
  is already `cannot_establish/count_unknown` by construction, census `None` (ADR-0041 D-D; note `:27`–`:28`).
- `stream_checkpoints.evidence_highwater / knowledge_highwater` have no writer — only the 0011 GRANT exists
  (note `:31`) — yet C6 exposes them as `u64` "0 until it writes" (note `:32`).
- Totals exist only inside `ExactReport` (note `:43`). §22.1 forbids passing recall counts off as `total`; §33.5
  bounds every tool's output; without one mapping each M26 tool and the M14 brief would invent its own fields.
  §23.1② pins `LedgerCounts` at exactly 6 fields (note `:21`).
- The EXACT census covers the subject axis and the ADR-0067 note axes; predicates
  `authorized_memory_enumeration_v1` and `rejected_decisions_v1` are the only two. There is no project axis
  (note `:22`–`:23`, `:46`).
- `gateway/src/status.rs` is process readiness only (note `:33`); `ops.consistency_reports` has no writer
  (note `:34`). Audit: 19 implemented / 10 partial / 0 missing, 6 partial rows without a registered verifier
  (note `:35`).

## Decisions

### D-A get reports the frontier, not the closure (note D1)

`pipeline.projection` becomes
`{mode: "frontier", issued, settled_prefix, behind = issued − settled_prefix, serving, observed_at}`, read through
C6 `ledger_frontier` (note `:93`); no `visible`, no ratio, no Qdrant count, no closure. The contract vehicle is
`ProjectionReading::{Closure, Frontier}` plus the memory.output schema (note `:94`); the schema file is
`contracts/mcp/memory.output.schema.json`, fingerprinted in `crates/protocol/src/mcp_catalog.rs` (note `:101`). `None`
(no checkpoint row) → `projection: null` with reason `no_checkpoint` — never a fabricated zero (§23.1④; note D1 cites
it as §23.3④). Class unchanged (`cannot_establish/count_unknown`: a point read establishes no universe). The
PostgreSQL read stays authoritative (§15.5). `behind` is an upper bound on in-flight tickets and never feeds A2 or a
LOST verdict (§23.1②). recall / context / enumerate keep the closure (they need A1/A2). Authority: B23 verdict, M09
D3, §23.1② (note `:55`–`:56`).

Which read gets which reading — the single table note §14 points at (note `:174`):

| read | reading | why |
|---|---|---|
| `memory.get` | frontier | one memory has no universe to close; the block answers "written, not yet searchable" |
| `recall` / `context` / `enumerate` | closure | they need A1/A2 and `visible` (§23.1②) |

Rejected: a TTL cache of the closure (`LEDGER_CACHE_MS` has no result, stale-envelope semantics undefined, M09 D3);
B23's incremental `stream_projection_summary` (a second truth source and a hot-row write per settle, M09 D3);
dropping the projection block from get (agents lose "written, not yet searchable"); a universe-of-1 EXACT for get
(changes `classify()` ordering, ADR-0041 D-D, no consumer) (note `:56`–`:59`).

### D-B Dormant highwaters stay unread (note D2)

Frontier consumers read only `issued_hw / projection_hw / serving / updated_at`; an xtask sentinel forbids reads of
`evidence_hw` / `knowledge_hw` outside `stream_repo` until a writer exists. Rejected: M13 writes them — a second
count next to `stream_log`, the same argument as M09 D3 (note `:60`–`:62`).

### D-C One totals constructor (note D3)

`envelope::totals(&FinalOutcome) -> Totals { Exact{total, returned, omitted, truncated}, AtLeast{n}, Unknown{reason},
NotApplicable }`. `Exact` only with a `predicate_id` (§22.0: class and predicate come from the same source);
`AtLeast` only from `known_lower_bound`; get → `NotApplicable`. Every new-surface tool (M26) renders totals from this
one function. Authority: §22.0, §22.1 (`total` from a count over the enumerable scope in the same snapshot), §33.5
(note `:64`–`:67`). Rejected: tool-local total fields (drift); `total = returned` or `total = Qdrant count`
(§22.1) (note `:67`–`:68`).

### D-D FACET_COMPLETE producer (note D5)

A pure function over a continuity snapshot's slot states against the declared required-facet profile: all required
`CURRENT` → `facet_complete{covered, required}`, else `cannot_establish(facet_missing)` with the missing names.
`STALE` / `CONFLICTED` never count as covered. Consumer: the M14 brief coverage line. Authority: §22.2, B17 Q4
(note `:78`–`:80`).

### D-E Processing status per account (note D6)

The sum of frontiers over the caller's streams: `{issued, settled_prefix, behind, observed_at}` per workspace,
worded "not yet confirmed processed" — an upper bound that includes failures — never "failed". The exact `failed` /
`waiting_key` breakdown exists only in `detailed`, through the closure, rate-limited (`ponytail:` O(stream) per
detailed call; upgrade = real evidence/knowledge highwaters). Consumers: M26 `status.health` and M22 (note `:98`).
Authority: B17 Q4 (processing ≠ done) (note `:81`–`:84`).

### D-F Project axis on the EXACT census (note D7)

One M29-owned SQL predicate over `private.memory_projects_live` (`security_invoker`), so the M29 reader arm stays the
single read path (ADR-0078 D-D; xtask `m29_attribution_reader`). Unresolved memories are outside the project universe
and are reported as such, never guessed (N09 R3) (note `:85`–`:87`). The M13→M29 dependency is a declared same-layer,
read-only edge (note §7 `:109`).

### D-G DoD verifier rows (note D8)

D240–D243, D248 and D253 are registered against the tests that already prove them; no new code (note `:88`). D8
carries no ADR tag in the note; it is recorded here, not in ADR-0111, because the rows are this module's verifier
bookkeeping and nothing in D8 is freshness-specific.

## Consequences

- Positive: a get costs one PK lookup (< 0.1 ms) instead of the ≈ 6.8 ms closure plus a Qdrant count; expected PG CPU
  per get ≈ 13.5 ms, measured by E-M13-1 (note `:113`–`:114`), and flat cost across stream sizes is part of G-M13-1
  (note `:152`). One totals mapping for every new tool; facet coverage and per-account processing status gain a producer.
- Cost: `behind` is an upper bound, never a failure count (note `:82`); recall still pays the closure, and its
  upgrade (frontier + sampled reconciliation) needs a new ADR when recall p95 passes B23's 200/500 ms with the
  closure above 25 % of PG time (note `:176`–`:178`); detailed status is O(stream) (note `:84`, `:116`).
- Asks M09: make `evidence_highwater` / `knowledge_highwater` `Option` or drop them (note `:62`–`:63`).
- Asks M26: render every new-surface total from `envelope::totals` (note `:66`–`:67`, contract row `:95`) and surface
  `status.health` from `processing_status(account)` (note `:98`).
- Asks M14: take the brief coverage line and the reuse wording ("N eligible, showing k") from `Totals` (note `:95`)
  and `facet_completeness()` (note `:80`, `:97`).
- Asks M29: the guest card for `private.memory_in_project(...)` (note `:99`, `:143`).
- Asks M24: register the six DoD rows (D240–D243, D248, D253) in the DoD registry format (note `:35`, `:130`, `:145`).
- Neutral: nothing compiles or runs for this card; no migration, code or gate lands with it.

## Gates

Planned, implementer-owned, tri-state (§57.1); none exists here:

| gate | owner card | injected fault | expected red |
|---|---|---|---|
| G-M13-1 get is O(1) (B23 red 15); setup: throwaway DB with `stream_log` SELECT revoked (note `:121`) | M13-2b | call `close_ledger_in_txn` / `visible_index_count` from get | permission denied on `stream_log`; Qdrant-count counter ≠ 0 Red record (M13-2, r1): `get_frontier_door_needs_neither_stream_log_nor_the_point_ledger` red in targeted run 40489193309 (`bins/gateway/tests/memory_get_frontier.rs:413`, the frontier door answered `DependencyUnavailable` once get also closed the ledger; `stream_log` narrowed to the three columns the body gate reads and `stream_point_ledger` EXECUTE revoked, so the closure is denied by construction); green: PR #389 CI run 40482622006. The Qdrant-count leg is the spy `== 0` in `memory_get_over_mcp_reports_the_frontier_and_makes_no_qdrant_request`, with a recall as positive control. |
| G-M13-2 no fabricated frontier | M13-2a (type), M13-2b (wire) | map `None` to a zero frontier; read `evidence_hw` in gateway | `projection` not null on a row-less stream; sentinel count ≠ 0 Red records (M13-2): r2 `a_row_less_stream_is_null_with_no_checkpoint_never_a_zero_frontier` red in targeted run 40489201321 (`bins/gateway/tests/memory_get_frontier.rs:459`, `frontier_pipeline_block(None)` mapped to a zero frontier, `projection` was an object); r3 `xtask` `architecture_check::tests::m13_2_real_repo_passes` red in targeted run 40489211598 (`xtask/src/architecture_check.rs:21370`, `bins/gateway/src/memory.rs` naming `evidence_highwater`, `found 1`); green: PR #389 CI run 40482622006. |
| G-M13-3 totals honesty | M13-3 | `total = returned` for semantic | Exact without `predicate_id` fails; `Totals {` constructed ≠ 1. Red records (M13-3): `humaux-retrieval` `envelope::totals_tests::totals_semantic_and_facet_classes_are_never_exact_or_at_least` red in targeted run 40395113359; `xtask` `architecture_check::tests::m13_3_real_repo_passes` red (`found 2`) in targeted run 40398267295; after review rv-362 (a `Self::Exact` in an `impl From<..> for Totals` in `bins/gateway/src/memory.rs`) the same test red in targeted run 40408308516 |
| G-M13-7 FACET_COMPLETE | M13-5 | count `STALE` as covered | covered/required wrong; class ≠ `cannot_establish`; red run 40402537381 (`facet_completeness_stale_is_not_covered`, `continuity.rs:912`); tests in crates/application/src/continuity.rs (the continuity status and class types live there, so the lead ruled 2'' for M13-5) |
| G-M13-8 project-axis census | M13-7 | read `memory_projects` instead of `_live` | a revoked link counted in `total` |
| G-M13-9 status wording | M13-6 | emit 0 for a row-less stream; label `behind` as failed | `not_applicable` missing / wire word wrong |
| G-M13-10 DoD verifiers | M13-8 | point DOD-009 at a nonexistent test | registry check red |

Each needs its inject → red → fix → green record (§80.1) in the implementing card. The DB gates (G-M13-1, G-M13-2,
G-M13-8, G-M13-9) need `HUMAUX_TEST_PG_DSN`: a missing database is a fail in CI and `not_applicable` locally;
G-M13-3, G-M13-7 and G-M13-10 need no database (note `:118`).

## Owner-gated

None. The note records no owner question (note `:166`), no red-line item (note `:168`) and no research request
(note `:169`): the frontier-versus-closure choice and the totals constructor are engineering rulings under the spec
and the cited research, recorded here and not re-decided.

## Open research

- **U1** When contract C6 `ledger_frontier` lands is unknown (note `:156`). Fallback: M13-2a/3/4a/5/8 proceed;
  M13-2b and M13-6 wait.
- **U2** Whether any client parses get's `projection.visible` / `completeness_ratio` (note `:157`). Fallback: no
  client of this wire is known to parse it; the contract fingerprint bump is the signal; no dual-shape period.
- **U5** The required-facet profile per project — which facets are "required" — is undeclared (note `:162`).
  Fallback: the §25.3.1 `SOURCE_BACKED` set minus the unavailable phase-11/12 facets (B90) until M14 declares
  profiles.

## Alternatives rejected

A TTL cache of the closure; B23's incremental `stream_projection_summary`; dropping get's projection block; a
universe-of-1 EXACT for get (D-A). M13 writing the dormant highwaters (D-B). Tool-local total fields;
`total = returned`; `total = Qdrant count` (D-C).

## References

Module design note M13 §1, §4 D1–D3 and D5–D8, §5, §7, §8, §9, §10, §12, §14; Baseline §9, §15.5, §22.0, §22.1,
§22.2, §23.1②, §23.1④, §23.3, §25.3.1, §33.5, §57.1, §78.1, §80.1; ADR-0041 D-D; ADR-0057; ADR-0078 D-D;
`contracts/mcp/memory.output.schema.json`; research B23, B17, N09.
