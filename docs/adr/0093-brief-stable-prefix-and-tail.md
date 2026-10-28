# ADR-0093 — Context brief: one stable prefix and one variable tail

- Status: Accepted (2026-10-23). Card M14-1 (docs only). Content authority: module design M14 §4 D1 and §5; the owner
  accepted the lead's defaults on 2026-10-22. The code lands in M14-3a (pure assembly) and M14-3b (read port and op);
  until then every sentence about behaviour below is **planned**.
- Relates to: Baseline §25.3.1 (project continuity), §25.4 (Mandatory context lane), §57.1 (three-state gates), §78.1
  (no hard-coded business config), §78.6; ADR-0078 D-H (the access layer); ADR-0080 D-D (experience list); ADR-0083 and
  ADR-0084 (retrieval read only); design notes M13 (totals and freshness), M18 (task/lease read port), M26
  (`brief.get`), M27 (session hooks).

## Context

- `context.assemble` is wired: `adapters::context_repo::assemble_materialized`,
  `probe_selectors` and `task_obligation_report`; `retrieval::compiler::compile` keeps Mandatory and Pinned items out
  of semantic eviction; `gateway::context` serves the op; `contracts/mcp/context.schema.json` has one op
  (`workspace_id, task_id, query, limit`). Nothing returns a brief.
- `continuity.get` is wired as one `REPEATABLE READ READ ONLY` transaction over the facet slots and versions, with the
  deterministic handoff byte domain (`retrieval::handoff`, `canonical_bytes`). The facet tables are append-only and the
  slot is a compare-and-swap pointer (0136/0137).
- The prefix's GOAL / CONSTRAINTS / REJECTIONS section reads current facet versions. Until ADR-0094's publish door has
  a caller (audit B89), those facets are `MISSING` in production; the brief must report that, not omit the section.
- A host prompt cache matches on a stable prefix. A brief whose prefix moves on every read earns no cache benefit and
  hides which input changed.

## Decision

### D-A Shape: fixed sections, fixed order (M14 D1)

- **Prefix**: protocol version; the user's pinned and Mandatory rules; project GOAL, CONSTRAINTS and REJECTIONS as the
  exact current facet version id plus body; active prevention rules (at most 8).
- **Tail**: CURRENT_STATE and NEXT_ACTIONS; the caller's active tasks; the last hand-off; the coverage line (M13
  `FACET_COMPLETE` plus freshness); experience-list items; reuse suggestions (at most 5).
- A section whose owner is not delivered prints `not_applicable` and names the missing object (§57.1) — for example the
  task section until M18 publishes its task/lease read port (M14 U3).

### D-B Byte identity of the prefix

- The prefix is built in the fixed order above from canonical bytes, on the handoff pattern: no clock, no scores, no
  `HashMap` iteration order, no request ids.
- The result carries `prefix_sha256`. The prefix changes only when one of its inputs changes; equal inputs at the same
  snapshot produce equal bytes (§25.3.1's single-snapshot contract).
- One `REPEATABLE READ READ ONLY` snapshot serves the whole brief, so the prefix and the tail cannot straddle a commit.

### D-C Budget honesty

- The token cap and the prefix share are configuration entries read by the registry, never caller input and never a
  literal (§78.1). Start values: 1,000 tokens and a 60 % prefix share (the proposal B21 records; unmeasured — E-M14-1
  measures them).
- Overflow is reported, not silent: omitted items are counted per section and `truncated` is set. A Mandatory rule is
  never silently evicted; if the Mandatory set cannot fit, the answer is `cannot_establish` (§25.4), never a smaller
  brief that looks complete.
- The budget check is three-state: a missing budget input fails in CI and is `not_applicable` (naming the object) only
  while the object does not exist.

### D-D One command, deterministic project resolution (M14 D7)

- Explicit `project_id`, validated as an A1 identity, wins. Otherwise the project comes from the task run's CONTAINS
  mapping at `now` (A3, ADR-0078 D-D). Otherwise the brief is user-level and marked `project_unresolved`.
- Rejected: create-on-first-use from a repository or cwd fingerprint (keys are deferred in ADR-0078), and "most recent
  project" (N09 R3). Both guess identity, which N09 R1–R3 forbid.

### D-E Surface

- The op is `context.brief`, added by M14-3b. M26 maps its `brief.get` onto the same command and M27's session hooks
  read it; there is one brief builder (`retrieval::brief`) and one command, and no second assembly path.
- The command is read-only: it writes no facet, no snapshot and no cache row.

## Rejected (from M14 D1)

- One unsplit blob: no stable region for a host prompt cache, and no way to tell which input moved.
- A server-cached brief: unmeasured, and sharing one cached brief across users risks cross-user content.
- An LLM-curated brief in the open-core build: a generative call inside context assembly; cloud only, not built.

## Gates

| Gate | Planned test file | Injected fault | Expected red |
|---|---|---|---|
| G-M14-3 prefix stability | `crates/retrieval/src/brief.rs` tests and `crates/adapters/tests/brief.rs` | put `updated_at` or `HashMap` order in the prefix | the same snapshot yields different bytes; a NEXT_ACTIONS publish changes `prefix_sha256` |
| G-M14-4 budget honesty | `crates/retrieval/src/brief.rs` tests | drop truncation accounting; let a Mandatory rule be evicted | the omitted count is wrong; a Mandatory rule is missing without `cannot_establish` |

No gate exists in this PR (docs only). Each gate exists when M14-3a / M14-3b land with its §80.1 inject → red → fix →
green record, and that record is added to this ADR.

- §80.1 G-M14-3 (M14-3a pure): targeted run [40677507806](https://github.com/humaux-Thread/humaux-thread/actions/runs/40677507806), mutation `updated_at` derived from NEXT_ACTIONS in the prefix; compiled, then `g_m14_3_prefix_matches_exact_serialization` and `g_m14_3_tail_only_change_keeps_prefix_sha` failed their equality assertions. Green: M14-3a PR CI.
- §80.1 G-M14-4 (M14-3a): targeted run [40678212907](https://github.com/humaux-Thread/humaux-thread/actions/runs/40678212907), mutation `truncated = false`; compiled, then `g_m14_4_omissions_and_mandatory_retention_are_exact`, `g_m14_4_overflow_has_exact_manifest_and_no_partial_output` and `g_m14_4_caps_share_and_validation` failed exact `(omitted, truncated)` assertions. Green: M14-3a PR CI.

## Open numbers and owner-gated items

- No research is open for the brief: the design note records none, and the open items are measurements, not research.
- The cap, the prefix share and the p95 target are **open and measured**: E-M14-1 measures brief
  tokens, p95 and the prefix-unchanged rate across 20 sessions on 5 of the owner's projects (a dev copy); the M11 read
  behind it is bounded at 1,024 ids.
- Owner-gated: none in this ADR. E-M14-1 reads a dev copy of the owner's own library; it writes nothing to production
  and sends no email.

## Consequences

- A host can cache the prefix and identify a change by `prefix_sha256`; the tail stays free to move per turn.
- The prefix is per user and per project; it is never shared across users or tenants.
- No timestamp, score or unordered map may enter the prefix; those are tail data.
