# ADR-0114 — M16 code graph: client-pushed snapshots, verified extraction, bounded reads, and explicit code bridges

- Status: Accepted. Card M16-1 (docs only, wave D, module M16), ADR-M16-a (this ADR). Content authority: module design note M16 (§4 D1–D12, §5–§6, §9–§13);
  this ADR is the repository home of those decisions and re-decides none of them. No code, migration or gate lands with it.
- Authority order (note :6-10): owner (29f37ded → charter v2 829c952f: client push; 2026-10-22 "finish all modules before go-live" and "embed all content")
  → lead decision 03b9aca9 → spec / ADR-0078 D-B → research B30 §code graph → plan v2 cards 46/47 and R-46 as evidence.
- Amends: Baseline §27 and §33 Tool 7 (note :172); one pointer each (provider fetch / webhook / reconcile deferred; identity, overlays, completeness
  denominators, ingestion security; Tool 7 operation set v2). Frozen judge text is not rewritten.
- Relates to: Baseline §4.2, §4.3, §6.1.1, §17.1, §34.0.1, §49, §57.1, §78.1, §78.2, §80.1; ADR-0078 D-B; ADR-0050 (tri-state gates; no DSN is `not_applicable`, an
  unreachable DSN is a fail); ADR-0066 D-B (parse-sandbox budget line). Cross-module: module design notes M17, M18, M19, M28, M29, M12, M10.

## Context

- Five tables exist with 0 writers (`private.{code_snapshots, code_files, code_symbols, code_edges, worktree_overlays}`, `0006_private_skeleton.sql`
  :51–:87): no `commit_sha`, qualified name or content hash, `edge_kind` free text, single-column symbol FKs, no RLS (note :22-25).
- `contracts/mcp/code.schema.json` declares 9 ops, all `code:manage` / `ordinary1`, with no gateway handler; domain and projection files are 5-line headers,
  `bins/worker` prints "not wired yet", `parse-sandbox` has a budget line only, no manifest carries tree-sitter (note :27-32).
- ADR-0078 D-B: Repository is not a SubjectKind; key `(provider, platform immutable id)`, URL/path are locators, Project —TARGETS→ Repository deferred (note
  :33-34).
- Old system: client-pushed `code_index(files[{path, content}])` with per-file sha256, a graph-store call graph plus `code_entities` with uuid5 ids, a
  PageRank repo map, search and `code_query`; it dropped inbound edges on re-index and bound a wrong file across projects by unqualified name (memories
52317131, 04e4039f, 444a198a, 4aab4ce8; note :35-40). New system: UUIDv7, §49 (memory 9b3cd506; note :36).
- Gaps: snapshot identity, push protocol and sandboxed extraction, links / search / impact, §27.5 denominators and §27.2 freshness, per-run overlays, typed
  bridges, tenant RLS (note :42-51). Deferred: §27.1/§27.2/§27.6 provider, webhook, reconcile, GitHub App — re-open with a provider ADR, audit rows B100,
B101, B105 (note :52-53); SCIP (§27 preferred source) → client-produced upload later (M27) (note :53).

## Decisions
### D-A  The client pushes file contents; the server extracts
One extractor version makes snapshots comparable; the only client that could extract locally (M27) is built last (note D1, :56-60; owner 829c952f).
Rejected: server git fetch / GitHub App (owner); client-side extraction (unverifiable, drift); per-file Evidence rows (~3k per push break R11 and the
stream).
### D-B  Five new tables replace the 0006 skeletons
`code_snapshots`, `code_files`, `code_symbols`, `code_edges`, `code_active_snapshots`; `tenant_id` in every PK and composite FKs (files `(tenant,
snapshot_id)`, symbols `(tenant, snapshot_id, file_id)`, edges `(…, from_symbol_id)` / `(…, to_symbol_id)`). FORCE RLS: tenant predicate AND repository
visible; `worktree_overlays` retires (D-H). Closed sets are CHECK **and** Rust enum (§78.2): `edge_kind` = §27's six, `evidence_level` {syntax_candidate,
semantic_resolved, runtime_observed}, kind {COMMIT, WORKTREE}, state {BUILDING, READY, FAILED, EXPIRED} (note D2, :61-68; lead 03b9aca9).
Amendment (M16-3): every parsed file has one file-scope MODULE symbol; it is the from end of top-level IMPORTS/REFERENCES, so from_symbol_id is NOT NULL.
### D-C  Snapshot identity is one canonical digest
`identity_sha256` covers repository_id, kind, commit_sha (NULL for a never-committed tree), dirty_tree_sha256, target_key (triple + sorted features),
lockfile_sha256, generated_code_sha256 (client-declared paths + hashes), tree_sitter_version, grammar_set (sorted `lang=version`), extractor_version; client
fields are ClientDeclared, the last three server-set. `UNIQUE (tenant, repository_id, identity_sha256)` over BUILDING|READY returns the existing snapshot on
re-push; extractor upgrades re-extract stored content without a re-push (note D3, :69-75; lead).
### D-D  Push → verify → atomic publish
`index` is one op with a `phase` field: `begin` carries identity fields, the manifest and an idempotency key → BUILDING + `needed[sha256]`, looked up only
in the caller's own repository (never a cross-repo hash oracle; note :78-79); `put` batches ≤ config bytes re-hash every file and content is stored once per
(tenant, repository, sha256) via M17's ObjectStore; `commit` enqueues extraction. Verify: manifest_sha256 recomputed; every entry has content with its hash;
expected = received; parsed + unsupported + poison = expected; symbol/edge counts written = emitted. Publish in ONE transaction: READY plus the
`code_active_snapshots` CAS (`generation = generation + 1 WHERE … AND generation = $expected`), rows must be 1, else FAILED with reason and the active row
untouched; BUILDING/FAILED are never readable by query ops. Idempotency uses §34.0.1 receipts (note D4, :76-86).
### D-E  Extraction runs in the §4.3 sandbox, tree-sitter, syntax only
Job host `humaux-worker` (§4.2); each job spawns `humaux-worker parse-sandbox` (M17 runner, C-M17-3). Languages v1: Rust, Python, TypeScript/TSX,
JavaScript, Go (card 46 set), grammars pinned, definitions/references from tags queries; other files are stored and path-searchable with
`parse_state=UNSUPPORTED`. Limits are config (§78.1); an over-limit file is POISON (recorded, not retried until extractor_version changes, §4.3) and the
snapshot reports `complete=false`. Resolution is import-scoped name match, then a unique snapshot-wide name → `syntax_candidate`; ambiguous names stay
`to_unresolved_name`, counted, never force-linked. v1 emits only `syntax_candidate`; other levels arrive with client SCIP / trace uploads and their gates
are `not_applicable` (note D5, :87-97). Rejected: in-process tree-sitter (§4.3); pure-Rust parsers; SCIP on the server.
### D-F  Read ops keep legacy parity
`status` = snapshot, freshness {last_indexed_commit_sha, active overlay hash, remote_head = UNKNOWN unless the client declares it, checked_at} plus §27.5
denominators; `symbol` = exact qualified name → spans, kind, signature, optional body by ranged read (max_answer_chars cap); `search` = exact → prefix →
identifier-token match (GIN on split camel/snake tokens), ≥ 2 chars, limit ≤ 100; `repo_map` = query-time personalized power-iteration PageRank over the
file graph (IMPORTS/REFERENCES candidates; 20 iterations, damping 0.85, config), token budget by binary search, stable tie order, cached in M12 by
(snapshot, focus, budget, algorithm version) (note D6, :98-105). Rejected: per-symbol LLM summaries; petgraph in core.
### D-G  Impact and call chain are a bounded BFS over one fixed snapshot
One `REPEATABLE READ READ ONLY` transaction, one batched query per layer (never N+1), `SET LOCAL statement_timeout` from the remaining budget per statement.
Start caps (config): depth ≤ 4 (request ≤ 8), ≤ 32 neighbours per expansion, ≤ 256 nodes, ≤ 768 edges, ≤ 75 ms wall; `visited(node)` is separate from state.
Result `{nodes, edges(kind, level), unresolved_count, complete, truncation_reason, layers_scanned}`; truncated is never "full impact"; `min_evidence_level`
filters. `history` = retained snapshots in which a qualified name existed with its content hash; `complete=false` once older ones were purged (note D7,
:106-112; lead, B30). Rejected: recursive CTE (outer LIMIT does not bound recursion); whole graph in memory.
### D-H  Overlays are WORKTREE snapshots, one view per run
`base_snapshot_id` (READY COMMIT of the same repository, composite FK), `run_id`/`task_id` (FK `coord.task_runs`/`coord.tasks`, M18) — the task bridge.
Unchanged files are copied from the base inside SQL; resolution re-runs over the overlay. `code_active_snapshots` PK (tenant, repository_id, run_id NULLS
NOT DISTINCT), NULL = main line, so runs never overwrite each other. TTL `expires_at` (config, start 24 h); ≤ N live overlays per repository (config, start
8) else POLICY_OVERFLOW — never evict another run's overlay. `clear_overlay` expires the caller's run overlay; `submit_overlay` = `index` kind WORKTREE
(note D8, :113-120). `ponytail:` full row copy per overlay; upgrade = content-addressed per-file extraction shared across snapshots when X-M16-1 shows
overlay bytes over budget.
### D-I  Bridges are typed, explicit and have real FKs
(a) `code_memory_links(tenant, link_id, memory_id, repository_id, path, qualified_name NULL, content_sha256_at_link, snapshot_id_at_link, created_by)`: the
anchor resolves exactly in the ACTIVE snapshot; 0 → NOT_FOUND, > 1 → AMBIGUOUS with candidates, never the first (memory 4aab4ce8). Staleness is computed at
read (current hash ≠ hash at link), never stored; RLS = memory visible (M08) AND repository visible. (b) `code_subject_bridges` = C-M28-3 shape (tenant,
snapshot_id ACTIVE at creation, file_id | symbol_id, subject_id, rule@ver, evidence_level); first rule: Cargo.lock packages → SOFTWARE subjects keyed PURL
via `ensure_subject_by_key_in_txn` (C-M28-4), pull-based with M28-4/M28-16. (c) task = D-H FKs. (d) project: ADR-0078's deferred Project —TARGETS→
Repository becomes a relation-kernel pair (guest M29, ADR-0078 D-B amendment). Rejected: one polymorphic bridge table (no FK); links keyed by snapshot or
symbol id (die on re-index); links by bare symbol name (note D9, :121-130).
### D-J  Repository identity is a provider key, not a URL
`control.repositories` gains `provider` {CLIENT, LEGACY_PROJECT} (GITHUB later) and `external_id` with UNIQUE (tenant, provider, external_id); CLIENT = a
client-minted UUID the client persists, LEGACY_PROJECT = the old `project_id` for the M25 facade. `register_repository` is idempotent by key (INSERT … ON
CONFLICT DO NOTHING RETURNING, then re-select); `repository_url` becomes an optional locator. `sync` stays declared-only; `repository_connections` untouched
(note D10, :131-135; ADR-0078 D-B).
### D-K  Retention runs through one purge door
Keep active + previous READY per view (K = 2, config), live overlays, FAILED ≤ 7 d. SECURITY DEFINER `control.purge_code_snapshots(tenant, repository)` with
EXECUTE to `role_maintenance` only (M19 D3 pattern); content objects unreferenced by any retained snapshot are deleted after a grace period. All code tables
enter M19's purge catalog as PURGE; links survive re-index because anchors are path + qualified name (note D11, :136-139).
### D-L  Dense code search stays conditional
The owner's "embed all content" (2026-10-22) removes any privacy objection; the card waits only on measured quality lift and R11 bytes (`code_v1` family,
M10 generation spec) (note D12, :140-141). Not decided here; see X-M16-2.

## Contracts and owned data

Produced (note §5, :143-153): **C-M16-1** `code.*` ops v2 (register_repository, index, overlays, status, symbol, search, repo_map, impact, history,
link_memory) with the manifest fingerprint; **C-M16-2** freshness envelope + §27.5 denominators → M14 CODE/TESTS facets and M13 census; **C-M16-3** bridge
rows (implements C-M28-3) → M28; **C-M16-4** bounded-traversal result protocol offered to M28-13 (M28 owner decides); **C-M16-5** purge catalog rows + purge
door → M19. Consumed: M17 C-M17-2 ObjectStore, C-M17-3 runner; M18 `coord.task_runs`/`tasks`; M29 kernel (guest); M28 C-M28-4 subject door; M08 `can_read`;
M12 cache; M04 metering (`ordinary1`); M01 config registry; §34.0.1 receipts.

Owned (note §6, :155-160): `control.repositories`, `control.repository_connections` (unchanged), and `private.{code_snapshots, code_files, code_symbols,
code_edges, code_active_snapshots, code_memory_links, code_subject_bridges}`; object prefix `code/<tenant>/<repository>/`. Retires
`private.worktree_overlays`. Reads only: `coord.task_runs`/`tasks`, `private.memory_records`, `private.subjects` (FKs). Layer L5, core edition; may depend
on M01, M04, M08, M12, M17, M18, M29; never on M28 crates (cloud) or M10/M11 until D-L.

## Consequences

- Positive: one digest, one verified publish and one active-row CAS per snapshot; queries read one fixed snapshot; each run's overlay is isolated; links are
  exact anchors; code never becomes a second Memory authority.
- Cost: content dedup belongs to M17; caps, TTL and K are config that X-M16-1 and X-M16-3 measure (note :208, :210); PageRank
  parameters are config-registry items (note :231).
- Neutral for this card: docs only; no table, migration, contract, gate or config key changes.

Asks M17: ObjectStore content once per (tenant, repository, sha256) and the C-M17-3 sandbox runner (note :81, :151-152). Asks M18: `coord.task_runs`/`tasks`
FKs (note :114, :158). Asks M19: code tables in the purge catalog (note :138-139, :149-150). Asks M28: C-M28-3 shape, C-M28-4 subject door (note :125-127). Offers M28: C-M16-4 for
M28-13 reuse, M28 owner decides (note :148-149). Asks M29: the Project —TARGETS→ Repository kernel pair and ADR-0078 D-B amendment via guest M16-13 (note
:127-129, :184). Asks M12: cache repo_map by (snapshot, focus, budget, algorithm version) (note :103-104). Asks M10: `code_v1` generation spec for
conditional M16-14, after X-M16-2 (note :140-141, :185). Offers M14/M13: C-M16-2 freshness envelope + §27.5 denominators (note :147).

## Maintenance notes (note §13, :228-234)

`//!` headers on every new file (responsibility · Depends-on · Called-by · Invariants · Spec); `code_repo.rs` states "sole writer of code tables; publish =
one txn with the generation CAS (G-M16-1)". Caps/TTL/K/PageRank parameters change in the config registry; a language addition bumps `extractor_version` (new
identity) and this ADR's language row; an edge-kind or level change touches enum + CHECK + contract test + this ADR. Two ceilings stand: name-based
resolution only, and repo map computed per request (cached) (note :233). Runbook sections owned: "snapshot FAILED triage", "overlay cap hit", "re-extract
after extractor upgrade". §7 p95 targets: symbol/search ≤ 50 ms, repo_map ≤ 150 ms cold / cache hit ≤ 10 ms, impact ≤ 75 ms wall (note :167).

## Gates

Planned, tri-state (§57.1); none exists yet. For DB tests a missing `HUMAUX_TEST_PG_DSN` is a fail in CI, never `not_applicable` (note :188; ADR-0050).

| gate | owner card | test file | injected fault | expected red |
|---|---|---|---|---|
| G-M16-1 snapshot integrity | M16-6 | `crates/adapters/tests/code_publish.rs` | skip manifest re-hash; drop the generation CAS | missing/mismatched file still READY; two commits both active |
| G-M16-2 evidence level | M16-6, M16-8, M16-12 | `crates/adapters/tests/code_impact.rs` | label resolver output `semantic_resolved` | `min_evidence_level=semantic_resolved` returns syntax edges |
| G-M16-3 one-snapshot edges | M16-3 | `crates/adapters/tests/code_schema.rs` | replace composite FK by symbol-id FK | edge from snapshot A to a symbol of B accepted |
| G-M16-4 identity | M16-4 | `crates/adapters/tests/code_identity.rs` | drop lockfile/features/extractor from the digest | different builds share a snapshot; same identity makes a second |
| G-M16-5 path and content safety | M16-4 | `bins/gateway/tests/code_push.rs` | accept `..`, absolute, NUL, `\`; skip deny list; skip hash check | traversal path or `.env` stored; mismatched content accepted |
| G-M16-6 BFS budget | M16-8 | `crates/adapters/tests/code_impact.rs` | remove fan-out cap; one session timeout | hub/self-loop/cycle → `complete=true` or > 256 nodes; statement survives the budget |
| G-M16-7 isolation | M16-2, M16-3 | `crates/adapters/tests/code_rls.rs` | tenant-only policy on `code_symbols` | other tenant / other workspace reads rows |
| G-M16-8 sandbox extraction | M16-5 | `bins/worker/tests/code_extract.rs` (Linux CI) | run extractor in-process; lift depth cap | deep-nesting file kills the worker / not POISON; snapshot claims complete |
| G-M16-9 overlay isolation | M16-9 | `crates/adapters/tests/code_overlay.rs` | key views by repository only | run B's overlay replaces run A's; base view changes |
| G-M16-10 link anchors | M16-10 | `crates/adapters/tests/code_links.rs` | take first match; store staleness flag at write | ambiguous name links silently; stale link not flagged after re-index |
| G-M16-11 enum contracts (§78.2) | M16-2 | `crates/adapters/tests/facet_contract.rs` (extend) | add a DB value only | Rust set ≠ CHECK set |
| G-M16-12 repo map budget | M16-7 | `crates/domain/src/code/rank.rs` tests | drop the token check | output over budget / unstable order across runs |
| G-M16-13 purge door scope | M16-11 | `crates/adapters/tests/code_purge.rs` | GRANT DELETE to `role_maintenance`; purge active | runtime DELETE allowed; active snapshot or linked anchor lost |

Each needs its inject → red → fix → green record (§80.1) in the implementing card.

## Owner-gated (listed, not decided)

Owner questions: none — client push is decided and provider sync is deferred under that decision (note §12, :222). Red lines: none in M16 cards (no money,
no live keys); a future GitHub App needs live keys and is out of scope (note :222-223).

## Open research

- **R1** current `tree-sitter` Rust and grammar crates (Rust, Python, TypeScript/TSX, JavaScript, Go): ABI, licences, aarch64 build, usable `tags.scm`;
  fallback: pin the last pairing that builds in CI (note U1, :213, :224-226).
- **R2** = M17 R3, sandbox isolation on the target (note :226).
- **X-M16-1** extraction on this repo + 2 polyglot repos: CPU s, peak RSS vs 512 MiB, rows/bytes per snapshot and overlay; decides M16-9 cap/TTL, M16-11 K
  and U3 (note :208).
- **X-M16-2** lexical vs lexical + dense on a fixed zh/en query set: hit@5, MRR, bytes per point; gates M16-14 (:209).
- **X-M16-3** 80-agent overlay churn: overlay create p95, lock waits on the active row, bytes; decides M16-9 config (note :210).
- **U1** tree-sitter/grammar ABI on arm64 → R1; fallback as above (note :213).
- **U2** sandbox network isolation inside Compose → M17 U2; fallback per M17 (note :214).
- **U3** sandbox memory: 512 MiB sizing line vs §4.3 `RLIMIT_AS = 1 GiB` → X-M16-1; until then 512 MiB (the tighter value), POISON above it (note :215-216).
- **U4** M18 `coord.task_runs` shape when M16-9 lands → overlay `run_id` stays nullable and per-run views wait for it (note :217).
- **U5** workspace vs project scoping → workspace (existing column); project via M16-13 only (note :218-219).

## References

- Module design note M16 (§1–§13), especially :6-10 (authority), :56-141 (D1–D12), :143-160 (contracts, owned data), :162-167 (budget), :169-203 (cards,
  gates), :205-219 (experiments, UNKNOWNs), :221-234 (owner questions, research, maintenance); card row M16-1 at :172.
- Baseline §27, §27.1–§27.6, §4.2, §4.3, §6.1.1, §17.1, §33 Tool 7, §34.0.1, §49, §57.1, §78.1, §78.2, §80.1.
- ADR-0078 D-B (repository identity, deferred project target), ADR-0050 (gate truth), ADR-0066 D-B (parse-sandbox).

## Red records (§80.1)

M16-2 (migration 0284). Each red is a targeted.yml run on a throwaway branch carrying one mutation; the branches are deleted after recording. Green is the implementing PR's required CI at its current head.

- G-M16-7 red (r1): [40457234614](https://github.com/humaux/humaux-thread/actions/runs/40457234614), mutation `7dfa986042be1e094dbdd192c2662fe509290175`
  makes the `code_files` policy tenant-only. `crates/adapters/tests/code_rls.rs:411` fails: A1 reads six files instead of its two.
- G-M16-11 red (r2): [40457735105](https://github.com/humaux/humaux-thread/actions/runs/40457735105), mutation `25fbf8d7edf43cfe852763eccc12342f0406ca12`
  adds `'ARCHIVED'` to the `code_snapshots` state CHECK only. `crates/adapters/tests/facet_contract.rs:391` fails on the DB/Rust set difference `{ARCHIVED}`.
- G-M16-7 red (r3): [40458365522](https://github.com/humaux/humaux-thread/actions/runs/40458365522), mutation `f86ef5e5f9e5298475af35a06032efcc7390595b`
  keys the `code_files` FK on `snapshot_id` alone. `crates/adapters/tests/code_rls.rs:489` (`expect_err` in `rejected_fk`, reached from the cross-tenant assertion) fails because tenant B's file naming tenant A's snapshot is accepted.
- Green on the unmutated card branch before the PR: [40456029676](https://github.com/humaux/humaux-thread/actions/runs/40456029676) (`code_rls` 3 passed, `facet_contract` 7 passed).
