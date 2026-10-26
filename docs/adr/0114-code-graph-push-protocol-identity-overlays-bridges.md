# ADR-0114 — M16 code graph: client-pushed snapshots, verified extraction, bounded reads, and explicit code bridges

- Status: Accepted (2026-10-23). Card M16-1 (docs only, wave D, module M16), ADR-M16-a (this ADR). Content authority:
  module design note M16 (§4 D1–D12, §5–§6, §9–§13); this ADR is the repository home of those decisions and re-decides
  none of them. No code, migration or gate lands with it.
- Authority order (note :5-10): owner (29f37ded → carried into charter v2 829c952f) → lead decision 03b9aca9 →
  spec / ADR-0078 D-B → research B30 §code graph → plan v2 cards 46/47 and R-46 as evidence.
- Amends: Baseline §27 and §27.1–§27.6 (provider fetch / webhook / reconcile becomes client push; identity, overlays,
  completeness denominators, ingestion security) and §33 Tool 7 (operation set v2). Each amended section gets one
  additive pointer paragraph; frozen judge text is not rewritten.
- Relates to: Baseline §4.2, §4.3, §6.1.1, §17.1, §34.0.1, §49, §57.1, §78.1, §78.2, §80.1; ADR-0078 D-B; ADR-0050
  (tri-state gates, a missing DB is a fail); ADR-0066 D-B (parse-sandbox budget line). Cross-module: module design
  notes M17, M18, M19, M28, M29, M12, M10.

## Context

- Five tables exist with 0 writers (`private.{code_snapshots, code_files, code_symbols, code_edges,
  worktree_overlays}`, `0006_private_skeleton.sql` :51–:87): no `commit_sha`, no qualified name, no content hash,
  `edge_kind` free text, edges keyed by symbol ids with single-column FKs, no RLS (note :22-25).
- `contracts/mcp/code.schema.json` declares 9 ops, all `code:manage` / `ordinary1`, with no gateway handler; the domain
  and projection files are 5-line headers, `bins/worker` prints "not wired yet", `parse-sandbox` has a budget line
  only, and no manifest carries tree-sitter (note :27-32).
- ADR-0078 D-B: Repository is not a SubjectKind; key `(provider, platform immutable id)`, URL/path are locators, and
  Project —TARGETS→ Repository is deferred (note :33-34).
- The old system pushed `code_index(files[{path, content}])` with per-file sha256, a call graph in a graph store plus
  `code_entities` with uuid5 ids (new system: UUIDv7, §49), a PageRank repo map, lexical + per-symbol-summary search
  and `code_query`; it dropped inbound edges on incremental re-index and bound a wrong file across projects by
  unqualified name (memories 52317131, 04e4039f, 444a198a, 4aab4ce8, 9b3cd506; note :35-40).
- Gaps: snapshot identity, push protocol and sandboxed extraction, links / search / impact, §27.5 denominators and
  §27.2 freshness, per-run overlays, typed bridges, tenant RLS; provider sync, webhook, reconcile, GitHub App and
  server-side SCIP deferred with reason (note :42-53).

## Decisions

### D-A  The client pushes file contents; the server extracts

One server-side extractor version makes snapshots from 80 agents comparable, and the only client that could extract
locally (M27) is built last; plan v3 keeps the client-push shape of card 46 (note D1, :56-60; owner 829c952f).
Rejected: server git fetch / GitHub App (owner); client-side extraction (unverifiable output, extractor drift);
per-file Evidence rows (code is a rebuildable index; ~3k Evidence + tickets per push break R11 and the stream).

### D-B  Five new tables replace the 0006 skeletons, by forward migration

`code_snapshots`, `code_files`, `code_symbols`, `code_edges`, `code_active_snapshots`. `tenant_id` is in every PK and
every FK is composite — files `(tenant, snapshot_id)`, symbols `(tenant, snapshot_id, file_id)`, edges
`(tenant, snapshot_id, from_symbol_id)` and `(tenant, snapshot_id, to_symbol_id)` — so an edge cannot join two
snapshots. FORCE RLS: tenant predicate AND repository visible (workspace scope of `control.repositories`).
`worktree_overlays` is retired (D-H). Closed sets are CHECK **and** Rust enum (§78.2): `edge_kind` = §27's six,
`evidence_level` {syntax_candidate, semantic_resolved, runtime_observed}, kind {COMMIT, WORKTREE}, state
{BUILDING, READY, FAILED, EXPIRED} (note D2, :61-68; lead 03b9aca9).

### D-C  Snapshot identity is one canonical digest

`identity_sha256` covers repository_id, kind, commit_sha (NULL for a never-committed tree), dirty_tree_sha256,
target_key (triple + sorted features), lockfile_sha256, generated_code_sha256 (client-declared generated paths +
hashes), tree_sitter_version, grammar_set (sorted lang=version) and extractor_version (query-set version). Client
fields are ClientDeclared claims; the last three are server-set. `UNIQUE (tenant, repository_id, identity_sha256)`
over BUILDING|READY makes a re-push return the existing snapshot; an extractor upgrade re-extracts stored content into
a new snapshot without a re-push (note D3, :69-75; lead).

### D-D  Push → verify → atomic publish

`index` is one op with a `phase` field. `begin{repository_id, kind, base_snapshot_id?, identity fields,
manifest[{path, sha256, size}], manifest_sha256, idempotency_key}` → BUILDING + `needed[sha256]`, looked up only in the
caller's own repository (never a cross-tenant or cross-repository hash oracle; note :78-79). `put{snapshot_id, files}`
in batches ≤ config bytes, server re-hashes every file, content stored once per (tenant, repository, sha256) through
M17's ObjectStore. `commit{snapshot_id}` enqueues extraction. Verify: manifest_sha256 recomputed; every entry has
content with its hash; expected = received; parsed + unsupported + poison = expected; symbol/edge counts written =
counts emitted. Publish in ONE transaction: READY plus `UPDATE code_active_snapshots SET snapshot_id = $new,
generation = generation + 1 WHERE … AND generation = $expected`, rows must be 1, else FAILED with reason and the
active row untouched. BUILDING/FAILED snapshots are never readable by query ops, which read through the active row.
Idempotency uses §34.0.1 receipts (note D4, :76-86).

### D-E  Extraction runs in the §4.3 sandbox, tree-sitter, syntax only

Job host is the existing `humaux-worker` (§4.2); each job spawns `humaux-worker parse-sandbox` (M17 runner, C-M17-3)
with CBOR frames. Languages v1: Rust, Python, TypeScript/TSX, JavaScript, Go (card 46 set), grammars pinned,
definitions/references from tags queries; other files are stored and path-searchable with `parse_state=UNSUPPORTED`,
counted in denominators. Limits are config (§78.1); an over-limit file is POISON (recorded, not retried until
extractor_version changes, §4.3) and the snapshot reports `complete=false`. Resolution is import-scoped name match,
then a unique snapshot-wide name → `syntax_candidate`; ambiguous names stay `to_unresolved_name`, counted, never
force-linked. v1 emits only `syntax_candidate`; other levels arrive with client SCIP / trace uploads and their gates
name them `not_applicable` (note D5, :87-97). Rejected: in-process tree-sitter (C parser on untrusted input in a
resident process, §4.3); pure-Rust per-language parsers (lead binds tree-sitter + grammar versions into identity);
SCIP on the server.

### D-F  Read ops keep legacy parity

`status` = snapshot, freshness {last_indexed_commit_sha, active overlay hash, remote_head = UNKNOWN unless the client
declares it, checked_at} plus §27.5 denominators; `symbol` = exact qualified name → spans, kind, signature, optional
body by ranged read (max_answer_chars cap); `search` = exact → prefix → identifier-token match (GIN on split
camel/snake tokens), ≥ 2 chars, limit ≤ 100; `repo_map` = query-time personalized power-iteration PageRank over the
file graph (IMPORTS/REFERENCES candidates; 20 iterations, damping 0.85, config), token budget by binary search, stable
tie order, cached in M12 by (snapshot, focus, budget, algorithm version) (note D6, :98-105). Rejected: per-symbol LLM
summaries (paid BYOK output nobody asked for; M15 budget rules); petgraph in core (~40 lines of power iteration
suffice; M28 is cloud).

### D-G  Impact and call chain are a bounded BFS over one fixed snapshot

One `REPEATABLE READ READ ONLY` transaction, one batched query per layer (never N+1), `SET LOCAL statement_timeout`
from the remaining budget per statement. Caps (config): depth ≤ 4 (request ≤ 8), ≤ 32 neighbours per expansion,
≤ 256 nodes, ≤ 768 edges, ≤ 75 ms wall; `visited(node)` is separate from state. Result `{nodes, edges(kind, level),
unresolved_count, complete, truncation_reason, layers_scanned}`; truncated is never "full impact";
`min_evidence_level` filters. `history` = the retained snapshots in which a qualified name existed with its content
hash; `complete=false` once older ones were purged (note D7, :106-112; lead, B30). Rejected: recursive CTE (outer LIMIT
does not bound recursion, PG 18 docs); whole graph in memory.

### D-H  Overlays are WORKTREE snapshots, one view per run

`base_snapshot_id` (READY COMMIT of the same repository, composite FK), `run_id`/`task_id` (FK
`coord.task_runs`/`coord.tasks`, M18) — this is the task bridge. Unchanged files are copied from the base inside SQL;
resolution re-runs over the overlay. `code_active_snapshots` PK (tenant, repository_id, run_id NULLS NOT DISTINCT),
NULL = main line, so each run has its own view and agents never overwrite each other. TTL `expires_at` (config, start
24 h); ≤ N live overlays per repository (config, start 8) else POLICY_OVERFLOW — never evict another run's overlay.
`clear_overlay` expires the caller's run overlay; `submit_overlay` = `index` kind WORKTREE (note D8, :113-120).
`ponytail:` full row copy per overlay; upgrade = content-addressed per-file extraction shared across snapshots when
X-M16-1 shows overlay bytes over budget.

### D-I  Bridges are typed, explicit and have real FKs

(a) `code_memory_links(tenant, link_id, memory_id, repository_id, path, qualified_name NULL,
content_sha256_at_link, snapshot_id_at_link, created_by)`: the anchor is resolved exactly in the ACTIVE snapshot; 0 →
NOT_FOUND, > 1 → AMBIGUOUS with candidates, never the first (old-system wrong-file lesson, memory 4aab4ce8).
Staleness is computed at read (current hash ≠ hash at link), never stored, never dropped; RLS = memory visible (M08)
AND repository visible. (b) `code_subject_bridges` = C-M28-3 shape (tenant, snapshot_id ACTIVE at creation, file_id |
symbol_id, subject_id, rule@ver, evidence_level); first rule: Cargo.lock packages → SOFTWARE subjects keyed PURL via
`ensure_subject_by_key_in_txn` (C-M28-4), pull-based with M28-4/M28-16. (c) task = D-H FKs. (d) project: ADR-0078's
deferred Project —TARGETS→ Repository becomes a relation-kernel pair (guest M29, ADR-0078 D-B amendment), one home
for project relations (note D9, :121-130). Rejected: one polymorphic bridge table (no FK); links keyed by snapshot or
symbol id (die on re-index); links by bare symbol name.

### D-J  Repository identity is a provider key, not a URL

`control.repositories` gains `provider` {CLIENT, LEGACY_PROJECT} (GITHUB later) and `external_id` with UNIQUE
(tenant, provider, external_id); CLIENT = a client-minted UUID the client persists, LEGACY_PROJECT = the old
`project_id` for the M25 facade. `register_repository` is idempotent by key (INSERT … ON CONFLICT DO NOTHING
RETURNING, then re-select); `repository_url` becomes an optional locator. `sync` stays declared-only (no provider);
`repository_connections` untouched (deferred, provider-side) (note D10, :131-135; ADR-0078 D-B).

### D-K  Retention runs through one purge door

Keep active + previous READY per view (K = 2, config), live overlays, FAILED ≤ 7 d. SECURITY DEFINER
`control.purge_code_snapshots(tenant, repository)` with EXECUTE to `role_maintenance` only (M19 D3 pattern); content
objects unreferenced by any retained snapshot are deleted after a grace period. All code tables enter M19's purge
catalog as PURGE. Links survive re-index because anchors are path + qualified name (note D11, :136-139).

### D-L  Dense code search stays conditional

The owner's "embed all content" (2026-10-22) removes any privacy objection; the card waits only on measured quality
lift and R11 bytes (`code_v1` family, M10 generation spec) (note D12, :140-141). Not decided here; see X-M16-2.

## Contracts and owned data

Produced (note §5, :143-153): **C-M16-1** `code.*` ops v2 (register_repository by key, index begin/put/commit,
submit/clear_overlay, status, symbol, search, repo_map, impact, history, link_memory) with the manifest fingerprint;
**C-M16-2** freshness envelope + §27.5 denominators → M14 CODE/TESTS facets and M13 census; **C-M16-3** bridge rows
(implements C-M28-3) → M28; **C-M16-4** bounded-traversal result protocol offered to M28-13 (M28 owner decides);
**C-M16-5** purge catalog rows + purge door → M19. Consumed: M17 C-M17-2 ObjectStore and C-M17-3 runner; M18
`coord.task_runs`/`tasks`; M29 kernel (guest); M28 C-M28-4 subject door; M08 `can_read`; M12 cache; M04 metering
(`ordinary1`); M01 config registry; §34.0.1 receipts.

Owned (note §6, :155-160): `control.repositories`, `control.repository_connections` (unchanged), and
`private.{code_snapshots, code_files, code_symbols, code_edges, code_active_snapshots, code_memory_links,
code_subject_bridges}`; object prefix `code/<tenant>/<repository>/`. Retires `private.worktree_overlays`. Reads only:
`coord.task_runs`/`tasks`, `private.memory_records`, `private.subjects` (FKs). Layer L5, core edition; may depend on
M01, M04, M08, M12, M17, M18, M29; never on M28 crates (cloud) or M10/M11 until D-L.

## Consequences

- Positive: one digest, one verified publish and one active-row CAS per snapshot; queries read one fixed snapshot;
  each run's overlay is isolated; links are exact anchors that survive re-index; code never becomes a second Memory
  authority.
- Cost: content dedup and object lifetime belong to M17; extraction is serial per node; K, TTL, caps and PageRank
  parameters are config that X-M16-1/X-M16-3 must measure; the purge door is a new owner function.
- Neutral for this card: docs only; no table, migration, contract, gate or config key changes.

Asks M17: ObjectStore content once per (tenant, repository, sha256), the C-M17-3 sandbox runner, and deletion of
unreferenced objects (note :81, :137-138, :149-151). Asks M18: `coord.task_runs`/`tasks` FKs and the final `run_id`
shape (note :114, :158, :217). Asks M19: code tables in the purge catalog and the purge-door pattern (note :138-139,
:149-150). Asks M28: C-M28-3 shape, C-M28-4 subject door, C-M16-4 reuse if M28-13 wants it (note :125-127, :148-149).
Asks M29: the Project —TARGETS→ Repository kernel pair and ADR-0078 D-B amendment via guest M16-13 (note :127-129,
:184). Asks M14/M13: consume C-M16-2 (note :147). Asks M12: cache repo_map by (snapshot, focus, budget, algorithm
version) (note :103-104). Asks M10: the `code_v1` generation spec and X-M16-2 before any dense leg (note :140-141,
:184).

## Maintenance notes (note §13, :228-234)

`//!` headers on every new file (responsibility · Depends-on · Called-by · Invariants · Spec); `code_repo.rs` states
"sole writer of code tables; publish = one txn with the generation CAS (G-M16-1)". Caps/TTL/K/PageRank parameters
change in the config registry; a language addition bumps `extractor_version` (new identity) and this ADR's language
row; an edge-kind or level change touches enum + CHECK + contract test + this ADR. Runbook sections owned: "snapshot
FAILED triage", "overlay cap hit", "re-extract after extractor upgrade".

## Gates

Planned, implementer-owned, tri-state (§57.1); none exists yet. A missing `HUMAUX_TEST_PG_DSN` is a fail in CI, never
`not_applicable` (ADR-0050).

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

Owner questions: none — client push is decided and provider sync is deferred under that decision (note §12, :222).
Red lines: none in M16 cards (no money, no live keys); a future GitHub App needs live keys and is out of scope
(note :222-223).

## Open research

- **R1** current `tree-sitter` Rust crate and grammar crates (Rust, Python, TypeScript/TSX, JavaScript, Go): compatible
  versions/ABI, licences, aarch64 build, and whether each ships a usable `tags.scm`; fallback: pin the last pairing
  that builds in CI (note U1, :213, :224-226).
- **R2** = M17 R3, sandbox network isolation on the target (note :226).
- **X-M16-1** extraction on this repo + 2 polyglot repos: CPU s, peak RSS vs 512 MiB, rows and bytes per snapshot and
  overlay; decides M16-9 cap/TTL, M16-11 K and U3 (note :208).
- **X-M16-2** lexical vs lexical + dense on a fixed zh/en query set: hit@5, MRR, bytes per point; gates M16-14
  (note :209).
- **X-M16-3** 80-agent overlay churn: overlay create p95, lock waits on the active row, bytes; decides M16-9 config
  (note :210).
- **U1** tree-sitter/grammar ABI on arm64 → R1; fallback as above (note :213).
- **U2** sandbox network isolation inside Compose → M17 U2; fallback per M17 (note :214).
- **U3** sandbox memory: sizing line 512 MiB vs §4.3 `RLIMIT_AS = 1 GiB` → X-M16-1; until then `RLIMIT_AS` 512 MiB
  (the tighter value), POISON above it (note :215-216).
- **U4** M18 `coord.task_runs` shape when M16-9 lands → overlay `run_id` stays nullable; per-run views wait for it
  (note :217).
- **U5** workspace vs project scoping → workspace (existing column); project via M16-13 only (note :218-219).

## Alternatives rejected

Server git fetch / GitHub App; client-side extraction; per-file Evidence rows; in-process tree-sitter; pure-Rust
per-language parsers; SCIP on the server; per-symbol LLM summaries; petgraph in core; recursive CTE; whole graph in
memory; one polymorphic bridge table; links keyed by snapshot or symbol id; links by bare symbol name. Each is
grounded in its decision above (note :58-60, :96-97, :104-105, :112, :129-130).

## References

- Module design note M16 (§1–§13), especially :5-10 (authority), :56-141 (D1–D12), :143-160 (contracts, owned data),
  :162-167 (budget), :169-203 (cards, gates), :205-219 (experiments, UNKNOWNs), :221-234 (owner questions, research,
  maintenance); card row M16-1 at :172.
- Baseline §27, §27.1–§27.6, §4.2, §4.3, §6.1.1, §17.1, §33 Tool 7, §34.0.1, §49, §57.1, §78.1, §78.2, §80.1.
- ADR-0078 D-B (repository identity, deferred project target), ADR-0050 (gate truth), ADR-0066 D-B (parse-sandbox).
- Research B30 §code graph; plan v2 cards 46/47 and R-46 (batch 3) as evidence.
