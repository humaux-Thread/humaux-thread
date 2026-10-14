# ADR-0069 — `memory.grep`: a literal line search with true totals, under the census's own visibility

- Status: Accepted (2026-10-14). Card 41 of delivery plan v2 (parity: legacy `memory_grep`).
- Relates to: ADR-0044 (recall narrowed to the semantic lane — grep is a new operation, not a recall mode), ADR-0041
  / §22.1 (exact census in one snapshot), ADR-0067 D-J2 (`Lifecycle` selector), §20.4 (signed cursors), §33.10
  (cursor paging), §52 (closed error set), §78 (role statement timeouts).
- Research: web-GPT batch 2 R-41 (`research_gpt_batch2_20260926.md`), re-checked for this card (below).

## Context

The legacy tool `memory_grep(pattern, limit, layer)` returns every memory whose text contains a literal,
case-insensitively, as the matching lines with one line of context each, a per-memory match count and the true total.
Agents rely on it for identifiers, error strings and quoted phrases that a semantic lane ranks poorly. Thread had no
literal lane: recall is semantic only (ADR-0044) and enumerate filters by structured axes.

## Research check (R-41, verified, not taken on trust)

- **Trigram index under RLS.** R-41 rejects `pg_trgm` because `textlike` / `texticlike` are not `LEAKPROOF`. That
  holds: under row-level security PostgreSQL evaluates a user predicate whose operator is not leakproof only after
  the policy quals, so it cannot become an index condition, and a GIN trigram index would buy nothing for the
  runtime roles. Marking the operators `LEAKPROOF` or granting `BYPASSRLS` would trade the tenant boundary for
  speed; both stay forbidden (§6.2.0). A trigram index can return only behind a definer that applies the
  visibility itself — a follow-up card, conditioned on the measured ceiling below.
- **True total.** A keyset page plus `count(*)` over the same materialized hit set in one `REPEATABLE READ`
  transaction is exact for that snapshot; `COUNT(*) OVER ()` after the keyset would count only the page. Adopted.

## Decisions

- **D-A Operation.** `memory.grep` (tool `memory`, `action: "grep"`, scope `context:read`, `ordinary1` meter) — the
  read gate of `memory.enumerate` (`run_local_read`, the read routes' workspace rule), never a recall mode.
- **D-B Pattern.** One line (a pattern containing `\n` or `\r` is refused), 1–512 scalars, matched by
  `ILIKE '%…%' ESCAPE '!'` with `!`, `%` and `_` escaped (`grep_repo::literal_like_pattern`). Case folding is
  PostgreSQL's `ILIKE` under the database collation; no regex.
- **D-C Text.** The searched text is the text an agent reads back: a bare-string content (the `memory.correct`
  shape) whole, otherwise `title`, `key_claim` and `evidence_excerpt` joined by line breaks (an absent field is
  skipped). Key names, other keys and JSON escaping are never searched. Line numbers and the ±1 context come from that
  same text, split exactly as `string_to_array(text, E'\n')` splits it (a `\r` stays on its line).
- **D-D Visibility and budget.** Candidates are the enumeration scope (tenant + workspace) and the literal over the
  whole text; what a grep may count or show is then exactly what the shared final read gate admits
  (`read_materialize::final_memory_ids_about_in_txn` under the request's `Lifecycle` selection — defaults active and
  not archived): `can_read` over the memory and every backing evidence, revoked/expired never, `SECRET_MATERIAL`
  backing excluded, and a tombstoned evidence on ANY stream excluded — the gate `memory.get` uses, so grep cannot show
  a forgotten memory another read would refuse. (The census's tombstone overlay is scoped to one stream and is a
  counting device; a workspace-less memory forgotten in another workspace would pass it.) Everything runs in one
  `REPEATABLE READ READ ONLY` transaction under the role's statement timeout. A statement of this module cancelled
  by it (`57014`) is `CANNOT_ESTABLISH_COMPLETENESS` — the closed set's "a total we cannot vouch for"; one cancelled
  inside the shared gate keeps that gate's own `DEPENDENCY_UNAVAILABLE`. Either way a refusal, never a partial total.
  No new error variant.
- **D-E Page and cursor.** Hits ordered by `(memory_id, line_no)`; a page is `limit` (1–100, default 50) hits; the
  cursor is the §20.4 signed `Cursor` (enumeration MAC key and TTL) carrying the keyset position (`snapshot_id` =
  the last hit's memory id, `last_ordinal` = its line) and bound to a fingerprint of the pattern, the lifecycle
  selection and the workspace — replayed against anything else it is `INVALID_INPUT`.
- **D-F Response.** `{items[{memory_id, line_no, line, before, after, memory_matching_lines, status, archived}],
  total, total_unit: "matching_lines", total_matching_lines, total_memories, has_more, truncated, next_cursor,
  consistency: "per_call_snapshot"}`. `total` = `total_matching_lines` (the legacy `total`); `truncated` means this
  response did not carry the rest, never "estimate". Each page is its own snapshot: a write between pages can shift
  the totals, which the `consistency` value states.

## Rejected

- **pg_trgm GIN index now** — useless under RLS for the runtime roles (above); a definer-mediated variant waits for a
  measured need.
- **`recall` with `mode=literal`** — recall's envelope, ranking and projection semantics do not fit an exact,
  PostgreSQL-only line search (ADR-0044).
- **Searching `content::text`** — would match key names and JSON escapes and number lines that `memory.get` never
  shows.
- **A server-side snapshot manifest for grep** — a manifest per pattern would store every hit set; keyset paging over
  a per-call snapshot is enough for a literal search, and the response says so.

## Gates

- `native_mcp_memory_grep_counts_pages_and_excludes` (`bins/gateway/tests/mcp_gateway.rs`, real gateway and
  PostgreSQL): totals 3 lines in 2 memories while the word is also in a peer's private memory, a memory whose only
  evidence is a peer's, an archived, a superseded, a secret-linked one, one tombstoned on this stream and a
  workspace-less one tombstoned on another workspace's stream; two keyset pages carry the three hits once; context,
  the archive and status axes, the literal `%` (with a `!`-only decoy) and the cursor binding; a 1 ms budget over
  20 000 rows is `CANNOT_ESTABLISH_COMPLETENESS`.
- `memory_grep_pages_a_large_universe_exactly` (adapter over the real database): 10 000 filler memories plus 42
  holding 137 matching lines — every page of 10 reports 137/42 and the 14 pages carry each hit once in keyset order;
  the case profile pinned (ASCII and Greek fold, CJK matches, `İ` folds to `i`, `ß` does not fold to `SS`); the
  printed `GREP_MEASURE` lines are the latency record for a common word, a rare one and a two-character pattern.
- `literal_pattern_escapes_every_wildcard`, `query_shape_is_validated`, `context_lines_follow_string_to_array`
  (`adapters::grep_repo`).

## Declared limits

- **Sequential scan.** Without a usable index a grep reads every candidate row of the workspace; the role's
  statement timeout bounds it and an over-budget grep is refused, not approximated. CI record (targeted run
  38528237538, 10 043 memories in one workspace, 20 calls each): a rare word p50 229 ms / p95 230 ms; a common word
  (every row) p50 1 539 ms / p95 2 418 ms; a two-character pattern p50 1 537 ms / p95 1 546 ms. The card's bar
  (p95 < 200 ms at 50k) is NOT met. The deployed role timeout is 10 s (`HUMAUX_GATEWAY_PG_STATEMENT_TIMEOUT_MS` in
  `deploy/env/values/gateway.env`), so a common-word grep extrapolates past it near 50k memories and is then refused
  (`CANNOT_ESTABLISH_COMPLETENESS`), never approximated. The floor even for a rare word is the per-row RLS cost on
  `private.memory_records` (the SECURITY DEFINER subject-visibility function and the membership `EXISTS` run for every
  row before any non-leakproof filter) — card 35b's set-based subject visibility, scheduled next — and the common-word
  cost adds the final gate over every candidate. Upgrade path: card 35b, then the definer-mediated trigram card if a
  re-measurement still misses the bar. After card 35b (ADR-0070, targeted run 38536153236, same seed): a common word
  p50 240 ms / p95 243 ms, a rare word 28 / 29 ms, a two-character pattern 240 / 250 ms — the rare word meets the bar
  at 10k; a common word at 50k extrapolates to ~1.2 s, inside the 10 s budget but over the bar (the final gate over
  every candidate), so the trigram card stays conditioned on a production need. The 100k figure is recorded by card 53's soak on the release stack.
- **Budget knob.** Production runs under the role pool's §78 statement timeout; `GrepQuery`'s explicit budget is
  set only by tests (the same refusal path).
- **No per-operation concurrency slot.** Greps share the gateway's admission controller (§67.2); a dedicated slot
  waits for a measured need.
- **Per-call snapshot.** Totals and pages are consistent within a call, not across pages.
- **Case profile.** Folding is the database collation's; the gate pins it as the CI database (the PostgreSQL 18.6
  image's default locale) decides it — `İ` folds to `i`, `ß` does not fold to `SS`, Greek capitals fold — so a
  deployment with another collation must re-run that gate. The legacy system's exact behaviour for those pairs is not
  reproduced deliberately.
