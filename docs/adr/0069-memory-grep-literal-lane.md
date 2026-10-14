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
- **D-D Visibility and budget.** Candidates are the enumeration scope (tenant + workspace), the census's tombstone
  overlay (`exact_census::NOT_TOMBSTONED`) and the `Lifecycle` selector (`statuses`, `archive`, defaults active and
  not archived), then `context_repo::readable_memory_ids` — the same authorization authority as the census, so there
  is no second visibility predicate. A memory linked to `SECRET_MATERIAL` evidence is neither counted nor shown.
  Everything runs in one `REPEATABLE READ READ ONLY` transaction under the role's statement timeout; a statement
  cancelled by it (`57014`) is `CANNOT_ESTABLISH_COMPLETENESS` — the closed set's "a total we cannot vouch for" —
  never a partial total. No new error variant.
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
  PostgreSQL): totals 3 lines in 2 memories while a peer's private, an archived, a tombstoned and a secret-linked
  memory also contain the word; two keyset pages carry the three hits once; context, the archive axis, the literal
  `%` and the cursor binding; a 1 ms budget over 20 000 rows is `CANNOT_ESTABLISH_COMPLETENESS`.
- `literal_pattern_escapes_every_wildcard`, `query_shape_is_validated`, `context_lines_follow_string_to_array`
  (`adapters::grep_repo`).

## Declared limits

- **Sequential scan.** Without a usable index a grep reads every candidate row of the workspace; the role's
  statement timeout bounds it and an over-budget grep is refused, not approximated. Upgrade signal: a measured p95
  over budget at the target corpus size — then the definer-mediated trigram card.
- **No per-operation concurrency slot.** Greps share the gateway's admission controller (§67.2); a dedicated slot
  waits for a measured need.
- **Per-call snapshot.** Totals and pages are consistent within a call, not across pages.
- **Case profile.** Folding is the database collation's (`İ`/`i`, `ß`/`SS` follow it); the legacy system's exact
  behaviour for those pairs is not reproduced deliberately.
