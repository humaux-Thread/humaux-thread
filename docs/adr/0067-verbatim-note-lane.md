# ADR-0067 — Verbatim note lane: `memory.note_put`, note lineage, note_kind, history reads

- Status: Accepted (2026-10-13). Card 40 of `docs/ops/delivery_plan_v2.md`, implemented in three slices, one PR each:
  40a write path (D-A–D-F, D-I), 40b reads (D-G, D-H), 40c replacement (D-J). Research: web-GPT batch 2 (R-40,
  2026-09-26) re-checked against the code at main 17c5895 in batch 9 (2026-10-13, ChatGPT Pro, 10 conflicts; TW
  `research_gpt_batch9_20261013.md`); this ADR is the main line's adjudication and wins over both.
- Supersedes for card 40: R-40's "extend `remember.put` to return a synchronous Memory", "lesson/note → FACT", the
  DB column name `claim_type`, and "the gateway waits for the worker"; the delivery-plan amendment "single write path
  through the outbox, gateway-side insert rejected" (reinterpreted in D-A).

## Context

Card 40 delivers the legacy `memory_store` semantics: an agent stores a note verbatim and gets its `memory_id` back
in the same call; `enumerate` filters by note kind, status and time; `get` returns title, provenance and
`superseded_by`. The code map of main 17c5895 found ten collisions with the R-40 ruling:

1. `remember.put` returns `{evidence_id, processing_handle, consistency_token, status:"accepted"}`; Memory is made
   later by the private worker's LLM distill (`distill_repo::insert_memory`), and §15.5 / §34 say put never returns a
   `memory_id` (`accepted` ≠ a Memory exists).
2. The 0164 trigger turns every `EVIDENCE_ACCEPTED` outbox row into a `DERIVED_DISTILL` job (4 provider slots,
   tenant scheduler, budget gate 0196, automation policy) — no event_kind filter.
3. `remember.put` has no requested authority; its origin is fixed `AuthenticatedAgent` (ceiling PrivateKnowledge).
4. `memory_type` already has `LESSON` and `NOTE`; the generated `facet` (ADR-0045 D-B) has 4 values and cannot carry
   a 9-value classification; §9 already uses "claim_type" loosely for `memory_type`.
5. `enumerate` and the exact census share `ACTIVE_FINAL` (active, not superseded, not archived); §9 makes
   `occurred_at` the only since/until basis; there is no project column.
6. `memory.get` returns NotFound for a superseded id and carries no title / provenance / `superseded_by`.
7. Memory content is `{title, key_claim}`; the Evidence `payload_sha256` is over the raw JSON bytes of `content`.
8. There is no client id or revision; a version is a new `memory_id` + supersede, and supersede / correct are
   confirm-gated (ADR-0018).
9. §8.5 asks independent facts to be split into several MemoryRecords.
10. Extending `remember.put` vs a new op key (wired list, `SUPPORTED_OPERATION_KEYS`, the architecture gate).

## Decisions

### D-A — A new op `memory.note_put`; the gateway materialises the note in one PG transaction

`remember.put` is unchanged (Evidence intake; `accepted` does not imply a Memory). The new op
`memory.note_put` stores a note and answers `status:"stored"` with the real `memory_id` only after one PostgreSQL
transaction committed all of: the idempotency receipt, a `MANUAL_NOTE` Evidence (origin `AuthenticatedAgent`, fixed
by the server), the identity contract (D-B), the authorised Memory and its PRIMARY `memory_evidence` link, the note
head (D-J), the stream / outbox / projection events, and the locally signed consistency token. Indexing (embedding,
Qdrant) follows the commit through the existing outbox and is reported as `indexing:"scheduled"`, never awaited.

"Single write path" means one authority policy, one candidate type, one persistence function
(`distill_repo::insert_memory` and its link invariants) and the same projection events — not one process. The
gateway already inserts Memory for `memory.confirm` (ADR-0026) and `memory.correct`; `role_gateway` holds INSERT on
`private.memory_records`. Nothing in the transaction leaves the PG session (no LLM, embedding, Qdrant or remote
signer), so §34.0.1 holds unchanged.

Rejected: (B) commit Evidence, then wait for a worker job — a second failure/recovery state ("Evidence ok, Memory
pending"), and waiting inside the receipt transaction deadlocks (the worker cannot see uncommitted Evidence);
(C) return a pre-derived `memory_id` with `pending` — names an object that may never exist and does not meet "get
right after store"; extending `remember.put` with a mode flag — one tool with two success contracts.

### D-B — Identity contract: no LLM derivation, exactly one Memory

`private.identity_note_materializations (tenant_id, evidence_id) PK → strategy 'identity_note_v1',
output_memory_id UNIQUE, body_sha256, policy_version` is written in the D-A transaction before the
`EVIDENCE_ACCEPTED` outbox row. The 0164 enqueue trigger creates no `DERIVED_DISTILL` job for an Evidence that has a
contract (audit, stream and projection events still flow — only semantic derivation is skipped), and the private
worker re-checks before any provider reservation. The split is by the persisted contract, never by
`event_kind = 'MANUAL_NOTE'` (that would reinterpret every historic MANUAL_NOTE and `remember.put` itself).
No UNIQUE on `memory_evidence.evidence_id`: ordinary Evidence may still distill into several Memories (§8.5).

### D-C — Requested authority is exact; above the ceiling is refused

`memory.note_put.requested_authority` is an optional closed enum, default `PrivateKnowledge`. The existing
`OriginBoundAuthorityPolicy::authorize` must grant exactly that class for the server-fixed origin, else the call
fails with the business error `AUTHORITY_CEILING_EXCEEDED` (MCP tool error, `isError:true`; requested class, origin,
safe reason) and nothing is stored — no Evidence, Memory, PENDING candidate or accepted outbox row. No inference from
`note_kind`, title or body; no clamp; no detour through `memory.correct` (that would launder the origin to
DirectUserInput). The worker path keeps its PENDING candidates (awaiting user proof, not a granted request).

### D-D — `note_kind`, a closed 9-value column mapped onto `memory_type`

`private.memory_records.note_kind text` (NULL for every non-note Memory) with a CHECK of nine values and a CHECK that
binds it to `memory_type`:

| note_kind | memory_type | facet (generated, unchanged) |
|---|---|---|
| rejected | REJECTION | decisions |
| decision | DECISION | decisions |
| fix | OUTCOME | NULL |
| problem | ISSUE | issues |
| lesson | LESSON | NULL |
| research | NOTE | NULL |
| preference | PREFERENCE | NULL |
| state | STATE | state |
| note | NOTE | NULL |

`fix` = the record of an implemented fix (its result), not a proposal. `note_kind` is the author's classification:
it certifies no truth and decides no authority. The legacy `claim_type` argument is an edge alias of `note_kind` in
the compat facade (card 42); no DB column is named `claim_type`. Rust: a closed `NoteKind` enum in `humaux_domain`
with `memory_type()`; a contract test reconciles enum ↔ DB CHECK ↔ mapping ↔ generated facet.
Rejected: lesson/note → FACT (loses the existing LESSON/NOTE semantics); research → FACT (hypotheses and citations
are not facts) or REFERENCE (not a pointer); fix → PROCEDURE; a writable facet (ADR-0045 D-B).

### D-E — The verbatim body and its digest

The body is the JSON-decoded `content` string, stored unchanged in `content.key_claim` (no trim, no newline or
Unicode normalisation); `content = {"title", "key_claim", "representation":"verbatim_assertion"}`. `title` is the
explicit argument (≤ 1 KiB UTF-8) or the first non-blank line cut to 80 Unicode scalars; an all-blank body gets a
fixed default title; the title never edits the body. `body_sha256 = SHA-256(UTF-8 bytes of the decoded body)` is
computed at the input edge and stored in the identity contract; the Evidence `payload_sha256` keeps its meaning (raw
payload bytes). The 64 KiB limit counts decoded UTF-8 bytes. `U+0000` (refused by jsonb) and unrepresentable input
are refused at the edge, never repaired.

### D-F — §8.5: a bounded exception for identity notes

Independent-fact splitting applies to semantically distilled Memories. An identity note is one verbatim document
record that may hold several statements; they are not separately verified facts, carry no higher authority than
D-C grants, and create no mandatory-context binding. `representation` is set only by `memory.note_put`, never by a
caller. Splitting such a note later is a separate, explicit derivation that never replaces the original.

### D-G — `enumerate` and the census share one parameterised query (40b)

`ACTIVE_FINAL` stays the predicate of current-state reads and recall. `memory.enumerate` and its exact census share
one QuerySpec: authorised scope ∧ not forgotten ∧ statuses ∈ {["active"], ["superseded"], ["active","superseded"]}
∧ archive selection ∧ `note_kind` set ∧ subjects ∧ `occurred_at ∈ [since, until)`. Every parameter (and the query
version) enters `enumeration_fingerprint`; a page and its total come from one snapshot (one statement, or one short
`REPEATABLE READ READ ONLY` transaction). An identity note's `occurred_at` is the server receipt time of that version.
`project` is refused as an unsupported filter (declared limit L-1); `workspace` is an authorisation scope, not a
project.

### D-H — `memory.get` history and provenance (40b)

`include_history` (default false — a superseded id stays NotFound for existing callers). With it, `get` returns the
exact version asked for (no jump to the successor) with `status`, `superseded_by`, `note_id`, `note_kind`,
`content.title`, `content.key_claim` and `provenance {primary_evidence_id, event_kind, origin, derivation_strategy,
asserted_at, authority_class, body_sha256}`; references the caller may not see are omitted. History never bypasses
tombstones or forget; recall keeps `ACTIVE_FINAL`.

### D-I — Zero-LLM and recall evidence

The card's "0 MiniMax ledger rows" is not proof alone. The gate checks, for the notes written: MiniMax ledger delta
0, generative-provider invocations 0, `DERIVED_DISTILL` jobs 0, provider slot / reservation delta 0. "Recall finds
the notes" waits for this write's projection watermark (not an empty queue) with no failed or quarantined related
job; a body longer than the embedding input is chunked deterministically into several points of one Memory, recall
dedupes by `memory_id`, and the PG body is never truncated. Storage quota counts every retained version.

### D-J — Note identity and replacement (40c)

`idempotency_key` names one call, `note_id` one note, `memory_id` one immutable version. `private.note_heads
(tenant_id, note_id) → head_memory_id` (+ the immutable visibility scope) and `memory_records.note_id`. Create: a
fresh key, no `note_id`. Replace: a fresh key + `note_id` + `supersedes` = the expected current `memory_id` (CAS) +
a `confirm_token` (ADR-0018 holds; no author exemption). Under the note-head row lock the old version becomes
`superseded` with `superseded_by` = the new id, then the new version is inserted (deferred FKs, no fake intermediate
status). Same key with a different request → `IDEMPOTENCY_CONFLICT`; a stale `supersedes` → `STALE_NOTE_VERSION`.
The confirm challenge and the final commit are separate receipt phases. A new version does not inherit task-level
context bindings. `memory.correct`, `supersede`, `archive` and forget keep the note head consistent or refuse.

## Acceptance (gates; each must be shown red once before it counts)

40a: G01 a barrier before COMMIT yields no `stored` and no half object in another session; `get` right after the
commit succeeds. G02 a failure injected at each write point leaves nothing behind. G03 COMMIT ok + response lost →
the same key returns the original ids, no second Evidence/Memory. G04 automation OFF, 4 slots busy, LLM budget 0 and
the distill worker stopped → `note_put` still stores. G05 outbox replay → still one Memory, 0 `DERIVED_DISTILL`, 0
reservation, 0 provider calls. G06 a forged second PRIMARY output for a contracted Evidence fails; ordinary
two-memory distill stays green. G07 PrivateKnowledge stored exactly; above-ceiling → `AUTHORITY_CEILING_EXCEEDED` with
zero Memory / candidate / outbox delta. G08 high-authority prose without a request stays PrivateKnowledge. G09 enum ↔
CHECK ↔ mapping ↔ facet drift fails. G10 research and note both NOTE, counted apart. G16 whitespace, CRLF, CJK, emoji,
combining marks, escaped quotes, backslashes and the 64 KiB edge are byte-equal with an independently computed
digest. G17 `"a"` and `"a"` share a digest; different normal forms do not. G18 NUL refused before any Evidence.
G22 a three-statement note → exactly one Memory, no candidates. G23 ordinary distill splitting unchanged. G24 the op
is listed by real MCP `tools/list` and runs through `tools/call`. G25 the `remember.put` schema and response are
unchanged; the new fields are refused there. Fault pair: a rewriting fake provider turns the verbatim gate red; an
echo provider turns the no-provider gate red.
40b: G11 page and total from one snapshot under concurrent writes; joins do not inflate the count. G12 a tampered
cursor is refused. G13 filters use `occurred_at`, not `created_at`. G14 superseded: NotFound by default, readable
with `include_history`, absent from recall. G15 after forget nothing (history, provenance, enumerate, cache, recall)
returns the body or its digest.
40c: G19 concurrent same key → one version; same key, different body → refused. G20 two editors on one old version →
at most one wins, the other `STALE_NOTE_VERSION`. G21 no token / changed body / cross-note token / reused token → all
refused.
Card baseline (real stack): 50 notes (rejected, decision, fix, problem, lesson 6 each; research, preference, state,
note 5 each) → exact per-kind counts; replay (50 active / 0 superseded / 50 kept); one confirmed revision (50/1/51); a
stale revision refused (50/1/51); an above-ceiling note refused (50/1/51).

## Spec text changed (§78.6) — applied with the slice that implements it

- §15.5 / §34: the "no synchronous `memory_id`" rule is per operation — `remember.put` (Evidence intake) keeps it;
  `memory.note_put` answers only after the joint commit of D-A. `event_kind = MANUAL_NOTE` alone changes nothing.
- §34.0.1: clarified — no external network I/O inside the receipt transaction other than its PG session.
- §8.5: the D-F exception.
- §9: the loose "claim_type" wording becomes `memory_type`; `note_kind` defined as in D-D.
- Wired op keys (§34 list checked by `cargo xtask architecture-check`): `memory.note_put`.

## Declared limits

- L-1 No `project` filter until notes carry a real, authorisation-checked continuity-project link (signal: card 42's
  `memory_store(project=…)` fixtures or a continuity-project card).
- L-2 No arbitrary client-chosen `external_id`; a legacy facade `id` resolves only to a returned `note_id`.
- L-3 `body_sha256` of a low-entropy body is enumerable; it is on the forget surface with the body (40b G15).
