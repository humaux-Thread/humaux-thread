# ADR-0067 — Verbatim note lane: `memory.note_put`, note lineage, note_kind, history reads

- Status: Accepted (2026-10-13). Card 40 of `docs/ops/delivery_plan_v2.md`, implemented in three slices, one PR each:
  40a write path (D-A–D-F, D-I), 40b reads (D-G, D-H), 40c replacement (D-J), 40d long-note chunking (D-I, L-4). Research: web-GPT batch 2 (R-40,
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
The note's `EVIDENCE_ACCEPTED` outbox row is born `DONE` (a BEFORE INSERT trigger: `role_gateway` holds no INSERT on
`ops.outbox.status`), so projection claims the ticket at once and resolves it through `memory_evidence` to the note's
Memory — the existing path recall uses (40a implementation). The note's PRIMARY link enqueues no
`DERIVED_CONSOLIDATE` job either (that job calls the LLM): 0164's consolidate trigger skips a Memory whose
`note_kind` is set. A later ordinary memory in the same domain still triggers a consolidation pass, which may read
notes as inputs.

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

40b as shipped (staged): `memory.enumerate` takes `note_kinds` (1–9 distinct `NoteKind` wire strings) and `since` /
`until` (RFC 3339, `occurred_at ∈ [since, until)`; `since >= until` is `INVALID_INPUT`; a NULL `occurred_at` is outside
every bounded window). The three axes are one text (`exact_census::note_axes`) run by the manifest candidate query
(`$5..$7`), the census candidate statement (`$10..$12`) and the three readout statements (`$11..$13`), every value
bound, never interpolated; the registry path (`exact_enumerate`) binds NULL for all three. They enter
`enumeration_fingerprint` as `kinds sorted+deduped joined by "," : since unix-nanos : until unix-nanos`, appended only
when an axis is set, so a cursor minted under one filter set is refused (`NOT_FOUND`) under another and an unfiltered
manifest keeps its fingerprint. Items of both reads carry `note_kind` when the Memory is a note. The `statuses` axis
and archive selection are deferred to 40c (L-5): both need the shared `ACTIVE_FINAL` census face parameterised
together with the final-body gate, which every current-state read also runs. `project` stays refused by the input
schema's `additionalProperties:false` (L-1).

### D-H — `memory.get` history and provenance (40b)

`include_history` (default false — a superseded id stays NotFound for existing callers). With it, `get` returns the
exact version asked for (no jump to the successor) with `status`, `superseded_by`, `note_id`, `note_kind`,
`content.title`, `content.key_claim` and `provenance {primary_evidence_id, event_kind, origin, derivation_strategy,
asserted_at, authority_class, body_sha256}`; references the caller may not see are omitted. History never bypasses
tombstones or forget; recall keeps `ACTIVE_FINAL`.

40b as shipped: `include_history` threads one lifecycle choice through the shared final gate
(`read_materialize::final_memory_ids_about_in_txn`, `$5`: `(active ∧ superseded_by IS NULL) ∨ ($5 ∧ superseded)`)
and the DirectGet grounding read; every recall / context / enumerate caller passes `false`, so `revoked` / `expired`,
`SECRET_MATERIAL` backing and tombstoned Evidence stay `NOT_FOUND` with history too. With it, the item carries
`status`, `superseded_by` (only when the successor passes `readable_memory_ids` for the caller) and `provenance`
(read in the same RR snapshot under the caller's RLS; Evidence-side fields omitted when the PRIMARY Evidence is not
visible). `derivation_strategy` is the contract's `strategy` for a note and the fixed label `"distill"` (the §16.1
processor kind of the semantic path) for every other Memory — including `memory.correct` / `memory.confirm` versions,
which the label does not distinguish yet. `body_sha256` is lowercase hex, notes only. Without `include_history` the
response is unchanged. `note_id` is not in 40b: the column arrives with D-J (40c).

### D-I — Zero-LLM and recall evidence

The card's "0 MiniMax ledger rows" is not proof alone. The gate checks, for the notes written: MiniMax ledger delta
0, generative-provider invocations 0, `DERIVED_DISTILL` jobs 0, provider slot / reservation delta 0. "Recall finds
the notes" waits for this write's projection watermark (not an empty queue) with no failed or quarantined related
job. Long bodies, staged: in 40a a note is projected through the existing single retrieval card (§18.2 budget, 600
chars), so recall covers the title and the first card budget of the body; `build_card` caps over-long fields before
fitting so a 64 KiB body costs no more than a card-sized one (PR #7 Codex P1). Slice 40d chunks a body longer than the
card deterministically into several points of one Memory with recall deduping by `memory_id` (declared limit L-4 until
then); the PG body is never truncated, and literal full-text search over it is card 41. A `SECRET_MATERIAL` note is
never carded (§18.2): `note_put` answers `indexing:"excluded"` instead of `"scheduled"`. Storage quota counts every
retained version.

### D-J — Note identity and replacement (40c)

`idempotency_key` names one call, `note_id` one note, `memory_id` one immutable version. `private.note_heads
(tenant_id, note_id) → head_memory_id` (+ the immutable visibility scope) and `memory_records.note_id`. Create: a
fresh key, no `note_id`. Replace: a fresh key + `note_id` + `supersedes` = the expected current `memory_id` (CAS) +
a `confirm_token` (ADR-0018 holds; no author exemption). Under the note-head row lock the old version becomes
`superseded` with `superseded_by` = the new id, then the new version is inserted (deferred FKs, no fake intermediate
status). Same key with a different request → `IDEMPOTENCY_CONFLICT`; a stale `supersedes` → `STALE_NOTE_VERSION`.
The confirm challenge and the final commit are separate receipt phases. A new version does not inherit task-level
context bindings. `memory.correct`, `supersede`, `archive` and forget keep the note head consistent or refuse.

### D-J as adjudicated (40c, web-GPT batch 10, 2026-10-13; TW `research_gpt_batch10_20261013.md`) — wins over D-J above

40c ships in two slices: **40c-1** is the replacement loop (below), **40c-2** the history axes (D-J2).

- **Identity.** `memory_records.note_id uuid` = the first version's `memory_id`, with no FK to that root.
  - CHECK `(note_id IS NOT NULL) = (note_kind IS NOT NULL)`.
  - `private.note_heads(tenant_id, note_id, head_memory_id)` is the note's lock anchor.
  - A new version may carry another `note_kind`; no version is ever re-classified in place.
  - Migration 0236 backfills every 40a note as a singleton (`note_id = memory_id`, head = itself). Its precheck aborts if any note row already has a supersession edge in or out (merge ≠ go-live: nothing is deployed).
- **One active version per note** is a DB constraint: `EXCLUDE USING btree (tenant_id WITH =, note_id WITH =) WHERE (status = 'active' AND note_id IS NOT NULL) DEFERRABLE INITIALLY DEFERRED`.
- **Write order** under `SELECT … FOR UPDATE` of the head row:
  1. The CAS: head = `supersedes`, that version active and not archived, and it passes the final read gate, so a tombstoned or secret head is NOT_FOUND.
  2. A new MANUAL_NOTE Evidence.
  3. The new version through the unchanged single `insert_memory`, carrying `note_id`.
  4. The identity contract.
  5. `UPDATE` the old row: `status='superseded'`, `superseded_by` = new, `superseded_at` in one statement (the FK is satisfied immediately).
  6. Head = new.
  7. Outbox and the receipt.

  There is no fake status and no deferred FK; the EXCLUDE is checked at COMMIT.
- **Replacement request.** The same op `memory.note_put` with `note_id` + `supersedes` (+ `confirm_token` on the second call). No scope input: the new version inherits the head's visibility and data class. A create (no `note_id`) is unchanged and needs no token.
- **Confirmation (ADR-0018 extended).**
  - A new `DestructiveOp::MemoryNoteReplace` (target = `supersedes`, no successor).
  - `control.confirm_tokens.request_sha256` binds the replacement intent: H = SHA-256 of a domain-separated (`memory.note_put.replace/v1`), length-prefixed encoding of note_id, supersedes, note_kind, title, body digest, requested_authority and idempotency_key.
  - The consume predicate matches H. Every older consumer requires `request_sha256 IS NULL`, so no other tool can spend a note token.
  - The challenge writes no receipt and costs 0 BMO. It CAS-prechecks: a stale `supersedes` answers STALE_NOTE_VERSION and mints no token.
  - The commit re-checks everything, consumes the token and costs 1 BMO.
- **Idempotency.**
  - One `idempotency_key` names one logical edit across challenge, commit and retries.
  - The commit receipt's fingerprint is H, which is domain-separated from 40a's raw-bytes fingerprint, so the same key on a create and a replace never matches. The same key with another intent → the existing `CONFLICT` (there is no `IDEMPOTENCY_CONFLICT` code).
  - A retry after COMMIT, with or without the token, returns the receipt's result: no consume, no write, no BMO.
  - An expired token is re-challenged with the same key and intent.
- **Errors.** No new `ErrorCode` (§52.1 stays at 18).
  - `STALE_NOTE_VERSION` is a business refusal (`isError`, structured `code`) like `AUTHORITY_CEILING_EXCEEDED`. It carries no head id in 40c-1.
  - An archived or non-active head → `CONFLICT`.
  - Confirmation never raises authority: the commit re-runs the exact-grant check.
  - A new version inherits no task binding, pin or confirmation result.
- **Generic governance on notes.** `memory.correct`, `memory.supersede` (either operand a note) and `memory.restore` are refused with `CONFLICT` before any challenge is minted. `memory.archive`/`unarchive` stay per version and never move the head.
  - Forgetting the head closes the note by derivation: the head no longer passes the final gate, so no replacement can CAS against it and nothing can reopen it.
  - Forgetting an older version leaves the head alone.
  - Ponytail: the closure is derived, not stored; store `head_memory_id = NULL` if a reader ever needs "closed" as a fact.
- **Outputs.** `note_put`, `get` and `enumerate` items carry `note_id` for notes.
- **Rejected:**
  - Receipt-only binding (a token must bind its content on its own).
  - A second idempotency code.
  - Extending the 18 ErrorCodes.
  - Update-then-insert with a deferred self-FK (needs the existing FK altered and immediate triggers that tolerate a future row).
  - An explicit closed state or tombstone trigger (derivation suffices).
  - Auto-forwarding `correct` to a replacement.
  - Fallback to an older version after forgetting the head.

**40c-1 as shipped** (deviations and additions to the list above):

- **Order:** the CAS runs before the BMO reservation. Both happen in one transaction, so a stale refusal writes and bills nothing.
- **Same-key race:** of two simultaneous calls with the same key, the loser gets 40a's receipt try-lock `CONFLICT` and replays on retry. G19 accepts either.
- **Fields a replacement refuses:** `visibility_class`, `data_class`, `subject_ids`, `subject_keys` and `affects`. The token binds only the intent fields, and anything else would ride along unconfirmed.
- **Revoked or expired head:** answers `NOT_FOUND`, because the final gate runs before the active check. An archived head answers `CONFLICT`.
- **MEMORY_LIFECYCLE ticket:** the replacement also issues one retiring the old version, as `memory.correct` does (ADR-0057 D-B). That adds one outbox row and one stream_log row beyond the G28 counts.
- **Lifecycle event (card 40 follow-ups 2, 40c-1 P2-1):** with that ticket the old version gets the `SUPERSEDE` row `memory.supersede` writes to `ops.memory_lifecycle_events` (reason `EXPLICIT_SUPERSEDE`, `replacement_memory_id` = the new version, keyed by the consumed token, naming the retire ticket) and its `lifecycle_head_event_id` stamp, through the same writer. `undo_deadline` stays NULL: `memory.restore` refuses a note (G26).
- **Confirm gate:** gained a pre-mint hook (`run_confirmed_write_checked`). Both the CAS precheck and the generic-governance note refusal run there, before any token is minted.

### D-J2 — History axes (40c-2)

- `memory.enumerate` gets a validated selector, used only by enumerate:
  - `statuses` ∈ {["active"], ["superseded"], ["active","superseded"]} (revoked/expired refused);
  - `archive` ∈ {exclude (default), only, include};
  - `note_id`.

  It runs on the manifest, every census statement and a dedicated enumerate final gate, under one RR snapshot, and all axes go into the cursor fingerprint.
- recall/context keep the non-parameterizable active gate.
- `memory.get` takes `memory_id` XOR `note_id`. `note_id` resolves the head, and there is never a fallback between the two namespaces.
- The version list is `enumerate(note_id, statuses both, archive include)`.
- **Blocking decision before `statuses:["superseded"]` ships:** a superseded version that is later revoked or expired cannot be expressed with one status column. Its own ADR decision is required (GPT batch 10, missed conflict 3).

**D-J2 status decision (2026-10-14, main line; resolves GPT batch 10 missed conflict 3).** On main 8b6e5c3 no code path writes
`revoked` or `expired` to `private.memory_records.status`. The variants exist only in `AuthorityStatus`, its wire maps and
adjudication tests, so the one-column conflict is latent, not live. The rule, chosen fail-closed:

- `revoked` and `expired` are terminal hide-states. No read returns them: not the default gates, not `include_history`,
  not the 40c-2 selector.
- The history selector ranges over `{active, superseded}` only. A request for `revoked` or `expired` is `INVALID_INPUT`.
- A superseded version that some future operation revokes or expires simply leaves history. Nothing re-surfaces it.
- The first operation that writes `revoked` or `expired` must state, in its own ADR, how it treats superseded versions
  and note heads (declared limit L-6).

**40c-2 shape.**

- One typed lifecycle selection replaces the shared final gate's `include_archived` / `include_superseded` booleans:
  statuses ⊆ {active, superseded} (non-empty) × archive ∈ {exclude, only, include}.
  - Recall and context pass the `CURRENT` constant (active, exclude).
  - `get` passes active (+ superseded with `include_history`) and archive `include`.
  - `enumerate` passes the request's selection.
- The selection is one SQL fragment, bound on both §22.1 faces: the manifest candidate query and every census statement.
  The registry path (`exact_enumerate`) keeps `ACTIVE_FINAL`.
- Inputs:
  - `memory.enumerate` gains `statuses` (default `["active"]`), `archive` (default `"exclude"`) and `note_id`.
    All three enter the cursor fingerprint in canonical form. Unfiltered fingerprints stay byte-identical.
  - Enumerate items carry `status` whenever `statuses` was given.
  - `memory.get` takes `memory_id` XOR `note_id`. A `note_id` resolves the head through `note_heads`, then runs the same
    gate. A `memory_id` never falls back to a note, and vice versa.

**40c-2 as shipped.**

- **`Lifecycle` type.** Its fields are private. Values come only from `CURRENT`, `ACTIVE_FINAL` (registry), `for_get` and the validated `for_enumerate`.
  - The recall and context entry points take no lifecycle at all; they hardwire `CURRENT`.
  - Only the enumerate mint and pages, `get`, and the note-head lock accept a selection.
- **Shared SQL fragment.** One fragment, with statuses and archive mode as bound parameters, ANDs onto both faces of the enumerate predicate. `ENUMERATION_PREDICATE` becomes `true`: the archive axis moved into the fragment.
- **Registry path.** It binds `ACTIVE_FINAL`, which is active × archive include, its previous semantics.
- **`get(note_id)`.** It builds its DirectGet plan from the head's `memory_id`.
- **Enumerate items** carry their own `archived` flag when an archive selection admits archived rows.
- **`memory.get` second lifecycle layer (card 40 follow-ups 2).** After the final gate admits the version, `get` re-reads its status in the same RR snapshot, as enumerate's page does: anything but `active` (or `superseded` with `include_history`) is `Internal`, never a body. `Internal`, not `NOT_FOUND`, is the existing answer for a post-gate invariant break here, and it keeps a gate regression visible to the L-6 `NOT_FOUND` gate instead of masking it.
- **`memory_id` XOR `note_id`** is enforced once, by the input schema's `oneOf` (`CanonicalCatalog::validate`, before any handler); the handler only parses the id present.
- **Possible plan cost.** The archive axis is a CASE on a bound parameter, so the planner may stop choosing the `archived_at IS NULL` partial index under generic plans. The scale bar (`enumerate_scale`, ignored tier) is the signal.

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
digest. G17 `"\u0061"` and `"a"` share a digest; different normal forms do not. G18 NUL refused before any Evidence.
G22 a three-statement note → exactly one Memory, no candidates. G23 ordinary distill splitting unchanged. G24 the op
is listed by real MCP `tools/list` and runs through `tools/call`. G25 the `remember.put` schema and response are
unchanged; the new fields are refused there. Fault pair (the two ways an LLM could sneak in): a body rewritten on the way
in turns G16's byte-equality red (CI mutation: trim in `NoteBody`); a provider reached for a note turns the worker gate
`d13` red (it runs the real worker with a call-counting provider; CI mutation: drop the identity-contract re-check) and
G04/G05's job count red (CI mutation: drop 0235's distill skip). Gate tests assert stored rows, never two literals.
40b: G11 page and total from one snapshot under concurrent writes; joins do not inflate the count. G12 a tampered
cursor is refused. G13 filters use `occurred_at`, not `created_at`. G14 superseded: NotFound by default, readable
with `include_history`, absent from recall. G15 after forget nothing (history, provenance, enumerate, cache, recall)
returns the body or its digest.
40c-1 (as adjudicated):
- **G19:** a concurrent same key → one version; the same key with a different intent → `CONFLICT`.
- **G20:** two editors on one old version → exactly one wins, the other `STALE_NOTE_VERSION`. The EXCLUDE keeps one active version per note even if the CAS is bypassed.
- **G21:** no new replacement executes without a valid confirmation. A token presented with a changed body, title, kind or authority, for another note, or under another key → refused, with nothing written. A retry of a committed key returns the stored result without consuming, writing or billing; that is not token reuse.
- **G26:** `memory.correct`, `supersede` and `restore` on a note → `CONFLICT` before any challenge.
- **G27:** a tombstoned head cannot be replaced (NOT_FOUND).
- **G28:** every success adds exactly one Evidence, one Memory, one PRIMARY link, one contract and one BMO, with zero LLM jobs; refusals and replays add none. Follow-ups 2: also exactly one `SUPERSEDE` lifecycle event, which the old version's `lifecycle_head_event_id` names; none on a refusal or a replay.
40c-2:
- **G29:** every `statuses` × `archive` selection returns exactly the owner-computed set on both §22.1 faces (page and census total).
- **G30:** recall and context stay current-only (active, not archived) whatever history exists.
- **G31:** a cursor is bound to its selection (statuses, archive, `note_id`); the default selection keeps its pre-40c-2 fingerprint byte for byte.
- **G32:** `get(note_id)` reads the head; a `memory_id` never falls back to a note nor a `note_id` to a version; a closed head is `NOT_FOUND`, never an older version. Another user's private note answers exactly like an unknown `note_id`.
- **G33:** a tombstone overrides every selection, `include_history` included.
- **L-6:** a `revoked` or `expired` version is in no selection and is not gettable (`NOT_FOUND` by `memory_id` and by `note_id`, with and without history).
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
- L-4 Until slice 40d, recall over a note longer than one retrieval card covers its title and first card budget only
  (signal: card 40's 64 KiB recall fixture, or a note recall miss reported against text past the card budget).
- L-6 No operation writes `revoked`/`expired` to a Memory; the first one must define its effect on superseded versions and
  note heads (D-J2 status decision). Until then history is `{active, superseded}` only.
- L-5 (closed by 40c-2): `memory.enumerate` gained `statuses`/`archive`/`note_id` and `memory.get` a `note_id` selector.
