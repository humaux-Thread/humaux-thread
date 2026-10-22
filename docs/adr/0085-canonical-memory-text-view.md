# ADR-0085 — Canonical Memory text: one view, `private.memory_text_v` (text once, step 1)

- Status: Accepted (card M07-2, 2026-10-22). Content authority: module design note M07 (§2, §6 D1, §8 G-M07-3), a
  private document kept outside this repository; the design lead decided it for wave B. This ADR is the home of D1 in
  the repository; card M07-3 (the writer stops duplicating) cites it and completes the amendment of ADR-0067 D-E.
- Relates to: Baseline §8.2 (Event payload is raw and immutable), §8.5 (Memory), §46, §80.1; ADR-0067 D-B, D-E (the note
  lane's content shape); ADR-0078 D-D (0255, the `security_invoker` view precedent); ADR-0082.

## Context

- An identity note's text is stored twice: raw in `private.events.payload` (a JSON string, §8.2, immutable) and again as
  `private.memory_records.content ->> 'key_claim'` (ADR-0067 D-E: "the body is `key_claim`, byte for byte"), with a
  `title` beside it.
- Readers take the text from `content` in many places: `grep_repo` (SQL), `projection_worker` and the card builder
  (Rust), `projection.note_chunk_count` and `projection.stream_point_ledger` (0240, SQL). Each reads `key_claim`, so
  removing the duplicate means changing every reader at once.
- Card order in the wave-B plan removes that coupling: a view first (this card, no reader changes), then each reader
  switches in its own module's card, then the writer stops duplicating (M07-3).

## Decisions

### D-A  `private.memory_text_v (tenant_id, memory_id, title, body)` is the one place text is resolved
Migration 0259, `security_invoker = true`, owner `role_migration_owner`, over `memory_records` LEFT JOIN
`identity_note_materializations` (tenant, output memory) LEFT JOIN `events` (by `event_id`):

- `title` is `content ->> 'title'`.
- `body` of a Memory with an identity contract is its Evidence's `payload #>> '{}'` when the payload is a JSON string,
  else NULL. There is no fallback to `key_claim` on that branch: an identity note whose Evidence the caller cannot read
  reads NULL, never a second copy of the text.
- `body` of any other Memory is `content ->> 'key_claim'` (distilled, confirmed and corrected Memories).

Until M07-3 the writer stores a `key_claim` equal to the payload text, so both branches agree for every existing row.
The view carries no derived-title rule; the fallback for a stripped title belongs to the writer change (M07-3).

### D-B  Access is the invoker's, SELECT only, two roles
`security_invoker` gives a reader exactly the privileges and RLS of the three tables under its own role; a Memory the
caller cannot read is absent from the view. SELECT is granted to `role_gateway` and `role_private_worker`, the two
runtime roles that already read all three tables; no other role, no write privilege, nothing for PUBLIC. A reader card
that needs another role extends the grant in its own migration after the table grants are confirmed. `rls-check` carries
the two cells; absence is "no grant".

### D-C  The Rust accessor is `memory_repo::memory_texts_in_txn`
`(txn, tenant_id, &[memory_id]) -> Vec<MemoryText { memory_id, title: Option<String>, body: Option<String> }>`, ordered
by `memory_id`, no query for an empty slice. It lives in `memory_repo` because that module is the Memory door and the
view's Rust half. SQL readers join the view; Rust readers call the accessor. Neither this card nor the accessor changes
an existing reader.

### D-D  What this card does not do
No reader is switched and the writer is unchanged (the amendment of ADR-0067 D-E, "identity notes keep no
`key_claim`", takes effect with M07-3, which also carries the sentinel that counts direct `key_claim` reads, G-M07-4,
and the Baseline text). No compression change. The M07-3 migration replaces the view only by `CREATE OR REPLACE` with the
same column list.

## Gates (§80.1: each exists only after inject, red, fix, green on CI)

| gate | location | injected fault | expected red |
|---|---|---|---|
| G-M07-3, view half | `crates/adapters/tests/note_text_once.rs::g_m07_3_the_view_resolves_identity_and_legacy_text_alike` | the view returns the title as the body of a non-identity Memory (`ELSE m.content ->> 'title'`) | the legacy twin reads its title instead of the rewritten `key_claim` (`note_text_once.rs:268`, `left == right`) |

The test writes two notes through the real `memory.note_put` transaction, reads them through the accessor as
`role_gateway` with the member's RLS context, then reshapes them as the owner: the identity note loses its `key_claim`
(the shape M07-3 writes) and must still read its payload byte for byte; the other loses its identity contract and gets a
`key_claim` that differs from its payload, and must read the `key_claim`. A view that read only `key_claim`, only the
payload, or the title fails one of the three reads.

Red record: `red/m07-2-r1` (this branch plus the single mutation above, deleted after recording), targeted run 39811915711: FAILED on `note_text_once.rs:268`, the legacy twin's body assertion (left: its title, right: the rewritten `key_claim`), not on setup. Green: the PR's CI on the unmutated branch.

## Consequences

- Positive: the text has one resolver before any reader moves; M07-3 can strip the duplicate (about the body size per note)
  without a flag day; readers switch one module at a time.
- Cost: one extra PK probe per identity note in a page. `ponytail:` the `events` lookup is by `event_id` alone (the
  partition key `recorded_at` is not on the contract), so it probes each monthly leaf; add `recorded_at` to the contract if
  a 200-row page ever shows it.
- The view is read-only plumbing: no row, grant or policy of an existing table changes.

## Rejected

- A generated or maintained `body` column on `memory_records`: a third copy, and it would have to be rewritten by M07-3.
- Resolving in Rust (`COALESCE(key_claim, payload)` per reader): SQL readers (`grep`, `note_chunk_count`, the ledger
  function) need the same rule and would each spell it.
- Falling back to `key_claim` when the Evidence is unreadable: it would re-open a second text path for exactly the rows
  M07-3 strips.
