# ADR-0098 — Ingest source identity, one source-kind classification, and the receipt amendment 1b needs

- Status: Accepted (2026-10-23). Card M06-1a (ADR-M06-a in the M06 design note), the first half of the lead-approved
  split of M06-1. 1a records the identity and applies the classification; the dedupe, the advisory lock,
  `SOURCE_VERSION_CONFLICT` and the receipt-trigger amendment recorded in D3 are card M06-1b.
- Relates to: Baseline §7.5, §8.2, §8.7, §10.1, §34.0.1, §60, §78.2; ADR-0078 (`attribution::SourceKind`, the work axis);
  migration 0114 (`control.check_operation_receipt`); migration 0264 (`private.evidence_sources`).

## Context

- Owner ruling 2026-10-15: all data enters through MCP agents (email threads, chat exports, calendar items,
  conversations). Third-party and emotional content must be USER_PRIVATE and never public, and nothing is shared across
  users, so identity is scoped to one owner user.
- `remember` has no notion of what an Evidence was relayed from. Two agents relaying the same email, or one agent
  relaying it twice, produce independent Evidence, and the caller alone declares `data_class`, `origin_class` and
  visibility (the §7.5 classifier gap).
- `RememberCommand` has 28 struct-literal call sites. A new field would edit all of them, and a second implementation of
  the write path would duplicate the §60 order.

## Decision

D1. **Source identity, never body hash.** The identity of a relayed object is
`(tenant_id, owner_user_id, source_kind, object_key_d16, source_version)`, stored in `private.evidence_sources` with a
UNIQUE over exactly those columns. It excludes the agent, the ingest time and the project. `object_key_d16` and
`thread_key_d16` are the first 16 bytes of the SHA-256 of the raw external key; the raw key is never stored
(`humaux_domain::source::SourceIdentity::new` is where it ends). An absent version is `''`, so the key has no NULL
member; a version is at most 64 characters (CHECK and `SOURCE_VERSION_MAX_CHARS`). The row is one per Evidence
(PK `(tenant_id, evidence_id)`), cascades with its Evidence, and has FORCE RLS on the tenant GUC and on
`owner_user_id = humaux.user_id`.
  - Rejected: body-hash dedupe (two genuine "OK" messages are two Evidence, gate G-M06-3); the agent id in the key
    (two agents relaying one email would not collapse); raw external ids in a uniqueness index (PII).
  - `ponytail:` the digest is unkeyed, so a reader of the table can confirm a guessed key. Upgrade path: a tenant-keyed
    HMAC when M05's key hierarchy exists; that re-keys history and needs its own ADR.

D2. **One classification, by source kind.** `humaux_domain::source::classify_source` is the one `match` that maps an
`IngestSourceKind` to (event kind rule, origin class, data-class floor, visibility rule); every kind has its own arm and
there is no wildcard. The type is named `IngestSourceKind` so it cannot be confused with `attribution::SourceKind`.

| kind | event kind | origin class | data class | visibility |
|---|---|---|---|---|
| AgentNote | caller's | caller's | caller's | caller's (today's rules) |
| EmailMessage, ChatMessage, CalendarItem | `SYSTEM_IMPORT` | `ExternalContent` | join(requested, `SENSITIVE`) | `USER_PRIVATE` only |
| ConversationTurn | `USER_MESSAGE` or `ASSISTANT_MESSAGE` | `AuthenticatedAgent` | caller's | anything but `TENANT_SHARED` |
| LegacyImport | `SYSTEM_IMPORT` | `SystemMigration` | caller's | caller's |

A refused request is `INVALID_INPUT` (`RememberError::Source`), never a silent narrowing, and nothing is written (§8.7:
a relayed email can never become user-authority knowledge without a user confirmation). The data class is the lattice
join with the floor, so it is never lowered (§7.5.1). The origin class is stamped by the ingress path, not self-reported.
  - Rejected: a caller-declared data class for third-party kinds (the §7.5 classifier gap); an LLM classifier (no server
    LLM in core).
  - `ponytail:` ConversationTurn's visibility rule ("narrow-only") is read as "never tenant-wide" because the request
    carries no default to narrow from; revisit when M06-2 defines the wire default.

D3. **One implementation path; the receipt-trigger amendment 1b will make.** The sourced entry point
`remember::remember_sourced_in_txn` classifies, calls the unchanged `remember_in_txn`, and inserts the one source row in
the same transaction. It is a separate function, not a `RememberCommand` field, so the 28 unsourced literals and callers
are untouched and there is exactly one write path. The source row is written after the Evidence, so a refused row rolls
the whole transaction back (G-M06-7).
  1a has no dedupe: a repeated identity hits the UNIQUE and is a `RememberError::Db`. 1b adds the advisory lock and the
  existing-Evidence receipt. The current trigger `control.check_operation_receipt` (0114) requires
  `e.origin_principal_id = NEW.principal_id AND origin_class = 'AuthenticatedAgent'` for the Evidence a receipt points
  at. That refuses a dedupe-hit receipt for a second agent (the existing Evidence names the first agent) and every
  Email, Chat and Calendar arm of D2 (`ExternalContent`). 1b keeps the old predicate and adds an alternative: an
  `evidence_sources` row for that Evidence whose `owner_user_id = NEW.user_id` in the same tenant. It lands in
  migration 0265, not in 1a, so 1a does not touch the trigger.

## Consequences

- Positive: relayed Evidence carries a PII-free identity; third-party kinds cannot be stored wider than USER_PRIVATE or
  below SENSITIVE; the classification has one home; unsourced callers are byte for byte unchanged.
- Cost: a new `RememberError::Source` arm in three adapter mappers (`memory_governance_repo`, `distill_repo`,
  `operation_receipt`); until 1b, a repeated identity is an error rather than a replay.
- Not done here: the wire fields (M06-2), the receipt changes and the conflict code (1b), `evidence_refs` (M06-4).

## Gates

- G-M06-3 `two_ok_messages_two_evidence`, G-M06-4 `email_cannot_be_workspace_shared` and G-M06-7
  `sourced_write_is_one_atomic_unit` (all in `crates/adapters/tests/evidence_sources.rs`; G-M06-7's existing form is
  `outbox_batch_remember`). The §78.2 reconciliation tests are in the same file (`source_kind_codes_match_the_0264_check`,
  `ingest_event_kinds_are_members_of_the_events_check`); the table itself is pinned by
  `humaux_domain::source::tests::the_table_is_exactly_the_adr_table`.
- Red records (targeted runs on throwaway branches, deleted after recording; each failed on the gate's own assertion):
  - G-M06-3, run 39910867763 (r1): object-key digest bound from the payload hash; `two_ok_messages_two_evidence` failed
    at `evidence_sources.rs:286` ("second message with equal text", SQLSTATE 23505 on `evidence_sources_identity_key`).
  - G-M06-4, run 39911578823 (r2): the Email arm replaced by the AgentNote arm; `email_cannot_be_workspace_shared`
    failed at `evidence_sources.rs:321`, the `WORKSPACE_SHARED` refusal assertion.
  - G-M06-7, run 39912106428 (r3): outbox INSERT skipped in `stream_repo`; `sourced_write_is_one_atomic_unit` failed
    at `evidence_sources.rs:381` with `left: [1, 1, 1, 0], right: [1, 1, 1, 1]`. Run 39912676269 (same mutation): the
    existing `outbox_batch_remember::m09_1_ticket_door_*` failed at `outbox_batch_remember.rs:830` with `left: 0, right: 1`.
  - Green: the PR's CI on the unmutated branch.
