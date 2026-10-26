# ADR-0094 — Facet publish: one door over the existing slot CAS, with merge-retry for list facets

- Status: Accepted (2026-10-23). Card M14-1 (docs only). Content authority: module design M14 §4 D2 and §5; the owner
  accepted the lead's defaults on 2026-10-22. The code lands in M14-2 (op, door and merge-retry) and M18-6
  (`checkpoint` calls the door inside its own transaction); until then the statements about behaviour are **planned**.
- Relates to: Baseline §25.3.1 (append-only authority, CAS current slot, publish), §33 (tool surface), §52.1, §57.1,
  §78.2, §78.6; ADR-0078 D-C (the revision/CAS pattern); design note M18 D8 and D16 (`checkpoint`).
- No migration changes: 0136 already owns the tables and the SQL function, and 0137 the read path. This ADR adds an
  operation and an application door over them.

## Context

- 0136 / 0137 already store continuity: `private.continuity_facet_versions` (append-only, canonical body, exact
  `body_sha256`), `_slots` (one CAS pointer per project and `SOURCE_BACKED` facet, `CURRENT` / `STALE` /
  `CONFLICTED`), `_memory_links` and `_evidence_links` (immutable sha-pinned source sets), and the 15-facet closed set
  (`domain::continuity::ContinuityFacetKind::ALL`, asserted `== 15`; only the 15 `SOURCE_BACKED` kinds are writable).
- `private.publish_continuity_facet` (0136) is `SECURITY DEFINER`. One call authorises the registry parent, locks the
  slot row `FOR UPDATE`, compares `expected_slot_version`, validates every exact Memory and Evidence source (id and
  sha256, plus visibility), inserts the immutable version and both link sets, then updates the slot with the CAS
  predicate; affected rows other than 1 raise. Rust `adapters::continuity_repo::publish_facet` wraps it.
- **No caller and no op** (audit B89): `git grep` finds the definition, the Rust wrapper and test fixtures only. A
  `SOURCE_BACKED` facet can therefore never be `CURRENT` in production, and `continuity.get` answers `MISSING`.
- The Baseline's publish paragraph names `expected_slot_version` as a publish input. The M26 tool surface does not
  expose slot versions to callers. D-C below states where the value lives.

## Decision

### D-A One door, one transaction

- The operation is `continuity.publish`; its application entry is `publish_facets_in_txn`, which takes the caller's
  open transaction. M18's `checkpoint` (`run_yield(HANDOFF)`) calls the door in its one transaction, so a hand-off and
  the facets it publishes commit or roll back together.
- The order inside the transaction is the spec's: authorise the registry parent, validate the exact sources, insert the
  immutable version and links, then perform the slot compare-and-swap. When the CAS affects anything but one row, the
  whole transaction rolls back — no orphan version, no orphan links, no upsert, no last-writer-wins.
- The door returns the new version id, version number, slot version and body hash; a lost CAS returns
  `ErrorCode::Conflict` together with the current slot version. That conflict is not the semantic `CONFLICTED` slot
  state, which only records a deliberately persisted unresolved conflict (§25.3.1).

### D-B Scalar facets: strict compare-and-swap

- `GOAL` and `CURRENT_STATE` take the scalar path. The door reads the current slot version in its own transaction; a
  concurrent writer that read the same version loses with `Conflict`, and the winner's version stays current.
- No client-supplied slot version is accepted (see D-C). A caller therefore cannot express "overwrite whatever is
  there"; it can only publish on the version the server just read.

### D-C Wire shape and where the expected version lives

- `continuity.publish` carries: `project_id`; `facet_kind` from the publishable closed set (`GOAL`,
  `CURRENT_STATE`, `DECISIONS`, `REJECTIONS`, `CONSTRAINTS`, `KNOWN_ISSUES`, `NEXT_ACTIONS`, `PROCEDURES`,
  `OUTCOMES`); the canonical body; the exact Memory and Evidence sources as `(id, sha256)`; and, for a list facet, the
  explicit removal entries.
- The exact source set is required: the SQL rejects a publication with zero sources, and a source whose sha256 or
  visibility no longer matches is rejected rather than dropped.
- `expected_slot_version` is the **door's** argument, as §25.3.1's publish contract states; it is never a tool input.
  The op's value comes from the door's own in-transaction read. This is the point behind the note's rejection of a
  client-managed `expected_slot_version` (tool surface §5), not a contradiction of the spec's publish paragraph.

### D-D List facets: server-side merge-retry, at most three attempts

- `DECISIONS`, `REJECTIONS`, `CONSTRAINTS`, `KNOWN_ISSUES`, `NEXT_ACTIONS`, `PROCEDURES` and `OUTCOMES` take the list
  path. The door reads the current body, unions the incoming items by source id, applies the explicit removal entries,
  and publishes the merged body against the version it read.
- On a CAS race the door re-reads, merges again and retries, at most 3 attempts in total; the fourth failure is
  `Conflict`. The retry never replaces the list: a whole-list replace would drop a concurrent writer's item, which is
  the failure the 80-writer case in G-M14-2 shows.
- The merge function is one deterministic unit in `adapters::continuity_repo`; there is no second merge in the gateway
  or in a caller.

### D-E Facets outside this op

- The six `SOURCE_BACKED` facets whose sources belong to Phase 11 / M18 (`ACTIVE_TASKS`, `RECENT_CHANGES`, `CODE`,
  `TESTS`, `CONFIG`, `MIGRATIONS`) are not published by this op. Audit B90 keeps them `UNAVAILABLE` until their owner
  supplies an authoritative source; this ADR changes nothing about them.

## Rejected (from M14 D2)

- A client-managed `expected_slot_version` on the tool surface (tool surface §5): a client could pin a stale version
  into a write it did not read.
- Last-writer-wins: the B17 red record ("80 concurrent head updates") is exactly the lost-update shape.
- Whole-list replace instead of union: a concurrent writer's item disappears. The repository's status-merge rule is
  `{**current, **incoming}` with explicit removal, never a wholesale replace.

## Gates

| Gate | Planned test file | Injected fault | Expected red |
|---|---|---|---|
| G-M14-1 scalar CAS | `crates/adapters/tests/continuity_publish.rs` | drop the slot `FOR UPDATE` / the expected-version check | two versions for one slot, or a lost version |
| G-M14-2 list merge | the same file | whole-list replace instead of union | an item from writer A is missing after writer B (80 writers) |

No gate exists in this PR (docs only). G-M14-1 and G-M14-2 exist when M14-2 lands with their §80.1 inject → red → fix →
green records; a missing database in CI is a failure, never `not_applicable`.

## Open numbers and owner-gated items

- D8 of the design note: once publish exists, M14-9 builds the G25-2 / G80-46 W3 live verifier (audit B91,
  D329) with the 14 spec mutations. It is a gate on this path, not a design in this ADR.
- The merge bound (3 attempts) is a starting value from the design note; no experiment measures it. The publish latency
  target is one transaction and one slot row lock.
- Owner-gated: none in this ADR. Every write is to the owner's own project storage; no production write, no email, no
  live key is involved.

## Consequences

- Production finally has a path from source-backed facets to `CURRENT`; until M14-2 lands, the honest answer stays
  `MISSING`.
- Two list writers no longer erase each other, and a scalar loser learns the current version instead of silently
  overwriting it.
- The door is the only writer of facet versions; callers cannot bypass the source validation or the CAS.
