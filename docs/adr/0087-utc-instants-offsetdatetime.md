# ADR-0087 — UTC instants are `time::OffsetDateTime`, normalised at construction

- Status: Accepted (2026-10-23). Card ds-docs-186 (docs only). The decision is the lead's; this ADR records it. No code
  changes with it: `domain::temporal` and `domain::audit` still use `SystemTime` (#186 item 2, a separate code card).
- Relates to: Baseline §59.1; issue #186 (this ADR and the temporal/audit migration), #169 (`asserted_at` typed
  `time::OffsetDateTime`), #176 (UTC normalisation in `Authority::new`).

## Context

- §59.1's table typed `Authority.asserted_at` as `DateTime<Utc>`, the `chrono` type. The code has not used that type
  since #169: `crates/domain/src/authority.rs` holds `time::OffsetDateTime` (the instant `TIMESTAMPTZ` stores), and #176
  made `Authority::new` normalise it with `.to_offset(time::UtcOffset::UTC)`.
- No ADR recorded the choice: `git grep OffsetDateTime docs/adr` was empty, so §59.1 and the code disagreed. The review
  of #169 at 11a2ca3 found it; issue #186 item 1 is this record plus the §59.1 wording.
- `time` is the only direct datetime dependency of the workspace (`crates/domain/Cargo.toml`); `chrono` appears in the
  lockfile only as a transitive dependency, so there is no second instant type to reconcile.

## Decision

- The workspace's UTC-instant type is `time::OffsetDateTime`.
- Every value is normalised to UTC at its single construction point: `.to_offset(time::UtcOffset::UTC)`. For `Authority`
  that point is `Authority::new`, the workspace's only construction entry (§59.1 G59-3). A value is never stored with a
  non-UTC offset.
- `Ord` and `PartialEq` compare instants, not offsets, so a caller-supplied offset never changes I1's "asserted_at later
  wins" tier, and two spellings of one instant are equal.
- New value types that carry an instant use this type and normalise at their own single construction point. They do not
  introduce a second instant type and do not carry an offset past construction.
- Scope: this ADR does not move `domain::temporal` or `domain::audit`; they still use `SystemTime`. That migration is
  #186 item 2, a separate code card with its own red record. The §59.1 type wording now cites this ADR; no semantics
  change.

## Consequences

- Positive: spec and code agree; the domain has one instant type; a `TIMESTAMPTZ` round-trips as an instant; callers may
  pass any offset and the construction boundary erases it, so I1 stays a total order.
- Cost: `SystemTime` producers need an explicit conversion when #186 item 2 lands; new callers construct with `time`
  types rather than `chrono`.
- Neutral: no wire, schema, migration or behaviour change. Nothing compiles or runs for this card.

## Gates

- No new gate in this PR (docs only). The type and its normalisation are already covered by the unit test
  `authority_new_normalises_asserted_at_to_utc_and_equal_instants_tie_on_time` (`crates/domain/src/authority.rs:525`),
  added by #176.
- Existing red record: with the `.to_offset(time::UtcOffset::UTC)` normalisation removed, targeted run 39833444276
  (red r3, branch deleted after recording) failed on the offset assertion at `crates/domain/src/authority.rs:546` with
  `left: -08:00:00, right: +00:00:00`, not on setup. #176's PR CI was green on the unmutated branch.
