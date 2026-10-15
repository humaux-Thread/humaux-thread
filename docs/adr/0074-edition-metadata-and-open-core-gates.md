# ADR-0074 — Edition metadata contract and the two open-core gates

- Status: Accepted (2026-10-15). Card M01-1 (module design M01 D1).
- Relates to: ADR-0073 D-B (the dependency direction this ADR makes checkable); Baseline §58 (workspace contract,
  extended here with the edition declaration), §78.3, §57.1.

## Context
ADR-0073 D-B says every crate declares its edition and a gate fails on any core -> cloud dependency. Until the
repository split (ADR-0073 D-D) core and cloud-to-be code share one workspace, so the boundary has to be a property
of the manifests that the existing `cargo metadata` reading in `xtask architecture-check` can compare.

## Decision
- **D-A Edition metadata.** Every workspace member manifest carries
  `[package.metadata.humaux] edition = "core" | "cloud"`. The vocabulary is closed, there is no default and no
  workspace-level inheritance: a new crate must choose, and a missing or unknown value is red. Initial marking:
  `humaux-public-worker` is `cloud` (the public knowledge pool, ADR-0073 D-A), the other 23 members are `core`.
  Cloud-to-be code that still sits in core crates (`humaux-adapters` contribution and public modules) moves behind
  core-side ports in M20 / M28 / M04, not here.
- **D-B Ownership rows.** `docs/architecture/module_ownership.toml` holds a `[crates]` table, package name -> module
  id (`M01`..`M28`). Crates that host several modules' files are marked `shared` and carry the module that owns the
  crate-level contract; the file-level map is card M01-5 and replaces those rows.
- **D-C G-M01-1 (workspace members).** `cargo xtask architecture-check` sub-check: the `cargo metadata --no-deps`
  member set equals the `[crates]` keys, every member declares an edition in `{core, cloud}`, every row names a
  module id. It has no `not_applicable` leg: the metadata and the ownership file are delivered by the same card, so
  absence is a regression (§57.1 rule 2). Failure lines name the member or row.
- **D-D G-M01-2 (core never depends on cloud).** Same sub-check family: no `core` package has a normal, dev or build
  dependency, optional or not, on a `cloud` package. Direct edges of core packages are sufficient (induction over
  the member graph: a transitive path starts with a core -> X edge, X cloud or X core with its own offending edge).
  Packages with a missing or unknown edition are skipped here because G-M01-1 reports them. With no cloud package
  the sub-check prints `not_applicable` naming `package with edition = "cloud"` — the expected state of the
  open-source repository after the split, which keeps this gate.
- **D-E Where.** Both live in `xtask/src/architecture_check.rs` next to the §78.3 comparator and share its one
  `cargo metadata` spawn helper; pure comparators take the JSON text so unit tests inject fixtures.

## Rejected
- A Cargo feature `cloud` in core crates: one crate graph, the split would need source edits.
- A `cargo-deny` `[bans]` list: cannot express "core may not, cloud may".
- Deciding by directory name: silent when a crate moves.
- A workspace default of `core`: a new cloud-bound crate would be core by omission.

## Red records
Each gate has an injected-fault record on a throwaway branch; run ids are in the card's PR description.
- G-M01-1: delete the `edition` line of one member (`ci/red-m01-1a`) -> the sub-check fails naming that package.
- G-M01-2: a `[dev-dependencies]` entry from `humaux-telemetry` to `humaux-public-worker` (`ci/red-m01-1b`) ->
  the sub-check fails naming the edge.
- Unit fixtures (`xtask`, `architecture_check::tests`): missing edition, unknown edition, member missing from the
  ownership file, extra row, bad module id, core -> cloud normal / dev / build / optional edges, cloud -> core
  allowed, no-cloud `not_applicable`.

## Consequences
- A new crate lands with its edition and its `[crates]` row in the same PR; a core crate that needs cloud
  functionality gets a core-side port instead.
- The cloud repository created at the split depends on the open-source crates and never the reverse, so the
  open-source repository's copy of G-M01-2 stays `not_applicable` there.
