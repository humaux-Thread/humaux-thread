# ADR-0095 — Project hierarchy: a query-time rollup over the M29 relation kernel

- Status: **Provisional** (2026-10-23) on the hierarchy contract; **Accepted** on the rollup rules. Card M14-1 (docs
  only). Content authority: module design M14 §4 D3 and the owner answers at its end (2026-10-22); M29's relation
  kernel and the M29 E-A ruling of 2026-10-20. The code lands in M14-4. No migration changes with this card.
- Relates to: Baseline §25.3.1, §6.1.3 (subjects), §6.1.4 (work attribution), §78.6; ADR-0078 D-A (registry owner),
  D-C (relation kernel), D-G (high-risk project reorganisation); design notes M29 (relations and attribution), M18
  D1/D3 (the B31 single-parent tree), M20 v2 (public pool boundary).

## Context

- M29 is merged. Its relation kernel has `project_subject_relations` (Project —SERVES→ BUSINESS / BRAND, Project
  —TARGETS→ WEBSITE / PRODUCT / BRAND) and `subject_relations` (WEBSITE / PRODUCT —OWNED_BY→ BRAND, BRAND
  —OWNED_BY→ BUSINESS). Project → Project (`PART_OF`, `DEPENDS_ON`, `REORGANIZED_INTO`) is deferred in ADR-0078 D-C,
  with cycle detection under a tenant graph lock.
- `private.continuity_projects` is the M29-owned registry (ADR-0078 D-A). It has no parent and only
  `lifecycle_state ACTIVE|ARCHIVED`.
- A business line is a BUSINESS or BRAND **subject**, not a project. A channel project is a project that runs on a
  platform — an independent site, `alibaba_intl`, `1688`, `facebook`; Alibaba International is not 1688 (B20). A
  channel becomes its own project only when it has its own goal, lifecycle and archive.
- The owner asked for project memory and hierarchy on 2026-10-15 (item 1), and for reuse across projects, products and
  languages (items 2–5).

## Decision (M14 D3, as the note records it)

### D-A Business line and channel, from merged triples only

- Business line = the BUSINESS or BRAND subject. A channel project —SERVES→ its BRAND, and that BRAND —OWNED_BY→ the
  BUSINESS. Every edge used here is a triple ADR-0078 D-C already whitelists; this ADR adds no relation kind.
- The read is a query over current relation revisions, not a copy: there is no hierarchy projection table and no
  second identity store.

### D-B `private.project_channels`

- M14 adds only `private.project_channels(tenant_id, project_id PK/FK, channel_key slug)`: the platform a project runs
  on. It carries no goal, no lifecycle and no parent; those stay on the project registry.
- One slug per project is chosen at write. zh/en aliases ("阿里国际站" against `alibaba_intl`) wait for ADR-0078 D-H's
  vocabulary layer; the signal that it is needed is two slugs for one platform (M14 U4).

### D-C Rollup is a read, never a write

- A rollup at brand or business level returns each child project's facet references **pinned to exact immutable
  versions**, plus coverage. It never writes a child summary into a parent's `CURRENT_STATE` and creates no parent
  row.
- Each child is read under its own authorization, not the parent's. A hidden child leaks neither its content nor its
  count; the count is computed after the visibility filter (G-M14-5).
- The read is bounded: at most 64 visible children per rollup (`ponytail:` ceiling; the upgrade is a paged or
  materialised rollup when a measurement shows the bound is reached).

### D-D Function sub-projects wait for the first real one

- A function sub-project (site development against site operations) needs Project —PART_OF→ Project. That is the
  ADR-0078 D-C deferred item, built as guest card M29-g2 only when the first such project exists.
- Reparenting is the ADR-0078 D-G high-risk flow: a prepared manifest, a delay, a re-check, and one confirmation of one
  concrete manifest through a trusted user entry — never an agent's API-key channel.

## Provisional status and cross-module note (recorded, not resolved here)

- The owner's answer of 2026-10-22 is binding: project hierarchy (decision #2) is **provisional**; the owner asked for
  a fresh hierarchy and canvas design (B31), and **M18 will own the hierarchy contract**.
- The M18 design note (2026-10-23) proposes a single-parent tree: guest columns `parent_id`, `kind` and `version` on
  `private.continuity_projects`, a self-FK, a depth limit, `project_ancestors` / `project_subtree`, and moves under a
  tenant topology guard. It also proposes `private.project_facets(kind CHANNEL|PLATFORM)` in place of
  `project_channels`, describes this ADR's D3 as superseded, cancels M29-g2, and keeps `tasks.project_id` as the one
  writable task→project authority.
- This ADR records M14's decision and **does not choose between the two designs**. The conflict is listed for the lead
  in the M14-1 PR body. Whichever tree wins, M14 keeps these rollup rules: a read at query time, child rows read under
  the child's authorization, nothing written into a parent, hidden children leaking neither content nor count, and every
  facet reference pinned to an exact immutable version.

## Rejected (from M14 D3)

- `project_profiles.parent_project_id`, and a parent column on `continuity_projects`: a second hierarchy store beside
  the M29 relations, which ADR-0078's Context calls "two sources of identity truth". **The M18 note proposes to reverse
  this rejection; it is recorded here as a cross-module conflict, not resolved.**

## Gates

| Gate | Planned test file | Injected fault | Expected red |
|---|---|---|---|
| G-M14-5 rollup no leak | `crates/adapters/tests/project_rollup.rs` | read children with the parent's authorization; count before the visibility filter | a hidden child's title or count is visible |

No gate exists in this PR (docs only). G-M14-5 exists when M14-4 lands with its §80.1 inject → red → fix → green record.

## Open questions and owner-gated items

- The hierarchy contract itself is open and owned by M18 (see "Provisional status" above). The Project —PART_OF→
  Project pair is deferred with a named trigger: the first function sub-project.
- Channel aliases (M14 U4) are open until the vocabulary layer exists; the fallback is one slug chosen at write.
- Owner-gated: reparenting is an ADR-0078 D-G high-risk operation and needs the owner's confirmation of a concrete
  manifest. No M14 card performs one, and no production data is read by this ADR.

## Consequences

- Business-line and brand views need no new hierarchy table: they compose the relation kernel M29 already owns.
- A channel's platform is one slug, not a second subject kind, so B20's "Alibaba International is not 1688" survives.
- If M18's single-parent tree is accepted, the rollup reads `project_subtree` instead of the SERVES / OWNED_BY walk;
  the authorization, no-parent-write and pinning rules above still hold.
