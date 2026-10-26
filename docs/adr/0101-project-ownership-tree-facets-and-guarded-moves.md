# ADR-0101 — Project ownership tree: a single parent on the registry, channel/platform facets, moves under one tenant guard

- Status: Accepted (2026-10-23). Card M18-0 (docs only, wave D, module M18), ADR-M18-a (this ADR). Content authority:
  module design note M18 §4 D1–D3 and §9 (2026-10-23), which record the lead decision of 2026-10-22 and the owner's
  question. This ADR records those decisions and re-decides none. Code lands in M18-1; no migration, code or gate
  changes with this card.
- Amends: Baseline §30 and §48 by pointer only; the new §30.4 project tree is recorded here (note D1, §9 (e)).
- Relates to: Baseline §30, §48, §78.6; ADR-0078 D-A (the registry row stays M29's), D-C (relation kernel);
  ADR-0095 (M14 D3 rollup, superseded by this ADR); ADR-0096 (M14 D4 applicability); ADR-0102 (task→project
  authority); design notes M14 and M29.

## Context

- `private.continuity_projects` (0136) is M29's registry: no parent, `lifecycle_state ACTIVE|ARCHIVED`, and
  `UNIQUE (tenant_id, workspace_id, project_id)` already present — usable as a same-workspace self-FK target
  (note §2 :27-28).
- The owner asked for a main project and sub-projects on 2026-10-22 (note §1 :10, §3 :34). M14 D3's hierarchy is
  provisional: a query-time rollup over relations, with no single-parent, cycle or depth guarantee (ADR-0095).
- A channel becomes a project only when it has its own goal, lifecycle and archive (note D3 :50-52). A cross-project
  goal is a collection, not a second parent.
- Two hierarchy stores would make "which project owns this task" ambiguous. The M18 tree is the one store; the M29
  relation kernel keeps business relations and the same-transaction task mapping (ADR-0102).

## Decisions

### D-A The tree is `parent_id` on the registry row (note D1)

- Guest columns owned by M18 on `private.continuity_projects`: `parent_id uuid NULL`,
  `kind BUSINESS_LINE|PROJECT|MODULE`, `version bigint`.
- Self-FK `(tenant_id, workspace_id, parent_id) → (tenant_id, workspace_id, project_id)`: same tenant and workspace by
  construction. Depth ≤ `coord.project_max_depth` (config, default 8, root = 1). Archive is the existing
  `lifecycle_state` (note D1 :43).
- Reads are `private.project_ancestors(id)` and `private.project_subtree(id)`, recursive CTEs marked
  `security_invoker`. The registry row itself remains M29-owned (ADR-0078 D-A); M18 owns only the hierarchy guest
  columns.
- Rejected: M14 D3's relation rollup plus M29-g2 `PROJECT PART_OF PROJECT` — a triple gives no single-parent, cycle or
  depth guarantee and creates two hierarchy stores (note D1 :43-45); `ltree`, materialised path or a closure table as
  the authority — a closure table may come later only as an accelerator (note D1 :44-45; §15 :249).

**Amended (M18-1):** `project_ancestors` / `project_subtree` are SECURITY DEFINER doors in 0271/0254's shape (tenant assertion, caller workspace list, `declared_project_visible` per row), not `security_invoker`: 0136:505-509 keeps runtime roles off the registry.

### D-B Moves run under a tenant topology guard (note D2)

- `project_move(id, new_parent, expected_version)` takes
  `pg_advisory_xact_lock(<const class>, hashtext(tenant))` — one const in `coord_tree_repo`, also taken by task-graph
  edits; heartbeats never take it (note D2 :46-48).
- Inside the lock: a fresh READ COMMITTED statement re-reads the row and the subtree; the move is refused if it would
  create a cycle, if the subtree depth after the move exceeds the limit, or if any task whose parent task sits in
  another project would no longer keep `parent.project_id ∈ ancestors(child.project_id)`.
- Success bumps `version` and writes an event. Read rights never widen: visibility stays tenant + workspace, and the
  FK forbids cross-workspace moves (U3). A CHECK cannot perform this check — it reads other rows.
- Rejected: trigger-only enforcement, which has no fresh snapshot inside the guard (note D2 :49).

### D-C Channels and platforms are facets, not parents (note D3)

- `private.project_facets(tenant, project_id, kind CHANNEL|PLATFORM, value slug)` replaces M14's planned
  `project_channels` (note D3 :50; §9 M14 row :165).
- A channel becomes a project only with its own goal, lifecycle and archive. Cross-project goals are collections
  (task `GROUP`), never a second parent. M29's business relations (Project —SERVES→ BRAND, and the rest) are
  unchanged; no `PROJECT`-under-`PROJECT` triple is added.

**Amended (M18-1):** M14-4 had built `project_channels` (0271); 0281 copies it into `project_facets` (CHANNEL), re-points `set_project_channel` / `read_project_rollup` with unchanged signatures, and drops it.

### D-D M14 D3 is superseded by this contract (note §9 M14 row)

- M14 consumes `project_ancestors` / `project_subtree`; M14-4's `private.project_channels` becomes
  `project_facets(kind CHANNEL)`; card M29-g2 is cancelled.
- M14 D3's rejection of "a parent column on `continuity_projects`" is reversed (lead 2026-10-22, B31).
- M14 D4's `memory_applicability` gains `project_scope EXACT|SUBTREE`, which stays M14-owned. Rollup still reads
  children under their own authorization (G-M14-5 unchanged).

## Consequences

- Positive: one hierarchy store with a same-workspace self-FK; moves are checked under one guard with a fresh
  snapshot; channel projects no longer need a second parent mechanism.
- Cost: the tenant advisory guard serialises topology edits (and task-graph edits) per tenant; the recursive CTE is a
  documented ceiling (note §15 :249).
- Neutral for this card: docs only; no table, migration, config key or wire format changes.

## Gates

Planned, implementer-owned, tri-state (§57.1); none exists here. Each needs its inject → red → fix → green record
(§80.1) in the card that builds it.

| gate | owner card | test file | injected fault | expected red |
|---|---|---|---|---|
| G-M18-1 tenant isolation | M18-1 | `crates/adapters/tests/coord_rls.rs` | drop the tenant leg from one coord FK / policy | a cross-tenant row is visible or an FK accepts a foreign parent |
| G-M18-4 concurrent project cycle | M18-1 | `crates/adapters/tests/project_tree.rs` | skip the advisory guard / reuse the old snapshot | two concurrent moves commit a cycle |
| G-M18-5 depth + task ancestry on move | M18-1 | `crates/adapters/tests/project_tree.rs` | drop the depth / ancestry re-check | depth 9 commits; a child task ends outside its parent's subtree |

## Owner-gated

None in this ADR. The hierarchy is the owner's request of 2026-10-22; no production write, live key or email is
involved.

## Open research

- U3: there is no per-project ACL today. Fallback: the same-workspace FK keeps moves non-widening; any future ACL must
  be re-checked in `project_move` (note §13 :230).
- The closure-table accelerator is a ceiling, not a decision: it starts when `project_subtree` p95 exceeds its budget
  at depth 8 (note §15 :249). The depth default of 8 is a config start value.
- Whether reparenting is a D-G high-risk operation (ADR-0078) is not addressed by the note.

## Alternatives rejected

M14 D3's relation rollup and M29-g2's `PROJECT PART_OF PROJECT` triple; `ltree`, a materialised path or a closure
table as the hierarchy authority; two hierarchy stores; trigger-only move enforcement.

## References

Module design note M18 §1, §2, §3, §4 D1–D3, §9 (M14 row), §10, §13, §15; Baseline §30, §48, §78.6; ADR-0078 D-A/D-C;
ADR-0095; ADR-0096; ADR-0102; design notes M14 and M29.
