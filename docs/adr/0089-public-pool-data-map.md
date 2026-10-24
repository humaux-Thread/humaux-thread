# ADR-0089 — Public pool data map: three logical layers, unit revisions, roots-only closure

- Status: Accepted (2026-10-23). Card M20-1 (docs only), ADR-M20-b. The decisions are the design lead's record of module
  design note M20 v2 (D1', D3' shape, D7', D13', D14', D17, D18 records, D19); this ADR records them and does not
  re-decide. No migration here; tables land in M20-7, -17, -18, -19, -24, the crate move in M20-2.
- Relates to: Baseline §12.1, §12.3; ADR-0008 (the one physical closure contract); ADR-0090 (admission and serve);
  ADR-0091 (withdrawals); module design note M28 (public is never a bridge).

## Context

- The pool today is 16 `public.*` tables plus staging/control/ops: a free-text claim with support counts. There is no
  problem/condition/result shape, classification, "I am building X" entry, completeness view, or anything for units,
  conditions, vocabulary, task maps, feedback or adoption (module design note M20, §2 and §3).
- §12.3's closure contract (`public.provenance_edges`, `public.synthesis_inputs`, `public.source_closure`, ADR-0008) is
  the one physical derivation contract. This ADR adds no second closure and no second derivation path.
- B33's 23-table SQL attachment was not available locally; the shapes below are the design note's (U8).

## Decisions

### D-A Three logical layers; no new physical schemas

| layer | content |
|---|---|
| `knowledge_public` | servable objects in schema `public`: existing sources, claims, syntheses (= unit revisions), `synthesis_inputs` (= roots), `provenance_edges`, `source_closure`, trust tables, plus `public.{units, unit_fields, unit_conditions, concepts, concept_labels, concept_relations, entities, unit_classifications, task_maps, task_map_stages, unit_feedback}` |
| `knowledge_guard` | existing staging/control/ops guard plus `control.{contribution_notices, contribution_notice_events}`, `ops.public_revocation_acks`, `public.pool_epoch` |
| `knowledge_private` | `private.{public_adoptions, public_adoption_events}` — user plane, FORCE RLS where tenant-keyed |

The names are logical: no physical `knowledge_*` schema is created. Public tables carry no tenant column; guard and
private tables keep their existing roles.

### D-B A unit is typed; a revision is a synthesis row bound to one unit

`public.units(unit_id, unit_type, created_at)`; a revision is a `public.syntheses` row bound to exactly one unit (the
binding column is M20-7's migration). `public.unit_fields(revision_id, field_key, state KNOWN|UNKNOWN|NOT_APPLICABLE,
value jsonb, reason, assist RULE|MODEL|CONTRIBUTOR)`; `public.unit_conditions(revision_id, entity_id, version_range,
platform, constraint_key, value)` — versions live here, never in tags. Per-claim evidence stays `public.claims` plus
`provenance_edges` with a source locator. Every merge, translation or summary is a new revision, re-admitted (ADR-0090);
the old free-text claim + support-count unit is retired by the later unit migrations.

### D-C Roots only; closure stays ADR-0008's

Admission inputs are claims only: at most 64 roots, concept depth at most 3 per facet. `source_closure` is written by the
existing closure contract alone; M20 adds no closure row and no second derivation path. Every `target/root` pair keeps
its one lifetime row, its `is_current` input-version meaning and the "no physical DELETE" rule of ADR-0008.

### D-D No bridge to the private graph

Three edge kinds stay apart: classification (unit to concept), fact/evidence (claim to source), permission/derivation
(lineage, never exposed). Public tables hold no subject/node/memory id; `crates/graph` never reads `public.*`; private
merge proofs write nothing public. Public `entities` reuse M28's deterministic external-key scheme (purl, SQLSTATE, rustc
code) by recomputing the key string on each side, never by an id join.

### D-E Controlled vocabulary (SKOS subset)

Facets: domain, task (main entry), project_type, industry, knowledge_type (= unit_type), content_language.
`concepts(concept_id stable, facet, status ACTIVE|DEPRECATED, replaced_by, definition)`; `concept_labels(lang,
PREF|ALT)`; `concept_relations(BROADER|RELATED|CLOSE_MATCH|EXACT_MATCH)`. BROADER is a DAG within a facet; BROADER and
CLOSE_MATCH are not transitive (SKOS Reference 2009) and expansion walks one hop. The source of truth is
`contracts/public/vocab_v1.toml`, changed by PR; free tags and model suggestions are aggregated into
`unit_classifications(origin SUGGESTED)` and only feed that PR. DEPRECATED means "known wrong" (Wikidata rank semantics),
never "historical": a historically correct unit keeps time state `historical` with validity bounds; schema.org is used
only for export (phase 3). The anti-rot gate checks stable ids, deprecated entries with `replaced_by`, duplicate labels,
zero use and cycles (G-M20-16).

### D-F Task maps, feedback and adoption records

`task_maps(map_id, version)` + `task_map_stages(stage_key, ord, concept_id)` load from `contracts/public/task_maps/*.toml`
(seed "B2B SaaS": auth, permissions, migration, backup/restore, billing, observability). Coverage is read per stage:
usable, conditions-mismatch, unverified, gap. Phase 2 playbooks are a contributed project's units ordered by stage.

`public.unit_feedback(revision, kind USEFUL|NOT_USEFUL|CONDITIONS_MISMATCH|OUTDATED|WRONG|UNSAFE|LICENCE_DISCLOSURE,
family_hash, at)` is rate-limited per tenant and counted per family; `WRONG` enters the A7 dispute path and `UNSAFE` or
`LICENCE_DISCLOSURE` triggers the W3 freeze check (ADR-0090, ADR-0091). Adoption is
`private.public_adoptions(exact public revision, own adaptation memory, verification evidence)` plus
`public_adoption_events(VIEWED|SAVED|ADOPTED|EXECUTED|VERIFY_TRIED|VERIFIED)`. Adaptation is the norm, not the exception
(Baltes & Diehl: of 100 attributed Stack Overflow reuses, 60 were adapted and 22 verbatim), so the record stores the
user's adaptation beside the exact public revision. Contributors see aggregates only; counts below
`public.min_report_count` (config, 5) are suppressed. No unfunded credit rewards exist (phase 3; a funded reward is an
owner red line).

### D-G Crate and dependency direction

The pool's code is `crates/public-pool`, `edition = "cloud"`; M20-2 moves the existing public code there. No core crate
depends on `humaux-public-pool` (G-M01-2). Forbidden: M26/M21/M25, M28 (no edge, D-D), and
`role_public_worker`/`role_public_disclosure` reading `private.*`.

## Consequences

- Positive: one named home per object and one closure contract; the private graph is unreachable; fields and conditions
  are queryable instead of free text.
- Cost: `public.syntheses` now carries two roles (synthesis row and unit revision), so the binding is explicit; the crate
  move changes ownership rows and dependency edges (M20-2).
- Neutral: no row, grant or policy changes in this PR; nothing compiles or runs here.

## Gates

Planned, implementer-owned, tri-state (§57.1); none is added by this PR:

| gate | owner card | injected fault | expected red |
|---|---|---|---|
| G-M20-16 vocabulary rot | M20-17 | add a cycle, duplicate label, deprecated entry without a replacement, or rename an id | the check fails naming the concept |
| G-M20-21 projection | M20-20 | put a tenant field in the payload; derive a vector from a private point | a private field or private vector id reaches the public collection |
| G-M20-23 no bridge | M20-26 | grant `private.subjects` to a public role; make `graph` read `public.`; join entities by id | the ACL matrix or sentinel is non-zero |
| G-M20-19/20 cards, feedback, adoption | M20-23, M20-24 | render FAILED as a plan; count per event not per family; withdraw deletes a user note | an executable step from FAILED; a burst inflates; a small count is visible |

Each needs its inject → red → fix → green record (§80.1) in the implementing card; a missing database is a fail in CI,
never `not_applicable` (ADR-0050).

## Open

- **U1** private-side contribution code cut: if X-M20-1 shows the cut is not cheap, the code stays in core and inert and
  the ownership row says so (M20-3).
- **U2** placement of the public-schema migrations at the repository split: inert DDL stays in the one sequence until
  M01's split card decides.
- **U7** B33 claims beyond the ten verified ones are background only; no decision rests on them.
- **U8** B33's SQL attachment was not read; the shapes above are the design note's. Diff it in a follow-up if it is
  filed, not by re-deciding D1' here.

## Alternatives rejected

New physical `knowledge_*` schemas (they re-prove the existing schema gates, two truths); a parallel unit store beside
`public.syntheses`; the free-text entry plus support count; one generic schema for all unit types; model-created
concepts, per-tenant vocabularies, versions as tags; joining entities by id instead of recomputing the external key; any
edge from the public plane into the private graph.

## References

Module design note M20 v2, D1', D3', D7', D13', D14', D17, D18, D19 and §16; batch-33 public-pool research digest (B33);
Baseline §12.1, §12.3; ADR-0008; ADR-0090; ADR-0091.
