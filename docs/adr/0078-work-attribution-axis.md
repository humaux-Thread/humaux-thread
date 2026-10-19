# ADR-0078 — Work attribution axis: module M29, relation kernel, attribution ladder and rule N09

- Status: Accepted (2026-10-19). Card M29 T01 (docs only). Content authority: design v0.2 "objects, relations and
  attribution (M29)", baseline `ea7b459`, which the owner delegated on 2026-10-19. Amended the same day with the
  design owner's rulings on review questions Q1, Q2 and Q4 (D-A, D-B, D-D).
- Relates to: Baseline §6.1.3 (Subject axis), §6.1.4 (this ADR's normative home), §25.3.1 (project continuity),
  §25.4 (`context_bindings`), §33.10 rule 9 (two-step confirm), §15 (`commit_seq`), §78.2, §78.6, §80.1;
  ADR-0018 (confirm-token gate), ADR-0020 (lifecycle log), ADR-0027 / ADR-0028 / ADR-0029 (Subject axis).

## Context

The owner requirement (REQ §3.2) names the objects one person's work runs through: people / organisations, businesses,
brands, products or product lines, websites, projects, tasks, workflows, capabilities and knowledge. It adds that these
objects can be related "but must not be merged into one kind of Project". REQ §3.3 asks for many-to-many project
relations (one project, several websites; one website, several projects). REQ §3.4 and N09 ask that unknown identity or
attribution stay unknown. The owner's reply of 2026-10-19 adds two things: formal attribution must be automated, and the
object kinds (including store / channel account) are designed here and then checked by experiment.

The repository already has most of the substrate, so this ADR adds no object table:

- **Subject axis (§6.1.3, ADR-0027/0028/0029).** `private.subjects` / `subject_keys` / `subject_roles` (migration 0153),
  the four memory↔subject link tables and the deterministic resolver `private.link_memory_subjects` (0154,
  `0154_memory_subjects.sql:207`), and subject-scoped recall with a RESTRICTIVE policy (0155). `SubjectKind` is
  `{Person, Organisation}` and `SubjectKeyKind` is `{Crm}` (`crates/domain/src/subject.rs:61`, `:115`). A brand, a
  website, a product and a store are all things a memory is *about*, which is the question the Subject axis answers.
- **Projects.** `private.continuity_projects` (0136, `0136_project_continuity.sql:4`; §25.3.1) already carries the
  project identity, with an immutable `(tenant_id, workspace_id)` parent.
- **Repositories.** `control.repositories` (0003, `0003_control_core.sql:62`) already exists as a scope dimension.
- **Tasks.** `coord.tasks` / `coord.task_runs` (0009) model a task's existence and tenant only
  (`crates/adapters/src/context_repo.rs:151`); 0173 states that no task lifecycle operation exists in the tree.
- **Context bindings.** `private.context_bindings` (0006, mode / scope from 0102; §25.4) is the context-injection
  obligation per scope, including `TASK`.

A second identity registry for business objects, or a second project table, would give the system two sources of
identity truth. What is missing is narrower: relations between these objects, memory → project attribution, and
deterministic inheritance rules for task runs and capture contexts.

## Decision

### D-A Module M29 and data ownership

- New module **M29 "work attribution and relation registry"** at layer **L4** (the layering of module map v3 §2, where
  L0 → L6 may only depend downward).
- **Edges (Q1 ruling).** M29 → M07: M29 implements the attribution port that M07 defines next to the Memory INSERT
  door (D-D). Composition roots → M29: the gateway and worker processes (L4 and above) construct the M29
  implementation and hand it to callers of the door; the Distill worker's edge is the declared same-layer
  **M15 → M29**. There is no L3 → L4 edge.
- M29 owns the relation-kernel tables (D-C), `evidence_projects` / `memory_projects` / the revocation table (D-D), and,
  later, the candidate table, the vocabulary tables (D-H) and the workflow registry.
- **Contract ownership of `private.continuity_projects` moves from M14 (L5) to M29.** M29 depends on the project
  registry; leaving it in M14 would be an upward edge. M14 keeps its facet tables, whose foreign keys point at the
  registry. The move is card T03 and changes the contract and module registration only; no table changes.
- **Subjects stay in M07** (L3). M29 adds kinds and relations that reference subjects; M07 never reads M29.
- **Tasks stay in M18** (L5). M29 does not read M18. A task run is verified by the gateway application layer through an
  M18 port (lease and principal), and M06 writes the verified result as the `evidence_task_runs` carrier on Evidence.
  M29 reads only that carrier.

### D-B SubjectKind / SubjectKeyKind extension (authorised here, implemented by T02)

- `SubjectKind` gains **`BUSINESS`, `BRAND`, `PRODUCT`, `WEBSITE`** (T02). It remains a frozen closed set,
  expand-only, reconciled DB ↔ Rust by contract test (§78.2).
- **Provisional kinds wait for E-C (Q2 ruling).** `CHANNEL_ACCOUNT` (not listed in REQ §3.2) and `PRODUCT_LINE` do not
  enter the closed set until experiment E-C accepts them. An accepted kind is added by a later ADR-amendment card; a
  rejected kind needs no removal, because it was never added. Until then a product line is one `PRODUCT` that other
  `PRODUCT`s point at with `PART_OF`.
- **No new `SubjectKeyKind` in T02 (Q4 ruling).** `subject_keys` is `UNIQUE(tenant_id, key_kind, key_value)` (§6.1.3),
  so every key kind is an exclusive identity key per tenant. A namespace becomes a `SubjectKeyKind` only after E-C
  shows it is exclusive. Shared locators (a domain served by several sites, a path, a remote) are never
  `SubjectKeyKind`s. Key namespaces arrive with A2 (deferred), not in T02.
- A domain is never an object: changing the domain does not change the website.
- Repository is **not** a `SubjectKind`. It keeps `control.repositories`; its exclusive key is
  `(provider, platform immutable id / node_id)`, with remote URL and path as locators only (GH-REPO, GH-RENAME). The
  Project —TARGETS→ Repository endpoint is deferred.

### D-C Relation kernel (shape and invariants; implemented by T05)

One SQL template and one Rust kernel serve every relation pair:

```text
<pair>_relation_revisions(
  tenant_id, relation_id, revision bigint,     -- PK (tenant_id, relation_id, revision)
  src_id, dst_id, relation_kind,               -- real composite FKs with a tenant leg (§6.1.3)
  valid tstzmultirange NOT NULL,               -- valid time; '{}' = retracted
  decided_by text NOT NULL,                    -- 'rule:<id>@<ver>' | 'principal:<uuid>'
  proposed_by text NULL,                       -- 'model:<id>@<ver>', provenance only, never authority
  factual_evidence_ids uuid[] NOT NULL,
  authorization_evidence_id uuid NOT NULL,     -- kept apart from the factual evidence
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp())
```

- **Append-only.** INSERT only; an owner trigger rejects UPDATE (same technique as 0156,
  `0156_memory_affects.sql:94`). Current state = the highest revision per `relation_id`.
- **Retraction** is a new revision whose `valid` is the empty multirange `'{}'`.
- **CAS.** A write carries `expected_revision` and must insert `revision = expected_revision + 1`; the primary key
  rejects the loser of a race.
- **Interval shape.** One shared IMMUTABLE SQL function, used in a CHECK, requires every range of `valid` to be `[)`,
  with a finite lower bound and an upper bound that is finite or omitted; explicit `±infinity` is rejected.
  `tstzrange` has no canonical form, so `[)` and `[]` would otherwise compare unequal (PG-RT).
- **Whitelist.** The allowed `(src_kind, relation_kind, dst_kind)` triples are a Rust closed set; the DB mirrors them
  in a CHECK reconciled by contract test (§78.2).
- **No temporal unique key and no `btree_gist` in the first slice.** Revisions of one relation overlap in valid time
  by construction, and PostgreSQL forbids empty multiranges in a `WITHOUT OVERLAPS` column (PG-CT). `btree_gist`
  arrives with keys that carry a validity period, under its own ADR.
- **First three pairs:**

| Table | First-slice whitelist |
|---|---|
| `project_task_relations` | Project —CONTAINS→ Task; Project —REFERENCES→ Task (only CONTAINS counts toward a project's workload) |
| `project_subject_relations` | Project —TARGETS→ {WEBSITE, PRODUCT, BRAND}; Project —SERVES→ {BUSINESS, BRAND} |
| `subject_relations` | WEBSITE / PRODUCT —OWNED_BY→ BRAND; BRAND —OWNED_BY→ BUSINESS; PRODUCT —PART_OF→ PRODUCT |

Design v0.2 also lists `CHANNEL_ACCOUNT` in TARGETS and OWNED_BY. Those triples join the whitelist with the kind, in the
same ADR-amendment card, if E-C accepts it (D-B).

Deferred: Project → Project (PART_OF, DEPENDS_ON, REORGANIZED_INTO) with cycle detection under a tenant graph lock;
workflow relations; repository relations.

### D-D Attribution ladder: memory → project (implemented by T06)

Tables, shaped like 0154: `private.evidence_projects(tenant_id, evidence_id, project_id, source_kind)` written with the
Evidence in `remember.put`'s transaction; `private.memory_projects(tenant_id, memory_id, project_id, relation
ATTRIBUTED_TO, source_kind, rule_id_ver, decision_evidence_id)`, immutable per memory version, the attribution source
of truth; `private.memory_project_revocations(...)`, append-only. Read paths accept a link only if it exists and is not
revoked.

`source_kind` is a frozen closed set with **no model-derived variant** (as in §6.1.3):

| Rung | `source_kind` (+ rule) | Deterministic condition | First slice |
|---|---|---|---|
| A1 | `DECLARED` | `project_id` on `remember.put`, resolved server-side: exists in the tenant and is visible to the caller | yes |
| A2 | `EXTERNAL_KEY` | exact match of a Subject key, then a unique project via `project_subject_relations` at the Evidence's occurrence time; more than one project → unknown | deferred (needs keys with validity) |
| A3 | `INHERITED` + `task_run@1` | Evidence carries a verified `task_run_id` (`evidence_task_runs`); inherit every project with a CONTAINS relation valid at occurrence time | yes |
| A3' | `INHERITED` + `correction@1` | a `USER_CORRECTION` version inherits the corrected predecessor's attribution (§6.1.3 rule 3) | yes |
| A4 | `INHERITED` + `capture_context@1` | server-issued capture handle bound to exactly one project and one live task run, short TTL [starting value 30 min], no exact hit on another known key | deferred |
| A5 | none (never written to `memory_projects`) | similarity, embeddings, Topic names, model inference | candidates only, deferred |

- When no rung holds, no row is written and the read path reports the memory as `unresolved` (REQ §3.4).
- Every formal row carries `rule_id_ver` and `decision_evidence_id`, so a falsified rule can be revoked in bulk.
- **Revocation shares the correction's transaction.** Correcting a `project_task_relations` revision ("T1 never
  belonged to P1") writes, in the same transaction, a revocation row for every `memory_projects` row that A3 derived
  from it. Dependent continuity outputs keep the existing `continuity_facet_memory_links` + sha check and read as
  damaged on mismatch.
- **Single call site through an M07-owned port (Q1 ruling).** The workspace's only Memory INSERT is
  `adapters::memory_repo::insert_memory_in_txn` (`crates/adapters/src/memory_repo.rs:1`, `:107`; M07 D9, G-M07-1).
  Design v0.2 names it by its re-export alias `adapters::distill_repo::insert_memory`
  (`crates/adapters/src/distill_repo.rs:60`). The function is defined in an M07 (L3) file, so it cannot call M29 (L4)
  directly. Instead:
  - M07 defines an attribution port next to the door (a `MemoryAttribution` trait or fn-pointer struct).
  - `insert_memory_in_txn` takes the port as a **required** argument, never `Option` and never a default or no-op. It
    invokes the port **exactly once**, in the caller's transaction, after the memory row is written.
  - M29 implements the port (`link_memory_projects` behind it). Callers obtain the implementation from their
    composition root (D-A).
  - A no-op implementation in production code is forbidden. Tests use the real M29 implementation. T06 validates the
    design.
- Candidates (deferred): a separate table with `proposed_by=model@ver`, score and state; readable only through a
  candidate API and labelled when used; never counted. A candidate becomes formal only when an A1–A4 condition appears,
  or when the user confirms a concrete manifest (D-G), and only if it passes the independence test (N09 R5).

### D-E Rule N09 — identity and attribution are never guessed

Authority: the owner requirement (REQ N09, REQ §3.4, REQ §6.4) and spec §6.1.3 (model output is never used for linking;
unknowns are never auto-registered). Fellegi–Sunter (ER-FS) is cited only as the precedent for a three-way decision
(link / possible link / non-link). FS itself lets a probabilistic rule link directly, so "probability yields only
candidates" is stricter than FS and is the owner's policy. ER-HZ §2.1.1 supports R4; ZEP §2.2.2–2.2.3 is the
counterexample (LLM deduplication and edge invalidation); ST-SC supports abstention.

- **R1** A formal identity or attribution is written only on one of these deterministic grounds: ① an explicit id
  validated by the server; ② a trusted external key that matches uniquely within its validity period; ③ inheritance
  from an already-formal relation under a registered rule (`rule_id@version`); ④ a current authorised confirmation of
  a concrete manifest (§6.1.4 high-risk operations).
- **R2** Similarity, embeddings, Topic names and model output (including model-reported confidence) yield candidates
  only. Candidates never enter formal read paths, counts, constraints, prevention rules or handoff manifests.
- **R3** When R1 does not hold, the answer stays unknown: no default, no most-recent, no majority.
- **R4** Identity merges and splits are never derived from the transitive closure of pairwise similarity. Each merge
  is an explicit high-risk operation on exactly the pair its manifest lists.
- **R5** A candidate with model involvement becomes formal only if it passes the independence test: with the model's
  output removed, the R1 grounds replay the same endpoint, kind, scope and time.
- **R6** Every automatic formal record carries `rule_id@version` and `decision_evidence_id`; when a rule is falsified,
  its records are revoked in bulk.

### D-F Time and audit

- Two axes, named after SQL:2011 (TM-KM): `valid` (application time) and `recorded_at` (close to transaction time).
- "Known at time K" is approximate. `recorded_at` (`clock_timestamp()`) and every `*_seq` mark write time, not commit
  time (PG-SEQ, PG-DT). Commit timestamps are off by default and vacuum removes them (PG-CTS). Replay to a declared
  recorded-time cutoff is allowed only with its error window stated (the longest in-flight transaction).
  Counterexample, kept as a fixture: A writes first, B writes later and commits first; a cutoff between the two
  commits replays A although A was not visible then. Replay also starts no earlier than the lifecycle log's coverage
  boundary: rows superseded before 0149 were not backfilled (`0149_memory_lifecycle_events.sql:158`, ADR-0020).
- `commit_seq` (0043) is a plain sequence that §15 limits to a global audit order, never a completeness judgement.
  Whether it yields a consistent cut is unverified; nothing relies on it until a concurrent-commit fixture shows it.
- Exact audit uses a **dependency manifest**: an output records the `memory_id` + sha it used when it is written, in
  the shape of `continuity_facet_memory_links`. v0.1's `known_snapshot_id` is not revived.
- Three manifests prove different things and are not interchangeable: the **access manifest** (what
  `context.assemble` offered), the **operation manifest** (a high-risk change list, D-G) and the **dependency
  manifest** (what an output used).
- PROV-O mapping, documentation only (no column renames, no RDF): a decision is an Activity; rules and models are
  SoftwareAgents; `decided_by=rule@ver` ≈ hadPlan of a qualifiedAssociation; `factual_evidence_ids` ≈
  used / wasDerivedFrom; revocation ≈ wasInvalidatedBy.

### D-G High-risk operations and proof of the owner

- High-risk: identity merge or split, project reorganisation, cross-workspace reference, permission change.
- Flow: prepare a manifest (≤ 100 relations per batch [starting value]) → check → delay [starting value 24 h] →
  re-check → commit with a receipt; then a quick-undo window [starting value 7 days].
- Authorisation = one confirmation of one concrete manifest, persisted by the server, bound to principal, manifest
  digest and TTL, single use. The server half **reuses `control.confirm_tokens`** (0148 / ADR-0018; the server half
  of §33.10 rule 9): single use, bound to tenant, user, operation, target and successor, plus workspace (0187) and
  `request_sha256` (0236), which binds the manifest digest. Nothing new is built.
- **New constraint on that gate for these operations:** the token is consumed through a trusted user entry (console
  or REST with a user session), never through an agent's API-key channel. A second step that an agent can also send
  proves no more than an elicitation accept.
- **Not proof of the owner:** an elicitation accept (a local hook can produce or rewrite it, CC-HOOKS; a URL-mode
  accept only consents to start, MCP-EL); MRTR `requestState` (attacker-controlled, MCP-MRTR); an OAuth token (proves
  access on behalf of the resource owner, not authorship, MCP-AUTH); `clientInfo` (self-reported, MCP-OV); roots
  (a hint, MCP-ROOTS); an agent relaying the owner's words; silence or expiry.
- **Valid:** a first-party out-of-band approval page whose server records the exact content and outcome. It produces
  a new attested Evidence and never rewrites the origin of earlier Evidence. Capture of raw input by a trusted host
  before any model or hook rewrite is UNKNOWN (open question Q6).

### D-H Ontology layers

| Layer | Content | How it changes |
|---|---|---|
| Schema | Rust closed sets: `SubjectKind`, `SubjectKeyKind`, relation whitelist, `source_kind` | ADR only (§78.6) |
| Vocabulary | plain PG tables on the SKOS data model: `vocab_schemes` / `vocab_concepts` / `vocab_labels(kind PREF\|ALT\|HIDDEN, lang, text)` / `vocab_broader` (direct parent only) / `vocab_related`; capabilities, aliases, key-namespace notes | Parent / Candidate paired gate (E-F) |
| Access | `context.assemble` returns a manifest; entries resolve on demand (M14) | follows M14 |

- SKOS integrity in the DB: S14 as `UNIQUE (concept_id, lang) WHERE kind='PREF'`; S13 by the single `kind` column;
  S27 checked when writing `related` (no broaderTransitive between the ends) and `broader` (no cycle). Two choices
  are ours, not SKOS's: notation unique within a scheme, and acyclic `broader`.
- Vocabulary changes pass E-F: EVO's structure (paired comparison, two-fold isolation, keep the Parent on failure)
  with our own acceptance test, an exact conditional McNemar on a frozen replay set (ST-MN), because EVO gives no τ
  and no significance test. N09 hard gates must not regress.
- **The vocabulary layer is not built in the first slice.** It waits for a real consumer, such as recall by
  capability in M14.

## Gates (planned; none exists yet)

All are three-state. Each gate exists only after its inject → red → fix → green record (§80.1) lands in the card that
implements it; until then these ids are a plan, not registry entries.

| Gate | Criterion | Injected fault |
|---|---|---|
| G-M29-1 closed-set reconciliation | Rust enums of `SubjectKind`, `SubjectKeyKind`, `source_kind` and the relation whitelist == DB CHECKs (§78.2) | add a kind in the DB only |
| G-M29-2 interval shape | `[]`, explicit infinity and an unbounded lower bound are rejected by the CHECK | drop the `upper_inc` test from the CHECK function |
| G-M29-3 CAS | two connections writing with the same `expected_revision` concurrently: exactly one succeeds | drop the revision check |
| G-M29-4 append-only | UPDATE / DELETE by any runtime role fails | grant UPDATE |
| G-M29-5 single call site | the attribution port is invoked exactly once, inside `memory_repo::insert_memory_in_txn` (`== 1`), and the door's signature requires it | (a) a second invocation; (b) making the port parameter `Option` / defaulted |
| G-M29-6 same-transaction revocation | after correcting a project_task revision, every `memory_projects` row derived from it has a revocation row in the same transaction | move the revocation to a second transaction |
| G-N09-1 no model source | `source_kind` has no model-derived variant; an architecture check finds no provider / inference import on the `memory_projects` write path | add `ModelExtracted` |
| G-N09-2 candidate isolation | authoritative read-path functions never reference the candidates table (architecture_check rule) | join candidates in recall hydrate |
| G-N09-3 unknown stays unknown | same-name trap fixture: two projects with one name and no deterministic ground → zero formal rows, reported `unresolved` | "take the most recent project" |
| G-N09-4 models off, same result | with every provider off, formal attribution is row-for-row identical and external calls = 0 (E-D) | make A3 call a model once |

## Cards and experiments

- **T01** (docs): this ADR, Baseline §6.1.4 with N09, the `context_bindings` boundary sentence (§25.4).
- **T02** (M07): `SubjectKind` += `BUSINESS`, `BRAND`, `PRODUCT`, `WEBSITE`; no new `SubjectKeyKind` (D-B);
  migration, domain enum, contract test. Gate G-M29-1.
- **T03** (contract): `continuity_projects` contract ownership M14 → M29; contract and module registration only.
- **T04** (M18 + M06): minimal task-run lifecycle (principal, lease, verification port) and the `evidence_task_runs`
  carrier; a write after lease expiry does not inherit.
- **T05** (M29): relation kernel, SQL template + Rust kernel + the three pairs. Gates G-M29-2/3/4.
- **T06** (M29 + M15): attribution tables and `link_memory_projects` with A1, A3, A3' behind the M07 attribution port;
  the door's required port argument and the composition-root wiring (D-D). Gates G-M29-5/6, G-N09-1/3.
- **T07** (M29): first E2E on a synthetic fixture (website A, projects P1 / P2, shared task T1, same-name trap
  project, three messages, one correction, plus replay, revoked access and faults). Gates G-N09-3/4.
- **E-A** precision per ladder rung (A1 / A3 / A3' × relation kind × source scope), binding correctness and
  conditional attribution judged separately; cluster sampling with one decision per cluster; CP one-sided upper
  bound ≤ 0.5% [starting value] per cell with LTT multiplicity control.
- **E-B** (deferred, with A5) paired comparison of candidate generators by exact conditional McNemar, reporting
  coverage beside precision.
- **E-C** object-kind coverage on the owner's real portfolio: acceptance of `PRODUCT_LINE` and `CHANNEL_ACCOUNT`,
  exclusivity of each candidate key namespace (`DOMAIN` first),
  the five workflow and six repository scenarios; κ reported only as human–model agreement, diagnostic only.
- **E-D** models-off consistency, row-for-row and zero external calls (G-N09-4).
- **E-F** vocabulary evolution gate (D-H).
- The design defines no E-E.

## Alternatives rejected

- A `business_objects` table: duplicates the Subject axis and creates a second identity source (§6.1.3).
- A new projects table: `continuity_projects` exists (0136).
- One revision / CAS / interval implementation per relation pair: six copies of the same structure.
- `WITHOUT OVERLAPS` on the revision tables: retraction is an empty multirange, which that column forbids, and
  revisions overlap by construction (PG-CT).
- Exact "known at K" from `created_at ≤ K`: write time is not commit time (PG-SEQ / PG-DT / PG-CTS).
- Reviving a `known_snapshot_id` snapshot table: the dependency manifest covers it.
- LLM deduplication / LLM edge invalidation (Graphiti / Zep style): violates N09 (ZEP; REQ §3.4).
- Identity merge by transitive closure of similarity: builds large clusters (ER-HZ §2.1.1).
- EvoOntology's acceptance gate as is: no τ, no significance test (EVO).
- An RDF / triple store: only the SKOS data model is needed; PostgreSQL stays the single fact authority.
- Elicitation accept, `requestState`, OAuth token, `clientInfo` or roots as proof of the owner (CC-HOOKS, MCP-MRTR,
  MCP-AUTH, MCP-OV, MCP-ROOTS).
- Workflow as a Project `work_mode`: REQ §3.2 forbids merging these objects into one kind of Project.
- A procedure Memory's id as workflow identity: every supersede changes the id.
- Repository as a `SubjectKind` or a new `REPOSITORY` kind: `control.repositories` exists and is a scope dimension.
- Remote URL or local path as repository identity: a rename redirect breaks once the old name is reused (GH-RENAME);
  paths differ per machine.
- Calling a CP interval "exact" after an n/DEFF adjustment for correlated samples: replaced by one decision per
  cluster.

## Review questions closed by ruling (design owner, 2026-10-19)

- **Q1 Layer edge of the single call site.** The design asked T01 to check its edges against the repository instead of
  inferring them. That check found the Memory INSERT door is M07's `memory_repo::insert_memory_in_txn` (L3), which
  also serves `memory.confirm`, `memory.correct` and `memory.note_put`. A direct call from there to M29 would be an
  L3 → L4 edge.
  - **Ruling:** dependency inversion through an M07-owned port. The port is a required argument and is invoked exactly
    once. M29 implements it, and composition roots supply it.
  - **Edges:** M29 → M07 and composition roots → M29, with no L3 → L4 edge (D-A, D-D).
  - **Gate:** G-M29-5 is restated to match.
- **Q2 Provisional kinds under an expand-only set.**
  - **Ruling:** provisional kinds do not enter the closed set until E-C accepts them. T02 adds only `BUSINESS`,
    `BRAND`, `PRODUCT` and `WEBSITE`.
  - `CHANNEL_ACCOUNT` and `PRODUCT_LINE` each wait for E-C. If E-C accepts one, a later ADR-amendment card adds it.
    If E-C rejects one, nothing is removed, because nothing was added (D-B).
- **Q4 Key kinds under `UNIQUE(tenant_id, key_kind, key_value)`.**
  - **Ruling:** T02 adds no new `SubjectKeyKind`. `subject_keys` uniqueness makes every key kind an exclusive identity
    key per tenant, so a namespace becomes a `SubjectKeyKind` only after E-C shows it is exclusive.
  - Shared locators (a domain served by several sites, paths, remotes) are never `SubjectKeyKind`s.
  - Key namespaces arrive with A2 (deferred), not in T02 (D-B).

## Open questions

- **Q3 `PRODUCT_LINE` as its own kind.** UNKNOWN; E-C, and it enters only under the Q2 ruling.
- **Q5 Workflow identity.** Recommended: a light registry (WorkflowId → definition versions, each pinning a
  Procedure Memory revision; runs pin both). The table shape is an engineering ruling; E-C's five workflow scenarios
  test it.
- **Q6 Trusted-host capture of the owner's words.** UNKNOWN. The experiment: an auto-accepting hook, rewritten
  content, a forged owner field, a replayed `requestState`, and a swapped principal or manifest digest must all be
  rejected.
- **Q7 `commit_seq` as a consistent cut.** UNKNOWN; concurrent-commit fixture.
- **Q8 Workspace parent of `continuity_projects`.** Kept as is in the first slice; relaxing it for cross-workspace
  projects needs its own ADR under the high-risk flow.
- Deferred with stated prerequisites (design §9): keys with validity and A2 (history ledger + current head, partial
  exclusion, first extension `btree_gist` under its own ADR); A4 capture handles; workflow registry; repository
  attribution with `(provider, node_id)`; Project → Project; retiring `private.entities` / `private.relations`
  (0006) only after a read-only count of zero, otherwise stop and ask the owner.

## References

Verified 2026-10-19 (design v0.2 source register).

- PG-CT — PostgreSQL 18, CREATE TABLE: https://www.postgresql.org/docs/18/sql-createtable.html
- PG-RT — PostgreSQL 18, Range Types: https://www.postgresql.org/docs/18/rangetypes.html
- PG-SEQ — PostgreSQL 18, Sequence Manipulation Functions: https://www.postgresql.org/docs/18/functions-sequence.html
- PG-DT — PostgreSQL 18, Current Date/Time: https://www.postgresql.org/docs/18/functions-datetime.html
- PG-CTS — PostgreSQL 18, track_commit_timestamp and committed-transaction functions:
  https://www.postgresql.org/docs/18/runtime-config-replication.html,
  https://www.postgresql.org/docs/18/functions-info.html
- TM-KM — Kulkarni & Michels, Temporal features in SQL:2011, SIGMOD Record 41(3), 2012, doi:10.1145/2380776.2380786
- MCP-MRTR — MCP 2026-07-28, Multi Round-Trip Requests:
  https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr
- MCP-EL — MCP 2026-07-28, Elicitation: https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation
- MCP-AUTH — MCP 2026-07-28, Authorization: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- MCP-OV — MCP 2026-07-28, Overview: https://modelcontextprotocol.io/specification/2026-07-28/basic/index
- MCP-ROOTS — MCP 2026-07-28, Roots: https://modelcontextprotocol.io/specification/2026-07-28/client/roots
- CC-HOOKS — Claude Code Docs, Hooks: https://code.claude.com/docs/en/hooks
- ER-FS — Fellegi & Sunter, A Theory for Record Linkage, JASA 64(328), 1969, doi:10.1080/01621459.1969.10501049
- ER-HZ — Hassanzadeh et al., Framework for evaluating clustering algorithms in duplicate detection, PVLDB 2(1), 2009:
  https://www.vldb.org/pvldb/vol2/vldb09-1025.pdf
- ZEP — Rasmussen et al., Zep: A Temporal Knowledge Graph Architecture for Agent Memory, arXiv:2501.13956v1:
  https://arxiv.org/html/2501.13956v1
- ST-SC — Geifman & El-Yaniv, Selective Classification for Deep Neural Networks: https://arxiv.org/abs/1705.08500
- ST-MN — McNemar, Psychometrika 12(2), 1947, doi:10.1007/BF02295996
- ST-LTT — Angelopoulos et al., Learn then Test: https://arxiv.org/abs/2110.01052
- SKOS — W3C Recommendation 2009-08-18: https://www.w3.org/TR/skos-reference/
- EVO — Chong et al., EvoOntology, arXiv:2609.15779v1: https://arxiv.org/html/2609.15779v1
- PROV-O — W3C Recommendation 2013-04-30: https://www.w3.org/TR/2013/REC-prov-o-20130430/
- GH-RENAME — GitHub Docs, Renaming a repository:
  https://docs.github.com/en/repositories/creating-and-managing-repositories/renaming-a-repository
- GH-REPO — GitHub REST API 2026-03-10, Repositories:
  https://docs.github.com/en/rest/repos/repos?apiVersion=2026-03-10
