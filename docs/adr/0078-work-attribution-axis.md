# ADR-0078 — Work attribution axis: module M29, relation kernel, attribution ladder and rule N09

- Status: Accepted (2026-10-19). Card M29 T01 (docs only). Content authority: design v0.2 "objects, relations and
  attribution (M29)", baseline `ea7b459`, which the owner delegated on 2026-10-19. Amended the same day with the
  design owner's rulings on review questions Q1, Q2, Q4 and Q9 (D-A, D-B, D-D) and two gap rulings (D-D).
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
  M29 → M07 also covers the A3' trigger that M29 owns on M07's `private.memory_records` (Q9 ruling, D-D). That edge
  runs in the allowed direction and has no Rust counterpart.
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

- `SubjectKind` gains **`Business`, `Brand`, `Product`, `Website`** (T02). Their DB CHECK values are the upper-case
  forms `BUSINESS` / `BRAND` / `PRODUCT` / `WEBSITE`, as 0153 stores `PERSON` / `ORGANISATION`. It remains a frozen
  closed set, expand-only, reconciled DB ↔ Rust by contract test (§78.2).
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
<pair>_relations(
  tenant_id, relation_id, revision bigint,     -- PK (tenant_id, relation_id, revision)
  src_id, dst_id, relation_kind,               -- real composite FKs with a tenant leg (§6.1.3)
  valid tstzmultirange NOT NULL,               -- valid time; '{}' = retracted
  decided_by text NOT NULL,                    -- 'rule:<id>@<ver>' | 'principal:<uuid>'
  proposed_by text NULL,                       -- 'model:<id>@<ver>', provenance only, never authority
  factual_evidence_ids uuid[] NOT NULL,
  authorization_evidence_id uuid NOT NULL,     -- kept apart from the factual evidence
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp())
```

- **Append-only.** INSERT only; an owner trigger rejects UPDATE and DELETE (same technique as 0156,
  `0156_memory_affects.sql:94`; no foreign key cascades into these rows). Current state = the highest revision per
  `relation_id`.
- **Retraction** is a new revision whose `valid` is the empty multirange `'{}'`.
- **CAS.** A write carries `expected_revision` and must insert `revision = expected_revision + 1`; the primary key
  rejects the loser of a race.
- **Interval shape.** One shared IMMUTABLE SQL function, used in a CHECK, requires every range of `valid` to be `[)`,
  with a finite lower bound and an upper bound that is finite or omitted; explicit `±infinity` is rejected.
  `tstzrange` has no canonical form, so `[)` and `[]` would otherwise compare unequal (PG-RT).
- **Whitelist.** The allowed `(src_kind, relation_kind, dst_kind)` triples are a Rust closed set
  (`domain::relation::WHITELIST`). The DB mirrors them in one IMMUTABLE function called from a BEFORE INSERT trigger,
  not a CHECK: a CHECK sees only its own row, and an endpoint's kind lives on its `private.subjects` row. The contract
  test (§78.2) evaluates that function over every endpoint kind × relation kind and compares the result with the Rust
  set.
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
of truth; `private.memory_project_revocations(tenant_id, memory_id, project_id, revoked_by, reason, recorded_at)`,
append-only. Read paths accept a link only if it exists and is not
revoked.
Since T06b (migration 0255) that rule lives only in the `security_invoker` view `private.memory_projects_live`, and an
A3' row names its predecessor in `memory_projects.inherited_from_memory_id` (design v0.2 §15.7).

`source_kind` is a frozen closed set with **no model-derived variant** (as in §6.1.3):

| Rung | `source_kind` (+ rule) | Deterministic condition | First slice |
|---|---|---|---|
| A1 | `DECLARED` | `project_id` on `remember.put`, resolved server-side: exists in the tenant and is visible to the caller; otherwise `INVALID_INPUT` with zero writes | yes |
| A2 | `EXTERNAL_KEY` | exact match of a Subject key, then a unique project via `project_subject_relations` at the Evidence's occurrence time; more than one project → unknown | deferred (needs keys with validity) |
| A3 | `INHERITED` + `task_run@1` | Evidence carries a verified `task_run_id` (`evidence_task_runs`); inherit every project with a CONTAINS relation valid at occurrence time | yes |
| A3' | `INHERITED` + `correction@1` | a `USER_CORRECTION` successor inherits the predecessor's current rows, in the M29 trigger at the supersede point (Q9 ruling) | yes |
| A4 | `INHERITED` + `capture_context@1` | server-issued capture handle bound to exactly one project and one live task run, short TTL [starting value 30 min], no exact hit on another known key | deferred |
| A5 | none (never written to `memory_projects`) | similarity, embeddings, Topic names, model inference | candidates only, deferred |

- When no rung holds, no row is written and the read path reports the memory as `unresolved` (REQ §3.4).
- **Unknown declared project (gap ruling).** A declared `project_id` that is unknown in the tenant, or not visible to
  the caller, is `INVALID_INPUT` with zero writes, as for subject ids in §6.1.3.
- **Rollups (gap ruling).** Rollups live in `private.memory_rollups`, outside the door, and stay unattributed in the
  first slice (N09 R3); they are not Memories and have no `memory_projects` row. (`consolidate_repo` imports only
  `authority_class_to_db_str` from `memory_repo`; it never calls the door.) A rollup rung needs a later ADR amendment.
- **Attribution Evidence (gap ruling, design v0.2 §15.4).** A1 and A3 read the Memory's attribution Evidence, carried
  as the required closed enum `NewMemory::attribution: AttributionSource` (`Primary` | `CandidateSource(id)`, no
  default). The door resolves `Primary` to the PRIMARY Evidence it links itself, so no caller can pass a free id, and
  every row's `decision_evidence_id` is that Evidence:
  - by default it is the PRIMARY Evidence;
  - for `memory.confirm` it is the candidate's `source_evidence_id` (E1), mirroring §6.1.3 rule 3a, which already takes
    the subject declarations from E1. E2 is the confirmation itself, and the work facts (task run, declared project)
    are on E1;
  - E1's `evidence_task_runs` carrier is never copied onto E2: that would forge a verification and add a second
    carrier writer (G-T04c-3). If E1 is invisible under the caller's RLS, the rows are simply absent (`unresolved`);
  - notes stay `unresolved` in the first slice: a note cannot carry a task run (`operation_receipt.rs:437`), and
    `memory.note_put` has no `project_id`.
- Every formal row carries `rule_id_ver` and `decision_evidence_id`, so a falsified rule can be revoked in bulk.
- **Revocation shares the correction's transaction.** Correcting a `project_task_relations` revision ("T1 never
  belonged to P1") writes, in the same transaction, a revocation row for every `memory_projects` row that A3 derived
  from it. Dependent continuity outputs keep the existing `continuity_facet_memory_links` + sha check and read as
  damaged on mismatch.
- **A1 and A3: single call site through an M07-owned port (Q1 ruling).** The workspace's only Memory INSERT is
  `adapters::memory_repo::insert_memory_in_txn` (`crates/adapters/src/memory_repo.rs:1`, `:107`; M07 D9, G-M07-1).
  Design v0.2 names it by its re-export alias `adapters::distill_repo::insert_memory`
  (`crates/adapters/src/distill_repo.rs:60`). The function is defined in an M07 (L3) file, so it cannot call M29 (L4)
  directly. Instead:
  - M07 defines an attribution port next to the door (a `MemoryAttribution` trait or fn-pointer struct).
  - `insert_memory_in_txn` takes the port as a **required** argument, never `Option` and never a default or no-op. It
    invokes the port **exactly once**, in the caller's transaction, after the memory row and its PRIMARY
    `memory_evidence` link are written (the subject hook has the same constraint, `memory_repo.rs:107-111`).
  - M29 implements the port (`link_memory_projects` behind it). Callers obtain the implementation from their
    composition root (D-A).
  - A no-op implementation in production code is forbidden. Tests use the real M29 implementation. T06 validates the
    design.
- **A3': one M29-owned trigger at the supersede point (Q9 ruling).** `correct_atomically` inserts the successor
  through the door (`memory_governance_repo.rs:1756`). It sets `superseded_by` only later, in the arbiter UPDATE
  (`:1800`), and `NewMemory` carries no predecessor (`memory_repo.rs:52-63`). A3' therefore cannot run at the door.
  - It runs in a single M29-owned DB trigger on that UPDATE, mirroring §6.1.3 rule ③ (`0154_memory_subjects.sql:314-331`).
  - For a `USER_CORRECTION` successor, the trigger copies the predecessor's current `memory_projects` rows (linked
    and not revoked) to the successor as `INHERITED` + `correction@1`.
  - It fires only when the correction becomes current. A correction the arbiter does not make current inherits
    nothing.
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

## Gates

All are three-state. Each gate exists only after its inject → red → fix → green record (§80.1) lands in the card that
implements it, and that card adds it to "Red records" below, as ADR-0077 does. Existing: G-M29-2, G-M29-3, G-M29-4
and the relation-whitelist half of G-M29-1 (T05); the `source_kind` half of G-M29-1, G-M29-5(a), G-N09-1 and G-N09-3
(T06a); G-T06d-1..4, with G-M29-4 strengthened (T06d); G-M29-5(b) and G-M29-6 (T06b). The rest are a plan. Module gate ids such as `G-M29-2` fall outside
the §80.1 anchor grammar (`G<n>-<n>`), so like ADR-0077's `G-M01-4` they are not §80.1 registry rows; registering
module gates there needs its own spec change.

| Gate | Criterion | Injected fault |
|---|---|---|
| G-M29-1 closed-set reconciliation | Rust enums of `SubjectKind`, `SubjectKeyKind` and `source_kind` == DB CHECKs; the relation whitelist == `private.relation_triple_allowed` over every kind × relation kind (§78.2) | add a kind or triple in the DB only |
| G-M29-2 interval shape | `[]`, explicit infinity and an unbounded lower bound are rejected by the CHECK | drop the `upper_inc` test from the CHECK function |
| G-M29-3 CAS | two connections writing with the same `expected_revision` concurrently: exactly one succeeds | drop the revision check |
| G-M29-4 append-only | no non-owner role holds UPDATE (any column) or DELETE on any relation table (`has_*_privilege`, as the manifest postchecks ask, issue #92 item 1); the owner's UPDATE / DELETE hit the trigger | grant UPDATE |
| G-T06d-1 authorisation Evidence | on each relation table, an `authorization_evidence_id` that is no Evidence or another tenant's is `INVALID_INPUT` | drop 0253's FK line |
| G-T06d-2 factual Evidence | on each table, a factual id that is no Evidence, another tenant's, this tenant's but invisible to the writer, or repeated is `INVALID_INPUT` | drop the guard's factual check |
| G-T06d-3 principal membership | on each table, a `principal:` decider that is a user ACTIVE only elsewhere, an INVITED / SUSPENDED / REMOVED member, a SUSPENDED user (directly or through a live key), a key of a non-member, a machine key, a revoked key, another tenant's key, or a member of a SUSPENDED tenant is `INVALID_INPUT`; a malformed value is `INVALID_INPUT`, not 22P02; the predicate is false for a tenant other than the session's | drop the guard's membership check, one predicate leg, or the cast guard |
| G-T06d-4 authorisation ∉ factual | the authorisation Evidence among the factual ones is `INVALID_INPUT` | drop 0253's CHECK line |
| G-M29-5 single attribution sites | two counts, both `== 1`: (a) the attribution port is invoked once, inside `memory_repo::insert_memory_in_txn`, with a required parameter (A1, A3); (b) exactly one A3' inheritance site, the M29 trigger on the supersede transition | (1) a second port invocation; (2) the port parameter made `Option` / defaulted; (3) a second A3' site, as a Rust call or another trigger; (4) the A3' trigger removed, so a fixture correction leaves the successor `unresolved` |
| G-M29-6 same-transaction revocation | after correcting a project_task revision, every `memory_projects` row derived from it has a revocation row in the same transaction | move the revocation to a second transaction |
| G-N09-1 no model source | `source_kind` has no model-derived variant; an architecture check finds no provider / inference import on the `memory_projects` write path | add `ModelExtracted` |
| G-N09-2 candidate isolation | authoritative read-path functions never reference the candidates table (architecture_check rule) | join candidates in recall hydrate |
| G-N09-3 unknown stays unknown | same-name trap fixture: two projects with one name and no deterministic ground → zero formal rows, reported `unresolved` | "take the most recent project" |
| G-N09-4 models off, same result | with every provider off, formal attribution is row-for-row identical and external calls = 0 (E-D) | make A3 call a model once |

## Red records

Each fault is injected on its own throwaway branch off the card's green head and run through `targeted.yml`; run ids
and the failing lines are in the card's PR description.

- T05 (PR #80), branches `red/m29-t05-r1..r4` off `e7b79cb`:
  - r1: an extra DB-only triple `('PROJECT','TARGETS','CHANNEL_ACCOUNT')` in `private.relation_triple_allowed` ->
    G-M29-1 (whitelist half) red: the DB set has a triple the Rust set lacks.
  - r2: `AND NOT upper_inc(r)` dropped from `private.relation_valid_shape` -> G-M29-2 red: an upper-inclusive range is
    accepted.
  - r3: a red-only later migration widens the primary key with `recorded_at` -> G-M29-3 red: both concurrent writers
    of one `expected_revision` win.
  - r4: a red-only later migration grants UPDATE on `private.project_task_relations` to `role_gateway` -> G-M29-4 red:
    the UPDATE reaches the trigger (23514) instead of failing on privilege (42501).
  - r3 and r4 are later migrations because 0249's own postcheck pins the key shape and the grants, so the same fault
    inside 0249 stops the migration before any test runs.
- T06a (PR #96), branches `red/m29-t06a-r1..r9` off `cef110f`:
  - r1: a second `attribution.link_memory_projects(..)` call in `insert_memory_in_txn` -> G-M29-5(a) red: found 2.
  - r2: the door's port parameter as `impl Into<Option<&dyn MemoryAttribution>>` -> G-M29-5(a) red: the port
    parameter is optional.
  - r3: `'MODEL_GUESS'` added to `memory_projects_source_kind_check` -> G-M29-1 (`source_kind` half) red: the DB set
    has a value `SourceKind::ALL` lacks.
  - r4: a `ModelExtracted` variant in `SourceKind` -> G-N09-1 red: the set is no longer the frozen three.
  - r5: `AND cur.valid @> e.occurred_at` dropped from A3 -> G-T06a-A3 red: an Evidence outside P1's CONTAINS window
    still inherits P1.
  - r6: A1's `WHERE false AND ...` -> G-T06a-A1 red: the declared project writes no row.
  - r7: A1 reads the most recently related project instead of `evidence_projects` -> G-N09-3 red: an Evidence with no
    ground is attributed to one of two same-title projects.
  - r8: the guard's NULL-tenant line dropped -> #92 item 4 red: a NULL-tenant append is CONFLICT, not FORBIDDEN.
  - r9: `project_task_relations_one_relation_per_edge` predicate `revision = 0` -> #92 item 5 red: a second
    `relation_id` for one edge is accepted.
  - r2 changes two lines (the parameter and the call's `.into().expect(..)`): `xtask` links `humaux-adapters`, so a
    one-line `Option` parameter fails to compile before the arm runs. r3, r8 and r9 stay inside 0252 because its
    postcheck deliberately leaves the CHECK values, the guard body and the index predicate to these tests.
- T06a review fixes (PR #96), branches `red/m29-t06a-r10..r17` off `4a54d50`:
  - r10: `AND ptr.dst_id = tr.task_id` dropped from A3 -> G-T06a-A3 red: P3, which CONTAINS another task, is
    inherited too.
  - r11: A1's `ep.evidence_id = $3` replaced by `$3::uuid IS NOT NULL` -> G-T06a-A1 red: P4, declared on another
    Evidence, is attributed. `$3` stays referenced so the query still types.
  - r12: A1's `AND ep.source_kind = $4` dropped -> G-T06a-A1 red: P5, an INHERITED row on this Evidence, comes back
    as DECLARED.
  - r13: A3's NULL guard as `cur.valid @> COALESCE(e.occurred_at, clock_timestamp())` -> G-T06a-A3 red: a put with
    no `occurred_at` inherits under a currently valid CONTAINS (N09 R3).
  - r14: `subject_relations_one_relation_per_edge` predicate `revision = 0` -> #92 item 5 red, now per pair:
    `SubjectSubject` accepts a second `relation_id` for one edge.
  - r15, re-cut as `red/m29-t06a-r15b` off `9bed6b7` after the closed `AttributionSource` replaced the free id (the
    first cut passed E2's id through that field): confirm passes `AttributionSource::Primary` -> G-T06a-confirm red:
    no row, since E2 carries no task run.
  - r16: `ON CONFLICT (tenant_id, memory_id, project_id) DO NOTHING` dropped -> G-T06a-A3 red: A1 and A3 on one
    project fail on `memory_projects_pkey` instead of keeping the A1 row.
  - r17: `use crate::byok;` in `attribution_repo.rs` -> G-N09-1 red: the attribution code names a model module.
  - The `AttributionSource` change leaves the fault lines of r10-r14, r16 and r17 verbatim (each still applies once on
    `9bed6b7`), so those records stand without a re-run.
- T06d (PR #100), branches `red/m29-t06d-r1..r7` and `r3a..r3e` off `b52d025`:
  - r1: 0253's FK line dropped -> G-T06d-1 red: an `authorization_evidence_id` that is no Evidence is accepted.
  - r2: the guard's factual check dropped -> G-T06d-2 red: a factual id that is no Evidence is accepted.
  - r3: the guard's membership check dropped -> G-T06d-3 red: a user ACTIVE only in another tenant decides.
  - r3a: the predicate's `m.tenant_id = p_tenant_id` as `true` -> G-T06d-3 red: the same decoy decides.
  - r3b: `AND m.state = 'ACTIVE'` dropped -> G-T06d-3 red: a SUSPENDED member decides.
  - r3c: `AND k.revoked_at IS NULL` dropped -> G-T06d-3 red: a revoked key decides.
  - r3d: `AND k.tenant_id = p_tenant_id` dropped -> G-T06d-3 red: another tenant's key, bound to a member here,
    decides.
  - r3e: the session-tenant pin as `SELECT true` -> G-T06d-3 red: the predicate answers true for another tenant.
  - r4: 0253's CHECK line dropped -> G-T06d-4 red: the authorisation Evidence is accepted among the factual ones.
  - r5: a red-only line in 0253 grants UPDATE on `private.subject_relations` to `role_admin` -> G-M29-4 red: the
    privilege is held (issue #92 item 1: the old behavioural check could not see it, because `role_admin` has no
    USAGE on `private`).
  - r6: `Validity::new`'s `t >= PG_TIMESTAMPTZ_MIN_MICROS` guard dropped -> #92 item 2 red: `Micros(i64::MIN)` is
    admitted.
  - r7: the guard compares `relation_kind` only -> #92 item 3 red: a revision that moves `src_id` is accepted.
  - r2 and r3 each remove one whole statement (6 and 3 lines); the others change one line. All stay inside 0253 or
    `Validity::new`, because 0253's postcheck leaves the FKs, the CHECKs, the guard body and the predicate body to
    these tests.
  - Later commits change fixtures, a dep tag, headers and generated docs, and the review fixes below add two
    predicate legs and more decoys; every fault line above still applies once on the final head, so these records
    stand without a re-run.
- T06d review fixes (PR #100), branches `red/m29-t06d-r3f..r3h`, `r8` and `r9` off `5bfbc1a`:
  - r3f: `AND u.state = 'ACTIVE'` dropped from the predicate -> G-T06d-3 red: a SUSPENDED user whose membership is
    ACTIVE decides.
  - r3g: `AND t.state = 'ACTIVE'` dropped -> G-T06d-3 red: an ACTIVE member of a SUSPENDED tenant decides.
  - r3h: the key leg's `k.user_id` as `coalesce(k.user_id, m.user_id)` -> G-T06d-3 red: a machine key (no user)
    decides as any live member.
  - r8: a red-only later migration grants EXECUTE on `private.relation_principal_is_member` to `role_admin` ->
    rls-check "§6.1.4 relation principal predicate" red, run through
    `rls_check::tests::relation_principal_predicate_gate_holds_on_the_migrated_schema` (the same call `cargo xtask
    rls-check` makes in the CI gates job, which `targeted.yml` cannot reach). It is a later migration because
    0253's postcheck pins that EXECUTE list.
  - r9: the guard's `pg_input_is_valid` test as `IF true` -> G-T06d-3 red: `principal:not-a-uuid` raises 22P02
    (INTERNAL) instead of 23503.
  - The INVITED / REMOVED members, the key bound to a SUSPENDED user and the key of a non-member are refused by legs
    r3b, r3f and r3a already break; the factual Evidence the writer cannot see is refused by the check r2 drops.
- T06b (PR #104), branches `red/m29-t06b-r1..r11` off `589a456`:
  - r1: 0255's `CREATE TRIGGER memory_projects_on_supersede` dropped -> G-M29-5(b) red: the correction's M2 inherits
    nothing.
  - r2: a red-only later migration adds a second trigger on `private.memory_records` executing the A3' function ->
    rls-check "§6.1.4 A3' single site" red (`correction_inheritance_site_gate_holds_on_the_migrated_schema`): found 2.
  - r3: the live view's `NOT EXISTS` as `true OR NOT EXISTS` -> G-M29-5(b) red: the retracted P1 link is inherited too.
  - r4: 0255's `CREATE TRIGGER project_task_relations_revoke_attributions` dropped -> G-M29-6 red: the narrowing
    revision revokes nothing.
  - r5: the window leg `NOT (NEW.valid @> e.occurred_at)` as `true` -> G-M29-6 red: the row whose Evidence stays
    inside the narrowed window is revoked too.
  - r6: `tr.task_id = NEW.dst_id` as `true` -> G-M29-6 red: the row derived through T2, which P1 also CONTAINS, is
    revoked too.
  - r7: `l.rule_id_ver = 'task_run@1'` as `true` -> G-M29-6 red: the DECLARED row on the same Evidence is revoked too.
  - r8: the relation-correction function as `SECURITY INVOKER` -> G-M29-6 red: the revision fails `FORBIDDEN`, since
    the writing role_gateway holds no INSERT on `private.memory_project_revocations`.
  - r9: 0255's `CREATE TRIGGER memory_project_revocations_follow_inheritance` dropped -> G-M29-6 (chain) red: only M1
    is revoked, not its corrections M2 and M3.
  - r10: a red-only later migration grants EXECUTE on `private.revoke_attributions_on_relation_correction()` to
    `role_admin` -> rls-check "§6.1.4 attribution revocation definers" red
    (`attribution_revocation_definers_gate_holds_on_the_migrated_schema`).
  - r11: the relation-correction function's session-tenant pin as `IF false AND ...` -> the session-tenant test red:
    an owner write under another session tenant is not refused 42501.
  - r1, r4 and r9 each remove one whole statement (6, 6 and 5 lines); r3, r5-r8 and r11 change one line inside 0255,
    whose postcheck leaves the triggers, the view body, the function bodies and the definers' SECURITY DEFINER to these
    tests. r2 and r10 are later migrations: 0255's postcheck pins the EXECUTE list, and a second site arrives as a
    later migration.

## Consequences

- The first wire reader of attributions reads `memory_projects_live`, and its card adds an xtask arm forbidding direct
  reads of the table (design v0.2 §15.7).

## Cards and experiments

- **T01** (docs): this ADR, Baseline §6.1.4 with N09, the `context_bindings` boundary sentence (§25.4).
- **T02** (M07): `SubjectKind` += `Business`, `Brand`, `Product`, `Website`; no new `SubjectKeyKind` (D-B);
  migration, domain enum, contract test, and an update to §6.1.3's frozen-set sentence. Gate G-M29-1.
- **T03** (contract): `continuity_projects` contract ownership M14 → M29; contract and module registration only.
  The first M29 ownership row needs two other changes:
  - raise `MODULE_ID_MAX` (`xtask/src/architecture_check.rs:881` on main);
  - update the fixtures that reject `M29` (`:8815`, `:8986`).
- **T04** (M18 + M06): minimal task-run lifecycle (principal, lease, verification port) and the `evidence_task_runs`
  carrier; a write after lease expiry does not inherit.
- **T05** (M29): relation kernel, SQL template + Rust kernel + the three pairs. Gates G-M29-2/3/4.
- **T06** (M29 + M15): attribution tables; A1 and A3 in `link_memory_projects` behind the M07 attribution port, with
  the door's required port argument and the composition-root wiring; A3' in the M29 supersede trigger (D-D). Gates
  G-M29-5/6, G-N09-1/3.
- **T06d** (M29): relation provenance integrity, migration 0253 (design v0.2 §15.2 / §15.5). Gates G-T06d-1..4,
  G-M29-4 strengthened, issue #92 items 2 and 3. Workspace visibility of both endpoints stays the caller's
  precondition of `append_revision` (`coord.tasks` has no workspace column). No runtime caller exists yet, so the
  first card that wires one must test that the caller refuses an endpoint outside its authorised workspaces, and
  that caller must install the visibility GUCs (`humaux.tenant_id` and `humaux.user_id`, which the 0163 policy's
  USER_PRIVATE and WORKSPACE_SHARED arms read) before the append: the factual check runs under RLS, so without them a
  legitimate USER_PRIVATE or WORKSPACE_SHARED factual id is refused.
- **T07** (M29): first E2E on a synthetic fixture (website A, projects P1 / P2, shared task T1, same-name trap
  project, three messages, one correction, plus replay, revoked access and faults). Gates G-N09-3/4.
- **E-A** precision per ladder rung (A1 / A3 / A3' × relation kind × source scope), binding correctness and
  conditional attribution judged separately; cluster sampling with one decision per cluster; CP one-sided upper
  bound ≤ 0.5% [starting value] per cell with LTT multiplicity control.
- **E-B** (deferred, with A5) paired comparison of candidate generators by exact conditional McNemar, reporting
  coverage beside precision.
- **E-C** object-kind coverage on the owner's real portfolio: acceptance of `PRODUCT_LINE` and `CHANNEL_ACCOUNT`,
  exclusivity of each candidate key namespace (`DOMAIN` first),
  the five workflow and six repository scenarios; κ reported only as human–model agreement, diagnostic only. Exit
  gate: owner-ruled classification coverage, and every key scenario passes. D-B's "E-C accepts" means passing this
  gate.
- **E-D** models-off consistency, row-for-row and zero external calls (G-N09-4).
- **E-F** vocabulary evolution gate (D-H).

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
- **Q9 A3' timing (review P1).**
  - **Finding:** at the door, the successor has no predecessor yet; `superseded_by` is set later by the arbiter
    UPDATE.
  - **Ruling:** A3' runs in a single M29-owned DB trigger at the supersede point, mirroring §6.1.3 rule ③. It copies
    the predecessor's current rows as `INHERITED` + `correction@1` (D-D).
  - **Edges:** an M29 trigger on M07's table is an M29 → M07 dependency, and there is no Rust edge.
  - **Rationale:** it follows the subject precedent, and it fires only when the correction actually becomes current.
  - **Gate:** G-M29-5 counts this site separately, as (b).
- **Q10 `coordinate.task_*` wire format vs §30.2 (T04b pre-check).**
  - **Finding:** the declared-only `contracts/mcp/coordinate.schema.json` addressed `task_heartbeat`, `task_complete` and
    `task_fail` by `task_id` alone. §30.2 rejects a stale holder's write by its old token; with no token on the wire the
    gateway would have to pick "the caller's open run", and a second session of the same principal could renew or close
    the other session's run. `task_submit.description` and `task_complete` / `task_fail.summary` were required on the
    wire but had no column.
  - **Ruling:** `task_claim` returns `task_run_id`, `fencing_token` and `lease_expires_at`. `task_heartbeat`,
    `task_complete` and `task_fail` require `task_run_id` and `fencing_token` next to `task_id`; a run that does not
    belong to `task_id` is `NOT_FOUND`. `description` persists on `coord.tasks.description`, `summary` on
    `coord.task_runs.outcome_summary` (nullable; rows written before 0250 have none). The five keys leave the
    declared-only list in the same change.
  - **Rationale:** the contract had no caller, so nothing breaks; §30.2 outranks a contract derived from it.

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

Verified 2026-10-19 against the design v0.2 source register. Read depth follows the register's marks; an unmarked entry
was read in the part the text relies on.

- PG-CT — PostgreSQL 18, CREATE TABLE: https://www.postgresql.org/docs/18/sql-createtable.html
- PG-RT — PostgreSQL 18, Range Types: https://www.postgresql.org/docs/18/rangetypes.html
- PG-SEQ — PostgreSQL 18, Sequence Manipulation Functions: https://www.postgresql.org/docs/18/functions-sequence.html
- PG-DT — PostgreSQL 18, Current Date/Time: https://www.postgresql.org/docs/18/functions-datetime.html
- PG-CTS — PostgreSQL 18, track_commit_timestamp and committed-transaction functions:
  https://www.postgresql.org/docs/18/runtime-config-replication.html,
  https://www.postgresql.org/docs/18/functions-info.html
- TM-KM — Kulkarni & Michels, Temporal features in SQL:2011, SIGMOD Record 41(3), 2012, doi:10.1145/2380776.2380786
  (bibliography checked; full text not read)
- MCP-MRTR — MCP 2026-07-28, Multi Round-Trip Requests:
  https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr
- MCP-EL — MCP 2026-07-28, Elicitation: https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation
- MCP-AUTH — MCP 2026-07-28, Authorization: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- MCP-OV — MCP 2026-07-28, Overview: https://modelcontextprotocol.io/specification/2026-07-28/basic/index
- MCP-ROOTS — MCP 2026-07-28, Roots: https://modelcontextprotocol.io/specification/2026-07-28/client/roots
- CC-HOOKS — Claude Code Docs, Hooks: https://code.claude.com/docs/en/hooks (partial read: the first 100K characters)
- ER-FS — Fellegi & Sunter, A Theory for Record Linkage, JASA 64(328), 1969, doi:10.1080/01621459.1969.10501049
  (bibliography checked; full text not read)
- ER-HZ — Hassanzadeh et al., Framework for evaluating clustering algorithms in duplicate detection, PVLDB 2(1), 2009:
  https://www.vldb.org/pvldb/vol2/vldb09-1025.pdf (§2.1.1 read)
- ZEP — Rasmussen et al., Zep: A Temporal Knowledge Graph Architecture for Agent Memory, arXiv:2501.13956v1:
  https://arxiv.org/html/2501.13956v1 (§2.2.2–2.2.3 and the appendix prompts read)
- ST-SC — Geifman & El-Yaniv, Selective Classification for Deep Neural Networks: https://arxiv.org/abs/1705.08500 (abstract checked)
- ST-MN — McNemar, Psychometrika 12(2), 1947, doi:10.1007/BF02295996 (bibliography checked; full text not read)
- ST-LTT — Angelopoulos et al., Learn then Test: https://arxiv.org/abs/2110.01052 (abstract checked)
- SKOS — W3C Recommendation 2009-08-18: https://www.w3.org/TR/skos-reference/ (partial read: the latter part of the page
  is unread)
- EVO — Chong et al., EvoOntology, arXiv:2609.15779v1: https://arxiv.org/html/2609.15779v1
- PROV-O — W3C Recommendation 2013-04-30: https://www.w3.org/TR/2013/REC-prov-o-20130430/ (term definitions read)
- GH-RENAME — GitHub Docs, Renaming a repository:
  https://docs.github.com/en/repositories/creating-and-managing-repositories/renaming-a-repository
- GH-REPO — GitHub REST API 2026-03-10, Repositories:
  https://docs.github.com/en/rest/repos/repos?apiVersion=2026-03-10 (response structure checked)
