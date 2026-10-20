# ADR-0079 — User-uploaded documents: identity layers, receipt, locator, adoption, derived Memory, association and deletion

- Status: Accepted (2026-10-20). Card T-DOC-0 (docs only). Content authority: design v0.2 §17 "User-uploaded documents:
  identity, version, locator, association, current basis, deletion" (private file, sha256 prefix `330f6bbe`), decided by
  the design owner, with the repository owner's delegation, after two independent review rounds. Every gate in this ADR
  is planned: none exists until its §80.1 record lands with the implementing card (see Gates).
- Relates to: Baseline §6.1.1 (visibility), §6.1.3 (Subject axis), §6.1.4 (work attribution axis), §8.1
  (`payload_sha256`), §8.3 (Artifact; the normative home of this ADR is the new §8.3.1), §8.4 (Observation), §8.6
  (`memory_evidence`), §8.8 (grounding validity), §10.1 (authority ceiling), §11.10 (grounding revalidation), §37
  (deletion), §78.1, §78.2, §80.1; ADR-0027 / ADR-0028 (Subject axis and Memory↔Subject linkage), ADR-0057 D-B
  (lifecycle ticket on the PRIMARY Evidence), ADR-0078 (M29: relation kernel, attribution ladder, rule N09).

## Context

The owner's requirement of 2026-10-20, in three parts: user-uploaded documents had not been designed; an uploaded
document may relate to a project, a task or to knowledge, and those relations must be worked out; and the
unique-authority rule applies throughout (every fact has one home, everything else is derived from it or cites it).

Facts about the owner's legacy store, aggregates only (private evaluation notes; no titles, paths or memory text leave
that store):

- 1,057 documents, 99.1% of them Markdown.
- 103 file names uploaded more than once; 109 version-like file families covering 334 files. Both are heuristics, so
  they are candidate sets only; the two overlap.
- About a thousand legacy memories carry document-layer provenance; 1,007 of the 1,018 that carry a storage URI resolve
  deterministically to a document row. The legacy store has no `derived_from` links and no supersession records.

The repository already has most of the substrate, so this ADR adds no identity registry and no second Evidence path:

- **Evidence and Artifact (§8.1, §8.3).** `private.artifacts` is an Evidence (`artifact_id == evidence_id`); the server
  computes `payload_sha256` over the raw bytes at the single construction point, with no normalisation. A parser's
  output is an Observation (§8.4).
- **Memory ↔ Evidence (§8.6, §8.8).** `memory_evidence` carries `role`, `grounding_mode` (`LIVE | SNAPSHOT |
  IMMUTABLE`) and `recorded_version`; §11.10 revalidates grounding deterministically (`RECHECK_REQUIRED`, finalization
  CAS).
- **Subject axis (§6.1.3, ADR-0027/0028).** `private.subjects` has tenant-level RLS only, no visibility column, and a
  `NOT NULL display_name` (migration 0153). Today a subject's visibility is "same tenant".
- **Work attribution (§6.1.4, ADR-0078).** The relation kernel (including `project_subject_relations`), `memory_projects`
  (A1 / A3 / A3'), `evidence_task_runs` and rule N09.
- **Authority ceiling and deletion (§10.1, §37).** An `UploadedArtifact` is capped at `PrivateKnowledge + DATA_ONLY`;
  deletion has one exit, `retention::tombstone`, and an eight-step `DeletionPlan` (migration 0054).
- **EvidenceMode (design v0.2 §16.9).** The closed set `HostObserved / ClientDeclared / UserReported / Imported`,
  introduced by the external-tool axis. It has no Rust type in the repository yet (see the note under Gates).

What is missing is narrower: a logical document with versions that is not its bytes; a record of how the bytes arrived
and how far they can be trusted; a stable locator into extracted text; a grounded "which version is in force, for which
scope"; Memory derived from spans of a document; the three families of association with projects, tasks, runs and
knowledge; and deletion semantics for a Memory that depends on several sources.

## Decision

### D-A (D-DOC-1) Four identity layers, each with its own identifier

| Layer | What it is | Home | Identity |
|---|---|---|---|
| Document | the logical document ("the design document", "this book") | `private.subjects`, kind `DOCUMENT` (a `SubjectKind` extension, authorised here) | `subject_id`. Registered only explicitly, or by an exact external key. The first slice extends only `subject_keys.key_kind` with `LEGACY_DOCUMENT_ROW`, i.e. `legacy:<instance>:document-row:<old row id>`; Notion, Drive and similar wait until they are connected. **Never registered or merged by file name, path, hash or similarity** (N09; a path is a locator only, the GH-RENAME lesson of ADR-0078 D-B). `DOCUMENT` does not use `subjects.merged_into`: the DB rejects a `merged_into` on a row of kind `DOCUMENT` and rejects such a row as a merge target (G-DOC-17). Document merge is deferred and will go through explicit governance |
| Version | one independent version identity | new table `private.document_versions` | `version_id` (uuidv7). The owning `document_id` is immutable once written. A → B → A is 3 versions and 2 byte contents |
| Received bytes | one receipt event and its bytes | the existing `private.artifacts` (which is an Evidence) | `evidence_id`. Byte identity = `payload_sha256`. **Every receipt is a separate Evidence**, with its own visibility and origin, and is not deduplicated across uploads |
| Extraction | the text representation deterministically parsed from the bytes | a §8.4 Observation plus the typed side table `private.document_extractions` | `observation_id`. Immutable; one row per (source Evidence, processor, processor version, `config_sha256`) |

- **The title does not go on the subject row.** `private.subjects` has only tenant-level RLS and `display_name` is
  `NOT NULL` (§6.1.3: today a subject's visibility is the tenant).
  - A `DOCUMENT` subject's `display_name` holds only an opaque placeholder, `document:<first 8 characters of subject_id>`.
  - The title and the version label live on `document_versions`. That table carries the §6.1.1 visibility columns, with
    the same values as its receipt Evidence, enforced by the DB.
  - **Every `document_*` table uses the RLS shape of migrations 0154 and 0252:** the NULLIF tenant predicate AND an
    EXISTS "the parent object is visible to the reader". The parent of each table:
    - `document_receipts`, `document_extractions`, `document_nodes`, `document_excerpts`: the owning version row
      (`document_excerpts` additionally requires the excerpt Evidence to be visible);
    - `document_state`: the head version row; a row without a head (UNKNOWN / CONFLICT) requires the document to have at
      least one version visible to the reader; a `PROJECT`-scope row also requires the project to be visible;
    - `document_adoptions`: the adopted version row, plus `basis_evidence_id`;
    - `run_document_io`: the version row, plus the Evidence the run is bound to;
    - `citations`: `basis_evidence_id`;
    - `memory_source_spans`: the owning Memory (the same Memory parent as in 0154).
  - Consequence: another reader in the same tenant can at most learn that "a document exists" (the subject row) and
    which projects and tasks it is linked to: the relation-kernel `DOCUMENTED_BY` / `ATTACHES` rows follow the 0249
    table template, whose policy is tenant-only, and carry ids, `decided_by` and Evidence ids, never content. They see
    no title, version, adoption state, pin, generation or content.
    ponytail: existence and links are visible inside a tenant; the upgrade signal is several people in one tenant with
    private documents; the upgrade path is a per-subject ACL hook (§6.1.3) plus a RESTRICTIVE parent-visibility policy
    on the relation tables for `DOCUMENT` endpoints.
  - A reader who can see v1 but not the head v2 cannot read the `GLOBAL` state row, so for that reader the current
    version is UNKNOWN. The existence of v2 does not leak.
- **Rendition** (one version in several formats, say md and pdf): in the first slice every version has exactly one
  receipt Evidence, `document_versions.source_evidence_id`. A multi-rendition table is deferred.
- **Equal text hash across formats** is neither necessary nor sufficient for "same version" and is not used to decide it.
- **Physical deduplication is deferred.** No interface answers "does this hash already exist", because that is a
  deduplication side channel. Each receipt stores its own object.
  ponytail: storage grows linearly with the number of copies; the upgrade signal is a growing share of storage taken by
  same-byte duplicates; on upgrade a reference count enters §37 step 6.

### D-B (D-DOC-2) Receipt: orthogonal fields, not one "entry mode"

A new side table `private.document_receipts(evidence_id PK)` with these fields:

- `ingest_channel`: `UPLOAD_API | MCP_TEXT | HOST_HOOK | MIGRATION`.
- `received_payload_kind`: `ORIGINAL_BYTES | FULL_TEXT | EXCERPT | SUMMARY`.
- `original_bytes_verified`: bool; true only if the server itself received the original bytes.
- `coverage`: `FULL | PARTIAL | UNKNOWN`.
- `source_claims`: jsonb, stores verbatim what the client reported (path, original hash, author, version label). **The
  domain never interprets it**, as with `events.payload`.
- `attribution_mode` (`WHOLE | SPAN`) is part of the same record, written with it and immutable (D-G).

Rules:

- The server computes `payload_sha256` over the bytes it actually received (the single construction point, §8.1). The
  object store's ETag is not a substitute: the ETag of a multipart upload is not an MD5.
- A summary relayed by an agent can at most prove "this text was received". A citation that lands on that summary **must
  not** become a verified citation of the form "section 4.2 of the original file".
- The authority ceiling stays as in §10.1: `UploadedArtifact → PrivateKnowledge + DATA_ONLY`. A document that says
  "ignore the previous rules" is still only data.

### D-C (D-DOC-3) Locator: a selector bound to an Extraction, in Unicode code points

- selector = `(extraction_id, start_cp, end_cp, exact_sha256)`, with optional prefix and suffix.
  - The coordinate system is fixed to Unicode code points, start inclusive, end exclusive (the Web Annotation
    TextPositionSelector).
  - A Rust byte offset must be converted explicitly.
- When a locator is ambiguous (repeated paragraphs), return every candidate or fail. **Never silently take the first.**
- A parser upgrade produces a new Extraction. Old citations keep resolving to the old Extraction and **are not
  re-bound**.
- **Structure nodes** are a derived index, `private.document_nodes`, which can be deleted and rebuilt.
  - The node kinds are a Rust closed-set enum named after DoCO 1.4.0: section, heading, paragraph, list item, table,
    table cell, figure, caption, footnote, code block, block quote. No RDF is introduced.
  - A node id = (`extraction_id`, ordinal along the structure path). It is not a paragraph-text hash, because repeated
    paragraphs would collide.
  - Heading levels are only those the document itself declares (Markdown ATX / Setext). A level inferred from layout can
    at most be a candidate later.
- **Extraction of md and plain text:** strict UTF-8 decoding, no normalisation. The text is the original bytes,
  `text_sha256 == payload_sha256`, and the text locator points straight at the original object; no second copy is
  stored.

### D-D (D-DOC-4) Current version: a separate, grounded adoption record; "unique authority" = exactly one grounded selection state per scope

- `private.document_state`: **one row per scope**, each with its own generation.
  - Fields: `document_id`, `scope_kind` (`GLOBAL | PROJECT`), `scope_project_id`, `authority_state` (`UNKNOWN |
    RESOLVED | CONFLICT`), `head_version_id`, `head_generation`.
  - Unique key `UNIQUE NULLS NOT DISTINCT (tenant_id, document_id, scope_project_id)` and `CHECK ((scope_kind =
    'GLOBAL') = (scope_project_id IS NULL))`.
  - `CHECK ((authority_state = 'RESOLVED') = (head_version_id IS NOT NULL))`.
  - Composite FK `(document_id, head_version_id) → document_versions(document_id, version_id)`.
  - **State is the sole authority.** The log is audit only, and both are written in the same transaction.
  - A project pin is the row with scope = `PROJECT`. It advances its own generation and does not touch the `GLOBAL` row.
    A project's UNKNOWN / CONFLICT also lives on that row.
- `private.document_adoptions`: an append-only audit log.
  - Fields: scope, `version_id`, `basis_evidence_id`, `decided_by` (the relation kernel's closed format, ADR-0078 D-C),
    `expected_generation`.
- **The basis of an adoption** is one of three:
  - an explicit declaration by a client with the permission (`adopt: true` in the upload request counts as explicit);
  - a user confirmation;
  - a sync rule the user confirmed beforehand (for example "the latest immutable Drive revision is adopted").
- **Not a basis:** upload time, a version number in the file name, a model's judgement. **Upload without a declaration
  only adds a Version; the head does not move.**
- Concurrency: an adoption request carries `expected_head_generation` and runs as a conditional UPDATE.
  - Zero rows returned leads to a conflict or a proposal; **there is no unconditional retry that overwrites.**
  - `head_generation` also recognises a stale request after v1 → v2 → v1.
- An exclusion constraint on historical adoption intervals needs btree_gist (PostgreSQL 18 supports uuid there).
  **Deferred.**
  - In the first slice, "which version was adopted at time T" comes from replaying the append-only log in order.
  - Upgrade signal: a product-level as-of query.

### D-E (D-DOC-5) Document-derived Memory: content source + spans + SNAPSHOT grounding

- The content source reuses `memory_evidence`: role PRIMARY is the receipt Evidence in whole mode and the excerpt
  Evidence in span mode (D-G); `grounding_mode = SNAPSHOT`; `recorded_version = version_id`.
- New `private.memory_source_spans(memory_id, evidence_id, extraction_id, start_cp, end_cp, exact_sha256, ordinal)`. One
  Memory may cite several non-contiguous spans, for example the method steps plus an exception in a footnote.
- **Invariant: a span is not a second dependency path.** In the same transaction, every `memory_source_spans` row must
  have a `memory_evidence` row pointing at the receipt Evidence that holds the span, or at one of that receipt's excerpt
  Evidence. A constraint trigger checks it at commit. Deletion therefore only walks `memory_evidence`; the span table is
  used only to locate text in the original.
- **What SNAPSHOT means:** "this Memory states what v1 said". The arrival of v2 does not make it stale (§8.8
  GroundingMode).
  - Only a Memory that explicitly claims "what the document says **now**" uses LIVE. Then a head move makes §11.10 set
    `RECHECK_REQUIRED` deterministically, with no model call.
  - The first slice uses SNAPSHOT only.
- **Unit granularity:** the smallest independently usable assertion or procedure, keeping its premises, step order,
  exceptions and scope of applicability. It is not one Memory per sentence: a counter-example is "only after positioning
  is complete, use M" being distilled to "use M" with every locator correct and the meaning wrong.
  - The type reuses the existing `memory_type` closed set (FACT / PROCEDURE / CONSTRAINT / DECISION / LESSON / REFERENCE
    …); **no new unit-type enum.**
- **Distillation:** in the first slice every version is re-distilled in full, with a deterministic cache.
  - Cache key = (tenant, extraction `text_sha256`, span range, processor, model, prompt version, schema version).
  - No differential propagation. Counter-example: v0.2 changes only "yuan" to "ten thousand yuan" in section 1, section
    8's bytes are unchanged, and the conclusion still changes.
- The "same conclusion" in two versions is two independent Memories. An equivalence relation yields candidates only and
  **never a physical merge.**
- **Reflow guard:** an agent writes document v2 using Memory K, then v2 is ingested; the Memory derived from v2 must not
  count as independent corroboration of K.
  - The first slice has no corroboration count, so there is nothing to guard yet. The invariant is written into the spec
    anyway: once a corroboration count exists, it must first exclude the chain "run R USED K and GENERATED v2".

### D-F (D-DOC-6) Three families of association: every association answers who is connected, by what relation, on what basis, where it applies, and what stays unknown

| Association | Relation | Home | Formal ground | What it does not imply |
|---|---|---|---|---|
| Document ↔ project: related | Project —`DOCUMENTED_BY`→ Document | the existing `RelationPair::ProjectSubject` (`project_subject_relations`); no new table. Changes: `RelationKind` gains `DocumentedBy`; the `relation_kind` CHECK of `project_subject_relations` (the 0249 table template) gains `DOCUMENTED_BY`; `SubjectKind` gains `Document`; the WHITELIST and `relation_triple_allowed` gain the triple `(PROJECT, DOCUMENTED_BY, SUBJECT(DOCUMENT))`. The four places are reconciled by §78.2 | an explicit declaration, or a candidate that was confirmed | **grants no visibility**, changes no Memory's attribution, does not mean adoption |
| Document ↔ project: adopted | project pin | `document_adoptions` (scope = `PROJECT`) | as in D-D | the document's global head ≠ the version the project uses |
| Document ↔ project: knowledge attribution | Memory —`ATTRIBUTED_TO`→ Project | the existing `memory_projects` (A1 / A3 / A3') | the project in the upload request is an A1 declaration; a commit inside a valid run is A3; the assignment of ranges is D-G | no A4 is added, no MIGRATED basis is created |
| Document ↔ task: attachment | Task —`ATTACHES`→ Document (role `REFERENCE / DELIVERABLE`) | a new relation-kernel pair, `TaskSubject` (the existing three pairs have no Task → Subject): a new table on the 0249 template, `RelationKind` gains `Attaches`, triple `(TASK, ATTACHES, SUBJECT(DOCUMENT))` | an explicit declaration | an attachment is not use; it provides no A3 |
| Document ↔ run: bytes read / produced | TaskRun ↔ Version (optionally a span), direction `USED / GENERATED` | new table `private.run_document_io`. **It records I/O provenance only** (PROV `used` / `wasGeneratedBy`); declarative citation, adoption and rejection live only in the knowledge-application records of design v0.2 §18 (`knowledge_applications`), so one fact does not have two homes | GENERATED: ClientDeclared, with the run binding verified by the server (reusing the fencing of `evidence_task_runs`). USED: only HostObserved is accepted, i.e. the content was captured in the same event and binds uniquely to one version; the first slice does not build it | a path and a read event alone: the read event is an Evidence as usual, **the version is recorded as UNKNOWN and no row is built**. A UUID in the body that happens to hit a task is at most a mention. A file change reported by a watcher is not attributed to the run that happened to be active |
| Document → knowledge: content source | Memory ← Version + span | `memory_evidence` + `memory_source_spans` | the pipeline records which inputs this generation actually used | traceable provenance ≠ faithful distillation (the semantic part of G-DOC-7 needs a gold set) |
| Knowledge ↔ document: discussed or mentioned | Memory —`ABOUT / MENTIONS`→ Document | the existing `memory_subjects` | ABOUT: an explicit declaration. MENTIONS: a registered, namespaced id appears in the body | **the source document does not automatically become ABOUT:** `VERSION_OF` and the source document id are not on the inheritance whitelist of `evidence_subjects` |
| Knowledge → document: citation | Memory —`CITES`→ Version + span, with an intent | new table `private.citations` | a structured citation record | intent is one of `AS_AUTHORITY / AS_EVIDENCE / DISAGREES_WITH / USES_METHOD_IN`, named after CiTO 2.9.0 (all sub-properties of `cito:cites`). **CITES ≠ SUPPORTED_BY:** "supports" needs a per-item confirmation by an authorised principal, and the first slice only produces candidates. `cito:supports` is not copied, because its direction (the citing side supports the cited side) is the opposite of what is needed |

- Reverse queries are answered by reverse lookup, not by separately written reverse facts. For example "which Memory
  did this document derive" is a reverse lookup of `memory_evidence`.
- A revision relation connects Version and Version and **is not put in `evidence_edges`**, because the endpoint types
  differ.
  - The first slice builds no revision edge: the version sequence is the order in which versions of one document were
    created.
  - A branch relation such as "v3 was edited from v2" is deferred. Upgrade signal: parallel drafts appear.
  - While it is deferred, the requirement that the revision graph be checked for cycles is already written into the spec
    (§8.3.1): when revision edges arrive, the graph over the versions of one document must stay acyclic, the check is
    serialised per document, and the citation graph is not subject to it.

### D-G (D-DOC-7) Project assignment per span, with no new attribution basis

The current A1 mechanism (attribution_repo `A1_DECLARED`): every project declared in `evidence_projects` on the PRIMARY
Evidence becomes a `declared@1` row whose `decision_evidence_id` is that PRIMARY. If span assignment made
`decision_evidence_id` differ from the PRIMARY, that would add a rung of attribution rule (the `rule_id_ver` CHECK has
three values). So there are two modes, and **a version uses exactly one**. Enforcement:

- `document_receipts.attribution_mode` (`WHOLE | SPAN`) is written with the receipt and immutable afterwards;
- the upload gate: a request carrying both `project_id` and an assignment list is `INVALID_INPUT` with zero writes;
- the function that generates excerpts accepts only receipts with `attribution_mode = SPAN`; appending an assignment to a
  `WHOLE` receipt is `INVALID_INPUT`;
- only `WHOLE` writes the receipt Evidence's `evidence_projects`; `SPAN` does not;
- DB backstop, because with only application-layer checks a `SPAN` receipt could later still be written into
  `evidence_projects`: `evidence_projects` gets a BEFORE INSERT trigger rejecting a receipt Evidence whose
  `attribution_mode = SPAN`; the new table `document_excerpts(receipt_evidence_id, excerpt_evidence_id, selector,
  project_id)` gets a BEFORE INSERT trigger rejecting a receipt whose `attribution_mode = WHOLE`. `document_excerpts` is
  also the only source of the deletion closure C (D-J).

The two modes:

- **Whole mode:** the upload request carries `project_id` → the receipt Evidence's `evidence_projects` = P, distillation
  takes the receipt Evidence as PRIMARY, and the current A1 applies unchanged.
- **Span mode:** the upload request carries an assignment list `(selector, target_project_id)`.
  - The receipt Evidence **does not write** `evidence_projects`.
  - For every assignment the server generates one deterministic **excerpt Evidence**: its bytes are the exact text of the
    span; an `evidence_edges` DERIVED_FROM edge points to the receipt Evidence; `evidence_projects` = the declared
    project; and the same transaction registers one `document_excerpts` row.
  - The excerpt Evidence's origin (`UploadedArtifact`), its §6.1.1 visibility columns and its `data_class` are **copied
    unchanged from the receipt Evidence R**. It goes through the single existing Evidence write door and does not open a
    second `payload_sha256` construction point. So the ceiling computed under §10.1 is the same as R's
    (`UploadedArtifact` → `PrivateKnowledge` + `DATA_ONLY`), and a Memory's visibility is never wider than the original's.
  - Distillation takes the excerpt Evidence as PRIMARY. The current A1 applies unchanged: `decision_evidence_id` = the
    excerpt, and no rule is added.
  - The excerpt is itself the real content, which satisfies G-DOC-6. `memory_source_spans` still points at the receipt
    Evidence's Extraction plus a selector, to locate the text in the original.
  - Spans nobody assigned are not distilled and go to a work queue. **No Memory with zero attribution rows is produced,
    and no project is guessed from the topic.**
  - An output that would need to depend on spans assigned to P1 and P2 at once is not synthesised: each span is distilled
    separately, and a cross-span synthesis needs another request that declares a single project.
- A3's multi-project semantics (a task CONTAINed by several projects) is current M29 behaviour; this ADR does not change
  it and adds no path that produces a second project.
- An A3 binding that was validated and sealed at ingest is still inherited by the worker after the lease ends (reusing the
  T06b sealing semantics). A request submitted after expiry gets no A3.

### D-H (D-DOC-8) The effect of a new version on knowledge: four states, none writes `effective_to`

| State | How it is obtained | Nature |
|---|---|---|
| `has_later_revision` | a later Version exists under the same document | projection, computed automatically |
| `not_selected_for_scope` | the source version is not the version currently adopted for that scope | projection, computed automatically |
| `possibly_outdated` | proposed by a model or by a diff comparison | candidate |
| `superseded` | explicit governance (§36) | authoritative state |

- Uploading a second version **does not** fill `effective_to` or `superseded_at` of the first version's Memory.
- "The text cannot be found at the same locator" is a very weak signal: it may only have moved, or the parser changed.

### D-I (D-DOC-9) Recalling "what is decided now": fix the scope and adoption first, then fetch material

1. Determine the applicable scope and the adoption state: first the project pin, and if there is none, the document head.
   UNKNOWN and CONFLICT are presented as they are; **no answer is filled in by similarity or by time.**
2. Fetch only the Memory and original text derived from that version that the reader currently has permission to read.
3. Trace key conclusions back to the version plus selector, and show the basis of the adoption.
4. A version that is adopted but not yet fully processed is answered as "currently v2, this part is not processed yet";
   **v1's value is not passed off as the answer.**

Audit questions go back to the source by assertion type: "what did that run declare as its basis" goes to
`knowledge_applications` (design v0.2 §18); "which bytes did that run actually read or produce" goes to
`run_document_io`. Neither is the same query as "what does the project adopt now".

### D-J (D-DOC-10) Deletion: through the single exit of §37, plus three document rules

- **Unit of deletion:** one Version, or a whole Document (expanded to all its Versions). It runs through the existing
  DeletionPlan (migration 0054) and the eight steps of §37; a tombstone acts on a `seq` of `projection.stream_log`, and
  the overlay has a single predicate.
  - **Step 1.** Seqs hang on Evidence; `memory_records` has no seq. One Evidence can have several seqs in `ops.outbox`:
    one at acceptance, then one for every lifecycle / annotate / rollup ticket (migration 0008 has no uniqueness
    constraint on `evidence_id`), and a re-projected point carries the seq of the latest ticket. So the tombstone target is
    **all** `stream_seq` values in `ops.outbox` of the Evidence closure C, whatever the `event_type`.
    - C = {receipt Evidence R} ∪ {the excerpts E_i registered in `document_excerpts` with R as source}. **It is not taken
      from the generic `evidence_edges` DERIVED_FROM**: a tombstone is irreversible, and other derived Evidence must not
      be deleted along the way.
    - EXACT surface: the overlay (`exact_census`'s `NOT_TOMBSTONED`: memory → `memory_evidence` → outbox →
      `stream_log.state`) excludes every Memory that chains through `memory_evidence` to C, whatever the role. The hydrate
      gate (the same-shaped predicate in `read_materialize`) excludes them too, so none appears in retrieval results.
    - Vector surface: a multi-source Memory whose PRIMARY is not in C (for example PRIMARY from another document D2's X,
      SUPPORTING from R) has a point carrying X's seq, which the overlay cannot filter; read safety is guaranteed by the
      hydrate gate. These Memories are found by reverse lookup of `memory_evidence`, and step 5 physically deletes their
      points by `memory_id` (`retire_points_for_memory`). **No `MEMORY_LIFECYCLE` ticket is sent:** ADR-0057 D-B tickets
      are placed on the PRIMARY and go with a state change; the Memory is still active, so a ticket would only make the
      point be upserted again.
      ponytail: between step 1 and step 5 these stale points occupy top-k slots and may affect the vector-surface A2
      count; the upgrade signal is the step 5 backlog exceeding the purge SLA; the upgrade path is a new
      `LifecycleReason` that moves these Memories out of active (needs an ADR), then a ticket on the PRIMARY's home
      stream.
    - **Evidence outside C is not tombstoned:** tombstoning X would make D2's unrelated Memory disappear with it.
  - Steps 2 and 3: the `document_*` rows and relation rows.
  - Step 5: all points that C chains to, plus the points of the multi-source Memories above.
  - Step 6: the bytes of R and of every E_i, and the Extraction text objects.
- **Common dependency:** if any one source of a Memory is deleted, that derivation loses eligibility as a whole, **even if
  other sources remain.** If needed, derive a new Memory from the remaining sources.
- The append-only `knowledge_applications` (design v0.2 §18) and `citations` are history and **keep their rows**. When
  their target points at a deleted Version or Memory, the same overlay filter applies; no extra predicate is added.
- **Late tasks:** no new generation column. In the commit transaction of a distillation or parse, the inputs are
  re-checked against the overlay: if any input Evidence is already tombstoned, the result is `STALE_INPUT` and is
  discarded (the shape of the §11.10 finalization CAS). The `head_generation` used by the adoption CAS is unrelated to
  deletion; deleting a non-head version does not make an in-flight adoption fail.
- **Visibility is not widened:** after deletion there is no fallback to a wider visibility.
- **Bytes:** in a bucket with versioning, a plain DELETE only adds a delete marker. §37 step 6 must delete all versions of
  the object and verify the purge, with `tombstoned_unpurged_over_sla` as the backstop.
- The Extraction text object is also deleted at step 6. md / plain text has no separate text object, so no extra work.

### D-K (D-DOC-11) Security

- The distillation model can only produce candidates and Memory drafts. It has **no authority to execute** a change of
  attribution, a privilege elevation, the choice of the current version, an ACL change or a deletion; those go only
  through deterministic server paths (N09).
- **Upload:**
  - a presigned **POST** policy bound to the exact object key, with `content-length-range` limiting the size (this
    condition exists only in a POST policy; a presigned PUT cannot do it);
  - the server reads the bytes back and computes the hash itself, and seals the object version at ingest, preventing
    "scanned as A, then overwritten with B" (a PUT to the same key overwrites).
- **Parsing md / plain text:** strict UTF-8; the size limit comes from configuration (§78.1, not hard-coded).
- PDF / DOCX are deferred. When they come, parsing runs in a separate process with a memory limit (the Apache POI
  recommendation).

### D-L (D-DOC-12) Legacy document migration: replay the original files through the new upload front door; no importer

This is isomorphic with "migration = L0 replayed through the `remember()` front door".

- For each legacy document row (from the object store):
  - explicitly register one DOCUMENT with the external key `legacy:<instance>:document-row:<old row id>`;
  - go through the upload front door with `ingest_channel = MIGRATION` and origin `SystemMigration` (§10.1: migration is
    not a privilege elevation);
  - produce one legacy snapshot Version.
- This only preserves the old record. It **does not assert** that the legacy store holds 1,057 mutually distinct logical
  documents.
- What is read at migration is the bytes **as of the moment of migration**. The bytes as of back then are recorded as
  UNKNOWN, because an old object key could be overwritten and had no version history.
- The legacy document-layer memories are **not migrated as Memory** (migration goes through L0 only). Their links to
  documents serve only as gold clues for E-DOC-1.
- The 103 same-name groups, the 109 file families, the 1,509 "document + project" co-occurrences and the 1,240 "document +
  UUID" co-occurrences are **all candidate sets only.**
  - No Cartesian-product inference.
  - The 28.5% of legacy entries that name a document file and the 12.0% that carry an absolute local path to one may overlap
    and cannot be added.
  - An old entry is not put under a guessed project just to complete the migration.

## Modules and table ownership

| Module | Responsibility | Tables owned | Depends on |
|---|---|---|---|
| `domain::document` (new) | Document / Version / Extraction / Selector types; `DocumentAuthorityState`; code-point conversion; the node-kind closed set | none | only inside domain (§3: domain imports no I/O) |
| `adapters::document_repo` (new) | version registration, receipt side table, Extraction side table, spans, adoption CAS, `run_document_io`, `citations` | `document_versions`, `document_receipts`, `document_extractions`, `document_nodes`, `document_excerpts`, `memory_source_spans`, `document_state`, `document_adoptions`, `run_document_io`, `citations` | domain; the existing Evidence write door (no second `payload_sha256` construction point); the attribution port of `memory_repo` (the `== 1` count of G-M29-5 is unchanged) |
| relation kernel (existing) | `DOCUMENTED_BY` enters the existing ProjectSubject triples; a new `TaskSubject` pair carries `ATTACHES` | one new table (the §3 template) | unchanged |
| ingest (the gateway's HTTP upload plus an MCP text tool) | presign, read back, hash, write the receipt | none | `document_repo`; touches no provider |
| distill (private-worker) | document → Memory drafts, plus spans and the cache key | none | routed through §11.1 USER_REASONING; **its output enters only the existing Memory write door** |
| recall / context (M14) | adoption-aware retrieval; the manifest gains on-demand expansion | none | read only |
| retention (existing) | tombstone (Evidence closure), common dependency, commit-time overlay re-check | none | the exit is unchanged |

The design assigns no module id to these two modules.

## Gates

All are three-state (`pass / fail / not_applicable`, with the missing object named, §57.1). **Every gate below is
planned.** Each exists only after its inject → red → fix → green record (§80.1) lands in the card that implements it, and
that card adds a "Red records" entry to this ADR, as ADR-0077 and ADR-0078 do. Module gate ids such as `G-DOC-1` fall
outside the §80.1 anchor grammar (`G<n>-<n>`), so like ADR-0078's `G-M29-*` they are not §80.1 registry rows; registering
module gates there needs its own spec change.

| Gate | Criterion | Injected fault |
|---|---|---|
| G-DOC-1 identity layers | Two Documents with byte-identical template bytes → two Documents, two Evidence, no merge of any kind. A → B → A → 3 Versions | deduplicate or merge Documents by `payload_sha256`; use the hash as the version id |
| G-DOC-2 no automatic registration | an unknown `document_id` is rejected; a file-name or path match yields candidates only | "if not found, create one from the file name" |
| G-DOC-3 roles do not mix | a source document does not appear in the ABOUT links of a derived Memory | write `source_document_id` into `evidence_subjects` |
| G-DOC-4 association does not authorise | add a `DOCUMENTED_BY` for P2 pointing at P1's USER_PRIVATE document → P2's reader cannot read the body, the Memory or the title (the link row itself is tenant-visible and carries ids only, see D-A). **Per-table assertion:** the fixture plants at least one row in every `document_*` table (versions, receipts, extractions, nodes, excerpts, state, adoptions, run_document_io, citations, memory_source_spans); the owner reads ≥ 1 rows and P2's reader reads 0 rows; the subject row shows only the opaque placeholder | (a) recall relaxes visibility by `DOCUMENTED_BY`; (b) write the title into `display_name`; (c) the policy of any one `document_*` table keeps only the tenant predicate |
| G-DOC-5 attribution is complete | (a) in span mode an unassigned span produces no Memory; (b) an upload carrying both `project_id` and an assignment list → `INVALID_INPUT` with zero writes; appending an assignment to a `WHOLE` receipt → `INVALID_INPUT`; bypassing the application layer and writing the DB directly: writing `evidence_projects` for a `SPAN` receipt Evidence, or writing `document_excerpts` for a `WHOLE` receipt → both rejected by triggers; (c) no project is picked by topic; (d) for every excerpt Evidence, origin, visibility columns and `data_class` equal R's column by column | (a) unassigned spans are distilled anyway, writing a Memory with zero attribution rows; (b) remove the application-layer `attribution_mode` check, so both are written; (b') remove one of the two DB triggers; (c) pick a project by topic; (d) write an excerpt with an `AuthenticatedAgent` origin, or with the default visibility |
| G-DOC-6 content source required | a document-derived Memory without a PRIMARY (the receipt Evidence or its excerpt) or without a span → the commit is rejected | link only the range-assignment request, with no content source |
| G-DOC-7 locator determinism | code points versus bytes for CJK text and emoji; repeated paragraphs → ambiguity failure; after a new Extraction, an old citation still resolves to the old text | use byte offsets; take the first match; silently re-bind |
| G-DOC-8 adoption CAS | two concurrent adoptions at the same generation of the same scope → exactly one succeeds (tested once for GLOBAL and once for PROJECT); a pin on P does not change the `GLOBAL` row's generation; RESOLVED with an empty head → the CHECK rejects; a head pointing at another document → the FK rejects | drop the generation condition; share one generation across all scopes; drop the CHECK |
| G-DOC-9 upload ≠ adoption | upload without a declaration → the head is unchanged; a late-arriving older version does not take the head | "the latest upload is the current version" |
| G-DOC-10 new version ≠ invalidation | the fixture has a v1-derived FACT or DECISION Memory. Upload **and adopt** v2 → `effective_to` and `superseded_at` of the v1-derived STATE / FACT / DECISION Memory (the `effective_*` of other types are forced NULL by the CHECK of migration 0004) are unchanged; the document-derived `memory_evidence` rows have `grounding_mode = 'SNAPSHOT'` and the grounding is CURRENT | (a) write `effective_to` in bulk on a version change; (b) do not write `grounding_mode`, so the DDL default 'LIVE' applies |
| G-DOC-11 attachment ≠ use | attachment only → `run_document_io` has zero rows and `knowledge_applications` has zero rows | record an attachment automatically as USED or CITED |
| G-DOC-12 run binding | another principal, the wrong tenant or an expired lease → no ClientDeclared GENERATED. A sealed binding stays valid after the lease ends. A separate case: under a **valid binding** (the user, the tenant, a live lease) a ClientDeclared USED → rejected (USED accepts only HostObserved; a valid binding is used so that fencing does not reject first and make the injection stay green) | (a) remove the fencing check; (b) require the lease to still be valid while the worker runs; (c) accept a ClientDeclared USED |
| G-DOC-13 common dependency in deletion | the fixture: a whole-mode v1; a span-mode v1' (two excerpts); another document D2's X; and a Memory with PRIMARY = X and SUPPORTING = R. Delete v1 and v1' → (a) every Memory that chains to R or an E_i is excluded by the EXACT overlay and the hydrate gate, even if other sources remain; every outbox seq of C (lifecycle tickets included) is tombstoned; after step 5 the multi-source Memory has no point; (b) a `memory_source_spans` row with no matching `memory_evidence` row → the commit is rejected; (c) an in-flight distillation task gets `STALE_INPUT` on commit; (d) X's seq is not tombstoned and D2's other Memory stays readable; (e) deleting a non-head version, an in-flight adoption CAS still succeeds; visibility is not widened | (a) "keep the Memory alive while another Evidence remains"; (a') tombstone only the acceptance-time seq (the fixture first annotates a Memory derived from R, so R has one more seq); (a'') step 5 does not delete the points of multi-source Memory; (b) remove the constraint trigger of the span invariant → a Memory linked only through a span is still readable after deletion; (c) remove the commit-time overlay re-check; (d) tombstone the dependent Memory's PRIMARY seq |
| G-DOC-14 project-pin recall | the document head is v3, P's pin is v2 → answer v2 and show the pin | answer with the head directly |
| G-DOC-15 a summary is not the original | a receipt with `received_payload_kind = SUMMARY` → cannot produce a citation "original-file span verified" | record the summary's selector as an original-text selector |
| G-DOC-16 no hash existence query | architecture-check: no external interface takes an input hash and returns whether it exists | add an `exists_by_sha256` endpoint |
| G-DOC-17 closed-set reconciliation | the DOCUMENT kind, `key_kind` `LEGACY_DOCUMENT_ROW`, `RelationKind` `DOCUMENTED_BY` / `ATTACHES`, node kinds, receipt enums (including `attribution_mode`), `scope_kind`, intent, EvidenceMode: Rust enum == DB CHECK (§78.2). A subject of kind DOCUMENT with `merged_into` set → the DB rejects; a subject of kind DOCUMENT used as a merge target → the DB rejects | (a) add one value only in the DB; (b) remove only "DOCUMENT cannot set `merged_into`"; (c) remove only "DOCUMENT cannot be a merge target" |

Note on closed sets that do not exist yet: any G-DOC-17 member whose type does not exist when the gate lands (EvidenceMode,
the closed set `HostObserved / ClientDeclared / UserReported / Imported` of design v0.2 §16.9 on the external-tool axis;
node kinds before T-DOC-2; `intent` and `DOCUMENTED_BY` / `ATTACHES` before T-DOC-5) is reported `not_applicable`, naming
it (§57.1). The card that introduces the type removes that `not_applicable`.

## Experiments

Run on `exp/*` branches; the corpus never enters git; only MiniMax is used; statistics follow ADR-0078's E-A: sampling
and counting by cluster, and a CP95 bound reported even when zero errors are observed. Acceptance rules are stated here;
the data stays in the private evaluation notes.

- **E-DOC-1 Layered accuracy of migrated associations.** Data: the legacy document-layer memories and their storage
  links serve as gold clues; legacy L0 entries that hit a document name, a path or a UUID are sampled by stratum.
  - Measured separately: legacy-row recovery, Version recovery, mention-target resolution, project-association
    candidates, task-association candidates.
  - Primary metrics: formal wrong links = 0; recovery rate per layer; share of UNKNOWN; confirmation workload for
    candidates.
  - Where the gold evidence is insufficient, UNKNOWN is allowed.
- **E-DOC-2 Version-family replay.** Data: the 109 families (334 files) plus the 103 same-name groups (the two overlap
  and cannot be added).
  - The owner confirms a sample: which are revisions of one document, same-name but different documents, copies,
    unadopted drafts, or undecidable.
  - Replay in the original order, then with the arrival order shuffled.
  - Primary metrics: wrong automatic merges = 0; wrong automatic invalidations = 0; precision and recall of the candidate
    families (this decides whether candidate generation for D-A is worth building).
- **E-DOC-3 Per-span assignment.** The owner confirms several documents that cover more than one project. Compare three
  approaches: whole-document inheritance, explicit spans, unassigned staging.
  - Measured: attribution errors, share awaiting assignment, operator effort.
  - Also verify that `DOCUMENTED_BY` does not widen visibility.
- **E-DOC-4 Host-observation coverage** (decides whether HostObserved is worth the investment). Claude Code only (the
  owner's main host), recording the actual version number.
  - Entry points: built-in Read, Bash, MCP, @-file, edit, modification by an external process.
  - Measured: event capture rate, share where content can be captured, share where the exact version can be determined,
    share correctly reported as UNKNOWN, number of wrong attributions.
  - First-hand facts (CC-HOOKS): an @-file does not trigger PreToolUse by default; `tool_use_id` is an event-specific
    field.
- **E-DOC-5 Distillation faithfulness and cost.** Use real design-document version pairs (the design v0.1 / v0.2 pair, and
  historical versions of the Baseline).
  - A person labels "was a condition lost": fault-injected samples that delete an "only if" or an "unless", or shuffle
    steps, must be caught by the gold set.
  - Measure the calls and tokens of full re-distillation, as the baseline for D-E's cache and for any later differential
    scheme.

## Cards

One card, one PR; documents before code.

| Card | Content | Gates |
|---|---|---|
| T-DOC-0 | this ADR; spec text: §8.3.1 document layer, `SubjectKind` `DOCUMENT` (§6.1.3), `RelationKind` gains `DOCUMENTED_BY` (existing ProjectSubject pair) and `ATTACHES` (new TaskSubject pair) (§6.1.4); the reflow-dedup, span and revision-graph-acyclicity invariants | none |
| T-DOC-1 | migration and contract: the DOCUMENT kind, `key_kind` `LEGACY_DOCUMENT_ROW`, `document_versions` (with the visibility columns), `document_receipts`, `document_extractions`, `memory_source_spans`, `document_state` (per scope), `document_adoptions` | G-DOC-1 / G-DOC-8 / G-DOC-17 |
| T-DOC-2 | receipt: HTTP upload (md / plain text) plus an MCP text tool → receipt Evidence + Version + Extraction + structure nodes + selector | G-DOC-2 / G-DOC-7 / G-DOC-15 / G-DOC-16 |
| T-DOC-3 | adoption: CAS, project pin, read model (version list, state, pin, basis) | G-DOC-9 / G-DOC-14 |
| T-DOC-4 | document → Memory: spans, SNAPSHOT, A1 / A3 range assignment | G-DOC-3 / G-DOC-5 / G-DOC-6 / G-DOC-10 |
| T-DOC-5 | association: the `DOCUMENTED_BY` triple, the TaskSubject pair plus `ATTACHES`, `run_document_io` (ClientDeclared GENERATED only), `citations` | G-DOC-4 / G-DOC-11 / G-DOC-12 |
| T-DOC-6 | deletion into §37: tombstone of every outbox seq of the Evidence closure, step 5 deletes the points of multi-source Memory, commit-time overlay re-check | G-DOC-13 |

- Experiments are interleaved: E-DOC-1 and E-DOC-2 run after T-DOC-2 (they need the receipt front door); E-DOC-5 after
  T-DOC-4; E-DOC-3 after T-DOC-5; E-DOC-4 runs on its own, and its result decides when HostObserved is scheduled.
- **Acceptance of the first slice:** a real design document of the owner, in two versions, goes through the whole chain:
  upload → adoption → derived Memory (with spans) → project pin → recall of "what is decided now" → delete v1. At every
  step the read model can answer who is connected, by what relation, on what basis, where it applies, and what stays
  unknown.

## Deferred items and upgrade signals

| Deferred | Upgrade signal |
|---|---|
| multiple renditions (several formats of one version) | multi-format input becomes the norm |
| PDF / DOCX / OCR | a real PDF consumption need (the legacy store has only 2 PDFs) |
| physical deduplication | the share of storage taken by same-byte duplicates grows |
| HostObserved (hook adapters) | E-DOC-4 shows a host can fill in exact versions to a significant degree |
| revision branch edges | parallel drafts appear |
| exclusion constraint on adoption intervals | a product-level as-of query appears |
| a formal confirmation flow for SUPPORTED_BY | a real query "which conclusions does this document support" appears |
| differential distillation | E-DOC-5 shows full re-distillation cost has become the bottleneck, and a dependency-propagation scheme has passed the unit counter-examples |
| automatic version-family candidates | E-DOC-2 shows candidate generation significantly lowers confirmation workload. **N09 is not relaxed with it** |

## Alternatives rejected

- Version identity = the byte sha256: A → B → A collides, and several formats would contradict.
- Merging Document or ACL by bytes or hash: physical deduplication ≠ authorisation merge.
- Putting the project or ACL on the shared Artifact: the basis of attribution is on the write event and the receipt.
- One HostObserved / ClientDeclared field that expresses both entry channel and evidence strength: split into the
  orthogonal fields of D-B.
- Bulk-writing `effective_to` on a version change: a new version, a withdrawal and "no longer true" are three different
  events.
- A hard "exactly one head" constraint: it is incompatible with UNKNOWN / CONFLICT; it becomes "exactly one when
  RESOLVED".
- A global authority order by author role: authority is decided per matter and scope (the PROV-DM primary source is a
  relation, not a type of entity).
- Revision relations reusing `evidence_edges`: the endpoint types differ, and it would make two ledgers.
- Merging CITES and SUPPORTED_BY, or mapping `cito:supports` directly: both direction and meaning are wrong.
- A dedicated importer for legacy documents: migration replays through the front door (isomorphic with the L0 migration).
- "Keep the Memory while another Evidence remains": the set of inputs to one derivation is a common dependency.

## References

Verified 2026-10-20 against the design v0.2 source register. Read depth follows the register's marks; an unmarked entry
was read in the part the text relies on.

- WA-DM — W3C Recommendation 2017-02-23, Web Annotation Data Model (TextPositionSelector: start inclusive, end
  exclusive, counted in Unicode code points; TextQuoteSelector: exact / prefix / suffix): https://www.w3.org/TR/annotation-model/
- DoCO — Document Components Ontology 1.4.0 (2026-06-25): https://sparontologies.github.io/doco/current/
- CiTO — Citation Typing Ontology 2.9.0 (2026-09-03; five citation-intent properties, all sub-properties of `cito:cites`;
  the direction of `cito:supports` is citing side supports cited side): https://sparontologies.github.io/cito/current/
- PROV-DM — W3C Recommendation 2013-04-30, The PROV Data Model (primary source is a kind of derivation, not a subtype of
  Entity, §5.2.4; `used` + `wasGeneratedBy` is necessary but not sufficient for derivation): https://www.w3.org/TR/2013/REC-prov-dm-20130430/
- S3-DM — Amazon S3 User Guide, working with delete markers (a DELETE on a versioning-enabled bucket only adds a delete
  marker; the pages carry no date): https://docs.aws.amazon.com/AmazonS3/latest/userguide/DeleteMarker.html
- S3-PRE — Amazon S3 User Guide, sharing objects with presigned URLs (a presigned URL can be reused until it expires; a
  PUT to the same key overwrites): https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html
- S3-POST — boto3, `generate_presigned_post` (POST policy supports `content-length-range`):
  https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/generate_presigned_post.html
- S3-OBJ — Amazon S3 API Reference, Object (the ETag of a multipart upload is not an MD5):
  https://docs.aws.amazon.com/AmazonS3/latest/API/API_Object.html
- POI-SEC — Apache POI, Security: https://poi.apache.org/security.html (partial read: the advice to parse in a separate
  process with memory settings is scoped to "highly sensitive environments"; it does not state general resource and
  time limits)
- CC-HOOKS — Claude Code Docs, Hooks: https://code.claude.com/docs/en/hooks (the page carries no version number;
  @-file does not trigger PreToolUse by default; `tool_name`, `tool_input` and `tool_use_id` are event-specific fields)
- PG-BG — PostgreSQL 18.6, F.8 btree_gist (supports uuid): https://www.postgresql.org/docs/18/btree-gist.html
- GH-RENAME — GitHub Docs, Renaming a repository (a path is a locator, not an identity), as cited in ADR-0078:
  https://docs.github.com/en/repositories/creating-and-managing-repositories/renaming-a-repository
