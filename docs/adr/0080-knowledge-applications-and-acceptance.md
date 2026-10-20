# ADR-0080 — Knowledge applications, acceptances and the experience list

- Status: Accepted (2026-10-20). Card T-KNOW-0 (docs only). Content authority: design v0.2 §18, "the knowledge base is
  no longer flat" (sha256 prefix 330f6bbe), decided by the design owner, to whom the repository owner delegated it,
  after two independent review rounds. Every gate below is planned; none exists yet (Gates).
- Relates to: Baseline §6.1.1 (intra-tenant visibility), §6.1.4 (N09, the A3 rung, the trusted user entry), §8 and §8.6
  (Evidence is the one provenance root; `memory_evidence` is the one provenance relation), §8.7 and §10.1 (Evidence
  origin and its authority ceiling), §8.8 and §11.10 (grounding of a Memory formed from a source; left unchanged), §9
  (time semantics), §11.5.1 (BYOK budget), §11.6 and §11.9 (consolidation proposes only; derived views), §15
  (`commit_seq`), §30.2 (fencing), §33.10 rule 9 (confirm tokens), §36 (correction and supersession), §57.1, §78.1,
  §78.2, §80.1; ADR-0018 (confirm-token gate), ADR-0078 (work attribution axis, rule N09, vocabulary layers D-H),
  ADR-0079 (documents, versions, selectors and `run_document_io`; it lands in parallel and is referenced by number
  only). The normative text is Baseline §8.9. Where this ADR says "design v0.2 §n" it means the design document, not
  the Baseline.

## Context

The owner requirement of 2026-10-20 is this. When a user uploads a long document such as a book, later tasks and
projects will cite parts of it, and that reuse is what makes self-evolution possible, as in the open-source
self-evolving knowledge-base project the owner shared (EvoOntology, EVO). The knowledge base must therefore stop being
flat in this iteration. The requirement book's related items add four constraints: content is normalised when written,
relations keep evolving, authority levels are never mixed, and a derived product never replaces the source of truth.

**A premise of the earlier question is corrected here.** The question assumed that a task run already has an
acceptance port. Checked against the code, which is the sole authority for this, `coord.task_runs` carries only
`outcome_summary`, free text, and the tool-run Outcome of design v0.2 §16.9 says outright that business acceptance is
recorded elsewhere. No acceptance record exists today. D-C creates it.

What the repository already has, and this ADR therefore does not add:

- **Evidence and provenance.** `private.evidence_objects` with RLS (§6.1.1, §8) and `private.memory_evidence` (§8.6).
- **Verified task runs.** `coord.tasks` / `coord.task_runs` with a fencing token per lease (§30.2). `task_claim`
  returns a new `task_run_id` every time (ADR-0078 Q10). `evidence_task_runs` (migration 0251) is the carrier by which
  M06 binds a verified run to Evidence.
- **Attribution.** `private.memory_projects` and rule N09 (ADR-0078, §6.1.4).
- **Documents.** Versions, Extractions, structure nodes, selectors and `run_document_io` come from ADR-0079.

What is missing is narrower. The system can say what it served and what a run read, but it has no record of which run
declared that it used which piece of knowledge, under which acceptance standard, with what result, and nothing lets a
later task benefit from that in a traceable way. Without that record the usual shortcuts follow: "it was retrieved, so
it was adopted" and "it was adopted, so it worked". D-B keeps those assertions apart.

## Decision

Each decision carries its design identifier in parentheses, so the numbering can be followed back to design v0.2 §18.1.

### D-A (D-KNOW-1) Two axes, three business structures; everything else is derived

- **Two axes.**
  - Internal structure of a source: which version, which chapter, which passage, and which premises, exceptions and
    steps it depends on.
  - Use and outcome: which run declared that it used it, under which acceptance standard, with what result, and what
    was corrected afterwards.
- **Three business structures**, all on the source-of-truth chain:

| Structure | Content | Home |
|---|---|---|
| Versioned source with locators | Version, Extraction, structure node, selector | ADR-0079 |
| Memory formed on demand | has premises and a passage, SNAPSHOT-grounded (§8.8) | ADR-0079 |
| Application and acceptance records | what a run declared it cited, adopted or rejected at the time; the standard it was accepted against; the result | this ADR, D-B and D-C (new) |

- **Derived products:** structure navigation, the experience list, concept navigation, the relation-candidate graph,
  summary trees, playbooks and ranking policy. All can be rebuilt, and all can be switched back to an older version.
- **Rebuild invariant (G-KNOW-1).** Delete every derived product (structure nodes, graph, summaries, vectors, the
  experience list, ranking caches) and rebuild. Originals, Memories, application and acceptance records, confirmed
  relations, and recorded candidates with their governance basis must not change. Deterministic derived results
  (structure nodes, the experience list) must equal their pre-deletion values item by item. Model-generated derived
  products (a later summary tree) need only be rebuildable and traceable to source, not item-by-item equal.
  - Otherwise "derived" is only a name, and the graph has quietly become a third source of truth.

### D-B (D-KNOW-2) Application records state only what the run declared; assertions never move up a level

- New table `private.knowledge_applications`:
  - `task_run_id`;
  - `target`: a `memory_id`, or `version_id` plus selector, **exactly as declared at the time**;
  - `usage`: `CITED` / `ADOPTED` / `REJECTED`;
  - `mode`: the EvidenceMode `ClientDeclared` (after validation) or `UserReported`. The EvidenceMode closed set belongs
    to the tool-run design (design v0.2 §16.9), which has no Baseline home yet. This ADR only uses these two values
    and does not define the enum. Its §78.2 Rust == DB reconciliation is ADR-0079 G-DOC-17 (not_applicable, naming
    EvidenceMode, until the type exists);
  - `basis_evidence_id`;
  - `rationale_memory_id`, nullable.
- **Validation.**
  - The target exists and is visible to the run's principal.
  - The run binding passes fencing through `evidence_task_runs`.
  - The selector resolves to the Extraction the target sits in.
- **Idempotency.** `UNIQUE (task_run_id, target, usage)`: a retry of one run merges into one row.
- **The unit of independence is the task, not the run attempt.** "How many times was it used" counts distinct
  `task_id`.
- **The assertions are kept apart** (five rows):

| Assertion | Where it comes from |
|---|---|
| The system served it | the retrieval log (not in this table) |
| The agent read it (a server-provided item) | the access record of an on-demand resolve (not in this table) |
| A run read or produced a document at byte level | `run_document_io` (ADR-0079): I/O provenance, not a declaration |
| A run declared it cited, adopted or rejected it | `knowledge_applications` |
| The implementation met the requirement, and the business result | the acceptance record (D-C) |

  **"The method caused the success" is asserted by no automatic path.**
- A rejection is useful too, but the nature of its reason must be marked: an agent's inference, or a user's preference.
  Which column carries that mark is a T-KNOW-1 schema detail; G-KNOW-2 (d) holds the requirement. Relabelling a
  rejection (say, an agent inference later stated by the user) is an appended correction, not an UPDATE; T-KNOW-1 picks a
  correction shape that `UNIQUE (task_run_id, target, usage)` neither rejects nor silently merges.
- **Lazy distillation does not back-attribute (G-KNOW-3).** An old run cited `version + selector`. If memories m1 and m2
  are later distilled from that passage, the old run is not automatically recorded as having adopted either. Method-level
  attribution needs a new deterministic ground or a confirmation event.
- **An application does not change the source's attribution.** The record shows the run's project; the cited Memory's
  `memory_projects` rows are not touched (§6.1.4).

### D-C (D-KNOW-3) Acceptance records must store the standard they were accepted against

- New table `private.run_acceptances`:
  - `task_run_id`;
  - `criterion_id` and `criterion_version`, both NOT NULL;
  - `verifier`: `CI` / `USER` / `AGENT_CHECK` / `EXTERNAL_METRIC`;
  - `result`: `PASS` / `FAIL` / `PENDING` / `UNKNOWN`;
  - `evidence_id`, pointing at the artefact or observation that supports the result.
- **The server derives `verifier` from the origin of `evidence_id`; the client cannot set it.** Otherwise an agent could
  report "CI passed" about itself.
  - `USER` comes from origin `DirectUserInput` or `UserConfirmed`.
  - `CI` comes from origin `TrustedConnector` when it is the server's own read-back of the raw check-run receipt.
  - `EXTERNAL_METRIC` comes from a `TrustedConnector` metric receipt (not in the first slice).
  - Everything else is `AGENT_CHECK`. The map is closed over origins, and that, not the §10.1 ceiling, keeps
    `AuthenticatedAgent` from passing for CI or the user (`TrustedConnector` and `ToolResult` share its ceiling).
- **When `verifier` is not `AGENT_CHECK`, `result` and `(criterion_id, criterion_version)` are also derived server-side
  from the receipt.** Deriving only the verifier is not enough: an agent could attach a genuine receipt to another
  check's name, or to a PASS.
  - `CI`: take the check name, the workflow file SHA and the conclusion from the receipt the server read back, and map
    them to a criterion and a result. The receipt's `head_sha` must be a commit this run registered as its output
    (`run_document_io` GENERATED per ADR-0079, or the SHA recorded in Evidence bound through `evidence_task_runs`). If it
    cannot be bound the answer is `INVALID_INPUT`; otherwise a run could borrow another PR's genuine green receipt.
  - `USER`: the Evidence must be the user's confirmation of one concrete manifest
    `(task_run_id, criterion_id, criterion_version, result)`, given through the trusted user entry of §6.1.4 (the same
    manifest digest as `control.confirm_tokens`, §33.10 rule 9). The server reads the values from the manifest. That
    confirmation writes new Evidence of origin `DirectUserInput`; it never mints `UserConfirmed`, whose only creation
    path stays `memory.confirm` (§25.4.B).
  - A client-supplied value that differs from the derived one is `INVALID_INPUT`. Only `AGENT_CHECK` takes `result` and
    criterion from the client, and those are by nature only the agent's own account.
- A business outcome not yet observed (a search ranking, a conversion rate) is recorded as `PENDING`, neither success
  nor failure. "The page deployed" does not stand in for the business metric.
- **Criterion sources in the first slice:** a CI check name plus the workflow file SHA (this repository's own PRs are a
  ready real example), and acceptance items the user states explicitly in the task.

### D-D (D-KNOW-4) The first slice's only automatic change: the experience list

The context a later task receives must change, traceably, because of application results that already exist.

- **What it is.** For each applied target (a Memory, or a Version passage), a list produced by fixed rules. Each item
  says which task, which run, which declared usage, against which standard, with what result. It adds `USER_CORRECTION`
  Evidence about that target and the recorded conflict candidates.
  - A conflict candidate is a record in an append-only candidate table, the governance suggestion of §11.6. It is not a
    derived product. The list only projects it.
  - The candidate table (the candidate mechanism of ADR-0078, N09 R2 / A5) is deferred past the first slice. This column
    is therefore always empty in the first slice, and G-KNOW-7 reports `not_applicable` while the table does not exist,
    printing the missing table name (§57.1).
- **How it is produced.** A deterministic SQL projection. It calls no model and needs no consolidation run.
  - In the first slice it is computed at read time and not materialised. `ponytail:` read amplification grows linearly
    with the number of applications; the upgrade signal is `context.assemble` P95 over its budget; the upgrade is a
    materialised projection, guarded by G-KNOW-1.
- **When it is given.** When a task or run opens, and when a target is resolved on demand. Through `context.assemble`
  only the list (titles, results, counts) is returned, and items expand on demand (the access layer of ADR-0078 D-H,
  M14).
- **Ordering and coverage.** Fixed rules. **Success, failure, correction and pending items all appear**; successes are
  not shown alone by popularity. Popularity affects order only, never authority.
- **Permission covers the whole provenance closure (G-KNOW-5).** "The project a run belongs to" has no single definition:
  a task can have zero to n CONTAINS projects, and they change over time. So:
  - each item is filtered, per item, by the reader's visibility (RLS) over its `basis_evidence_id`, its acceptance
    `evidence_id` and the Evidence the target sits in;
  - the run's project is display only, computed under the A3 rule at the `occurred_at` of the basis (ADR-0078 D-D); a
    run with no mapping is handled by Evidence visibility alone;
  - counts are computed over visible items only (filter before count);
  - the title, failure reason or count of an invisible item must not appear, and must not be inferable from an ordering
    explanation either.
- **It is a derived product** (the Rollup role of §11.9). A behavioural ruling must expand back to the application
  records and the acceptance Evidence.

### D-E (D-KNOW-5) Experience Memory and experience Rollup are told apart by production path

- **Experience Memory** goes through the existing Memory write door, has Evidence (the application and acceptance
  events) and an explicit assertion nature.
  - Wording is an auditable observation: "R1 declared it adopted M and passed under V2; R2 missed metric Q; the user's
    explanation is Z; the system's proposed explanation H is unconfirmed". It does not read "effective in context A,
    ineffective in context B, because ...".
  - Ownership is one project, by A1 or A3. A cross-project experience must have an explicitly declared owner project.
  - The authority ceiling follows §10.1. A model-proposed experience is first a §11.6 governance suggestion and then an
    explicit write.
- **Experience Rollup** is an automatically assembled cross-case summary and is a derived product.
- **There is no general N.** Creating an experience candidate, describing an observed fact, claiming transferability and
  publishing a new retrieval strategy each need a different amount of evidence and share no threshold. A retry, a
  copied project and a rewrite of the same task template are not independent applications.
- The first slice **does not** generate experience Memories with a model; the experience list already covers the
  navigation need. The upgrade signal is in Deferred.

### D-F (D-KNOW-6) Concepts and vocabulary: ADR-0078 D-H's layers stay, with checked SKOS constraints added

- ADR-0078 D-H stands: the first slice builds no vocabulary until there is a real consumer. Aligning a book's concepts
  with the user's capability vocabulary yields candidate mappings only.
- When a vocabulary is built, these constraints go into the database and the code:
  - `exactMatch` is symmetric and transitive (SKOS S44 and S45), but it is **not** implemented as an identity merge or as
    union-find. SKOS §10.6.8 says linking concepts of different schemes with `owl:sameAs` is generally inappropriate. Two
    concepts each keep their own scheme, id, provenance and governance history.
  - `closeMatch` is **not** transitive (§10.1).
  - `broader` is not transitive (§8.6.6); navigation computes `broaderTransitive` at read time.
  - "Chapter A contains chapter B" does **not** imply "concept A is broader than concept B".
  - We choose to require an acyclic `broader`; SKOS allows cycles (§8.6.8). This matches ADR-0078 D-H.
  - A confirmation binds `candidate_revision` / `payload_hash`, the endpoint versions, the relation type, the scope and the
    basis ids.

### D-G (D-KNOW-7) Evolution operators: what may change automatically

| Object | Allowed automatic change | Gate | Rollback |
|---|---|---|---|
| Evidence | append only | not overwritable, idempotent | append a correction or governance event |
| Extraction / structure node | create a new Extraction; rebuild the node index | an old reference still resolves to the old Extraction | switch back to the old projection |
| Memory | add only through the existing write door | provenance, attribution (N09), authority ceiling | correction and supersession under §36 |
| Formal relation | materialise only on a deterministic ground | N09, row by row | replay governance events |
| Application and acceptance records | append | the D-B and D-C validation | append a correction |
| Experience list | recompute by fixed rule | G-KNOW-1 / G-KNOW-5 | rebuild |
| Conflict, misunderstanding and cross-version-correspondence candidates | propose, add evidence | candidate status is explicit; **never silently promoted** | discard the candidate projection |
| Vocabulary version, ranking policy | build a candidate and evaluate it | the D-H publish protocol | atomic switch back to the Parent |
| Schema | **never automatic** | ADR plus code review | migration process |

- **Two kinds of change, kept apart.**
  - Refreshing a view by fixed rules is a data update and does not go through a statistical gate.
  - Changing ranking parameters, mappings or aggregation rules is a policy change and goes through D-H.
- **Comparison with EvoOntology (EVO-REPO).** Its editable layers are Content, Tool and Schema, **Schema included**. This
  ADR borrows only the structure "paired comparison plus keep the Parent if the candidate falls short", and narrows the
  editable scope to the vocabulary and derived policies. Automatic Schema evolution was rejected earlier.

### D-H (D-KNOW-8) Publish protocol: two independent gates, bound to the exact evaluated content

This supplements the vocabulary evolution gate E-F of ADR-0078 D-H.

- **Two gates:**
  - relation admission: every formal relation has a deterministic ground or an authorised confirmation (N09);
  - version publish: a candidate is significantly better than its Parent under a pre-registered protocol.
  - **A statistical win does not promote the candidate's relations along with it.**
- **Atomic publish conditions.** All must hold; otherwise the Parent stays.
  1. The hash of the published content equals the hash of the evaluated candidate, and the evaluated Parent equals the
     current Parent. The publish pointer moves by an expected-parent CAS.
  2. Zero N09 violations, and all hard gates on provenance, permission and history pass.
  3. The number of independent paired units is n >= a minimum computed beforehand. The paired unit is the task family:
     within a cluster the outcomes are first aggregated into one binary result. Several seeds of one task, or rephrased
     questions about one method, are not independent.
  4. b > c, and the two-sided exact conditional McNemar test gives p <= the pre-registered, corrected alpha, where
     p = min(1, 2 · Σ_{k=0..min(b,c)} C(m,k) · 2^(−m)) and m = b + c. For m = 0, p = 1.
  5. The effect size (b − c)/n reaches a pre-registered threshold, cost stays under its cap, and no critical task group
     regresses unacceptably.
- **Why a minimum sample is also required** (recomputed locally by the design owner):
  - For (b, c) = (6, 0), p = 0.03125. Six improvements and zero regressions are already "significant".
  - A power example: p_b = 0.15, p_c = 0.05, alpha = 0.05 and power 80% need n = 168. It is an illustration, not a
    general threshold, and must be recomputed whenever the expected effect changes.
- **A sealed split expires.** A frozen set that is used repeatedly to pick candidates becomes a training interface
  (Dwork et al., DWORK). A sealed split is invisible to the evolving side. Once its result is fed back to that side it
  is downgraded to a development set, and the next publish uses a fresh sealed split.
- McNemar applies to paired binary outcomes only. NDCG, latency and tokens are reported separately and are not forced
  into the test.
- **Trigger.** It borrows the idea of EvoOntology's trigger (EVO-REPO: a count of new trajectories or a number of days,
  whichever comes first). A candidate evaluation is triggered by "new independent applications >= X, or days since the
  last evaluation >= Y". X and Y come from configuration (§78.1).
- **Replay carries no future information.** "Replay as the system knew it then" happens only in the experiment harness,
  cut by `created_at`, and never in product retrieval (§9 makes `created_at` audit-only). `occurred_at` can be backfilled
  and is therefore not a valid cut (G-KNOW-11). `commit_seq` (§15) is not used as a consistent cut until verified (§6.1.4, Time).

### D-I (D-KNOW-9) Recall: several entry points in parallel, three source layers labelled apart

- **Parallel candidate entry points:**
  - direct retrieval of source text (Extraction text);
  - structure location plus expansion to the parent section;
  - confirmed concept navigation (once a vocabulary exists);
  - application and experience retrieval.
- A single "concept → tree → passage" path is not forced. Basis: the RAPTOR main experiment retrieves with a collapsed
  tree, over all layers together (RAPTOR); HippoRAG 2 falls back to dense passage retrieval when the filtered triples are
  empty (HIPPORAG2, appendix G.1).
- **Source layering when presented:** this project's own knowledge; source knowledge (the book, by version); other
  projects' application experience (labelled with its source and bound by G-KNOW-5).

### D-J (D-KNOW-10) Authority is settled per assertion, against its own basis

| Question | Where it is settled |
|---|---|
| What the book says | the named Version's original text, plus a selector |
| Which document a run read or produced at byte level | `run_document_io` (ADR-0079): I/O provenance only, never proof of "adopted" |
| What the run declared it adopted at the time | that run's `knowledge_applications` |
| How the acceptance turned out at the time | `run_acceptances`, plus the standard's version |
| How the user understands or corrects it | the user's own words (`USER_CORRECTION` Evidence) and its explicit scope |
| Which relation or revision is formally in force | an authorised governance event, plus the target version |
| Whether it generalises to a new project | the evidence above plus a judgement of applicability; if the evidence is not enough, mark UNKNOWN |

- A book's authority covers "what this edition of the book says", not real-world effect. One failed project does not
  refute a conditional or probabilistic claim in the book.
- "Practice conflicts with the book" is raised only as a candidate. Both ends' original text and their scope are kept, and
  **neither side is rewritten automatically**.

### D-K (D-KNOW-11) Cost and BYOK phasing (budget basis reuses §11.5 and §11.5.1)

| Stage | What is done | Generation-model calls |
|---|---|---|
| Upload | save the original; deterministic markdown parsing; structure nodes; hash and locator checks | 0 |
| First question about the source | direct retrieval of the source text, then an answer | no need to distil the whole book first |
| First use of a method | extract only that method's unit and its premises | local |
| After application and acceptance | update the experience list deterministically | 0 |
| Candidate policy evaluation | frozen paired evaluation | a separate budget, often larger than ingestion |

- The semantic relation of all M(M−1)/2 unit pairs is not computed. Only units that were used, and a few candidate
  neighbours, are looked at.
- The total call count has no single value per page count (UNKNOWN). E-KNOW-1 measures it on this repository's own long
  document.
- The budget is reserved first, retries are capped, and the account is settled afterwards (§11.5.1).

## Modules

| Module | Responsibility | Tables it owns | Depends on |
|---|---|---|---|
| `domain::application` (new) | closed sets `Usage` / `Verifier` / `AcceptanceResult`; type-level separation of the assertions | none | inside domain only |
| `adapters::application_repo` (new) | validating and writing application declarations; writing acceptances | `knowledge_applications`, `run_acceptances` | the Evidence write door; `evidence_task_runs` (fencing) |
| experience list (a projection query inside recall) | D-D | none in the first slice | `application_repo` (read only); the visibility function |
| MCP tool surface | `knowledge.declare_use` (declare cited, adopted or rejected) and `run.record_acceptance` | none | gateway; no plugin packaging in this ADR |
| publish protocol (later) | D-H | vocabulary versions, policy versions | the experiment harness |

Domain stays free of HTTP, SQLx and the other imports barred by §3 and §78.3.

## Gates

All are three-state (`pass` / `fail` / `not_applicable`), and a `not_applicable` prints the missing object (§57.1).
**Every gate below is planned.** Each exists only after its inject → red → fix → green record (§80.1) lands in the card
that implements it, and that card adds a "Red records" section here, as ADR-0077 and ADR-0078 do. Module gate ids such
as `G-KNOW-1` fall outside the §80.1 anchor grammar (`G<n>-<n>`), so like ADR-0078's `G-M29-n` they are not §80.1
registry rows; registering them there needs its own spec change.

| Gate | Criterion | Injected fault |
|---|---|---|
| G-KNOW-1 rebuildable | delete `document_nodes` and rebuild from the Extraction; compute the experience list twice on the same input; both are item-by-item equal to the pre-deletion (or earlier) result, and formal relations, confirmation bases and application history are unchanged | (a) give `document_nodes` a field that cannot be derived from the Extraction (for example a write-time wall clock), with a comparator covering every column; (b) give the experience-list ordering no deterministic last key. Fixture: two applications with identical sort keys, a database built twice with opposite insertion orders, and the two outputs compared |
| G-KNOW-2 applications are honest | (a) retrieved but not declared gives zero rows; read but not declared gives zero rows; declared and then accepted as FAIL gives one application row, with the FAIL acceptance beside it. (b) the same run declaring 3 times gives 1 row. (c) 3 runs of one task, one declaration each, give 3 rows, yet "times used" counts distinct tasks and gives 1 (`task_claim` returns a new `task_run_id` every time, ADR-0078 Q10; fencing per §30.2). (d) writing the database directly, past the application layer: a `REJECTED` row without its reason kind is rejected, and a `REJECTED` row with each reason kind (agent inference, user preference) is accepted | (a) record ADOPTED on retrieval; (b) drop `UNIQUE (task_run_id, target, usage)`; (c) count by run; (d) drop the reason-kind constraint for `REJECTED` |
| G-KNOW-3 no retroactive attribution | an old run cited passage p, and m1 and m2 are distilled from p afterwards; the old run's application still points only at p | copy p's application onto m1 and m2 at distillation |
| G-KNOW-4 acceptance has a standard | an acceptance with no `criterion_id` or `criterion_version` is rejected by the database (the test writes to the database directly, past the application layer); a verifier derived from Evidence of origin `AuthenticatedAgent` can only be `AGENT_CHECK`; take one genuine CI receipt (check A, conclusion failure) and declare "check A PASS" in one case and "check B FAIL" in the other: both are `INVALID_INPUT`; a receipt whose `head_sha` does not belong to the run is `INVALID_INPUT` | (a) drop NOT NULL; (b) accept a client-supplied verifier; (c) accept only the client's result; (c') accept only the client's criterion; (d) skip the `head_sha` check |
| G-KNOW-5 permission closure | fixture: the run's project is visible to the reader, but one application's basis Evidence is not. Mixed into the experience list, that application leaks nothing in body, title, count or ordering explanation; a run with no project mapping is filtered by Evidence visibility too; once a source's permission is revoked it disappears at once | count first and then filter; hide only the link; filter by "the run's project" |
| G-KNOW-6 failures are not suppressed | a target with 3 successes, 1 failure and 1 correction shows all three kinds in the list | truncate after sorting by success count alone |
| G-KNOW-7 conflicts are not promoted | a "practice conflicts with the book" candidate leaves both Memories' status, `superseded_at` and body unchanged. While the candidate table does not exist: `not_applicable`, printing the missing table name (§57.1) | auto-supersede the book's unit on a conflict candidate |
| G-KNOW-8 publish CAS and hash | two candidates built on one Parent publish concurrently: exactly one succeeds; a payload changed after evaluation is rejected; a late worker after a rollback is rejected | drop the hash comparison or the expected-parent check |
| G-KNOW-9 statistics are valid | 6 pairs; 100 cloned seeds; the same sealed split used again and again: publish is rejected, and the missing or violated object names are printed (§57.1) | judge by the p value alone; count n by run |
| G-KNOW-10 the two gates are independent | a candidate vocabulary with a higher total score but one formal relation that has no N09 ground is rejected | promote everything whenever the statistics pass |
| G-KNOW-11 replay carries no future information | in the harness, an outcome written after the task ended is excluded by the `created_at` cut | cut by `occurred_at` (it can be backfilled) |
| G-KNOW-12 closed sets reconcile | `Usage`, `Verifier`, `AcceptanceResult` and the REJECTED reason kind: Rust == DB (§78.2). `mode` reconciles under ADR-0079 G-DOC-17, `not_applicable` naming EvidenceMode until that type exists | add a value in the database only |

- **Scheduling.** G-KNOW-1 to G-KNOW-7 and G-KNOW-12 belong to the first slice. G-KNOW-8 to G-KNOW-11 land with the
  publish protocol, except that G-KNOW-11 is carried early by the replay-harness base card T-KNOW-3, because the harness
  is where the cut lives.
- **Distillation fidelity** (dropping an "only if", shuffling steps) cannot be judged by a rule or by a single judge. It
  belongs to the human gold set of the documents design (E-DOC-5). Reports keep "decidable by rule" and "semantics still
  to be judged" apart.

## Cards and experiments

### Experiments

All use real data, MiniMax only, are sampled by cluster, and report a one-sided Clopper–Pearson 95% bound (CP95) even
when the error count is zero, as the E-A record of ADR-0078 does.

**This repository is already a "book + tasks + acceptances" dataset.**

- The Baseline is long and has git history, which gives it real versions.
- The M29 cards and PRs cite it by § number. A § reference in a PR body is a mention, not a declaration (the rule of the
  documents design, ADR-0079). In the experiments such historical references are tagged `Imported`; they build gold sets
  and controls only, and never enter the formal application records.
- CI results are acceptances that carry a standard version (the workflow SHA).
- All of it is in the public repository and involves no private corpus.

| Experiment | Method | Acceptance |
|---|---|---|
| E-KNOW-1 does structure improve questions about a book | A pilot gold set of about 100 questions on the Baseline: definitions, conditions, steps, tables, cross-section dependencies, plus repeated paragraphs and rewritten versions of a paragraph. Compare flat chunks with "paragraph index + structure location + parent expansion", on the same model, retrieval count and context budget. Runs after the documents card T-DOC-2 | Measure answer correctness, source-evidence Recall@k, version and location precision, and cost. 100 questions is a pilot and does not stand in for a publish power proof |
| E-KNOW-2 are application records honest | Replay the real M29 cards (T01–T08): the § references in PRs and cards are `Imported` historical mentions and CI results are the acceptances. Then have an agent declare formally with `knowledge.declare_use` in a shadow run and compare the two. Add constructed cases: returned but not read, read but not declared, declared with an incomplete implementation, a retry, distillation after the fact. Runs after T-KNOW-1 | Zero over-inference: the real-data form of G-KNOW-2 and G-KNOW-3 |
| E-KNOW-3 does the experience list improve later tasks | Hold out the later cards by time and compare four arms: no list, the list, popularity-only ordering, the list with failure items removed. Expensive (it runs real agent tasks), so it runs after the first slice and only once the owner confirms the budget | Primary metric: the real acceptance outcome. Also count wrong suggestions and tokens |
| E-KNOW-4 candidate quality for corrections and revisions | Data: real user corrections (a private corpus, kept outside git) and real rewrites between document versions (the Baseline's git history is the public part; the design v0.1 → v0.2 pair is private and stays out). Inject changes of unit, of polarity and of condition, and hard "not a contradiction" negatives. Runs after the documents card T-DOC-4 | Precision and recall of conflict candidates; both ends' original text kept; automatic wrong invalidations must be 0 |
| E-KNOW-5 can the publish gate reject "a higher total but unqualified" | Construct: crossing N09, precision up with coverage down, a rare critical task regressing, leakage, future information, content changed after evaluation, concurrency and a crash | All are rejected, and the switch back is atomic. It verifies governance and does not replace E-KNOW-3's effect check |

When the owner uploads their own books (a private corpus, kept outside git), E-KNOW-1 and E-KNOW-4 are rerun on those
books under the same protocol.

### Cards

| Card | Content | Gates | Depends on |
|---|---|---|---|
| T-KNOW-0 | this ADR; Baseline §8.9 (applications and acceptances, the experience list, the publish protocol as a supplement to ADR-0078's E-F) | none | T-DOC-0 (ADR-0079) |
| T-KNOW-1 | the tables `knowledge_applications` and `run_acceptances`, plus two MCP tools | G-KNOW-2 / 3 / 4 / 12 | T-DOC-2 (a target must be able to point at a Version plus selector) |
| T-KNOW-2 | the experience-list projection, wired into `context.assemble` | G-KNOW-5 / 6 / 7 | T-KNOW-1 |
| T-KNOW-3 | the rebuild gate and the replay-harness base | G-KNOW-1 / 11 | T-KNOW-2 |

**The closed loop of the first slice:**

1. A document with a fixed version and locators (preferably this repository's Baseline) is cited explicitly by a real
   task (`knowledge.declare_use`).
2. The task leaves an acceptance that carries a standard version (CI).
3. When the next task citing the same passage opens, the experience list `context.assemble` returns shows this
   application and its result, and can expand back to source.
4. Delete every derived product and rebuild: the result does not change.

## Deferred

| Deferred item | Upgrade signal | To be shown before upgrading |
|---|---|---|
| Whole-book distillation | local extraction keeps repeating the same chapter, or hot chapters are already well covered | batch processing saves total cost and loses no conditions |
| Model-generated experience Memory | the experience list has grown long enough to need a summary, and there are varied, independent, comparable applications | more useful than the raw case list, with scope and uncertainty kept |
| Vocabulary and concept alignment | logs show term differences repeatedly causing missed recall | gains on gold synonym and polysemy cases, with N09 admission not degraded |
| SKOS auto-evolution / the publish protocol | enough independent replay samples and valid candidates exist | the D-H thresholds are met; if not, keep the Parent |
| RAPTOR-style summary trees | cross-chapter synthesis questions grow in share and local retrieval often misses | better synthesised answers under the same budget, traceable to source (RAPTOR appendix E: 6 of 150 sampled nodes, 4%, hallucinated) |
| GraphRAG community summaries | many global questions across documents | real-task gain exceeds the cost of graph building, summaries and permissions (GRAPHRAG: the evidence is mainly judge preference) |
| HippoRAG-style graph propagation | multi-hop questions fail often although the right source text is in the library | multi-hop recall improves and similarity edges do not become formal relations (HIPPORAG: on HotpotQA it came out below the baseline) |
| Learned ranking | fixed rules show repeatable missed recall or popularity bias | the paired success rate improves, and failure experiences and rare cases are not suppressed |
| Materialised experience list | `context.assemble` P95 exceeds its budget | G-KNOW-1 holds |

If a graph store is ever wanted, no graph database needs to be introduced: LightRAG v1.5.6 implements graph storage on
native PostgreSQL tables and drops the Apache AGE dependency (LIGHTRAG). That shows feasibility only; its performance
claims are not taken as our conclusion.

## Alternatives rejected

- Turning the whole book into a complete knowledge graph before use: two axes and three structures already satisfy
  "not flat", the full graph is a derived product, and it is built when a signal calls for it.
- Recall along the single path "concept → tree → passage": a missing concept would block the right source text (D-I).
- Atomic knowledge units of one sentence each: the premises are lost.
- "The more it is used the more correct it is", or letting popularity influence authority: popularity affects order only.
- "Recalled once means adopted" and "adopted means effective": the assertions are kept apart (D-B).
- A general N for cross-project generalisation: the four questions each need a different amount of evidence (D-E).
- Reusing EvoOntology's acceptance gate as is, `decide_gt` (strictly greater mean) or `decide_judge` (more wins and no
  critical error): neither has a significance test or a minimum sample (EVO-REPO).
- Promoting the candidate's relations wholesale when the statistics win: the two gates are independent (D-H).
- Allowing Schema changes during evolution: EvoOntology allows it, and this project rejected it earlier (ADR-0078 D-H:
  the Schema layer changes by ADR only; D-G).
- Implementing `exactMatch` as an identity merge or as union-find (SKOS §10.6.8).
- Zep or Graphiti-style "the model judges a contradiction and invalidates the old edge": violates N09 (ZEP).
- Mem0 or A-MEM-style model UPDATE or DELETE rewriting memory: a model may only produce candidates (MEM0, AMEM).
- ACE-style in-place edits of bullets, embedding de-duplication and model helpful/harmful counters as the formal ruling
  (ACE).

## Consequences

- Today this ADR and Baseline §8.9 change text only. No code and no migration change. The two tables arrive with
  T-KNOW-1, and the experience list with T-KNOW-2.
- A card that implements a gate adds that gate's red record to this file.

## References

Verified 2026-10-20 against the design v0.2 source register. The EvoOntology repository and commit were also re-read on
2026-10-20 through the GitHub API (full SHA and commit date). An unmarked entry was read in the part the text relies on.

- EVO — Chong et al., EvoOntology: A Self-Evolving Ontology Layer for Data Agents, arXiv:2609.15779v1 (2026-09-14):
  https://arxiv.org/html/2609.15779v1. Only v1 exists. The paper's acceptance rule is "gain >= tau" with tau not given;
  the repository below uses a strict greater-than, so the two disagree.
- EVO-REPO — github.com/ruc-datalab/EvoOntology at commit c94389b764394379086ff25e50d0e0f4396167b4 (2026-10-09):
  `evoontology/evaluation/evaluation.py` (`decide_gt`, `decide_judge`; no significance test and no minimum sample),
  `evoontology/trigger/trigger.py` (a trigger threshold of 30 new trajectories or 7 days, which is not an acceptance
  gate), `evoontology/evolution/session.py` (checks equal lengths, unique case ids and finite scores;
  `unacceptable_regressions` is declared by the caller and is not computed).
- SKOS — W3C Recommendation 2009-08-18: https://www.w3.org/TR/skos-reference/. §10.3 (S44, S45: `exactMatch` symmetric
  and transitive), §10.1 (`closeMatch` not transitive), §8.6.6 (`broader` not transitive, `broaderTransitive`
  transitive), §8.6.8 (cycles in a hierarchy are not forbidden), §10.6.8 (`owl:sameAs` across schemes is generally
  inappropriate).
- ST-MN — McNemar, Psychometrika 12(2), 1947, doi:10.1007/BF02295996 (bibliography checked; full text not read).
- DWORK — Dwork, Feldman, Hardt, Pitassi, Reingold, Roth, Generalization in Adaptive Data Analysis and Holdout Reuse,
  arXiv:1506.02629v2 (2015-09-25): https://arxiv.org/abs/1506.02629 (abstract checked).
- RAPTOR — Sarthi et al., RAPTOR: Recursive Abstractive Processing for Tree-Organized Retrieval, arXiv:2401.18059v1
  (2024-01-31): https://arxiv.org/abs/2401.18059. The main experiment uses the collapsed tree; appendix E samples 150
  nodes of 40 stories and finds 6 (4%) hallucinated.
- GRAPHRAG — Edge et al., From Local to Global: A Graph RAG Approach to Query-Focused Summarization, arXiv:2404.16130v2
  (2025-02-19): https://arxiv.org/abs/2404.16130.
- HIPPORAG — Gutiérrez et al., HippoRAG: Neurobiologically Inspired Long-Term Memory for Large Language Models,
  arXiv:2405.14831v3 (2025-01-14, NeurIPS 2024): https://arxiv.org/abs/2405.14831. Table 4 against ColBERTv2: average
  48.1 against 42.5, but HotpotQA 55.0 against 57.7.
- HIPPORAG2 — Gutiérrez et al., From RAG to Memory: Non-Parametric Continual Learning for Large Language Models,
  arXiv:2502.14802v2 (2025-06-19, ICML 2025): https://arxiv.org/abs/2502.14802. Appendix G.1: the fallback to dense
  retrieval applies only when the filtered triples are empty.
- LIGHTRAG — LightRAG v1.5.6 release (2026-08-06), native PostgreSQL table graph storage without Apache AGE (PR #3103):
  https://github.com/HKUDS/LightRAG/releases/tag/v1.5.6.
- ZEP — Rasmussen et al., Zep: A Temporal Knowledge Graph Architecture for Agent Memory, arXiv:2501.13956v1
  (2025-01-20): https://arxiv.org/html/2501.13956v1.
- AMEM — Xu et al., A-MEM: Agentic Memory for LLM Agents, arXiv:2502.12110v11 (2025-10-08, NeurIPS 2025):
  https://arxiv.org/abs/2502.12110.
- MEM0 — Chhikara et al., Mem0: Building Production-Ready AI Agents with Scalable Long-Term Memory, arXiv:2504.19413v1
  (2025-04-28): https://arxiv.org/abs/2504.19413. The update phase lets the model choose among ADD, UPDATE, DELETE and
  NOOP.
- ACE — Zhang et al., Agentic Context Engineering: Evolving Contexts for Self-Improving Language Models, arXiv:2510.04618v3
  (2026-03-29, ICLR 2026): https://arxiv.org/abs/2510.04618.
