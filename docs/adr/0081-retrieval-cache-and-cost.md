# ADR-0081 — Knowledge-base caching, recall accuracy and embedding / rerank cost

- Status: Accepted (2026-10-20). Card T-RET-0 (docs only). Content authority: design v0.2 §19, a private document kept
  outside this repository (its numbering is the design's own, not Baseline §19). The design lead decided it on
  2026-10-20 under delegation from the repository owner. Amended the same day by the design's §19.5 note, which splits
  T-RET-1 into T-RET-1a (ledger) and T-RET-1b (query-hash log) and records the deferred metric and the `billable_tokens`
  ponytail (D-A, Cards).
- Relates to: Baseline §19.1 (ModelCallLedger), §23 (`cand_k`), §51, §55 (§55.6), §57.1, §78.1, §80.1; ADR-0076 (cache
  layer crate).

## Context

The owner asked for the knowledge-memory database to be designed for three things: caching, recall accuracy, and the
spend on embedding and reranking. The owner added that this must be settled by experiment, and named the cache-hit
practice of DeepSeek and Claude as the thing to learn from.

The repository already has the substrate, so this ADR adds no new store for cached values:

- **Provider usage is parsed but dropped.** `crates/adapters/src/byok.rs` reads `prompt_tokens_details.cached_tokens`
  into `cached_input_tokens`; nothing persists it and no metric exports it.
- **Query embedding goes through DashScope's OpenAI-compatible interface** and sends no `text_type`
  (`crates/retrieval-provider/src/adapters.rs`). The query-embedding cache of ADR-0076 is wired but not enabled: the
  three `HUMAUX_GATEWAY_EMBEDDING_*` deployment values (provider id, model id, model revision) are empty
  (`deploy/env/values/gateway.env`).
- **Candidate depth is `min(top_k × 5, 200)`** with a default `top_k` of 5, so `cand_k` is 25. The multiplier is the
  constant `RETRIEVAL_CANDIDATE_MULTIPLIER` (`crates/contracts/src/retrieval_config.rs`,
  `crates/retrieval/src/request.rs`).
- **Every Evidence is embedded in full each time** (`seal_and_embed`, `crates/adapters/src/projection_worker.rs`).
- **The distillation prompt varies by variant.** The system prompt and the tool schema of
  `crates/adapters/src/distill_reasoner.rs` change with the authority-class menu allowed for the evidence's origin and
  with whether an emotion field is offered, so variants diverge at the start of the prefix.
- **Stage timings exist** (`bins/gateway/src/recall.rs`), without a baseline report.

The goal is restated as measurable indicators (the "optimise" contract: measure first, find the bottleneck, then
propose, then state the expected gain). Numbers in the "Current measurement" column are aggregates from a read-only
probe of the owner's previous deployment (2026-10-20) and from a public-data pilot (E-CACHE-2). That deployment's
corpus is private and never enters this repository.

| # | Indicator | Current measurement | Bottleneck / judgement |
|---|---|---|---|
| M1 | **Continuation hit@5** on the 198-question set (single positive per question, so hit@5 = recall@5); plus the **pool ceiling** (share of questions whose correct item enters the candidate pool) and the **conversion** (share of in-pool items that reach the top 5) | The new pipeline is **unmeasured**: no harness exists (`continuation_198_v2` is `NOT_DECLARED`, §69). Old system (hybrid retrieval plus rerank, 50–60 candidates): hit@5 0.773–0.778, pool ceiling 0.798–0.815 across runs (each from a different run and denominator, so no exact conversion is derived from them; E-RET-0 measures it on one run); with 30 / 50 / 60 candidates the ceiling was 0.803 / 0.843 / 0.865 | **Recall is the bottleneck.** The new pipeline has one dense leg and, at the default `top_k` of 5, takes 25 candidates; queries probably do not use the query role. Its ceiling is probably below the old system's, so it is measured first |
| M2 | **LLM input-cache hit rate** H = Σ cache-read tokens ÷ Σ total input tokens, per provider × model × purpose | **Not measurable.** The new system parses `cached_input_tokens` and drops it; the old system handled about 760 million input tokens in 90 days (about 728 million on one model) and recorded no cache field | Meter first. Distillation's tool schema and system prompt vary by authority-class menu × whether an emotion field is offered, so the prefix forks at its start |
| M3 | **Re-embedding volume per document revision** = bytes newly embedded ÷ bytes in full | 100% today (each Evidence is embedded in full). Pilot (E-CACHE-2): content addressing needs about 2.2%–2.5%, a prefix chain about 81% | Content-address the final input (D-C) |
| M4 | **Retrieval-side cache hits**: request hit rate of the query-vector cache; reuse rate of single-pair rerank scores | The query cache is wired but off (the three deployment values are empty); no query-hash log exists. Old system, caches keyed by library state: result cache 0.96%, rerank cache keyed by the candidate set 0.39% | A cache bound to library state fails under frequent agent writes. Cache only what does not depend on library state |
| M5 | Stage p50 / p95 (embed / qdrant / hydrate / rerank / assemble), cold and warm | Stage timings exist; no baseline report | Measure later |
| M6 | **Safety constraint**: no cache hit may return a tombstoned, invisible or cross-tenant item | The current query cache holds vectors, not results; the hydrate gate runs as usual | Every new cache layer must pass G-RET-3 |

**Expected gains** (only quantities with a basis; the rest are "to be measured"):

- M2: at the list prices of the model that carried most of the old system's usage (input 2.10 and cache read 0.42 CNY
  per million tokens, MM-CACHE; list price, not the bill; plan status UNKNOWN), raising the input hit rate from 44% to 80% would have saved
  about 440 CNY over those 90 days. Distillation calls are single-evidence and short, so what is reachable is to be
  measured.
- M3: re-embedding volume per revision from 100% to about 2%–3% (pilot).
- M1: ceiling gain to be measured. In the old system, going from 30 to 60 candidates raised the ceiling by 6.2 points.
- M4: reuse of single-pair rerank scores to be measured; the old candidate-set key reached 0.39%.

## Decisions

### D-A (D-RET-1) Make caching measurable: four ledger categories and a query-hash log (implemented by T-RET-1a, T-RET-1b)

- `ops.model_call_ledger` gains two columns for LLM calls, `provider_cache_read_tokens` and
  `provider_cache_write_tokens`.
  - Both are nullable. **NULL means "the provider did not report", never 0.** Embedding and rerank rows leave both NULL.
  - `input_tokens` stays the **total** prompt tokens. With the existing input and output columns the ledger yields four
    non-overlapping categories: new input, cache write, cache read, output. Baseline §19.1 holds the derivation.
  - A rate over these columns leaves a NULL row out of both its numerator and its denominator instead of counting it as
    zero.
- **Normalisation happens in one place**, the single usage→ledger normaliser in `adapters` (today `contribution_reasoner::finalize_from_usage`, the function every generative hop already routes through), and converts per protocol. Baseline
  §19.1 holds the mapping for OpenAI-compatible replies (MiniMax, DashScope), Anthropic-compatible replies and
  DeepSeek. It must be explicit because the same field name is not the same measure: OpenAI-compatible `prompt_tokens`
  is the total and `cached_tokens` a part of it, while Anthropic-compatible `input_tokens` counts only new input, beside
  `cache_creation_input_tokens` and `cache_read_input_tokens` (MM-CACHE).
- **Metric and alerts.** The family `llm_input_tokens_total{provider,model,purpose,category}`, from which H derives, is
  **deferred** (design §19.5 note, 2026-10-20) until the alert thresholds are chosen. Thresholds are configuration
  (§78.1), set after two weeks of observation.
  - ponytail: during those two weeks H is computed by SQL against the ledger; add the family when the thresholds are
    set.
  - No hit-rate target is borrowed from vendor guidance on long agent loops. Distillation calls are single-evidence and
    short, so those figures do not describe them.
- **Our own caches keep ADR-0076's `cache_requests_total{cache,result}`.** Each new layer adds one `cache` label value
  (today the set has one value, `embed_query`).
- **`billable_tokens` is unchanged** and still equals the total input: a cache read is priced in full, so cost estimates
  are an upper bound. ponytail: add cache-price columns to `provider_pricing_versions` and one leg to `compute_cost`
  when the saving needs to be priced.
- **Query-hash log** `ops.retrieval_query_log`.
  - Fields: tenant, time, scope, `HMAC(tenant secret, normalised query)`, the result of each cache layer, candidate
    count, per-stage timings.
  - **No plaintext is stored.** Retention is configuration (§78.1), 30 days by default.
  - It is used for two things only: replaying to estimate cache hits (E-CACHE-1) and observing recall drift.
  - ponytail: one table, partitioned by time; add a sampling pipeline when cross-tenant analysis is needed.

### D-B (D-RET-2) Order LLM prompts by stability; isolate variants only after an experiment (implemented by T-RET-4)

- **Layers, from stable to changing:** (1) tool and output schema; (2) system rules; (3) shared data, meaning the
  context of one document or section, used for document processing only; (4) this call's evidence and instructions.
  The cache discipline of the Claude API documentation is the model: cached content first, JSON key order stable, and
  nothing that changes between requests inside the cached part (CLAUDE-PC).
- Layers 1–3 of one version must be **byte-identical**. Serialisation is deterministic (serde_json's default ordered
  map); time, ids and progress go into layer 4 only.
- Within one run, a purpose **does not change model and does not add or remove tools**; changing tool definitions
  invalidates the whole cache (CLAUDE-PC).
- **Scheduling** groups calls by *prefix fingerprint* = (provider, model, purpose, hash of tools + system). Within a
  group one warm-up call goes first, and concurrency is released once it has begun returning. A parallel request sees the
  Claude cache only after the first has begun returning (CLAUDE-PC); a DashScope explicit cache is billed at creation
  before it can be hit (DASH-CC); DeepSeek stores a shared prefix only after a request has revealed it, so the second
  request with the same start misses and the third hits (DS-KV). The concurrency cap is unchanged.
- **The distillation variant problem.** The tool schema and the grade menu in the system prompt vary by source. That is
  deliberate, from the card 24 soak of 2026-09-26 (recorded in the doc comment of `render_system_prompt` in
  `crates/adapters/src/distill_reasoner.rs`): removing the illegal options keeps the model from over-grading or
  inventing types. It is therefore **not changed directly**. E-CACHE-3 compares two arms:
  - arm A = the current text plus variant-grouped scheduling;
  - arm B = fixed full-set tool schema and system text, with the grades allowed for this evidence placed in the envelope
    as data.
  - It measures four numbers together: H, the over-grading rate, the parse-failure rate and the total cost per
    qualified output. Arm B is adopted only if its over-grading and parse-failure rates are no worse than arm A's
    (paired, with a non-inferiority margin fixed beforehand).
- **Thresholds:** MiniMax caches from 512 input tokens (MM-CACHE), DashScope from 1024 (DASH-CC). Below the threshold we
  pay as usual; **we do not add useless content or more private evidence to reach it.**

### D-C (D-RET-3) Document vectors are reused by content address of the final input; no prefix chain (implemented by T-RET-5)

- **Reuse key** = H(generation fingerprint, `text_type`, hash of `instruct`, preprocessing version, **the complete final
  input sent to the embedding model**).
  - The generation fingerprint is provider + model + revision + dimension + version, as the existing cached query path
    already uses it (ADR-0076 D-D).
  - The document version id is **not in the key**; it lives in the reference relation.
- **Scope is the tenant.** Nothing is shared across tenants, so a hit never reveals what another tenant holds.
- **ponytail implementation: no new vector table.**
  - The Qdrant point payload gains `embed_input_sha256`, indexed.
  - Before the projection writes, it looks up an existing point in the same tenant's placement by (fingerprint, input
    hash); on a hit it copies the vector and makes no provider call.
  - Ceiling: the cache lives only as long as the last point that carries it, so deletion semantics are naturally
    correct (step 5 of §37 removes the points).
  - Upgrade path: if "delete, then re-import the same content" turns out to be common, move to a PostgreSQL artifact
    table with reference counting and a deletion path.
- **Chunks must be stable** at paragraph / structure-node boundaries (ADR-0079 D-C, D-DOC-3), not at fixed offsets; an
  inserted sentence would otherwise change everything after it.
- **The context prefix (heading path, project, document name) is part of the final input.** The pilot shows that adding
  the heading path does not hurt reuse (E-CACHE-2).
- **Why not a prefix chain.** A KV cache must match from the start because attention depends on earlier tokens, which is
  why DeepSeek's production cache matches 128-token blocks along a hash chain (DS-PROD). An embedding has no such
  constraint. On 84 revisions of the Baseline, the prefix chain re-embedded about 81% of the bytes and content
  addressing about 2%.

### D-D (D-RET-4) Query vectors: fix the role first, then enable the cache (implemented by T-RET-3)

- Queries move to DashScope's native interface with `text_type=query`. `instruct` carries a version that enters the
  generation fingerprint. The document side stays `document`, so **no index rebuild**.
  - Premise, to be re-verified against the vendor's current documentation by T-RET-3 before the change ships: the
    native interface offers `text_type` (`query` / `document`) and `instruct` (query only), and the compatible
    interface offers neither.
  - **Adoption is decided by E-RET-2**: hit@5 paired no worse, and the pool ceiling not lower.
  - Whether the compatible interface silently accepts the field is UNKNOWN. E-RET-2 tests it once, by checking whether
    the two requests return the same vector.
- The generation fingerprint must include the endpoint kind, `text_type` and the `instruct` version. Otherwise changing
  the role would still hit old vectors (G-RET-4).
- Enabling the existing query cache needs the three `HUMAUX_GATEWAY_EMBEDDING_*` deployment values. That is an owner
  action; agents do not fill them.
- TTL starts at 24 hours. Whether to switch to TTI (renewal on hit) is decided after the E-CACHE-1 replay; moka's TTL
  (counted from insertion) and TTI (counted from last access) differ, and ADR-0076 configures a TTL.

### D-E (D-RET-5) Recall-first accuracy plan; rerank after recall (implemented by T-RET-2, T-RET-6)

In the old system the pool ceiling (0.798–0.815 across runs) was the binding limit: about a fifth of the questions never
entered the candidate pool, and no ranking change can recover those. How much ranking loses inside the pool is measured on
one run by E-RET-0, not derived from numbers of different runs. So the order is fixed, and **each step is its own paired experiment, never several
changes at once**:

1. stage-loss diagnosis (E-RET-0);
2. candidate depth: the multiplier 5, today a constant, becomes configuration (§78.1) and is tried at 25 / 50 / 100 /
   200 candidates (E-RET-1);
3. query role (E-RET-2);
4. BM25 + RRF, using Qdrant's built-in BM25 (§17.6) (E-RET-3);
5. deterministic context prefix (E-RET-4).

- **The multiplier becomes a registered-profile field `cand_multiplier`**, default 5, never caller input
  (§55.1 / §55.6 unchanged). The formula in §23.3 and §55.6 becomes `min(top_k × profile.cand_multiplier, 200)`. It is
  **planned, T-RET-6**; until then the multiplier is the constant 5, and the wire string `cand_k_formula` stays
  `min(top_k*5, 200)`; afterwards it renders the resolved multiplier.
- **Before BM25 lands** the following must be checked against Qdrant's current documentation: the default RRF constant of
  the Qdrant version in use, the Chinese tokenizer, and per-tenant IDF. All three are UNKNOWN today. The Python BM25 in
  the experiment only estimates the gain and does not represent the online configuration.
- **Local rerank** (bge-reranker-v2-m3 against Qwen3-Reranker-0.6B) comes after recall and is chosen by p95 measured on
  the target machine (E-RET-5). Running models on the local machine needs the owner's decision.

### D-F (D-RET-6) Rerank scores are cached per (query × single document) pair (no card yet; after E-RET-5)

- **Key** = (tenant, hash of the query's final input, hash of the document's final input, reranker fingerprint
  (weights / tokenizer / quantisation / runtime version), truncation-policy version).
- The value holds the **score only, never the text**. The cache is a bounded moka cache; a hit still passes the
  PostgreSQL gate before results are ordered.
- Adding one document to a candidate set costs one new score; the others still hit.
- The old semantics are retired: a key built from the hash of the sorted candidate set, FIFO of 256. Under production
  load in the old system it hit 0.39% of the time, and it left the query and the model version out of the key.

### D-G (D-RET-7) No semantic cache; the candidate cache is deferred

- **Semantic cache** (reusing a result for a similar query): rejected. It can be poisoned, similar queries can differ
  in project, time or negation, and it would hide recall defects.
- **Candidate-list cache:** it would have to bind to a corpus epoch plus an index watermark. With frequent agent writes
  its hit rate is very low (0.96% in the old system). A new ADR is opened only when E-CACHE-1 shows that repeats inside
  one epoch are considerable.

## Modules and table ownership

| Module | Responsibility | Tables | Dependency direction |
|---|---|---|---|
| `adapters` usage→ledger normaliser (extended; today `contribution_reasoner::finalize_from_usage`, fed by `byok`'s parsed usage) | The only place that turns each protocol's usage into the four categories | none | provider reply → ledger |
| `adapters::model_call_ledger` (extended) | Persists the four categories | `ops.model_call_ledger` gains two columns | append-only |
| `gateway::recall` (extended) | Writes the query-hash log; reads candidate depth from configuration; later the BM25 leg and fusion | `ops.retrieval_query_log` (new) | reads config; writes ops |
| `retrieval-provider` DashScope adapter (extended) | Queries use the native interface with `text_type` / `instruct`; fingerprint extended | none | infra-egress |
| `adapters::projection_worker` (extended) | Before writing, looks up a reusable vector in Qdrant by (fingerprint, input hash) | Qdrant payload gains a field | Qdrant ← PostgreSQL source of truth |
| `adapters::distill_reasoner` / scheduling (extended) | Prefix-fingerprint grouping with warm-up before concurrency; (after E-CACHE-3 passes) fixed prefix | none | output contract unchanged |
| Offline harness (outside the repository, Python standard library) | E-RET-0..4, E-CACHE-1 and E-CACHE-3 | none (private corpus stays in a private evaluation store) | reads the old library and a snapshot of the new one, read-only |

## Gates

All are three-state (`pass` / `fail` / `not_applicable`, §57.1) and **all are planned**. Each gate exists only after its
inject → red → fix → green record (§80.1) lands in the card that implements it, and that card adds the record to this
ADR. Module gate ids such as `G-RET-1` fall outside the §80.1 anchor grammar (`G<n>-<n>`), so, like `G-M29-1`, they
are not §80.1 registry rows; registering them there needs its own spec change.

| Gate | Criterion | Injected fault |
|---|---|---|
| G-RET-1 cache-token accounting (T-RET-1a) | Every LLM ledger row carries `provider_cache_read_tokens` / `provider_cache_write_tokens` as either a number or an explicit NULL ("not reported"), never a fabricated 0. Fixed reply samples of the **one wired protocol** (OpenAI-compatible) convert so that the four categories sum to total input + output. The fixed samples of the other two protocols (Anthropic-compatible, DeepSeek) are `not_applicable`, and the line prints the missing adapter's name (§57.1) | (a) record an unreported cache count as 0. (b) From the day the Anthropic-compatible adapter is wired: read that reply's `input_tokens` as total input |
| G-RET-2 prefix byte stability (T-RET-4) | For every LLM purpose, under one variant, two renderings of layers 1–3 with different input and different clocks are byte-identical | insert a timestamp into the system text; take the tool order from a HashMap |
| G-RET-3 caches do not resurrect (T-RET-6) | With the query vector and the rerank scores (and, later, candidates) already cached, tombstone a Memory: the next recall does not return it. The same query from another tenant does not hit | skip the PostgreSQL hydrate gate after a cache hit |
| G-RET-4 fingerprint completeness (T-RET-3) | Changing the model revision, `text_type`, the `instruct` version, the truncation policy or the reranker version makes each of them miss | drop any one of these fields from the key |
| G-RET-5 exact vector reuse (T-RET-5) | A vector is reused only if the fingerprint **and** the final-input hash both match; changing one character, or only the context prefix, calls the provider | key on the hash of the raw text (without the context prefix) |
| G-RET-6 harness completeness (the log part: T-RET-1b; the key-set, duplicate-key and manifest part lives in the out-of-repo offline harness, T-RET-2, and is not a repo gate) | The expected key set (question, arm, repetition) is complete; a duplicate key is an error, not an overwrite; the effective manifest (snapshot hash, fingerprints, configuration) is recorded | allow duplicate keys and let the later write win |

G-RET-1 is narrowed on purpose (design §19.5 note): `byok` has one reply protocol today, so only that one is
normalised. The other two protocols' fixed samples are reported `not_applicable`, naming the missing adapter, and the card
that wires an adapter replaces its `not_applicable` with the real sample and adds its injection.

## Experiments

**Common rules.**

- Real data stays on the local machine; only aggregate numbers enter this repository.
- Comparisons are paired. One primary comparison per step is registered before the run. It is judged per question by
  exact McNemar, reporting N, b, c and p. Questions from the same slot or project are clustered and compared with a
  paired bootstrap; cluster means never enter McNemar. Even with zero errors the 95% Clopper-Pearson bound is reported.
- Why b and c are reported: on 198 questions a net gain of 6 gives p = 0.031 when b / c = 0 / 6 and p = 0.18 when
  b / c = 4 / 10 (recomputed locally).
- The 198 questions took part in tuning the old system, so they are a **development / regression** set only.
  Confirmation uses a new sealed set: questions built by the same rule from the state slots created after 2026-08-15,
  sealed by the design lead without looking at results.
- **Data.** The old system's memory database: entries with status active or unset, about 55 thousand entries and about
  56 million characters. The 198-question set carries an expected memory id per question.
- **Spending comes in two stages.** Stage one reuses the v3 vectors already in the old vector store, read-only, at zero
  cost, for the structural experiments. Stage two uses v4 (query role, final numbers): full embedding costs about
  25 CNY synchronously, Batch pricing is unverified (official pages disagree) and is not counted on. Alibaba-side spend is charged by default
  against the owner's experiment budget and proceeds unless the owner objects.

| Experiment | Question | Method | Data class | Cost bound | Acceptance rule |
|---|---|---|---|---|---|
| E-RET-0 | Where does the new pipeline lose items? | Simulate the new semantics: dense only, 25 candidates, visibility filter, top 5. Record per question whether the vector leg found it, whether it survived filtering, whether it survived truncation, and whether it reached the top 5 | Private real data, local; the stage-one part uses existing v3 vectors | v3 stage 0; v4 stage about 12.5–25 CNY | Diagnostic; no accept / reject. Its output ranks the bottleneck stage |
| E-RET-1 | How deep must the candidate pool be? | Pool-ceiling curve at 25 / 50 / 100 / 200 candidates | Private real data, local; existing vectors | 0 | Primary comparison: hit@5 at 25 against 100 candidates, with the ranking method held fixed |
| E-RET-2 | Does the query role help? | Compatible-interface default against native `text_type=query` + `instruct`; also test whether the compatible interface accepts the field (are the two vectors equal?) | Private real data, local | 198 × 2 queries, negligible | Adopt only if hit@5 is paired no worse and the pool ceiling does not drop (D-D) |
| E-RET-3 | Does BM25 + RRF help? | Dense against dense + BM25 (Chinese character bigrams plus English / identifier tokens; sweep the RRF constant). Report the union oracle (how many questions the new leg recovers) | Private real data, local | 0 | Primary comparison registered before the run; the union oracle is reported beside it |
| E-RET-4 | Does a deterministic context prefix help? | Only if room remains after E-RET-0..3: document name / project / section prefix against none | Private real data, local | One more embedding, about 12.5–25 CNY | Primary comparison registered before the run |
| E-CACHE-1 | Query-cache TTL / TTI | Replay the D-A log in time order once it is online (capacity, TTL / TTI and restarts simulated). The old capture file was polluted by evaluation replays and is an upper bound only: without its busiest day, 43.9% of queries repeat, nearly all within 5 minutes | Query-hash log (no plaintext) | 0 | Decides TTL against TTI (D-D); also decides whether to open the candidate-cache ADR (D-G) |
| E-CACHE-2 | How much of a revised document's vector work can be reused? | Pilot done: 85 versions of the Baseline as of main `197e5f0` (84 adjacent revisions; the newest version has 4,238 paragraphs, about 0.87 MB). Prefix chain: 80.6% of bytes re-embedded, median per-revision reuse 11.6%. Paragraph hash against the previous version: 2.5%, median reuse 98.0%. Against all older versions: 2.2%, 98.4%. Heading path in the key: 1.65% (the denominator grows, the absolute volume is comparable). Limit: one document, written incrementally, so not representative of book revisions | Public (this repository's history); book revisions are retested on the E-KNOW-4 corpus (ADR-0080) | 0 | Pilot supports content addressing (D-C); the book retest repeats the comparison |
| E-CACHE-3 | LLM prefix layout | MiniMax (M3.1-Flash), the same batch of 40 evidence items in both arms. Arm A = current text + variant-grouped warm-up. Arm B = fixed full-set schema and system text, with the allowed grades in the envelope. Measure H, over-grading rate, parse-failure rate and total cost per qualified output; pair by evidence | Not fixed by the design (UNKNOWN); the card that runs it declares it | at most USD 1 | Arm B is adopted only if over-grading and parse-failure rates are no worse than arm A's (paired, margin fixed beforehand) (D-B) |
| E-RET-5 | Local reranker | bge-reranker-v2-m3 against Qwen3-Reranker-0.6B; candidates 20 / 50 / 100; truncation 256 / 512; p95 on the target machine | Private real data | Pending the owner's decision on how to run it (D-E) | Chosen by target-machine p95 (D-E) |

## Cards

| Card | Scope | Gates |
|---|---|---|
| T-RET-0 | This ADR; Baseline §19.1 and §51; the `cand_k` wording in §23.3 and §55.6 (docs only; same rule as T-DOC-0 and T-KNOW-0) | none |
| T-RET-1a | `adapters` (byok, model_call_ledger, contribution_reasoner): the two ledger columns and normalisation (migration 0257), for the one wired protocol. Cites "ADR-0081 D-A (D-RET-1)". **Do first**: without it no later gain can be measured | G-RET-1 |
| T-RET-1b | `gateway::recall`: the query-hash log (new table) | the log part of G-RET-6 |
| T-RET-2 | Offline harness (outside the repository, Python standard library, private data); stage one of E-RET-0..3. Only aggregate numbers enter this ADR | none |
| T-RET-3 | D-D after E-RET-2: query role and fingerprint | G-RET-4 |
| T-RET-4 | D-B: prefix-grouped warm-up scheduling; fixed prefix only if E-CACHE-3 passes | G-RET-2 |
| T-RET-5 | D-C: vector reuse (same batch as T-DOC-2, ADR-0079) | G-RET-5 |
| T-RET-6 | After E-RET-1 / 3: candidate-depth configuration (`cand_multiplier`) and the BM25 leg | G-RET-3 |
| Later | Local rerank and the D-F pair cache, after E-RET-5; no card yet | |

Code state behind the T-RET-1 split (design §19.5 note, 2026-10-20): `byok` has one reply protocol, OpenAI-compatible, so
T-RET-1a normalises only that one; the Anthropic-compatible and DeepSeek samples are `not_applicable` in G-RET-1 until
their adapters exist. The `llm_input_tokens_total` family is deferred (D-A), and `billable_tokens` stays equal to total
input (D-A).

## Deferred items

| Item | Upgrade signal |
|---|---|
| Candidate-list cache | E-CACHE-1 shows that repeats inside one corpus epoch are considerable |
| Vector reuse as a PostgreSQL artifact table | "Delete, then re-import the same content" becomes common |
| Dimension from 1024 to 512 | Qdrant memory becomes the bottleneck. The vendor's table reportedly scores 512 lower than 1024 by 0.65–2.96 retrieval points; unverified, to be checked before acting |
| Query rewriting / multi-query | Only as an experiment on continuation-type queries that omit context: it costs extra LLM calls and may lower top-ranked quality |
| DeepSeek API as a provider | A paired evaluation against MiniMax on the distillation task; `user_id` would carry a stable tenant hash |

## Alternatives rejected

- Self-hosting DeepInfer / vLLM / SGLang with LMCache / Mooncake / 3FS: we have no model KV to manage, and the hardware
  threshold and cost do not fit. DeepInfer targets one model on two hardware families and does not open-source its KV
  cache system (DS-SCOPE).
- A prefix chain for embeddings: it needs about 81% new bytes per revision against about 2% for content addressing
  (E-CACHE-2).
- A rerank cache keyed by the hash of the sorted candidate set: 0.39% hit rate in the old production, and it omits the
  query and the model version (D-F).
- A semantic cache: poisoning risk, and it hides recall defects (D-G).
- TTL / LRU / invalidation broadcast in place of the PostgreSQL visibility and deletion gate (M6, G-RET-3).
- Padding a prompt to reach a cache threshold; sharing cache prefixes across tenants.
- Changing the distillation schema to a fixed full set without an experiment: the card 24 soak (D-B), where illegal
  options in the menu led to over-grading and invented types.

## References

Read 2026-10-20. None of the vendor pages carries a date, so the read date is the version marker.

- CLAUDE-PC — Claude API docs, Prompt caching: https://platform.claude.com/docs/en/build-with-claude/prompt-caching
  (scope `tools → system → messages`; identical-content requirement; tool-definition changes invalidate the cache;
  placement and warm-up advice read)
- DS-KV — DeepSeek API docs, Context caching: https://api-docs.deepseek.com/guides/kv_cache (cache-prefix units, the
  A+B / A+C / A+D example, usage fields `prompt_cache_hit_tokens` / `prompt_cache_miss_tokens`; the minimum unit length is
  not stated, so UNKNOWN)
- DS-PROD — DeepSeek DeepInfer repository, `doc/inference_deployment_qa.md`, "KV cache storage" (128-token block hash
  chain, metadata-only prefix matching): https://github.com/deepseek-ai/DeepInfer
- DS-SCOPE — same repository, README (offline inference only; one supported model; NVIDIA SM100 and Ascend 950 only;
  "not included" list: KV cache system, prefill / decode separation, data-parallel load balancing)
- MM-CACHE — MiniMax, Prompt caching: https://platform.minimax.io/docs/api-reference/text-prompt-caching (automatic cache
  from 512 input tokens; prefix order tool list → system prompts → user messages; hits at a discount, no separate write
  price; TTL not stated, so UNKNOWN; OpenAI-compatible and Anthropic-compatible usage fields differ). List prices:
  https://platform.minimax.cn/docs/guides/pricing
- DASH-CC — Alibaba Cloud Model Studio, Context cache: https://help.aliyun.com/zh/model-studio/context-cache (explicit
  and implicit modes are mutually exclusive; minimum 1024 tokens; implicit matches the message prefix with no fixed TTL
  and no guarantee; explicit TTL 5 minutes renewed on hit, creation billed at 125%, hit at 10%; the page's update-time
  field is empty)
