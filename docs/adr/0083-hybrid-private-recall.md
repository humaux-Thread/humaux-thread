# ADR-0083 — Hybrid private recall: a Qdrant built-in BM25 leg and memory-level RRF in the gateway

- Status: Accepted (2026-10-22). Card T-RET-6a (docs only). Decisions D-A to D-F are the design lead's, taken from the
  evidence of E-RET-PB2 and E-RET-PB5 (ADR-0081 D-E step 4, the BM25 + RRF step). The code lands in T-RET-6b and
  T-RET-6c; until then every sentence below about behaviour is **planned**.
- Relates to: Baseline §17.1, §17.2, §17.6, §20.0, §23.3, §33, §52, §53, §55.6, §57.1, §78.1; ADR-0055 D-C (lane
  substitution); ADR-0064 (Qdrant rebuild as an in-place generation); ADR-0068 (grouped recall, in-place backfill);
  ADR-0081 D-E and T-RET-6.

## Context

- Private recall has one dense leg. Candidate depth is `cand_k = min(top_k × 5, 200)`; the leg is grouped by Memory when
  the serving projection names a chunk profile (ADR-0068 D-E); every candidate then passes the PostgreSQL hydrate gate.
- Baseline §17.6 fixes the sparse path as Qdrant's built-in `qdrant/bm25`, computed inside the Cell, and §17.2 requires
  its IDF corpus to be the authorized universe. `projection::sparse` builds the lane's filter and its
  `SKIPPED_BY_POLICY` decision, and computes IDF locally; nothing outside tests calls it. The public BM25 projection
  (§17.6.1) already runs `qdrant/bm25` with `modifier: idf`.
- ADR-0081 D-E ordered the accuracy plan and left three checks open as UNKNOWN before BM25 could land: the default RRF
  constant, the Chinese tokenizer, and per-tenant IDF. E-RET-PB2 and E-RET-PB5 have measured the legs since. This ADR
  answers the three checks against Qdrant v1.19.0, the version the deployment pins (`deploy/compose/prod.yml`), and
  then decides.

## Evidence

Aggregates only; the corpus behind them is private and never enters this repository. N = 198 development questions,
one correct Memory each.

- **E-RET-PB2**: CI run 39614883398 (head cf3582e), method and results in the README of branch `exp/e-ret-pb-harness`
  at 16e3f72. Dense order by exact search, a bigram BM25 leg in Python, client-side RRF over Memories.
- **E-RET-PB5**: CI runs 39624388700 (head 5f93d7a) and 39625766381 (head 7121635), branch `exp/e-ret-pb-qdrant`.
  Qdrant v1.19.0 service container (the job log prints `qdrant version: 1.19.0`), one tenant, the PB2 snapshot indexed
  as points with the dense vector unnamed and `bm25` / `bm25_ml` sparse vectors with `modifier: idf`, queries with
  `params.idf.corpus` set to the tenant filter. The smoke step tried the unnamed default dense vector first and it
  worked (0 failed layouts in both runs).

| setup (hit@5 and pool@25 over 198 questions) | hit@5 | pool@25 |
|---|---|---|
| dense, exact search | 64 | 127 |
| Qdrant `bm25` leg with the multilingual tokenizer, gateway-style memory-level RRF (k 60) | 96 | 147 |
| Qdrant server-side chunk-level RRF (k 60), default-tokenizer leg | 79 | 125 |
| gateway-style memory-level RRF (k 60), default-tokenizer leg | 90 | 125 |
| reference: PB2's own bigram BM25 leg, client RRF (k 60) | 100 | 140 |

- Server against client fusion, both on the default-tokenizer leg: 79 against 90, b/c 12/1, exact McNemar p .0034
  (PB5 follow-up, secondary (c)). Server fusion on the multilingual leg at k 60 was not run.
- Multilingual tokenizer against the default tokenizer, fused pool@25: b/c 7/29, p .0003 (PB5 follow-up, secondary (b)).
- The bigram-leg reference (100 / 140) against the multilingual Qdrant leg (96 / 147): not significant.
- PB2, pre-registered: pool@25 127 to 140 with the bigram leg and RRF (b/c 6/19, p .015); hit@5 64 to 100 (b/c 9/45,
  p 7.3e-7).
- Rerank is not part of this design. It is decided in ADR-0084: the owner's decision of 2026-10-22 to run hybrid recall
  without a reranker was replaced the same day by a local rerank lane (see Alternatives rejected for the measurements
  that were recorded here).

Caveats that bound these numbers:

1. The 198 questions are a **development set**: they tuned the old system. They justify building the leg; they do not
   confirm it. The sealed set of ADR-0081 (Experiments, common rules) re-measures later.
2. The measured fusions took **200 points from each leg** and folded them to Memories on the client; the dense leg was
   an exact search. Production asks Qdrant for grouped Memories, `leg_depth` (200) per leg, so both legs keep the measured
   depth; the dense leg is an approximate (HNSW) search, which PB5 measured within one hit of exact (65 against 64).
3. PB5 had one tenant, so cross-principal IDF scoping was not exercised there (G-RET-8 does).

## Qdrant v1.19.0: what was verified

Read 2026-10-21 at tag `v1.19.0` (commit 74f3e85b9473, "Bump version to 1.19.0", 2026-08-04), from
`docs/redoc/master/openapi.json` and the source files cited per row (`path@v1.19.0`, raw URL pattern in References).

| # | Question | Answer | Source |
|---|---|---|---|
| V1 | Can `PATCH /collections/{name}` add a new sparse vector to an existing collection? | **No.** `sparse_vectors` in the PATCH body is a "map of sparse vector data parameters to update". The handler first requires every name to exist already in the collection's `sparse_vectors` (error `vector_name_not_exists` otherwise), then updates only `index` and `modifier`. | `docs/redoc/master/openapi.json@v1.19.0` (`UpdateCollection.sparse_vectors`); `lib/storage/src/content_manager/toc/collection_meta_ops.rs@v1.19.0` (`update_collection`); `lib/collection/src/collection/collection_ops.rs@v1.19.0` (`update_sparse_vectors_from_other`); `lib/collection/src/operations/types.rs@v1.19.0` (`SparseVectorsConfig::check_vector_names`); `lib/collection/src/config.rs@v1.19.0` (`update_sparse_vectors_from_other`) |
| V1b | Is there another route that does? | **Yes: `PUT /collections/{name}/vectors/{vector_name}`** (`create_vector_name`, "create a new named vector on an existing collection"). Sparse body: `{"sparse": {"modifier": "idf"}}`, optional `datatype`. Idempotent: the same name and config is a no-op; a different config, or the other kind (dense against sparse), is a bad-input error. Existing points hold no vector in the new space until they are written (storage is prefilled as deleted for every existing point). It runs as a consensus operation (`CreateNamedVector`). | `openapi.json@v1.19.0` (path `/collections/{collection_name}/vectors/{vector_name}`); `src/actix/api/vector_name_api.rs@v1.19.0`; `lib/segment/src/data_types/vector_name_config.rs@v1.19.0`; `lib/collection/src/collection/vector_name_schema.rs@v1.19.0` (`add_vector_to_config`); `lib/segment/src/segment/vector_name_ops.rs@v1.19.0` (`create_sparse_vector`) |
| V2 | Is `group_by` accepted with a Document query plus `params.idf` in the Query API, or only on `/points/search/groups`? | **Accepted in the Query API's own grouped endpoint, `POST /collections/{name}/points/query/groups`.** Its body takes `query` (a `QueryInterface`, which admits a `Document`), `using`, `filter`, `params` (`SearchParams`, which holds `idf`), `group_by` (a string or number payload field), `group_size`, and `limit` (the number of groups). `POST /points/query` has no `group_by`. The handler runs the same inference batch as the plain query and passes `params` into the base query. The legacy `/points/search/groups` handler does no inference. Group search is bounded: at most 5 collecting and 5 filling rounds of `limit × group_size` points, and only points that carry the `group_by` field take part, so fewer groups than `limit` is a valid answer (ADR-0068 D-E). **Not yet run in this repository**: PB5 folded the sparse leg client-side (U1). | `openapi.json@v1.19.0` (`QueryGroupsRequest`, `QueryRequest`); `src/actix/api/query_api.rs@v1.19.0` (`query_points_groups`); `src/common/inference/query_requests_rest.rs@v1.19.0` (`convert_query_groups_request_from_rest`); `lib/collection/src/grouping/group_by.rs@v1.19.0`; `lib/shard/src/grouping/driver.rs@v1.19.0` (`MAX_GET_GROUPS_REQUESTS`, `MAX_GROUP_FILLING_REQUESTS`); `lib/shard/src/grouping/mod.rs@v1.19.0` (`shape_candidates_query`); `src/actix/api/search_api.rs@v1.19.0` |
| V3 | Key and value of the multilingual tokenizer for `qdrant/bm25` Document inference | **`options.tokenizer = "multilingual"`.** `TokenizerType` is `prefix`, `whitespace`, `word`, `multilingual`, serialised `snake_case`, default `word`. `options` is deserialised into `Bm25Config` for the model name `qdrant/bm25` (matched case-insensitively; `bm25` also routes there). The tokenizer is a property of each request, not of the collection (`SparseVectorConfig` carries only `modifier` and `datatype`), so write and query must send the same `options`. Chinese and Japanese text is segmented with charabia (the detection list includes `Cmn` and `Jpn`). Documents go through `doc_embed`, queries through `search_embed`. | `openapi.json@v1.19.0` (`TokenizerType`, `Bm25Config`, `DocumentOptions`); `lib/api/src/rest/schema.rs@v1.19.0`; `lib/segment/src/data_types/index.rs@v1.19.0`; `src/common/inference/inference_input.rs@v1.19.0` (`parse_bm25_config`); `src/common/inference/local_model.rs@v1.19.0`; `lib/segment/src/index/field_index/full_text_index/tokenizers/multilingual.rs@v1.19.0`; `src/common/inference/bm25_inference.rs@v1.19.0`. Used by E-RET-PB5 on v1.19.0. |
| V4 | `modifier` on the wire | `"idf"` (enum `none`, `idf`). A doc comment in the Qdrant source writes `"Idf"`; the schema is the authority. | `openapi.json@v1.19.0` (`Modifier`); `lib/segment/src/data_types/modifier.rs@v1.19.0` |
| V5 | What `params.idf.corpus` does | The document count and the per-term document frequencies are computed over the points matching the corpus filter only; the corpus is independent of the retrieval filter. Omitted, or `"global"`, means collection-wide. Per query, the corpus points are collected and the posting lists are walked against them, so cost scales with the corpus. | `openapi.json@v1.19.0` (`IdfParams`, `IdfScope`, `IdfCorpusParams`); `lib/segment/src/index/sparse_index/sparse_vector_index/read_view/idf.rs@v1.19.0` |
| V6 | Server-side RRF | Default `DEFAULT_RRF_K = 2`. Score `1 / (position + k)` with a 0-based position, which is `1 / (rank + k - 1)` for 1-based ranks. "Does not break ties". It fuses points (chunks), not Memories. A server `k` of 60 is therefore not the gateway formula; `k` 61 would equal `1 / (60 + rank)`. | `lib/segment/src/common/reciprocal_rank_fusion.rs@v1.19.0` |
| V7 | BM25 preprocessing | With only `tokenizer` sent, the defaults are language english, lowercase on, ascii folding off, English stopwords and the Snowball English stemmer, `k` 1.2, `b` 0.75, `avg_len` 256; E-RET-PB5 measured exactly that. The multilingual tokenizer drops tokens with no alphabetic character (a pure-digit token goes; CJK ideographs stay). Text that yields no token embeds to an empty sparse vector. `k`, `b` and `avg_len` shape the stored document weights. | `src/common/inference/bm25_inference.rs@v1.19.0` (`build_tokens_processor`, `doc_embed`, `to_persisted`); `lib/api/src/rest/schema.rs@v1.19.0` (`default_k`, `default_b`, `default_avg_len`); `lib/segment/src/index/field_index/full_text_index/tokenizers/multilingual.rs@v1.19.0` (`tokenize_charabia`) |
| V8 | Documentation against source | The openapi text for `Document` still says "work-in-progress, unimplemented". The source routes `qdrant/bm25` to a local model and PB5 ran it on v1.19.0. Source and run win. | `openapi.json@v1.19.0` (`Document`); `src/common/inference/local_model.rs@v1.19.0` |

The three checks ADR-0081 D-E left open are answered by V6 (RRF constant), V3 (tokenizer) and V5 (per-tenant IDF).

### UNKNOWN, with the fallback each carries

| # | Not known today | Fallback | Resolved by |
|---|---|---|---|
| U1 | Whether a real server returns the expected groups for a Document query with `params.idf.corpus` and `group_by memory_id` (the source says it should, V2; nothing here has run it) | Fold the sparse leg client-side over `leg_depth` points on `POST /points/query`, the shape PB5 measured; this ADR is then amended to say so | T-RET-6c, G-RET-7 and G-RET-8 through a real Qdrant |
| U2 | What a real server does with a query whose tokens are all dropped (empty sparse vector, V7) | A 2xx with zero groups is an empty leg; any non-2xx is a leg failure and shows as the D-C degradation, never silently | T-RET-6c reads it once and records the result here |
| U4 | Where the policy value behind `SKIPPED_BY_POLICY` comes from: `build_sparse_lane` takes `local_text_processing_allowed` from its caller and only tests call it, so no policy value is read anywhere today | No source exists (checked: `control.egress_policies`, `TenantDataPolicy`, card `egress_disposition`); always allowed via `in_cell_text_processing_allowed`, the one decision the write path, the rebuild verifier and T-RET-6c's query path read; a later card adds a `TenantDataPolicy` field when a tenant needs it | T-RET-6b (settled) |
| U5 | How a skipped sparse lane renders in the envelope: `LaneStatus` has `ok`, `failed`, `not_required` and nothing for "skipped by policy" | Render `not_required` (no wire change) unless that card's contract review asks for a new value | T-RET-6c |
| U6 | What turns the sparse leg on for a stream: it must find `bm25` and `memory_id` on every point, or a memory missing either is silently never matched (dense-only quality, no error) | A registered flag, off by default, flipped after the T-RET-6b backfill reads zero missing and ADR-0068's `memory_id` backfill reads `strays = 0` | T-RET-6c |
| U7 | The cost of the corpus-scoped IDF (V5) on a large authorized corpus, and of a grouped sparse search at depth 200 (up to ten rounds, V2) | Lower `leg_depth` through the registry (no code change); no cache is added before a number exists (ADR-0081 D-G) | T-RET-6c reads the sparse leg's own stage timing |

## Decisions

### D-A Sparse leg

- Qdrant's built-in `qdrant/bm25` on a named sparse vector `bm25` with `modifier: idf` (V4) in `private_memory_v1`.
- **Document text** is the card text the dense vector embeds, chunk cards included (ADR-0068). **Query text** is the exact
  query bytes (§20.0): no rewrite, no folding.
- **Options** are `{"tokenizer": "multilingual"}` (V3), identical at index and query time. One function builds the
  Document value for both the write and the query path. Any change to the options changes every stored sparse vector
  (V7), so it is a new rebuild generation (ADR-0064), never a toggle.
- **IDF corpus.** `params.idf.corpus` is the authorization part of the retrieval filter (§17.2): `tenant_id = T` and the
  §6.1.2 visibility disjunction, what `projection::dense::build_dense_filter` emits with no `narrow_by`. Subject, affect,
  projection and embedding version, the servable condition, the workspace stream and the tombstone overlay narrow the
  retrieval only. Never `"global"` (V5).
  - ponytail: while a shadow projection version coexists with the serving one (§16.2) both generations' points enter the
    corpus, and inactive Memories stay in it until purged. The statistic is slightly inflated and never wider than the
    authorization. Pin the serving version into the corpus if a G-RET-8-style measurement shows a rank change.
- **Policy.** When tenant policy forbids text processing inside the Cell (§17.6), the leg is `SKIPPED_BY_POLICY`: no
  sparse request is sent, the write carries no `bm25` for that tenant, and recall answers from the dense leg. That is a
  lane state, not a degradation and not a failure (U4, U5).

### D-B Indexing

- **Collection body and generation.** `create_collection_body` gains `sparse_vectors: {"bm25": {"modifier": "idf"}}`,
  and the canonical string `provisioning::collection_generation` hashes gains the sparse config. A collection created
  earlier therefore reads `collection_misconfigured` until `collection ensure` adds the vector, the same path ADR-0068
  (40d-1c-i) used for the `memory_id` index.
- **How an existing collection gets the vector.** `collection ensure` (the step `rebuild_stream` already runs, ADR-0064
  S3) sends `PUT /collections/{name}/vectors/bm25` with `{"sparse": {"modifier": "idf"}}`. `PATCH /collections/{name}`
  cannot do this (V1); the route can (V1b), and a repeat call with the same body is a no-op. The alternative the card
  allowed, a new collection through `maintenance switch-visible`, is not needed and stays the fallback if T-RET-6b's
  real-Qdrant test shows the route unusable on the deployed topology.
- **Upsert.** The point write sends named vectors: `""` for the dense vector, `bm25` for the Document, with the D-A
  options. The unnamed dense plus a named sparse layout is the one PB5 ran on v1.19.0.
- **Backfill.** Existing points get `bm25` through the ADR-0064 rebuild generation, in place: stored dense vectors are
  re-sent (no provider call), Qdrant computes the sparse vector in the Cell, and there is **no `projection_version`
  bump** (the ADR-0068 D-I precedent; a bump would move every Memory's fingerprint and point id). The rebuild verifier
  (ADR-0064 D-F) **expects the sparse vector**: a point without `bm25` is not equivalent. The sparse vector cannot be
  derived from PostgreSQL state, so the exact rule is presence, not numeric equality, and an empty sparse vector is a
  legal value (V7); T-RET-6b fixes the wording.

### D-C Recall

- The gateway issues the dense leg and the sparse leg **concurrently**. The dense leg keeps its request shape and asks for
  `leg_depth` grouped Memories instead of `cand_k`. The sparse leg is
  `POST /collections/{name}/points/query/groups` (V2) with the D-A Document query, `using: bm25`, `group_by` set to
  `memory_id`, group size 1, and `limit` = `leg_depth`. Both legs carry the **identical filter set**: tenant,
  visibility, subject, affect, and the tombstone overlay (§17.1, §37).
- **Fusion** is reciprocal-rank fusion over Memory ranks, in the gateway: `score(m) = Σ 1 / (rrf_k + rank)` over the
  legs that returned `m`, ranks 1-based, ties broken by `memory_id` ascending. The fused list is cut to `cand_k` and
  then passes the **unchanged** PostgreSQL hydrate gate; a candidate that only the sparse leg found gets no weaker a
  gate than a dense one.
- **Not Qdrant server-side fusion.** Measured worse on the same default-tokenizer leg (79 against 90, p .0034), it fuses chunks so one
  note fills several slots, it does not break ties (V6), and its default constant is not the formula above.
- A short sparse leg (fewer groups than asked, V2) is valid, not a failure.
- **Lanes** are `dense` and `sparse`. `LANE_SUBSTITUTED` keeps its meaning (ADR-0055 D-C): it fires only for a planner
  class whose own lane is still undelivered, literal and association among them, when the caller sent no `mode`. The
  sparse lane adds no `mode` value, so `x-humaux-v1-supported` and the `recall_v1_supported_lanes` gate (§33) do not
  move.
- **A sparse-leg failure answers from the dense leg with an explicit `DegradeCode`, `SparseLaneUnavailable`** (wire
  `SPARSE_LANE_UNAVAILABLE`). Failure means a transport error, a timeout, a non-2xx reply or a reply of unexpected
  shape. The result is still returned, so by §52.3 Q1 it is a `DegradeCode` and no `ErrorCode` is added; the name
  collides with no `ErrorCode` (G52-3 stays `{PROJECTION_LAG}`). It is emitted only through `abstain()` (§53.1), the
  lane reads `failed` in `completeness.lanes`, and it is never silent. T-RET-6c makes the §53.2 edit (11 to 12 variants),
  adds `testkit/fault/sparse_lane_unavailable.rs` and its §53.4 entry, and keeps the §53.3 rule-2 equality at 12 / 12 / 12.
  A dense-leg failure is unchanged by this ADR; answering from the sparse leg alone is not decided here.

### D-D Configuration (§78.1)

Four registered-profile entries, beside `top_k` in the §50 registry, none ever caller input (the fourth, `sparse_leg_enabled`, is U6's switch):

| Field | Default | Meaning |
|---|---|---|
| `cand_multiplier` | 5 (ADR-0081 D-E) | `cand_k = min(top_k × cand_multiplier, 200)`; replaces the constant `RETRIEVAL_CANDIDATE_MULTIPLIER` |
| `leg_depth` | 200 | `limit` of each leg's grouped request (dense and sparse), in Memories; the fused list is then cut to `cand_k` |
| `rrf_k` | 60 | the constant in the D-C formula |
| `sparse_leg_enabled` | false | turns the sparse leg on for the profile after the T-RET-6b backfill reads zero missing `bm25` (U6) |

All four enter `request_profile_fingerprint` and the envelope validation (§23.3 fixture assertions), so a change moves
`profile_fingerprint` and G23-4 refuses to pool runs across values. `cand_k_formula` renders the resolved multiplier.
`RetrievalRequest` and `build_request` take no parameter for any of them (§55.1); T-RET-6c adds the four names to the
G55-6 ① forbidden-name set, red-recorded by that card. Bounds are validated when the registry loads, and no literal of
the four appears outside it.

### D-E `projection::sparse`

`build_sparse_lane` stays the **single** `SKIPPED_BY_POLICY` decision and the single source of the sparse filter. When
T-RET-6c lands, the local IDF computation (`tenant_scoped_document_frequency`, `bm25_idf`, and whatever only they use;
the card names the exact set) is deleted, because Qdrant computes IDF over `params.idf.corpus` (V5).

- ponytail: the local IDF stays until T-RET-6c lands; it computes nothing the gateway uses (the module has no caller
  outside tests), and the first card that sends a sparse query removes it. No upgrade path is needed: IDF is Qdrant's.

### D-F Gates

All are three-state (`pass` / `fail` / `not_applicable`, §57.1) and **all are planned**. Each gate exists only after its
inject, red, fix, green record (§80.1) lands in the card that implements it, and that card adds the record to this ADR.
Module gate ids such as `G-RET-7` fall outside the §80.1 anchor grammar, like `G-RET-1` to `G-RET-6` of ADR-0081.
A gate that runs before its object exists reports `not_applicable` and names that object (§57.1).

| Gate | Owner | Criterion | Injected fault |
|---|---|---|---|
| G-RET-3 hydrate gate on every leg (extends ADR-0081) | T-RET-6c | A Memory tombstoned after indexing is not returned when the dense leg, the sparse leg, or both produced it; the PostgreSQL hydrate gate runs on the fused list | skip the hydrate gate for candidates only the sparse leg returned |
| G-RET-7 lexical-only hit | T-RET-6c | A Memory whose text matches the query only lexically (the fixture's dense order does not retrieve it) is returned through a real Qdrant; the dense-only baseline does not return it | write points without `bm25`, or fuse the dense leg alone |
| G-RET-8 IDF corpus scoping | T-RET-6c | Through a real Qdrant, another principal's private document that carries the query term does not change principal A's ranking; a control adds the same document inside A's own scope and **does** change it, so the gate can fail | omit `params.idf.corpus` (global statistics) |
| G-RET-9 deterministic fusion | T-RET-6c | The same leg lists give the same fused order on repeat and under permutation of equal-score entries, ties by `memory_id` ascending; a Memory found by one leg only is ordered by that one contribution | break ties by arrival order or hash-map iteration order |
| G-RET-10 sparse failure is explicit | T-RET-6c | With the Qdrant sparse request failing (timeout, 5xx, malformed body) and the dense request succeeding, recall returns the dense-order result, `lanes.sparse` reads `failed`, `degradations` holds `SPARSE_LANE_UNAVAILABLE` and `degrade_total{code="SparseLaneUnavailable"}` rises by 1; a dense failure does not emit that code | swallow the sparse error and return the dense list without calling `abstain()` |

T-RET-6b adds no new `G-RET-` id. It extends the provisioning sentinel (`collection_setup_puts` and
`collection_generation` carry the sparse config) and the rebuild-verify test (a point without `bm25` is not
equivalent), each red-recorded by that card.

## Modules and table ownership

No PostgreSQL table changes. The sparse vector lives in Qdrant and is derived from the card text; PostgreSQL stays the
source of truth, and a lost `bm25` vector is rebuilt like any other point (ADR-0064).

| Module | Change | Card |
|---|---|---|
| `adapters::qdrant` | collection body gains `sparse_vectors`; upsert body names its vectors; the Document builder; a grouped sparse query body beside `dense_group_query_body`; the `PUT .../vectors/bm25` body | T-RET-6b, T-RET-6c |
| `adapters::provisioning` | `collection_setup_puts`, `collection_generation` and `ensure_collection` add and check `bm25` | T-RET-6b |
| `adapters::projection_worker`, `adapters::rebuild` | the point write sends `bm25`; the verifier expects it | T-RET-6b |
| `adapters::retrieve`, `gateway::recall` | the sparse leg runs beside the dense leg; RRF; lanes; `abstain()` on sparse failure | T-RET-6c |
| `contracts::retrieval_config`, `retrieval::request` | the four registry entries; fingerprint; `cand_k_formula` | T-RET-6c |
| `projection::sparse` | `build_sparse_lane` stays; local IDF deleted | T-RET-6c |
| `telemetry::degrade`, `testkit/fault` | `DegradeCode::SparseLaneUnavailable` and its fault test (Baseline §53.2 and §53.4) | T-RET-6c |

## Cards

| Card | Scope | Gates |
|---|---|---|
| T-RET-6a | This ADR; Baseline §17.6, §23.3, §33, §55.6; the T-RET-6 row and the D-E checks of ADR-0081 (docs only) | none |
| T-RET-6b | Indexing and backfill (D-B): collection body and generation, `collection ensure` adds `bm25`, named-vector upsert, rebuild backfill and verifier. **Before T-RET-6c.** Names the policy source (U4) | the provisioning sentinel and the rebuild-verify test, extended |
| T-RET-6c | Recall, configuration and lanes (D-C to D-E): the four registry entries, the sparse leg, RRF, lanes, the `DegradeCode`, deleting the local IDF. Settles U1, U2, U5, U6, U7. Needs the T-RET-6b backfill read on the stream it enables | G-RET-3 (extended), G-RET-7, G-RET-8, G-RET-9, G-RET-10 |

## Alternatives rejected

- **Qdrant server-side fusion** (`query: {fusion: rrf}` or `rrf: {k}`): 79 against 90 hit@5, both on the default-tokenizer
  leg (p .0034); chunk-level, no tie-break, a different constant (V6).
- **The default `word` tokenizer for the leg**: 29 against 7 fused questions in pool@25 (p .0003) against the
  multilingual one.
- **Global IDF** (no `params.idf.corpus`): other principals' term statistics would shape the ranking (§17.2).
- **A second BM25 implementation in the gateway** (PB2's Python bigram leg or the local `projection::sparse` IDF): its
  100 / 140 is not significantly different from the Qdrant leg's 96 / 147, and it would need its own index and its own
  authorized-corpus code where §17.6 and Qdrant already provide both.
- **Adding the sparse vector with `PATCH /collections/{name}`**: it cannot create one (V1).
- **A `projection_version` bump for the backfill**: it would move every Memory's fingerprint and point id (ADR-0068 D-I).
- **Rerank in this design** (superseded by ADR-0084): the owner decided on 2026-10-22 to run hybrid recall without a
  reranker, and replaced that decision the same day with a local rerank lane, which ADR-0084 records. For the record,
  E-RET-5f (run 39629912275, `exp/e-ret-pb-rrf-rerank`) measured, on the fused pool of the same 198 questions, a cloud
  reranker at 140 (from 96, p 3.7e-11) and local int8 at 111 (p .077, 3.5 s p50 on the 4-vCPU Neoverse-N2 CI runner).
  On the 4-vCPU Neoverse-N1 production host (Baseline §67.2) the same int8 model measured 6.43 s p50 / 11.92 s p95 per
  depth-25 query with all four cores busy (E-RET-5e, 2026-10-21, the public bundle `n1-bench-bundle-v1`, run by the lead
  with the owner's approval; not a CI run). The local lane that was chosen afterwards is ADR-0084 (cards T-RET-7a to
  T-RET-7d).

## Deferred items

| Item | Upgrade signal |
|---|---|
| Sealed-set confirmation of the fused ranking | The sealed set of ADR-0081 exists; re-measure dense and fused on it |
| Tuning `k`, `b`, `avg_len` or the language options | A paired experiment shows a gain; every stored sparse vector is rewritten, so it is a new rebuild generation (V7) |
| Pinning the serving version into the IDF corpus | A G-RET-8-style measurement shows a rank change during a backfill window |
| Answering from the sparse leg alone when the dense leg fails | The dense leg's failure rate makes dense-only recall the dominant outage |

## References

Qdrant sources were read on 2026-10-21 at tag `v1.19.0` (commit 74f3e85b9473c62560006c043e13737ce6b48412). A file is
cited as `path@v1.19.0` and is fetched as `https://raw.githubusercontent.com/qdrant/qdrant/v1.19.0/<path>`; the schema is
`docs/redoc/master/openapi.json` at the same tag. The files are listed in the V1 to V8 rows above.

Experiment records: E-RET-PB2 (run 39614883398, README at 16e3f72 on `exp/e-ret-pb-harness`) and E-RET-PB5 (runs
39624388700 and 39625766381 on `exp/e-ret-pb-qdrant`; each run's aggregates artifact is `eret-qdrant-results`).
