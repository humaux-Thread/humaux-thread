# E-RET-PB1 / PB2: own-corpus retrieval experiments on public CI (E-RET-0, E-RET-1, E-RET-5b; PB2: E-RET-2, E-RET-3)

PB1 sections come first; the PB2 sections (full-corpus snapshot, query role, BM25 + RRF) start at "E-RET-PB2" below.

Experiment, not product code. Branch `exp/e-ret-pb-harness` (never merged), workflow `.github/workflows/eret-pb.yml`, harness `harness.py` (stdlib), scorers `rerank.py` (torch), pins `requirements.txt`.
Design authority: design_v0.2 sections 19.4 and 19.5 (private). Speed of the same models: E-RET-5a (branch `exp/e-ret-5a-rerank-bench`).

Questions this answers (aggregates only): how much does dense ranking lose inside the candidate pool (E-RET-0, E-RET-1), and what does a local cross-encoder gain or lose on our own data (E-RET-5b).

## Privacy

- The corpus (memory and chunk text, titles, query text, ids) never enters git, logs, summaries, artifacts or issues. The pack is published only as AES-256-CBC ciphertext (`openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -md sha256 -salt`), as prerelease assets on tag `eval-pack-e-ret-2026-10-v1` (not a software release). The key is the repo secret `HUMAUX_EVAL_PACK_KEY`, present only in the `fetch` step's `env`.
- Plaintext lives in `$RUNNER_TEMP` under `umask 077` and is removed in an `if: always()` step. Triggers are `push` to `exp/e-ret-pb-*` and `workflow_dispatch` only; `permissions: contents: read`.
- Output is counts, rates, Clopper-Pearson 95% intervals, b/c/p and latencies. Per-question bits never leave the job that computed them: arms that must be compared pairwise run in the same job. Exceptions print class and source line only.
- Guard (`harness.py guard`): before any summary line or artifact is published, every 12-character window of every query, chunk, title and id in the pack is looked up in the output files; a hit fails the job. Windows made of code-owned strings (labels, model names, the `env` and `model` blocks) or of digits are exempt (a window needs at least 6 letters/CJK characters not covered by a code-owned string). `harness.py selftest` proves on a fake pack that a leaked window fails, clean output passes, and an exempt label that also occurs in the corpus passes; it runs first in the embed and J0 jobs.
- The old system was read-only throughout: Postgres sessions with `default_transaction_read_only = on` (checked with `SHOW`), Qdrant search and GET only, no old-system MCP or search API.

## Stages

1. **embed** (run with `environment: minimax m3`). Mini-pack #1 (asset `qpack.json.gz.enc`) holds the 198 queries and 3 sanity chunks (raw chunk text and the stored point vector, read by Qdrant GET). The job embeds the 3 texts per candidate model and requires cosine >= 0.99 on 3 of 3; candidates in order: `text-embedding-v4` (OpenAI-compatible endpoint) and `qwen3-vl-embedding` (native multimodal-embedding endpoint, `dimension` 1024, independent embedding per text, no instruction). A 404 `model_not_supported` skips a candidate; any other 4xx (auth, Arrearage, quota, bad request) stops the job and prints the raw status and error code. If no candidate passes, the job fails. Then it embeds the 198 queries (raw text, no prefix or instruction, as the old code does) in batches of 10 (one call per query would not fit the 200-call budget), and uploads only `qvec.json.gz.enc` as artifact `qvec-enc`.
   - Old-system authority (read-only): the old ingestion embeds the raw chunk text (clamped to 7000 characters), the old retrieval embeds the raw query, both with `dimensions` 1024 and no prefix or instruction; the old Rust source names cloud `text-embedding-v4` (1024 dims) as the production dense model, while its `providers.json` names `qwen3-vl-embedding` and the memory rows are tagged `text-embedding-v3`.
   - Alibaba Model Studio references, read 2026-10-21, both "last updated Oct 11, 2026": multimodal-embedding API reference (`https://www.alibabacloud.com/help/en/model-studio/multimodal-embedding-api-reference`: native endpoint `.../api/v1/services/embeddings/multimodal-embedding/multimodal-embedding`, `input.contents[].text`, `parameters.dimension` in 2560/2048/1536/1024/768/512/256) and text embedding (`https://www.alibabacloud.com/help/en/model-studio/text-embedding-synchronous-api`: `text-embedding-v4` on `/compatible-mode/v1/embeddings`, `dimensions` default 1024, 10 inputs per call).
2. **local build** (stdlib Python, ssh reads). Decrypt the vectors; per query: Qdrant search on the dense vector, `limit 200`, payload limited to `memory_id` and `chunk_index`, no vectors; Postgres read-only for chunk text, memory status, layer and title of the union of candidates plus every gold memory. Pack = `manifest`, `questions` (qid, type, query, gold memory, candidates `[chunk_id, memory_id, score]`), `memories` (status, layer, title), `chunks`, `gold_info` (per gold memory: in Postgres, chunk count, point count). Asset `pack.json.gz.enc`; its gz sha256 is `PACK_SHA256` in the workflow.
3. **eval** (J0 and the rerank matrix).

## Method

- Questions: the 198-question continuation set (178 `state`, 20 `fact`; one gold memory each). It took part in the old system's tuning, so it is a development / regression set only (spec 19.4).
- Fold: the 200 dense chunk hits per question fold into memories by max score; the filter keeps `status` active or NULL (a memory absent from Postgres is dropped and counted). Depth d = the first d memories after the filter.
- J0 stages per question (counts, rate, Clopper-Pearson 95%, split by type): gold reachable in the old store (has a chunk and a point) / gold in the top-200 chunks / gold after the status filter / gold within memory depth 25, 50, 100, 200 (pool ceiling) / gold in the top 5 at depth 25. `conversion = top5 / in_pool@25`. A second block repeats the stages over reachable questions only. Pool 25 vs 100 gets an exact McNemar.
- Rerank input: each memory of the depth-d pool is represented as `(title + "\n" + best chunk text).strip()`, the way old production built its reranker input (`f"{title}\n{text}".strip()`, backend `memory/retrieval.py`, read-only; old production took `title` and `text` from the Qdrant payload, here both come from Postgres). Best chunk = the highest-scoring chunk of that memory among the 200 hits that has stored text. The (query, document) pair is truncated to L tokens by the tokenizer (`truncation=True`, `max_length=L`, as in 5a). Ties keep dense order. All 198 questions are reranked, including those whose gold is outside the pool (a miss in both arms).
- Arms: bge-reranker-base fp32 (L 512, 256), the same weights as ONNX int8 (optimum arm64 dynamic quantisation, onnxruntime, as in 5a; L 512, 256, plus depth 10 at L 256), bge-reranker-v2-m3 fp32 (L 256, accuracy reference), Qwen3-Reranker-0.6B (depth 10, L 256). Pins and licences are in the workflow and re-checked in each job. fp32 and int8 of bge-reranker-base run in one job, so fp32 vs int8 and arm vs dense McNemar are computed in-job.
- Statistics: exact two-sided McNemar on the same 198 questions. A = baseline (dense, or fp32), B = challenger (arm, or int8); b = A hit and B miss, c = A miss and B hit (c is the gain). hit@5 is reported with Clopper-Pearson 95%.
- Latency: per query, wall time of tokenise + forward for the whole pool in batches of 8 on the runner (`ubuntu-24.04-arm`, 4 vCPU, torch 4 threads, ORT 4 threads), p50 / p95 over the 198 queries after one untimed warm-up. The runner is Neoverse-N2; the production host is N1 (spec 67.2), so production latency will be higher.
- Runs: at most 4 workflow runs in total. A push only starts a run when the commit message carries `[stage:embed]` or `[stage:eval]`.

## Runs

- Run 1 (39587713869, stage embed): `text-embedding-v3` through compatible mode gave cosines -0.03324, -0.00162, -0.06065 against the 3 stored vectors; `qwen3-vl-embedding` through compatible mode answered HTTP 404 `model_not_supported`. Nothing else ran.
- Run 2 (39589741131, stage embed): `text-embedding-v4` through compatible mode (dimensions 1024, raw chunk text) gave cosines 1.00000 on 3 of 3 sanity chunks (rounded to 5 decimals); the 198 queries were embedded with it (raw query text, no prefix) in 21 API calls (1 identity + 20 batches of at most 10), sealed as `qvec-enc`. The native `qwen3-vl-embedding` candidate was never called (the first candidate passed).

## Results

Run 39593059326 (stage eval, all jobs green, artifact `eret-pb-results`). Pack: 198 questions, 11,250 distinct candidate points (11,006 with a Postgres chunk), 9,516 memories, pack ciphertext 8,200,256 bytes. Query vectors: `text-embedding-v4`, 1024 dims, identity cosines 1.00000 on 3 of 3. Dense order alone (no BM25, no rerank) is the baseline for every McNemar below; the old system's tuned hybrid pipeline is a different system.

### E-RET-0 / E-RET-1 (dense order, no model)

Stage counts, rate and Clopper-Pearson 95% interval. Denominator = questions of the split.

| stage | all | state | fact |
|---|---|---|---|
| reachable | 171/198 = 0.864 [0.808, 0.908] | 152/178 = 0.854 [0.793, 0.902] | 19/20 = 0.950 [0.751, 0.999] |
| in_top200_chunks | 161/198 = 0.813 [0.752, 0.865] | 144/178 = 0.809 [0.743, 0.864] | 17/20 = 0.850 [0.621, 0.968] |
| after_status_filter | 159/198 = 0.803 [0.741, 0.856] | 142/178 = 0.798 [0.731, 0.854] | 17/20 = 0.850 [0.621, 0.968] |
| pool_25 | 123/198 = 0.621 [0.550, 0.689] | 111/178 = 0.624 [0.548, 0.695] | 12/20 = 0.600 [0.360, 0.809] |
| pool_50 | 139/198 = 0.702 [0.633, 0.765] | 125/178 = 0.702 [0.629, 0.768] | 14/20 = 0.700 [0.457, 0.881] |
| pool_100 | 153/198 = 0.773 [0.708, 0.829] | 136/178 = 0.764 [0.695, 0.824] | 17/20 = 0.850 [0.621, 0.968] |
| pool_200 | 159/198 = 0.803 [0.741, 0.856] | 142/178 = 0.798 [0.731, 0.854] | 17/20 = 0.850 [0.621, 0.968] |
| top5_at_depth_25 | 63/198 = 0.318 [0.254, 0.388] | 54/178 = 0.303 [0.237, 0.377] | 9/20 = 0.450 [0.231, 0.685] |

| | all | state | fact |
|---|---|---|---|
| conversion = top5 / pool_25 | 63/123 = 0.512 [0.420, 0.603] | 54/111 = 0.486 [0.391, 0.583] | 9/12 = 0.750 [0.428, 0.945] |

Reachable questions only (gold memory has a chunk and a point in the old store).

| stage | all | state | fact |
|---|---|---|---|
| questions | 171 | 152 | 19 |
| in_top200_chunks | 144/171 = 0.842 [0.779, 0.893] | 127/152 = 0.836 [0.767, 0.891] | 17/19 = 0.895 [0.669, 0.987] |
| after_status_filter | 142/171 = 0.830 [0.766, 0.883] | 125/152 = 0.822 [0.752, 0.880] | 17/19 = 0.895 [0.669, 0.987] |
| pool_25 | 110/171 = 0.643 [0.567, 0.715] | 98/152 = 0.645 [0.563, 0.721] | 12/19 = 0.632 [0.384, 0.837] |
| pool_50 | 123/171 = 0.719 [0.646, 0.785] | 109/152 = 0.717 [0.638, 0.787] | 14/19 = 0.737 [0.488, 0.908] |
| pool_100 | 137/171 = 0.801 [0.733, 0.858] | 120/152 = 0.789 [0.716, 0.851] | 17/19 = 0.895 [0.669, 0.987] |
| pool_200 | 142/171 = 0.830 [0.766, 0.883] | 125/152 = 0.822 [0.752, 0.880] | 17/19 = 0.895 [0.669, 0.987] |
| top5_at_depth_25 | 56/171 = 0.328 [0.258, 0.403] | 47/152 = 0.309 [0.237, 0.389] | 9/19 = 0.474 [0.244, 0.711] |

Pool ceiling, depth 25 vs 100, exact McNemar (b = in pool_25 only, c = gained at depth 100):

| split | N | b | c | p |
|---|---|---|---|---|
| all | 198 | 0 | 30 | 1.863e-09 |
| state | 178 | 0 | 25 | 5.96e-08 |
| fact | 20 | 0 | 5 | 0.0625 |

Counters: questions=198, chunk_candidates=39600, candidates_without_pg_chunk=1068, candidates_memory_absent_from_pg=1, mean_memories_after_fold=185.87, mean_memories_after_filter=176.13, gold_memories_total=109, gold_missing_from_pg=1, gold_without_chunk_or_point=14, dense_hit5=63

### E-RET-5b rerank job bge-reranker-base

Dense hit@5 on the same questions: 63/198 = 0.318 [0.254, 0.388]. McNemar: A = dense, B = arm; b = dense hit & arm miss, c = dense miss & arm hit.

| arm | hit@5 | state | fact | pool ceiling | N | b | c | p | p50 s | p95 s |
|---|---|---|---|---|---|---|---|---|---|---|
| fp32-L512-d25 | 97/198 = 0.490 [0.418, 0.562] | 85/178 = 0.477 [0.402, 0.554] | 12/20 = 0.600 [0.360, 0.809] | 123/198 = 0.621 [0.550, 0.689] | 198 | 12 | 46 | 8.22e-06 | 13.513 | 14.114 |
| fp32-L256-d25 | 90/198 = 0.455 [0.384, 0.527] | 78/178 = 0.438 [0.364, 0.514] | 12/20 = 0.600 [0.360, 0.809] | 123/198 = 0.621 [0.550, 0.689] | 198 | 16 | 43 | 0.0005844 | 6.54 | 6.689 |
| int8-L512-d25 | 101/198 = 0.510 [0.438, 0.582] | 89/178 = 0.500 [0.424, 0.576] | 12/20 = 0.600 [0.360, 0.809] | 123/198 = 0.621 [0.550, 0.689] | 198 | 9 | 47 | 2.572e-07 | 3.53 | 3.699 |
| int8-L256-d25 | 92/198 = 0.465 [0.394, 0.537] | 80/178 = 0.449 [0.375, 0.526] | 12/20 = 0.600 [0.360, 0.809] | 123/198 = 0.621 [0.550, 0.689] | 198 | 14 | 43 | 0.0001539 | 1.608 | 1.649 |
| int8-L256-d10 | 81/198 = 0.409 [0.340, 0.481] | 71/178 = 0.399 [0.326, 0.475] | 10/20 = 0.500 [0.272, 0.728] | 92/198 = 0.465 [0.394, 0.537] | 198 | 9 | 27 | 0.003933 | 0.644 | 0.664 |

fp32 vs int8 (A = fp32, B = int8):

| pair | N | b | c | p |
|---|---|---|---|---|
| L512-d25 | 198 | 2 | 6 | 0.2891 |
| L256-d25 | 198 | 2 | 4 | 0.6875 |

### E-RET-5b rerank job bge-reranker-v2-m3

Dense hit@5 on the same questions: 63/198 = 0.318 [0.254, 0.388]. McNemar: A = dense, B = arm; b = dense hit & arm miss, c = dense miss & arm hit.

| arm | hit@5 | state | fact | pool ceiling | N | b | c | p | p50 s | p95 s |
|---|---|---|---|---|---|---|---|---|---|---|
| fp32-L256-d25 | 109/198 = 0.550 [0.478, 0.621] | 98/178 = 0.551 [0.474, 0.625] | 11/20 = 0.550 [0.315, 0.769] | 123/198 = 0.621 [0.550, 0.689] | 198 | 5 | 51 | 1.17e-10 | 22.245 | 23.083 |

### E-RET-5b rerank job qwen3-reranker-0.6b

Dense hit@5 on the same questions: 63/198 = 0.318 [0.254, 0.388]. McNemar: A = dense, B = arm; b = dense hit & arm miss, c = dense miss & arm hit.

| arm | hit@5 | state | fact | pool ceiling | N | b | c | p | p50 s | p95 s |
|---|---|---|---|---|---|---|---|---|---|---|
| qwen-L256-d10 | 91/198 = 0.460 [0.389, 0.532] | 81/178 = 0.455 [0.380, 0.531] | 10/20 = 0.500 [0.272, 0.728] | 92/198 = 0.465 [0.394, 0.537] | 198 | 1 | 29 | 5.774e-08 | 13.192 | 13.634 |

### Notes

- Unreachable by chunk-level dense retrieval: 27 of 198 questions (14 gold memories: 1 missing from Postgres, 13 without chunk or point). They count as misses in every arm.
- 1,068 of the 39,600 candidate chunk hits have no chunk row in Postgres (their memory id comes from the Qdrant payload); they take part in dense ranking but cannot supply text, so a memory is represented by its best-scoring chunk that has text (title only if none).
- Query text is embedded raw. The old retrieval may append an entity-alias expansion to the query before embedding; that table is not part of the pack, so it is not replicated.
- Rerank latency is per query on the CI runner (Neoverse-N2, 4 vCPU), tokenise + forward for the whole pool, batch 8, after one untimed warm-up. Pairs are padded to the longest in each batch, so p50 is close to the exactly-L numbers of E-RET-5a.
- The 198 questions took part in the old system's tuning (development / regression set only).
- Not done in PB1: Qwen3-Reranker at depth 25, int8 for v2-m3 and Qwen3, fp32 at depth 10, Neoverse-N1 latency. E-RET-2 and E-RET-3 are PB2 (below); E-RET-4 is not run.

# E-RET-PB2: full-corpus snapshot, query role (E-RET-2), BM25 + RRF (E-RET-3), rerank on the fused pool

Same branch, same privacy rules (see Privacy above; they bind PB2 unchanged). New code: `pb2.py` (dense / BM25 / RRF / rerank arm / variants / guard), subcommands `embed2`, `eval2`, `guard2` in `harness.py`, jobs `embed2` and `eval2` in the workflow (stage markers `[stage:embed2]`, `[stage:eval2]`). PB2 reuses `fetch`, the statistics and the leak guard of PB1 unchanged.

## Corpus snapshot (local, read-only, stdlib)

- Qdrant: the team's collection scrolled with `with_vector` limited to the dense vector (the sparse `bm25` vector is not read) and the payload fields `memory_id`, `chunk_index`. Vectors are stored as IEEE half (`struct` format `e`, little endian), row-major, one blob; an id index (`points.jsonl`) gives point id, payload memory id, chunk index and, through `chunks.qdrant_point_id`, the chunk id.
- Postgres (every session `SET default_transaction_read_only = on`, `SHOW` must print `on`): every chunk of the team's memories (id, memory id, chunk index, point id, text) and every memory of the team (id, status, layer, title), keyset-paginated, 0.5 s between queries.
- Questions: the 198 of `continuation_198_v2` with gold ids and the PB1 gold_info (in Postgres / chunk count / point count).
- Load guard on the live host: batches of at most 256 points, 0.5 s pause, stop when one request takes more than 10 s. See Runs for the numbers and for how the first batch was measured.
- Encrypted exactly as in PB1 (tar, `gzip -9`, `openssl enc -aes-256-cbc -pbkdf2 -iter 600000`), round-tripped locally, published as the prerelease asset `corpus.v1.tar.gz.enc` on tag `eval-pack-e-ret-2026-10-v1`; its gz sha256 is `CORPUS_SHA256` in the workflow.

## Query vectors (stage `embed2`, environment `minimax m3`)

- `q0` = PB1's call: compat mode, `text-embedding-v4`, `dimensions` 1024, raw query, batches of 10. Harness self-check: searched over the full corpus it must give PB1's dense hit@5 = 63.
- `q1` = native text-embedding API (`POST /api/v1/services/embeddings/text-embedding/text-embedding`), `text-embedding-v4`, `parameters.text_type = "query"`, `dimension` 1024, `output_type` dense, batches of 10.
- `q2` = `q1` plus `parameters.instruct = "Given a question, retrieve the memory that answers it"`. Made because the official reference lists `instruct` as an optional request parameter: Alibaba Cloud Model Studio, "Text embedding" synchronous API reference, https://www.alibabacloud.com/help/en/model-studio/text-embedding-synchronous-api, "Last Updated: Oct 11, 2026", read 2026-10-21 ("Provides custom instructions to guide the model in understanding the query intent. English instructions are recommended"). The page does not say where `instruct` goes in an HTTP body; it places the sibling parameters (`text_type`, `dimension`, `output_type`) in `parameters`, so `instruct` goes there too. If the API ignored it, q2 would equal q1; the job records the cosines between variants.
- One extra compat call with `text_type` added to the body records whether compat mode accepts it (raw HTTP status and error code; cosine against q0 if it answers 200).
- Output: `{meta, variants}` sealed with the pack key, artifact `qvec2-enc`; the log holds status codes, call counts and cosine summaries only.

## Evaluation (stage `eval2`; numpy is pinned in `requirements.txt`)

- **Dense.** Brute-force cosine over every row of the float16 corpus (float32 arithmetic, rows and queries L2-normalised). Per query the top-200 chunk rows are folded into memories by max score, then the status filter (active or NULL; a memory absent from the memories table is dropped). The J0 stage table is the PB1 one (same definitions, same `type` split), once per query variant.
- **BM25.** One document per chunk text. Tokens: lower-cased `[A-Za-z0-9_]+` runs plus overlapping bigrams of every run of CJK characters (U+3400-4DBF, U+4E00-9FFF; a lone character is its own token). Okapi BM25, `k1 = 1.2`, `b = 0.75` (textbook defaults, not tuned), `idf = ln(1 + (N - df + 0.5) / (df + 0.5))`, unique query terms. Top-200 chunks, folded and filtered like the dense leg.
- **RRF.** `score = sum 1 / (k + rank)` over the two filtered memory lists (1-based ranks; a memory missing from a list gets nothing from it), `k` in {10, 30, 60}; ties keep first appearance, dense first. Fused with the dense variant carried forward (q1 if it wins primary comparison 1, else q0).
- **Union oracle.** Questions whose gold memory is in the top 25 of either leg (after the status filter), with the dense-only / BM25-only / both split.
- **Pre-registered primary comparisons (exactly two; everything else is secondary).** (1) q1 vs q0 on dense hit@5, A = q0, B = q1; q1 "wins" iff c > b and p < 0.05. (2) the best RRF k vs the carried-forward dense variant on pool@25, A = dense, B = RRF; best k = highest pool@25, ties to higher hit@5, then larger k. Exact two-sided McNemar with N, b, c, p; rates with Clopper-Pearson 95%.
- **Rerank.** One arm, as in PB1: bge-reranker-base (same pinned revision) ONNX int8, L = 512, depth 25, input `title + "\n" + best chunk`. The best chunk of a memory is its highest-scoring chunk with stored text for the query variant of the pool (PB1 used the best among the 200 hits; the two differ only for memories whose text-bearing chunks all lie outside the top 200). The arm runs on q0's pool and, if different, on the best pool of this card (the RRF pool if its pool@25 beats the carried-forward dense pool, else the dense pool). McNemar of the reranked hit@5 against the same pool's pre-rerank hit@5, and of the best-pool rerank against the q0-pool rerank.
- Output: `$GITHUB_STEP_SUMMARY` and artifact `eret-pb2-results` (aggregates only), both through `harness.py guard2` (the 12-character window check against every query, chunk, title and id of the corpus). `harness.py selftest` now also runs the embed2 flow against fake endpoints and dense / BM25 / RRF on a fake corpus; it runs first in the `embed2` and `eval2` jobs.

## Runs (PB2: 3 of 4 workflow runs used)

- Corpus snapshot (local, 2026-10-21): 52,143 points scrolled (collection had 52,140 at the start, 52,143 at the end: the old system is live), 49,995 chunks and 58,289 memories from Postgres, 198 questions. 49,993 points map to a Postgres chunk, 2,150 do not; 2 chunks have no scrolled point; payload memory vs Postgres chunk memory mismatches: 0; gold memories 109 (1 missing from Postgres, 14 without chunk or point, as in PB1). Plaintext tar 198,144,000 bytes; ciphertext asset `corpus.v1.tar.gz.enc` 147,612,560 bytes (gz sha256 in the workflow as `CORPUS_SHA256`); `qvec2.json.gz.enc` 5,335,376 bytes (`QVEC2_SHA256`).
- Load guard on the old host. Scroll: 211 batches in two phases. Phase 1 timed each request with `curl -w time_total` through ssh: the first 256-point batch showed 25.6 s (end to end 51.4 s), which is over the 10 s limit, so the guard stopped the scroll. The same machine answered 64-point batches in 0.009 s of curl time. The 25.6 s was the slow ssh link (about 0.1 to 0.2 MB/s) back-pressuring `curl`'s stdout, not Qdrant. Phase 2 therefore timed each Qdrant request on the host itself (a read-only stdlib client sending only `POST .../points/scroll` to 127.0.0.1, request sent to body fully read), batches of 256, 0.5 s pause, same 10 s limit, vectors packed to float16 on the host: 201 batches, max 0.028 s, mean 0.019 s. Overall: 10 batches in phase 1 (1 of 256, 9 of 64) and 201 in phase 2; the limit was exceeded once, in the transport-inflated reading, and the scroll was stopped and restarted with host-side timing rather than with a higher limit. Postgres: keyset pages of 4,000 memories / 1,500 chunks, 0.5 s pause, every session `SET default_transaction_read_only = on` and `SHOW` = `on`.
- Run 39607864149 (stage embed2, green): selftest including numpy parts; q0, q1, q2 produced in 61 API calls (20 + 20 + 20 + 1 compat probe); HTTP 200 on all; sealed as `qvec2-enc`.
- Run 39610197524 (stage eval2): the evaluation completed, then `guard2` stopped the job on 2 windows (the outputs held a manifest column name, `qdrant_point...`, that also occurs in the corpus text), so nothing was published and the numbers were not kept. Fix: `static_strings` now exempts every result key (they are code-made); regression test in `pb2.selftest` (key built from bytes so no source literal exempts it): red on the old guard, green on the new, and a real leak is still caught. A raw sealed artifact (`eret-pb2-results-enc`, ciphertext) was added so a false positive can no longer lose a run.
- Run 39614883398 (stage eval2, green, artifact `eret-pb2-results`, guard ok on 2 files against 108,680 corpus texts): dense / BM25 / RRF in 16 s, rerank 2 x about 11.5 min.
- Diagnostic after the run (local, read-only, one ssh session, load guard as above, max request 0.035 s on the host): the 198 q0 vectors searched with Qdrant `exact: true` (brute force, full precision, `limit` 200) and put through PB1's fold, filter and stages give reachable 171, in top-200 chunks 166, after filter 164, pool@25 127, pool@100 154, pool@200 164, dense hit@5 64: identical to the CI brute force over float16 rows. So the differences from PB1 below come from PB1's approximate (HNSW) search, not from float16 storage.

## Results (run 39614883398)

Dense order alone is the baseline for every dense McNemar; BM25 and RRF lists are top-200 chunks folded and filtered (Method above). `q0` vs `q1`: the native API with `text_type=query` returned vectors identical to q0 for all 198 queries (cosine >= 0.999999), and compat mode accepted `text_type` (HTTP 200) and ignored it (cosine 0.999999 against q0 on 2 queries). `q2` (with `instruct`) differs from q0 (mean cosine 0.915449, min 0.797426).

Counts, rate and Clopper-Pearson 95% interval; McNemar exact two-sided (A = baseline, B = challenger, b = A hit and B miss, c = A miss and B hit).

Corpus: rows=52143, chunks=49995, memories=58289, questions=198, points_without_pg_chunk=2150, pg_chunks_without_scrolled_point=2

Query vectors: {"calls": {"compat_text_type_probe": 1, "q0": 20, "q1": 20, "q2": 20}, "compat_text_type": {"cos_vs_q0": [0.999999, 0.999999], "http": 200}, "cos_q0_q1": {"identical_ge_0.999999": 198, "mean": 1.0, "min": 1.0}, "cos_q0_q2": {"identical_ge_0.999999": 0, "mean": 0.915449, "min": 0.797426}, "cos_q1_q2": {"identical_ge_0.999999": 0, "mean": 0.915449, "min": 0.797426}, "dim": 1024, "instruct": "Given a question, retrieve the memory that answers it", "model": "text-embedding-v4", "status": {"q0": {"http": 200}, "q1": {"http": 200}, "q2": {"http": 200}}}

### q0 self-check against PB1 (now / PB1)

| dense_hit5 | reachable | in_top200_chunks | after_status_filter | pool_25 | pool_100 | pool_200 |
|---|---|---|---|---|---|---|
| 64/63 | 171/171 | 166/161 | 164/159 | 127/123 | 154/153 | 164/159 |

### Pre-registered primary comparisons (exactly two)

| comparison | A | B | N | b | c | p |
|---|---|---|---|---|---|---|
| 1. dense hit@5 | q0 = 64 | q1 = 64 | 198 | 0 | 0 | 1.0 |
| 2. pool@25 | q0 = 127 | rrf-k60 = 140 | 198 | 6 | 19 | 0.01463 |

Dense variant carried forward: q0. RRF pool@25 / hit@5 per k: k10: 134 / 79, k30: 140 / 100, k60: 140 / 100

### J0 stages, dense variant q0

| stage | all | state | fact |
|---|---|---|---|
| reachable | 171/198 = 0.864 [0.808, 0.908] | 152/178 = 0.854 [0.793, 0.902] | 19/20 = 0.950 [0.751, 0.999] |
| in_top200_chunks | 166/198 = 0.838 [0.780, 0.887] | 149/178 = 0.837 [0.774, 0.888] | 17/20 = 0.850 [0.621, 0.968] |
| after_status_filter | 164/198 = 0.828 [0.768, 0.878] | 147/178 = 0.826 [0.762, 0.878] | 17/20 = 0.850 [0.621, 0.968] |
| pool_25 | 127/198 = 0.641 [0.570, 0.708] | 115/178 = 0.646 [0.571, 0.716] | 12/20 = 0.600 [0.360, 0.809] |
| pool_50 | 144/198 = 0.727 [0.660, 0.788] | 130/178 = 0.730 [0.659, 0.794] | 14/20 = 0.700 [0.457, 0.881] |
| pool_100 | 154/198 = 0.778 [0.713, 0.834] | 139/178 = 0.781 [0.713, 0.839] | 15/20 = 0.750 [0.509, 0.913] |
| pool_200 | 164/198 = 0.828 [0.768, 0.878] | 147/178 = 0.826 [0.762, 0.878] | 17/20 = 0.850 [0.621, 0.968] |
| top5_at_depth_25 | 64/198 = 0.323 [0.259, 0.393] | 55/178 = 0.309 [0.242, 0.383] | 9/20 = 0.450 [0.231, 0.685] |
| conversion = top5 / pool_25 | 64/127 = 0.504 [0.414, 0.594] | 55/115 = 0.478 [0.384, 0.573] | 9/12 = 0.750 [0.428, 0.945] |

### J0 stages, dense variant q1

| stage | all | state | fact |
|---|---|---|---|
| reachable | 171/198 = 0.864 [0.808, 0.908] | 152/178 = 0.854 [0.793, 0.902] | 19/20 = 0.950 [0.751, 0.999] |
| in_top200_chunks | 166/198 = 0.838 [0.780, 0.887] | 149/178 = 0.837 [0.774, 0.888] | 17/20 = 0.850 [0.621, 0.968] |
| after_status_filter | 164/198 = 0.828 [0.768, 0.878] | 147/178 = 0.826 [0.762, 0.878] | 17/20 = 0.850 [0.621, 0.968] |
| pool_25 | 127/198 = 0.641 [0.570, 0.708] | 115/178 = 0.646 [0.571, 0.716] | 12/20 = 0.600 [0.360, 0.809] |
| pool_50 | 144/198 = 0.727 [0.660, 0.788] | 130/178 = 0.730 [0.659, 0.794] | 14/20 = 0.700 [0.457, 0.881] |
| pool_100 | 154/198 = 0.778 [0.713, 0.834] | 139/178 = 0.781 [0.713, 0.839] | 15/20 = 0.750 [0.509, 0.913] |
| pool_200 | 164/198 = 0.828 [0.768, 0.878] | 147/178 = 0.826 [0.762, 0.878] | 17/20 = 0.850 [0.621, 0.968] |
| top5_at_depth_25 | 64/198 = 0.323 [0.259, 0.393] | 55/178 = 0.309 [0.242, 0.383] | 9/20 = 0.450 [0.231, 0.685] |
| conversion = top5 / pool_25 | 64/127 = 0.504 [0.414, 0.594] | 55/115 = 0.478 [0.384, 0.573] | 9/12 = 0.750 [0.428, 0.945] |

### J0 stages, dense variant q2

| stage | all | state | fact |
|---|---|---|---|
| reachable | 171/198 = 0.864 [0.808, 0.908] | 152/178 = 0.854 [0.793, 0.902] | 19/20 = 0.950 [0.751, 0.999] |
| in_top200_chunks | 170/198 = 0.859 [0.802, 0.904] | 153/178 = 0.860 [0.800, 0.907] | 17/20 = 0.850 [0.621, 0.968] |
| after_status_filter | 168/198 = 0.849 [0.791, 0.895] | 151/178 = 0.848 [0.787, 0.898] | 17/20 = 0.850 [0.621, 0.968] |
| pool_25 | 137/198 = 0.692 [0.623, 0.755] | 123/178 = 0.691 [0.618, 0.758] | 14/20 = 0.700 [0.457, 0.881] |
| pool_50 | 147/198 = 0.742 [0.676, 0.802] | 133/178 = 0.747 [0.677, 0.809] | 14/20 = 0.700 [0.457, 0.881] |
| pool_100 | 158/198 = 0.798 [0.735, 0.852] | 144/178 = 0.809 [0.743, 0.864] | 14/20 = 0.700 [0.457, 0.881] |
| pool_200 | 168/198 = 0.849 [0.791, 0.895] | 151/178 = 0.848 [0.787, 0.898] | 17/20 = 0.850 [0.621, 0.968] |
| top5_at_depth_25 | 71/198 = 0.359 [0.292, 0.430] | 62/178 = 0.348 [0.279, 0.423] | 9/20 = 0.450 [0.231, 0.685] |
| conversion = top5 / pool_25 | 71/137 = 0.518 [0.431, 0.604] | 62/123 = 0.504 [0.412, 0.595] | 9/14 = 0.643 [0.351, 0.872] |

### BM25 alone and RRF (secondary), all questions

| list | pool_25 | pool_50 | pool_100 | pool_200 | top5 | pool25 vs dense (N/b/c/p) | hit5 vs dense (N/b/c/p) |
|---|---|---|---|---|---|---|---|
| bm25 | 74/198 = 0.374 [0.306, 0.445] | 112/198 = 0.566 [0.493, 0.636] | 139/198 = 0.702 [0.633, 0.765] | 148/198 = 0.748 [0.681, 0.806] | 27/198 = 0.136 [0.092, 0.192] | 198/75/22/6.073e-08 | 198/50/13/3.016e-06 |
| rrf-k10 | 134/198 = 0.677 [0.607, 0.741] | 153/198 = 0.773 [0.708, 0.829] | 167/198 = 0.843 [0.785, 0.891] | 178/198 = 0.899 [0.848, 0.937] | 79/198 = 0.399 [0.330, 0.471] | 198/8/15/0.21 | 198/5/20/0.004077 |
| rrf-k30 | 140/198 = 0.707 [0.638, 0.769] | 155/198 = 0.783 [0.719, 0.838] | 168/198 = 0.849 [0.791, 0.895] | 178/198 = 0.899 [0.848, 0.937] | 100/198 = 0.505 [0.433, 0.577] | 198/7/20/0.01916 | 198/5/41/4.406e-08 |
| rrf-k60 | 140/198 = 0.707 [0.638, 0.769] | 156/198 = 0.788 [0.724, 0.843] | 171/198 = 0.864 [0.808, 0.908] | 178/198 = 0.899 [0.848, 0.937] | 100/198 = 0.505 [0.433, 0.577] | 198/6/19/0.01463 | 198/9/45/7.288e-07 |

BM25 index: {"avgdl": 265.99, "b": 0.75, "docs": 49995, "k1": 1.2, "query_terms": 394}

Union oracle (gold in the top 25 of either leg; dense = q0): dense 127/198 = 0.641 [0.570, 0.708], bm25 74/198 = 0.374 [0.306, 0.445], union 149/198 = 0.752 [0.686, 0.811]; both 52, dense only 75, bm25 only 22.

Secondary comparisons: q2_vs_q0_hit5: 198/5/12/0.1435, q2_vs_q1_hit5: 198/5/12/0.1435, q1_vs_q0_pool25: 198/0/0/1.0

### Rerank arm int8-L512-d25 (bge-reranker-base ONNX int8), pool = best pool: rrf-k60

| pool | hit@5 | state | fact | pool@25 | pre-rerank hit@5 | N | b | c | p | p50 s | p95 s |
|---|---|---|---|---|---|---|---|---|---|---|---|
| q0_pool | 105/198 = 0.530 [0.458, 0.601] | 93/178 = 0.522 [0.446, 0.598] | 12/20 = 0.600 [0.360, 0.809] | 127/198 = 0.641 [0.570, 0.708] | 64/198 = 0.323 [0.259, 0.393] | 198 | 9 | 50 | 5.265e-08 | 3.445 | 3.587 |
| best_pool | 106/198 = 0.535 [0.463, 0.606] | 88/178 = 0.494 [0.419, 0.570] | 18/20 = 0.900 [0.683, 0.988] | 140/198 = 0.707 [0.638, 0.769] | 100/198 = 0.505 [0.433, 0.577] | 198 | 24 | 30 | 0.4966 | 3.479 | 3.58 |

Rerank on best pool vs rerank on q0 pool (A = q0 pool, B = best pool): N=198 b=16 c=17 p=1.0

PB1 reference (not paired): int8 L512 depth 25 hit@5 = 101/198.

### Notes

- q0 does not reproduce PB1 exactly: 64 vs 63 on hit@5, 127 vs 123 on pool@25, 164 vs 159 on pool@200 (exact search finds more of the gold memories than PB1's approximate search did; see the diagnostic above). Reachable questions and the missing-gold counts are identical to PB1 (171; 1 missing from Postgres, 14 without chunk or point).
- Primary comparison 1 is degenerate (q1 equals q0 vector for vector, b = c = 0). q2 is a secondary variant: its comparisons (q2 vs q0 and q2 vs q1 on hit@5, b/c = 5/12, p = 0.1435) were not pre-registered as primary and are not significant at 0.05; its pool@25 is 137 vs 127 for q0.
- The RRF best-k selection (k = 60 on pool@25, ties with k = 30 resolved by the pre-registered rule: hit@5 equal at 100, then the larger k) is itself a choice among three k, so primary comparison 2 carries a small selection effect; the other k are in the table.
- Rerank: the best pool is the RRF pool (k = 60). Reranking improves each pool's own hit@5 (q0 pool 64 -> 105, RRF pool 100 -> 106); reranked hit@5 of the RRF pool against the q0 pool: b/c = 16/17, p = 1.0. Per type the RRF pool is lower on state (88 vs 93 of 178) and higher on fact (18 vs 12 of 20). The reranked q0 pool gives 105 (PB1: 101 on the PB1 pool).
- The rerank arm reads the memory's best chunk by dense score of the pool's query variant over all of the memory's chunks that have stored text; PB1 used the best among the 200 hits. Latencies are on the CI runner (Neoverse-N2, 4 vCPU), not on the production host.
- Not done: E-RET-4 (context prefix, not in this card); native text-embedding with default role (`text_type=document`) as a transport control; any rerank arm other than bge-reranker-base int8 L512 depth 25; Neoverse-N1 latency; per-cluster bootstrap.
