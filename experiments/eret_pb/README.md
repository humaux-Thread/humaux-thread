# E-RET-PB1: own-corpus retrieval and rerank accuracy on public CI (E-RET-0, E-RET-1, E-RET-5b)

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
- Not done: Qwen3-Reranker at depth 25, int8 for v2-m3 and Qwen3, fp32 at depth 10, Neoverse-N1 latency, E-RET-2 to 4.
