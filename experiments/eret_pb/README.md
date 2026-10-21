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

1. **embed** (run with `environment: minimax m3`). Mini-pack #1 (asset `qpack.json.gz.enc`) holds the 198 queries and 3 sanity chunks (text and the stored point vector, read by Qdrant GET). The job embeds the 3 texts with `text-embedding-v3` through the DashScope OpenAI-compatible endpoint, requires cosine >= 0.99 on 3 of 3 (else tries `qwen3-vl-embedding`, else fails), embeds the 198 queries in batches of 10 (one call per query would not fit the 200-call budget together with the two earlier 401 calls), and uploads only `qvec.json.gz.enc` as artifact `qvec-enc`. Any 4xx stops the job and prints the raw status and error code.
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

## Results

(filled in after the eval run)
