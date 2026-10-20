# E-RET-5a: CPU cross-encoder reranker feasibility bench (experiment, not product code)

Question: can a local cross-encoder rerank at candidate depth 10-100 on the ARM CI runner (proxy for the ARM production host, spec section 67.2)?
This measures **speed, memory and scoring sanity only**. Accuracy across models is **not** measured here (see "Published scores").

- Branch `exp/e-ret-5a-rerank-bench`, never merged. Workflow `.github/workflows/rerank-bench.yml`, harness `bench.py`, pins `requirements.txt`.
- Runs: smoke 39432820142; full torch models + ONNX smoke 39433853458 (run A); full, all four jobs 39444896267 (run B, the numbers below). Artifact `rerank-bench-results` (JSON, aggregates only) of run 39444896267.
- Re-run: push a change to `bench.py`, `requirements.txt` or the workflow on a branch matching `exp/e-ret-5a-*` (a README-only push does not trigger). No secrets; `permissions: contents: read`.
- Public data only: public HF model repos and the public C-MTEB reranking set `C-MTEB/T2Reranking` @ `76631901a18387f85eaa53e5450019b87ad58ef9` (file sha256 verified in-job). Dataset text is never printed or stored; only aggregates leave the job.

## Licences (read in-job from the HF API and the pinned README; a non-commercial licence aborts the model)

| model | pinned revision (commit SHA) | licence (HF API / card header) | commercial use | pin == HEAD at run time | card README sha256 at the pin | harness reproduces card snippet (markers found) |
|---|---|---|---|---|---|---|
| `BAAI/bge-reranker-base` | `2cfc18c9415c912f9d8155881c133215df768a70` | mit / mit | yes | True | `b4223c8c1e95538f` | 5/5 |
| `BAAI/bge-reranker-v2-m3` | `953dc6f6f85a1b2dbfca4c34a2796e7dde08d41e` | apache-2.0 / apache-2.0 | yes | True | `c887aa6dd2598f90` | 5/5 |
| `Qwen/Qwen3-Reranker-0.6B` | `e61197ed45024b0ed8a2d74b80b4d909f1255473` | apache-2.0 / apache-2.0 | yes | True | `5bba8c734f6dd3ae` | 7/7 |
| `BAAI/bge-reranker-base` (ONNX int8 build of the same weights) | `2cfc18c9415c912f9d8155881c133215df768a70` | mit / mit | yes | True | `b4223c8c1e95538f` | 5/5 |

- Not run: `jinaai/jina-reranker-v2-base-multilingual` (named in the card as CC-BY-NC, so excluded by rule; not re-verified here).
- Dataset `C-MTEB/T2Reranking`: Apache-2.0 (upstream THUIR/T2Ranking README; HF mirror card states none). Used for timing text only.
- Pins: the commit SHAs were read from the public HF model API (JSON metadata, no weights) before the first push and are re-resolved in every job (`pinned_resolves_to`, `head_sha_now` in the JSON); the job fails if a pin does not resolve to itself.

## Method

- Runner `ubuntu-24.04-arm` (4 vCPU / 15.6 GB), Python 3.12, torch 2.10.0 (PyPI aarch64 CPU wheel), transformers 4.57.6; `torch.set_num_threads(4)`, fp32, `model.eval()`, `torch.inference_mode()`, one model per process.
- Scoring follows each model card's own transformers snippet: bge = `AutoModelForSequenceClassification` logit per pair; Qwen3-Reranker = `AutoModelForCausalLM`, yes/no last-token logits, card prompt prefix/suffix and `<Instruct>/<Query>/<Document>` format. Card README at the pinned revision is hashed and grepped for the snippet pieces (markers column above).
- Qwen3 deviation, equal by construction: the card computes logits at every position; the throughput path keeps only the last position (`logits_to_keep=1`). Sanity checks the two paths agree (max abs diff below 1e-3) and the card-literal path is timed once (row "card-literal") to show what the shortcut saves.
- Text: real Chinese (query, passages) from the C-MTEB T2Reranking dev split; each pair is a real query plus real passages concatenated, truncated to **exactly** L tokens (asserted, no padding). L in {256, 512}, batch in {8, 16, 32}.
- Per cell: 1 warm-up batch (untimed), then timed batches until 90 s or 40 batches, at least 1. Cells where a single batch exceeds 45 s therefore have 1-2 timed batches, so their p95 equals the max; the batch count is in the table.
- Derived latency: `latency(depth, L, b) = depth / pairs_per_s(L, b) + depth * tokenise_s_per_pair(L) + fixed_call_s`, where `tokenise_s_per_pair` is the median card-path tokenisation time per pair at L and `fixed_call_s` the median forward of one very short pair (framework dispatch and thread wake-up). The headline table uses the best batch size per (model, L); all batch sizes are in the JSON (`derived`).
- Verification: one real query (real query + 25 real candidates) at L=512, run end to end (tokenise + forward in batches of the best b), compared with the formula; `predicted (ceil batches)` charges the last partial batch as a full batch. A second pass with the natural passage lengths (padded to the longest in each batch) is reported as "natural".
- Peak RSS: `ru_maxrss` for the whole process and `VmHWM` (reset before each cell) per cell. It includes about 0.75-0.8 GB of Python + torch + data baseline (column "baseline"); one model per process.
- ONNX round 2: the fastest model (bge-reranker-base) exported with optimum (`optimum==2.1.0`, `optimum-onnx==0.1.0`), dynamically quantised to int8 weights (`AutoQuantizationConfig.arm64(is_static=False, per_channel=False)`), run with `onnxruntime==1.30.0`, 4 intra-op threads. Export runs in a separate process, so its memory is not in the serving peak. Quantisation moves the scores (card example: int8 -6.66 / 5.76 vs fp32 -8.15 / 6.18, order preserved); accuracy after quantisation is not measured.

## Results (run 39444896267, run B)

Reading the numbers:
- Batch size does not matter on this CPU: for every (model, L) the pairs/s across batch 8 / 16 / 32 differ by at most 3.2%, which is the noise level, so "best batch" in the derived table is a tie and batch 8 is the memory-cheapest choice.
- Throughput scales roughly with 1 / L: going from 256 to 512 tokens halves pairs/s for every model.
- RSS: `ru_maxrss` never decreases and glibc keeps freed heap, so a cell's `VmHWM` includes memory retained from earlier cells (cells run 256 first, then 512, batch 8 to 32). The cleanest per-config numbers are the first cell and the load numbers; Qwen3-Reranker grows with batch size (activations in fp32), the card-literal full-logits path adds the [batch, L, 151936] logits tensor.
- Rows labelled `bge-reranker-base-ort-int8` are round 2 (same weights, int8 dynamic quantisation, onnxruntime); `params` is not available for them.

## E-RET-5a: CPU reranker bench
Runner: Neoverse-N2 (aarch64), 4 vCPU, 15.6 GB; torch 2.10.0+cpu, transformers 4.57.6, threads 4, fp32, eval + inference_mode; features fphp,asimddp,sve,sve2,i8mm,bf16; profile full

### Models
| model | revision | licence | pin==HEAD now | params (M) | download s | load s | RSS after load MB (peak during load / now) | baseline RSS MB (torch+data, before load) | peak RSS MB (grid + query) | peak RSS MB (whole run) | sanity |
|---|---|---|---|---|---|---|---|---|---|---|---|
| BAAI/bge-reranker-base | `2cfc18c9415c` | mit | True | 278.0 | 7.3 | 1.9 | 1751 / 1305 | 798 | 3229 | 3229 | PASS |
| BAAI/bge-reranker-v2-m3 | `953dc6f6f85a` | apache-2.0 | True | 567.8 | 0.0 | 1.5 | 1067 / 1067 | 728 | 4070 | 4070 | PASS |
| Qwen/Qwen3-Reranker-0.6B | `e61197ed4502` | apache-2.0 | True | 595.8 | 0.1 | 1.5 | 4551 / 3416 | 764 | 14132 | 15036 | PASS |
| BAAI/bge-reranker-base | `2cfc18c9415c` | mit | True | None | 0.2 | 29.9 | 1568 / 1434 | 755 | 2953 | 2953 | PASS |

### Throughput (batches of exactly L tokens, 4 threads)
| model | L | batch | timed batches | pairs/s | p50 ms/batch | p95 ms/batch | max ms | cell peak RSS MB |
|---|---|---|---|---|---|---|---|---|
| bge-reranker-base | 256 | 8 | 40 | 3.9779 | 2007.7 | 2030.6 | 2047.7 | 2451 |
| bge-reranker-base | 256 | 16 | 22 | 4.0016 | 3994.9 | 4025.1 | 4036.8 | 2527 |
| bge-reranker-base | 256 | 32 | 11 | 3.9771 | 8014.2 | 8183.2 | 8279.0 | 2717 |
| bge-reranker-base | 512 | 8 | 21 | 1.8793 | 4255.7 | 4285.1 | 4306.6 | 2845 |
| bge-reranker-base | 512 | 16 | 10 | 1.8639 | 8576.7 | 8640.4 | 8679.4 | 2838 |
| bge-reranker-base | 512 | 32 | 5 | 1.8614 | 17188.9 | 17216.3 | 17218.5 | 3203 |
| bge-reranker-v2-m3 | 256 | 8 | 12 | 1.1224 | 7084.2 | 7228.1 | 7235.1 | 2661 |
| bge-reranker-v2-m3 | 256 | 16 | 6 | 1.0921 | 14659.2 | 14747.3 | 14762.9 | 2814 |
| bge-reranker-v2-m3 | 256 | 32 | 3 | 1.0927 | 29186.0 | 29531.9 | 29570.4 | 3098 |
| bge-reranker-v2-m3 | 512 | 8 | 5 | 0.5177 | 15479.9 | 15490.8 | 15493.4 | 3246 |
| bge-reranker-v2-m3 | 512 | 16 | 2 | 0.5164 | 30983.9 | 30993.1 | 30994.1 | 3246 |
| bge-reranker-v2-m3 | 512 | 32 | 1 | 0.5013 | 63838.2 | 63838.2 | 63838.2 | 4027 |
| qwen3-reranker-0.6b | 256 | 8 | 8 | 0.732 | 10902.1 | 11077.0 | 11144.9 | 4141 |
| qwen3-reranker-0.6b | 256 | 16 | 4 | 0.7463 | 21406.7 | 21585.9 | 21614.6 | 6160 |
| qwen3-reranker-0.6b | 256 | 32 | 2 | 0.7483 | 42761.2 | 42775.3 | 42776.8 | 7674 |
| qwen3-reranker-0.6b | 512 | 8 | 3 | 0.3488 | 22900.6 | 23009.0 | 23021.0 | 5626 |
| qwen3-reranker-0.6b | 512 | 16 | 1 | 0.3481 | 45960.0 | 45960.0 | 45960.0 | 7554 |
| qwen3-reranker-0.6b | 512 | 32 | 1 | 0.3507 | 91252.1 | 91252.1 | 91252.1 | 10177 |
| qwen3-reranker-0.6b (card-literal full logits) | 512 | 8 | 2 | 0.2308 | 34655.7 | 37234.6 | 37521.2 | 15036 |
| bge-reranker-base-ort-int8 | 256 | 8 | 40 | 16.0079 | 498.5 | 508.7 | 522.4 | 1629 |
| bge-reranker-base-ort-int8 | 256 | 16 | 40 | 16.0158 | 997.3 | 1011.5 | 1026.6 | 1721 |
| bge-reranker-base-ort-int8 | 256 | 32 | 40 | 15.6273 | 2042.0 | 2083.7 | 2113.6 | 1907 |
| bge-reranker-base-ort-int8 | 512 | 8 | 40 | 7.0459 | 1126.4 | 1181.7 | 1237.7 | 2009 |
| bge-reranker-base-ort-int8 | 512 | 16 | 39 | 7.0185 | 2279.2 | 2301.4 | 2351.0 | 2313 |
| bge-reranker-base-ort-int8 | 512 | 32 | 19 | 6.8945 | 4636.9 | 4706.4 | 4716.2 | 2955 |

### Derived per-query latency (s) = depth / pairs_per_s + depth * tokenise_s_per_pair + fixed_call_s; best batch size per L
| model | L | best batch | fixed call ms | tokenise ms/pair | depth 10 | depth 25 | depth 50 | depth 100 |
|---|---|---|---|---|---|---|---|---|
| bge-reranker-base | 256 | 16 | 33.4 | 3.59 | 2.57 | 6.37 | 12.71 | 25.38 |
| bge-reranker-base | 512 | 8 | 33.4 | 3.59 | 5.39 | 13.43 | 26.82 | 53.60 |
| bge-reranker-v2-m3 | 256 | 8 | 99.3 | 3.65 | 9.04 | 22.46 | 44.83 | 89.56 |
| bge-reranker-v2-m3 | 512 | 8 | 99.3 | 3.66 | 19.45 | 48.48 | 96.86 | 193.63 |
| qwen3-reranker-0.6b | 256 | 32 | 485.1 | 4.40 | 13.89 | 34.00 | 67.52 | 134.56 |
| qwen3-reranker-0.6b | 512 | 32 | 485.1 | 4.65 | 29.05 | 71.89 | 143.29 | 286.09 |
| bge-reranker-base-ort-int8 | 256 | 16 | 6.2 | 3.71 | 0.67 | 1.66 | 3.31 | 6.62 |
| bge-reranker-base-ort-int8 | 512 | 8 | 6.2 | 3.59 | 1.46 | 3.64 | 7.28 | 14.56 |

### One real query (depth 25 at L=512 unless smoke): predicted vs measured
| model | depth | batch | predicted s | predicted (ceil batches) s | measured s (exact L) | measured/predicted | natural passages s | natural mean tokens | query peak RSS MB |
|---|---|---|---|---|---|---|---|---|---|
| bge-reranker-base | 25 | 8 | 13.43 | 17.15 | 13.43 | 1.001 | 13.24 | 365.2 | 3229 |
| bge-reranker-v2-m3 | 25 | 8 | 48.48 | 62.11 | 47.93 | 0.989 | 46.86 | 365.2 | 4070 |
| qwen3-reranker-0.6b | 25 | 32 | 71.89 | 91.85 | 71.77 | 0.998 | 70.73 | 395.0 | 14132 |
| bge-reranker-base-ort-int8 | 25 | 8 | 3.64 | 4.6 | 3.52 | 0.967 | 3.41 | 365.2 | 2954 |

### Scoring sanity (card example order)

| model | sanity | scores |
|---|---|---|
| bge-reranker-base | PASS | [-8.1544, 6.1821]; zh extra ok |
| bge-reranker-v2-m3 | PASS | [-8.1838, 5.265]; zh extra ok |
| qwen3-reranker-0.6b | PASS | [0.9995, 0.0, 0.0, 0.9994]; zh extra ok |
| bge-reranker-base-ort-int8 | PASS | [-6.6557, 5.764]; zh extra ok |

### Repeatability: run A (39433853458) vs run B (39444896267), same code path, fresh runners

| model | L | batch | run A pairs/s | run B pairs/s | B/A |
|---|---|---|---|---|---|
| bge-reranker-base | 256 | 8 | 3.9498 | 3.9779 | 1.007 |
| bge-reranker-base | 256 | 16 | 3.9905 | 4.0016 | 1.003 |
| bge-reranker-base | 256 | 32 | 4.0143 | 3.9771 | 0.991 |
| bge-reranker-base | 512 | 8 | 1.8622 | 1.8793 | 1.009 |
| bge-reranker-base | 512 | 16 | 1.8609 | 1.8639 | 1.002 |
| bge-reranker-base | 512 | 32 | 1.8566 | 1.8614 | 1.003 |
| bge-reranker-v2-m3 | 256 | 8 | 1.1194 | 1.1224 | 1.003 |
| bge-reranker-v2-m3 | 256 | 16 | 1.0978 | 1.0921 | 0.995 |
| bge-reranker-v2-m3 | 256 | 32 | 1.0973 | 1.0927 | 0.996 |
| bge-reranker-v2-m3 | 512 | 8 | 0.524 | 0.5177 | 0.988 |
| bge-reranker-v2-m3 | 512 | 16 | 0.5268 | 0.5164 | 0.980 |
| bge-reranker-v2-m3 | 512 | 32 | 0.5211 | 0.5013 | 0.962 |
| qwen3-reranker-0.6b | 256 | 8 | 0.7445 | 0.732 | 0.983 |
| qwen3-reranker-0.6b | 256 | 16 | 0.7485 | 0.7463 | 0.997 |
| qwen3-reranker-0.6b | 256 | 32 | 0.7481 | 0.7483 | 1.000 |
| qwen3-reranker-0.6b | 512 | 8 | 0.3514 | 0.3488 | 0.993 |
| qwen3-reranker-0.6b | 512 | 16 | 0.3484 | 0.3481 | 0.999 |
| qwen3-reranker-0.6b | 512 | 32 | 0.3474 | 0.3507 | 1.009 |
| qwen3-reranker-0.6b (literal) | 512 | 8 | 0.248 | 0.2308 | 0.931 |

## Published reranking scores (vendors' own numbers; different evaluation sets; not comparable to this bench; read 2026-10-20)

| model | source | numbers as published |
|---|---|---|
| BAAI/bge-reranker-base | https://huggingface.co/BAAI/bge-reranker-base (C-MTEB reranking) | T2Reranking 67.28, T2RerankingZh2En 63.95, T2RerankingEn2Zh 60.45, MMarcoReranking 35.46, CMedQAv1 81.26, CMedQAv2 84.1, avg 65.42 |
| BAAI/bge-reranker-v2-m3 | https://huggingface.co/BAAI/bge-reranker-v2-m3 | model card shows charts only, no numeric reranking table. Third-party row in the Qwen3-Reranker card (https://huggingface.co/Qwen/Qwen3-Reranker-0.6B): MTEB-R 57.03, CMTEB-R 72.16, MMTEB-R 58.36, MLDR 59.51, MTEB-Code 41.38, FollowIR -0.01 |
| Qwen/Qwen3-Reranker-0.6B | https://huggingface.co/Qwen/Qwen3-Reranker-0.6B | MTEB-R 65.80, CMTEB-R 71.31, MMTEB-R 66.36, MLDR 67.28, MTEB-Code 73.42, FollowIR 5.41 (reranking the top-100 of Qwen3-Embedding-0.6B) |

Accuracy on our own data is Phase B, a separate private venue that the owner decides on.

## Limits

- fp32 torch and int8 ONNX only; no bf16 / fp16 / other int8 recipes, no Rust runtime (candle / ort), no multi-process or concurrent-request test (one process, 4 threads, one request stream).
- Shared CI runner: neighbours can add noise; the repeat table above is the only noise estimate (n=2).
- Exactly-L inputs are the worst case for a given L (no padding savings); natural passages in the real-query check are shorter on average.
- ONNX round 2 covers bge-reranker-base only (fastest model, per card); v2-m3 and Qwen3 were not exported.
