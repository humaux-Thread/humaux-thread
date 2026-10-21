# N1 bench bundle (E-RET-5e): int8 cross-encoder rerank speed on a CPU host

Public benchmark bundle: `BAAI/bge-reranker-base` (MIT) int8 ONNX + C-MTEB T2Reranking sample (Apache-2.0). Not a software release.
Experiment E-RET-PB4, branch `exp/e-ret-pb-cloud`. Nothing here touches the project's own corpus: the model and the text are public.

## What it measures

`n1_bench.py` (onnxruntime, tokenizers, numpy; no torch, no transformers), one process, 4 threads by default:

- **cells**: pairs/s and p50/p95/max batch latency of the forward pass at L = 256 and L = 512, batch 8. Every pair is exactly L tokens
  (64 real long passages per L, cycled), pre-tokenised, so the timing is the forward pass only. 25 s of timed batches per cell after 2
  untimed warm-up batches.
- **depth-25 query**: one real public query with 25 real passages (truncation 512, dynamic padding per batch of 8), tokenise + forward,
  5 timed repetitions after 1 untimed. The result lists the measured time and the prediction from the cells: all 25 pairs at L=256 (lower
  bound), all 25 at L=512 (upper bound), and a straight line through the two cells' per-pair times at the query's mean padded length.
- peak RSS (`resource`), model sha256, CPU facts (`lscpu` fields, the feature flags of `/proc/cpuinfo`, the cgroup CPU limit).

Hard caps, enforced inside the script: total runtime <= 150 s (cells and the query stop early; the result says `partial`) and memory
<= 2.5 GB (VmHWM; the run aborts and writes what it has). Exit code 0 complete, 3 partial, 4 memory abort, 5 the model-card sanity check failed. The script prints no passage text.

## Run (production host, CPU only, nothing is pulled: the image is `python:3.11-slim`)

```bash
tar xzf n1_bench_bundle.tar.gz && cd n1_bench_bundle && sha256sum -c MANIFEST.sha256 && mkdir -p out
docker run --rm --network none --memory 3g -e PIP_DISABLE_PIP_VERSION_CHECK=1 \
  -v "$PWD":/bundle:ro -v "$PWD/out":/out python:3.11-slim \
  bash -c 'pip install --no-index --find-links /bundle/wheels -r /bundle/requirements.txt > /dev/null && python /bundle/n1_bench.py --bundle /bundle --threads 4 --out /out/n1_result.json --table /out/n1_result.txt'
```

`requirements.txt` pins every wheel in `wheels/` (resolved for CPython 3.11, linux aarch64, manylinux, in CI): the install is offline.
The result is `out/n1_result.json` plus the table in `out/n1_result.txt` (also printed). Compare with the N2 reference in the release
notes (same image, same command, same 4 threads, measured on the 4-vCPU Neoverse-N2 CI runner).

## Bundle contents

| path | what |
|---|---|
| `n1_bench.py`, `requirements.txt`, `wheels/` | the bench and its pinned dependencies (onnxruntime 1.30.0, tokenizers 0.22.2, numpy 2.3.5 and their wheels) |
| `model/model_quantized.onnx` | `BAAI/bge-reranker-base` at revision `2cfc18c9415c912f9d8155881c133215df768a70`, exported with optimum 2.1.0 / onnxruntime 1.30.0 and quantised with `AutoQuantizationConfig.arm64(is_static=False, per_channel=False)`: E-RET-5a's recipe, `experiments/eret_pb/rerank.py export-ort` |
| `model/tokenizer.json` + tokenizer files, `model/MODEL_CARD.md` | the same revision's tokenizer and model card |
| `bench_pairs.json` | pairs built from `C-MTEB/T2Reranking` (revision `76631901a18387f85eaa53e5450019b87ad58ef9`, file sha256 `ceaf1ba1a4777dbb7aecad86fb8aa9cae7a678af6d711d5529c238e89bb6adff`, first 300 dev rows) |
| `MANIFEST.sha256` | sha256 of every file above |

## Licences

- Model `BAAI/bge-reranker-base`: MIT (the pinned revision's model card header, checked in CI before the export).
- Data `C-MTEB/T2Reranking`: the Hugging Face mirror card states no licence; the upstream T2Ranking README (github.com/THUIR/T2Ranking, read
  2026-10-20 for E-RET-5a) says Apache-2.0.
- Wheels in `wheels/` keep their own licences (onnxruntime MIT, numpy BSD-3-Clause, tokenizers Apache-2.0, others as published on PyPI).
