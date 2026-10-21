#!/usr/bin/env python3
"""E-RET-5e prep: build the model / tokenizer / pairs part of the N1 bench bundle in CI (experiment, not product code).

  build   check the pinned BAAI/bge-reranker-base revision and its licence, export it to ONNX with dynamic int8 (exactly E-RET-5a's
          recipe, via ../eret_pb/rerank.py export-ort), copy model_quantized.onnx + tokenizer files, and write bench_pairs.json from
          public C-MTEB/T2Reranking text (pinned revision and file hash as in 5a).
  pins    write requirements.txt with an exact == pin for every wheel in a directory (the wheels were downloaded by `pip download`).

Public model (MIT) and public data (Apache-2.0, upstream THUIR/T2Ranking) only; no corpus of ours is involved. Needs torch, optimum,
pyarrow and huggingface_hub (the CI job installs them); the bench itself needs none of these.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "eret_pb"))

REPO, REV = "BAAI/bge-reranker-base", "2cfc18c9415c912f9d8155881c133215df768a70"
DATASET_REPO = "C-MTEB/T2Reranking"
DATASET_REV = "76631901a18387f85eaa53e5450019b87ad58ef9"
DATASET_FILE = "data/dev-00000-of-00001-65d96bde8023d9b9.parquet"
DATASET_SHA256 = "ceaf1ba1a4777dbb7aecad86fb8aa9cae7a678af6d711d5529c238e89bb6adff"
# HF card of the mirror states no licence; the upstream T2Ranking README (github.com/THUIR/T2Ranking, read 2026-10-20 by E-RET-5a) says Apache-2.0.
DATASET_LICENCE = "Apache-2.0 (upstream THUIR/T2Ranking README; the HF mirror card states none)"
LENGTHS, POOL, ROWS = (256, 512), 64, 300  # pairs per length, dataset rows used (as in 5a)
TOKENIZER_FILES = ("tokenizer.json", "tokenizer_config.json", "special_tokens_map.json", "sentencepiece.bpe.model", "config.json")


def build_pool(rows, min_chars: int):
    """POOL (query, doc) pairs whose doc concatenates real passages until it is long enough to fill a pair to exactly L tokens (5a)."""
    pool = []
    for i in range(POOL):
        docs = list(rows[i]["positive"]) + list(rows[i]["negative"])
        j = POOL
        while sum(map(len, docs)) < min_chars and j < POOL + len(rows):
            docs += list(rows[(i + j) % len(rows)]["positive"])
            j += 1
        pool.append((rows[i]["query"], "\n".join(docs)))
    return pool


def build(a):
    import pyarrow.parquet as pq
    from huggingface_hub import hf_hub_download

    import rerank as R  # torch; only this subcommand imports it

    out, work = Path(a.out), Path(a.work)
    (out / "model").mkdir(parents=True, exist_ok=True)
    info = R.pin_and_licence(REPO, REV)  # fails unless the pin resolves to itself and the licence is MIT or Apache-2.0
    src = R.download(REPO, REV)
    subprocess.run([sys.executable, str(HERE.parent / "eret_pb" / "rerank.py"), "export-ort", src, str(work)], check=True)
    q = work / "int8" / "model_quantized.onnx"
    shutil.copy2(q, out / "model" / "model_quantized.onnx")
    for f in TOKENIZER_FILES:  # the bench reads tokenizer.json only; the rest is shipped for completeness
        if (Path(src) / f).exists():
            shutil.copy2(Path(src) / f, out / "model" / f)
    if not (out / "model" / "tokenizer.json").exists():
        raise SystemExit("tokenizer.json missing from the pinned snapshot")
    shutil.copy2(Path(src) / "README.md", out / "model" / "MODEL_CARD.md")

    pq_path = hf_hub_download(DATASET_REPO, DATASET_FILE, repo_type="dataset", revision=DATASET_REV)
    h = hashlib.sha256(Path(pq_path).read_bytes()).hexdigest()
    if h != DATASET_SHA256:
        raise SystemExit("dataset file hash mismatch")
    rows = pq.read_table(pq_path).slice(0, ROWS).to_pylist()
    big = next(r for r in rows if len(r["positive"]) + len(r["negative"]) >= 25)
    docs = (list(big["positive"]) + list(big["negative"]))[:25]
    pairs = {"meta": {"model": {**info, "quantisation": "optimum 2.1.0 / onnxruntime 1.30.0 AutoQuantizationConfig.arm64(is_static=False, per_channel=False)"},
                      "dataset": {"repo": DATASET_REPO, "revision": DATASET_REV, "file": DATASET_FILE, "sha256": DATASET_SHA256, "licence": DATASET_LICENCE},
                      "pairs_per_length": POOL, "query25_passages": len(docs)},
             "cells": {str(L): build_pool(rows, 3 * L) for L in LENGTHS},
             "query25": {"query": big["query"], "passages": docs}}
    (out / "bench_pairs.json").write_text(json.dumps(pairs, ensure_ascii=False), encoding="utf-8")
    print("built:", {"int8_mb": round(q.stat().st_size / 1048576, 1), "pairs": POOL, "licence": info["licence"], "dataset_sha_ok": True})


def pins(a):
    names = sorted(p.name for p in Path(a.wheels).glob("*.whl"))
    lines = ["# Exact pins of every wheel in wheels/ (python:3.11-slim, linux aarch64, resolved by `pip download` in CI); install with",
             "# pip install --no-index --find-links wheels -r requirements.txt", ""]
    for n in names:
        name, ver = n.split("-")[:2]
        lines.append(f"{name}=={ver}")
    Path(a.out).write_text("\n".join(lines) + "\n")
    print("pins:", len(names), "wheels")


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    b = sp.add_parser("build")
    b.add_argument("--out", required=True)
    b.add_argument("--work", required=True)
    p = sp.add_parser("pins")
    p.add_argument("--wheels", required=True)
    p.add_argument("--out", required=True)
    a = ap.parse_args()
    build(a) if a.cmd == "build" else pins(a)


if __name__ == "__main__":
    main()
