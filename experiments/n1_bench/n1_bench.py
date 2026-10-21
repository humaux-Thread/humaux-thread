#!/usr/bin/env python3
"""E-RET-5e: int8 cross-encoder rerank speed test for a CPU host (experiment, not product code).

Runs BAAI/bge-reranker-base (dynamic int8 ONNX) on public C-MTEB text only. Dependencies: onnxruntime, tokenizers, numpy
(pinned in requirements.txt of the bundle); no torch, no transformers. Prints and writes aggregate numbers only, never passage text.

Measures, per cell (L = 256, 512; batch 8): pairs/s and p50/p95 batch latency of the forward pass, on pre-tokenised pairs that are
exactly L tokens long (the pool cycles through bench_pairs.json). Then one real public query with 25 passages end to end (tokenise
plus forward, dynamic padding), predicted from the cells vs measured. Also peak RSS and the CPU flags.

Hard caps: total runtime <= 150 s (cells and the query stop early and the result says partial) and memory <= 2.5 GB (VmHWM; the run
aborts with the partial result). Exit codes: 0 complete, 3 partial (deadline), 4 memory abort, 5 the model-card sanity check failed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import resource
import subprocess
import sys
import time
from pathlib import Path

DEADLINE_S = 150.0  # whole process, from the first line of main()
MEM_CAP_B = 2_500_000_000  # 2.5 GB, compared with VmHWM
SLACK_S = 5.0  # internal deadline = DEADLINE_S - SLACK_S, so one in-flight batch and the write-out stay inside the cap
QUERY_RESERVE_S = 25.0  # the cells stop this long before the internal deadline so the depth-25 query still runs
LENGTHS, BATCH, QUERY_REPS = (256, 512), 8, 5
T0 = time.monotonic()


class Abort(Exception):
    """A hard cap fired. `why` is 'deadline' or 'memory'; the partial result is still written."""

    def __init__(self, why: str):
        super().__init__(why)
        self.why = why


def left(deadline: float) -> float:
    return deadline - (time.monotonic() - T0)


def vm_kb(field: str) -> int:
    m = re.search(rf"{field}:\s+(\d+) kB", Path("/proc/self/status").read_text())
    return int(m.group(1)) if m else 0


def check_mem():
    if vm_kb("VmHWM") * 1024 > MEM_CAP_B:
        raise Abort("memory")


def pct(xs, q):
    s = sorted(xs)
    i = (len(s) - 1) * q
    lo = int(i)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (i - lo)


def sh(cmd: str) -> str:
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def cpu_info() -> dict:
    """lscpu fields plus the feature flags of /proc/cpuinfo (hardware facts only)."""
    kv = {}
    for line in sh("lscpu").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            kv.setdefault(k.strip(), v.strip())
    flags = ""
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.split(":", 1)[0].strip() in ("Features", "flags"):
                flags = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    cg = ""
    for p in ("/sys/fs/cgroup/cpu.max", "/sys/fs/cgroup/cpu/cpu.cfs_quota_us"):
        try:
            cg = Path(p).read_text().strip()
            break
        except OSError:
            pass
    keep = ("Architecture", "Model name", "Vendor ID", "CPU(s)", "Thread(s) per core", "Core(s) per socket", "CPU max MHz", "BogoMIPS",
            "L1d cache", "L2 cache", "L3 cache")
    return {"lscpu": {k: kv[k] for k in keep if k in kv}, "flags": flags.split(), "cgroup_cpu_max": cg, "os_cpu_count": os.cpu_count()}


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Model:
    """ONNX session + tokenizer. Tokenisation is done by the caller through `encode`; `run` is the forward pass only."""

    def __init__(self, bundle: Path, threads: int):
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer

        self.np = np
        so = ort.SessionOptions()
        so.intra_op_num_threads, so.inter_op_num_threads = threads, 1
        t = time.perf_counter()
        self.sess = ort.InferenceSession(str(bundle / "model" / "model_quantized.onnx"), so, providers=["CPUExecutionProvider"])
        self.load_s = round(time.perf_counter() - t, 2)
        self.names = [i.name for i in self.sess.get_inputs()]
        self.tok = Tokenizer.from_file(str(bundle / "model" / "tokenizer.json"))
        self.pad_id = self.tok.token_to_id("<pad>")
        self.pad_id = 1 if self.pad_id is None else self.pad_id

    def encode(self, pairs, length: int, fixed: bool):
        """Pairs -> (input_ids, attention_mask) int64. fixed=True pads every pair to `length`; otherwise to the longest in the batch."""
        self.tok.enable_truncation(max_length=length)
        if fixed:
            self.tok.enable_padding(pad_id=self.pad_id, pad_token="<pad>", length=length)
        else:
            self.tok.enable_padding(pad_id=self.pad_id, pad_token="<pad>")
        encs = self.tok.encode_batch([(q, d) for q, d in pairs])
        ids = self.np.array([e.ids for e in encs], dtype=self.np.int64)
        mask = self.np.array([e.attention_mask for e in encs], dtype=self.np.int64)
        return ids, mask

    def run(self, ids, mask):
        feeds = {"input_ids": ids, "attention_mask": mask}
        out = self.sess.run(None, {k: v for k, v in feeds.items() if k in self.names})[0]
        return out.reshape(-1).tolist()


def sanity(m: Model) -> bool:
    """bge model card example: the panda passage must outscore 'hi'. Public text, short."""
    ids, mask = m.encode([("what is panda?", "hi"), ("what is panda?", "The giant panda (Ailuropoda melanoleuca), sometimes called a "
                           "panda bear or simply panda, is a bear species endemic to China.")], 128, False)
    s = m.run(ids, mask)
    return s[1] > s[0]


def run_cell(m: Model, pairs, length: int, cell_s: float, cell_deadline: float, cells: list) -> dict:
    """Forward-pass timing of batches of BATCH pre-tokenised pairs; 2 untimed warm-up batches; runs for cell_s seconds of timed work
    or until the cell deadline, whichever is first. The cell dict is appended to `cells` first, so a memory abort keeps it."""
    ids, mask = m.encode(pairs, length, True)
    real = mask.sum(axis=1)
    n = len(pairs)
    cell = {"L": length, "batch": BATCH, "pool_pairs": n, "pairs_shorter_than_L": int((real < length).sum()),
            "mean_real_tokens": round(float(real.mean()), 1), "timed_batches": 0, "complete": False}
    cells.append(cell)

    def batch(k):
        idx = [(k * BATCH + j) % n for j in range(BATCH)]
        return ids[idx], mask[idx]

    lat, started = [], None
    try:
        for k in range(2):  # warm-up, untimed
            if left(cell_deadline) <= 0:
                raise Abort("deadline")
            m.run(*batch(k))
            check_mem()
        started = time.monotonic()
        k = 2
        while time.monotonic() - started < cell_s:
            if left(cell_deadline) <= (sorted(lat)[len(lat) // 2] if lat else 0):
                raise Abort("deadline")
            x = batch(k)
            t = time.perf_counter()
            m.run(*x)
            lat.append(time.perf_counter() - t)
            k += 1
            check_mem()
        cell["complete"] = True
    except Abort as e:
        cell["stopped"] = e.why
        if e.why == "memory":
            raise
    cell["timed_batches"] = len(lat)
    if lat:
        cell.update({"timed_s": round(sum(lat), 2), "pairs_per_s": round(len(lat) * BATCH / sum(lat), 3),
                     "batch_ms_p50": round(pct(lat, .5) * 1000, 1), "batch_ms_p95": round(pct(lat, .95) * 1000, 1),
                     "batch_ms_max": round(max(lat) * 1000, 1)})
    return cell


def predict(cells, depth: int, mean_len: float):
    """Seconds for `depth` pairs: upper bound from the L=512 cell, lower bound from L=256, and a straight line through the two
    cells' per-pair times evaluated at the mean padded length of the real query."""
    by = {c["L"]: c for c in cells if c.get("pairs_per_s")}
    out = {}
    for L, c in by.items():
        out[f"all_pairs_at_L{L}_s"] = round(depth / c["pairs_per_s"], 3)
    if 256 in by and 512 in by:
        a, b = 1 / by[256]["pairs_per_s"], 1 / by[512]["pairs_per_s"]
        out["interpolated_at_mean_len_s"] = round(depth * (a + (b - a) * (mean_len - 256) / 256), 3)
    return out


def run_query(m: Model, q: dict, cells, query_deadline: float) -> dict:
    """One real public query, 25 passages, truncation 512, dynamic padding per batch of 8, tokenise + forward, QUERY_REPS repeats."""
    docs = q["passages"][:25]
    walls, tok_s, lens = [], [], []
    res = {"depth": len(docs), "batch": BATCH, "L_max": 512}
    try:
        for rep in range(QUERY_REPS + 1):  # rep 0 is untimed warm-up
            if left(query_deadline) <= 0:
                raise Abort("deadline")
            t0 = time.perf_counter()
            tk, ln = 0.0, []
            for i in range(0, len(docs), BATCH):
                if left(query_deadline) <= 0:
                    raise Abort("deadline")
                t = time.perf_counter()
                ids, mask = m.encode([(q["query"], d) for d in docs[i:i + BATCH]], 512, False)
                tk += time.perf_counter() - t
                ln += [int(x) for x in mask.sum(axis=1)]
                m.run(ids, mask)
                check_mem()
            if rep:
                walls.append(time.perf_counter() - t0)
                tok_s.append(tk)
                lens = ln
    except Abort as e:
        res["stopped"] = e.why
        if e.why == "memory":
            raise
    res["reps_timed"] = len(walls)
    if walls:
        mean_len = sum(lens) / len(lens)
        res.update({"tokens_per_pair_mean": round(mean_len, 1), "tokens_per_pair_max": max(lens),
                    "measured_s_p50": round(pct(walls, .5), 3), "measured_s_p95": round(pct(walls, .95), 3), "measured_s_min": round(min(walls), 3),
                    "of_which_tokenise_s_p50": round(pct(tok_s, .5), 4), "predicted": predict(cells, len(docs), mean_len)})
    return res


def table(r: dict) -> str:
    L = [f"n1_bench: threads={r['threads']} model_load_s={r.get('model_load_s')} peak_rss_mb={r.get('peak_rss_mb')} total_s={r['total_s']} "
         f"partial={r['partial']} stopped={r.get('stopped')} sanity_ok={r.get('sanity_ok')}",
         f"cpu: {r['cpu']['lscpu'].get('Model name', '?')} cpus={r['cpu']['lscpu'].get('CPU(s)', '?')} arch={r['cpu']['lscpu'].get('Architecture', '?')} "
         f"cgroup={r['cpu']['cgroup_cpu_max'] or '-'}", "",
         "| L | batch | batches | pairs/s | p50 ms | p95 ms | max ms | complete | pairs < L |", "|---|---|---|---|---|---|---|---|---|"]
    for c in r["cells"]:
        L.append(f"| {c['L']} | {c['batch']} | {c['timed_batches']} | {c.get('pairs_per_s', '-')} | {c.get('batch_ms_p50', '-')} | "
                 f"{c.get('batch_ms_p95', '-')} | {c.get('batch_ms_max', '-')} | {c['complete']} | {c['pairs_shorter_than_L']} |")
    q = r.get("query25")
    if q and q.get("reps_timed"):
        L += ["", f"depth-{q['depth']} query (L<=512, batch 8, mean {q['tokens_per_pair_mean']} tokens/pair, {q['reps_timed']} reps): "
              f"measured p50 {q['measured_s_p50']} s, p95 {q['measured_s_p95']} s (tokenise p50 {q['of_which_tokenise_s_p50']} s)",
              "predicted from the cells (s): " + ", ".join(f"{k}={v}" for k, v in q["predicted"].items())]
    elif q:
        L += ["", f"depth-25 query: not completed ({q.get('stopped')})"]
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", required=True, help="bundle directory (model/, bench_pairs.json)")
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--out", required=True, help="result JSON")
    ap.add_argument("--table", help="also write the text table here")
    ap.add_argument("--cell-seconds", type=float, default=25.0)
    a = ap.parse_args()
    bundle = Path(a.bundle)
    r = {"threads": a.threads, "caps": {"deadline_s": DEADLINE_S, "memory_bytes": MEM_CAP_B}, "cells": [], "partial": False,
         "env": {"python": sys.version.split()[0], "platform": platform.platform(), "machine": platform.machine()}, "cpu": cpu_info()}
    code = 0
    try:
        import numpy
        import onnxruntime
        import tokenizers
        r["env"].update({"numpy": numpy.__version__, "onnxruntime": onnxruntime.__version__, "tokenizers": tokenizers.__version__})
        pairs = json.loads((bundle / "bench_pairs.json").read_text(encoding="utf-8"))
        mp = bundle / "model" / "model_quantized.onnx"
        r["model"] = {"file": "model_quantized.onnx", "bytes": mp.stat().st_size, "sha256": sha256_file(mp), "pairs_meta": pairs.get("meta", {})}
        m = Model(bundle, a.threads)
        r["model_load_s"] = m.load_s
        r["rss_after_load_mb"] = round(vm_kb("VmRSS") / 1024)
        check_mem()
        r["sanity_ok"] = sanity(m)
        internal = DEADLINE_S - SLACK_S
        for L in LENGTHS:
            if left(internal - QUERY_RESERVE_S) <= 0:
                r["cells"].append({"L": L, "batch": BATCH, "timed_batches": 0, "complete": False, "pairs_shorter_than_L": 0, "stopped": "deadline"})
                continue
            run_cell(m, pairs["cells"][str(L)], L, a.cell_seconds, internal - QUERY_RESERVE_S, r["cells"])
        r["query25"] = run_query(m, pairs["query25"], r["cells"], internal)
    except Abort as e:
        r["stopped"] = e.why
        code = 4 if e.why == "memory" else 3
    r["partial"] = (code != 0 or "query25" not in r or r["query25"].get("stopped") is not None or r["query25"].get("reps_timed", 0) < QUERY_REPS
                    or any(not c["complete"] for c in r["cells"]) or len(r["cells"]) < len(LENGTHS))
    if r["partial"] and code == 0:
        r["stopped"] = "deadline"
        code = 3
    if code == 0 and not r.get("sanity_ok"):
        code = 5
    r["total_s"] = round(time.monotonic() - T0, 1)
    r["peak_rss_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024)  # Linux: KiB
    Path(a.out).write_text(json.dumps(r, indent=1))
    t = table(r)
    if a.table:
        Path(a.table).write_text(t)
    print(t, end="")
    sys.exit(code)


if __name__ == "__main__":
    main()
