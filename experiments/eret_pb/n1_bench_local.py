#!/usr/bin/env python3
"""E-RET-PB7: int8 cross-encoder rerank speed test for a CPU host, v2 (experiment, not product code). Shipped in the bundle as n1_bench.py.

Derived from n1-bench-bundle-v1's n1_bench.py (E-RET-5e). Runs the int8 ONNX models listed in cells.json on public C-MTEB text only. Dependencies:
onnxruntime, tokenizers, numpy (pinned in the bundle's requirements.txt); no torch, no transformers. Prints and writes aggregate numbers only, never passage text.

Per cell (model, depth K, truncation L) it times whole queries the way the rerank stage runs them: K passages, tokenise + forward in batches of 8 with dynamic
padding. Variants: `full_L` (every pair is L tokens: long public passages cut at L, the worst case for that cell) and `matched` (every pair is cut at T tokens, the
mean padded pair length measured in the corpus run; only when T < L). p50 / p95 / min / max over up to MAX_Q timed queries after one untimed warm-up query.

Hard caps: total runtime <= 150 s (variants stop early and the result says partial) and memory <= 2.5 GB (VmHWM; the run aborts with the partial result).
Exit codes: 0 complete, 3 partial (deadline), 4 memory abort, 5 a model's sanity check failed.
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
SLACK_S = 5.0  # internal deadline = DEADLINE_S - SLACK_S, so one in-flight query and the write-out stay inside the cap
BATCH, MAX_Q, MIN_Q = 8, 24, 3
PANDA = ("The giant panda (Ailuropoda melanoleuca), sometimes called a panda bear or simply panda, is a bear species endemic to China.")
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
    keep = ("Architecture", "Model name", "Vendor ID", "CPU(s)", "Thread(s) per core", "Core(s) per socket", "CPU max MHz", "BogoMIPS", "L1d cache", "L2 cache", "L3 cache")
    return {"lscpu": {k: kv[k] for k in keep if k in kv}, "flags": flags.split(), "cgroup_cpu_max": cg, "os_cpu_count": os.cpu_count()}


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Model:
    """ONNX session + tokenizer. `encode` tokenises a batch of pairs (truncation at `trunc` tokens, padding to the longest in the batch); `run` is the forward pass."""

    def __init__(self, mdir: Path, threads: int):
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer

        self.np = np
        so = ort.SessionOptions()
        so.intra_op_num_threads, so.inter_op_num_threads = threads, 1
        t = time.perf_counter()
        self.sess = ort.InferenceSession(str(mdir / "model_quantized.onnx"), so, providers=["CPUExecutionProvider"])
        self.load_s = round(time.perf_counter() - t, 2)
        self.names = [i.name for i in self.sess.get_inputs()]
        self.tok = Tokenizer.from_file(str(mdir / "tokenizer.json"))
        self.pad_id = self.tok.token_to_id("<pad>")
        self.pad_id = 1 if self.pad_id is None else self.pad_id

    def encode(self, pairs, trunc: int):
        self.tok.enable_truncation(max_length=trunc)
        self.tok.enable_padding(pad_id=self.pad_id, pad_token="<pad>")
        encs = self.tok.encode_batch([(q, d) for q, d in pairs])
        ids = self.np.array([e.ids for e in encs], dtype=self.np.int64)
        mask = self.np.array([e.attention_mask for e in encs], dtype=self.np.int64)
        return ids, mask

    def run(self, ids, mask):
        feeds = {"input_ids": ids, "attention_mask": mask}
        if "token_type_ids" in self.names:
            feeds["token_type_ids"] = self.np.zeros_like(ids)
        out = self.sess.run(None, {k: v for k, v in feeds.items() if k in self.names})[0]
        return out.reshape(-1).tolist()


def sanity(m: Model) -> bool:
    """bge / gte model-card style example: the panda passage must outscore 'hi'. Public text, short."""
    ids, mask = m.encode([("what is panda?", "hi"), ("what is panda?", PANDA)], 128)
    s = m.run(ids, mask)
    return s[1] > s[0]


def time_query(m: Model, query: str, docs, trunc: int):
    """One whole query: tokenise + forward for every batch. Returns (wall s, tokenise s, real pair lengths)."""
    t0 = time.perf_counter()
    tk, lens = 0.0, []
    for i in range(0, len(docs), BATCH):
        t = time.perf_counter()
        ids, mask = m.encode([(query, d) for d in docs[i:i + BATCH]], trunc)
        tk += time.perf_counter() - t
        lens += [int(x) for x in mask.sum(axis=1)]
        m.run(ids, mask)
        check_mem()
    return time.perf_counter() - t0, tk, lens


def run_variant(m: Model, queries, cell: dict, variant: str, trunc: int, budget_s: float, deadline: float, out: list) -> None:
    """Warm-up query (untimed), then timed queries until the budget or MAX_Q (at least MIN_Q while time remains). The record is appended first, so an abort keeps it."""
    rec = {"cell": cell["id"], "variant": variant, "K": cell["K"], "trunc": trunc, "timed_queries": 0, "complete": False}
    out.append(rec)
    walls, tks, lens = [], [], []
    docs = lambda q: q["passages"][:cell["K"]]  # noqa: E731
    try:
        if left(deadline) <= 0:
            raise Abort("deadline")
        time_query(m, queries[0]["query"], docs(queries[0]), trunc)
        start, k = time.monotonic(), 1
        while len(walls) < MAX_Q and (len(walls) < MIN_Q or time.monotonic() - start < budget_s):
            q = queries[k % len(queries)]
            k += 1
            if left(deadline) <= (sorted(walls)[len(walls) // 2] if walls else 0):
                raise Abort("deadline")
            w, tk, ln = time_query(m, q["query"], docs(q), trunc)
            walls.append(w)
            tks.append(tk)
            lens += ln
        rec["complete"] = True
    except Abort as e:
        rec["stopped"] = e.why
        if e.why == "memory":
            raise
    finally:
        rec["timed_queries"] = len(walls)
        if walls:
            rec.update({"tokens_per_pair_mean": round(sum(lens) / len(lens), 1), "p50_s": round(pct(walls, .5), 3), "p95_s": round(pct(walls, .95), 3),
                        "min_s": round(min(walls), 3), "max_s": round(max(walls), 3), "tokenise_p50_s": round(pct(tks, .5), 4)})


def table(r: dict) -> str:
    L = [f"n1_bench_v2: threads={r['threads']} peak_rss_mb={r.get('peak_rss_mb')} total_s={r['total_s']} partial={r['partial']} stopped={r.get('stopped')} "
         f"sanity_ok={r.get('sanity_ok')}",
         f"cpu: {r['cpu']['lscpu'].get('Model name', '?')} cpus={r['cpu']['lscpu'].get('CPU(s)', '?')} arch={r['cpu']['lscpu'].get('Architecture', '?')} "
         f"cgroup={r['cpu']['cgroup_cpu_max'] or '-'}", "", "model load s: " + ", ".join(f"{k}={v}" for k, v in r.get("model_load_s", {}).items()), "",
         "| cell | variant | K | trunc | queries | tokens/pair | p50 s | p95 s | min s | max s | complete |", "|---|---|---|---|---|---|---|---|---|---|---|"]
    for c in r["runs"]:
        L.append(f"| {c['cell']} | {c['variant']} | {c['K']} | {c['trunc']} | {c['timed_queries']} | {c.get('tokens_per_pair_mean', '-')} | {c.get('p50_s', '-')} | "
                 f"{c.get('p95_s', '-')} | {c.get('min_s', '-')} | {c.get('max_s', '-')} | {c['complete']} |")
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", required=True, help="bundle directory (cells.json, models/, bench_pairs.json)")
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--out", required=True, help="result JSON")
    ap.add_argument("--table", help="also write the text table here")
    a = ap.parse_args()
    bundle = Path(a.bundle)
    r = {"threads": a.threads, "caps": {"deadline_s": DEADLINE_S, "memory_bytes": MEM_CAP_B}, "runs": [], "model_load_s": {}, "partial": False, "sanity_ok": True,
         "env": {"python": sys.version.split()[0], "platform": platform.platform(), "machine": platform.machine()}, "cpu": cpu_info()}
    code = 0
    try:
        import numpy
        import onnxruntime
        import tokenizers
        r["env"].update({"numpy": numpy.__version__, "onnxruntime": onnxruntime.__version__, "tokenizers": tokenizers.__version__})
        cells = json.loads((bundle / "cells.json").read_text(encoding="utf-8"))["cells"]
        queries = json.loads((bundle / "bench_pairs.json").read_text(encoding="utf-8"))["queries"]
        r["models"] = {c["model_dir"]: {"sha256": sha256_file(bundle / c["model_dir"] / "model_quantized.onnx"),
                                         "bytes": (bundle / c["model_dir"] / "model_quantized.onnx").stat().st_size} for c in cells}
        plan = [(c, "full_L", c["L"]) for c in cells] + [(c, "matched", c["matched_T"]) for c in cells if c.get("matched_T") and c["matched_T"] < c["L"]]
        plan.sort(key=lambda x: (x[0]["model_dir"], x[0]["id"], x[1]))  # one model loaded at a time
        internal = DEADLINE_S - SLACK_S
        cur, m = None, None
        for i, (c, variant, trunc) in enumerate(plan):
            if c["model_dir"] != cur:
                m = None  # release the previous session before the next model is loaded
                m = Model(bundle / c["model_dir"], a.threads)
                cur = c["model_dir"]
                r["model_load_s"][cur] = m.load_s
                r["rss_after_load_mb"] = round(vm_kb("VmRSS") / 1024)
                check_mem()
                if not sanity(m):
                    r["sanity_ok"] = False
            budget = max(1.0, left(internal) / (len(plan) - i))
            run_variant(m, queries, c, variant, trunc, budget, internal, r["runs"])
    except Abort as e:
        r["stopped"] = e.why
        code = 4 if e.why == "memory" else 3
    r["partial"] = code != 0 or any(not x["complete"] for x in r["runs"]) or not r["runs"]
    if r["partial"] and code == 0:
        r["stopped"] = "deadline"
        code = 3
    if code == 0 and not r["sanity_ok"]:
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
