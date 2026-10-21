#!/usr/bin/env python3
"""E-RET-PB1: own-corpus retrieval experiments on public CI from an encrypted pack (E-RET-0, E-RET-1, E-RET-5b).

Subcommands (stdlib only, except `rerank` which imports rerank.py and needs torch):
  fetch     download a ciphertext release asset with curl, decrypt it, check the sha256 of the gz, write plaintext to $RUNNER_TEMP
  embed     stage 1: model-identity check on 3 sanity chunks, then embed the query set (needs DASHSCOPE_API_KEY in this step's env)
  j0        E-RET-0 / E-RET-1 on dense order: stage counts, pool ceilings, conversion, Clopper-Pearson 95% intervals
  rerank    one job of the rerank matrix: arms of the form kind:L:depth over the depth-d memory pool
  aggregate merge the part files of all jobs into one results file
  guard     fail if any 12-character window of any corpus text appears in the given output files
  selftest  statistics + J0 + guard on a fake pack (runs in CI before any real data is touched)
  embed2    PB2 stage 1: query-vector variants q0 / q1 / q2 and the compat text_type probe (pb2.py)
  eval2     PB2 stage 3: dense variants, BM25, RRF and the rerank arm on the full corpus (pb2.py)
  guard2    like guard, against the PB2 corpus tar

Privacy: the plaintext pack is corpus text. Nothing here prints, logs or writes it: output is counts, rates, intervals, b/c/p,
latencies. Exceptions are reported by class and source line only. Per-question results never leave the job that computed them
(McNemar needs paired bits, so paired arms run in one job). Design: design_v0.2 sections 19.4 / 19.5 (private).
"""
from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

REPO = "humaux/humaux-thread"
TAG = "eval-pack-e-ret-2026-10-v1"
DASH_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1/embeddings"
DASH_MM_URL = "https://dashscope.aliyuncs.com/api/v1/services/embeddings/multimodal-embedding/multimodal-embedding"
# (model, endpoint kind), tried in this order; the first with cos >= 0.99 on 3 of 3 wins. Run 1 showed text-embedding-v3 does not match
# (cosines ~0) and qwen3-vl-embedding is not served by compatible mode (404 model_not_supported). The old Rust source names cloud
# text-embedding-v4 (1024 dims) as the production dense model; providers.json names qwen3-vl-embedding, which only the native
# multimodal endpoint serves (Alibaba Model Studio multimodal-embedding API reference, read 2026-10-21, last updated 2026-10-11).
CANDIDATES = (("text-embedding-v4", "compat"), ("qwen3-vl-embedding", "native"))
DIM, BATCH, COS_MIN = 1024, 10, 0.99
ACTIVE = (None, "active")  # status filter: active or NULL
DEPTHS = (25, 50, 100, 200)
TYPES = ("state", "fact")
WINDOW = 12  # guard: any 12-character window of corpus text
OPENSSL = ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "600000", "-md", "sha256"]


def log(*a):
    print(*a, file=sys.stderr, flush=True)


# ---------------------------------------------------------------- statistics
def _binom_cdf(k: int, n: int, p: float) -> float:
    if p <= 0:
        return 1.0
    if p >= 1:
        return 1.0 if k >= n else 0.0
    return min(1.0, sum(math.comb(n, i) * p**i * (1 - p) ** (n - i) for i in range(k + 1)))


def _root(f, increasing: bool) -> float:
    lo, hi = 0.0, 1.0
    for _ in range(80):
        mid = (lo + hi) / 2
        if (f(mid) < 0) == increasing:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def clopper_pearson(k: int, n: int, alpha: float = 0.05):
    """Exact two-sided interval for k successes in n trials (zero errors still gets a bound)."""
    if n == 0:
        return None, None
    lo = 0.0 if k == 0 else _root(lambda p: (1 - _binom_cdf(k - 1, n, p)) - alpha / 2, True)
    hi = 1.0 if k == n else _root(lambda p: _binom_cdf(k, n, p) - alpha / 2, False)
    return lo, hi


def rate(k: int, n: int) -> dict:
    lo, hi = clopper_pearson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 4) if n else None,
            "lo": None if lo is None else round(lo, 4), "hi": None if hi is None else round(hi, 4)}


def mcnemar(a_hits, b_hits) -> dict:
    """Exact two-sided McNemar. A = baseline, B = challenger: b = A hit & B miss, c = A miss & B hit (c is the gain)."""
    assert len(a_hits) == len(b_hits)
    b = sum(1 for x, y in zip(a_hits, b_hits) if x and not y)
    c = sum(1 for x, y in zip(a_hits, b_hits) if y and not x)
    n = b + c
    p = 1.0 if n == 0 else min(1.0, 2 * sum(math.comb(n, i) for i in range(min(b, c) + 1)) / 2**n)
    return {"N": len(a_hits), "b": b, "c": c, "p": float(f"{p:.4g}")}


def pct(xs, q: float) -> float:
    s = sorted(xs)
    i = (len(s) - 1) * q
    lo = int(math.floor(i))
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (i - lo)


# ---------------------------------------------------------------- pack and fold
def load_pack(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def fold(q: dict, memories: dict, chunks: dict):
    """Chunks fold into memories by max score. Returns (seq_all, kept, mem_chunk, stats): seq_all = memories in dense order,
    kept = those passing the status filter (active or NULL; absent from the memories table = dropped), mem_chunk = the
    best-scoring chunk id that has stored text, per memory."""
    seq, score, mem_chunk = [], {}, {}
    n_nochunk = n_absent = 0
    for cid, mid, sc in sorted(q["cands"], key=lambda c: -c[2]):  # stable: ties keep search order
        if mid not in score:
            score[mid] = sc
            seq.append(mid)
        if mid not in mem_chunk and cid is not None and cid in chunks:
            mem_chunk[mid] = cid
        n_nochunk += cid is None
        n_absent += mid not in memories
    kept = [m for m in seq if m in memories and memories[m].get("status") in ACTIVE]
    return seq, kept, mem_chunk, {"cands": len(q["cands"]), "cands_without_chunk": n_nochunk, "cands_memory_absent": n_absent}


def analyse(pack: dict) -> list[dict]:
    mem, chunks, gi = pack["memories"], pack["chunks"], pack.get("gold_info", {})
    out = []
    for q in pack["questions"]:
        g = q["gold_memory_id"]
        seq, kept, mem_chunk, st = fold(q, mem, chunks)
        out.append({"type": q["type"], "reach": gi.get(g, {}).get("n_points", 0) > 0, "in200": g in seq,
                    "kept": g in kept, "rank": kept.index(g) + 1 if g in kept else None, "kept_list": kept,
                    "mem_chunk": mem_chunk, "stats": st, "n_seq": len(seq), "n_kept": len(kept)})
    return out


def dense_hits(an: list[dict]) -> list[int]:
    return [int(r["rank"] is not None and r["rank"] <= 5) for r in an]


# ---------------------------------------------------------------- J0 (E-RET-0 / E-RET-1)
STAGES = (("reachable", lambda r: r["reach"]),
          ("in_top200_chunks", lambda r: r["in200"]),
          ("after_status_filter", lambda r: r["kept"]),
          ("pool_25", lambda r: r["rank"] is not None and r["rank"] <= 25),
          ("pool_50", lambda r: r["rank"] is not None and r["rank"] <= 50),
          ("pool_100", lambda r: r["rank"] is not None and r["rank"] <= 100),
          ("pool_200", lambda r: r["rank"] is not None and r["rank"] <= 200),
          ("top5_at_depth_25", lambda r: r["rank"] is not None and r["rank"] <= 5))


def j0(pack: dict, an: list | None = None) -> dict:
    an = analyse(pack) if an is None else an  # PB2 passes its own per-question records
    out = {"stages": {}, "conversion": {}, "reachable_only": {}, "pool25_vs_pool100": {}, "counters": {}}
    for split in ("all",) + TYPES:
        rs = [r for r in an if split == "all" or r["type"] == split]
        n = len(rs)
        out["stages"][split] = {"questions": n, **{name: rate(sum(1 for r in rs if f(r)), n) for name, f in STAGES}}
        p25, top5 = sum(1 for r in rs if STAGES[3][1](r)), sum(1 for r in rs if STAGES[7][1](r))
        out["conversion"][split] = rate(top5, p25)  # conversion = top5 / in_pool@25
        reach = [r for r in rs if r["reach"]]
        out["reachable_only"][split] = {"questions": len(reach),
                                        **{name: rate(sum(1 for r in reach if f(r)), len(reach)) for name, f in STAGES[1:]}}
        out["pool25_vs_pool100"][split] = mcnemar([int(STAGES[3][1](r)) for r in rs], [int(STAGES[5][1](r)) for r in rs])
    st = [r["stats"] for r in an]
    out["counters"] = {"questions": len(an), "chunk_candidates": sum(s["cands"] for s in st),
                       "candidates_without_pg_chunk": sum(s["cands_without_chunk"] for s in st),
                       "candidates_memory_absent_from_pg": sum(s["cands_memory_absent"] for s in st),
                       "mean_memories_after_fold": round(sum(r["n_seq"] for r in an) / len(an), 2),
                       "mean_memories_after_filter": round(sum(r["n_kept"] for r in an) / len(an), 2),
                       "gold_memories_total": len({q["gold_memory_id"] for q in pack["questions"]}),
                       "gold_missing_from_pg": sum(1 for g in {q["gold_memory_id"] for q in pack["questions"]}
                                                   if not pack.get("gold_info", {}).get(g, {}).get("in_pg")),
                       "gold_without_chunk_or_point": sum(1 for g in {q["gold_memory_id"] for q in pack["questions"]}
                                                          if pack.get("gold_info", {}).get(g, {}).get("n_points", 0) == 0),
                       "dense_hit5": sum(dense_hits(an))}
    out["manifest"] = {k: v for k, v in pack["manifest"].items() if isinstance(v, (int, float, str))}
    return out


def fmt_rate(r: dict) -> str:
    return "n/a" if not r["n"] else f"{r['k']}/{r['n']} = {r['rate']:.3f} [{r['lo']:.3f}, {r['hi']:.3f}]"


def render_j0(r: dict) -> str:
    L = ["## E-RET-0 / E-RET-1 (dense order, no model)", "", "Stage counts, rate and Clopper-Pearson 95% interval. Denominator = questions of the split.", "",
         "| stage | all | state | fact |", "|---|---|---|---|"]
    for name, _ in STAGES:
        L.append(f"| {name} | " + " | ".join(fmt_rate(r["stages"][s][name]) for s in ("all",) + TYPES) + " |")
    L += ["", "| | all | state | fact |", "|---|---|---|---|",
          "| conversion = top5 / pool_25 | " + " | ".join(fmt_rate(r["conversion"][s]) for s in ("all",) + TYPES) + " |", ""]
    L += ["Reachable questions only (gold memory has a chunk and a point in the old store).", "",
          "| stage | all | state | fact |", "|---|---|---|---|",
          "| questions | " + " | ".join(str(r["reachable_only"][s]["questions"]) for s in ("all",) + TYPES) + " |"]
    for name, _ in STAGES[1:]:
        L.append(f"| {name} | " + " | ".join(fmt_rate(r["reachable_only"][s][name]) for s in ("all",) + TYPES) + " |")
    L += ["", "Pool ceiling, depth 25 vs 100, exact McNemar (b = in pool_25 only, c = gained at depth 100):", "",
          "| split | N | b | c | p |", "|---|---|---|---|---|"]
    for s in ("all",) + TYPES:
        m = r["pool25_vs_pool100"][s]
        L.append(f"| {s} | {m['N']} | {m['b']} | {m['c']} | {m['p']} |")
    L += ["", "Counters: " + ", ".join(f"{k}={v}" for k, v in r["counters"].items()), ""]
    return "\n".join(L)


# ---------------------------------------------------------------- rerank (E-RET-5b)
def rerank_job(a):
    import gc
    import platform

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import rerank as R  # needs torch; only this subcommand imports it

    R.torch.set_num_threads(4)
    pack = load_pack(a.pack)
    an = analyse(pack)
    dense = dense_hits(an)
    mem = pack["memories"]
    arms = [tuple(x.split(":")) for x in a.arms.split(",")]
    arms = [(k, int(L), int(d)) for k, L, d in arms]
    res = {"job": a.key, "env": {"machine": platform.machine(), "cpus": os.cpu_count(), "python": sys.version.split()[0],
                                 "torch": R.torch.__version__}, "model": R.pin_and_licence(a.repo, a.rev), "dense": rate(sum(dense), len(dense)),
           "arms": [], "pairs": [], "errors": []}
    path = R.download(a.repo, a.rev)
    hits = {}
    for kind in dict.fromkeys(k for k, _, _ in arms):
        sc = R.Scorer(R.KIND[kind], path)
        ok = sc.sanity()
        log("scorer", kind, "sanity", ok, "export_s", sc.export_s)
        for k, L, depth in (x for x in arms if x[0] == kind):
            name = f"{k}-L{L}-d{depth}"
            hit, wall, pool_hit = [], [], 0
            docs_all = []
            for r, q in zip(an, pack["questions"]):  # pool = first `depth` memories after the filter, each as title + best chunk text
                docs_all.append([(mem[m].get("title", "") + "\n" + pack["chunks"].get(r["mem_chunk"].get(m), "")).strip() for m in r["kept_list"][:depth]])
            sc.score_query(pack["questions"][0]["query"], docs_all[0], L)  # warm-up, untimed
            for i, (r, q) in enumerate(zip(an, pack["questions"])):
                t = time.perf_counter()
                s = sc.score_query(q["query"], docs_all[i], L)
                wall.append(time.perf_counter() - t)
                order = sorted(range(len(s)), key=lambda j: (-s[j], j))  # stable by dense rank
                top5 = [r["kept_list"][j] for j in order[:5]]
                hit.append(int(q["gold_memory_id"] in top5))
                pool_hit += int(r["rank"] is not None and r["rank"] <= depth)
                if (i + 1) % 33 == 0:
                    log(name, f"{i + 1}/{len(an)} questions, {sum(wall):.0f}s")
            hits[name] = hit
            res["arms"].append({
                "arm": name, "kind": k, "L": L, "depth": depth, "scorer_sanity": ok, "export_s": sc.export_s,
                "hit5": rate(sum(hit), len(hit)),
                "hit5_by_type": {t: rate(sum(h for h, r in zip(hit, an) if r["type"] == t), sum(1 for r in an if r["type"] == t)) for t in TYPES},
                "pool_ceiling": rate(pool_hit, len(hit)),
                "mcnemar_vs_dense": mcnemar(dense, hit),
                "latency_s": {"n": len(wall), "p50": round(pct(wall, .5), 3), "p95": round(pct(wall, .95), 3), "mean": round(sum(wall) / len(wall), 3)}})
            log("arm done", name, res["arms"][-1]["hit5"], res["arms"][-1]["latency_s"])
            Path(a.out).write_text(json.dumps(res, indent=1))
            Path(a.summary).write_text(render_rerank(res))
        del sc
        gc.collect()
    for k, L, depth in arms:  # fp32 vs int8, same model, same L and depth
        if k == "int8" and f"fp32-L{L}-d{depth}" in hits:
            res["pairs"].append({"fp32_vs_int8": f"L{L}-d{depth}", **mcnemar(hits[f"fp32-L{L}-d{depth}"], hits[f"int8-L{L}-d{depth}"])})
    Path(a.out).write_text(json.dumps(res, indent=1))
    Path(a.summary).write_text(render_rerank(res))


def render_rerank(res: dict) -> str:
    L = [f"## E-RET-5b rerank job {res['job']}", "", f"Dense hit@5 on the same questions: {fmt_rate(res['dense'])}. McNemar: A = dense, B = arm; "
         "b = dense hit & arm miss, c = dense miss & arm hit.", "",
         "| arm | hit@5 | state | fact | pool ceiling | N | b | c | p | p50 s | p95 s |", "|---|---|---|---|---|---|---|---|---|---|---|"]
    for x in res["arms"]:
        m, t = x["mcnemar_vs_dense"], x["latency_s"]
        L.append(f"| {x['arm']} | {fmt_rate(x['hit5'])} | {fmt_rate(x['hit5_by_type']['state'])} | {fmt_rate(x['hit5_by_type']['fact'])} | "
                 f"{fmt_rate(x['pool_ceiling'])} | {m['N']} | {m['b']} | {m['c']} | {m['p']} | {t['p50']} | {t['p95']} |")
    if res["pairs"]:
        L += ["", "fp32 vs int8 (A = fp32, B = int8):", "", "| pair | N | b | c | p |", "|---|---|---|---|---|"]
        L += [f"| {x['fp32_vs_int8']} | {x['N']} | {x['b']} | {x['c']} | {x['p']} |" for x in res["pairs"]]
    return "\n".join(L) + "\n"


def aggregate(a):
    parts = [json.loads(p.read_text()) for p in sorted(Path(a.parts).glob("*.json"))]
    out = {"j0": next((p for p in parts if "stages" in p), None), "rerank": [p for p in parts if "arms" in p]}
    Path(a.out).write_text(json.dumps(out, indent=1))
    L = ["## E-RET-PB1 results (merged)", "", f"Parts: {len(parts)}. J0 present: {out['j0'] is not None}.", "",
         "| job | arm | hit@5 | N | b | c | p | p50 s | p95 s |", "|---|---|---|---|---|---|---|---|---|"]
    for p in out["rerank"]:
        for x in p["arms"]:
            m, t = x["mcnemar_vs_dense"], x["latency_s"]
            L.append(f"| {p['job']} | {x['arm']} | {fmt_rate(x['hit5'])} | {m['N']} | {m['b']} | {m['c']} | {m['p']} | {t['p50']} | {t['p95']} |")
    Path(a.summary).write_text("\n".join(L) + "\n")


# ---------------------------------------------------------------- fetch / embed
def fetch(a):
    """curl the ciphertext asset (public repo), decrypt with the pack key from this step's env, verify the gz sha256, gunzip."""
    raw = os.environ["HUMAUX_EVAL_PACK_KEY"]
    key = raw.splitlines()[0].strip() if raw.strip() else ""  # same as `openssl -pass file:` (first line, no newline)
    tmp = Path(os.environ.get("RUNNER_TEMP", "/tmp"))
    enc, gz = tmp / "asset.enc", tmp / "asset.gz"
    subprocess.run(["curl", "-fsSL", "--retry", "3", "-o", str(enc), f"https://github.com/{REPO}/releases/download/{TAG}/{a.asset}"], check=True)
    subprocess.run(OPENSSL[:2] + ["-d"] + OPENSSL[2:] + ["-pass", "env:EVAL_K", "-in", str(enc), "-out", str(gz)], check=True,
                   env={**os.environ, "EVAL_K": key})
    got = hashlib.sha256(gz.read_bytes()).hexdigest()
    enc.unlink()
    if got != a.sha:
        gz.unlink()
        raise SystemExit(f"sha256 mismatch for {a.asset}: got {got[:12]}, want {a.sha[:12]}")
    with gzip.open(gz, "rb") as f, open(a.out, "wb") as o:
        shutil.copyfileobj(f, o)
    gz.unlink()
    if a.keyfile:
        fd = os.open(a.keyfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key + "\n")
    log("fetched", a.asset, "sha ok", "bytes", Path(a.out).stat().st_size)


def cosine(x, y) -> float:
    return sum(p * q for p, q in zip(x, y)) / math.sqrt(sum(p * p for p in x) * sum(q * q for q in y))


class ApiError(SystemExit):
    pass


class ApiHttp(Exception):
    """A non-retryable 4xx answer, raised only when the caller asked for soft errors (PB2 probes and optional variants)."""

    def __init__(self, http, code):
        super().__init__(f"http={http} code={code}")
        self.http, self.code = http, code


class ModelUnsupported(Exception):
    """HTTP 404 model_not_supported: this endpoint does not serve the model. A reason to try the next candidate, not to stop."""


def api_embed(model: str, kind: str, texts: list[str], key: str, scrub: list[str], urls: dict, extra: dict | None = None,
              soft: bool = False) -> list[list[float]]:
    """One embeddings call. compat = OpenAI-compatible body, native = multimodal-embedding body (independent embedding per text, no
    instruction, dimension 1024; the old code applies no prefix or instruction either). 5xx and 429 are retried with backoff (429
    twice only). 404 model_not_supported raises ModelUnsupported; any other 4xx (auth, Arrearage, quota, bad request) stops the job
    and prints the raw status and error code: those are the owner's to settle. PB2 adds kind "text" (native text-embedding API:
    input.texts, parameters incl. `extra`), `extra` (compat: extra body fields) and soft=True (a non-retryable 4xx raises ApiHttp
    instead of stopping the job)."""
    if kind == "compat":
        body = {"model": model, "input": texts, "dimensions": DIM, "encoding_format": "float", **(extra or {})}
    elif kind == "text":
        body = {"model": model, "input": {"texts": texts}, "parameters": {"dimension": DIM, "output_type": "dense", **(extra or {})}}
    else:
        body = {"model": model, "input": {"contents": [{"text": t} for t in texts]}, "parameters": {"dimension": DIM}}
    raw_body = json.dumps(body).encode()
    for attempt in range(4):
        req = urllib.request.Request(urls[kind], data=raw_body, method="POST", headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                j = json.loads(r.read())
            data = j["data"] if kind == "compat" else j["output"]["embeddings"]
            return [d["embedding"] for d in sorted(data, key=lambda d: d["index"] if "index" in d else d["text_index"])]
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            try:
                j = json.loads(raw)
                code = j.get("code") or (j.get("error") or {}).get("code") or (j.get("error") or {}).get("type")
                msg = str(j.get("message") or (j.get("error") or {}).get("message") or "")
            except ValueError:
                code, msg = None, ""
            for s in scrub:  # the message should not echo the input, but never let a query through
                if len(s) >= 6:
                    msg = msg.replace(s[:6], "***")
            print(f"API_ERROR kind={kind} model={model} http={e.code} code={code} message={msg[:200]!r} attempt={attempt + 1}", flush=True)
            if e.code == 404 and code == "model_not_supported":
                raise ModelUnsupported(model)
            if (e.code == 429 and attempt < 2) or e.code >= 500:
                if attempt < 3:
                    time.sleep(5 * 4**attempt)
                    continue
            if soft and e.code < 500 and e.code != 429:
                raise ApiHttp(e.code, code)
            raise ApiError(3)
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            print(f"API_NETWORK_ERROR {type(e).__name__} attempt={attempt + 1}", flush=True)
            if attempt < 3:
                time.sleep(5 * 4**attempt)
                continue
            raise ApiError(3)
    raise ApiError(3)


def embed(a, urls: dict | None = None):
    urls = urls or {"compat": DASH_URL, "native": DASH_MM_URL}
    key = os.environ["DASHSCOPE_API_KEY"]
    qp = json.loads(Path(a.qpack).read_text(encoding="utf-8"))
    scrub = [q["query"] for q in qp["queries"]] + [s["text"] for s in qp["sanity"]]
    calls, chosen, cos = 0, None, {}
    for model, kind in CANDIDATES:  # 3 sanity texts (raw chunk text, as the old ingestion embeds them) in one call per candidate
        try:
            vecs = api_embed(model, kind, [s["text"] for s in qp["sanity"]], key, scrub, urls)
        except ModelUnsupported:
            calls += 1
            print(f"identity model={model} kind={kind} not served by this endpoint, skipped", flush=True)
            continue
        calls += 1
        cs = [cosine(v, s["vector"]) for v, s in zip(vecs, qp["sanity"])]
        cos[model] = [round(c, 5) for c in cs]
        print(f"identity model={model} kind={kind} dim={len(vecs[0])} cosines={cos[model]}", flush=True)
        if len(vecs[0]) == DIM and all(c >= COS_MIN for c in cs):
            chosen, chosen_kind = model, kind
            break
    if not chosen:
        raise SystemExit("identity check failed: no candidate model reaches cosine 0.99 on 3 of 3 chunks")
    vectors = {}
    qs = qp["queries"]
    for i in range(0, len(qs), BATCH):  # ponytail: batches of 10 instead of one call per query keep the run well inside the 200-call budget
        vecs = api_embed(chosen, chosen_kind, [q["query"] for q in qs[i:i + BATCH]], key, scrub, urls)  # raw query text, no prefix or instruction
        calls += 1
        for q, v in zip(qs[i:i + BATCH], vecs):
            if len(v) != DIM or not all(math.isfinite(x) for x in v):
                raise SystemExit("bad vector shape")
            vectors[q["qid"]] = v
    assert len(vectors) == len(qs)
    Path(a.out).write_text(json.dumps({"model": chosen, "kind": chosen_kind, "dim": DIM, "cosines": cos, "calls": calls, "vectors": vectors}))
    print(f"embedded queries={len(vectors)} model={chosen} kind={chosen_kind} dim={DIM} api_calls={calls}", flush=True)


# ---------------------------------------------------------------- guard
def static_strings(out_files: list[str], extra: list[str]) -> set[str]:
    """Strings that code (not the corpus) put into the outputs: every literal in this file and rerank.py, the command line, and
    the code-made identifiers in the results (job key, arm names, model pins, `env` / `model` / `manifest` blocks). They are exempt from the window check, so a label that happens to occur in the
    corpus (model names, table headers) cannot fail the guard."""
    s = set(extra)
    for p in (Path(__file__), Path(__file__).with_name("rerank.py"), Path(__file__).with_name("pb2.py")):
        if p.exists():
            s.update(n.value for n in ast.walk(ast.parse(p.read_text())) if isinstance(n, ast.Constant) and isinstance(n.value, str))
    def walk(j):  # code-made identifiers in the results: every key, job key, arm name, kind, model pin; env / model blocks as a whole
        if isinstance(j, dict):
            s.update(str(k) for k in j)  # keys are never corpus text (PB2 run 39610197524: a manifest column name also occurs in the corpus)
            for k, v in j.items():
                if k in ("env", "model", "manifest") and isinstance(v, dict):
                    s.update(str(x) for x in v.values())
                    s.update(str(x) for x in v)
                elif k in ("job", "arm", "kind", "repo", "revision", "licence", "fp32_vs_int8") and isinstance(v, str):
                    s.add(v)
                else:
                    walk(v)
        elif isinstance(j, list):
            for v in j:
                walk(v)

    for f in out_files:
        if f.endswith(".json"):
            walk(json.loads(Path(f).read_text()))
    return {x for x in s if len(x) >= 2}


def corpus_texts(pack: dict) -> list[str]:
    ts = [q["query"] for q in pack["questions"]] + [q["qid"] for q in pack["questions"]] + list(pack["chunks"].values())
    ts += [m.get("title", "") for m in pack["memories"].values()]
    return [t for t in ts if t]


def guard_findings(texts: list[str], out_files: list[str], static: set[str], min_alpha: int = 6) -> list[tuple[str, int]]:
    """Windows of WINDOW characters in the outputs that occur in the corpus, ignoring windows made (almost) only of code-owned
    strings or digits: a window must hold at least `min_alpha` letters/CJK characters not covered by a static string."""
    pat = re.compile("|".join(re.escape(x) for x in sorted(static, key=len, reverse=True))) if static else None
    cand: dict[str, tuple[str, int]] = {}
    for f in out_files:
        s = Path(f).read_text(encoding="utf-8", errors="replace")
        cov = bytearray(len(s))
        for m in (pat.finditer(s) if pat else ()):
            cov[m.start():m.end()] = b"\x01" * (m.end() - m.start())
        free = [0]
        for ch, c in zip(s, cov):
            free.append(free[-1] + (1 if (ch.isalpha() and not c) else 0))
        for i in range(len(s) - WINDOW + 1):
            if free[i + WINDOW] - free[i] >= min_alpha:
                cand.setdefault(s[i:i + WINDOW], (f, i))
    hits = []
    for t in texts:
        for i in range(len(t) - WINDOW + 1):
            w = t[i:i + WINDOW]
            if w in cand:
                hits.append(cand[w])
    return hits


def guard(a):
    pack = load_pack(a.pack)
    static = static_strings(a.files, (a.static or []) + sys.argv[1:] + [x for arg in sys.argv[1:] for x in re.split(r"[,:]", arg)])
    hits = guard_findings(corpus_texts(pack), a.files, static)
    if hits:  # offsets only; never the text
        raise SystemExit(f"GUARD FAILED: {len(hits)} corpus window(s) in outputs, first at {hits[0][0]!r} offset {hits[0][1]}")
    print(f"guard ok: {len(a.files)} file(s) scanned against {len(corpus_texts(pack))} corpus texts")


def _fakevec(text: str) -> list[float]:
    import random
    rng = random.Random(hashlib.sha256(text.encode()).hexdigest())
    return [rng.random() - 0.5 for _ in range(DIM)]


def _fake_endpoint(mode: str):
    """Local stand-in for the embeddings endpoints: deterministic vectors per text (the text-embedding kind folds text_type and
    instruct into the vector), a 400 Arrearage answer, or a compat endpoint that rejects the extra field text_type."""
    import http.server
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            native = self.path.endswith("multimodal-embedding")
            text = self.path.endswith("text-embedding/text-embedding")
            texts = [c["text"] for c in body["input"]["contents"]] if native else (body["input"]["texts"] if text else body["input"])
            if native:
                assert body["parameters"] == {"dimension": DIM} and body["model"] == "qwen3-vl-embedding", body
            if mode == "arrears":
                out, code = {"code": "Arrearage", "message": "Access denied, account is in arrears"}, 400
            elif mode == "native_only" and not (native or text):
                out, code = {"error": {"code": "model_not_supported", "message": "Unsupported model for OpenAI compatibility mode."}}, 404
                out = {"code": "model_not_supported", "message": out["error"]["message"]}
            elif mode == "compat_strict" and not (native or text) and "text_type" in body:
                out, code = {"error": {"code": "invalid_parameter_error", "message": "Unknown field text_type"}}, 400
            elif mode == "no_instruct" and text and "instruct" in body["parameters"]:
                out, code = {"code": "InvalidParameter", "message": "instruct is not supported"}, 400
            elif native:
                out, code = {"output": {"embeddings": [{"index": i, "embedding": _fakevec(t), "type": "vl"} for i, t in enumerate(texts)]}}, 200
            elif text:
                pr = body["parameters"]
                assert pr["dimension"] == DIM and pr["output_type"] == "dense" and body["model"] == "text-embedding-v4", body
                out, code = {"output": {"embeddings": [{"text_index": i, "embedding": _fakevec(t + "|" + pr.get("text_type", "document") + "|" + pr.get("instruct", ""))}
                                                       for i, t in reversed(list(enumerate(texts)))]}}, 200  # reversed: the client must sort by text_index
            else:
                out, code = {"data": [{"index": i, "embedding": _fakevec(t)} for i, t in enumerate(texts)]}, 200
            raw = json.dumps(out).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *args):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    return srv, {"compat": base + "/compatible-mode/v1/embeddings", "native": base + "/api/v1/services/embeddings/multimodal-embedding/multimodal-embedding",
                 "text": base + "/api/v1/services/embeddings/text-embedding/text-embedding"}


def selftest(_a=None):
    # statistics
    assert abs(clopper_pearson(0, 198)[1] - (1 - 0.025 ** (1 / 198))) < 1e-6
    lo, hi = clopper_pearson(5, 10)
    assert abs(lo - 0.1871) < 1e-3 and abs(hi - 0.8129) < 1e-3, (lo, hi)
    assert mcnemar([1, 0, 1], [1, 0, 1])["p"] == 1.0
    assert mcnemar([0] * 6, [1] * 6)["p"] == 0.03125 and mcnemar([0] * 6, [1] * 6)["c"] == 6
    m = mcnemar([1] * 4 + [0] * 10, [0] * 4 + [1] * 10)
    assert (m["b"], m["c"], round(m["p"], 2)) == (4, 10, 0.18), m
    # J0 on a fake pack: q1 gold is rank 1, q2 gold is a superseded memory (dropped by the filter), q3 gold has no point (unreachable)
    fake_text = "zebra quartz mountain river"
    pack = {"manifest": {"date": "fake"}, "memories": {"m1": {"status": "active", "title": "t1"}, "m2": {"status": "superseded", "title": "t2"},
                                                        "m3": {"status": None, "title": "t3"}},
            "chunks": {"c1": fake_text, "c2": "other words here", "c3": "third chunk text"},
            "gold_info": {"m1": {"in_pg": True, "n_points": 1}, "m2": {"in_pg": True, "n_points": 1}, "m3": {"in_pg": True, "n_points": 0}},
            "questions": [{"qid": "q1", "type": "state", "query": "fake query one", "gold_memory_id": "m1", "cands": [["c1", "m1", .9], ["c2", "m3", .5]]},
                          {"qid": "q2", "type": "fact", "query": "fake query two", "gold_memory_id": "m2", "cands": [["c2", "m2", .9], ["c3", "m1", .4]]},
                          {"qid": "q3", "type": "fact", "query": "fake query three", "gold_memory_id": "m3", "cands": [[None, "m9", .8], ["c2", "m3", .7]]}]}
    r = j0(pack)
    s = r["stages"]["all"]
    assert (s["reachable"]["k"], s["in_top200_chunks"]["k"], s["after_status_filter"]["k"], s["top5_at_depth_25"]["k"]) == (2, 3, 2, 2), s
    c = r["counters"]
    assert (c["gold_missing_from_pg"], c["gold_without_chunk_or_point"], c["candidates_without_pg_chunk"], c["candidates_memory_absent_from_pg"]) == (0, 1, 1, 1), c
    assert r["conversion"]["all"]["k"] == 2 and r["pool25_vs_pool100"]["all"]["b"] == 0
    render_j0(r)
    # guard: a leak fails, clean output passes, a code-owned label that also occurs in the corpus passes only when exempted
    tmp = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / f"eret_selftest_{os.getpid()}"
    tmp.mkdir(parents=True, exist_ok=True)
    try:
        label = "bge-reranker-base arm"
        texts = corpus_texts(pack) + [f"notes on {label} scoring"]
        bad, good, cjk = tmp / "bad.md", tmp / "good.md", tmp / "cjk.md"
        bad.write_text("| x | 1 |\nleak: zebra quartz mountain river")
        good.write_text(f"| {label} | 0.5 | 12 | 3 |\nnumbers 0.123456789012 and 2026-10-21")
        cjk.write_text("泄漏的中文片段是这样的一段文字")
        assert guard_findings(texts, [str(bad)], {label}), "guard missed a leaked window"
        assert not guard_findings(texts, [str(good)], {label}), "guard flagged clean output"
        assert guard_findings(texts, [str(good)], set()), "without the exemption the label must be flagged"
        assert guard_findings(texts + ["前文泄漏的中文片段是这样的一段文字后文"], [str(cjk)], set())
        # stage 1 against a fake endpoint: success path (23 queries = 3 batches), identity failure, Arrearage stops with code 3
        os.environ["DASHSCOPE_API_KEY"] = "fake-key-for-selftest"
        qp = {"queries": [{"qid": f"q{i}", "query": f"fake query number {i}"} for i in range(23)],
              "sanity": [{"text": t, "vector": _fakevec(t)} for t in ("san one", "san two", "san three")]}
        (tmp / "qp.json").write_text(json.dumps(qp))
        ns = argparse.Namespace(qpack=str(tmp / "qp.json"), out=str(tmp / "qv.json"))
        srv, url = _fake_endpoint("ok")
        embed(ns, url)
        qv = json.loads((tmp / "qv.json").read_text())
        assert qv["model"] == CANDIDATES[0][0] and qv["calls"] == 4 and len(qv["vectors"]) == 23 and len(qv["vectors"]["q0"]) == DIM, qv["calls"]
        qp["sanity"][1]["vector"] = _fakevec("not the same text")
        (tmp / "qp.json").write_text(json.dumps(qp))
        try:
            embed(ns, url)
            raise AssertionError("identity failure not detected")
        except SystemExit as e:
            assert "identity check failed" in str(e.code), e.code
        srv.shutdown()
        srv, url = _fake_endpoint("native_only")  # compat mode refuses every model; the native endpoint serves qwen3-vl-embedding
        qp["sanity"] = [{"text": t, "vector": _fakevec(t)} for t in ("san one", "san two", "san three")]
        (tmp / "qp.json").write_text(json.dumps(qp))
        embed(ns, url)
        qv = json.loads((tmp / "qv.json").read_text())
        assert qv["model"] == "qwen3-vl-embedding" and qv["kind"] == "native" and qv["calls"] == 5 and len(qv["vectors"]) == 23, qv["calls"]
        srv.shutdown()
        srv, url = _fake_endpoint("arrears")
        try:
            embed(ns, url)
            raise AssertionError("Arrearage not detected")
        except SystemExit as e:
            assert e.code == 3, e.code
        srv.shutdown()
        # PB2 stage 1 against the fake endpoints: q1 / q2 differ from q0 and from each other, compat refusing text_type is recorded,
        # an endpoint that rejects `instruct` leaves q1 and no q2 (and the run ends red with code 4, artifact still written)
        import pb2
        qp["sanity"] = [{"text": t, "vector": _fakevec(t)} for t in ("san one", "san two", "san three")]
        (tmp / "qp.json").write_text(json.dumps(qp))
        ns2 = argparse.Namespace(qpack=str(tmp / "qp.json"), out=str(tmp / "qv2.json"))
        srv, url = _fake_endpoint("compat_strict")
        pb2.embed_variants(ns2, url)
        q2 = json.loads((tmp / "qv2.json").read_text())
        v, mt = q2["variants"], q2["meta"]
        assert sorted(v) == ["q0", "q1", "q2"] and all(len(x) == 23 for x in v.values()) and mt["calls"] == {"q0": 3, "compat_text_type_probe": 1, "q1": 3, "q2": 3}, mt
        assert mt["compat_text_type"] == {"http": 400, "code": "invalid_parameter_error"} and mt["cos_q0_q1"]["identical_ge_0.999999"] == 0
        assert v["q0"]["q0"] == _fakevec("fake query number 0") and v["q1"]["q0"] == _fakevec("fake query number 0|query|")
        assert v["q2"]["q5"] == _fakevec("fake query number 5|query|" + pb2.INSTRUCT)
        srv.shutdown()
        srv, url = _fake_endpoint("no_instruct")
        try:
            pb2.embed_variants(ns2, url)
            raise AssertionError("missing q2 not flagged")
        except SystemExit as e:
            assert e.code == 4, e.code
        q2 = json.loads((tmp / "qv2.json").read_text())
        assert sorted(q2["variants"]) == ["q0", "q1"] and q2["meta"]["status"]["q2"] == {"http": 400, "code": "InvalidParameter"}, q2["meta"]
        assert q2["meta"]["compat_text_type"]["http"] == 200 and len(q2["meta"]["compat_text_type"]["cos_vs_q0"]) == 2  # fake compat ignores text_type
        srv.shutdown()
        srv, url = _fake_endpoint("arrears")
        try:
            pb2.embed_variants(ns2, url)
            raise AssertionError("Arrearage not detected")
        except SystemExit as e:
            assert e.code == 3, e.code
        srv.shutdown()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    import pb2
    pb2.selftest()
    print("selftest ok")


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    f = sp.add_parser("fetch")
    f.add_argument("--asset", required=True)
    f.add_argument("--sha", required=True)
    f.add_argument("--out", required=True)
    f.add_argument("--keyfile")
    e = sp.add_parser("embed")
    e.add_argument("--qpack", required=True)
    e.add_argument("--out", required=True)
    j = sp.add_parser("j0")
    j.add_argument("--pack", required=True)
    j.add_argument("--out", required=True)
    j.add_argument("--summary", required=True)
    r = sp.add_parser("rerank")
    for k in ("pack", "out", "summary", "key", "repo", "rev", "arms"):
        r.add_argument("--" + k, required=True)
    ag = sp.add_parser("aggregate")
    for k in ("parts", "out", "summary"):
        ag.add_argument("--" + k, required=True)
    g = sp.add_parser("guard")
    g.add_argument("--pack", required=True)
    g.add_argument("--files", nargs="+", required=True)
    g.add_argument("--static", nargs="*")
    e2 = sp.add_parser("embed2")
    e2.add_argument("--qpack", required=True)
    e2.add_argument("--out", required=True)
    v2 = sp.add_parser("eval2")
    for k in ("corpus", "qvec", "out", "summary", "repo", "rev"):
        v2.add_argument("--" + k, required=True)
    v2.add_argument("--no-rerank", action="store_true")
    g2 = sp.add_parser("guard2")
    g2.add_argument("--corpus", required=True)
    g2.add_argument("--files", nargs="+", required=True)
    g2.add_argument("--static", nargs="*")
    sp.add_parser("selftest")
    a = ap.parse_args()
    try:
        if a.cmd == "fetch":
            fetch(a)
        elif a.cmd == "embed":
            embed(a)
        elif a.cmd == "j0":
            res = j0(load_pack(a.pack))
            Path(a.out).write_text(json.dumps(res, indent=1))
            Path(a.summary).write_text(render_j0(res))
        elif a.cmd == "rerank":
            rerank_job(a)
        elif a.cmd == "aggregate":
            aggregate(a)
        elif a.cmd == "guard":
            guard(a)
        elif a.cmd == "embed2":
            import pb2
            pb2.embed_variants(a)
        elif a.cmd == "eval2":
            import pb2
            pb2.eval2(a)
        elif a.cmd == "guard2":
            import pb2
            pb2.guard2(a)
        else:
            selftest()
    except SystemExit:
        raise
    except Exception as ex:  # class and source line only: messages and locals can carry corpus text (e.g. a KeyError on a qid)
        fr = traceback.extract_tb(ex.__traceback__)
        print(f"FAILED {type(ex).__name__} at " + " <- ".join(f"{Path(x.filename).name}:{x.lineno}:{x.name}" for x in reversed(fr[-4:])), flush=True)
        if isinstance(ex, (ImportError, subprocess.CalledProcessError)):
            print("detail:", str(ex)[:300], flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
