#!/usr/bin/env python3
"""E-RET-PB5: Qdrant v1.19.0 built-in `qdrant/bm25` (sparse vector with modifier idf, `params.idf.corpus`) and server-side RRF,
against PB2's bigram BM25 and client-side RRF, on the PB2 full-corpus snapshot, inside a CI-local Qdrant service container.

Imports (does not copy) the PB2 pieces: corpus loader, DenseIndex, bm25_items, rrf, fold_pairs, make_records (pb2.py) and the
statistics, J0 stages and leak guard (harness.py). Nothing here prints or writes corpus text: output is counts, rates, intervals,
b/c/p and latencies. Qdrant error messages are printed only after a 12-character-window check against the corpus.

Subcommands: selftest (pure, no network), smoke (fake corpus against the live Qdrant, picks the vector layout), run (real corpus),
guard (leak guard that also exempts this file's own literals).

Pre-registered before any result was seen (card E-RET-PB5):
  primary     hit@5 of Qdrant server-side RRF (`fusion: rrf`, default bm25 options, q0 dense vector) vs PB2's client RRF k=60
              (A = PB2, B = Qdrant), exact McNemar N/b/c/p. Everything else is secondary. No primary comparison is added afterwards.
  units       every list is folded to memories by first occurrence, then the status filter (active or NULL), exactly as PB2;
              pool@25 / hit@5 are positions in the filtered memory list.
  not equal   (facts, not interpretation) Qdrant's default `fusion: rrf` is 1 / (position + 2) with a 0-based position
              (DEFAULT_RRF_K = 2), i.e. 1 / (rank + 1) in 1-based ranks; PB2 uses 1 / (60 + rank). Qdrant fuses chunk lists of 100,
              PB2 fuses filtered memory lists. The arm `qdrant_rrf_k61` (`rrf: {k: 61}` = 1 / (60 + rank)) is an EXTRA secondary
              control for the constant; it is not in the card.
"""
from __future__ import annotations

import argparse
import ast
import http.client
import json
import os
import re
import statistics
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness as H  # noqa: E402
import pb2 as P  # noqa: E402

MODEL = "qdrant/bm25"
COLL = "eret_pb5"
TENANT = "t0"
TENANT_FILTER = {"must": [{"key": "tenant_id", "match": {"value": TENANT}}]}
ML_OPTIONS = {"tokenizer": "multilingual"}  # the one variant: the only option in the v1.19.0 schema that changes CJK segmentation
BATCH = 256
PREFETCH, FUSED_LIMIT = 100, 100
RRF_K_SAME = 61  # Qdrant: 1 / (pos + k), pos 0-based = 1 / (rank + k - 1); k = 61 equals PB2's 1 / (60 + rank)
# effective defaults when no options are sent (Bm25Config in lib/api/src/rest/schema.rs and bm25_inference.rs at v1.19.0)
BM25_DEFAULTS = {"k": 1.2, "b": 0.75, "avg_len": 256, "tokenizer": "word", "language": "english", "lowercase": True, "ascii_folding": False,
                 "stopwords": "english list", "stemmer": "snowball english", "min_token_len": None, "max_token_len": None}
# name, kind, sparse vector name, multilingual options, fusion (priority order: the time budget drops the tail)
ARMS = [("qdrant_bm25", "sparse", "bm25", False, None),
        ("qdrant_rrf", "hybrid", "bm25", False, {"fusion": "rrf"}),
        ("qdrant_dense", "dense", None, False, None),
        ("qdrant_bm25_ml", "sparse", "bm25_ml", True, None),
        ("qdrant_rrf_ml", "hybrid", "bm25_ml", True, {"fusion": "rrf"}),
        ("qdrant_rrf_k61", "hybrid", "bm25", False, {"rrf": {"k": RRF_K_SAME}}),
        ("qdrant_rrf_k61_ml", "hybrid", "bm25_ml", True, {"rrf": {"k": RRF_K_SAME}})]
PB2_REF = {"dense_pool25": 127, "dense_hit5": 64, "rrf60_pool25": 140, "rrf60_hit5": 100}  # PB2 run 39614883398 (q0 dense), not a gate
_SCRUB = {"texts": None}  # corpus texts once the real corpus is loaded; None while only fake data exists


# ---------------------------------------------------------------- REST client
def _scrub(msg: str) -> str:
    msg = msg[:200]
    texts = _SCRUB["texts"]
    if texts is None:
        return msg
    wins = {msg[i:i + H.WINDOW] for i in range(len(msg) - H.WINDOW + 1)}
    return "[redacted]" if wins and any(t[i:i + H.WINDOW] in wins for t in texts for i in range(len(t) - H.WINDOW + 1)) else msg


class QdrantHttp(Exception):
    def __init__(self, http: int, msg: str):
        super().__init__(f"http={http}")
        self.http, self.msg = http, msg


class Qd:
    def __init__(self, base: str):
        self.base = base.rstrip("/")

    def call(self, method: str, path: str, body=None, timeout: int = 900):
        data = None if body is None else json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "replace")
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            try:
                msg = str((json.loads(raw).get("status") or {}).get("error") or "")
            except (ValueError, AttributeError):
                msg = ""
            raise QdrantHttp(e.code, _scrub(msg)) from None


def wait_ready(qd: Qd, timeout: int = 180) -> dict:
    t0 = time.monotonic()
    while True:
        try:
            return qd.call("GET", "/", timeout=5)
        except (OSError, http.client.HTTPException, QdrantHttp, ValueError):
            if time.monotonic() - t0 > timeout:
                raise SystemExit("qdrant not ready")
            time.sleep(2)


# ---------------------------------------------------------------- collection, points
def build_collection(qd: Qd, dim: int, dn: str, ml: bool):
    """Dense vector `dn` ("" = the unnamed default vector) size dim Cosine; sparse `bm25` (+ `bm25_ml`) with modifier idf; keyword index on tenant_id."""
    try:
        qd.call("DELETE", f"/collections/{COLL}")
    except QdrantHttp as e:
        if e.http != 404:
            raise
    dense = {"size": dim, "distance": "Cosine"}
    sparse = {"bm25": {"modifier": "idf"}, **({"bm25_ml": {"modifier": "idf"}} if ml else {})}
    qd.call("PUT", f"/collections/{COLL}", {"vectors": dense if dn == "" else {dn: dense}, "sparse_vectors": sparse})
    qd.call("PUT", f"/collections/{COLL}/index?wait=true", {"field_name": "tenant_id", "field_schema": {"type": "keyword", "is_tenant": True}})


def point_plan(c) -> list[tuple]:
    """(point id, vector row | None, chunk index | None, memory id). Every vector row is a point (dense + its chunk text, if it has one);
    every PG chunk that no row points at becomes a text-only point, so the BM25 corpus is every chunk (as in PB2) and the dense corpus is every row."""
    plan = [(r, r, c.row_chunk[r], c.row_mem[r]) for r in range(len(c.points))]
    attached = {k for k in c.row_chunk if k is not None}
    orphans = [k for k in range(len(c.chunks)) if k not in attached]
    return plan + [(len(c.points) + j, None, k, c.chunks[k][1]) for j, k in enumerate(orphans)]


def bm25_doc(text: str, ml: bool) -> dict:
    d = {"text": text, "model": MODEL}  # default options: what adapters::public_projection sends
    if ml:
        d["options"] = ML_OPTIONS
    return d


def upsert(qd: Qd, c, plan, dn: str, ml: bool, V) -> dict:
    t0, n_text = time.perf_counter(), 0
    for s in range(0, len(plan), BATCH):
        pts = []
        for pid, row, k, mem in plan[s:s + BATCH]:
            vec = {} if row is None else {dn: V[row].tolist()}
            txt = c.chunks[k][4] if k is not None else None
            if txt and txt.strip():
                vec["bm25"] = bm25_doc(txt, False)
                if ml:
                    vec["bm25_ml"] = bm25_doc(txt, True)
                n_text += 1
            pts.append({"id": pid, "vector": vec, "payload": {"memory_id": mem, "tenant_id": TENANT}})
        r = qd.call("PUT", f"/collections/{COLL}/points?wait=true", {"points": pts})
        assert r["result"]["status"] == "completed", r["result"]
        if (s // BATCH) % 40 == 0:
            H.log("upsert", f"{min(s + BATCH, len(plan))}/{len(plan)}", f"{time.perf_counter() - t0:.0f}s")
    return {"points": len(plan), "text_points": n_text, "batches": -(-len(plan) // BATCH), "batch_size": BATCH, "upsert_s": round(time.perf_counter() - t0, 1)}


def wait_green(qd: Qd, timeout: int = 1800) -> tuple[dict, float]:
    t0 = time.monotonic()
    while True:
        r = qd.call("GET", f"/collections/{COLL}")["result"]
        if (r.get("status") == "green" and r.get("optimizer_status") == "ok") or time.monotonic() - t0 > timeout:
            return r, time.monotonic() - t0
        time.sleep(2)


# ---------------------------------------------------------------- queries
def q_body(kind: str, qvec, text: str, dn: str, using, ml: bool, fusion) -> dict:
    dense = {"query": qvec, "filter": TENANT_FILTER, **({"using": dn} if dn else {})}
    sparse = {"query": bm25_doc(text, ml), "using": using, "filter": TENANT_FILTER, "params": {"idf": {"corpus": TENANT_FILTER}}}
    if kind == "hybrid":
        return {"prefetch": [{**dense, "limit": PREFETCH}, {**sparse, "limit": PREFETCH}], "query": fusion, "limit": FUSED_LIMIT,
                "with_payload": False, "with_vector": False}
    return {**(dense if kind == "dense" else sparse), "limit": P.LEG_DEPTH, "with_payload": False, "with_vector": False}


def run_arm(qd: Qd, c, q0, arm, dn: str, deadline: float):
    """Returns (per-question [(point id, score)], per-question seconds, HTTP 400 count) or None when the time budget ran out."""
    name, kind, using, ml, fusion = arm
    runs, lat, errors = [], [], 0
    for i, q in enumerate(c.questions):
        if time.monotonic() > deadline:
            return None
        body = q_body(kind, q0[q["qid"]], q["query"], dn, using, ml, fusion)
        try:
            if i == 0:
                qd.call("POST", f"/collections/{COLL}/points/query", body)  # warm-up, untimed
            t = time.perf_counter()
            r = qd.call("POST", f"/collections/{COLL}/points/query", body)
            lat.append(time.perf_counter() - t)
            runs.append([(p["id"], p["score"]) for p in r["result"]["points"]])
        except QdrantHttp as e:
            if kind == "dense" or e.http != 400:
                raise
            errors += 1  # e.g. a query that tokenizes to nothing; counted and reported, never silent
            runs.append([])
    assert errors <= max(2, len(c.questions) // 20), f"too many HTTP 400 answers in arm {name}"
    return runs, lat, errors


def to_items(c, pid_mem, runs):
    items = []
    for pts in runs:
        seq, kept = P.fold_pairs([(pid_mem[i], s) for i, s in pts], c.mem)
        items.append((seq, kept, {"cands": len(pts), "cands_without_chunk": 0, "cands_memory_absent": sum(1 for i, _ in pts if pid_mem[i] not in c.mem)}))
    return items


def pb2_lists(c, q0):
    """PB2's three lists for q0, built with PB2's own functions in the same composition as pb2.evaluate (dense_items, bm25_items, rrf, make_records)."""
    idx = P.DenseIndex(c.vec_bytes, c.dim)
    d = P.dense_items(c, idx, idx.scores([q0[q["qid"]] for q in c.questions]))
    del idx
    b, info = P.bm25_items(c)
    zero = {"cands": 0, "cands_without_chunk": 0, "cands_memory_absent": 0}
    fused = [P.rrf([x[1], y[1]], 60) for x, y in zip(d, b)]
    f = [(list(dict.fromkeys(x[0] + y[0])), z, zero) for x, y, z in zip(d, b, fused)]
    mk = lambda items: P.make_records(c.questions, c.gold_info, items)  # noqa: E731
    return {"pb2_dense_q0": mk(d), "pb2_bm25": mk(b), "pb2_rrf_k60": mk(f)}, info


# ---------------------------------------------------------------- aggregates
def arm_summary(c, an, lat=None, errors=0) -> dict:
    st = H.j0({"questions": c.questions, "gold_info": c.gold_info, "manifest": c.man}, an)["stages"]
    out = {s: {"n": st[s]["questions"], "pool25": st[s]["pool_25"], "hit5": st[s]["top5_at_depth_25"]} for s in ("all",) + H.TYPES}
    out["lt25_kept"] = sum(1 for r in an if r["n_kept"] < 25)
    out["mean_kept"] = round(sum(r["n_kept"] for r in an) / len(an), 2)
    out["query_errors_400"] = errors
    out["latency_ms"] = None if not lat else {"n": len(lat), "p50": round(1e3 * H.pct(lat, .5), 1), "p95": round(1e3 * H.pct(lat, .95), 1), "mean": round(1e3 * sum(lat) / len(lat), 1)}
    return out


def compare(an, a: str, b: str) -> dict:
    ha, hb, pa, pb = P.hits5(an[a]), P.hits5(an[b]), P.in_pool(an[a], 25), P.in_pool(an[b], 25)
    return {"A": a, "B": b, "pool25": {**H.mcnemar(pa, pb), "A_k": sum(pa), "B_k": sum(pb)}, "hit5": {**H.mcnemar(ha, hb), "A_k": sum(ha), "B_k": sum(hb)}}


def union_oracle(an, dense: str, other: str) -> dict:
    d, o = P.in_pool(an[dense], 25), P.in_pool(an[other], 25)
    both = sum(1 for x, y in zip(d, o) if x and y)
    return {"dense_pool25": sum(d), "list_pool25": sum(o), "union_pool25": H.rate(sum(1 for x, y in zip(d, o) if x or y), len(d)),
            "found_by_both": both, "dense_only": sum(d) - both, "list_only": sum(o) - both}


def tokenization_probe(qd: Qd, c, plan, ml: bool) -> dict:
    """Distinct terms per chunk for the first 1000 points: Qdrant's stored sparse vectors vs PB2's bigram tokens (counts only)."""
    names = ["bm25"] + (["bm25_ml"] if ml else [])
    pts = qd.call("POST", f"/collections/{COLL}/points/scroll", {"limit": 1000, "with_payload": False, "with_vector": names, "filter": TENANT_FILTER})["result"]["points"]
    stat = lambda xs: {"n": len(xs), "mean": round(sum(xs) / len(xs), 2) if xs else None, "median": statistics.median(xs) if xs else None, "empty": sum(1 for x in xs if x == 0)}  # noqa: E731
    out = {"sample": len(pts)}
    for nm in names:
        out["qdrant_" + nm] = stat([len(p["vector"][nm]["indices"]) for p in pts if (p.get("vector") or {}).get(nm)])
    out["pb2_bigram"] = stat([len(set(P.tokens(c.chunks[plan[p["id"]][2]][4]))) for p in pts if plan[p["id"]][2] is not None and c.chunks[plan[p["id"]][2]][4].strip()])
    return out


def pipeline(qd: Qd, c, q0, dn: str, ml: bool, budget_min: float, raw_out: str | None = None):
    import numpy as np
    qids = [q["qid"] for q in c.questions]
    assert all(q in q0 for q in qids), "query vectors do not cover every question"
    res = {"manifest": {k: v for k, v in c.man.items() if isinstance(v, (int, float, str))}, "arms": {}, "secondary": {}, "extra_secondary": {}, "union_oracle": {}}
    an, bm_info = pb2_lists(c, q0)
    plan = point_plan(c)
    V = np.frombuffer(c.vec_bytes, dtype="<f2").reshape(-1, c.dim)
    t0 = time.perf_counter()
    build_collection(qd, c.dim, dn, ml)
    up = upsert(qd, c, plan, dn, ml, V)
    info, green_s = wait_green(qd)
    res["indexing"] = {**up, "green_after_upsert_s": round(green_s, 1), "total_s": round(time.perf_counter() - t0, 1), "final_status": info.get("status"),
                       "points_count": info.get("points_count"), "indexed_vectors_count": info.get("indexed_vectors_count"), "segments_count": info.get("segments_count")}
    res["qdrant"] = {"image_tag": "v1.19.0", "dense_vector_name": "unnamed default" if dn == "" else dn, "collection_chunks": len(c.chunks), "collection_rows": len(c.points),
                     "orphan_chunk_points": len(plan) - len(c.points), "bm25_sent_options": None, "bm25_effective_defaults": BM25_DEFAULTS,
                     "bm25_ml_sent_options": ML_OPTIONS if ml else "not built", "idf_corpus_filter": "tenant_id = one value (all points)",
                     "retrieval_filter": "tenant_id = one value", "dense_ann": "default HNSW, no exact flag"}
    res["tokenization_probe"] = tokenization_probe(qd, c, plan, ml)
    pid_mem = [p[3] for p in plan]
    deadline, lat, errs, raw = time.monotonic() + 60 * budget_min, {}, {}, {}
    for arm in ARMS:
        if arm[3] and not ml:
            continue
        out = run_arm(qd, c, q0, arm, dn, deadline)
        if out is None:
            res["arms"][arm[0]] = {"skipped": "time budget"}
            continue
        runs, lat[arm[0]], errs[arm[0]] = out
        raw[arm[0]] = runs
        an[arm[0]] = P.make_records(c.questions, c.gold_info, to_items(c, pid_mem, runs))
        H.log("arm done", arm[0], "hit5", sum(P.hits5(an[arm[0]])), "pool25", sum(P.in_pool(an[arm[0]], 25)), "p50 ms", round(1e3 * H.pct(lat[arm[0]], .5), 1))
    if raw_out:
        Path(raw_out).write_text(json.dumps(raw))  # point ids and scores only; sealed before upload
    for name in an:
        res["arms"][name] = arm_summary(c, an[name], lat.get(name), errs.get(name, 0))
    res["pb2"] = {"bm25_index": bm_info, "reference_run_39614883398_now_vs_ref": {k: [v, PB2_REF[k]] for k, v in {
        "dense_pool25": sum(P.in_pool(an["pb2_dense_q0"], 25)), "dense_hit5": sum(P.hits5(an["pb2_dense_q0"])),
        "rrf60_pool25": sum(P.in_pool(an["pb2_rrf_k60"], 25)), "rrf60_hit5": sum(P.hits5(an["pb2_rrf_k60"]))}.items()}}
    if "qdrant_rrf" in an:
        res["primary"] = {"hit5_qdrant_server_rrf_vs_pb2_client_rrf_k60": compare(an, "pb2_rrf_k60", "qdrant_rrf")["hit5"] | {"A": "pb2_rrf_k60", "B": "qdrant_rrf"}}
    else:
        res["primary"] = {"not_applicable": "arm qdrant_rrf missing"}
    pairs = [("pb2_bm25", "qdrant_bm25"), ("qdrant_bm25", "qdrant_bm25_ml"), ("pb2_dense_q0", "qdrant_rrf")]
    extra = [("pb2_rrf_k60", "qdrant_rrf_k61"), ("pb2_rrf_k60", "qdrant_rrf_ml"), ("pb2_rrf_k60", "qdrant_rrf_k61_ml"), ("pb2_bm25", "qdrant_bm25_ml"),
             ("pb2_dense_q0", "qdrant_dense"), ("pb2_dense_q0", "pb2_rrf_k60")]
    for dest, lst in ((res["secondary"], pairs), (res["extra_secondary"], extra)):
        for a, b in lst:
            if a in an and b in an:
                dest[f"{b}_vs_{a}"] = compare(an, a, b)
    for name in ("pb2_bm25", "qdrant_bm25", "qdrant_bm25_ml"):
        if name in an:
            res["union_oracle"][name] = union_oracle(an, "pb2_dense_q0", name)
    return res, an


# ---------------------------------------------------------------- rendering
def render(res: dict) -> str:
    mc = lambda x: f"{x['N']}/{x['b']}/{x['c']}/{x['p']}"  # noqa: E731
    q, ix = res["qdrant"], res["indexing"]
    L = ["## E-RET-PB5 (Qdrant v1.19.0 qdrant/bm25 + server-side RRF vs PB2 bigram BM25 + client-side RRF)", "",
         "Counts, rate and Clopper-Pearson 95% interval; McNemar exact two-sided (A = baseline, B = challenger, b = A hit and B miss, c = A miss and B hit).", "",
         "Corpus: " + ", ".join(f"{k}={v}" for k, v in res["manifest"].items() if k in ("rows", "chunks", "memories", "questions")) + ".", ""]
    p = res["primary"]
    L += ["### Pre-registered primary comparison (exactly one)", "", "| comparison | A | B | N | b | c | p |", "|---|---|---|---|---|---|---|"]
    if "not_applicable" in p:
        L.append(f"| hit@5 | {p['not_applicable']} | | | | | |")
    else:
        x = p["hit5_qdrant_server_rrf_vs_pb2_client_rrf_k60"]
        L.append(f"| hit@5 | {x['A']} = {x['A_k']} | {x['B']} = {x['B_k']} | {x['N']} | {x['b']} | {x['c']} | {x['p']} |")
    L += ["", "### Lists (pool@25 and hit@5 over the filtered memory list; < 25 = questions whose list holds fewer than 25 memories)", "",
          "| list | pool@25 | hit@5 | state hit@5 | fact hit@5 | < 25 | p50 ms | p95 ms | HTTP 400 |", "|---|---|---|---|---|---|---|---|---|"]
    for name, a in res["arms"].items():
        if "skipped" in a:
            L.append(f"| {name} | skipped: {a['skipped']} | | | | | | | |")
            continue
        lt = a["latency_ms"] or {"p50": "", "p95": ""}
        L.append(f"| {name} | {H.fmt_rate(a['all']['pool25'])} | {H.fmt_rate(a['all']['hit5'])} | {H.fmt_rate(a['state']['hit5'])} | {H.fmt_rate(a['fact']['hit5'])} | "
                 f"{a['lt25_kept']} | {lt['p50']} | {lt['p95']} | {a['query_errors_400']} |")
    for title, sec in (("Secondary comparisons", res["secondary"]), ("Extra secondary comparisons (not in the card)", res["extra_secondary"])):
        L += ["", f"### {title} (N/b/c/p)", "", "| B vs A | pool@25 A | pool@25 B | pool@25 N/b/c/p | hit@5 A | hit@5 B | hit@5 N/b/c/p |", "|---|---|---|---|---|---|---|"]
        for k, x in sec.items():
            L.append(f"| {x['B']} vs {x['A']} | {x['pool25']['A_k']} | {x['pool25']['B_k']} | {mc(x['pool25'])} | {x['hit5']['A_k']} | {x['hit5']['B_k']} | {mc(x['hit5'])} |")
    L += ["", "### Union oracle (gold in the top 25 of the exact q0 dense list or of the BM25 list)", "", "| BM25 list | dense | list | union | both | dense only | list only |", "|---|---|---|---|---|---|---|"]
    for name, u in res["union_oracle"].items():
        L.append(f"| {name} | {u['dense_pool25']} | {u['list_pool25']} | {H.fmt_rate(u['union_pool25'])} | {u['found_by_both']} | {u['dense_only']} | {u['list_only']} |")
    L += ["", f"Indexing: {json.dumps(ix, sort_keys=True)}", "", f"Qdrant setup: {json.dumps(q, sort_keys=True)}", "",
          f"Distinct terms per chunk, first 1000 points: {json.dumps(res['tokenization_probe'], sort_keys=True)}", "",
          f"PB2 recomputed (now / run 39614883398): {json.dumps(res['pb2']['reference_run_39614883398_now_vs_ref'], sort_keys=True)}; PB2 BM25 index {json.dumps(res['pb2']['bm25_index'], sort_keys=True)}", ""]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- guard
def guard_check(texts: list[str], files: list[str], extra: list[str]) -> list:
    """harness.guard_findings with this file's own string literals exempt too (labels such as arm names may occur in the corpus)."""
    static = H.static_strings(files, extra)
    static |= {n.value for n in ast.walk(ast.parse(Path(__file__).read_text())) if isinstance(n, ast.Constant) and isinstance(n.value, str) and len(n.value) >= 2}
    return H.guard_findings(texts, files, static)


def guard(a):
    c = P.load_corpus(a.corpus)
    hits = guard_check(P.corpus_texts(c), a.files, sys.argv[1:] + [x for arg in sys.argv[1:] for x in re.split(r"[,:]", arg)])
    if hits:  # offsets only; never the text
        raise SystemExit(f"GUARD FAILED: {len(hits)} corpus window(s) in outputs, first at {hits[0][0]!r} offset {hits[0][1]}")
    print(f"guard ok: {len(a.files)} file(s) scanned against {len(P.corpus_texts(c))} corpus texts")


# ---------------------------------------------------------------- stages
def fake_q0() -> dict:
    return {"q1": [1, 0, 0, 0], "q2": [0, 1, 0, 0], "q3": [1, 0, 0, 0], "q4": [0, 0, 0, 1]}


def smoke(a):
    """Fake corpus against the live Qdrant: picks the vector layout that works (unnamed default dense vector first, then a named one;
    multilingual variant first, then without) and checks the whole pipeline on the toy data. Writes the choice for `run`."""
    qd = Qd(a.url)
    info = wait_ready(qd)
    print("qdrant version:", info.get("version"))
    assert str(info.get("version", "")).startswith("1.19"), info
    tmp = Path(tempfile.mkdtemp(prefix="pb5smoke_", dir=os.environ.get("RUNNER_TEMP")))
    try:
        P.fake_corpus_tar(str(tmp / "c.tar"))
        c, q0, tried, chosen = P.load_corpus(str(tmp / "c.tar")), fake_q0(), [], None
        for dn in ("", "dense"):
            for ml in (True, False):
                try:
                    res, an = pipeline(qd, c, q0, dn, ml, 5)
                    chosen = (dn, ml, res, an)
                    break
                except QdrantHttp as e:
                    tried.append({"dense_name": dn or "unnamed", "ml": ml, "http": e.http, "msg": e.msg})
                    print("layout failed:", json.dumps(tried[-1]), flush=True)
            if chosen:
                break
        assert chosen, "no vector layout works"
        dn, ml, res, an = chosen
        ranks = {n: [r["rank"] for r in x] for n, x in an.items()}
        assert res["indexing"]["points"] == 6 and res["indexing"]["text_points"] == 5 and res["indexing"]["points_count"] == 6, res["indexing"]
        assert ranks["qdrant_bm25"][1] == 1, ranks["qdrant_bm25"]  # "... postgresql": an ASCII token the word tokenizer keeps
        assert ranks["qdrant_rrf"][1] == 1 and ranks["qdrant_rrf_k61"][1] == 1, ranks  # dense and sparse both put the gold of q2 first
        assert ranks["qdrant_dense"][0] == 1 and ranks["pb2_dense_q0"][0] == 1, ranks  # q1: m1 first, the superseded m3 is filtered out
        assert res["tokenization_probe"]["sample"] == 6 and res["primary"]["hit5_qdrant_server_rrf_vs_pb2_client_rrf_k60"]["N"] == 4, res
        render(res)
        Path(a.out).write_text(json.dumps({"dense_name": dn, "ml": ml, "tried": tried}))
        print("smoke ok: dense vector", "unnamed default" if dn == "" else dn, "| multilingual variant", ml, "| failed layouts", len(tried), flush=True)
        print("smoke ranks:", json.dumps(ranks), flush=True)  # fake data only
    finally:
        try:
            qd.call("DELETE", f"/collections/{COLL}")
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


def run(a):
    cfg = json.loads(Path(a.smoke).read_text())
    c = P.load_corpus(a.corpus)
    _SCRUB["texts"] = P.corpus_texts(c)
    qv = json.loads(Path(a.qvec).read_text())
    qd = Qd(a.url)
    info = wait_ready(qd)
    res, _ = pipeline(qd, c, qv["variants"]["q0"], cfg["dense_name"], cfg["ml"], a.budget_min, a.raw)
    res["qdrant"]["server_version"] = info.get("version")
    res["qdrant"]["smoke_failed_layouts"] = [{k: v for k, v in t.items() if k != "msg"} for t in cfg["tried"]]
    Path(a.out).write_text(json.dumps(res, indent=1))
    Path(a.summary).write_text(render(res))
    print("run done; arms:", ", ".join(res["arms"]))


# ---------------------------------------------------------------- selftest (pure)
def selftest(_a=None):
    import random
    import shutil
    # request bodies
    h = q_body("hybrid", [1.0], "q", "", "bm25", False, {"fusion": "rrf"})
    assert h["query"] == {"fusion": "rrf"} and h["limit"] == 100 and [p["limit"] for p in h["prefetch"]] == [100, 100] and "using" not in h["prefetch"][0]
    assert h["prefetch"][1]["using"] == "bm25" and h["prefetch"][1]["params"] == {"idf": {"corpus": TENANT_FILTER}} and h["prefetch"][1]["query"] == {"text": "q", "model": MODEL}
    s = q_body("sparse", [1.0], "q", "d", "bm25_ml", True, None)
    assert s["limit"] == 200 and s["using"] == "bm25_ml" and s["query"]["options"] == ML_OPTIONS and s["params"]["idf"]["corpus"] == TENANT_FILTER and "prefetch" not in s
    d = q_body("dense", [1.0], "q", "d", None, False, None)
    assert d["using"] == "d" and d["limit"] == 200 and "params" not in d and "using" not in q_body("dense", [1.0], "q", "", None, False, None)
    assert bm25_doc("t", False) == {"text": "t", "model": MODEL} and RRF_K_SAME == 61 and ARMS[1][4] == {"fusion": "rrf"}
    # corpus, point plan (an unattached chunk becomes a text-only point), fold
    tmp = Path(tempfile.mkdtemp(prefix="pb5self_", dir=os.environ.get("RUNNER_TEMP")))
    try:
        P.fake_corpus_tar(str(tmp / "c.tar"))
        c = P.load_corpus(str(tmp / "c.tar"))
        plan = point_plan(c)
        assert len(plan) == 6 and [p[1] for p in plan] == [0, 1, 2, 3, 4, 5] and plan[5][2] is None and plan[5][3] == "m5"
        c.chunks.append(["c9", "m2", 1, "p9", "orphan text"])
        plan = point_plan(c)
        assert len(plan) == 7 and plan[6] == (6, None, 5, "m2"), plan[6]
        items = to_items(c, [p[3] for p in plan], [[(2, .9), (1, .8), (0, .7), (5, .6), (6, .5)], []])
        assert items[0][0] == ["m3", "m2", "m1", "m5"] and items[0][1] == ["m2", "m1"] and items[0][2]["cands_memory_absent"] == 1 and items[1][1] == [], items
        an = P.make_records(c.questions[:2], c.gold_info, items)
        assert an[0]["rank"] == 2 and an[1]["rank"] is None, an[0]["rank"]
        sm = arm_summary(type("C", (), {"questions": c.questions[:2], "gold_info": c.gold_info, "man": c.man})(), an, [.01, .02, .03], 1)
        assert sm["all"]["n"] == 2 and sm["lt25_kept"] == 2 and sm["latency_ms"]["n"] == 3 and sm["latency_ms"]["p50"] == 20.0 and sm["query_errors_400"] == 1, sm
        # scrub: a window of corpus text is redacted, an unrelated message is not
        _SCRUB["texts"] = ["x" * 5 + "abcdefghijklmnopq" + "y" * 5]
        assert _scrub("error about abcdefghijklmnop here") == "[redacted]" and _scrub("Wrong input: vector dimension error") != "[redacted]"
        _SCRUB["texts"] = None
        # guard: a leaked window fails, clean output passes, an arm name that also occurs in the corpus is exempt (this file's literals)
        rnd = "".join(random.Random(7).choice("abcdefghijklmnopqrstuvwxyz") for _ in range(40))
        label = "qdrant_rrf_k61_ml"
        texts = [rnd, f"notes about {label} scoring"]
        bad, good = tmp / "bad.md", tmp / "good.md"
        bad.write_text("| x | 1 |\nleak: " + rnd[5:35])
        good.write_text(f"| {label} | 12/198 = 0.061 | 0.123456789012 |")
        assert guard_check(texts, [str(bad)], []), "guard missed a leaked window"
        assert not guard_check(texts, [str(good)], []), "guard flagged clean output or an exempt label"
        assert H.guard_findings(texts, [str(good)], set()), "without the exemption the label must be flagged"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("selftest qdrant_sparse ok")


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    sp.add_parser("selftest")
    s = sp.add_parser("smoke")
    s.add_argument("--out", required=True)
    s.add_argument("--url", default=os.environ.get("QDRANT_URL", "http://127.0.0.1:6333"))
    r = sp.add_parser("run")
    for k in ("corpus", "qvec", "smoke", "out", "summary", "raw"):
        r.add_argument("--" + k, required=True)
    r.add_argument("--url", default=os.environ.get("QDRANT_URL", "http://127.0.0.1:6333"))
    r.add_argument("--budget-min", dest="budget_min", type=float, default=70.0)
    g = sp.add_parser("guard")
    g.add_argument("--corpus", required=True)
    g.add_argument("--files", nargs="+", required=True)
    a = ap.parse_args()
    try:
        {"selftest": selftest, "smoke": smoke, "run": run, "guard": guard}[a.cmd](a)
    except SystemExit:
        raise
    except QdrantHttp as ex:
        print(f"FAILED QdrantHttp http={ex.http} message={ex.msg!r}", flush=True)
        sys.exit(1)
    except Exception as ex:  # class and source line only: messages and locals can carry corpus text
        fr = traceback.extract_tb(ex.__traceback__)
        print(f"FAILED {type(ex).__name__} at " + " <- ".join(f"{Path(x.filename).name}:{x.lineno}:{x.name}" for x in reversed(fr[-4:])), flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
