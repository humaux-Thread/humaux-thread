#!/usr/bin/env python3
"""E-RET-PB2: full-corpus encrypted snapshot. Query role (E-RET-2), BM25 + RRF (E-RET-3) and one rerank arm, on public CI.

Stdlib only, except the dense leg (numpy, imported inside DenseIndex) and the rerank arm (rerank.py, torch). Imported by harness.py,
which owns the CLI, the statistics (rate, Clopper-Pearson, exact McNemar) and the leak guard. Nothing here prints or writes corpus
text: output is counts, rates, intervals, b/c/p and latencies.

Corpus tar (corpus.v1, built locally from a read-only snapshot, shipped as ciphertext): manifest.json, questions.json,
memories.jsonl [id, status, layer, title], chunks.jsonl [chunk_id, memory_id, chunk_index, point_id, text],
points.jsonl [point_id, payload_memory_id, chunk_index, chunk_id|null] (row order = vector row order), vectors.f16 (row-major
little-endian IEEE half, manifest.dim columns). JSON lines are split on "\\n" only: corpus text may hold U+2028 and friends.

Pre-registered before any result was seen (card E-RET-PB2, design_v0.2 19.4):
  legs        every leg is a top-200 CHUNK list, folded to memories by max score, then the status filter (active or NULL); a memory
              absent from the memories table is dropped. Ranks used by RRF are positions in the filtered memory list.
  primary 1   q1 vs q0 on dense hit@5 (A = q0, B = q1; exact McNemar). q1 "wins" iff c > b and p < 0.05, else q0 is the dense variant
              carried forward ("W").
  primary 2   best RRF k vs W on pool@25 (A = W, B = RRF). "Best k" = highest pool@25, ties -> higher hit@5, then larger k.
  secondary   everything else (q2, BM25 alone, other k, hit@5 of RRF, rerank arms). No primary comparison is added after the results.
"""
from __future__ import annotations

import json
import math
import os
import re
import struct
import sys
import tarfile
import time
from collections import Counter, defaultdict
from pathlib import Path

import harness as H

VARIANTS = ("q0", "q1", "q2")
MODEL = "text-embedding-v4"
NATIVE_URL = "https://dashscope.aliyuncs.com/api/v1/services/embeddings/text-embedding/text-embedding"
# The one instruction used for q2 (English is what the API reference recommends); documented in the reference as parameter `instruct`.
INSTRUCT = "Given a question, retrieve the memory that answers it"
RRF_KS = (10, 30, 60)
K1, B = 1.2, 0.75  # textbook BM25 defaults, NOT tuned
LEG_DEPTH = 200
# PB1 reference numbers (run 39593059326, exp/e-ret-pb-harness@8a2b7a3; 198 questions) for the q0 self-check
PB1 = {"dense_hit5": 63, "pool_25": 123, "pool_100": 153, "pool_200": 159, "reachable": 171, "in_top200_chunks": 161,
       "after_status_filter": 159, "rerank_int8_L512_d25_hit5": 101}


# ---------------------------------------------------------------- tokens and BM25 (stdlib)
_CJK = re.compile(r"[㐀-䶿一-鿿]+")
_ASCII = re.compile(r"[A-Za-z0-9_]+")


def tokens(text: str) -> list[str]:
    """Lower-cased ASCII/identifier tokens plus overlapping Chinese character bigrams (a lone CJK character is its own token)."""
    out = [m.lower() for m in _ASCII.findall(text)]
    for run in _CJK.findall(text):
        out += [run] if len(run) == 1 else map("".join, zip(run, run[1:]))
    return out


class BM25:
    """Okapi BM25 over documents, idf = ln(1 + (N - df + 0.5) / (df + 0.5)), unique query terms. Only the postings of the given
    query terms are kept (N, df and the average length still come from every document), so the scores are exact."""

    def __init__(self, docs: list[str], qterms: set[str], k1: float = K1, b: float = B):
        self.n, self.k1 = len(docs), k1
        self.post: dict[str, tuple[list[int], list[int]]] = {t: ([], []) for t in qterms}
        dl = [0] * self.n
        for i, text in enumerate(docs):
            toks = tokens(text)
            dl[i] = len(toks)
            for t, c in Counter(toks).items():
                p = self.post.get(t)
                if p is not None:
                    p[0].append(i)
                    p[1].append(c)
        self.avgdl = sum(dl) / self.n if self.n else 0.0
        self.norm = [k1 * (1 - b + b * (x / self.avgdl if self.avgdl else 0.0)) for x in dl]

    def score(self, qtoks: list[str]) -> dict[int, float]:
        acc: dict[int, float] = {}
        for t in set(qtoks):
            docs, tfs = self.post.get(t, ((), ()))
            if not docs:
                continue
            df = len(docs)
            idf = math.log(1 + (self.n - df + 0.5) / (df + 0.5))
            for d, tf in zip(docs, tfs):
                acc[d] = acc.get(d, 0.0) + idf * tf * (self.k1 + 1) / (tf + self.norm[d])
        return acc


# ---------------------------------------------------------------- fold, fusion, records (stdlib)
def fold_pairs(pairs, mem: dict):
    """pairs = (memory_id, score) in descending score order. Fold by max (first occurrence), then the status filter.
    Returns (seq = every memory in order, kept = those passing the filter)."""
    seen, seq = set(), []
    for m, _ in pairs:
        if m not in seen:
            seen.add(m)
            seq.append(m)
    return seq, [m for m in seq if m in mem and mem[m].get("status") in H.ACTIVE]


def rrf(lists: list[list[str]], k: int) -> list[str]:
    """Reciprocal rank fusion, score = sum 1 / (k + rank) with 1-based ranks; ties keep first-appearance order (first list first)."""
    sc: dict[str, float] = defaultdict(float)
    first: dict[str, int] = {}
    for L in lists:
        for r, m in enumerate(L, 1):
            sc[m] += 1.0 / (k + r)
            first.setdefault(m, len(first))
    return sorted(sc, key=lambda m: (-round(sc[m], 12), first[m]))


def make_records(questions: list[dict], gold_info: dict, items) -> list[dict]:
    """items[i] = (seq, kept, stats) -> the per-question records harness.STAGES / harness.j0 consume."""
    an = []
    for q, (seq, kept, st) in zip(questions, items):
        g = q["gold_memory_id"]
        pos = {m: i + 1 for i, m in enumerate(kept)}
        an.append({"type": q["type"], "reach": gold_info.get(g, {}).get("n_points", 0) > 0, "in200": g in set(seq), "kept": g in pos,
                   "rank": pos.get(g), "kept_list": kept, "n_seq": len(seq), "n_kept": len(kept), "stats": st, "mem_chunk": {}})
    return an


def hits5(an):
    return [int(r["rank"] is not None and r["rank"] <= 5) for r in an]


def in_pool(an, d: int):
    return [int(r["rank"] is not None and r["rank"] <= d) for r in an]


# ---------------------------------------------------------------- corpus
class Corpus:
    pass


def _lines(b: bytes):
    return [json.loads(x) for x in b.decode("utf-8").split("\n") if x]


def load_corpus(path: str) -> Corpus:
    """Read the (already gunzipped) corpus tar. numpy is not needed here."""
    c = Corpus()
    with tarfile.open(path) as t:
        rd = lambda n: t.extractfile(n).read()  # noqa: E731
        c.man = json.loads(rd("manifest.json"))
        qd = json.loads(rd("questions.json"))
        c.questions, c.gold_info = qd["questions"], qd["gold_info"]
        c.mem = {i: {"status": s, "layer": ly, "title": ti or ""} for i, s, ly, ti in _lines(rd("memories.jsonl"))}
        c.chunks = _lines(rd("chunks.jsonl"))  # [chunk_id, memory_id, chunk_index, point_id, text]
        c.points = _lines(rd("points.jsonl"))  # [point_id, payload_memory_id, chunk_index, chunk_id|None]
        c.vec_bytes = rd("vectors.f16")
    c.dim = c.man["dim"]
    assert len(c.vec_bytes) == len(c.points) * c.dim * 2, "vectors.f16 does not match points.jsonl"
    cidx = {ch[0]: i for i, ch in enumerate(c.chunks)}
    c.row_chunk, c.row_mem = [], []  # per vector row: index into c.chunks (None = no stored text), memory id
    for _pid, mid, _ci, cid in c.points:
        k = cidx.get(cid) if cid else None
        c.row_chunk.append(k)
        c.row_mem.append(mid or (c.chunks[k][1] if k is not None else None))
    c.rows_by_mem = defaultdict(list)  # vector rows that have stored text, per memory
    for r, k in enumerate(c.row_chunk):
        if k is not None:
            c.rows_by_mem[c.row_mem[r]].append(r)
    return c


def corpus_texts(c: Corpus) -> list[str]:
    ts = [q["query"] for q in c.questions] + [q["qid"] for q in c.questions] + [ch[4] for ch in c.chunks] + [m["title"] for m in c.mem.values()]
    return [t for t in ts if t]


# ---------------------------------------------------------------- dense leg (numpy)
class DenseIndex:
    """Brute-force cosine over the whole corpus, computed in float32 from the stored float16 rows."""

    def __init__(self, vec_bytes: bytes, dim: int):
        import numpy as np
        self.np = np
        v = np.frombuffer(vec_bytes, dtype="<f2").reshape(-1, dim).astype(np.float32)
        self.V = v / np.maximum(np.linalg.norm(v, axis=1, keepdims=True), 1e-12)

    def scores(self, qvecs):
        np = self.np
        q = np.asarray(qvecs, dtype=np.float32)
        q = q / np.maximum(np.linalg.norm(q, axis=1, keepdims=True), 1e-12)
        return q @ self.V.T  # (n_queries, n_rows) float32

    def top(self, row, k: int = LEG_DEPTH):
        idx = self.np.argsort(-row, kind="stable")[:k]  # ties keep row (= point id) order
        return idx.tolist(), row[idx].tolist()


def dense_items(c: Corpus, idx: DenseIndex, S):
    items = []
    for i in range(len(c.questions)):
        rows, sc = idx.top(S[i])
        seq, kept = fold_pairs([(c.row_mem[r], s) for r, s in zip(rows, sc)], c.mem)
        items.append((seq, kept, {"cands": len(rows), "cands_without_chunk": sum(1 for r in rows if c.row_chunk[r] is None),
                                  "cands_memory_absent": sum(1 for r in rows if c.row_mem[r] not in c.mem)}))
    return items


def bm25_items(c: Corpus):
    qtok = [tokens(q["query"]) for q in c.questions]
    bm = BM25([ch[4] for ch in c.chunks], {t for ts in qtok for t in ts})
    items = []
    for ts in qtok:
        top = sorted(bm.score(ts).items(), key=lambda x: (-x[1], x[0]))[:LEG_DEPTH]
        seq, kept = fold_pairs([(c.chunks[d][1], s) for d, s in top], c.mem)
        items.append((seq, kept, {"cands": len(top), "cands_without_chunk": 0, "cands_memory_absent": sum(1 for d, _ in top if c.chunks[d][1] not in c.mem)}))
    return items, {"docs": bm.n, "avgdl": round(bm.avgdl, 2), "query_terms": len(bm.post), "k1": K1, "b": B}


def pool_docs(c: Corpus, pool: list[str], srow) -> list[str]:
    """Rerank input per memory = title + "\\n" + its best chunk (highest dense score for this query variant among the memory's
    chunks that have stored text), as in PB1; title only when no chunk has text."""
    docs = []
    for m in pool:
        rows = c.rows_by_mem.get(m, ())
        best = max(rows, key=lambda r: (float(srow[r]), -r)) if rows else None
        docs.append(((c.mem[m]["title"] if m in c.mem else "") + "\n" + (c.chunks[c.row_chunk[best]][4] if best is not None else "")).strip())
    return docs


# ---------------------------------------------------------------- evaluation (E-RET-2 / E-RET-3)
def stages_only(j: dict) -> dict:
    return {"stages": j["stages"], "conversion": j["conversion"], "reachable_only": j["reachable_only"],
            "pool25_vs_pool100": j["pool25_vs_pool100"], "counters": j["counters"]}


def pair(a_hits, b_hits):
    return H.mcnemar(a_hits, b_hits)


def evaluate(c: Corpus, qv: dict) -> tuple[dict, dict]:
    """Dense variants, BM25, RRF and the pre-registered comparisons. Returns (results, ctx); ctx (per-question lists, score matrices)
    is for the rerank arm and never serialised."""
    qids = [q["qid"] for q in c.questions]
    for v, vecs in qv.items():
        assert all(q in vecs for q in qids), "query vectors do not cover every question"
    pseudo = {"questions": c.questions, "gold_info": c.gold_info, "manifest": c.man}
    idx = DenseIndex(c.vec_bytes, c.dim)
    res = {"manifest": {k: v for k, v in c.man.items() if isinstance(v, (int, float, str))}, "variants": {}, "secondary": {}}
    S, items, an = {}, {}, {}
    for v in VARIANTS:
        if v in qv:
            S[v] = idx.scores([qv[v][q] for q in qids])
            items[v] = dense_items(c, idx, S[v])
            an[v] = make_records(c.questions, c.gold_info, items[v])
            res["variants"][v] = stages_only(H.j0(pseudo, an[v]))
    h5 = {v: hits5(an[v]) for v in an}
    p25 = {v: in_pool(an[v], 25) for v in an}
    n = len(qids)
    # q0 self-check against PB1 (not a gate: reported)
    s0 = res["variants"]["q0"]["stages"]["all"]
    res["q0_vs_pb1"] = {"dense_hit5": [sum(h5["q0"]), PB1["dense_hit5"]], **{k: [s0[k]["k"], PB1[k]] for k in ("reachable", "in_top200_chunks", "after_status_filter", "pool_25", "pool_100", "pool_200")}}
    # primary 1: q1 vs q0 on dense hit@5
    p1 = pair(h5["q0"], h5["q1"]) if "q1" in h5 else None
    winner = "q1" if p1 and p1["c"] > p1["b"] and p1["p"] < 0.05 else "q0"
    res["primary"] = {"p1_q1_vs_q0_dense_hit5": {**p1, "q0_hits": sum(h5["q0"]), "q1_hits": sum(h5["q1"]), "A": "q0", "B": "q1"} if p1 else "not_applicable: no q1 vectors",
                      "dense_variant_carried_forward": winner}
    if "q2" in h5:
        res["secondary"]["q2_vs_q0_hit5"] = pair(h5["q0"], h5["q2"])
        res["secondary"]["q2_vs_q1_hit5"] = pair(h5["q1"], h5["q2"]) if "q1" in h5 else None
    res["secondary"]["q1_vs_q0_pool25"] = pair(p25["q0"], p25["q1"]) if "q1" in p25 else None
    # BM25 leg and RRF
    bi, bm_info = bm25_items(c)
    ban = make_records(c.questions, c.gold_info, bi)
    res["bm25"] = {"index": bm_info, **{k: v for k, v in stages_only(H.j0(pseudo, ban)).items() if k in ("stages", "conversion")}}
    W = winner
    seq_w, kept_w = [x[0] for x in items[W]], [x[1] for x in items[W]]
    res["rrf"], fused_an, fused_lists = {}, {}, {}
    for k in RRF_KS:
        fl = [rrf([kw, kb], k) for kw, kb in zip(kept_w, [x[1] for x in bi])]
        fused_lists[k] = fl
        fan = make_records(c.questions, c.gold_info, [(list(dict.fromkeys(sw + sb)), f, {"cands": 0, "cands_without_chunk": 0, "cands_memory_absent": 0})
                                                       for sw, sb, f in zip(seq_w, [x[0] for x in bi], fl)])
        fused_an[k] = fan
        res["rrf"][f"k{k}"] = {**{kk: v for kk, v in stages_only(H.j0(pseudo, fan)).items() if kk in ("stages", "conversion")},
                               "pool25_vs_dense": pair(p25[W], in_pool(fan, 25)), "hit5_vs_dense": pair(h5[W], hits5(fan))}
    # union oracle: gold in the top 25 of either leg (after the status filter)
    d25, b25 = in_pool(an[W], 25), in_pool(ban, 25)
    both = sum(1 for x, y in zip(d25, b25) if x and y)
    res["union_oracle"] = {"dense_variant": W, "dense_pool25": H.rate(sum(d25), n), "bm25_pool25": H.rate(sum(b25), n),
                           "union_pool25": H.rate(sum(1 for x, y in zip(d25, b25) if x or y), n), "found_by_both": both,
                           "found_by_dense_only": sum(d25) - both, "found_by_bm25_only": sum(b25) - both,
                           "by_type": {t: {"dense": sum(x for x, r in zip(d25, an[W]) if r["type"] == t), "bm25": sum(x for x, r in zip(b25, an[W]) if r["type"] == t),
                                           "union": sum(1 for x, y, r in zip(d25, b25, an[W]) if (x or y) and r["type"] == t),
                                           "n": sum(1 for r in an[W] if r["type"] == t)} for t in H.TYPES}}
    # primary 2: best k vs W on pool@25
    rows = [(sum(in_pool(fused_an[k], 25)), sum(hits5(fused_an[k])), k) for k in RRF_KS]
    best_k = max(rows)[2]
    res["primary"]["p2_best_rrf_k_vs_dense_pool25"] = {**pair(p25[W], in_pool(fused_an[best_k], 25)), "A": W, "B": f"rrf-k{best_k}", "best_k": best_k,
                                                         "dense_pool25": sum(p25[W]), "rrf_pool25": sum(in_pool(fused_an[best_k], 25)),
                                                         "all_k": {f"k{k}": {"pool25": a, "hit5": b} for a, b, k in rows}}
    res["secondary"]["bm25_vs_dense_pool25"] = pair(p25[W], b25)
    res["secondary"]["bm25_vs_dense_hit5"] = pair(h5[W], hits5(ban))
    # pools for the rerank arm: q0's pool, and the best pool (RRF if its pool@25 beats the carried-forward dense pool, else dense)
    use_rrf = sum(in_pool(fused_an[best_k], 25)) > sum(p25[W])
    best_pool = [f[:25] for f in fused_lists[best_k]] if use_rrf else [k[:25] for k in kept_w]
    q0_pool = [k[:25] for k in [r["kept_list"] for r in an["q0"]]]
    res["rerank_pools"] = {"best_pool": f"rrf-k{best_k}" if use_rrf else f"dense-{W}", "best_pool_equals_q0_pool": best_pool == q0_pool}
    ctx = {"S": S, "best_pool": best_pool, "q0_pool": q0_pool, "best_S": W, "pre_hit5": {"best": hits5(fused_an[best_k]) if use_rrf else h5[W], "q0": h5["q0"]}}
    return res, ctx


# ---------------------------------------------------------------- rerank (one arm: bge-reranker-base ONNX int8, L 512, depth 25)
def rerank_section(c: Corpus, ctx: dict, a) -> dict:
    import gc
    import platform

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import rerank as R  # needs torch

    R.torch.set_num_threads(4)
    L = 512
    out = {"env": {"machine": platform.machine(), "cpus": os.cpu_count(), "python": sys.version.split()[0], "torch": R.torch.__version__},
           "model": R.pin_and_licence(a.repo, a.rev), "arm": f"int8-L{L}-d25", "arms": {}}
    sc = R.Scorer(R.KIND["int8"], R.download(a.repo, a.rev))
    out["scorer_sanity"], out["export_s"] = sc.sanity(), sc.export_s
    jobs = [("q0_pool", ctx["q0_pool"], ctx["S"]["q0"], ctx["pre_hit5"]["q0"])]
    if not ctx.get("same_pool"):
        jobs.append(("best_pool", ctx["best_pool"], ctx["S"][ctx["best_S"]], ctx["pre_hit5"]["best"]))
    hits = {}
    for name, pools, S, pre in jobs:
        docs = [pool_docs(c, p, S[i]) for i, p in enumerate(pools)]
        sc.score_query(c.questions[0]["query"], docs[0], L)  # warm-up, untimed
        hit, wall = [], []
        for i, q in enumerate(c.questions):
            t = time.perf_counter()
            s = sc.score_query(q["query"], docs[i], L)
            wall.append(time.perf_counter() - t)
            order = sorted(range(len(s)), key=lambda j: (-s[j], j))  # ties keep pool order
            hit.append(int(q["gold_memory_id"] in [pools[i][j] for j in order[:5]]))
            if (i + 1) % 33 == 0:
                H.log(name, f"{i + 1}/{len(c.questions)} questions, {sum(wall):.0f}s")
        hits[name] = hit
        out["arms"][name] = {"hit5": H.rate(sum(hit), len(hit)),
                             "hit5_by_type": {t: H.rate(sum(h for h, q in zip(hit, c.questions) if q["type"] == t), sum(1 for q in c.questions if q["type"] == t)) for t in H.TYPES},
                             "pool25": H.rate(sum(int(q["gold_memory_id"] in p) for q, p in zip(c.questions, pools)), len(pools)),
                             "pre_rerank_hit5": H.rate(sum(pre), len(pre)), "mcnemar_vs_pre_rerank": H.mcnemar(pre, hit),
                             "latency_s": {"n": len(wall), "p50": round(H.pct(wall, .5), 3), "p95": round(H.pct(wall, .95), 3), "mean": round(sum(wall) / len(wall), 3)}}
        H.log("arm done", name, out["arms"][name]["hit5"])
    if len(hits) == 2:
        out["best_pool_vs_q0_pool"] = {"A": "q0_pool", "B": "best_pool", **H.mcnemar(hits["q0_pool"], hits["best_pool"])}
    out["pb1_reference"] = {"int8_L512_d25_hit5": PB1["rerank_int8_L512_d25_hit5"], "n": 198}
    del sc
    gc.collect()
    return out


# ---------------------------------------------------------------- rendering
def _row(label, r):
    return f"| {label} | " + " | ".join(H.fmt_rate(r[s]) for s in ("all",) + H.TYPES) + " |"


def render_variant(name: str, v: dict) -> list[str]:
    L = [f"### J0 stages, dense variant {name}", "", "| stage | all | state | fact |", "|---|---|---|---|"]
    L += [_row(st, {s: v["stages"][s][st] for s in ("all",) + H.TYPES}) for st, _ in H.STAGES]
    L += [_row("conversion = top5 / pool_25", v["conversion"]), ""]
    return L


def render_pb2(res: dict) -> str:
    L = ["## E-RET-PB2 (full corpus; E-RET-2 query role, E-RET-3 BM25 + RRF)", "",
         "Counts, rate and Clopper-Pearson 95% interval; McNemar exact two-sided (A = baseline, B = challenger, b = A hit and B miss, c = A miss and B hit).", ""]
    m = res["manifest"]
    L += ["Corpus: " + ", ".join(f"{k}={m[k]}" for k in ("rows", "chunks", "memories", "questions", "points_without_pg_chunk", "pg_chunks_without_scrolled_point") if k in m), ""]
    if "embed_meta" in res:
        L += ["Query vectors: " + json.dumps(res["embed_meta"], sort_keys=True), ""]
    L += ["### q0 self-check against PB1 (now / PB1)", "", "| " + " | ".join(res["q0_vs_pb1"]) + " |", "|" + "---|" * len(res["q0_vs_pb1"]),
          "| " + " | ".join(f"{a}/{b}" for a, b in res["q0_vs_pb1"].values()) + " |", ""]
    p = res["primary"]
    L += ["### Pre-registered primary comparisons (exactly two)", "", "| comparison | A | B | N | b | c | p |", "|---|---|---|---|---|---|---|"]
    p1, p2 = p["p1_q1_vs_q0_dense_hit5"], p["p2_best_rrf_k_vs_dense_pool25"]
    if isinstance(p1, dict):
        L.append(f"| 1. dense hit@5 | q0 = {p1['q0_hits']} | q1 = {p1['q1_hits']} | {p1['N']} | {p1['b']} | {p1['c']} | {p1['p']} |")
    else:
        L.append(f"| 1. dense hit@5 | {p1} | | | | | |")
    L += [f"| 2. pool@25 | {p2['A']} = {p2['dense_pool25']} | {p2['B']} = {p2['rrf_pool25']} | {p2['N']} | {p2['b']} | {p2['c']} | {p2['p']} |", "",
          f"Dense variant carried forward: {p['dense_variant_carried_forward']}. RRF pool@25 / hit@5 per k: " + ", ".join(f"{k}: {v['pool25']} / {v['hit5']}" for k, v in p2["all_k"].items()), ""]
    for v in VARIANTS:
        if v in res["variants"]:
            L += render_variant(v, res["variants"][v])
    L += ["### BM25 alone and RRF (secondary), all questions", "", "| list | pool_25 | pool_50 | pool_100 | pool_200 | top5 | pool25 vs dense (N/b/c/p) | hit5 vs dense (N/b/c/p) |", "|---|---|---|---|---|---|---|---|"]
    def cells(j):
        s = j["stages"]["all"]
        return " | ".join(H.fmt_rate(s[x]) for x in ("pool_25", "pool_50", "pool_100", "pool_200", "top5_at_depth_25"))
    mc = lambda x: f"{x['N']}/{x['b']}/{x['c']}/{x['p']}"  # noqa: E731
    sb = res["secondary"]
    L.append(f"| bm25 | {cells(res['bm25'])} | {mc(sb['bm25_vs_dense_pool25'])} | {mc(sb['bm25_vs_dense_hit5'])} |")
    for k, j in res["rrf"].items():
        L.append(f"| rrf-{k} | {cells(j)} | {mc(j['pool25_vs_dense'])} | {mc(j['hit5_vs_dense'])} |")
    u = res["union_oracle"]
    L += ["", f"BM25 index: {json.dumps(res['bm25']['index'], sort_keys=True)}", "",
          f"Union oracle (gold in the top 25 of either leg; dense = {u['dense_variant']}): dense {H.fmt_rate(u['dense_pool25'])}, bm25 {H.fmt_rate(u['bm25_pool25'])}, "
          f"union {H.fmt_rate(u['union_pool25'])}; both {u['found_by_both']}, dense only {u['found_by_dense_only']}, bm25 only {u['found_by_bm25_only']}.", "",
          "Secondary comparisons: " + ", ".join(f"{k}: {mc(v)}" for k, v in sb.items() if isinstance(v, dict) and k.startswith(("q1", "q2"))), ""]
    if "rerank" in res:
        r = res["rerank"]
        L += [f"### Rerank arm {r['arm']} (bge-reranker-base ONNX int8), pool = best pool: {res['rerank_pools']['best_pool']}", "",
              "| pool | hit@5 | state | fact | pool@25 | pre-rerank hit@5 | N | b | c | p | p50 s | p95 s |", "|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for name, x in r["arms"].items():
            mm, t = x["mcnemar_vs_pre_rerank"], x["latency_s"]
            L.append(f"| {name} | {H.fmt_rate(x['hit5'])} | {H.fmt_rate(x['hit5_by_type']['state'])} | {H.fmt_rate(x['hit5_by_type']['fact'])} | {H.fmt_rate(x['pool25'])} | "
                     f"{H.fmt_rate(x['pre_rerank_hit5'])} | {mm['N']} | {mm['b']} | {mm['c']} | {mm['p']} | {t['p50']} | {t['p95']} |")
        if "best_pool_vs_q0_pool" in r:
            x = r["best_pool_vs_q0_pool"]
            L += ["", f"Rerank on best pool vs rerank on q0 pool (A = q0 pool, B = best pool): N={x['N']} b={x['b']} c={x['c']} p={x['p']}"]
        L += ["", f"PB1 reference (not paired): int8 L512 depth 25 hit@5 = {r['pb1_reference']['int8_L512_d25_hit5']}/198."]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- stage B: query-vector variants
def embed_variants(a, urls: dict | None = None):
    """q0 = compat mode raw query (PB1's call); q1 = native text-embedding API with text_type=query; q2 = q1 + instruct. Batches of 10.
    Also one compat call with text_type to record whether compat mode accepts it. Only status codes and counts reach the log."""
    urls = urls or {"compat": H.DASH_URL, "text": NATIVE_URL}
    key = os.environ["DASHSCOPE_API_KEY"]
    qs = json.loads(Path(a.qpack).read_text(encoding="utf-8"))["queries"]
    scrub = [q["query"] for q in qs]
    meta = {"model": MODEL, "dim": H.DIM, "instruct": INSTRUCT, "queries": len(qs), "status": {}}
    calls = Counter()

    def run(variant, kind, extra, soft):
        out = {}
        for i in range(0, len(qs), H.BATCH):
            vecs = H.api_embed(MODEL, kind, [q["query"] for q in qs[i:i + H.BATCH]], key, scrub, urls, extra=extra, soft=soft)
            calls[variant] += 1
            for q, v in zip(qs[i:i + H.BATCH], vecs):
                if len(v) != H.DIM or not all(math.isfinite(x) for x in v):
                    raise SystemExit("bad vector shape")
                out[q["qid"]] = v
        return out

    def attempt(variant, kind, extra):
        try:
            out = run(variant, kind, extra, True)
            meta["status"][variant] = {"http": 200}
            return out
        except (H.ApiHttp, H.ModelUnsupported) as e:
            calls[variant] += 1
            e = e if isinstance(e, H.ApiHttp) else H.ApiHttp(404, "model_not_supported")
            if e.http in (401, 403) or e.code in ("Arrearage", "InvalidApiKey"):
                raise SystemExit(3)  # real money / credentials: the owner settles it
            meta["status"][variant] = {"http": e.http, "code": e.code}
            print(f"variant {variant}: not produced, http={e.http} code={e.code}", flush=True)
            return None

    variants = {"q0": run("q0", "compat", None, False)}
    meta["status"]["q0"] = {"http": 200}
    # does compat mode accept text_type? (2 queries; if it answers 200, compare with q0 to see whether it was honoured or ignored)
    try:
        v = H.api_embed(MODEL, "compat", [q["query"] for q in qs[:2]], key, scrub, urls, extra={"text_type": "query"}, soft=True)
        calls["compat_text_type_probe"] += 1
        meta["compat_text_type"] = {"http": 200, "cos_vs_q0": [round(H.cosine(x, variants["q0"][q["qid"]]), 6) for x, q in zip(v, qs[:2])]}
    except (H.ApiHttp, H.ModelUnsupported) as e:
        calls["compat_text_type_probe"] += 1
        meta["compat_text_type"] = {"http": e.http, "code": e.code} if isinstance(e, H.ApiHttp) else {"http": 404, "code": "model_not_supported"}
    print("compat text_type:", json.dumps(meta["compat_text_type"]), flush=True)
    q1 = attempt("q1", "text", {"text_type": "query"})
    if q1:
        variants["q1"] = q1
        q2 = attempt("q2", "text", {"text_type": "query", "instruct": INSTRUCT})
        if q2:
            variants["q2"] = q2
    meta["calls"] = dict(calls)
    cs = lambda x, y: [H.cosine(variants[x][q["qid"]], variants[y][q["qid"]]) for q in qs]  # noqa: E731
    for x, y in (("q0", "q1"), ("q1", "q2"), ("q0", "q2")):
        if x in variants and y in variants:
            c = cs(x, y)
            meta[f"cos_{x}_{y}"] = {"mean": round(sum(c) / len(c), 6), "min": round(min(c), 6), "identical_ge_0.999999": sum(1 for z in c if z >= 0.999999)}
    Path(a.out).write_text(json.dumps({"meta": meta, "variants": variants}))
    print("embedded variants:", sorted(variants), "api_calls:", dict(calls), "meta:", json.dumps({k: v for k, v in meta.items() if k.startswith(("cos_", "status"))}), flush=True)
    if "q1" not in variants or "q2" not in variants:
        raise SystemExit(4)  # artifact is still written and uploaded (if: always()); the run is red so the owner looks


# ---------------------------------------------------------------- stage C
def eval2(a):
    c = load_corpus(a.corpus)
    qv = json.loads(Path(a.qvec).read_text())
    res, ctx = evaluate(c, qv["variants"])
    res["embed_meta"] = {k: v for k, v in qv["meta"].items() if k in ("model", "dim", "instruct", "status", "compat_text_type", "calls") or k.startswith("cos_")}
    ctx["same_pool"] = res["rerank_pools"]["best_pool_equals_q0_pool"]
    Path(a.out).write_text(json.dumps(res, indent=1))
    Path(a.summary).write_text(render_pb2(res))  # partial results survive a rerank failure
    H.log("dense / BM25 / RRF done")
    if not a.no_rerank:
        res["rerank"] = rerank_section(c, ctx, a)
        Path(a.out).write_text(json.dumps(res, indent=1))
        Path(a.summary).write_text(render_pb2(res))


def guard2(a):
    c = load_corpus(a.corpus)
    static = H.static_strings(a.files, (a.static or []) + sys.argv[1:] + [x for arg in sys.argv[1:] for x in re.split(r"[,:]", arg)])
    hits = H.guard_findings(corpus_texts(c), a.files, static)
    if hits:  # offsets only; never the text
        raise SystemExit(f"GUARD FAILED: {len(hits)} corpus window(s) in outputs, first at {hits[0][0]!r} offset {hits[0][1]}")
    print(f"guard ok: {len(a.files)} file(s) scanned against {len(corpus_texts(c))} corpus texts")


# ---------------------------------------------------------------- selftest
def fake_corpus_tar(path: str, dim: int = 4):
    """Tiny corpus: M1/M2/M4 usable, M3 superseded, M5 only a point (no chunk, absent from memories), M9 gold without chunk."""
    import io
    mems = [["m1", "active", "L1", "title alpha"], ["m2", "active", "L1", "title beta"], ["m3", "superseded", "L1", "title gamma"], ["m4", None, "L1", "title delta"], ["m9", "active", "L1", "title omega"]]
    chunks = [["c1", "m1", 0, "p1", "项目进度更新 alpha_beta 详情"], ["c2", "m2", 0, "p2", "数据库迁移计划 PostgreSQL"], ["c3", "m3", 0, "p3", "项目进度更新旧版"],
              ["c4", "m4", 0, "p4", "部署流程 Docker compose"], ["c5", "m1", 1, "p5", "无关内容 foo bar"]]
    vecs = {"p1": [1, 0, 0, 0], "p2": [0, 1, 0, 0], "p3": [.9, .1, 0, 0], "p4": [0, 0, 1, 0], "p5": [0, 0, 0, 1], "p6": [.8, 0, .2, 0]}
    points = [["p1", "m1", 0, "c1"], ["p2", "m2", 0, "c2"], ["p3", "m3", 0, "c3"], ["p4", "m4", 0, "c4"], ["p5", "m1", 1, "c5"], ["p6", "m5", 0, None]]
    qs = [{"qid": "q1", "type": "state", "query": "项目进度", "gold_memory_id": "m1"}, {"qid": "q2", "type": "fact", "query": "数据库迁移 postgresql", "gold_memory_id": "m2"},
          {"qid": "q3", "type": "state", "query": "旧版进度", "gold_memory_id": "m3"}, {"qid": "q4", "type": "fact", "query": "没有这个", "gold_memory_id": "m9"}]
    gi = {"m1": {"in_pg": True, "n_chunks": 2, "n_points": 2}, "m2": {"in_pg": True, "n_chunks": 1, "n_points": 1}, "m3": {"in_pg": True, "n_chunks": 1, "n_points": 1},
          "m9": {"in_pg": True, "n_chunks": 0, "n_points": 0}}
    man = {"dim": dim, "rows": len(points), "date": "fake"}
    jl = lambda rows: "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows).encode()  # noqa: E731
    files = {"manifest.json": json.dumps(man).encode(), "questions.json": json.dumps({"questions": qs, "gold_info": gi}, ensure_ascii=False).encode(),
             "memories.jsonl": jl(mems), "chunks.jsonl": jl(chunks), "points.jsonl": jl(points),
             "vectors.f16": b"".join(struct.pack("<%de" % dim, *vecs[p[0]]) for p in points)}
    with tarfile.open(path, "w") as t:
        for n, b in files.items():
            ti = tarfile.TarInfo(n)
            ti.size = len(b)
            t.addfile(ti, io.BytesIO(b))


def selftest(_a=None):
    import shutil
    import tempfile
    # tokens and BM25 against an independent formula
    assert tokens("ABC_1 中文测试x 中") == ["abc_1", "x", "中文", "文测", "测试", "中"], tokens("ABC_1 中文测试x 中")
    docs = ["alpha beta", "alpha alpha gamma delta", "中文测试"]
    bm = BM25(docs, {"alpha", "beta"})
    n, avg = 3, (2 + 4 + 3) / 3
    idf = lambda df: math.log(1 + (n - df + .5) / (df + .5))  # noqa: E731
    want0 = idf(2) * 1 * 2.2 / (1 + 1.2 * (.25 + .75 * 2 / avg)) + idf(1) * 1 * 2.2 / (1 + 1.2 * (.25 + .75 * 2 / avg))
    got = bm.score(["alpha", "beta", "alpha"])
    assert abs(got[0] - want0) < 1e-12 and 2 not in got and got[1] < got[0], (got, want0)
    # fold, RRF
    mem = {"a": {"status": "active"}, "b": {"status": None}, "c": {"status": "superseded"}}
    seq, kept = fold_pairs([("a", .9), ("c", .8), ("a", .7), ("zz", .6), ("b", .5)], mem)
    assert seq == ["a", "c", "zz", "b"] and kept == ["a", "b"], (seq, kept)
    assert rrf([["x", "y", "z"], ["y", "x"]], 10) == ["x", "y", "z"]  # x and y tie, first appearance wins
    assert rrf([["x", "y"], ["y", "z"]], 10) == ["y", "x", "z"]
    ra = make_records([{"type": "state", "gold_memory_id": "b"}], {"b": {"n_points": 1}}, [(seq, kept, {})])[0]
    assert ra["rank"] == 2 and ra["in200"] and ra["kept"] and ra["reach"]
    tmp = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / f"pb2_selftest_{os.getpid()}"
    tmp.mkdir(parents=True, exist_ok=True)
    try:
        fake_corpus_tar(str(tmp / "c.tar"))
        c = load_corpus(str(tmp / "c.tar"))
        assert len(c.points) == 6 and c.row_chunk == [0, 1, 2, 3, 4, None] and c.row_mem[5] == "m5" and c.rows_by_mem["m1"] == [0, 4]
        # U+2028 inside a text field must survive the line split
        assert _lines('["a", "x y"]\n["b", "z"]\n'.encode()) == [["a", "x y"], ["b", "z"]]
        items, info = bm25_items(c)
        assert info["docs"] == 5 and items[0][1][0] == "m1" and items[3][1] == [], [x[1] for x in items]
        assert items[2][0][0] == "m3" and "m3" not in items[2][1], items[2]  # q3: the superseded memory matches best and is dropped by the filter
        # guard: leak fails, clean output and an exempt label pass (corpus text never printed)
        good, bad = tmp / "good.md", tmp / "bad.md"
        good.write_text("| rrf-k60 | 12/198 = 0.061 |\n")
        bad.write_text("leak: 项目进度更新 alpha_beta 详情 end")
        txt = corpus_texts(c)
        assert H.guard_findings(txt, [str(bad)], set()) and not H.guard_findings(txt, [str(good)], {"rrf-k60"})
        # regression (run 39610197524): result KEYS are code-made, never corpus text. A chunk that mentions a manifest column name must not
        # fail the guard. The key is built from bytes so no str literal in this file (which the guard exempts) equals it.
        key = bytes(b"qdrant_points_at_scroll_start").decode()
        rj = tmp / "r.json"
        rj.write_text(json.dumps({"manifest": {key: 52140}, "variants": {"q0": {"stages": {}}}}, indent=1))
        txt2 = txt + [f"columns such as chunks.{key} exist"]
        assert not H.guard_findings(txt2, [str(rj)], H.static_strings([str(rj)], [])), "result keys must be exempt from the window check"
        assert H.guard_findings(txt2, [str(bad)], {key}), "exempting keys must not hide a real leak"
        # numpy part: float16 byte order, dense scores, full evaluate() on the fake corpus (always required in CI)
        try:
            if os.environ.get("PB2_NO_NUMPY"):  # local runs: this machine runs no numpy (owner rule)
                raise ImportError
            import numpy as np
        except ImportError:
            if os.environ.get("GITHUB_ACTIONS") == "true":
                raise
            print("selftest pb2: numpy not used here, dense parts skipped")
            print("selftest pb2 ok (pure part)")
            return
        assert np.frombuffer(struct.pack("<3e", 1.0, -2.5, 0.125), dtype="<f2").tolist() == [1.0, -2.5, 0.125]
        qv = {"q0": {"q1": [1, 0, 0, 0], "q2": [0, 1, 0, 0], "q3": [1, 0, 0, 0], "q4": [0, 0, 0, 1]}}
        qv["q1"] = {k: v for k, v in qv["q0"].items()}
        qv["q2"] = {"q1": [.9, .1, 0, 0], "q2": [0, 1, 0, 0], "q3": [1, 0, 0, 0], "q4": [0, 0, 1, 0]}
        res, ctx = evaluate(c, qv)
        s = res["variants"]["q0"]["stages"]["all"]
        assert (s["questions"], s["reachable"]["k"], s["after_status_filter"]["k"], s["top5_at_depth_25"]["k"]) == (4, 3, 2, 2), s  # q3 gold superseded, q4 gold has no point
        p1 = res["primary"]["p1_q1_vs_q0_dense_hit5"]
        assert (p1["N"], p1["b"], p1["c"], p1["p"]) == (4, 0, 0, 1.0) and res["primary"]["dense_variant_carried_forward"] == "q0", p1
        assert res["primary"]["p2_best_rrf_k_vs_dense_pool25"]["N"] == 4 and set(res["rrf"]) == {"k10", "k30", "k60"}
        assert res["q0_vs_pb1"]["dense_hit5"][0] == 2 and ctx["best_pool"] and "best_pool_equals_q0_pool" in res["rerank_pools"]
        docs = pool_docs(c, ["m1", "m5", "m3"], ctx["S"]["q0"][0])
        assert docs[0].startswith("title alpha\n项目进度更新") and docs[1] == "" and docs[2].startswith("title gamma"), docs  # best chunk = highest dense score for the query
        out = render_pb2(res)
        j = json.dumps(res, ensure_ascii=False)
        for t in ("项目进度", "数据库迁移"):
            assert t not in out and t not in j, "aggregate output leaked query text"
        print("selftest pb2 ok")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
