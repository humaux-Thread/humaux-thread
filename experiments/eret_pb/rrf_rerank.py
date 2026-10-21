#!/usr/bin/env python3
"""E-RET-PB6: cloud rerank (DashScope gte-rerank-v2, qwen3-rerank) and PB3's local int8 arm on the hybrid RRF pool of E-RET-5f. Experiment, not product code.

Imports (does not copy) PB5's pool pieces (qdrant_sparse.py: collection, upsert, bm25_ml leg, client RRF; pb2.py: corpus, exact dense q0, pool_docs)
and PB4's cloud machinery (cloud_rerank.py: client, retries, stop rules, per-arm aggregates; jev_rerank.py: Ctx, Stop, paired McNemar).
Nothing here prints or writes corpus text: output is counts, rates, intervals, b/c/p, latencies, tokens and cost.

Subcommands:
  selftest  pure checks against a fake endpoint (no network, no key)
  smoke     fake corpus against the live Qdrant service: the whole pool -> cloud -> comparison path on toy data
  pools     stage 1: corpus into the local Qdrant, dense exact q0 + bm25_ml leg -> client RRF k=60; reproduction check vs PB5; top-25 pools + rerank documents
            (private file in $RUNNER_TEMP, aggregates out)
  int8      stage 2: bge-reranker-base ONNX int8, L512, depth 25 on the RRF pool (PB3's recompute recipe, jev_rerank.ref)
  cloud     stage 3: the cloud arms and every comparison. Needs ALIBABA_CLOUD_API_KEY in this step's env only.
  guard     fail if any 12-character window of corpus text occurs in the given output files

Pre-registered before any result was seen (card E-RET-PB6):
  pool        client memory-level RRF k=60 over the exact q0 dense list and the Qdrant `qdrant/bm25` leg with `tokenizer: multilingual`, each folded to
              memories and status-filtered, exactly as PB5's follow-up (run 39625766381, exp/e-ret-pb-qdrant@7121635). Reproduction gate: RRF hit@5 = 96
              and pool@25 = 147; otherwise the job reports the difference and stops before any rerank.
  documents   title + "\\n" + best chunk (highest exact q0 dense score among the memory's chunks with text), cut to 1,000 characters for the cloud arms
              (as PB3 / PB4); the int8 arm is cut by tokens (L512) only, as PB3's ref. Depth 25.
  PRIMARY     hit@5, A = RRF alone, B = gte-rerank-v2 on the RRF pool; paired exact McNemar N/b/c/p. Everything else is secondary or extra.
  secondary   qwen3-rerank on RRF vs RRF; int8 L512 on RRF vs RRF; gte-rerank-v2 on RRF vs gte-rerank-v2 on the dense pool (same job, recomputed);
              gte-rerank-v2 vs qwen3-rerank (both on RRF). Names read "B vs A"; b = A hit and B miss, c = A miss and B hit.
  extra       (not in the card, labelled) each cloud arm vs int8 on the RRF pool; gte-rerank-v2 on the dense pool vs dense alone.
  budget      at most 4 cloud arms x 198 calls: the three arms below, one spare.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import platform
import shutil
import sys
import tempfile
import time
import traceback
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import cloud_rerank as C  # noqa: E402
import harness as H  # noqa: E402
import jev_rerank as J  # noqa: E402
import pb2 as P  # noqa: E402
import qdrant_sparse as Q  # noqa: E402

POOL = C.POOL  # depth 25
LEG = "qdrant_bm25_ml"  # PB5 arm name of the multilingual qdrant/bm25 leg
EXPECT = {"hit5": 96, "pool25": 147}  # PB5 follow-up, run 39625766381: client RRF k=60, dense exact q0 + bm25_ml leg
RRF, DENSE, INT8 = "rrf", "dense", "int8@rrf"
ARMS = (("gte-rerank-v2", RRF), ("qwen3-rerank", RRF), ("gte-rerank-v2", DENSE))  # run order: the primary arm first
REPO, REV, LENGTH = "BAAI/bge-reranker-base", "2cfc18c9415c912f9d8155881c133215df768a70", 512  # PB3 ref: int8 L512
# (tier, B, A): the comparison "B vs A", A = baseline
TIERS = (("primary", "gte-rerank-v2@rrf", RRF),
         ("secondary", "qwen3-rerank@rrf", RRF),
         ("secondary", INT8, RRF),
         ("secondary", "gte-rerank-v2@rrf", "gte-rerank-v2@dense"),
         ("secondary", "gte-rerank-v2@rrf", "qwen3-rerank@rrf"),
         ("extra", "gte-rerank-v2@rrf", INT8),
         ("extra", "qwen3-rerank@rrf", INT8),
         ("extra", "gte-rerank-v2@dense", DENSE))


def arm_name(model: str, pool: str) -> str:
    return f"{model}@{pool}"


# ---------------------------------------------------------------- small helpers
def write_private(path: str, obj) -> None:
    """Plaintext corpus text lives in this file: mode 600, in $RUNNER_TEMP, removed by the workflow's always() cleanup."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)


def read_json(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def cut(docs: list[str]) -> list[str]:
    """Cloud documents: at most MAXCH characters; "-" for a memory with neither title nor text (the API refuses empty strings)."""
    return [(d[:C.MAXCH] or "-") for d in docs]


def hit_bits(ranks: list) -> dict[int, int]:
    return {i: int(r is not None and r <= 5) for i, r in enumerate(ranks)}


def by_type(types: list[str], bits) -> dict:
    b = list(bits.values()) if isinstance(bits, dict) else list(bits)
    return {t: H.rate(sum(x for x, ty in zip(b, types) if ty == t), sum(1 for ty in types if ty == t)) for t in H.TYPES}


def repro_check(got: dict) -> dict:
    return {"expected": EXPECT, "got": got, "diff": {k: got[k] - EXPECT[k] for k in EXPECT}, "ok": got == EXPECT, "reference": "PB5 follow-up run 39625766381"}


# ---------------------------------------------------------------- stage 1: pools
def pool_block(c, an: list[dict], S) -> dict:
    """Top-25 memories of one list, their rerank documents (title + newline + best chunk, PB2's pool_docs) and the gold rank in the full list."""
    mems = [r["kept_list"][:POOL] for r in an]
    return {"mems": mems, "docs": [P.pool_docs(c, m, S[i]) for i, m in enumerate(mems)], "rank": [r["rank"] for r in an]}


def doc_stats(blk: dict) -> dict:
    flat = [d for ds in blk["docs"] for d in ds]
    return {"docs": len(flat), "chars_mean": round(sum(map(len, flat)) / len(flat), 1) if flat else None,
            "cut_at_max_chars": sum(1 for d in flat if len(d) > C.MAXCH), "questions_with_fewer_than_25": sum(1 for m in blk["mems"] if len(m) < POOL),
            "questions_with_empty_pool": sum(1 for m in blk["mems"] if not m)}


def pools_core(qd, c, q0: dict, dn: str, ml: bool, budget_min: float = 30.0):
    """Builds the collection like PB5's `run`, then the three lists of PB5's follow-up: exact q0 dense (pb2.dense_items), the bm25_ml leg
    (Qdrant `limit` 200 points, folded by first occurrence) and their client RRF k=60 (qdrant_sparse.client_rrf). Returns (aggregates, private pools)."""
    import numpy as np
    if not ml:
        raise SystemExit("not_applicable: the bm25_ml sparse vector was not built (the smoke step chose a layout without it)")
    qids = [q["qid"] for q in c.questions]
    assert all(q in q0 for q in qids), "query vectors do not cover every question"
    plan = Q.point_plan(c)
    V = np.frombuffer(c.vec_bytes, dtype="<f2").reshape(-1, c.dim)
    t0 = time.perf_counter()
    Q.build_collection(qd, c.dim, dn, ml)
    up = Q.upsert(qd, c, plan, dn, ml, V)
    info, green_s = Q.wait_green(qd)
    idx = P.DenseIndex(c.vec_bytes, c.dim)
    S = idx.scores([q0[q] for q in qids])
    d = P.dense_items(c, idx, S)
    del idx
    out = Q.run_arm(qd, c, q0, next(x for x in Q.ARMS if x[0] == LEG), dn, time.monotonic() + 60 * budget_min)
    if out is None:
        raise SystemExit("time budget exceeded in the bm25_ml leg")
    runs, lat, errs = out
    b = Q.to_items(c, [p[3] for p in plan], runs)
    an = {DENSE: P.make_records(c.questions, c.gold_info, d), "leg": P.make_records(c.questions, c.gold_info, b), RRF: Q.client_rrf(c, d, b)}
    got = {"hit5": sum(P.hits5(an[RRF])), "pool25": sum(P.in_pool(an[RRF], 25))}
    blk = {DENSE: pool_block(c, an[DENSE], S), RRF: pool_block(c, an[RRF], S)}
    agg = {"job": "pools", "manifest": {k: v for k, v in c.man.items() if isinstance(v, (int, float, str))}, "repro": repro_check(got),
           "lists": {"dense_exact_q0": Q.arm_summary(c, an[DENSE]), "bm25_ml_leg": Q.arm_summary(c, an["leg"], lat, errs),
                     "client_rrf_k60": Q.arm_summary(c, an[RRF])},
           "dense_reference_pb2": {"dense_pool25": Q.PB2_REF["dense_pool25"], "dense_hit5": Q.PB2_REF["dense_hit5"]},
           "pool_docs": {k: doc_stats(v) for k, v in blk.items()},
           "indexing": {**up, "green_after_upsert_s": round(green_s, 1), "total_s": round(time.perf_counter() - t0, 1),
                        "final_status": info.get("status"), "points_count": info.get("points_count")},
           "leg": {"model": Q.MODEL, "options": Q.ML_OPTIONS, "limit": P.LEG_DEPTH}, "fusion": {"kind": "client memory-level RRF", "k": 60}}
    priv = {"n": len(qids), "types": [q["type"] for q in c.questions], "queries": [q["query"] for q in c.questions],
            "gold": [q["gold_memory_id"] for q in c.questions], **blk}
    return agg, priv


def render_pools(g: dict) -> str:
    r = g["repro"]
    L = ["## E-RET-PB6 stage 1: the hybrid RRF pool, rebuilt as PB5's follow-up did", "",
         "Client memory-level RRF k=60 over the exact q0 dense list and the Qdrant `qdrant/bm25` multilingual leg (limit 200 points, folded to memories, status-filtered). "
         "Counts, rate and Clopper-Pearson 95% interval.", "",
         f"Reproduction check (RRF alone): hit@5 {r['got']['hit5']} (expected {r['expected']['hit5']}, diff {r['diff']['hit5']}), "
         f"pool@25 {r['got']['pool25']} (expected {r['expected']['pool25']}, diff {r['diff']['pool25']}): {'OK' if r['ok'] else 'MISMATCH, the job stops here'}.", "",
         "| list | pool@25 | hit@5 | state hit@5 | fact hit@5 | < 25 | p50 ms | p95 ms |", "|---|---|---|---|---|---|---|---|"]
    for name, a in g["lists"].items():
        lt = a["latency_ms"] or {"p50": "", "p95": ""}
        L.append(f"| {name} | {H.fmt_rate(a['all']['pool25'])} | {H.fmt_rate(a['all']['hit5'])} | {H.fmt_rate(a['state']['hit5'])} | {H.fmt_rate(a['fact']['hit5'])} | "
                 f"{a['lt25_kept']} | {lt['p50']} | {lt['p95']} |")
    L += ["", f"Dense reference, PB2 / PB5 (not a gate): {json.dumps(g['dense_reference_pb2'], sort_keys=True)}.", "",
          f"Rerank documents (depth 25): {json.dumps(g['pool_docs'], sort_keys=True)}.", "", f"Indexing: {json.dumps(g['indexing'], sort_keys=True)}", ""]
    return "\n".join(L) + "\n"


def pools_cmd(a) -> int:
    cfg = read_json(a.smoke)
    c = P.load_corpus(a.corpus)
    Q._SCRUB["texts"] = P.corpus_texts(c)
    q0 = read_json(a.qvec)["variants"]["q0"]
    qd = Q.Qd(a.url)
    Q.wait_ready(qd)
    agg, priv = pools_core(qd, c, q0, cfg["dense_name"], cfg["ml"], a.budget_min)
    write_private(a.out, priv)
    Path(a.agg).write_text(json.dumps(agg, indent=1))
    Path(a.summary).write_text(render_pools(agg))
    r = agg["repro"]
    print("pools done; repro", json.dumps(r), flush=True)
    if not r["ok"] and not a.no_check:
        print("REPRODUCTION MISMATCH: stopping before any rerank", flush=True)
        return 2
    return 0


# ---------------------------------------------------------------- stage 2: int8 (PB3's recipe)
def int8_cmd(a) -> int:
    import rerank as R  # torch; only this subcommand imports it

    R.torch.set_num_threads(4)
    pk = read_json(a.pools)
    n, mems, docs = pk["n"], pk[RRF]["mems"], pk[RRF]["docs"]
    info = R.pin_and_licence(a.repo, a.rev)
    sc = R.Scorer(R.KIND["int8"], R.download(a.repo, a.rev))
    if not sc.sanity():
        raise SystemExit("scorer sanity check failed")
    warm = next((i for i, d in enumerate(docs) if d), None)
    if warm is not None:
        sc.score_query(pk["queries"][warm], docs[warm], a.length)  # untimed warm-up, as in PB1 / PB3
    hit, wall = [], []
    for i, q in enumerate(pk["queries"]):
        t = time.perf_counter()
        s = sc.score_query(q, docs[i], a.length)  # no character cut: the (query, document) pair is cut to L tokens, as PB3's ref
        wall.append(time.perf_counter() - t)
        order = sorted(range(len(s)), key=lambda j: (-s[j], j))  # ties keep pool order
        hit.append(int(pk["gold"][i] in [mems[i][j] for j in order[:5]]))
        if (i + 1) % 33 == 0:
            H.log(INT8, f"{i + 1}/{n} questions, {sum(wall):.0f}s")
    base = list(hit_bits(pk[RRF]["rank"]).values())
    write_private(a.bits, {"n": n, INT8: hit})
    agg = {"job": "int8", "arm": INT8, "length": a.length, "depth": POOL,
           "env": {"machine": platform.machine(), "cpus": os.cpu_count(), "python": sys.version.split()[0], "torch": R.torch.__version__},
           "model": info, "hit5": H.rate(sum(hit), n), "hit5_by_type": by_type(pk["types"], hit), "rrf_hit5": H.rate(sum(base), n),
           "mcnemar_vs_rrf": {"A": RRF, "B": INT8, **H.mcnemar(base, hit)},
           "latency_s": {"n": len(wall), "p50": round(H.pct(wall, .5), 3), "p95": round(H.pct(wall, .95), 3), "mean": round(sum(wall) / len(wall), 3)}}
    Path(a.agg).write_text(json.dumps(agg, indent=1))
    Path(a.summary).write_text(render_int8(agg))
    print("int8 done", json.dumps({"hit5": agg["hit5"]["k"], "rrf": agg["rrf_hit5"]["k"]}), flush=True)
    return 0


def render_int8(g: dict) -> str:
    m, t = g["mcnemar_vs_rrf"], g["latency_s"]
    return "\n".join([
        f"## E-RET-PB6 stage 2: bge-reranker-base ONNX int8, L{g['length']}, depth {g['depth']}, on the RRF pool (PB3's recompute recipe)", "",
        "| arm | hit@5 | state | fact | RRF alone hit@5 | N | b | c | p | per query p50 s | p95 s |", "|---|---|---|---|---|---|---|---|---|---|---|",
        f"| {g['arm']} | {H.fmt_rate(g['hit5'])} | {H.fmt_rate(g['hit5_by_type']['state'])} | {H.fmt_rate(g['hit5_by_type']['fact'])} | {H.fmt_rate(g['rrf_hit5'])} | "
        f"{m['N']} | {m['b']} | {m['c']} | {m['p']} | {t['p50']} | {t['p95']} |", "",
        f"Runner: {json.dumps(g['env'], sort_keys=True)}; model {json.dumps(g['model'], sort_keys=True)}.", ""]) + "\n"


def read_i8(path: str | None, n: int):
    """Per-question int8 bits written by `int8`; None when absent or malformed (the int8 comparisons then print not_applicable with the missing arm name)."""
    try:
        d = read_json(path) if path else None
        return d if d and d.get("n") == n and len(d.get(INT8, [])) == n and set(d[INT8]) <= {0, 1} else None
    except (OSError, ValueError, TypeError, AttributeError):
        return None


# ---------------------------------------------------------------- stage 3: cloud arms and comparisons
def cloud_core(key: str, base: str, arms, max_tokens: int, pk: dict, i8, rtt) -> dict:
    """Every arm in turn (4 workers each), then every comparison of TIERS. A fatal stop (401/402/403, quota or billing code) ends the job:
    later arms are not sent. Any other stop ends only that arm. Returns aggregates only."""
    n = pk["n"]
    pack = {"questions": [{"gold_memory_id": g} for g in pk["gold"]]}
    an = {p: [{"type": t, "rank": r, "kept_list": m} for t, r, m in zip(pk["types"], pk[p]["rank"], pk[p]["mems"])] for p in (RRF, DENSE)}
    docs = {p: [cut(d) for d in pk[p]["docs"]] for p in (RRF, DENSE)}
    hits: dict[str, dict[int, int]] = {p: hit_bits(pk[p]["rank"]) for p in (RRF, DENSE)}
    if i8 is not None:
        hits[INT8] = dict(enumerate(i8[INT8]))
    rtt_s = rtt["tcp_connect_ms"]["p50"] / 1000 if rtt and rtt.get("tcp_connect_ms", {}).get("p50") is not None else None
    out: dict = {"job": "cloud", "config": {"workers": C.WORKERS, "retries": C.RETRIES, "pool": POOL, "max_chars": C.MAXCH, "max_input_tokens_per_arm": max_tokens,
                                            "max_consecutive_failures": C.MAX_FAILS, "top_n": "len(documents) = all scores", "instruct": "not sent (documented default)",
                                            "endpoint_host": urllib.parse.urlsplit(base).hostname, "endpoint_path": C.PATH, "list_price_cny_per_m_tokens": {m: C.MODELS[m] for m in sorted({m for m, _ in arms})}},
                 "baselines": {p: H.rate(sum(hits[p].values()), n) for p in (RRF, DENSE)}, "arms": [], "stops": [], "comparisons": [], "rtt": rtt}
    fatal = False
    for model, pool in arms:
        name = arm_name(model, pool)
        if fatal:
            out["arms"].append({"arm": name, "not_run": True})
            continue
        ctx = J.Ctx(key, base, model, max_tokens)
        ctx.cl = C.Client(base, key)
        res = C.run_arm(ctx, pk["queries"], docs[pool])
        s, hits[name] = C.arm_summary(ctx, C.MODELS[model], res, pack, an[pool], rtt_s)
        s.update({"arm": name, "pool": pool, "http_codes": dict(ctx.codes), "ratelimit": {"retry_after_s": sorted(ctx.retry_after), "headers": ctx.hdrs}})
        out["arms"].append(s)
        print("ARM", json.dumps(s), flush=True)  # aggregates only; survives a later failure
        if ctx.stop is not None:
            out["stops"].append({"arm": name, **ctx.stop.info()})
            print("STOP", json.dumps(out["stops"][-1]), flush=True)
            fatal = ctx.stop.fatal
    for tier, b, a in TIERS:
        miss = [x for x in (a, b) if x not in hits]
        out["comparisons"].append({"tier": tier, "A": a, "B": b, "not_applicable": "missing arm(s): " + ", ".join(miss)} if miss
                                  else {"tier": tier, **J.paired(f"{b} vs {a}", a, b, hits[a], hits[b])})
    ran = [x for x in out["arms"] if not x.get("not_run")]
    out["totals"] = {"calls": sum(x["calls"] for x in ran), "tokens": sum(x["tokens"]["total"] for x in ran),
                     "cost_cny": round(sum(x["tokens"]["total"] * x["price_cny_per_m_tokens"] / 1e6 for x in ran), 4)}
    out["fatal"] = fatal
    return out


def render_cloud(o: dict) -> str:
    g = lambda v: "n/a" if v is None else v  # noqa: E731
    c, b = o["config"], o["baselines"]
    L = ["## E-RET-PB6 stage 3: DashScope cloud rerank on the hybrid RRF pool and on the dense pool", "",
         f"Endpoint host `{c['endpoint_host']}`, path `{c['endpoint_path']}`. One call per query: `query` + up to {c['pool']} documents (title + newline + best chunk, cut to "
         f"{c['max_chars']} characters, as PB3 / PB4), `top_n` = number of documents (all scores), `instruct` not sent. Concurrency {c['workers']}, keep-alive connections, up to "
         f"{c['retries']} retries on 429, 5xx and network errors. Rank = relevance_score, ties and unscored documents by pool order.", "",
         f"Baselines on the same questions: RRF alone hit@5 {H.fmt_rate(b[RRF])}; dense alone hit@5 {H.fmt_rate(b[DENSE])}.", "",
         "| arm | queries | hit@5 | state | fact | pool ceiling | rank 5/6 ties | calls ok/total | answers missing |", "|---|---|---|---|---|---|---|---|---|"]
    ms = [m for m in o["arms"] if not m.get("not_run")]
    L += [f"| {m['arm']} | {m['queries']} | {H.fmt_rate(m['hit5'])} | {H.fmt_rate(m['hit5_by_type']['state'])} | {H.fmt_rate(m['hit5_by_type']['fact'])} | "
          f"{H.fmt_rate(m['pool_ceiling'])} | {m['ties_at_5_6']} | {m['calls_ok']}/{m['calls']} | {m['answers_missing']} |" for m in ms]
    L += [f"| {m['arm']} | not run |" + " |" * 7 for m in o["arms"] if m.get("not_run")]
    L += ["", "| arm | latency per call p50 / p95 / max s | ttfb p50 / p95 s | server est. p50 / p95 s (call - RTT) | tokens total | per query | CNY per query | CNY per 1,000 queries |",
          "|---|---|---|---|---|---|---|---|"]
    for m in ms:
        w, t, se = m["latency_s"]["call"], m["latency_s"]["ttfb"], m.get("server_est_s", {})
        L.append(f"| {m['arm']} | {g(w['p50'])} / {g(w['p95'])} / {g(w['max'])} | {g(t['p50'])} / {g(t['p95'])} | {g(se.get('p50'))} / {g(se.get('p95'))} | "
                 f"{m['tokens']['total']} | {g(m['tokens']['per_query_mean'])} | {g(m['cost_cny']['per_query'])} | {g(m['cost_cny']['per_1000_queries'])} |")
    L += ["", f"List prices used (CNY per million input tokens, PB4): {json.dumps(c['list_price_cny_per_m_tokens'], sort_keys=True)}.", "",
          "Paired comparisons, exact McNemar on the same questions, named \"B vs A\" (A = baseline; b = A hit and B miss, c = A miss and B hit):", "",
          "| tier | B vs A | N | b | c | p |", "|---|---|---|---|---|---|"]
    for x in o["comparisons"]:
        L.append(f"| {x['tier']} | {x['B']} vs {x['A']} | " + (f"{x['N']} | {x['b']} | {x['c']} | {x['p']} |" if "N" in x else f"not_applicable: {x['not_applicable']} | | | |"))
    r = o.get("rtt")
    if r:
        L += ["", f"Runner to endpoint, {r['n']} probes of an unauthenticated request (ms, p50 / p95 / max): TCP connect (one RTT) {r['tcp_connect_ms']['p50']} / "
              f"{r['tcp_connect_ms']['p95']} / {r['tcp_connect_ms']['max']}; first byte on a warm connection {r['ttfb_warm_ms']['p50']} / {r['ttfb_warm_ms']['p95']} / {r['ttfb_warm_ms']['max']}."]
    for m in ms:
        L.append(f"HTTP status per attempt, {m['arm']} (net = no response): {json.dumps(m['http_codes'], sort_keys=True)}; Retry-After seconds seen = "
                 f"{m['ratelimit']['retry_after_s']}; connections opened {m['connections_opened']}.")
    t = o["totals"]
    L.append(f"Totals: {t['calls']} calls in finished queries; tokens billed by the API = {t['tokens']}; at list price {t['cost_cny']} CNY.")
    for s in o["stops"]:
        L.append(f"STOP arm={s['arm']} http={s['http']} why={s['why']} codes={s['codes']} message={s['message']!r} fatal={s['fatal']}")
    return "\n".join(L) + "\n"


def parse_arms(spec: str):
    names = {arm_name(m, p): (m, p) for m, p in ARMS}
    bad = [x for x in spec.split(",") if x not in names]
    if bad:
        raise SystemExit(f"unknown arm(s): {bad}")
    return [names[x] for x in spec.split(",") if x]


def cloud_cmd(a) -> int:
    key = os.environ["ALIBABA_CLOUD_API_KEY"].strip()
    pk = read_json(a.pools)
    out = cloud_core(key, C.BASE, parse_arms(a.arms), a.max_tokens, pk, read_i8(a.int8, pk["n"]), C.load_rtt(a.rtt))
    Path(a.out).write_text(json.dumps(out, indent=1))
    Path(a.summary).write_text(render_cloud(out))
    print("done", json.dumps({"arms": [(x["arm"], x.get("queries"), x.get("calls")) for x in out["arms"]], "stops": len(out["stops"]), **out["totals"]}), flush=True)
    return 3 if out["fatal"] else 0


# ---------------------------------------------------------------- guard
def literals(path) -> set[str]:
    return {n.value for n in ast.walk(ast.parse(Path(path).read_text())) if isinstance(n, ast.Constant) and isinstance(n.value, str) and len(n.value) >= 2}


def static_for(files: list[str]) -> set[str]:
    """Code-owned strings exempt from the window check: cloud_rerank.static_for (harness.static_strings, the literals of cloud_rerank.py and
    jev_rerank.py, the endpoint host) plus the literals of this file and of qdrant_sparse.py (arm names, labels)."""
    return C.static_for(files) | literals(__file__) | literals(Q.__file__)


def guard_check(texts: list[str], files: list[str], static: set[str] | None = None) -> list:
    return H.guard_findings(texts, files, static_for(files) if static is None else static)


def guard_cmd(a) -> int:
    c = P.load_corpus(a.corpus)
    files = [f for f in a.files if Path(f).exists()]
    hits = guard_check(P.corpus_texts(c), files)
    if hits:  # offsets only; never the text
        raise SystemExit(f"GUARD FAILED: {len(hits)} corpus window(s) in outputs, distinct places (file, offset): {sorted(set(hits))[:12]}")
    print(f"guard ok: {len(files)} file(s) scanned against {len(P.corpus_texts(c))} corpus texts")
    return 0


# ---------------------------------------------------------------- selftest and smoke
def fake_pk(n: int = 3) -> dict:
    """Synthetic private pools. Gold of question q sits at 1-based position RRF_POS[q] of the RRF pool and DENSE_POS[q] of the dense pool (None = outside
    the pool). The fake endpoint puts every document containing NEEDLE first. One document is longer than the cloud cut."""
    rrf_pos, dense_pos = [7, 3, None], [None, 3, 9]
    pk: dict = {"n": n, "types": ["state", "fact", "state"][:n], "queries": [f"fake query {q}" for q in range(n)], "gold": [f"g{q}" for q in range(n)]}
    for name, pos in ((RRF, rrf_pos), (DENSE, dense_pos)):
        mems, docs, rank = [], [], []
        for q in range(n):
            ms = [f"g{q}" if pos[q] == p else f"m{name}{q}_{p}" for p in range(1, POOL + 1)]
            mems.append(ms)
            docs.append([f"title {q} {p}\nchunk text {q} {p}" + (" NEEDLE" if m == f"g{q}" else "") + (" long" * 400 if (name, q, p) == (RRF, 0, 1) else "")
                         for p, m in enumerate(ms, 1)])
            rank.append(pos[q])
        pk[name] = {"mems": mems, "docs": docs, "rank": rank}
    return pk


def selftest(_a=None):
    # orientation of the paired McNemar: "B vs A", b = A hit and B miss, c = A miss and B hit
    pr = J.paired("x", "a", "b", {0: 1, 1: 1, 2: 0, 3: 0}, {0: 0, 1: 1, 2: 1, 3: 1})
    assert (pr["N"], pr["b"], pr["c"]) == (4, 1, 2), pr
    # reproduction gate and cloud document cut
    assert repro_check({"hit5": 96, "pool25": 147})["ok"] and repro_check({"hit5": 96, "pool25": 147})["diff"] == {"hit5": 0, "pool25": 0}
    assert not repro_check({"hit5": 95, "pool25": 148})["ok"] and repro_check({"hit5": 95, "pool25": 148})["diff"] == {"hit5": -1, "pool25": 1}
    assert cut(["a" * 1500, "", "t"]) == ["a" * 1000, "-", "t"]
    assert hit_bits([1, 5, 6, None]) == {0: 1, 1: 1, 2: 0, 3: 0}
    assert [tuple(x[:2]) for x in TIERS][0] == ("primary", "gte-rerank-v2@rrf") and len({(b, a) for _, b, a in TIERS}) == len(TIERS)
    assert {arm_name(m, p) for m, p in ARMS} <= {x for _, b, a in TIERS for x in (a, b)} and len(ARMS) <= 4  # the card's budget: at most 4 arms
    assert parse_arms("gte-rerank-v2@dense") == [("gte-rerank-v2", DENSE)]
    try:
        parse_arms("nope@rrf")
        raise AssertionError("unknown arm accepted")
    except SystemExit:
        pass
    pk = fake_pk()
    i8 = {"n": 3, INT8: [1, 0, 0]}
    tmp = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / f"eret_rrfrr_selftest_{os.getpid()}"
    tmp.mkdir(parents=True, exist_ok=True)

    def go(mode, i8_=None, arms=ARMS):
        srv, base, lg = C._fake_dash(mode)
        try:
            out = cloud_core("fake-dash-key", base, arms, 0, pk, i8_, None)
            return out, lg, json.dumps(out) + render_cloud(out)
        finally:
            srv.shutdown()

    try:
        # ok: every request is 25 documents, cut to MAXCH, correct shape; every arm lifts a NEEDLE document into the top 5
        out, lg, everything = go("ok", i8)
        by = {x["arm"]: x for x in out["arms"]}
        assert sorted(lg["sizes"]) == [25] * 9 and lg["maxlen"] == C.MAXCH and not lg["bad"] and not out["stops"] and not out["fatal"], (lg, out["stops"])
        assert [(x["hit5"]["k"], x["hit5"]["n"], x["calls_ok"]) for x in out["arms"]] == [(2, 3, 3), (2, 3, 3), (2, 3, 3)], out["arms"]
        assert out["baselines"][RRF]["k"] == 1 and out["baselines"][DENSE]["k"] == 1 and out["totals"]["calls"] == 9 and out["totals"]["tokens"] > 0
        assert abs(by["gte-rerank-v2@rrf"]["cost_cny"]["per_1000_queries"] - by["gte-rerank-v2@rrf"]["tokens"]["per_query_mean"] * 0.8 / 1e3) < 1e-3
        cm = {(x["B"], x["A"]): x for x in out["comparisons"]}
        assert len(out["comparisons"]) == len(TIERS) and out["comparisons"][0]["tier"] == "primary" and all("N" in x for x in out["comparisons"]), out["comparisons"]
        # rrf alone [0,1,0], gte@rrf [1,1,0] -> b0 c1; int8 [1,0,0] vs rrf -> b1 c1; gte@dense [0,1,1] vs gte@rrf -> b1 c1; gte@rrf = qwen3@rrf; gte@rrf vs int8 -> b0 c1; gte@dense vs dense [0,1,0] -> b0 c1
        for key, want in ((("gte-rerank-v2@rrf", RRF), (0, 1)), (("qwen3-rerank@rrf", RRF), (0, 1)), ((INT8, RRF), (1, 1)),
                          (("gte-rerank-v2@rrf", "gte-rerank-v2@dense"), (1, 1)), (("gte-rerank-v2@rrf", "qwen3-rerank@rrf"), (0, 0)),
                          (("gte-rerank-v2@rrf", INT8), (0, 1)), (("gte-rerank-v2@dense", DENSE), (0, 1))):
            assert (cm[key]["N"], cm[key]["b"], cm[key]["c"]) == (3, *want), (key, cm[key])
        for leak in ("chunk text", "fake query", "NEEDLE", "title 0"):
            assert leak not in everything, leak
        # without int8 bits: the int8 comparisons print the missing arm name instead of a number
        out, _, _ = go("ok", None)
        na = [x for x in out["comparisons"] if "not_applicable" in x]
        assert len(na) == 3 and all(INT8 in x["not_applicable"] for x in na) and out["comparisons"][0]["tier"] == "primary" and "N" in out["comparisons"][0]
        # 401: the whole job stops with the raw code, later arms are not sent, their comparisons say which arm is missing
        out, lg, everything = go("auth")
        assert out["fatal"] and out["stops"][0]["http"] == 401 and all(x.get("not_run") for x in out["arms"][1:]) and len(lg["sizes"]) <= 4, (out["stops"], lg)
        assert any("qwen3-rerank@rrf" in x.get("not_applicable", "") for x in out["comparisons"]) and "NEEDLE" not in everything
        # Arrearage (400) and an exhausted allocation (429) are quota or billing stops with their raw codes
        out, _, _ = go("arrears")
        assert (out["stops"][0]["http"], out["stops"][0]["why"], out["stops"][0]["codes"], out["fatal"]) == (400, "quota_or_billing", ["Arrearage"], True), out["stops"]
        out, _, _ = go("quota")
        assert (out["stops"][0]["http"], out["stops"][0]["why"], out["fatal"]) == (429, "quota_or_billing", True), out["stops"]
        # any other 4xx stops only that arm; the echoed document never reaches the outputs
        out, _, everything = go("bad400")
        assert [x["why"] for x in out["stops"]] == ["http_400"] * 3 and not out["fatal"] and "NEEDLE" not in everything and "chunk text" not in everything, out["stops"]
        # guard: a leaked window fails, clean output passes, an arm label that also occurs in the corpus is exempt (this file's literals)
        import random
        rnd = "".join(random.Random(7).choice("bcdfghjklmnpqrstvwxz") for _ in range(60))  # consonants only: short code literals cannot cover it
        label = "gte-rerank-v2@rrf"
        texts = [rnd, f"notes about {label} scoring"]
        bad, good, rep = tmp / "bad.md", tmp / "good.md", tmp / "report.json"
        bad.write_text("| x | 1 |\nleak: " + rnd[5:55])
        good.write_text(f"| {label} | 12/198 = 0.061 | 0.123456789012 |")
        out, _, text = go("ok", i8)
        rep.write_text(json.dumps(out, indent=1))
        (tmp / "report.md").write_text(text)
        assert guard_check(texts, [str(bad)]), "guard missed a leaked window"
        assert not guard_check(texts, [str(good)]), "guard flagged clean output or an exempt label"
        assert H.guard_findings(texts, [str(good)], set()), "without the exemption the label must be flagged"
        assert not guard_check(texts, [str(rep), str(tmp / "report.md")]), "guard flagged a clean report"
        # int8 bits reader: absent, wrong length, good
        (tmp / "i8.json").write_text(json.dumps({"n": 3, INT8: [1, 0, 0]}))
        (tmp / "i8bad.json").write_text(json.dumps({"n": 3, INT8: [1, 0]}))
        assert read_i8(str(tmp / "i8.json"), 3) is not None and read_i8(str(tmp / "i8bad.json"), 3) is None and read_i8(str(tmp / "none.json"), 3) is None and read_i8(None, 3) is None
        # private pool file mode
        write_private(str(tmp / "p.json"), {"x": 1})
        assert oct((tmp / "p.json").stat().st_mode & 0o777) == "0o600"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("selftest rrf_rerank ok")


def smoke(a):
    """Fake corpus against the live Qdrant: pools, private file round trip, the cloud arms against the fake endpoint, comparisons, render and guard."""
    cfg = read_json(a.smoke)
    qd = Q.Qd(a.url)
    Q.wait_ready(qd)
    tmp = Path(tempfile.mkdtemp(prefix="pb6smoke_", dir=os.environ.get("RUNNER_TEMP")))
    try:
        P.fake_corpus_tar(str(tmp / "c.tar"))
        c = P.load_corpus(str(tmp / "c.tar"))
        agg, priv = pools_core(qd, c, Q.fake_q0(), cfg["dense_name"], cfg["ml"], 5)
        assert priv["n"] == 4 and set(agg["repro"]["got"]) == {"hit5", "pool25"} and not agg["repro"]["ok"], agg["repro"]  # toy data cannot hit 96 / 147
        for name in (RRF, DENSE):
            b = priv[name]
            assert len(b["mems"]) == len(b["docs"]) == len(b["rank"]) == 4 and all(len(m) == len(d) <= POOL for m, d in zip(b["mems"], b["docs"])), name
        assert priv[DENSE]["rank"][0] == 1 and priv[DENSE]["docs"][0][0].startswith("title alpha\n"), priv[DENSE]["rank"]  # q1: m1 first, title + newline + chunk
        render_pools(agg)
        write_private(str(tmp / "pools.json"), priv)
        pk = read_json(str(tmp / "pools.json"))
        ne = lambda name: sum(1 for m in pk[name]["mems"] if m)  # noqa: E731
        srv, base, lg = C._fake_dash("ok")
        try:
            out = cloud_core("fake-dash-key", base, ARMS, 0, pk, {"n": 4, INT8: [1, 0, 0, 0]}, None)
        finally:
            srv.shutdown()
        assert len(lg["sizes"]) == 2 * ne(RRF) + ne(DENSE) and not lg["bad"] and not out["stops"] and len(out["comparisons"]) == len(TIERS), (lg, out["stops"])
        assert all("N" in x and x["N"] == 4 for x in out["comparisons"]), out["comparisons"]
        files = []
        for nm, obj, txt in (("pools", agg, render_pools(agg)), ("cloud", out, render_cloud(out))):
            (tmp / f"{nm}.json").write_text(json.dumps(obj, indent=1))
            (tmp / f"{nm}.md").write_text(txt)
            files += [str(tmp / f"{nm}.json"), str(tmp / f"{nm}.md")]
        assert not guard_check(P.corpus_texts(c), files), "guard flagged the toy outputs"
        leak = tmp / "leak.md"
        leak.write_text("note: " + c.chunks[0][4] + c.chunks[1][4])
        assert guard_check(P.corpus_texts(c), [str(leak)], set()), "guard missed a leaked toy chunk"
        print("smoke ok:", len(out["comparisons"]), "comparisons,", len(lg["sizes"]), "fake rerank calls, pool docs", json.dumps(agg["pool_docs"], sort_keys=True), flush=True)
    finally:
        try:
            qd.call("DELETE", f"/collections/{Q.COLL}")
        except Q.QdrantHttp:
            pass  # the collection was never created: keep the original error
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    sp.add_parser("selftest")
    url = os.environ.get("QDRANT_URL", "http://127.0.0.1:6333")
    s = sp.add_parser("smoke")
    s.add_argument("--smoke", required=True)
    s.add_argument("--url", default=url)
    p = sp.add_parser("pools")
    for k in ("corpus", "qvec", "smoke", "out", "agg", "summary"):
        p.add_argument("--" + k, required=True)
    p.add_argument("--url", default=url)
    p.add_argument("--budget-min", dest="budget_min", type=float, default=30.0)
    p.add_argument("--no-check", dest="no_check", action="store_true")
    i = sp.add_parser("int8")
    for k in ("pools", "bits", "agg", "summary"):
        i.add_argument("--" + k, required=True)
    i.add_argument("--repo", default=REPO)
    i.add_argument("--rev", default=REV)
    i.add_argument("--length", type=int, default=LENGTH)
    r = sp.add_parser("cloud")
    for k in ("pools", "out", "summary"):
        r.add_argument("--" + k, required=True)
    r.add_argument("--int8")
    r.add_argument("--rtt")
    r.add_argument("--arms", default=",".join(arm_name(m, q) for m, q in ARMS))
    r.add_argument("--max-tokens", dest="max_tokens", type=int, default=0, help="tripwire on total billed tokens per arm (0 = off)")
    g = sp.add_parser("guard")
    g.add_argument("--corpus", required=True)
    g.add_argument("--files", nargs="+", required=True)
    a = ap.parse_args()
    try:
        rc = {"selftest": selftest, "smoke": smoke, "pools": pools_cmd, "int8": int8_cmd, "cloud": cloud_cmd, "guard": guard_cmd}[a.cmd](a)
        sys.exit(rc or 0)
    except SystemExit:
        raise
    except Q.QdrantHttp as ex:
        print(f"FAILED QdrantHttp http={ex.http} message={ex.msg!r}", flush=True)
        sys.exit(1)
    except Exception as ex:  # class and source line only: messages and locals can carry corpus text or the key
        fr = traceback.extract_tb(ex.__traceback__)
        print(f"FAILED {type(ex).__name__} at " + " <- ".join(f"{Path(x.filename).name}:{x.lineno}:{x.name}" for x in reversed(fr[-4:])), flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
