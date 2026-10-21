#!/usr/bin/env python3
"""E-RET-PB4 (E-RET-5d): DashScope cloud text-rerank models on the PB1 depth-25 pools. Experiment, not product code.

Subcommands:
  rtt       10 probes of the runner's round trip to the endpoint: DNS, TCP connect, TLS, and time to first byte of an UNAUTHENTICATED
            request (fresh and warm connection). No key is sent.
  run       one rerank call per query and model (25 documents = title + newline + best chunk, cut to 1,000 characters as PB3 did),
            4 workers, keep-alive connections. Needs ALIBABA_CLOUD_API_KEY in this step's env; stdlib only. Output = aggregates only.
  guard     fail if any 12-character window of corpus text occurs in the given output files (as jev_rerank.py).
  selftest  statistics, request shape, retries, stop rules and the no-leak error path against a fake endpoint (no network, no key).

Privacy: as harness.py / jev_rerank.py. Documents and queries go to Alibaba Cloud Model Studio (DashScope, cn-beijing) only from the
`run` step inside CI, as card E-RET-PB4 asks (owner, 2026-10-21: the cloud rerank must be tested). Error bodies are never printed
whole (a 400 may echo the input): only the HTTP status, identifier-like codes, and for 401/402/403/quota a short message that is
withheld if it overlaps the request text. Pool, fold, McNemar, intervals and the guard come from harness.py / jev_rerank.py.

API authority (Alibaba Cloud Model Studio, read 2026-10-21): text-rerank API reference (help.aliyun.com/zh/model-studio/text-rerank-api;
English: alibabacloud.com/help/en/model-studio/text-rerank-api, updated 2026-10-12): POST .../api/v1/services/rerank/text-rerank/text-rerank,
body {model, input{query, documents[]}, parameters{top_n, return_documents, instruct}}, answer output.results[]{index, relevance_score},
usage.total_tokens. Endpoint: the documented examples use the workspace domain {WorkspaceId}.cn-beijing.maas.aliyuncs.com; the regions
page (help.aliyun.com/zh/model-studio/regions) still lists dashscope.aliyuncs.com for cn-beijing as the legacy domain, which is what this
card's key (the embeddings key of PB1) is known to reach. Per-model info pages give the CNY list prices used below.
"""
from __future__ import annotations

import argparse
import ast
import collections
import concurrent.futures as cf
import contextlib
import http.client
import http.server
import io
import json
import os
import random
import re
import shutil
import socket
import ssl
import sys
import threading
import time
import traceback
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import harness as H  # noqa: E402  (stdlib only: statistics, pack fold, guard)
import jev_rerank as J  # noqa: E402  (stdlib only: Ctx, Stop, pool, paired/unpaired, error-body helpers)

BASE = "https://dashscope.aliyuncs.com"
PATH = "/api/v1/services/rerank/text-rerank/text-rerank"
UA = "humaux-eret-pb4/1.0"
POOL, MAXCH = J.POOL, J.MAXCH  # depth 25; 1,000 characters per document, as PB3 (the documented limits are in tokens and far higher)
WORKERS, RETRIES, TIMEOUT = 4, 3, 120
BACKOFF = 2.0  # seconds before the first retry, doubled per retry (+25% jitter); selftest sets 0
MAX_FAILS = 12  # consecutive failed calls that stop an arm
# Text rerank models of the cn-beijing deployment (Chinese model pages and rate-limit page, read 2026-10-21) and their list price in CNY
# per million input tokens (output is 0). Skipped: qwen3-vl-rerank (multimodal; the card tests text rerank models, at most 3).
# Order = run order: the two models documented for the legacy domain first, the newest (qwen3.7, workspace-domain docs only) last, so a 403/404
# on it cannot cost the others their numbers.
MODELS = {"qwen3-rerank": 0.5, "gte-rerank-v2": 0.8, "qwen3.7-text-rerank": 0.5}
JEV_J1 = 84  # PB3 run 39609374444, J1 hit@5 out of 198 (per-question bits were not stored): comparisons against it are unpaired
# 429 is a rate limit (retry) unless its code names an exhausted allocation; Arrearage / FreeTierOnly / balance words are the owner's to settle
QUOTA_RE = re.compile(r"arrear|allocationquota|freetier|quotaexceed|insufficient|balance|overdue|billing|payment|credit", re.I)


def lat_stats(xs) -> dict:
    if not xs:
        return {"n": 0, "p50": None, "p95": None, "max": None}
    return {"n": len(xs), "p50": round(H.pct(xs, .5), 3), "p95": round(H.pct(xs, .95), 3), "max": round(max(xs), 3)}


# ---------------------------------------------------------------- HTTP
class Client:
    """Per-thread keep-alive connection to one host. `connect_ms` = TCP + TLS time of every connection opened."""

    def __init__(self, base: str, key: str):
        u = urllib.parse.urlsplit(base)
        self.https = u.scheme == "https"
        self.host, self.port = u.hostname, u.port or (443 if self.https else 80)
        self.headers = {"Authorization": "Bearer " + key, "Content-Type": "application/json", "Accept": "application/json", "User-Agent": UA}
        self.local, self.lock, self.connect_ms = threading.local(), threading.Lock(), []

    def _drop(self):
        c, self.local.c = getattr(self.local, "c", None), None
        if c is not None:
            with contextlib.suppress(Exception):
                c.close()

    def post(self, body: bytes) -> dict:
        """One attempt. {code, raw, hdr, ttfb, total}: code is None after a network failure. A stale kept-alive connection is replaced
        once without counting as a failure."""
        code, raw, hdr, ttfb, t0 = None, b"", {}, None, time.perf_counter()
        for _ in range(2):
            c, reused = getattr(self.local, "c", None), True
            try:
                if c is None:
                    reused = False
                    c = (http.client.HTTPSConnection if self.https else http.client.HTTPConnection)(self.host, self.port, timeout=TIMEOUT)
                    tc = time.perf_counter()
                    c.connect()
                    with self.lock:
                        self.connect_ms.append((time.perf_counter() - tc) * 1000)
                    self.local.c = c
                t0 = time.perf_counter()
                c.request("POST", PATH, body=body, headers=self.headers)
                r = c.getresponse()
                ttfb = time.perf_counter() - t0
                raw, code = r.read(), r.status
                hdr = {k.lower(): v for k, v in r.getheaders()}
                if hdr.get("connection", "").lower() == "close":
                    self._drop()
                break
            except (OSError, http.client.HTTPException):
                self._drop()
                if not reused:
                    break
        return {"code": code, "raw": raw, "hdr": hdr, "ttfb": ttfb, "total": time.perf_counter() - t0}


def err_stop(ctx, r: dict, body: bytes) -> J.Stop | None:
    """Stop rule of card E-RET-PB4. 401/402/403 and quota or billing codes (Arrearage ...) end the whole job; any other 4xx except 429
    ends this model's arm; 429, 5xx and network errors are retried by the caller (None here)."""
    code = r["code"]
    ids = J.err_idents(r["raw"]) if code is not None else []
    text = r["raw"][:2000].decode("utf-8", "replace") if code in (401, 402, 403, 429) else ""  # a 400 body may echo the input
    quota = bool(QUOTA_RE.search(" ".join(ids) + " " + text))
    if code in (401, 402, 403) or quota:
        return J.Stop(code, ids, J.msg_of(r["raw"], body.decode("utf-8", "replace"), ctx.key), "quota_or_billing" if quota else f"http_{code}", True)
    if code is not None and code != 429 and code < 500:
        return J.Stop(code, ids, "", f"http_{code}", False)
    return None


def failed(ctx, r: dict, attempt: int, wall: float, n: int) -> dict:
    """A call that ended without usable scores (retries exhausted, or a 200 without valid results). Counts toward the breaker."""
    with ctx.lock:
        ctx.fails += 1
        trip = ctx.fails >= MAX_FAILS
    if trip:
        raise J.Stop(r["code"], J.err_idents(r["raw"]) if r["code"] else [], "", "consecutive_failures", False)
    return {"ok": False, "code": r["code"], "lat": r["total"], "ttfb": r["ttfb"], "wall": wall, "attempts": attempt + 1, "tokens": 0, "ptokens": 0,
            "missing": n, "scores": {}}


def parse_ok(ctx, r: dict, attempt: int, wall: float, n: int) -> dict:
    scores, tok, ptok = {}, 0, 0
    try:
        j = json.loads(r["raw"])
    except ValueError:
        j = None
    if isinstance(j, dict):
        out = j.get("output") if isinstance(j.get("output"), dict) else {}
        for x in out.get("results") or []:
            i, s = (x.get("index"), x.get("relevance_score")) if isinstance(x, dict) else (None, None)
            if isinstance(i, int) and not isinstance(i, bool) and 0 <= i < n and isinstance(s, (int, float)) and not isinstance(s, bool):
                scores[i] = float(s)
        u = j.get("usage") if isinstance(j.get("usage"), dict) else {}
        tok, ptok = J.num(u.get("total_tokens")), J.num(u.get("prompt_tokens"))
    if not scores:
        return failed(ctx, r, attempt, wall, n)
    with ctx.lock:
        ctx.tokens += tok
        ctx.fails = 0
    return {"ok": True, "code": 200, "lat": r["total"], "ttfb": r["ttfb"], "wall": wall, "attempts": attempt + 1, "tokens": tok, "ptokens": ptok,
            "missing": n - len(scores), "scores": scores}


def call(ctx, query: str, docs: list[str]) -> dict:
    """One rerank call: all docs ranked (top_n = len(docs)). Raises J.Stop on a stop rule. Retries 429, 5xx and network errors up to
    RETRIES times with exponential backoff plus jitter, Retry-After honoured up to 60 s."""
    body = json.dumps({"model": ctx.model, "input": {"query": query, "documents": docs}, "parameters": {"top_n": len(docs)}},
                      ensure_ascii=False).encode("utf-8")
    t_all = time.perf_counter()
    for attempt in range(RETRIES + 1):
        if ctx.stop is not None:
            raise ctx.stop
        if ctx.max_tokens and ctx.tokens >= ctx.max_tokens:
            raise J.Stop(None, [], "", "token_cap", True)
        r = ctx.cl.post(body)
        ctx.note(r["code"], r["hdr"])
        if r["code"] == 200:
            return parse_ok(ctx, r, attempt, time.perf_counter() - t_all, len(docs))
        stop = err_stop(ctx, r, body)
        if stop is not None:
            raise stop
        if attempt < RETRIES:
            wait = BACKOFF * 2 ** attempt
            ra = r["hdr"].get("retry-after", "")
            if re.fullmatch(r"\d+(\.\d+)?", ra):
                wait = max(wait, min(float(ra), 60.0))
                with ctx.lock:
                    if len(ctx.retry_after) < 50:
                        ctx.retry_after.append(float(ra))
            time.sleep(wait * (1 + 0.25 * random.random()))
            continue
        return failed(ctx, r, attempt, time.perf_counter() - t_all, len(docs))
    raise AssertionError("unreachable")


def run_query(ctx, qi: int, query: str, docs: list[str]) -> dict:
    if not docs:  # an empty pool (gold outside the dense candidates): nothing to rerank, scored as the dense order like a failed call
        return {"qi": qi, "rec": None}
    try:
        return {"qi": qi, "rec": call(ctx, query, docs)}
    except J.Stop as e:  # flag it at once so the other workers stop before their next call
        with ctx.lock:
            ctx.stop = ctx.stop or e
        raise


def run_arm(ctx, queries: list[str], pools: list[list[str]]) -> dict[int, dict]:
    """One task per query on WORKERS threads. Returns {question index: result} for the queries that finished."""
    res, t0 = {}, time.perf_counter()
    with cf.ThreadPoolExecutor(WORKERS) as ex:
        futs = [ex.submit(run_query, ctx, i, q, pools[i]) for i, q in enumerate(queries)]
        for n, f in enumerate(cf.as_completed(futs), 1):
            try:
                r = f.result()
                res[r["qi"]] = r
            except J.Stop as e:
                with ctx.lock:
                    ctx.stop = ctx.stop or e
            except Exception as e:  # a bug in a worker: stop sending before the remaining tasks repeat it (class and line only)
                with ctx.lock:
                    ctx.stop = ctx.stop or J.Stop(None, [type(e).__name__, "line%d" % traceback.extract_tb(e.__traceback__)[-1].lineno], "", "internal_error", True)
            if n % 33 == 0:
                H.log(ctx.model, f"{n}/{len(queries)} queries, {time.perf_counter() - t0:.0f}s, tokens {ctx.tokens}, attempts {dict(ctx.codes)}")
    return res


# ---------------------------------------------------------------- aggregation
def arm_summary(ctx, price: float, res: dict[int, dict], pack: dict, an: list[dict], rtt_s: float | None):
    """Rank each finished query by relevance_score (unscored documents -1, ties by dense order) and aggregate. Returns
    (summary, {question index: hit bit}). A query without a usable answer keeps the dense order (all scores equal)."""
    idx, bits, ties, distinct = sorted(res), {}, 0, []
    for i in idx:
        kept = an[i]["kept_list"][:POOL]
        sc = res[i]["rec"]["scores"] if res[i]["rec"] else {}
        p = [sc.get(j, -1.0) for j in range(len(kept))]
        order = sorted(range(len(p)), key=lambda j: (-p[j], j))
        bits[i] = int(pack["questions"][i]["gold_memory_id"] in [kept[j] for j in order[:5]])
        ties += int(len(p) > 5 and p[order[4]] == p[order[5]])
        distinct.append(len(set(p)))
    recs = [res[i]["rec"] for i in idx if res[i]["rec"]]
    ok = [c for c in recs if c["ok"]]
    n = len(idx)
    tok = sum(c["tokens"] for c in recs)
    ty = lambda t: H.rate(sum(bits[i] for i in idx if an[i]["type"] == t), sum(1 for i in idx if an[i]["type"] == t))  # noqa: E731
    lat = lat_stats([c["lat"] for c in ok])
    s = {"model": ctx.model, "price_cny_per_m_tokens": price, "queries": n, "hit5": H.rate(sum(bits.values()), n),
         "hit5_by_type": {t: ty(t) for t in H.TYPES},
         "pool_ceiling": H.rate(sum(1 for i in idx if an[i]["rank"] is not None and an[i]["rank"] <= POOL), n),
         "ties_at_5_6": ties, "distinct_scores_mean": round(sum(distinct) / len(distinct), 2) if distinct else None,
         "calls": len(recs), "calls_ok": len(ok), "calls_failed": len(recs) - len(ok), "retried_calls": sum(1 for c in recs if c["attempts"] > 1),
         "answers_missing": sum(c["missing"] for c in recs), "queries_without_call": n - len(recs),
         "tokens": {"total": tok, "prompt_total": sum(c["ptokens"] for c in recs), "per_query_mean": round(tok / n, 1) if n else None},
         "cost_cny": {"per_query": round(tok / n * price / 1e6, 6) if n else None, "per_1000_queries": round(tok / n * price / 1e3, 4) if n else None},
         "latency_s": {"call": lat, "ttfb": lat_stats([c["ttfb"] for c in ok if c["ttfb"] is not None]),
                       "query_wall_incl_retries": lat_stats([c["wall"] for c in ok])},
         "connect_ms_mean": round(sum(ctx.cl.connect_ms) / len(ctx.cl.connect_ms), 1) if ctx.cl.connect_ms else None,
         "connections_opened": len(ctx.cl.connect_ms)}
    if rtt_s is not None and lat["p50"] is not None:
        s["server_est_s"] = {"rtt_s": round(rtt_s, 3), "p50": round(lat["p50"] - rtt_s, 3), "p95": round(lat["p95"] - rtt_s, 3)}
    return s, bits


def load_rtt(path: str | None) -> dict | None:
    try:
        return json.loads(Path(path).read_text()) if path else None
    except (OSError, ValueError):
        return None


def run_all(key: str, base: str, models: list[str], max_tokens: int, pack: dict, refpath: str | None, rtt: dict | None) -> dict:
    """Every model in turn (4 workers each), then the comparisons. A fatal stop ends the job; any other stop ends only that model's arm."""
    an = H.analyse(pack)
    qs = [q["query"] for q in pack["questions"]]
    pools = [[(d[:MAXCH] or "-") for d in p] for p in J.pool(pack, an)]  # "-" for a memory with neither title nor text (the API refuses empty strings)
    dense = H.dense_hits(an)
    hits: dict = {"dense": dict(enumerate(dense))}
    rtt_s = rtt["tcp_connect_ms"]["p50"] / 1000 if rtt and rtt.get("tcp_connect_ms", {}).get("p50") is not None else None
    out: dict = {"job": "cloud", "config": {"workers": WORKERS, "retries": RETRIES, "pool": POOL, "max_chars": MAXCH, "max_input_tokens_per_model": max_tokens,
                                            "max_consecutive_failures": MAX_FAILS, "top_n": "len(documents) = all scores", "instruct": "not sent (documented default)",
                                            "endpoint_host": urllib.parse.urlsplit(base).hostname, "endpoint_path": PATH},
                 "dense": H.rate(sum(dense), len(dense)), "models": [], "stops": [], "comparisons": {}, "rtt": rtt}
    ref = None
    if refpath and Path(refpath).exists():  # per-question bits of PB1's int8 L512 arm, recomputed in the ref job
        try:
            rb = json.loads(Path(refpath).read_text())
            if rb.get("n") == len(dense) and len(rb.get(J.REF_ARM, [])) == len(dense) and set(rb[J.REF_ARM]) <= {0, 1}:
                ref = dict(enumerate(rb[J.REF_ARM]))
                out["ref"] = {"recomputed_hit5": sum(rb[J.REF_ARM]), "pb1_hit5": J.PB1[J.REF_ARM], "dense_bits_identical": rb.get("dense") == dense}
        except (ValueError, TypeError, AttributeError):
            ref = None
    fatal = False
    for m in models:
        if fatal:
            out["models"].append({"model": m, "not_run": True})
            continue
        ctx = J.Ctx(key, base, m, max_tokens)
        ctx.cl = Client(base, key)
        res = run_arm(ctx, qs, pools)
        s, hits[m] = arm_summary(ctx, MODELS[m], res, pack, an, rtt_s)
        s["http_codes"] = dict(ctx.codes)
        s["ratelimit"] = {"retry_after_s": sorted(ctx.retry_after), "headers": ctx.hdrs}
        out["models"].append(s)
        print("ARM", json.dumps(s), flush=True)  # aggregates only; survives a later failure
        if ctx.stop is not None:
            out["stops"].append({"model": m, **ctx.stop.info()})
            print("STOP", json.dumps(out["stops"][-1]), flush=True)
            fatal = ctx.stop.fatal
        n = len(hits[m])
        c = [J.paired(f"{m} vs dense (pre-registered primary)", "dense", m, hits["dense"], hits[m])]
        if ref is not None:
            c.append(J.paired(f"{m} vs bge-reranker-base int8 L512 d25 (recomputed in CI)", J.REF_ARM, m, ref, hits[m]))
        else:
            c.append(J.unpaired(f"{m} vs bge-reranker-base int8 L512 d25 (PB1 aggregate)", "PB1 int8 L512", J.PB1[J.REF_ARM], J.PB1_N, m, sum(hits[m].values()), n))
        c.append(J.unpaired(f"{m} vs Jev J1 (PB3 aggregate)", "PB3 Jev J1", JEV_J1, J.PB1_N, m, sum(hits[m].values()), n))
        c.append(J.unpaired(f"{m} vs bge-reranker-v2-m3 L256 d25 (PB1 aggregate)", "PB1 v2-m3 L256", J.PB1["v2m3-L256-d25"], J.PB1_N, m, sum(hits[m].values()), n))
        out["comparisons"][m] = c
    out["totals"] = {"calls": sum(x.get("calls", 0) for x in out["models"]), "tokens": sum(x.get("tokens", {}).get("total", 0) for x in out["models"])}
    out["fatal"] = fatal
    return out


def render(o: dict) -> str:
    g = lambda v: "n/a" if v is None else v  # noqa: E731
    c = o["config"]
    L = ["## E-RET-PB4: DashScope cloud rerank on the PB1 depth-25 pools (E-RET-5d)", "",
         f"Endpoint host `{c['endpoint_host']}` (cn-beijing, legacy domain), path `{c['endpoint_path']}`. One call per query: `query` + {c['pool']} documents "
         f"(title + newline + best chunk, cut to {c['max_chars']} characters, as PB3), `top_n` = number of documents (all scores), `instruct` not sent. "
         f"Concurrency {c['workers']}, keep-alive connections, up to {c['retries']} retries on 429, 5xx and network errors. Rank = relevance_score, "
         "ties and unscored documents by dense order.", "", f"Dense hit@5 on the same questions: {H.fmt_rate(o['dense'])}.", "",
         "| model | queries | hit@5 | state | fact | pool ceiling | rank 5/6 ties | calls ok/total | answers missing |", "|---|---|---|---|---|---|---|---|---|"]
    ms = [m for m in o["models"] if not m.get("not_run")]
    L += [f"| {m['model']} | {m['queries']} | {H.fmt_rate(m['hit5'])} | {H.fmt_rate(m['hit5_by_type']['state'])} | {H.fmt_rate(m['hit5_by_type']['fact'])} | "
          f"{H.fmt_rate(m['pool_ceiling'])} | {m['ties_at_5_6']} | {m['calls_ok']}/{m['calls']} | {m['answers_missing']} |" for m in ms]
    for m in o["models"]:
        if m.get("not_run"):
            L.append(f"| {m['model']} | not run |" + " |" * 7)
    L += ["", "| model | latency per call p50 / p95 / max s | ttfb p50 / p95 s | server est. p50 / p95 s (call - RTT) | tokens total | per query | CNY per query | CNY per 1,000 queries |",
          "|---|---|---|---|---|---|---|---|"]
    for m in ms:
        w, t, se = m["latency_s"]["call"], m["latency_s"]["ttfb"], m.get("server_est_s", {})
        L.append(f"| {m['model']} | {g(w['p50'])} / {g(w['p95'])} / {g(w['max'])} | {g(t['p50'])} / {g(t['p95'])} | {g(se.get('p50'))} / {g(se.get('p95'))} | "
                 f"{m['tokens']['total']} | {g(m['tokens']['per_query_mean'])} | {g(m['cost_cny']['per_query'])} | {g(m['cost_cny']['per_1000_queries'])} |")
    L += ["", "Paired comparisons, exact McNemar on the same questions (A = baseline, B = model; b = A hit and B miss, c = A miss and B hit):", "",
          "| comparison | N | b | c | p |", "|---|---|---|---|---|"]
    L += [f"| {x['name']} | {x['N']} | {x['b']} | {x['c']} | {x['p']} |" for cs in o["comparisons"].values() for x in cs if x["paired"]]
    L += ["", "Unpaired (aggregate counts only; Fisher exact on two independent samples, conservative for the same questions):", "",
          "| comparison | A hits | B hits | Fisher p |", "|---|---|---|---|"]
    L += [f"| {x['name']} | {H.fmt_rate(x['A_hits'])} | {H.fmt_rate(x['B_hits'])} | {x['fisher_p']} |" for cs in o["comparisons"].values() for x in cs if not x["paired"]]
    if "ref" in o:
        L += ["", f"Reference arm recomputed in CI: hit@5 {o['ref']['recomputed_hit5']} (PB1 reported {o['ref']['pb1_hit5']}); dense bits identical: {o['ref']['dense_bits_identical']}."]
    r = o.get("rtt")
    if r:
        L += ["", f"Runner to endpoint, {r['n']} probes of an unauthenticated request (ms, p50 / p95 / max): DNS {r['dns_ms']['p50']} / {r['dns_ms']['p95']} / {r['dns_ms']['max']}; "
              f"TCP connect (one RTT) {r['tcp_connect_ms']['p50']} / {r['tcp_connect_ms']['p95']} / {r['tcp_connect_ms']['max']}; TLS {r['tls_ms']['p50']} / {r['tls_ms']['p95']} / {r['tls_ms']['max']}; "
              f"first byte on a fresh connection {r['ttfb_fresh_ms']['p50']} / {r['ttfb_fresh_ms']['p95']} / {r['ttfb_fresh_ms']['max']}; "
              f"first byte on a warm connection {r['ttfb_warm_ms']['p50']} / {r['ttfb_warm_ms']['p95']} / {r['ttfb_warm_ms']['max']}; HTTP {json.dumps(r['http'], sort_keys=True)}."]
    for m in ms:
        L.append(f"HTTP status per attempt, {m['model']} (net = no response): {json.dumps(m['http_codes'], sort_keys=True)}; Retry-After seconds seen = {m['ratelimit']['retry_after_s']}; "
                 f"related response headers [first, last] = {json.dumps(m['ratelimit']['headers'], sort_keys=True)}; connections opened {m['connections_opened']}, mean connect {g(m['connect_ms_mean'])} ms.")
    L.append(f"Totals: {o['totals']['calls']} calls in finished queries; tokens billed by the API = {o['totals']['tokens']}.")
    for s in o["stops"]:
        L.append(f"STOP model={s['model']} http={s['http']} why={s['why']} codes={s['codes']} message={s['message']!r} fatal={s['fatal']}")
    return "\n".join(L) + "\n"


def run(a) -> int:
    key = os.environ["ALIBABA_CLOUD_API_KEY"].strip()
    models = [m for m in a.models.split(",") if m]
    bad = [m for m in models if m not in MODELS]
    if bad:
        raise SystemExit(f"unknown model(s): {bad}")
    out = run_all(key, BASE, models, a.max_tokens, H.load_pack(a.pack), a.refbits, load_rtt(a.rtt))
    Path(a.out).write_text(json.dumps(out, indent=1))
    Path(a.summary).write_text(render(out))
    print("done", json.dumps({"models": [(x["model"], x.get("queries"), x.get("calls")) for x in out["models"]], "stops": len(out["stops"]), **out["totals"]}), flush=True)
    return 3 if out["fatal"] else 0


# ---------------------------------------------------------------- rtt
def rtt_probe(base: str, n: int = 10) -> dict:
    """n fresh connections, each: DNS, TCP connect, TLS, then an unauthenticated POST of `{}` (answered 401 by the gateway) timed to the
    first response byte, then the same request again on the warm connection. No key, no corpus text."""
    u = urllib.parse.urlsplit(base)
    https = u.scheme == "https"
    host, port = u.hostname, u.port or (443 if https else 80)
    rows, codes, fails = collections.defaultdict(list), collections.Counter(), 0
    hdr = {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": UA}
    sctx = ssl.create_default_context() if https else None  # built once: the CA-store load must not count as TLS time
    for _ in range(n):
        s = c = None
        row, cs = {}, collections.Counter()
        try:
            t0 = time.perf_counter()
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            ai = next((x for x in infos if x[0] == socket.AF_INET), infos[0])  # runners have no IPv6
            t1 = time.perf_counter()
            s = socket.create_connection(ai[4][:2], timeout=20)
            t2 = time.perf_counter()
            if https:
                s = sctx.wrap_socket(s, server_hostname=host)
            t3 = time.perf_counter()
            c = (http.client.HTTPSConnection if https else http.client.HTTPConnection)(host, port, timeout=20)
            c.sock = s
            row = {"dns_ms": (t1 - t0) * 1000, "tcp_connect_ms": (t2 - t1) * 1000, "tls_ms": (t3 - t2) * 1000}
            for name in ("ttfb_fresh_ms", "ttfb_warm_ms"):
                t = time.perf_counter()
                c.request("POST", PATH, body=b"{}", headers=hdr)
                r = c.getresponse()
                row[name] = (time.perf_counter() - t) * 1000
                cs[str(r.status)] += 1
                r.read()
        except (OSError, http.client.HTTPException):  # one failed probe is counted, not fatal
            fails += 1
            continue
        finally:
            for x in (c, s):
                if x is not None:
                    with contextlib.suppress(Exception):
                        x.close()
        for k, v in row.items():
            rows[k].append(v)
        codes.update(cs)
        time.sleep(0.2)
    if not rows["tcp_connect_ms"]:
        raise SystemExit(f"rtt: none of {n} probes succeeded")
    st = lambda xs: {"p50": round(H.pct(xs, .5), 1), "p95": round(H.pct(xs, .95), 1), "max": round(max(xs), 1)}  # noqa: E731
    return {"n": len(rows["tcp_connect_ms"]), "failed": fails, "http": dict(codes), **{k: st(v) for k, v in rows.items()}}


# ---------------------------------------------------------------- guard
def static_for(files: list[str]) -> set[str]:
    """Code-owned strings exempt from the window check: harness.static_strings, every string constant of this file and of jev_rerank.py
    (labels such as model names or result keys may also occur in the corpus), and the endpoint host (run 1 of PB4 failed the guard on
    it: the corpus itself talks about dashscope.aliyuncs.com, and the host is derived from BASE at run time, so it is no constant)."""
    s = H.static_strings(files, sys.argv[1:] + [x for arg in sys.argv[1:] for x in re.split(r"[,:]", arg)])
    for p in (Path(__file__), Path(J.__file__)):
        s |= {n.value for n in ast.walk(ast.parse(p.read_text())) if isinstance(n, ast.Constant) and isinstance(n.value, str) and len(n.value) >= 2}
    return s | {urllib.parse.urlsplit(BASE).hostname}


def guard(a):
    pack = H.load_pack(a.pack)
    texts = H.corpus_texts(pack)
    hits = H.guard_findings(texts, a.files, static_for(a.files))
    if hits:  # offsets only; never the text
        raise SystemExit(f"GUARD FAILED: {len(hits)} corpus window(s) in outputs, distinct places (file, offset): {sorted(set(hits))[:12]}")
    print(f"guard ok: {len(a.files)} file(s) scanned against {len(texts)} corpus texts")


# ---------------------------------------------------------------- selftest
def _fake_dash(mode: str):
    """Local stand-in for the DashScope rerank endpoint. Modes: ok, flaky (429 RateQuota, then 503, then ok per call), auth (401), arrears
    (400 Arrearage), quota (429 AllocationQuota), bad400 (400 InvalidParameter whose message echoes a document), down (500). A request
    without Authorization gets the gateway's 401 (what rtt_probe sees). Shape violations go to lg['bad']."""
    seen, lock = collections.Counter(), threading.Lock()
    lg = {"bad": [], "sizes": [], "maxlen": 0, "noauth": 0}

    class Hd(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, code, obj, hdr=None):
            raw = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            for k, v in (hdr or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            raw = self.rfile.read(int(self.headers["Content-Length"]))
            if self.headers["Authorization"] is None:
                with lock:
                    lg["noauth"] += 1
                return self._send(401, {"code": "InvalidApiKey", "message": "Invalid API-key provided."})
            body = json.loads(raw)
            inp, docs = body["input"], body["input"]["documents"]
            bad = []
            if self.path != PATH or self.headers["Authorization"] != "Bearer fake-dash-key":
                bad.append("path/auth")
            if (set(body) != {"model", "input", "parameters"} or body["model"] not in MODELS or set(inp) != {"query", "documents"} or not isinstance(inp["query"], str)
                    or body["parameters"] != {"top_n": len(docs)} or not all(isinstance(d, str) and d for d in docs)):
                bad.append("shape")
            with lock:
                lg["bad"] += bad
                lg["sizes"].append(len(docs))
                lg["maxlen"] = max(lg["maxlen"], max(len(d) for d in docs))
                seen[raw] += 1
                n = seen[raw]
            if mode == "auth":
                return self._send(401, {"code": "InvalidApiKey", "message": "Invalid API-key provided."})
            if mode == "arrears":
                return self._send(400, {"code": "Arrearage", "message": "Access denied, please make sure your account is in good standing."})
            if mode == "quota":
                return self._send(429, {"code": "Throttling.AllocationQuota", "message": "Allocated quota exceeded, please increase your quota limit."})
            if mode == "bad400":
                return self._send(400, {"code": "InvalidParameter", "message": "Range of input length should be [1, 4000]: " + docs[0]})
            if mode == "down":
                return self._send(500, {"code": "InternalError", "message": "boom"})
            if mode == "flaky" and n == 1:
                return self._send(429, {"code": "Throttling.RateQuota", "message": "Requests rate limit exceeded"}, {"Retry-After": "0", "X-RateLimit-Remaining": "0"})
            if mode == "flaky" and n == 2:
                return self._send(503, {"code": "ServiceUnavailable", "message": "busy"})
            res = sorted(((0.9 if "NEEDLE" in d else 0.1, i) for i, d in enumerate(docs)), key=lambda x: (-x[0], x[1]))
            self._send(200, {"output": {"results": [{"index": i, "relevance_score": s} for s, i in res]}, "usage": {"total_tokens": len(raw) // 4}, "request_id": "x"})

        def log_message(self, *args):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Hd)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}", lg


def selftest(_a=None):
    global BACKOFF, MAX_FAILS, WORKERS
    BACKOFF = 0.0
    assert MODELS == {"qwen3.7-text-rerank": 0.5, "qwen3-rerank": 0.5, "gte-rerank-v2": 0.8}
    assert QUOTA_RE.search("Arrearage") and QUOTA_RE.search("Throttling.AllocationQuota") and QUOTA_RE.search("AllocationQuota.FreeTierOnly")
    assert not QUOTA_RE.search("Throttling.RateQuota Requests rate limit exceeded") and not QUOTA_RE.search("InvalidParameter")
    pk = J._fake_pack()
    names = list(MODELS)
    tmp = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / f"eret_cloud_selftest_{os.getpid()}"
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "ref.json").write_text(json.dumps({"n": 2, "dense": [0, 1], J.REF_ARM: [1, 0]}))

    def go(mode, cap=0, refpath=None, rtt=None):
        srv, base, lg = _fake_dash(mode)
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                out = run_all("fake-dash-key", base, names, cap, pk, refpath, rtt)
                text = render(out)
            return out, lg, buf.getvalue() + text + json.dumps(out), text
        finally:
            srv.shutdown()

    try:
        # ok: gold at dense position 7 is lifted into the top 5 by every model; request shape, truncation, call counts, pairing, cost
        rtt = {"n": 10, "http": {"401": 20}, **{k: {"p50": 100.0, "p95": 120.0, "max": 130.0} for k in ("dns_ms", "tcp_connect_ms", "tls_ms", "ttfb_fresh_ms", "ttfb_warm_ms")}}
        out, lg, _, _ = go("ok", refpath=str(tmp / "ref.json"), rtt=rtt)
        ms = out["models"]
        assert [m["model"] for m in ms] == names and all((m["hit5"]["k"], m["hit5"]["n"], m["calls"], m["calls_ok"]) == (2, 2, 2, 2) for m in ms), ms
        assert not out["stops"] and sorted(lg["sizes"]) == [25] * 6 and lg["maxlen"] == MAXCH and not lg["bad"], (out["stops"], lg)
        assert all(m["tokens"]["total"] > 0 and m["connections_opened"] >= 1 for m in ms)
        m0 = ms[0]
        assert abs(m0["cost_cny"]["per_1000_queries"] - m0["tokens"]["per_query_mean"] * 0.5 / 1e3) < 1e-3, m0["cost_cny"]
        assert abs(m0["server_est_s"]["rtt_s"] - 0.1) < 1e-9 and m0["server_est_s"]["p50"] == round(m0["latency_s"]["call"]["p50"] - 0.1, 3)
        for m in names:
            c = out["comparisons"][m]
            assert c[0]["paired"] and (c[0]["N"], c[0]["b"], c[0]["c"]) == (2, 0, 1), c[0]  # vs dense [0, 1]: model [1, 1]
            assert c[1]["paired"] and (c[1]["b"], c[1]["c"]) == (0, 1), c[1]  # vs recomputed int8 bits [1, 0]
            assert not c[2]["paired"] and c[2]["A_hits"]["k"] == JEV_J1 and not c[3]["paired"] and c[3]["A_hits"]["k"] == J.PB1["v2m3-L256-d25"], c
        # no ref bits: the int8 comparison falls back to the PB1 aggregate, unpaired
        out, _, _, _ = go("ok")
        assert not out["comparisons"][names[0]][1]["paired"] and out["comparisons"][names[0]][1]["A_hits"]["k"] == J.PB1[J.REF_ARM]
        # 429 RateQuota then 503 then ok on every call: retried, all calls ok, codes and rate-limit headers recorded
        out, _, _, _ = go("flaky")
        m = out["models"][0]
        assert (m["calls_ok"], m["retried_calls"]) == (2, 2) and m["http_codes"] == {"429": 2, "503": 2, "200": 2} and not out["stops"], m
        assert "x-ratelimit-remaining" in m["ratelimit"]["headers"] and m["ratelimit"]["retry_after_s"] == [0.0, 0.0], m["ratelimit"]
        # 401: the whole job stops with the raw code, later models are not sent
        out, lg, _, _ = go("auth")
        s = out["stops"]
        assert len(s) == 1 and (s[0]["http"], s[0]["fatal"], s[0]["message"]) == (401, True, "Invalid API-key provided.") and out["fatal"], s
        assert all(m.get("not_run") for m in out["models"][1:]) and 1 <= len(lg["sizes"]) <= 2, lg  # the 2nd query may see the stop flag first
        # Arrearage (400) and an exhausted allocation (429) are quota or billing stops with their raw codes; RateQuota above was a retry
        out, _, _, _ = go("arrears")
        assert (out["stops"][0]["http"], out["stops"][0]["why"], out["stops"][0]["codes"], out["stops"][0]["fatal"]) == (400, "quota_or_billing", ["Arrearage"], True), out["stops"]
        assert all(m.get("not_run") for m in out["models"][1:])
        out, _, _, _ = go("quota")
        assert (out["stops"][0]["http"], out["stops"][0]["why"], out["stops"][0]["fatal"]) == (429, "quota_or_billing", True) and out["models"][1].get("not_run"), out["stops"]
        # any other 4xx stops only that model's arm; the echoed document never reaches the log, the summary or the JSON
        out, lg, everything, _ = go("bad400")
        assert [(x["model"], x["http"], x["codes"], x["fatal"]) for x in out["stops"]] == [(n, 400, ["InvalidParameter"], False) for n in names], out["stops"]
        assert all(m["queries"] == 0 and m["hit5"]["n"] == 0 for m in out["models"]) and not out["fatal"]
        for leak in ("chunk text", "fake query", "NEEDLE"):
            assert leak not in everything, leak
        # a dead endpoint: every call retried RETRIES times, the query falls back to dense order; the breaker (MAX_FAILS = 1 here) stops the arm
        out, _, _, _ = go("down")
        m = out["models"][0]
        assert (m["calls_failed"], m["hit5"]["k"], m["http_codes"]) == (2, 1, {"500": 8}) and not out["stops"], m
        MAX_FAILS = 1
        out, _, _, _ = go("down")
        assert out["stops"][0]["why"] == "consecutive_failures" and not out["stops"][0]["fatal"] and len(out["stops"]) == 3, out["stops"]
        MAX_FAILS = 12
        # token cap: checked before each attempt, fatal; one worker so the second query sees the first query's tokens
        WORKERS = 1
        out, _, _, _ = go("ok", cap=1)
        assert out["stops"][0]["why"] == "token_cap" and out["stops"][0]["fatal"] and out["models"][1].get("not_run"), out["stops"]
        WORKERS = 4
        # rtt probe: no Authorization header is sent, the gateway's 401 is what is timed
        srv, base, lg = _fake_dash("ok")
        try:
            r = rtt_probe(base, 3)
        finally:
            srv.shutdown()
        assert r["n"] == 3 and r["http"] == {"401": 6} and lg["noauth"] == 6 and not lg["bad"] and r["tcp_connect_ms"]["p50"] >= 0, (r, lg)
        # guard: the real outputs of an ok run are clean; a leaked corpus window is caught once the code-owned strings are not exempted
        out, _, _, text = go("ok", refpath=str(tmp / "ref.json"), rtt=rtt)
        f_json, f_md, f_leak = tmp / "cloud.json", tmp / "cloud.md", tmp / "leak.md"
        f_json.write_text(json.dumps(out, indent=1))
        f_md.write_text(text)
        texts = H.corpus_texts(pk)
        assert not H.guard_findings(texts, [str(f_json), str(f_md)], static_for([str(f_json), str(f_md)])), "guard flagged clean output"
        f_leak.write_text(text + "\nnote: " + pk["chunks"]["c0_5"] + "\n")
        assert H.guard_findings(texts, [str(f_leak)], set()), "guard missed a leaked window"
        # the endpoint host is derived from BASE, not a constant, and a real corpus mentions it: red without the exemption, green with it
        f_host = tmp / "host.json"
        f_host.write_text(json.dumps({"endpoint_host": urllib.parse.urlsplit(BASE).hostname}))
        host_texts = texts + [f"notes about {urllib.parse.urlsplit(BASE).hostname} and its rerank path"]
        assert H.guard_findings(host_texts, [str(f_host)], set()), "the host must be flagged without the exemption"
        assert not H.guard_findings(host_texts, [str(f_host)], static_for([str(f_host)])), "the host must be exempt"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("selftest ok")


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    r = sp.add_parser("run")
    for k in ("pack", "out", "summary"):
        r.add_argument("--" + k, required=True)
    r.add_argument("--refbits")
    r.add_argument("--rtt")
    r.add_argument("--models", default=",".join(MODELS))
    r.add_argument("--max-tokens", type=int, default=0, help="tripwire on total billed tokens per model (0 = off)")
    t = sp.add_parser("rtt")
    t.add_argument("--out", required=True)
    g = sp.add_parser("guard")
    g.add_argument("--pack", required=True)
    g.add_argument("--files", nargs="+", required=True)
    sp.add_parser("selftest")
    a = ap.parse_args()
    try:
        if a.cmd == "run":
            sys.exit(run(a))
        elif a.cmd == "rtt":
            res = rtt_probe(BASE)
            Path(a.out).write_text(json.dumps(res, indent=1))
            print("rtt", json.dumps(res))
        elif a.cmd == "guard":
            guard(a)
        else:
            selftest()
    except SystemExit:
        raise
    except Exception as ex:  # class and source line only: messages and locals can carry corpus text or the key
        fr = traceback.extract_tb(ex.__traceback__)
        print(f"FAILED {type(ex).__name__} at " + " <- ".join(f"{Path(x.filename).name}:{x.lineno}:{x.name}" for x in reversed(fr[-4:])), flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
