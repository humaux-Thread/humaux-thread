#!/usr/bin/env python3
"""E-RET-PB3 (E-RET-5c): TypeSafe Jev as a hosted relevance reranker on the PB1 depth-25 pools. Experiment, not product code.

Subcommands:
  run       J1 (one call per query, 25 noul questions) and J2 (five calls of five passages per query) against the Jev API.
            Needs JEV_API in this step's env; stdlib only. Output = aggregates: hit@5, McNemar, latency, tokens, HTTP codes.
  ref       recompute the per-question hit bits of PB1's bge-reranker-base int8 L512 depth-25 arm (torch + ORT, no secret). The
            workflow seals the bits with the pack key before they leave the job, so the `run` job can pair J1 against them.
  guard     fail if any 12-character window of corpus text occurs in the given output files (harness.guard_findings, plus this
            file's own string constants as code-owned labels).
  selftest  statistics, request shape, retries, stop rules and the no-leak error path against a fake endpoint (no network).

Privacy: as harness.py. Passages go to the Jev API only from the `run` step, inside CI (owner-authorised 2026-10-21). Error bodies
are never printed whole (a 422 may echo the input): only the HTTP status, identifier-like codes, and for 401/402/403/quota a short
message that is withheld if it overlaps the request text. Pool, fold, McNemar, intervals and the guard come from harness.py.
API authority: https://docs.typesafe.ai/api.md (OpenAPI info.version 0.2.0, read 2026-10-21): POST /v1/systemone {model, state,
questions{name: {type: noul, instructions, criteria{true, false}}}} -> {model, answers{name: {noul: p}}, usage{input_tokens}};
GET /v1/models; header TypeSafe-Danger-Zone-Long-Context: true; rate limits, pricing and retention are not documented.
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
import math
import os
import platform
import random
import re
import shutil
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import harness as H  # noqa: E402  (stdlib only: statistics, pack fold, guard)

API = "https://api.typesafe.ai"
MODEL = "jev-latest"
UA = "humaux-eret-pb3/1.0"
LONG_HDR = "TypeSafe-Danger-Zone-Long-Context"
ARMS = ("J1", "J2")
POOL, GROUP, MAXCH = 25, 5, 1000  # pool depth, J2 passages per call, characters per passage (no tokenizer in the run job)
WORKERS, RETRIES, TIMEOUT = 4, 3, 600
BACKOFF = 2.0  # seconds before the first retry, doubled per retry (+25% jitter); selftest sets 0
MAX_FAILS = 12  # consecutive failed calls that stop an arm (a wrong path or schema must not burn all 1,188 calls)
STOP_CODES = (401, 402, 403, 422)
QUOTA_RE = re.compile(r"quota|billing|insufficient|credit|balance|arrear|payment|overdue", re.I)
IDENT_RE = re.compile(r"[A-Za-z0-9_.:/\-]{1,60}")
HDR_RE = re.compile(r"ratelimit|rate-limit|retry-after|quota|limit", re.I)
INSTR = "Does passage {id} contain the information needed to answer the query?"
CRIT = {"true": "it answers or directly contains the answer", "false": "it does not"}
REF_ARM, REF_L = "int8-L512-d25", 512
# PB1 run 39593059326 hit@5 counts out of 198 (README): the unpaired fallback and the v2-m3 reference, which is not recomputed
PB1 = {"dense": 63, REF_ARM: 101, "v2m3-L256-d25": 109}
PB1_N = 198


# ---------------------------------------------------------------- small helpers
def ident(v):
    """Identifier-like strings only (error codes, model names): free text could echo the passages."""
    return v if isinstance(v, str) and IDENT_RE.fullmatch(v) else None


def num(x) -> int:
    return int(x) if isinstance(x, (int, float)) and not isinstance(x, bool) else 0


def stats(xs) -> dict:
    if not xs:
        return {"n": 0, "p50": None, "p95": None, "max": None}
    return {"n": len(xs), "p50": round(H.pct(xs, .5), 2), "p95": round(H.pct(xs, .95), 2), "max": round(max(xs), 2)}


def fisher(k1: int, n1: int, k2: int, n2: int) -> float:
    """Exact two-sided Fisher p for two independent proportions (UNPAIRED: both samples are the same 198 questions)."""
    n, k = n1 + n2, k1 + k2
    pr = lambda x: math.comb(n1, x) * math.comb(n2, k - x) / math.comb(n, k)  # noqa: E731
    p0 = pr(k1)
    return min(1.0, sum(pr(x) for x in range(max(0, k - n2), min(k, n1) + 1) if pr(x) <= p0 * (1 + 1e-9)))


def pool(pack: dict, an: list[dict]) -> list[list[str]]:
    """PB1's depth-25 pools: first POOL memories after the status filter, each as title + newline + best chunk text. The same
    expression as harness.rerank_job (inline there, so it cannot be imported)."""
    mem, chunks = pack["memories"], pack["chunks"]
    return [[(mem[m].get("title", "") + "\n" + chunks.get(r["mem_chunk"].get(m), "")).strip() for m in r["kept_list"][:POOL]] for r in an]


# ---------------------------------------------------------------- HTTP
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # a 3xx surfaces as an HTTPError instead of re-sending the Authorization header elsewhere


OPENER = urllib.request.build_opener(_NoRedirect)


class Stop(Exception):
    """A stop rule fired: 401/402/403/422, a quota or billing error, the token cap, or MAX_FAILS consecutive failures. `fatal`
    ends the job (nothing more is sent); otherwise only the current arm stops."""

    def __init__(self, code, ids, msg, why, fatal):
        super().__init__(why)
        self.code, self.ids, self.msg, self.why, self.fatal = code, ids, msg, why, fatal

    def info(self) -> dict:
        return {"http": self.code, "codes": self.ids, "message": self.msg, "why": self.why, "fatal": self.fatal}


class Ctx:
    """Shared state of one `run`: credentials, stop flag, token counter and HTTP bookkeeping. Mutated under `lock`."""

    def __init__(self, key: str, base: str, model: str, max_tokens: int):
        self.key, self.base, self.model, self.max_tokens = key, base, model, max_tokens
        self.lock = threading.Lock()
        self.stop = None  # first Stop of the current arm (or fatal Stop)
        self.tokens, self.fails = 0, 0
        self.codes = collections.Counter()  # per HTTP attempt; "net" = no response
        self.models: set[str] = set()
        self.hdrs: dict[str, list[str]] = {}  # rate-limit related response headers: name -> [first, last]
        self.retry_after: list[float] = []

    def note(self, code, h: dict):
        with self.lock:
            self.codes["net" if code is None else str(code)] += 1
            for k, v in h.items():
                if HDR_RE.search(k) and re.fullmatch(r"[\w.,;:= /-]{1,40}", v):
                    self.hdrs.setdefault(k, [v, v])[1] = v


def err_idents(raw: bytes) -> list[str]:
    """Identifier-like codes from an error body (code, type, error.code, error.type, detail[].type). Never the free-text message."""
    try:
        j = json.loads(raw)
    except ValueError:
        return []
    out: list[str] = []
    if isinstance(j, dict):
        e, d = j.get("error"), j.get("detail")
        cands = [j.get("code"), j.get("type"), e if isinstance(e, str) else None]
        if isinstance(e, dict):
            cands += [e.get("code"), e.get("type")]
        cands += [x.get("type") for x in d[:5] if isinstance(x, dict)] if isinstance(d, list) else [d]
        out = [i for i in (ident(c) for c in cands) if i]
    return out


def msg_of(raw: bytes, blob: str, key: str) -> str:
    """Short message of an auth or billing error, withheld if it overlaps the request text (12-character windows, or the whole message
    when shorter) or the API key (8-character windows: a 401 body may echo a masked key)."""
    try:
        j = json.loads(raw)
    except ValueError:
        return ""
    m = ""
    if isinstance(j, dict):
        e = j.get("error")
        m = next((x for x in (j.get("detail"), j.get("message"), e if isinstance(e, str) else None,
                              e.get("message") if isinstance(e, dict) else None) if isinstance(x, str)), "")[:120]
    leak = (m and m in blob) or any(m[i:i + 12] in blob for i in range(max(0, len(m) - 11))) or any(key[i:i + 8] in m for i in range(max(0, len(key) - 7)))
    return "<withheld>" if leak else m


def request(ctx: Ctx, path: str, blob: str | None = None) -> dict:
    """One HTTP exchange (GET when blob is None). 429, 5xx and network errors are retried up to RETRIES times with exponential
    backoff plus jitter, Retry-After honoured up to 60 s. Returns {code, json, lat, attempts, ids}; code is None after a network
    failure and json is None unless the answer was a 200 with a JSON body. Raises Stop on a stop rule."""
    data = None if blob is None else blob.encode("utf-8")
    hdr = {"Authorization": "Bearer " + ctx.key, "Content-Type": "application/json", "Accept": "application/json", "User-Agent": UA, LONG_HDR: "true"}
    for attempt in range(RETRIES + 1):
        if ctx.stop is not None:
            raise ctx.stop
        t0 = time.perf_counter()
        code, raw, h = None, b"", {}
        try:
            req = urllib.request.Request(ctx.base + path, data=data, headers=hdr, method="GET" if data is None else "POST")
            with OPENER.open(req, timeout=TIMEOUT) as r:
                code, raw, h = r.status, r.read(), {k.lower(): v for k, v in r.headers.items()}
        except urllib.error.HTTPError as e:
            code, raw, h = e.code, e.read(), {k.lower(): v for k, v in e.headers.items()}
        except (OSError, http.client.HTTPException):
            pass
        lat = time.perf_counter() - t0
        ctx.note(code, h)
        res = {"code": code, "json": None, "lat": lat, "attempts": attempt + 1, "ids": []}
        if code == 200:
            try:
                res["json"] = json.loads(raw)
            except ValueError:
                res["code"] = "bad_json"
            return res
        if code is not None:
            res["ids"] = err_idents(raw)
            text = "" if code == 422 or code >= 500 else raw[:2000].decode("utf-8", "replace")  # a 422 body may echo the input
            quota = bool(QUOTA_RE.search(" ".join(res["ids"]) + " " + text))
            if code in STOP_CODES or quota:
                raise Stop(code, res["ids"], "" if code == 422 else msg_of(raw, blob or "", ctx.key),
                           "quota_or_billing" if quota else f"http_{code}", code != 422)
        if (code is None or code == 429 or code >= 500) and attempt < RETRIES:
            wait = BACKOFF * 2 ** attempt
            ra = h.get("retry-after", "")
            if re.fullmatch(r"\d+(\.\d+)?", ra):
                wait = max(wait, min(float(ra), 60.0))
                with ctx.lock:
                    if len(ctx.retry_after) < 50:
                        ctx.retry_after.append(float(ra))
            time.sleep(wait * (1 + 0.25 * random.random()))
            continue
        return res
    raise AssertionError("unreachable")


def list_models(ctx: Ctx) -> str:
    """GET /v1/models once. Returns 'n=<count>: <names>' (identifier-like names only) or 'unavailable (<code>)'. Raises Stop."""
    r = request(ctx, "/v1/models")
    j, names = r["json"], []
    if not isinstance(j, (dict, list)):
        return f"unavailable ({r['code']})"

    def walk(x):
        if isinstance(x, str):
            names.append(x)
        elif isinstance(x, list):
            for y in x:
                walk(y)
        elif isinstance(x, dict):
            names.extend(x[k] for k in ("id", "name", "model") if isinstance(x.get(k), str))
            for k in ("data", "models"):
                if k in x:
                    walk(x[k])

    walk(j)
    if not names and isinstance(j, dict):
        names = list(j)
    names = [n for n in dict.fromkeys(names) if ident(n)]
    return f"n={len(names)}: " + ",".join(names[:40])


# ---------------------------------------------------------------- arms
def build(model: str, query: str, items: list[tuple[str, str]]) -> dict:
    """items = [(passage id, text)]. One noul question per passage, named like the passage id."""
    return {"model": model,
            "state": {"query": query, "passages": [{"id": pid, "text": t} for pid, t in items]},
            "questions": {pid: {"type": "noul", "instructions": INSTR.format(id=pid), "criteria": dict(CRIT)} for pid, _ in items}}


def ask(ctx: Ctx, query: str, items: list[tuple[str, str]]) -> dict:
    """One systemone call. Returns {"probs": {pid: noul}, "rec": per-call record}. A 200 without any valid answer counts as a failed
    call, so a schema mismatch trips the MAX_FAILS breaker instead of burning the budget."""
    if ctx.max_tokens and ctx.tokens >= ctx.max_tokens:
        raise Stop(None, [], "", "token_cap", True)
    blob = json.dumps(build(ctx.model, query, items), ensure_ascii=False)
    r = request(ctx, "/v1/systemone", blob)
    j, probs, tok, otok, model = r["json"], {}, 0, 0, None
    if isinstance(j, dict):
        ans = j.get("answers") if isinstance(j.get("answers"), dict) else {}
        for pid, _ in items:
            a = ans.get(pid)
            p = a.get("noul") if isinstance(a, dict) else None
            if isinstance(p, (int, float)) and not isinstance(p, bool) and 0 <= p <= 1:
                probs[pid] = float(p)
        u = j.get("usage") if isinstance(j.get("usage"), dict) else {}
        tok, otok, model = num(u.get("input_tokens")), num(u.get("output_tokens")), ident(j.get("model"))
    ok = bool(probs)
    with ctx.lock:
        ctx.tokens += tok
        ctx.fails = 0 if ok else ctx.fails + 1
        if model:
            ctx.models.add(model)
        trip = ctx.fails >= MAX_FAILS
    if trip:
        raise Stop(r["code"], r["ids"], "", "consecutive_failures", False)
    rec = {"ok": ok, "code": r["code"], "lat": r["lat"], "attempts": r["attempts"], "tokens": tok, "otokens": otok,
           "missing": len(items) - len(probs), "chars": len(blob)}
    return {"probs": probs, "rec": rec}


def run_query(ctx: Ctx, arm: str, qi: int, query: str, items: list[tuple[str, str]]) -> dict:
    """All calls of one query, in sequence inside one worker: J1 = one call over the pool, J2 = GROUP passages per call (global
    passage ids, so the questions are the same as J1's). `wall` = time from the first request to the last answer."""
    groups = [items] if arm == "J1" else [items[i:i + GROUP] for i in range(0, len(items), GROUP)]
    probs, calls, t0 = {}, [], time.perf_counter()
    try:
        for g in (g for g in groups if g):
            c = ask(ctx, query, g)
            probs.update(c["probs"])
            calls.append(c["rec"])
    except Stop as e:  # flag it at once so the other workers stop before their next call
        with ctx.lock:
            ctx.stop = ctx.stop or e
        raise
    return {"qi": qi, "wall": time.perf_counter() - t0, "calls": calls, "probs": probs}


def run_arm(ctx: Ctx, arm: str, queries: list[str], pools: list[list[str]]) -> dict[int, dict]:
    """One task per query on WORKERS threads. Returns {question index: result} for the queries that finished."""
    items = [[("p%d" % (j + 1), d[:MAXCH]) for j, d in enumerate(p)] for p in pools]
    res, t0 = {}, time.perf_counter()
    with cf.ThreadPoolExecutor(WORKERS) as ex:
        futs = [ex.submit(run_query, ctx, arm, i, q, items[i]) for i, q in enumerate(queries)]
        for n, f in enumerate(cf.as_completed(futs), 1):
            try:
                r = f.result()
                res[r["qi"]] = r
            except Stop as e:
                with ctx.lock:
                    ctx.stop = ctx.stop or e
            except Exception as e:  # a bug in a worker: stop sending before the remaining tasks repeat it (class and line only)
                with ctx.lock:
                    ctx.stop = ctx.stop or Stop(None, [type(e).__name__, "line%d" % traceback.extract_tb(e.__traceback__)[-1].lineno], "", "internal_error", True)
            if n % 33 == 0:
                H.log(arm, f"{n}/{len(queries)} queries, {time.perf_counter() - t0:.0f}s, input tokens {ctx.tokens}, attempts {dict(ctx.codes)}")
    return res


def arm_summary(arm: str, res: dict[int, dict], pack: dict, an: list[dict]):
    """Rank each finished query by noul probability (unanswered passages -1, ties by dense order) and aggregate. Returns
    (summary, {question index: hit bit})."""
    idx, bits, ties, distinct = sorted(res), {}, 0, []
    for i in idx:
        kept = an[i]["kept_list"][:POOL]
        p = [res[i]["probs"].get("p%d" % (j + 1), -1.0) for j in range(len(kept))]
        order = sorted(range(len(p)), key=lambda j: (-p[j], j))
        bits[i] = int(pack["questions"][i]["gold_memory_id"] in [kept[j] for j in order[:5]])
        ties += int(len(p) > 5 and p[order[4]] == p[order[5]])
        distinct.append(len(set(p)))
    calls = [c for i in idx for c in res[i]["calls"]]
    ok = [c for c in calls if c["ok"]]
    tok, tok_ok = sum(c["tokens"] for c in calls), sum(c["tokens"] for c in ok)
    ty = lambda t: H.rate(sum(bits[i] for i in idx if an[i]["type"] == t), sum(1 for i in idx if an[i]["type"] == t))  # noqa: E731
    return {"arm": arm, "queries": len(idx), "hit5": H.rate(sum(bits.values()), len(idx)), "hit5_by_type": {t: ty(t) for t in H.TYPES},
            "pool_ceiling": H.rate(sum(1 for i in idx if an[i]["rank"] is not None and an[i]["rank"] <= POOL), len(idx)),
            "ties_at_5_6": ties, "distinct_probs_mean": round(sum(distinct) / len(distinct), 2) if distinct else None,
            "calls": len(calls), "calls_ok": len(ok), "calls_failed": len(calls) - len(ok),
            "retried_calls": sum(1 for c in calls if c["attempts"] > 1), "answers_missing": sum(c["missing"] for c in calls),
            "input_tokens": {"total": tok, "per_query_mean": round(tok / len(idx), 1) if idx else None,
                             "per_call_mean": round(tok / len(calls), 1) if calls else None,
                             "chars_per_token": round(sum(c["chars"] for c in ok) / tok_ok, 2) if tok_ok else None},
            "output_tokens_total": sum(c["otokens"] for c in calls),
            "query_wall_s": stats([res[i]["wall"] for i in idx]), "call_latency_s": stats([c["lat"] for c in ok])}, bits


def paired(name: str, a_name: str, b_name: str, a: dict[int, int], b: dict[int, int]) -> dict:
    """Exact McNemar on the questions both sides have. A = baseline, B = challenger."""
    idx = sorted(set(a) & set(b))
    return {"name": name, "A": a_name, "B": b_name, "paired": True, **H.mcnemar([a[i] for i in idx], [b[i] for i in idx])}


def unpaired(name: str, a_name: str, a_k: int, a_n: int, b_name: str, b_k: int, b_n: int) -> dict:
    return {"name": name, "A": a_name, "B": b_name, "paired": False, "A_hits": H.rate(a_k, a_n), "B_hits": H.rate(b_k, b_n),
            "fisher_p": float(f"{fisher(a_k, a_n, b_k, b_n):.4g}")}


def run_all(ctx: Ctx, pack: dict, refpath: str | None) -> dict:
    """Models listing, J1, J2, then the comparisons. Returns the aggregate result (no corpus text)."""
    an = H.analyse(pack)
    qs = [q["query"] for q in pack["questions"]]
    pools = pool(pack, an)
    dense = H.dense_hits(an)
    hits: dict[str, dict[int, int]] = {"dense": dict(enumerate(dense)), "J1": {}, "J2": {}}
    out: dict = {"job": "jev", "config": {"workers": WORKERS, "retries": RETRIES, "pool": POOL, "j2_group": GROUP, "max_chars": MAXCH,
                                          "max_input_tokens": ctx.max_tokens, "max_consecutive_failures": MAX_FAILS},
                 "dense": H.rate(sum(dense), len(dense)), "arms": [], "stops": [], "http_codes": {}}
    try:
        listed = list_models(ctx)
    except Stop as e:
        ctx.stop, listed = e, f"unavailable ({e.code})"
        out["stops"].append({"arm": "models", **e.info()})
        print("STOP", json.dumps(out["stops"][-1]), flush=True)
    out["http_codes"]["models"] = dict(ctx.codes)
    for arm in ARMS:
        if ctx.stop is not None:  # a fatal stop: nothing more is sent
            out["arms"].append({"arm": arm, "not_run": True})
            continue
        ctx.codes, ctx.fails = collections.Counter(), 0
        res = run_arm(ctx, arm, qs, pools)
        out["http_codes"][arm] = dict(ctx.codes)
        s, hits[arm] = arm_summary(arm, res, pack, an)
        out["arms"].append(s)
        print("ARM", json.dumps(s), flush=True)  # aggregates only; survives a later failure
        if ctx.stop is not None:
            out["stops"].append({"arm": arm, **ctx.stop.info()})
            print("STOP", json.dumps(out["stops"][-1]), flush=True)
            if not ctx.stop.fatal:
                ctx.stop = None
    if refpath and Path(refpath).exists():  # per-question bits of PB1's int8 L512 arm, recomputed in the ref job
        try:
            rb = json.loads(Path(refpath).read_text())
            usable = rb.get("n") == len(dense) and len(rb.get(REF_ARM, [])) == len(dense) and set(rb[REF_ARM]) <= {0, 1}
        except (ValueError, TypeError, AttributeError):
            usable = False
        if usable:
            hits[REF_ARM] = dict(enumerate(rb[REF_ARM]))
            out["ref"] = {"recomputed_hit5": sum(rb[REF_ARM]), "pb1_hit5": PB1[REF_ARM], "dense_bits_identical": rb.get("dense") == dense}
    n1 = len(hits["J1"])
    out["comparisons"] = [paired("J1 vs dense (pre-registered primary)", "dense", "J1", hits["dense"], hits["J1"])]
    if REF_ARM in hits:
        out["comparisons"].append(paired("J1 vs bge-reranker-base int8 L512 d25 (recomputed in CI)", REF_ARM, "J1", hits[REF_ARM], hits["J1"]))
    else:
        out["comparisons"].append(unpaired("J1 vs bge-reranker-base int8 L512 d25 (PB1 aggregate)", "PB1 int8 L512", PB1[REF_ARM], PB1_N,
                                           "J1", sum(hits["J1"].values()), n1))
    out["comparisons"] += [
        unpaired("J1 vs bge-reranker-v2-m3 L256 d25 (PB1 aggregate)", "PB1 v2-m3 L256", PB1["v2m3-L256-d25"], PB1_N, "J1", sum(hits["J1"].values()), n1),
        paired("J2 vs J1", "J1", "J2", hits["J1"], hits["J2"]),
        paired("J2 vs dense", "dense", "J2", hits["dense"], hits["J2"])]
    out["model"] = {"requested": ctx.model, "returned": ",".join(sorted(ctx.models)) or "none", "listed": listed}
    out["ratelimit"] = {"attempts_429": sum(h.get("429", 0) for h in out["http_codes"].values()), "retry_after_s": sorted(ctx.retry_after),
                        "headers": ctx.hdrs}
    out["totals"] = {"calls": sum(a.get("calls", 0) for a in out["arms"]), "input_tokens_all_calls": ctx.tokens}
    return out


def render(o: dict) -> str:
    m, g = o["model"], (lambda v: "n/a" if v is None else v)
    L = ["## E-RET-PB3: Jev as a hosted reranker on the PB1 depth-25 pools (E-RET-5c)", "",
         f"Model requested `{m['requested']}`, returned `{m['returned']}`. GET /v1/models: {m['listed']}.", "",
         f"Pool = PB1's: dense memory order after the status filter, first {POOL}; passage = title + newline + best chunk, cut to {MAXCH} "
         f"characters (no tokenizer in this job). Rank = noul probability of the passage's own question, ties by dense order, unanswered "
         f"passages last. Header {LONG_HDR}: true on every call. Concurrency {WORKERS}; up to {RETRIES} retries on 429, 5xx and network "
         f"errors. J2 = {POOL // GROUP} calls of {GROUP} passages per query (global passage ids), run in sequence inside one worker.", "",
         f"Dense hit@5 on the same questions: {H.fmt_rate(o['dense'])}.", "",
         "| arm | queries | hit@5 | state | fact | pool ceiling | rank 5/6 ties | calls ok/total | answers missing |", "|---|---|---|---|---|---|---|---|---|"]
    for a in o["arms"]:
        if a.get("not_run"):
            L.append(f"| {a['arm']} | not run |" + " |" * 7)
        else:
            L.append(f"| {a['arm']} | {a['queries']} | {H.fmt_rate(a['hit5'])} | {H.fmt_rate(a['hit5_by_type']['state'])} | "
                     f"{H.fmt_rate(a['hit5_by_type']['fact'])} | {H.fmt_rate(a['pool_ceiling'])} | {a['ties_at_5_6']} | "
                     f"{a['calls_ok']}/{a['calls']} | {a['answers_missing']} |")
    L += ["", "| arm | input tokens | per query | per call | chars/token | output tokens | query wall p50 / p95 / max s | call latency p50 / p95 / max s |",
          "|---|---|---|---|---|---|---|---|"]
    for a in o["arms"]:
        if not a.get("not_run"):
            t, w, c = a["input_tokens"], a["query_wall_s"], a["call_latency_s"]
            L.append(f"| {a['arm']} | {t['total']} | {g(t['per_query_mean'])} | {g(t['per_call_mean'])} | {g(t['chars_per_token'])} | "
                     f"{a['output_tokens_total']} | {g(w['p50'])} / {g(w['p95'])} / {g(w['max'])} | {g(c['p50'])} / {g(c['p95'])} / {g(c['max'])} |")
    L += ["", "Paired comparisons, exact McNemar on the same questions (A = baseline, B = challenger; b = A hit and B miss, c = A miss and B hit):", "",
          "| comparison | N | b | c | p |", "|---|---|---|---|---|"]
    L += [f"| {c['name']} | {c['N']} | {c['b']} | {c['c']} | {c['p']} |" for c in o["comparisons"] if c["paired"]]
    L += ["", "Unpaired (PB1 aggregate counts only; Fisher exact on two independent samples, conservative for the same questions):", "",
          "| comparison | A hits | B hits | Fisher p |", "|---|---|---|---|"]
    L += [f"| {c['name']} | {H.fmt_rate(c['A_hits'])} | {H.fmt_rate(c['B_hits'])} | {c['fisher_p']} |" for c in o["comparisons"] if not c["paired"]]
    if "ref" in o:
        L += ["", f"Reference arm recomputed in CI: hit@5 {o['ref']['recomputed_hit5']} (PB1 reported {o['ref']['pb1_hit5']}); dense bits identical: {o['ref']['dense_bits_identical']}."]
    L += ["", "HTTP status per attempt (net = no response): " + "; ".join(f"{k} {json.dumps(v, sort_keys=True)}" for k, v in o["http_codes"].items()),
          f"Rate-limit observations: attempts with 429 = {o['ratelimit']['attempts_429']}; Retry-After seconds seen = {o['ratelimit']['retry_after_s']}; "
          f"related response headers [first, last] = {json.dumps(o['ratelimit']['headers'], sort_keys=True)}",
          f"Totals: {o['totals']['calls']} calls in finished queries; input tokens over all calls = {o['totals']['input_tokens_all_calls']}."]
    for s in o["stops"]:
        L.append(f"STOP arm={s['arm']} http={s['http']} why={s['why']} codes={s['codes']} message={s['message']!r} fatal={s['fatal']}")
    return "\n".join(L) + "\n"


def run(a) -> int:
    ctx = Ctx(os.environ["JEV_API"].strip(), API, a.model, a.max_tokens)
    out = run_all(ctx, H.load_pack(a.pack), a.refbits)
    Path(a.out).write_text(json.dumps(out, indent=1))
    Path(a.summary).write_text(render(out))
    print("done", json.dumps({"arms": [(x["arm"], x.get("queries"), x.get("calls")) for x in out["arms"]], "stops": len(out["stops"]), **out["totals"]}), flush=True)
    return 3 if out["stops"] else 0


# ---------------------------------------------------------------- ref (PB1's int8 L512 arm, per-question bits)
def ref(a):
    import rerank as R  # torch; only this subcommand imports it

    R.torch.set_num_threads(4)
    pack = H.load_pack(a.pack)
    an = H.analyse(pack)
    dense = H.dense_hits(an)
    info = R.pin_and_licence(a.repo, a.rev)
    sc = R.Scorer(R.KIND["int8"], R.download(a.repo, a.rev))
    if not sc.sanity():
        raise SystemExit("scorer sanity check failed")
    docs = pool(pack, an)  # no character cut here: PB1 truncated the (query, document) pair to REF_L tokens
    sc.score_query(pack["questions"][0]["query"], docs[0], REF_L)  # untimed warm-up, as in PB1
    hit, wall = [], []
    for i, (r, q) in enumerate(zip(an, pack["questions"])):
        t = time.perf_counter()
        s = sc.score_query(q["query"], docs[i], REF_L)
        wall.append(time.perf_counter() - t)
        order = sorted(range(len(s)), key=lambda j: (-s[j], j))  # stable by dense rank
        hit.append(int(q["gold_memory_id"] in [r["kept_list"][j] for j in order[:5]]))
        if (i + 1) % 33 == 0:
            H.log(REF_ARM, f"{i + 1}/{len(an)} questions, {sum(wall):.0f}s")
    Path(a.bits).write_text(json.dumps({"n": len(hit), "dense": dense, REF_ARM: hit}))
    res = {"job": "ref", "arm": REF_ARM, "env": {"machine": platform.machine(), "cpus": os.cpu_count(), "python": sys.version.split()[0], "torch": R.torch.__version__},
           "model": info, "dense": H.rate(sum(dense), len(dense)), "hit5": H.rate(sum(hit), len(hit)), "pb1_hit5": PB1[REF_ARM],
           "mcnemar_vs_dense": H.mcnemar(dense, hit),
           "latency_s": {"n": len(wall), "p50": round(H.pct(wall, .5), 3), "p95": round(H.pct(wall, .95), 3)}}
    Path(a.out).write_text(json.dumps(res, indent=1))
    m, t = res["mcnemar_vs_dense"], res["latency_s"]
    Path(a.summary).write_text("\n".join([
        f"## E-RET-PB3 reference arm recomputed ({REF_ARM})", "",
        f"Dense hit@5: {H.fmt_rate(res['dense'])}. Arm hit@5: {H.fmt_rate(res['hit5'])}; PB1 reported {PB1[REF_ARM]}/{len(hit)} for this arm.",
        f"McNemar vs dense (A = dense, B = arm): N={m['N']} b={m['b']} c={m['c']} p={m['p']}. Latency p50 {t['p50']} s, p95 {t['p95']} s.", ""]))


# ---------------------------------------------------------------- guard
def static_for(files: list[str]) -> set[str]:
    """Code-owned strings exempt from the window check: harness.static_strings plus every string constant of this file (labels such as
    model names may also occur in the corpus)."""
    s = H.static_strings(files, sys.argv[1:] + [x for arg in sys.argv[1:] for x in re.split(r"[,:]", arg)])
    s |= {n.value for n in ast.walk(ast.parse(Path(__file__).read_text())) if isinstance(n, ast.Constant) and isinstance(n.value, str) and len(n.value) >= 2}
    return s


def guard(a):
    pack = H.load_pack(a.pack)
    texts = H.corpus_texts(pack)
    hits = H.guard_findings(texts, a.files, static_for(a.files))
    if hits:  # offsets only; never the text
        raise SystemExit(f"GUARD FAILED: {len(hits)} corpus window(s) in outputs, first at {hits[0][0]!r} offset {hits[0][1]}")
    print(f"guard ok: {len(a.files)} file(s) scanned against {len(texts)} corpus texts")


# ---------------------------------------------------------------- selftest
def _fake_pack() -> dict:
    """Two questions with 30 candidates each; gold at dense position 7 (a dense miss) and 3 (a dense hit); one over-long passage."""
    mem, ch, qs = {}, {}, []
    for q, gp in enumerate((7, 3)):
        cands = []
        for i in range(1, 31):
            mid, cid = f"m{q}_{i}", f"c{q}_{i}"
            mem[mid] = {"status": "active", "title": f"title {q} {i}"}
            ch[cid] = f"chunk text {q} {i}" + (" NEEDLE" if i == gp else "") + (" long" * 800 if (q, i) == (0, 1) else "")
            cands.append([cid, mid, 1.0 - i / 100])
        qs.append({"qid": f"q{q}", "type": ("state", "fact")[q], "query": f"fake query {q}", "gold_memory_id": f"m{q}_{gp}", "cands": cands})
    return {"memories": mem, "chunks": ch, "questions": qs}


def _fake_jev(mode: str):
    """Local stand-in for the Jev API. Modes: ok, flat (equal probabilities), flaky (429 then 503 then ok per call), auth (401),
    quota (429 insufficient_quota), echo422 (422 whose body echoes a passage), down (500). Shape violations go to log['bad']."""
    seen, lock = collections.Counter(), threading.Lock()
    lg = {"bad": [], "sizes": [], "maxlen": 0, "models_get": 0}

    class Hd(http.server.BaseHTTPRequestHandler):
        def _send(self, code, obj, hdr=None):
            raw = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            for k, v in (hdr or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            with lock:
                lg["models_get"] += 1
                if self.path != "/v1/models" or self.headers["Authorization"] != "Bearer fake-jev-key":
                    lg["bad"].append("get")
            self._send(200, {"data": [{"id": "jev-latest"}, {"id": "jev-other"}]})

        def do_POST(self):
            raw = self.rfile.read(int(self.headers["Content-Length"]))
            body = json.loads(raw)
            st, qs = body["state"], body["questions"]
            ids = [p["id"] for p in st["passages"]]
            bad = []
            if self.path != "/v1/systemone" or self.headers["Authorization"] != "Bearer fake-jev-key" or self.headers[LONG_HDR] != "true":
                bad.append("path/auth/header")
            if body["model"] != MODEL or list(qs) != ids or not all(
                    q["type"] == "noul" and set(q["criteria"]) == {"true", "false"} and p in q["instructions"] for p, q in qs.items()):
                bad.append("shape")
            with lock:
                lg["bad"] += bad
                lg["sizes"].append(len(ids))
                lg["maxlen"] = max(lg["maxlen"], max(len(p["text"]) for p in st["passages"]))
                seen[raw] += 1
                n = seen[raw]
            if mode == "auth":
                return self._send(401, {"detail": "Invalid API key"})
            if mode == "quota":
                return self._send(429, {"error": {"code": "insufficient_quota", "message": "You exceeded your current quota"}})
            if mode == "echo422":
                return self._send(422, {"detail": [{"loc": ["body", "state"], "msg": "bad", "type": "value_error", "input": st["passages"][0]["text"]}]})
            if mode == "down":
                return self._send(500, {"detail": "boom"})
            if mode == "flaky" and n == 1:
                return self._send(429, {"detail": "slow down"}, {"Retry-After": "0", "X-RateLimit-Remaining": "0"})
            if mode == "flaky" and n == 2:
                return self._send(503, {"detail": "busy"})
            score = (lambda t: 0.5) if mode == "flat" else (lambda t: 0.9 if "NEEDLE" in t else 0.1)
            self._send(200, {"model": "jev-fake-1", "answers": {p["id"]: {"type": "noul", "noul": score(p["text"])} for p in st["passages"]},
                             "usage": {"input_tokens": len(raw) // 4, "output_tokens": 7}})

        def log_message(self, *args):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Hd)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}", lg


def selftest(_a=None):
    global BACKOFF, MAX_FAILS
    BACKOFF, MAX_FAILS = 0.0, 3
    assert abs(fisher(8, 10, 1, 6) - 0.034965) < 1e-5 and abs(fisher(5, 10, 5, 10) - 1.0) < 1e-9
    assert ident("insufficient_quota") and not ident("two words") and not ident(None)
    assert err_idents(b'{"detail":[{"type":"value_error","input":"free text here"}]}') == ["value_error"]
    assert msg_of(b'{"detail":"Invalid API key"}', "state with a passage", "fake-jev-key") == "Invalid API key"
    assert msg_of(b'{"detail":"echo of the passage text"}', "state with the passage text inside", "fake-jev-key") == "<withheld>"
    assert msg_of(b'{"detail":"bad key fake-jev-k..."}', "x", "fake-jev-key") == "<withheld>" and msg_of(b'{"detail":"short"}', "a short one", "k") == "<withheld>"
    assert MODEL in static_for([]) and "J1" in static_for([])
    pk = _fake_pack()
    tmp = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / f"eret_jev_selftest_{os.getpid()}"
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "ref.json").write_text(json.dumps({"n": 2, "dense": [0, 1], REF_ARM: [1, 0]}))

    def go(mode, cap=0, refpath=None):
        srv, base, lg = _fake_jev(mode)
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                out = run_all(Ctx("fake-jev-key", base, MODEL, cap), pk, refpath)
                text = render(out)
            return out, lg, buf.getvalue() + text + json.dumps(out)
        finally:
            srv.shutdown()

    try:
        # ok: gold at dense position 7 is lifted into the top 5 by both arms; request shape, truncation, call counts, pairing
        out, lg, _ = go("ok", refpath=str(tmp / "ref.json"))
        j1, j2 = out["arms"]
        assert out["dense"]["k"] == 1 and (j1["hit5"]["k"], j1["hit5"]["n"], j2["hit5"]["k"]) == (2, 2, 2), out["arms"]
        assert (j1["calls"], j1["calls_ok"], j2["calls"], j2["calls_ok"]) == (2, 2, 10, 10) and not out["stops"], out["arms"]
        assert sorted(lg["sizes"]) == [5] * 10 + [25] * 2 and lg["maxlen"] == MAXCH and not lg["bad"] and lg["models_get"] == 1, lg
        assert out["model"]["returned"] == "jev-fake-1" and "jev-latest" in out["model"]["listed"] and j1["input_tokens"]["total"] > 0
        c = out["comparisons"]
        assert (c[0]["N"], c[0]["b"], c[0]["c"]) == (2, 0, 1) and c[0]["paired"], c[0]  # J1 vs dense: dense [0, 1], J1 [1, 1]
        assert c[1]["paired"] and (c[1]["b"], c[1]["c"]) == (0, 1), c[1]  # J1 vs recomputed int8 bits [1, 0]
        assert not c[2]["paired"] and c[2]["A_hits"]["k"] == PB1["v2m3-L256-d25"] and (c[3]["b"], c[3]["c"]) == (0, 0), c
        # no ref bits: the int8 comparison falls back to the PB1 aggregate, unpaired
        out, _, _ = go("ok")
        assert not out["comparisons"][1]["paired"] and out["comparisons"][1]["A_hits"]["k"] == PB1[REF_ARM]
        # equal probabilities: ties fall back to dense order, so the arm equals dense
        out, _, _ = go("flat")
        assert out["arms"][0]["hit5"]["k"] == 1 and out["arms"][0]["ties_at_5_6"] == 2, out["arms"][0]
        # 429 then 503 then ok on every call: retried, all calls ok, codes and rate-limit headers recorded
        out, _, _ = go("flaky")
        assert (out["arms"][0]["calls_ok"], out["arms"][1]["calls_ok"], out["arms"][0]["retried_calls"]) == (2, 10, 2), out["arms"]
        assert out["http_codes"]["J1"] == {"429": 2, "503": 2, "200": 2} and "x-ratelimit-remaining" in out["ratelimit"]["headers"], out
        # 401: the arm stops with the raw code, J2 is not sent
        out, lg, _ = go("auth")
        s = out["stops"]
        assert len(s) == 1 and (s[0]["http"], s[0]["fatal"], s[0]["message"]) == (401, True, "Invalid API key") and out["arms"][1].get("not_run"), s
        # quota/billing on a 429 is not retried as a rate limit
        out, _, _ = go("quota")
        assert out["stops"][0]["why"] == "quota_or_billing" and out["stops"][0]["http"] == 429 and out["arms"][1].get("not_run"), out["stops"]
        # 422 stops each arm but not the job, and the echoed passage never reaches the log, the summary or the JSON
        out, lg, everything = go("echo422")
        assert [(x["arm"], x["http"], x["fatal"]) for x in out["stops"]] == [("J1", 422, False), ("J2", 422, False)], out["stops"]
        assert "chunk text" not in everything and "fake query" not in everything and "NEEDLE" not in everything
        # a dead endpoint trips the consecutive-failure breaker (MAX_FAILS = 3 here); J1 has only 2 calls
        out, _, _ = go("down")
        assert out["arms"][0]["calls_failed"] == 2 and out["stops"][0]["arm"] == "J2" and out["stops"][0]["why"] == "consecutive_failures", out["stops"]
        # token cap: checked before each call, fatal; after the first call's tokens every later call is refused
        out, _, _ = go("ok", cap=1)
        assert out["stops"][0]["why"] == "token_cap" and out["stops"][0]["fatal"] and out["totals"]["input_tokens_all_calls"] > 0, out["stops"]
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
    r.add_argument("--model", default=MODEL)
    r.add_argument("--max-tokens", type=int, default=0, help="tripwire on total input tokens (0 = off); pricing is undocumented")
    f = sp.add_parser("ref")
    for k in ("pack", "repo", "rev", "bits", "out", "summary"):
        f.add_argument("--" + k, required=True)
    g = sp.add_parser("guard")
    g.add_argument("--pack", required=True)
    g.add_argument("--files", nargs="+", required=True)
    sp.add_parser("selftest")
    a = ap.parse_args()
    try:
        if a.cmd == "run":
            sys.exit(run(a))
        elif a.cmd == "ref":
            ref(a)
        elif a.cmd == "guard":
            guard(a)
        else:
            selftest()
    except SystemExit:
        raise
    except Exception as ex:  # class and source line only: messages and locals can carry corpus text or the key
        fr = traceback.extract_tb(ex.__traceback__)
        print(f"FAILED {type(ex).__name__} at " + " <- ".join(f"{Path(x.filename).name}:{x.lineno}:{x.name}" for x in reversed(fr[-4:])), flush=True)
        if isinstance(ex, ImportError):
            print("detail:", str(ex)[:300], flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
