#!/usr/bin/env python3
"""E-RET-5a: CPU cross-encoder reranker throughput bench (experiment; public models + public C-MTEB data only).

`run`       one model per process (so ru_maxrss is that model's peak): licence + pin check, card-format sanity,
            throughput grid (max_length x batch), derived per-query latency, one real depth-25 query, peak RSS.
`aggregate` stdlib-only merge of the per-model JSON files into one artifact + markdown tables.
Stdout of `run` / `aggregate` is markdown (appended to $GITHUB_STEP_SUMMARY); progress goes to stderr.
Only aggregates are emitted: no dataset text is printed or stored in the results.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import os
import re
import resource
import statistics
import subprocess
import sys
import time
from pathlib import Path

DATASET_REPO = "C-MTEB/T2Reranking"
DATASET_REV = "76631901a18387f85eaa53e5450019b87ad58ef9"
DATASET_FILE = "data/dev-00000-of-00001-65d96bde8023d9b9.parquet"
DATASET_SHA256 = "ceaf1ba1a4777dbb7aecad86fb8aa9cae7a678af6d711d5529c238e89bb6adff"
# HF card of the mirror states no licence; the upstream T2Ranking README (github.com/THUIR/T2Ranking, read 2026-10-20) says Apache-2.0.
DATASET_LICENCE = "Apache-2.0 (upstream THUIR/T2Ranking README; HF mirror card states none)"

OK_LICENCES = {"apache-2.0", "mit"}  # commercial use allowed; anything else excludes the model (e.g. cc-by-nc)
POOL = 64  # distinct (query, long doc) pairs per length; batches cycle through them
DEPTHS = (10, 25, 50, 100)
FULL = dict(lengths=(256, 512), batches=(8, 16, 32), budget_s=90.0, max_timed=40, query_depth=25)
SMOKE = dict(lengths=(256, 512), batches=(8,), budget_s=10.0, max_timed=3, query_depth=5)
CELLS_DEADLINE_S = 38 * 60  # stop starting new cells after this; the job limit is 60 min incl. install + download

# Qwen3-Reranker model card (Transformers usage), reproduced as source text so the job can grep the pinned README for it.
QWEN_FORMAT = "<Instruct>: {instruction}\n<Query>: {query}\n<Document>: {doc}"
QWEN_PREFIX = ('<|im_start|>system\nJudge whether the Document meets the requirements based on the Query and the Instruct '
               'provided. Note that the answer can only be "yes" or "no".<|im_end|>\n<|im_start|>user\n')
QWEN_SUFFIX = "<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n"
QWEN_TASK = "Given a web search query, retrieve relevant passages that answer the query"
PANDA = ("The giant panda (Ailuropoda melanoleuca), sometimes called a panda bear or simply panda, "
         "is a bear species endemic to China.")  # bge model card example passage
GRAVITY = ("Gravity is a force that attracts two bodies towards each other. It gives weight to physical objects and is "
           "responsible for the movement of planets around the sun.")  # Qwen3 model card example passage

torch = None  # imported lazily so `aggregate` needs no ML stack


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def rss_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # Linux: KiB


def src_form(s: str) -> str:
    """The text as it appears inside a Python source literal in a README (newline and quote escaped)."""
    return s.replace("\n", "\\n").replace('"', '\\"')


class Scorer:
    """Scores (query, doc) pairs exactly as the model card's own transformers snippet does."""

    def __init__(self, kind: str, path: str):
        from transformers import AutoModelForCausalLM, AutoModelForSequenceClassification, AutoTokenizer
        self.kind = kind
        if kind == "seqcls":  # bge: cross-encoder logit, one per pair
            self.tok = AutoTokenizer.from_pretrained(path)
            self.model = AutoModelForSequenceClassification.from_pretrained(path, torch_dtype=torch.float32)
        else:  # Qwen3-Reranker: P("yes") from the last-position logits
            self.tok = AutoTokenizer.from_pretrained(path, padding_side="left")
            self.model = AutoModelForCausalLM.from_pretrained(path, torch_dtype=torch.float32)
            self.no = self.tok.convert_tokens_to_ids("no")
            self.yes = self.tok.convert_tokens_to_ids("yes")
            self.pre = self.tok.encode(QWEN_PREFIX, add_special_tokens=False)
            self.suf = self.tok.encode(QWEN_SUFFIX, add_special_tokens=False)
        self.model.eval()
        self.params = sum(p.numel() for p in self.model.parameters())

    def encode(self, pairs, length: int):
        if self.kind == "seqcls":
            return self.tok([list(p) for p in pairs], padding=True, truncation=True, max_length=length, return_tensors="pt")
        texts = [QWEN_FORMAT.format(instruction=QWEN_TASK, query=q, doc=d) for q, d in pairs]
        enc = self.tok(texts, padding=False, truncation="longest_first", return_attention_mask=False,
                       max_length=length - len(self.pre) - len(self.suf))
        enc["input_ids"] = [self.pre + ids + self.suf for ids in enc["input_ids"]]
        return self.tok.pad(enc, padding=True, return_tensors="pt", max_length=length)

    def forward(self, enc, literal: bool = False):
        """Call under torch.inference_mode(). literal=True computes logits at every position like the Qwen card does;
        the default keeps only the last position (identical scores, no [batch, len, vocab] tensor)."""
        if self.kind == "seqcls":
            return self.model(**enc, return_dict=True).logits.view(-1).float()
        last = self.model(**enc, **({} if literal else {"logits_to_keep": 1})).logits[:, -1, :]
        two = torch.log_softmax(torch.stack([last[:, self.no], last[:, self.yes]], dim=1), dim=1)
        return two[:, 1].exp()

    def score(self, pairs, length: int = 512, literal: bool = False):
        with torch.inference_mode():
            return self.forward(self.encode(pairs, length), literal).tolist()


def build_pool(rows, min_chars: int):
    """POOL (query, doc) pairs whose doc concatenates real passages until it is long enough to fill a pair to exactly L tokens."""
    pool = []
    for i in range(POOL):
        docs = list(rows[i]["positive"]) + list(rows[i]["negative"])
        j = POOL
        while sum(map(len, docs)) < min_chars and j < POOL + len(rows):
            docs += list(rows[(i + j) % len(rows)]["positive"])
            j += 1
        pool.append((rows[i]["query"], "\n".join(docs)))
    return pool


def time_cell(sc: Scorer, enc, length: int, b: int, prof, literal: bool = False):
    """Warm up 1 batch, then time batches until the cell budget or max_timed; at least 1 timed batch."""
    n = enc["input_ids"].shape[0]

    def batch(k):
        idx = [(k * b + j) % n for j in range(b)]
        return {key: v[idx] for key, v in enc.items()}

    lat = []
    with torch.inference_mode():
        t = time.perf_counter()
        sc.forward(batch(0), literal)
        warm = time.perf_counter() - t
        start = time.perf_counter()
        k = 1
        while len(lat) < prof["max_timed"]:
            est = statistics.median(lat) if lat else warm
            if lat and (time.perf_counter() - start) + est > prof["budget_s"]:
                break
            x = batch(k)
            t = time.perf_counter()
            sc.forward(x, literal)
            lat.append(time.perf_counter() - t)
            k += 1
    import numpy as np
    total = sum(lat)
    return {"L": length, "b": b, "literal_full_logits": literal, "n_batches": len(lat), "warmup_s": round(warm, 3),
            "timed_s": round(total, 3), "pairs_per_s": round(len(lat) * b / total, 4),
            "p50_ms": round(float(np.percentile(lat, 50)) * 1000, 1), "p95_ms": round(float(np.percentile(lat, 95)) * 1000, 1),
            "min_ms": round(min(lat) * 1000, 1), "max_ms": round(max(lat) * 1000, 1), "rss_mb": round(rss_mb())}


def score_query(sc: Scorer, query: str, docs, length: int, b: int):
    """One end-to-end rerank call (tokenise + forward in batches of b). Returns (total_s, tokenise_s, mean_tokens)."""
    tok_s, toks, t0 = 0.0, [], time.perf_counter()
    with torch.inference_mode():
        for i in range(0, len(docs), b):
            t = time.perf_counter()
            enc = sc.encode([(query, d) for d in docs[i:i + b]], length)
            tok_s += time.perf_counter() - t
            toks += enc["attention_mask"].sum(1).tolist()
            sc.forward(enc)
    return time.perf_counter() - t0, tok_s, sum(toks) / len(toks)


def measure_overhead(sc: Scorer, pools):
    """fixed_call_s: forward of one short pair (framework dispatch, thread wake-up). tok_s_per_pair[L]: tokenise+tensorise."""
    short = sc.encode([("什么是熊猫?", "熊猫")], 128)
    with torch.inference_mode():
        for _ in range(2):
            sc.forward(short)
        ts = []
        for _ in range(10):
            t = time.perf_counter()
            sc.forward(short)
            ts.append(time.perf_counter() - t)
    tok = {}
    for length, pool in pools.items():
        ts2 = []
        for _ in range(5):
            t = time.perf_counter()
            sc.encode(pool[:32], length)
            ts2.append((time.perf_counter() - t) / 32)
        tok[str(length)] = statistics.median(ts2)
    return {"fixed_call_s": statistics.median(ts), "tok_s_per_pair": tok}


def sanity(sc: Scorer):
    """Card example must rank as the card shows/implies; the Chinese pair is an extra, informational check."""
    zh = [("中国的首都是哪里？", "北京是中华人民共和国的首都。"), ("中国的首都是哪里？", "香蕉是一种热带水果，富含钾元素。")]
    if sc.kind == "seqcls":
        s = sc.score([("what is panda?", "hi"), ("what is panda?", PANDA)], 512)
        z = sc.score(zh, 512)
        return {"card_scores": s, "pass": s[1] > s[0], "zh_scores": z, "zh_ok": z[0] > z[1]}
    qs, ds = ["What is the capital of China?", "Explain gravity"], ["The capital of China is Beijing.", GRAVITY]
    pairs = [(q, d) for q in qs for d in ds]  # card pairs are the diagonal; the off-diagonal pairs are the contrast
    s, lit, z = sc.score(pairs, 8192), sc.score(pairs, 8192, literal=True), sc.score(zh, 8192)
    diff = max(abs(a - b) for a, b in zip(s, lit))
    return {"card_scores_2x2": s, "diag_beats_offdiag": s[0] > s[1] and s[3] > s[2], "diag_yes_gt_half": s[0] > .5 and s[3] > .5,
            "last_logit_vs_full_logits_max_abs_diff": diff, "pass": s[0] > s[1] and s[3] > s[2] and s[0] > .5 and s[3] > .5 and diff < 1e-3,
            "zh_scores": z, "zh_ok": z[0] > z[1]}


def card_markers(kind: str, readme: str):
    """Does the pinned README still contain the snippet pieces this harness reproduces? (recorded, not enforced)"""
    if kind == "seqcls":
        want = ["AutoModelForSequenceClassification", "truncation=True", "max_length=512", "logits.view(-1, ).float()", PANDA[:40]]
    else:
        want = [src_form(QWEN_FORMAT), src_form(QWEN_PREFIX), src_form(QWEN_SUFFIX), "padding_side='left'", "[:, -1, :]", "log_softmax", GRAVITY[:40]]
    return {w[:48]: (w in readme or w.replace("'", '"') in readme) for w in want}


@contextlib.contextmanager
def stage(res, name, save):
    try:
        yield
    except Exception as e:  # keep partial results; the job still ends red via res["errors"]
        res["errors"].append({"stage": name, "error": repr(e)[:600]})
        log("STAGE FAILED", name, repr(e))
    finally:
        save()


def env_info():
    def sh(c):
        return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=20).stdout
    kv = dict((l.split(":", 1)[0].strip(), l.split(":", 1)[1].strip()) for l in sh("lscpu").splitlines() if ":" in l)
    feats = kv.get("Flags") or kv.get("Features") or ""
    mem = re.search(r"MemTotal:\s+(\d+) kB", sh("cat /proc/meminfo"))
    import transformers
    return {"cpu_model": kv.get("Model name"), "arch": kv.get("Architecture"), "cpu_count": os.cpu_count(),
            "mem_total_gb": round(int(mem.group(1)) / 1048576, 1) if mem else None,
            "cpu_feats": [f for f in feats.split() if f in {"bf16", "i8mm", "sve", "sve2", "asimddp", "fphp", "avx2", "avx512f", "amx_tile"}],
            "python": sys.version.split()[0], "torch": torch.__version__, "transformers": transformers.__version__,
            "threads": torch.get_num_threads(), "mkldnn": torch.backends.mkldnn.is_available(),
            "parallel_info": torch.__config__.parallel_info().replace("\n", "; ")[:400]}


def derive(res):
    """latency(depth, L, b) = depth / pairs_per_s(L, b) + depth * tok_s_per_pair(L) + fixed_call_s."""
    ov, out = res.get("overhead"), []
    if not ov:
        return out
    for c in res["cells"]:
        if "pairs_per_s" not in c or c.get("literal_full_logits"):
            continue
        extra = ov["fixed_call_s"]
        out.append({"L": c["L"], "b": c["b"], "latency_s": {str(d): round(d / c["pairs_per_s"] + d * ov["tok_s_per_pair"][str(c["L"])] + extra, 3)
                                                              for d in DEPTHS}})
    return out


def run(a):
    global torch
    import torch as _t
    torch = _t
    import numpy as np  # noqa: F401  (fail early if missing)
    import pyarrow.parquet as pq
    from huggingface_hub import HfApi, hf_hub_download, snapshot_download

    prof = SMOKE if a.smoke else FULL
    t_job = time.monotonic()
    torch.set_num_threads(4)
    res = {"key": a.key, "repo": a.repo, "revision": a.revision, "kind": a.kind, "profile": "smoke" if a.smoke else "full",
           "cells": [], "errors": []}
    out = Path(a.out)

    def save():
        out.write_text(json.dumps(res, indent=1))

    res["env"] = env_info()

    # 1. in-job pin + licence check; a licence outside OK_LICENCES excludes the model (card rule)
    api = HfApi()
    head = api.model_info(a.repo).sha
    info = api.model_info(a.repo, revision=a.revision)
    readme_path = hf_hub_download(a.repo, "README.md", revision=a.revision)
    readme = Path(readme_path).read_text(encoding="utf-8")
    m = re.search(r"^license:\s*(\S+)", readme, re.M)
    lic = (info.card_data.license if info.card_data else None) or (m.group(1) if m else None)
    res["model"] = {"head_sha_now": head, "pinned_resolves_to": info.sha, "pinned_is_head": head == a.revision,
                    "licence_api": info.card_data.license if info.card_data else None, "licence_readme_header": m.group(1) if m else None,
                    "readme_sha256": hashlib.sha256(readme.encode()).hexdigest(), "card_markers": card_markers(a.kind, readme)}
    log("pin", a.repo, "pinned", a.revision, "api_resolves_to", info.sha, "head_now", head, "licence", lic)
    save()
    if info.sha != a.revision:
        raise SystemExit(f"pin {a.revision} does not resolve to itself ({info.sha})")
    if str(lic).lower() not in OK_LICENCES:
        res["model"]["excluded"] = f"licence {lic!r} not in {sorted(OK_LICENCES)}"
        save()
        raise SystemExit(res["model"]["excluded"])

    # 2. data first: the arrow table is freed before the model loads, so the RSS peak below belongs to the model phase
    pools, rows = {}, None
    with stage(res, "data", save):
        pq_path = hf_hub_download(DATASET_REPO, DATASET_FILE, repo_type="dataset", revision=DATASET_REV)
        h = hashlib.sha256()
        with open(pq_path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        res["dataset"] = {"repo": DATASET_REPO, "revision": DATASET_REV, "file": DATASET_FILE, "sha256_ok": h.hexdigest() == DATASET_SHA256,
                          "licence": DATASET_LICENCE}
        if h.hexdigest() != DATASET_SHA256:
            raise RuntimeError("dataset file hash mismatch")
        rows = pq.read_table(pq_path).slice(0, 300).to_pylist()
        for length in prof["lengths"]:
            pools[length] = build_pool(rows, 3 * length)
    if not pools:
        res["errors"].append({"stage": "abort", "error": "no data"})
        save()
        raise SystemExit("no data")
    res["rss_baseline_mb"] = round(rss_mb())

    # 3. download, then load (separately timed)
    t = time.perf_counter()
    path = snapshot_download(a.repo, revision=a.revision, allow_patterns=["*.json", "*.safetensors", "*.model", "*.txt", "README.md"])
    res["model"]["download_s"] = round(time.perf_counter() - t, 1)
    t = time.perf_counter()
    sc = Scorer(a.kind, path)
    res["model"].update(load_s=round(time.perf_counter() - t, 1), params_m=round(sc.params / 1e6, 1), rss_after_load_mb=round(rss_mb()))
    log("loaded", res["model"])
    save()

    # 4. sanity (card format)
    with stage(res, "sanity", save):
        res["sanity"] = sanity(sc)
        log("sanity", res["sanity"])

    # 5. overhead, then the throughput grid
    with stage(res, "overhead", save):
        res["overhead"] = measure_overhead(sc, pools)
        log("overhead", res["overhead"])
    deadline = time.monotonic() + CELLS_DEADLINE_S
    for length in prof["lengths"]:
        with stage(res, f"encode L={length}", save):
            enc = sc.encode(pools[length], length)
            if tuple(enc["input_ids"].shape) != (POOL, length) or not bool(enc["attention_mask"].all()):
                raise RuntimeError(f"pool is not exactly {length} tokens: {tuple(enc['input_ids'].shape)}")
            for b in prof["batches"]:
                if time.monotonic() > deadline:
                    res["cells"].append({"L": length, "b": b, "skipped": "deadline"})
                    continue
                with stage(res, f"cell L={length} b={b}", save):
                    c = time_cell(sc, enc, length, b, prof)
                    res["cells"].append(c)
                    log("cell", c)
    res["derived"] = derive(res)
    res["peak_rss_mb_grid"] = round(rss_mb())
    save()

    # 6. one real query: depth query_depth, L=512; predicted (from the grid) vs measured
    with stage(res, "query", save):
        depth, length = prof["query_depth"], 512
        done = [c for c in res["cells"] if c.get("L") == length and "pairs_per_s" in c]
        if not done:
            raise RuntimeError("no L=512 cell to predict from")
        best = max(done, key=lambda c: c["pairs_per_s"])
        b = best["b"]
        row = next(r for r in rows if len(r["positive"]) + len(r["negative"]) >= depth)
        cands = (list(row["positive"]) + list(row["negative"]))[:depth]
        longs = []
        for k in range(depth):  # real candidate k first, then the others, until the pair fills 512 tokens
            d, i = cands[k], 1
            while len(d) < 3 * length and i < 500:
                d += "\n" + cands[(k + i) % depth]
                i += 1
            longs.append(d)
        tot, tok, exact_len = score_query(sc, row["query"], longs, length, b)
        ov = res["overhead"]
        pred = depth / best["pairs_per_s"] + depth * ov["tok_s_per_pair"][str(length)] + ov["fixed_call_s"]
        pred_ceil = math.ceil(depth / b) * best["p50_ms"] / 1000 + depth * ov["tok_s_per_pair"][str(length)] + ov["fixed_call_s"]
        nat_tot, nat_tok, nat_len = score_query(sc, row["query"], cands, length, b)
        res["query"] = {"depth": depth, "L": length, "b": b, "predicted_s": round(pred, 2), "predicted_ceil_batches_s": round(pred_ceil, 2),
                        "measured_exact_L_s": round(tot, 2), "exact_mean_tokens": round(exact_len, 1), "measured_exact_L_tokenise_s": round(tok, 3),
                        "ratio_measured_over_predicted": round(tot / pred, 3),
                        "natural_passages_s": round(nat_tot, 2), "natural_mean_tokens": round(nat_len, 1)}
        log("query", res["query"])

    # 7. Qwen only: the card-literal path (logits at every position), run last so it cannot inflate the RSS of the cells above
    res["peak_rss_mb_before_literal"] = round(rss_mb())
    if a.kind == "causal_yesno":
        with stage(res, "literal", save):
            enc = sc.encode(pools[512], 512)
            c = time_cell(sc, enc, 512, 8, prof, literal=True)
            res["cells"].append(c)
            log("literal", c)
    res["peak_rss_mb"] = round(rss_mb())
    res["job_wall_s"] = round(time.monotonic() - t_job, 1)
    save()
    print(render([res]))
    if res["errors"]:
        raise SystemExit(f"{len(res['errors'])} stage error(s): {res['errors']}")


def fmt(x, nd=2):
    return "n/a" if x is None else f"{x:.{nd}f}"


def render(results):
    """Markdown tables (aggregates only). Works for one result or all models."""
    if not results:
        return "no results"
    e = results[0]["env"]
    L = ["## E-RET-5a: CPU reranker bench",
         f"Runner: {e['cpu_model']} ({e['arch']}), {e['cpu_count']} vCPU, {e['mem_total_gb']} GB; torch {e['torch']}, transformers {e['transformers']}, "
         f"threads {e['threads']}, fp32, eval + inference_mode; features {','.join(e['cpu_feats'])}; profile {results[0]['profile']}", ""]
    L += ["### Models", "| model | revision | licence | pin==HEAD now | params (M) | download s | load s | RSS after load MB | peak RSS MB | sanity |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for r in results:
        m = r.get("model", {})
        sn = r.get("sanity", {})
        L.append(f"| {r['repo']} | `{r['revision'][:12]}` | {m.get('licence_api') or m.get('licence_readme_header')} | {m.get('pinned_is_head')} | "
                 f"{m.get('params_m')} | {m.get('download_s')} | {m.get('load_s')} | {m.get('rss_after_load_mb')} | {r.get('peak_rss_mb')} | "
                 f"{'PASS' if sn.get('pass') else 'FAIL' if sn else 'n/a'} |")
    L += ["", "### Throughput (batches of exactly L tokens, 4 threads)",
          "| model | L | batch | timed batches | pairs/s | p50 ms/batch | p95 ms/batch | max ms |", "|---|---|---|---|---|---|---|---|"]
    for r in results:
        for c in r["cells"]:
            if "pairs_per_s" in c:
                tag = " (card-literal full logits)" if c.get("literal_full_logits") else ""
                L.append(f"| {r['key']}{tag} | {c['L']} | {c['b']} | {c['n_batches']} | {c['pairs_per_s']} | {c['p50_ms']} | {c['p95_ms']} | {c['max_ms']} |")
            else:
                L.append(f"| {r['key']} | {c['L']} | {c['b']} | skipped: {c.get('skipped')} | | | | |")
    L += ["", "### Derived per-query latency (s) = depth / pairs_per_s + depth * tokenise_s_per_pair + fixed_call_s; best batch size per L",
          "| model | L | best batch | fixed call ms | tokenise ms/pair | depth 10 | depth 25 | depth 50 | depth 100 |", "|---|---|---|---|---|---|---|---|---|"]
    for r in results:
        for length in sorted({d["L"] for d in r.get("derived", [])}):
            best = min((d for d in r["derived"] if d["L"] == length), key=lambda d: d["latency_s"]["100"])
            ov = r["overhead"]
            L.append(f"| {r['key']} | {length} | {best['b']} | {fmt(ov['fixed_call_s'] * 1000, 1)} | {fmt(ov['tok_s_per_pair'][str(length)] * 1000, 2)} | "
                     + " | ".join(fmt(best["latency_s"][str(d)]) for d in DEPTHS) + " |")
    L += ["", "### One real query (depth 25 at L=512 unless smoke): predicted vs measured",
          "| model | depth | batch | predicted s | predicted (ceil batches) s | measured s (exact L) | measured/predicted | natural passages s | natural mean tokens |",
          "|---|---|---|---|---|---|---|---|---|"]
    for r in results:
        q = r.get("query")
        if q:
            L.append(f"| {r['key']} | {q['depth']} | {q['b']} | {q['predicted_s']} | {q['predicted_ceil_batches_s']} | {q['measured_exact_L_s']} | "
                     f"{q['ratio_measured_over_predicted']} | {q['natural_passages_s']} | {q['natural_mean_tokens']} |")
    errs = [(r["key"], x) for r in results for x in r.get("errors", [])]
    if errs:
        L += ["", "### Errors"] + [f"- {k}: {x['stage']}: {x['error']}" for k, x in errs]
    return "\n".join(L)


def aggregate(parts: str, out: str):
    results = [json.loads(p.read_text()) for p in sorted(Path(parts).rglob("result-*.json"))]
    Path(out).write_text(json.dumps({"models": results}, indent=1))
    print(render(results))


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    for k in ("key", "repo", "revision", "out"):
        r.add_argument(f"--{k}", required=True)
    r.add_argument("--kind", choices=["seqcls", "causal_yesno"], required=True)
    r.add_argument("--smoke", action="store_true")
    g = sub.add_parser("aggregate")
    g.add_argument("parts")
    g.add_argument("out")
    a = p.parse_args()
    run(a) if a.cmd == "run" else aggregate(a.parts, a.out)


if __name__ == "__main__":
    main()
