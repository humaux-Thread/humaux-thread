#!/usr/bin/env python3
"""E-RET-PB7: local rerank models and configurations on the hybrid RRF pool of E-RET-5f, accuracy plus N2 speed, and an N1 bench bundle. Experiment, not product code.

Question (owner, 2026-10-22): a locally deployed reranker. Target on N1: rerank stage p50 <= 1 s and p95 <= 2 s, and hit@5 significantly above RRF alone (96/198).
Reference (PB6, run 39629912275): cloud gte-rerank-v2 140, local bge-reranker-base int8 L512 K25 111 (p .077 vs RRF, 6.4 s p50 on N1). N1 is ~1.9x slower
than the N2 CI runner, so the N2 screening bar is p50 <= 0.5 s per query.

Imports (does not copy): rrf_rerank.py (the private pools file its `pools` stage writes, hit_bits / by_type / repro_check / guard), rerank.py (Scorer, pin_and_licence,
download, and its `export-ort` CLI = 5a's int8 recipe), harness.py (statistics). Nothing here prints or writes corpus text: counts, rates, intervals, b/c/p, latencies.

Subcommands:
  selftest     pure checks, no model, no network (fake scorer, fake parts, guard red/green)
  grid         arms x cells on the private RRF pool (or `--pools fake`: public toy text, real models). One job = one process = one runner.
  merge        grid parts -> results.json, summary, qualify.json (the cells that go into the N1 bundle)
  guard        fail if any 12-character window of corpus text occurs in the given output files
  bundle       build the N1 bench bundle directory from qualify.json (or --cells-spec for a dry run). Public model and public data only.
  notes        release notes for the bundle
  export-gte   internal: fp32 ONNX + dynamic int8 of the gte remote-code model, in its own process (as 5a's export-ort)

Pre-registered before any result was seen (card E-RET-PB7):
  pool        PB6's hybrid RRF pool (client RRF k=60, exact q0 dense + qdrant/bm25 multilingual), reproduction gate hit@5 96 and pool@25 147.
  documents   title + "\\n" + best chunk, exactly as PB6; the (query, document) pair is cut to L tokens by the tokenizer, no character cut.
  grid        model x precision x K in {10, 25} x L in {256, 512}; int8 for every model, plus fp32 for gte. K = first K memories of the RRF pool.
  timing      per query, tokenise + forward for the K documents in batches of 8 with dynamic padding, 4 threads, p50 / p95 over the queries with a non-empty
              pool, one untimed warm-up query per cell.
  PRIMARY     gte-multilingual-reranker-base int8 (fp32 if int8 is impossible), K=10, L=256, hit@5 against RRF alone, paired exact McNemar. Everything else secondary.
  qualify     a cell qualifies for the N1 bundle iff McNemar vs RRF p < .05 with c > b (it beats RRF) AND N2 p50 <= 0.5 s AND it is int8. At most 3 cells: highest
              hit@5 first, then lowest p50.
"""
from __future__ import annotations

import argparse
import gc
import hashlib
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import traceback
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import harness as H  # noqa: E402  (stdlib only: statistics, guard)
import rrf_rerank as RR  # noqa: E402  (stdlib at import time: pools file helpers, repro check, guard)

RRF = RR.RRF
# Pins: commit SHAs of the official repos (git ls-remote, 2026-10-22). The licence is read from the pinned revision's model card inside the job
# (rerank.pin_and_licence): anything but apache-2.0 / mit drops the model. gte's remote code lives in a second repo; both of its files are pinned by sha256
# (read in full on 2026-10-22: imports are torch and transformers only, no network, no subprocess) and copied next to the weights, so nothing is fetched at load time.
MODELS = {
    "gte": {"repo": "Alibaba-NLP/gte-multilingual-reranker-base", "rev": "8215cf04918ba6f7b6a62bb44238ce2953d8831c", "precisions": ("int8", "fp32"),
            "code": {"repo": "Alibaba-NLP/new-impl", "rev": "40ced75c3017eb27626c9d4ea981bde21a2662f4",
                     "sha256": {"modeling.py": "374670b416fcc82f081c9cd28b5fd61c2bd91bbe18eb4798fcc48a81f9c250a0",
                                "configuration.py": "3411088045ffb8a9a0aa9936eae275896b39983a2ee5b08f091b44e6289e4fe4"}}},
    "mmarco12": {"repo": "cross-encoder/mmarco-mMiniLMv2-L12-H384-v1", "rev": "1427fd652930e4ba29e8149678df786c240d8825", "precisions": ("int8",)},
    "bge": {"repo": "BAAI/bge-reranker-base", "rev": "2cfc18c9415c912f9d8155881c133215df768a70", "precisions": ("int8",)},  # 5a / PB6 revision
}
ABSENT = ("cross-encoder/mmarco-mMiniLMv2-L6-H384-v1",)  # optional model 4: `git ls-remote` asked for credentials (= no such repo); re-checked in-job
PRIMARY = ("gte", "int8", 10, 256)
CELLS = ((10, 256), (25, 256), (10, 512), (25, 512))  # the primary cell first, so a budget stop costs the least
ALPHA, P50_MAX_S, BUNDLE_CAP, PARITY_MIN = 0.05, 0.5, 3, 0.9
POOLS = (10, 25)
CARD_FLAGS = ("non-commercial", "noncommercial", "non commercial", "research only", "research purposes only", "cc-by-nc", "not for commercial")
# Public C-MTEB/T2Reranking sample, as n1-bench-bundle-v1 (E-RET-5e): pinned revision and file hash; the HF mirror card states no licence, the upstream
# T2Ranking README (github.com/THUIR/T2Ranking, read 2026-10-20 by E-RET-5a) says Apache-2.0.
DATASET_REPO, DATASET_REV = "C-MTEB/T2Reranking", "76631901a18387f85eaa53e5450019b87ad58ef9"
DATASET_FILE = "data/dev-00000-of-00001-65d96bde8023d9b9.parquet"
DATASET_SHA256 = "ceaf1ba1a4777dbb7aecad86fb8aa9cae7a678af6d711d5529c238e89bb6adff"
BENCH_ROWS, BENCH_QUERIES, BENCH_DOC_CHARS = 300, 12, 1800
TOKENIZER_FILES = ("tokenizer.json", "tokenizer_config.json", "special_tokens_map.json", "sentencepiece.bpe.model", "config.json")

# Public sanity / parity texts (model-card style examples written for this card): one relevant passage first, then three that are not.
PUB = (
    ("what is panda?", "The giant panda (Ailuropoda melanoleuca), sometimes called a panda bear or simply panda, is a bear species endemic to China.",
     ("hi", "The stock market closed higher on Friday after a strong jobs report.", "A recipe for tomato soup needs ripe tomatoes, onions and garlic.")),
    ("中国的首都在哪儿", "北京是中华人民共和国的首都，也是全国的政治中心和文化中心。",
     ("苹果是一种常见的水果，富含维生素。", "今天的足球比赛在晚上八点开始。", "上海是中国最大的经济中心城市之一。")),
    ("how to implement quick sort in python?", "Quick sort picks a pivot, partitions the list around it and recurses on both sides; in Python it takes a few lines.",
     ("The Great Wall of China was built over many centuries to protect the northern borders.", "Photosynthesis converts light energy into chemical energy in plants.",
      "The marathon is a long-distance race of 42.195 kilometres.")),
    ("who wrote the novel Pride and Prejudice?", "Pride and Prejudice is an 1813 novel by the English author Jane Austen.",
     ("Mount Everest is the highest mountain above sea level.", "A balanced diet includes vegetables, fruit, grains and protein.", "The train to the airport leaves every ten minutes.")),
    ("光合作用是什么", "光合作用是植物、藻类和某些细菌利用光能把二氧化碳和水转化为有机物并释放氧气的过程。",
     ("长城是中国古代的军事防御工程。", "明天的天气预报说有小雨。", "这家餐厅的招牌菜是红烧肉。")),
    ("how long is a marathon?", "A marathon is a long-distance running race with an official distance of 42.195 kilometres.",
     ("Jane Austen published six major novels.", "The recipe asks for two cups of flour and one egg.", "Pandas eat mostly bamboo.")),
)


def log(*a):
    print(*a, file=sys.stderr, flush=True)


class Skip(Exception):
    """A model cannot be used for a reason that is a result, not a bug (licence, pin mismatch, code hash)."""


def where(ex: BaseException) -> str:
    fr = traceback.extract_tb(ex.__traceback__)
    return " <- ".join(f"{Path(x.filename).name}:{x.lineno}:{x.name}" for x in reversed(fr[-4:]))


def one_line(s, n: int = 300) -> str:
    return " ".join(str(s).split())[:n]


def sha256_file(p) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def lat_stats(xs) -> dict:
    if not xs:
        return {"n": 0, "p50": None, "p95": None, "mean": None, "max": None}
    return {"n": len(xs), "p50": round(H.pct(xs, .5), 3), "p95": round(H.pct(xs, .95), 3), "mean": round(sum(xs) / len(xs), 3), "max": round(max(xs), 3)}


def cell_id(key: str, prec: str, K: int, L: int) -> str:
    return f"{key}:{prec}:K{K}:L{L}"


def parse_arms(spec: str) -> list[tuple[str, str]]:
    out = []
    for x in [x for x in spec.split(",") if x]:
        key, _, prec = x.partition(":")
        if key not in MODELS or prec not in MODELS[key]["precisions"]:
            raise SystemExit(f"unknown arm {x!r}")
        out.append((key, prec))
    return out


def parse_cells(spec: str) -> list[tuple[int, int]]:
    out = []
    for x in [x for x in spec.split(",") if x]:
        k, _, l = x.partition("x")
        out.append((int(k), int(l)))
    return out


def qualifies(c: dict) -> bool:
    """Beats RRF significantly (p < .05 and c > b) with an N2 p50 inside the screening bar. Precision is checked by pick_bundle (only int8 can be bundled)."""
    v, t = c.get("vs_rrf"), c.get("latency_s")
    return bool(v and t and t.get("p50") is not None and v["p"] < ALPHA and v["c"] > v["b"] and t["p50"] <= P50_MAX_S)


def pick_bundle(cells: list[dict]) -> list[dict]:
    q = [c for c in cells if qualifies(c) and c["precision"] == "int8"]
    q.sort(key=lambda c: (-c["hit5"]["k"], c["latency_s"]["p50"], c["id"]))
    return q[:BUNDLE_CAP]


# ---------------------------------------------------------------- scorers (torch / onnxruntime; imported lazily so selftest needs neither)
_LS = None


def scorer_cls():
    """rerank.Scorer (PB6's scorer: encode / forward / score_query / sanity) plus token statistics. The base __init__ is used for PB6's int8 path (bge);
    the other models hand over a tokenizer and a model object built here."""
    global _LS
    if _LS is None:
        import rerank as R

        class LocalScorer(R.Scorer):
            def __init__(self, kind, path=None, tok=None, model=None):
                self.lens = self.pads = None  # lists while a cell is recorded
                if model is None:
                    super().__init__(kind, path)
                else:
                    self.kind, self.tok, self.model, self.export_s = kind, tok, model, None

            def encode(self, pairs, length):
                enc = super().encode(pairs, length)
                if self.lens is not None:
                    self.lens += enc["attention_mask"].sum(1).tolist()
                    self.pads += [int(enc["input_ids"].shape[1])] * int(enc["input_ids"].shape[0])
                return enc

        _LS = LocalScorer
    return _LS


class RawOrt:
    """An onnxruntime session behind the call signature rerank.Scorer.forward expects from an ORT model: model(**enc).logits."""

    def __init__(self, path):
        import onnxruntime as ort
        so = ort.SessionOptions()
        so.intra_op_num_threads, so.inter_op_num_threads = 4, 1  # as 5a / PB6
        self.sess = ort.InferenceSession(str(path), so, providers=["CPUExecutionProvider"])
        self.names = [i.name for i in self.sess.get_inputs()]

    def __call__(self, **enc):
        import numpy as np
        import torch
        feeds = {k: v.numpy().astype(np.int64, copy=False) for k, v in enc.items() if k in self.names}
        if "token_type_ids" in self.names and "token_type_ids" not in feeds:
            feeds["token_type_ids"] = np.zeros_like(feeds["input_ids"])
        return types.SimpleNamespace(logits=torch.from_numpy(self.sess.run(None, feeds)[0]))


def card_flags(readme: Path) -> list[str]:
    try:
        t = readme.read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        return []
    return [f for f in CARD_FLAGS if f in t]


def prepare_code(m: dict, snap: Path, local: Path) -> dict:
    """gte only: pinned remote code, sha256-checked, copied next to the weights with an auto_map that points at the local files."""
    import rerank as R
    from huggingface_hub import HfApi, hf_hub_download
    c = m["code"]
    info = HfApi().model_info(c["repo"], revision=c["rev"])
    lic = info.card_data.license if info.card_data else None
    if info.sha != c["rev"]:
        raise Skip(f"code repo pin {c['rev'][:12]} resolves to {str(info.sha)[:12]}")
    if lic is not None and str(lic).lower() not in R.OK_LICENCES:
        raise Skip(f"code repo licence {lic!r}")
    files = {}
    for name, want in c["sha256"].items():
        p = hf_hub_download(c["repo"], name, revision=c["rev"])
        got = sha256_file(p)
        if got != want:
            raise Skip(f"{name} sha256 {got[:12]} != pinned {want[:12]}")
        files[name] = p
    local.mkdir(parents=True, exist_ok=True)
    for f in snap.iterdir():
        if f.is_file() and f.name != "config.json" and not (local / f.name).exists():
            (local / f.name).symlink_to(f.resolve())
    cfg = json.loads((snap / "config.json").read_text(encoding="utf-8"))
    cfg["auto_map"] = {"AutoConfig": "configuration.NewConfig", "AutoModel": "modeling.NewModel",
                       "AutoModelForSequenceClassification": "modeling.NewForSequenceClassification"}
    (local / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    for name, p in files.items():
        shutil.copy2(p, local / name)
    return {"gte_dir": str(local), "code": {"repo": c["repo"], "revision": c["rev"], "licence": lic, "files_sha256_ok": sorted(c["sha256"])}}


def prepare(key: str, work: Path) -> dict:
    """Pin + licence (rerank.pin_and_licence: the pinned revision must resolve to itself, the card licence must be apache-2.0 or mit) and download.
    Raises Skip for a result-level reason."""
    import rerank as R
    m = MODELS[key]
    try:
        info = R.pin_and_licence(m["repo"], m["rev"])
    except SystemExit as e:
        raise Skip(str(e.code)) from None
    path = R.download(m["repo"], m["rev"])
    info["card_flags"] = card_flags(Path(path) / "README.md")
    prep = {"info": info, "path": path}
    if "code" in m:
        extra = prepare_code(m, Path(path), work / key / "local")
        prep["gte_dir"] = extra["gte_dir"]
        info["code"] = extra["code"]
    return prep


def gte_fp32(prep: dict):
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    d = prep["gte_dir"]
    tok = AutoTokenizer.from_pretrained(d, trust_remote_code=True)
    model = AutoModelForSequenceClassification.from_pretrained(d, trust_remote_code=True, torch_dtype=torch.float32).eval()
    return scorer_cls()("seqcls", tok=tok, model=model)


def export_int8(key: str, prep: dict, work: Path) -> tuple[Path, dict]:
    """int8 ONNX in work/<key>/int8/model_quantized.onnx. Standard architectures: 5a's recipe through `rerank.py export-ort`. gte (model_type `new`,
    unknown to optimum): `export-gte` below. Cached on disk for the lifetime of the job."""
    wd = work / key
    onnx = wd / "int8" / "model_quantized.onnx"
    if not onnx.exists():
        t = time.perf_counter()
        if key == "gte":
            cmd = [sys.executable, str(Path(__file__).resolve()), "export-gte", prep["gte_dir"], str(wd)]
        else:
            cmd = [sys.executable, str(HERE / "rerank.py"), "export-ort", prep["path"], str(wd)]
        subprocess.run(cmd, check=True)
        log(key, "export", round(time.perf_counter() - t, 1), "s")
    mp = wd / "meta.json"
    meta = json.loads(mp.read_text(encoding="utf-8")) if mp.exists() else {"route": "rerank.py export-ort (E-RET-5a recipe: optimum export, AutoQuantizationConfig.arm64 dynamic)"}
    return onnx, meta


def build_scorer(key: str, prec: str, prep: dict, work: Path):
    """-> (scorer, info). bge int8 is PB6's scorer unchanged; the others share RawOrt + the base class's encode / forward."""
    from transformers import AutoTokenizer
    if (key, prec) == ("bge", "int8"):
        return scorer_cls()("ort_int8", path=prep["path"]), {"route": "PB6 int8 scorer (rerank.Scorer ort_int8: optimum ORTModel, 5a recipe)"}
    if prec == "fp32":
        if key == "gte":
            return gte_fp32(prep), {"route": "torch fp32, card snippet (AutoModelForSequenceClassification, trust_remote_code); card loads float16, CPU runs float32"}
        return scorer_cls()("seqcls", path=prep["path"]), {"route": "torch fp32"}
    onnx, meta = export_int8(key, prep, work)
    kw = {"trust_remote_code": True} if key == "gte" else {}
    tok = AutoTokenizer.from_pretrained(prep["gte_dir"] if key == "gte" else prep["path"], **kw)
    return scorer_cls()("ort_int8", tok=tok, model=RawOrt(onnx)), {**meta, "onnx_mb": round(onnx.stat().st_size / 1048576, 1)}


# ---------------------------------------------------------------- gte export (own process)
def quantize_int8(src_dir: Path, dst_dir: Path, meta: dict) -> None:
    """5a's recipe first (optimum ORTQuantizer + AutoQuantizationConfig.arm64(is_static=False, per_channel=False)); if optimum cannot take this graph,
    onnxruntime's quantize_dynamic with the values of that same config."""
    from optimum.onnxruntime import ORTQuantizer
    from optimum.onnxruntime.configuration import AutoQuantizationConfig
    cfg = AutoQuantizationConfig.arm64(is_static=False, per_channel=False)
    dst_dir.mkdir(parents=True, exist_ok=True)
    out = dst_dir / "model_quantized.onnx"
    try:
        ORTQuantizer.from_pretrained(src_dir, file_name="model.onnx").quantize(save_dir=dst_dir, quantization_config=cfg)
        if not out.exists():
            raise FileNotFoundError("ORTQuantizer wrote no model_quantized.onnx")
        meta["quantizer"] = "optimum ORTQuantizer, AutoQuantizationConfig.arm64(is_static=False, per_channel=False): 5a's recipe"
        return
    except Exception as e:  # noqa: BLE001 (recorded, then the fallback runs)
        meta["attempts"].append({"route": "ORTQuantizer", "ok": False, "error": f"{type(e).__name__}: {one_line(e, 200)}"})
    from onnxruntime.quantization import QuantType, quantize_dynamic
    ops = [str(getattr(o, "value", o)) for o in cfg.operators_to_quantize]
    quantize_dynamic(str(src_dir / "model.onnx"), str(out), op_types_to_quantize=ops, per_channel=False, reduce_range=False, weight_type=QuantType.QInt8)
    meta["quantizer"] = f"onnxruntime quantize_dynamic with the values of that config (ops {ops}, QInt8 weights, per_channel False, reduce_range False)"


def export_gte(local_dir: str, dst: str) -> None:
    """Internal CLI. fp32 ONNX of the pinned gte remote-code model (optimum first; it has no config for model_type `new`, so then a plain torch.onnx.export of the
    padded path, `unpad_inputs` is false in the model's config), checked against torch on a padded batch, then dynamic int8 as above."""
    import numpy as np
    import onnxruntime as ort
    import torch
    from transformers import AutoModelForSequenceClassification
    dst = Path(dst)
    f32 = dst / "fp32"
    f32.mkdir(parents=True, exist_ok=True)
    model_path = f32 / "model.onnx"
    meta = {"attempts": []}
    model = AutoModelForSequenceClassification.from_pretrained(local_dir, trust_remote_code=True, torch_dtype=torch.float32, attn_implementation="eager").eval()
    try:
        from optimum.onnxruntime import ORTModelForSequenceClassification
        ORTModelForSequenceClassification.from_pretrained(local_dir, export=True, trust_remote_code=True).save_pretrained(f32)
        if not model_path.exists():
            raise FileNotFoundError("optimum export wrote no model.onnx")
        meta["route"] = "optimum ORTModelForSequenceClassification(export=True)"
    except Exception as e:  # noqa: BLE001
        meta["attempts"].append({"route": "optimum export", "ok": False, "error": f"{type(e).__name__}: {one_line(e, 200)}"})
    if not model_path.exists():
        class Wrap(torch.nn.Module):
            def __init__(self, m):
                super().__init__()
                self.m = m

            def forward(self, input_ids, attention_mask):
                return self.m(input_ids=input_ids, attention_mask=attention_mask, return_dict=True).logits

        ids = torch.tensor([[0, 6, 4, 32, 5, 2, 2, 10, 4, 2], [0, 6, 4, 32, 5, 2, 1, 1, 1, 1]])
        mask = torch.tensor([[1] * 10, [1] * 6 + [0] * 4])
        with torch.no_grad():
            torch.onnx.export(Wrap(model).eval(), (ids, mask), str(model_path), input_names=["input_ids", "attention_mask"], output_names=["logits"],
                              dynamic_axes={"input_ids": {0: "batch", 1: "sequence"}, "attention_mask": {0: "batch", 1: "sequence"}, "logits": {0: "batch"}},
                              opset_version=17, do_constant_folding=True, dynamo=False)
        meta["route"] = "torch.onnx.export (legacy exporter, opset 17) of the padded path; optimum has no export config for model_type `new`"
    sess = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
    names = [i.name for i in sess.get_inputs()]
    g = torch.Generator().manual_seed(0)
    ids = torch.randint(5, 5000, (3, 37), generator=g)
    mask = torch.ones_like(ids)
    mask[2, 30:] = 0
    ids[2, 30:] = 1
    with torch.no_grad():
        ref = model(input_ids=ids, attention_mask=mask, return_dict=True).logits.view(-1).numpy()
    feeds = {"input_ids": ids.numpy(), "attention_mask": mask.numpy()}
    if "token_type_ids" in names:
        feeds["token_type_ids"] = np.zeros_like(feeds["input_ids"])
    got = sess.run(None, {k: v for k, v in feeds.items() if k in names})[0].reshape(-1)
    meta["fp32_onnx_vs_torch_max_abs_diff"] = round(float(np.abs(ref - got).max()), 6)
    meta["fp32_onnx_mb"] = round(model_path.stat().st_size / 1048576, 1)
    del sess
    if meta["fp32_onnx_vs_torch_max_abs_diff"] > 0.05:
        (dst / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
        raise SystemExit("fp32 ONNX does not match torch: " + str(meta["fp32_onnx_vs_torch_max_abs_diff"]))
    quantize_int8(f32, dst / "int8", meta)
    (dst / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    print("export-gte", json.dumps(meta), flush=True)


# ---------------------------------------------------------------- sanity and parity (public text only)
def pub_scores(sc) -> list[list[float]]:
    return [sc.score_query(q, [rel] + list(oth), 512) for q, rel, oth in PUB]


def pub_top1(sc) -> str:
    s = pub_scores(sc)
    return f"{sum(1 for g in s if max(range(len(g)), key=g.__getitem__) == 0)}/{len(s)}"


def parity(a_sc, b_sc) -> dict:
    """a = the int8 scorer, b = the fp32 torch reference, on the public groups: correlation of the raw scores, largest absolute difference, same top-1 passage."""
    A, B = pub_scores(a_sc), pub_scores(b_sc)
    fa, fb = [x for g in A for x in g], [x for g in B for x in g]
    top = lambda g: max(range(len(g)), key=g.__getitem__)  # noqa: E731
    return {"pairs": len(fa), "pearson": round(statistics.correlation(fa, fb), 4), "max_abs_diff": round(max(abs(x - y) for x, y in zip(fa, fb)), 4),
            "same_top1": f"{sum(1 for x, y in zip(A, B) if top(x) == top(y))}/{len(A)}"}


# ---------------------------------------------------------------- the grid
def run_cell(sc, pk: dict, key: str, prec: str, K: int, L: int, base: list[int]) -> tuple[dict, list[int]]:
    """One cell: the first K memories of every RRF pool, reranked at truncation L. Returns (aggregates, per-question hit bits; the bits stay in the job)."""
    n, mems, docs = pk["n"], pk[RRF]["mems"], pk[RRF]["docs"]
    cid = cell_id(key, prec, K, L)
    warm = next((i for i in range(n) if docs[i]), None)
    sc.lens = sc.pads = None
    if warm is not None:
        sc.score_query(pk["queries"][warm], docs[warm][:K], L)  # untimed warm-up at this cell's shape
    sc.lens, sc.pads = [], []
    bits, wall = [], []
    for i in range(n):
        d = docs[i][:K]
        if not d:  # empty pool: a miss in both arms, no latency sample
            bits.append(0)
            continue
        t = time.perf_counter()
        s = sc.score_query(pk["queries"][i], d, L)
        wall.append(time.perf_counter() - t)
        order = sorted(range(len(s)), key=lambda j: (-s[j], j))  # ties keep pool order
        bits.append(int(pk["gold"][i] in [mems[i][j] for j in order[:5]]))
    lens, pads = sc.lens, sc.pads
    sc.lens = sc.pads = None
    tok = ({"pair_mean": round(sum(lens) / len(lens), 1), "padded_mean": round(sum(pads) / len(pads), 1),
            "truncated_share": round(sum(1 for x in lens if x >= L) / len(lens), 3)} if lens else None)
    rank = pk[RRF]["rank"]
    return ({"id": cid, "model": key, "precision": prec, "K": K, "L": L, "queries": n, "timed": len(wall), "hit5": H.rate(sum(bits), n),
             "hit5_by_type": RR.by_type(pk["types"], bits), "pool_at_K": H.rate(sum(1 for r in rank if r is not None and r <= K), n),
             "vs_rrf": {"A": RRF, "B": cid, **H.mcnemar(base, bits)}, "latency_s": lat_stats(wall), "tokens": tok}, bits)


def fake_pk() -> dict:
    """Public toy pools for the smoke run: the PUB groups, 25 passages each, the relevant one at a known position. Real models, no corpus."""
    pos = [1, 3, 7, 12, 4, 20]
    texts = [t for _, rel, oth in PUB for t in (rel, *oth)]
    pk = {"n": len(PUB), "types": ["state" if g % 2 == 0 else "fact" for g in range(len(PUB))], "queries": [q for q, _, _ in PUB],
          "gold": [f"g{g}" for g in range(len(PUB))]}
    blk = {"mems": [], "docs": [], "rank": []}
    for g, (_, rel, _) in enumerate(PUB):
        others = [t for t in texts if t != rel]
        dis = [others[k % len(others)] + ("" if k < len(others) else f" (copy {k // len(others)})") for k in range(24)]
        ids = [f"m{g}_{k}" for k in range(24)]
        p = pos[g] - 1
        blk["docs"].append(dis[:p] + [rel] + dis[p:])
        blk["mems"].append(ids[:p] + [f"g{g}"] + ids[p:])
        blk["rank"].append(pos[g])
    pk[RRF], pk["dense"] = blk, blk
    return pk


def env_info() -> dict:
    d = {"machine": platform.machine(), "cpus": os.cpu_count(), "python": sys.version.split()[0]}
    for mod in ("torch", "transformers", "tokenizers", "onnxruntime", "optimum", "numpy"):
        try:
            d[mod] = __import__(mod).__version__
        except Exception:  # noqa: BLE001
            d[mod] = None
    try:
        d["cpu_model"] = next((ln.split(":", 1)[1].strip() for ln in subprocess.run(["lscpu"], capture_output=True, text=True, timeout=10).stdout.splitlines()
                               if ln.startswith("Model name")), None)
    except (OSError, subprocess.SubprocessError):
        d["cpu_model"] = None
    return d


def absent_check(repo: str) -> dict:
    try:
        from huggingface_hub import HfApi
        HfApi().model_info(repo)
        return {"repo": repo, "exists": True, "note": "present on the Hub but not pinned or run by this card"}
    except Exception as e:  # noqa: BLE001
        return {"repo": repo, "exists": False, "error": type(e).__name__}


def save(o: dict, out: str, summary: str) -> None:
    Path(out).write_text(json.dumps(o, indent=1), encoding="utf-8")
    Path(summary).write_text(render_grid(o), encoding="utf-8")


def grid_cmd(a) -> int:
    t0 = time.monotonic()
    fake = a.pools == "fake"
    pk = fake_pk() if fake else RR.read_json(a.pools)
    n, rank = pk["n"], pk[RRF]["rank"]
    base = [int(r is not None and r <= 5) for r in rank]
    pool_at = {K: sum(1 for r in rank if r is not None and r <= K) for K in POOLS}
    o = {"job": "grid", "part": a.part, "fake_pool": fake, "env": env_info(), "config": {"threads": 4, "batch": 8, "arms": a.arms, "cells": a.cells, "budget_min": a.budget_min},
         "rrf": {"hit5": H.rate(sum(base), n), "hit5_by_type": RR.by_type(pk["types"], base), "pool_at": {str(K): H.rate(v, n) for K, v in pool_at.items()}},
         "models": {}, "skipped": [absent_check(r) for r in ABSENT], "arms": [], "fp32_vs_int8": []}
    if not fake:
        o["repro"] = RR.repro_check({"hit5": sum(base), "pool25": pool_at[25]})
        if not o["repro"]["ok"]:
            save(o, a.out, a.summary)
            print("REPRODUCTION MISMATCH: stopping before any rerank", json.dumps(o["repro"]), flush=True)
            return 2
    import rerank as R
    R.torch.set_num_threads(4)
    work = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / "eret_local"
    work.mkdir(parents=True, exist_ok=True)
    preps, bits_all = {}, {}
    for key, prec in parse_arms(a.arms):
        arm = {"model": key, "precision": prec, "status": "running", "cells": []}
        o["arms"].append(arm)
        sc = None
        try:
            if key not in preps:
                preps[key] = prepare(key, work)
                o["models"][key] = preps[key]["info"]
            prep = preps[key]
            t = time.perf_counter()
            sc, route = build_scorer(key, prec, prep, work)
            arm.update({"route": route, "build_s": round(time.perf_counter() - t, 1)})
            arm["sanity"] = bool(sc.sanity())
            arm["pub_top1"] = pub_top1(sc)
            if not arm["sanity"]:
                arm["status"] = "sanity_failed"
                continue
            if a.parity and prec == "int8":
                ref = gte_fp32(prep) if key == "gte" else scorer_cls()("seqcls", path=prep["path"])
                arm["parity"] = par = parity(sc, ref)
                del ref
                gc.collect()
                if par["pearson"] < PARITY_MIN:
                    arm["status"] = "parity_failed"
                    continue
            arm["status"] = "ok"
        except Skip as e:
            arm.update({"status": "dropped", "reason": one_line(e)})
            continue
        except Exception as e:  # noqa: BLE001  (public phase: model files and public text only, so the message is safe)
            arm.update({"status": "failed", "reason": f"{type(e).__name__}: {one_line(e)}", "where": where(e)})
            continue
        finally:
            save(o, a.out, a.summary)
        try:
            for K, L in parse_cells(a.cells):
                if time.monotonic() - t0 > a.budget_min * 60:
                    arm.setdefault("skipped_budget", []).append(f"K{K}L{L}")
                    continue
                c, bits = run_cell(sc, pk, key, prec, K, L, base)
                arm["cells"].append(c)
                bits_all[(key, prec, K, L)] = bits
                print("CELL", json.dumps(c), flush=True)  # aggregates only; survives a later failure
                save(o, a.out, a.summary)
        except Exception as e:  # noqa: BLE001  (corpus phase: class and source line only)
            arm.update({"status": "failed_in_cells", "reason": type(e).__name__, "where": where(e)})
        finally:
            del sc
            gc.collect()
            save(o, a.out, a.summary)
    for (key, prec, K, L), b8 in sorted(bits_all.items()):
        if prec == "int8" and (key, "fp32", K, L) in bits_all:
            o["fp32_vs_int8"].append({"A": cell_id(key, "fp32", K, L), "B": cell_id(key, "int8", K, L), **H.mcnemar(bits_all[(key, "fp32", K, L)], b8)})
    o["total_s"] = round(time.monotonic() - t0, 1)
    save(o, a.out, a.summary)
    print("grid done", json.dumps({"arms": [(x["model"], x["precision"], x["status"], len(x["cells"])) for x in o["arms"]], "total_s": o["total_s"]}), flush=True)
    # An arm that cannot run (licence, export, parity, sanity) is a result, shown in the table; the job is red only for a code failure while the corpus was in
    # memory, when no arm produced a cell, or for any arm that is neither ok nor dropped under --strict (the public smoke run).
    st = [x["status"] for x in o["arms"]]
    return 3 if "failed_in_cells" in st or not any(x["cells"] for x in o["arms"]) or (a.strict and any(x not in ("ok", "dropped") for x in st)) else 0


def route_str(r) -> str:
    """The route of an arm as one line: a dict from the exporters (route, quantizer, onnx size) or a plain string."""
    if not isinstance(r, dict):
        return "n/a" if r is None else str(r)
    return "; ".join(str(r[k]) for k in ("route", "quantizer") if r.get(k)) + (f"; attempts failed: {len([a for a in r.get('attempts', []) if not a.get('ok')])}" if r.get("attempts") else "")


def render_grid(o: dict) -> str:
    g = lambda v: "n/a" if v is None else v  # noqa: E731
    r = o["rrf"]
    L = [f"## E-RET-PB7 grid part `{o['part']}`: local rerank on the hybrid RRF pool" + (" (FAKE public toy pool, smoke only)" if o.get("fake_pool") else ""), "",
         "One cell = the first K memories of every RRF pool, input title + newline + best chunk, pair cut to L tokens, batch 8 with dynamic padding, 4 threads, per-query "
         "wall time = tokenise + forward on the runner. McNemar is exact two-sided against RRF alone (A = RRF, B = cell; b = RRF hit and cell miss, c = RRF miss and cell hit).", "",
         f"RRF alone hit@5 {H.fmt_rate(r['hit5'])}; pool@10 {H.fmt_rate(r['pool_at']['10'])}; pool@25 {H.fmt_rate(r['pool_at']['25'])}.", ""]
    if "repro" in o:
        rp = o["repro"]
        L += [f"Reproduction of PB5/PB6 (RRF alone): hit@5 {rp['got']['hit5']} (expected {rp['expected']['hit5']}), pool@25 {rp['got']['pool25']} "
              f"(expected {rp['expected']['pool25']}): {'OK' if rp['ok'] else 'MISMATCH'}.", ""]
    L += [f"Runner: {json.dumps(o['env'], sort_keys=True)}", ""]
    for k, m in o["models"].items():
        L.append(f"Model {k}: {m['repo']} @ {m['revision']}, licence {m['licence']}, card flags {m['card_flags']}" + (f"; code {json.dumps(m['code'], sort_keys=True)}" if "code" in m else ""))
    for s in o["skipped"]:
        L.append(f"Skipped: {json.dumps(s, sort_keys=True)}")
    L += ["", "| arm | status | route | sanity | public top-1 | parity vs fp32 (pearson / max abs diff / same top-1) | build s |", "|---|---|---|---|---|---|---|"]
    for x in o["arms"]:
        p = x.get("parity")
        L.append(f"| {x['model']}:{x['precision']} | {x['status']}{(': ' + x['reason']) if x.get('reason') else ''} | {route_str(x.get('route'))} | {g(x.get('sanity'))} | {g(x.get('pub_top1'))} | "
                 f"{(str(p['pearson']) + ' / ' + str(p['max_abs_diff']) + ' / ' + p['same_top1']) if p else 'n/a'} | {g(x.get('build_s'))} |")
    L += ["", "| cell | hit@5 | state | fact | pool@K | vs RRF N / b / c / p | timed | p50 s | p95 s | tokens per pair (padded mean) |", "|---|---|---|---|---|---|---|---|---|---|"]
    for x in o["arms"]:
        for c in x["cells"]:
            v, t, tk = c["vs_rrf"], c["latency_s"], c["tokens"] or {}
            L.append(f"| {c['id']} | {H.fmt_rate(c['hit5'])} | {H.fmt_rate(c['hit5_by_type']['state'])} | {H.fmt_rate(c['hit5_by_type']['fact'])} | {H.fmt_rate(c['pool_at_K'])} | "
                     f"{v['N']} / {v['b']} / {v['c']} / {v['p']} | {t['n']} | {g(t['p50'])} | {g(t['p95'])} | {g(tk.get('pair_mean'))} ({g(tk.get('padded_mean'))}) |")
    for x in o["arms"]:
        if x.get("skipped_budget"):
            L.append(f"Not run (time budget): {x['model']}:{x['precision']} {x['skipped_budget']}")
    if o["fp32_vs_int8"]:
        L += ["", "fp32 vs int8, same model, same cell (A = fp32, B = int8):", "", "| pair | N | b | c | p |", "|---|---|---|---|---|"]
        L += [f"| {x['B']} vs {x['A']} | {x['N']} | {x['b']} | {x['c']} | {x['p']} |" for x in o["fp32_vs_int8"]]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- merge
def merge_parts(parts: list[dict], expect: list[str]) -> tuple[dict, dict]:
    """Parts -> (results, qualify). Pure function of the part aggregates."""
    cells = [dict(c) for p in parts for x in p["arms"] for c in x["cells"]]
    for c in cells:
        c["qualifies"] = qualifies(c) and c["precision"] == "int8"
        c["qualifies_if_fp32_were_bundlable"] = qualifies(c)
    rrfs = {json.dumps(p["rrf"], sort_keys=True) for p in parts}
    arms = [{k: v for k, v in x.items() if k != "cells"} | {"part": p["part"], "cells_done": len(x["cells"])} for p in parts for x in p["arms"]]
    pid = cell_id(*PRIMARY)
    prim = next((c for c in cells if c["id"] == pid), None)
    fallback = False
    if prim is None:
        alt = cell_id(PRIMARY[0], "fp32", PRIMARY[2], PRIMARY[3])
        prim = next((c for c in cells if c["id"] == alt), None)
        fallback = prim is not None
    picked = pick_bundle(cells)
    all_q = [c["id"] for c in cells if c["qualifies"]]
    res = {"job": "merge", "parts": sorted(p["part"] for p in parts), "missing_parts": [x for x in expect if x not in {p["part"] for p in parts}],
           "rrf": parts[0]["rrf"] if parts else None, "rrf_identical_across_parts": len(rrfs) == 1, "repro": [p.get("repro") for p in parts],
           "env": parts[0]["env"] if parts else None, "models": {k: v for p in parts for k, v in p["models"].items()}, "skipped": parts[0]["skipped"] if parts else [],
           "arms": arms, "cells": cells, "fp32_vs_int8": [x for p in parts for x in p["fp32_vs_int8"]],
           "primary": {"id": pid, "cell_used": prim["id"] if prim else None, "fp32_fallback": fallback, "cell": prim},
           "qualify_rule": f"McNemar vs RRF p < {ALPHA} with c > b, N2 p50 <= {P50_MAX_S} s, int8 only; at most {BUNDLE_CAP} cells, highest hit@5 then lowest p50",
           "qualifying": all_q, "bundle_cells": [c["id"] for c in picked]}
    q = {"rule": res["qualify_rule"], "cells": [{"id": c["id"], "model": c["model"], "precision": c["precision"], "K": c["K"], "L": c["L"],
                                                 "matched_T": int(-(-c["tokens"]["padded_mean"] // 1)) if c.get("tokens") else None,
                                                 "n2": {"hit5": c["hit5"]["k"], "queries": c["queries"], "b": c["vs_rrf"]["b"], "c": c["vs_rrf"]["c"], "p": c["vs_rrf"]["p"],
                                                        "p50_s": c["latency_s"]["p50"], "p95_s": c["latency_s"]["p95"],
                                                        "pair_tokens": (c["tokens"] or {}).get("pair_mean"), "padded_tokens": (c["tokens"] or {}).get("padded_mean")}}
                                                for c in picked],
         "qualifying": all_q, "dropped_by_cap": [i for i in all_q if i not in res["bundle_cells"]]}
    return res, q


def render_merge(r: dict) -> str:
    g = lambda v: "n/a" if v is None else v  # noqa: E731
    rr = r["rrf"]
    L = ["## E-RET-PB7 result: local rerank on the hybrid RRF pool", "",
         f"Parts merged: {r['parts']}; missing: {r['missing_parts']}. RRF alone hit@5 {H.fmt_rate(rr['hit5'])}; pool@10 {H.fmt_rate(rr['pool_at']['10'])}; "
         f"pool@25 {H.fmt_rate(rr['pool_at']['25'])}. Same RRF numbers in every part: {r['rrf_identical_across_parts']}.", ""]
    for k, m in r["models"].items():
        L.append(f"- {k}: {m['repo']} @ `{m['revision']}`, licence {m['licence']}" + (f"; remote code {m['code']['repo']} @ `{m['code']['revision']}`" if "code" in m else ""))
    for s in r["skipped"]:
        L.append(f"- skipped: {json.dumps(s, sort_keys=True)}")
    L += ["", "| cell | hit@5 | state | fact | pool@K | RRF vs cell N / b / c / p | N2 p50 s | N2 p95 s | tokens per pair (padded) | qualifies |", "|---|---|---|---|---|---|---|---|---|---|"]
    for c in r["cells"]:
        v, t, tk = c["vs_rrf"], c["latency_s"], c["tokens"] or {}
        L.append(f"| {c['id']} | {H.fmt_rate(c['hit5'])} | {H.fmt_rate(c['hit5_by_type']['state'])} | {H.fmt_rate(c['hit5_by_type']['fact'])} | {H.fmt_rate(c['pool_at_K'])} | "
                 f"{v['N']} / {v['b']} / {v['c']} / {v['p']} | {g(t['p50'])} | {g(t['p95'])} | {g(tk.get('pair_mean'))} ({g(tk.get('padded_mean'))}) | {c['qualifies']} |")
    p = r["primary"]
    if p["cell"]:
        v = p["cell"]["vs_rrf"]
        L += ["", f"PRIMARY (pre-registered) {p['id']}" + (f", int8 impossible, fp32 used: {p['cell_used']}" if p["fp32_fallback"] else "") +
              f": hit@5 {H.fmt_rate(p['cell']['hit5'])} against RRF alone {H.fmt_rate(rr['hit5'])}; McNemar N {v['N']}, b {v['b']}, c {v['c']}, p {v['p']}."]
    else:
        L += ["", f"PRIMARY (pre-registered) {p['id']}: not_applicable, no such cell was produced."]
    if r["fp32_vs_int8"]:
        L += ["", "fp32 vs int8 (A = fp32, B = int8): " + "; ".join(f"{x['B']} N {x['N']} b {x['b']} c {x['c']} p {x['p']}" for x in r["fp32_vs_int8"])]
    L += ["", f"Qualify rule: {r['qualify_rule']}. Qualifying: {r['qualifying']}. Bundle cells: {r['bundle_cells'] or 'none qualified'}.", "",
          "| arm | status | route | sanity | parity (pearson / same top-1) |", "|---|---|---|---|---|"]
    for x in r["arms"]:
        pa = x.get("parity")
        L.append(f"| {x['model']}:{x['precision']} | {x['status']}{(': ' + x['reason']) if x.get('reason') else ''} | {route_str(x.get('route'))} | {g(x.get('sanity'))} | "
                 f"{(str(pa['pearson']) + ' / ' + pa['same_top1']) if pa else 'n/a'} |")
    return "\n".join(L) + "\n"


def merge_cmd(a) -> int:
    parts = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(Path(a.parts).glob("grid-*.json"))]
    if not parts:
        raise SystemExit("no grid parts found")
    res, q = merge_parts(parts, [x for x in a.expect.split(",") if x])
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
    (out / "qualify.json").write_text(json.dumps(q, indent=1), encoding="utf-8")
    (out / "summary.md").write_text(render_merge(res), encoding="utf-8")
    print("merge done", json.dumps({"parts": res["parts"], "missing": res["missing_parts"], "qualifying": res["qualifying"], "bundle": res["bundle_cells"]}), flush=True)
    return 0


# ---------------------------------------------------------------- guard
def recorded_messages(files: list[str]) -> set[str]:
    """Strings the public phase (model files and public text only; the corpus is never touched there) recorded under `reason`, `error` or `where`: library error
    messages and source locations. They are code-made, so they are exempt from the window check, in plain and in JSON-escaped form. The corpus phase records
    exception class names only."""
    out: set[str] = set()

    def walk(j):
        if isinstance(j, dict):
            for k, v in j.items():
                if k in ("reason", "error", "where") and isinstance(v, str) and len(v) >= 2:
                    out.update({v, json.dumps(v)[1:-1]})
                else:
                    walk(v)
        elif isinstance(j, list):
            for v in j:
                walk(v)

    for f in files:
        if f.endswith(".json"):
            walk(json.loads(Path(f).read_text(encoding="utf-8")))
    return out


def guard_check(texts: list[str], files: list[str], static: set[str] | None = None) -> list:
    return H.guard_findings(texts, files, (RR.static_for(files) | RR.literals(__file__) | recorded_messages(files)) if static is None else static)


def guard_cmd(a) -> int:
    c = RR.P.load_corpus(a.corpus)
    files = [f for f in a.files if Path(f).exists()]
    hits = guard_check(RR.P.corpus_texts(c), files)
    if hits:  # offsets only; never the text
        raise SystemExit(f"GUARD FAILED: {len(hits)} corpus window(s) in outputs, distinct places (file, offset): {sorted(set(hits))[:12]}")
    print(f"guard ok: {len(files)} file(s) scanned against {len(RR.P.corpus_texts(c))} corpus texts")
    return 0


# ---------------------------------------------------------------- bundle (public model, public data)
def build_pairs() -> dict:
    """BENCH_QUERIES public queries with 25 long passages each (>= BENCH_DOC_CHARS characters, built from consecutive real passages), so every pair fills any
    truncation up to 512 tokens. The bench cuts at L (worst case) and at the corpus run's mean padded length (matched)."""
    import pyarrow.parquet as pq
    from huggingface_hub import hf_hub_download
    p = hf_hub_download(DATASET_REPO, DATASET_FILE, repo_type="dataset", revision=DATASET_REV)
    if sha256_file(p) != DATASET_SHA256:
        raise SystemExit("dataset file hash mismatch")
    rows = pq.read_table(p).slice(0, BENCH_ROWS).to_pylist()
    flat = [t for r in rows for t in list(r["positive"]) + list(r["negative"])]
    cur, queries = 0, []
    for i in range(BENCH_QUERIES):
        docs = []
        for _ in range(25):
            parts, size = [], 0
            while size < BENCH_DOC_CHARS:
                t = flat[cur % len(flat)]
                cur += 1
                parts.append(t)
                size += len(t)
            docs.append("\n".join(parts))
        queries.append({"query": rows[i]["query"], "passages": docs})
    return {"meta": {"dataset": {"repo": DATASET_REPO, "revision": DATASET_REV, "file": DATASET_FILE, "sha256": DATASET_SHA256,
                                 "licence": "Apache-2.0 (upstream THUIR/T2Ranking README; the HF mirror card states none)"}, "rows": BENCH_ROWS,
                     "doc_min_chars": BENCH_DOC_CHARS}, "queries": queries}


def parse_spec(spec: str) -> list[dict]:
    """Dry-run cells: model:precision:K:L[:T], comma separated."""
    out = []
    for x in [x for x in spec.split(",") if x]:
        f = x.split(":")
        key, prec, K, L = f[0], f[1], int(f[2]), int(f[3])
        if key not in MODELS or prec != "int8":
            raise SystemExit(f"unknown or non-int8 bundle cell {x!r}")
        out.append({"id": cell_id(key, prec, K, L), "model": key, "precision": prec, "K": K, "L": L, "matched_T": int(f[4]) if len(f) > 4 else None, "n2": None})
    return out


def bundle_cmd(a) -> int:
    cells = parse_spec(a.cells_spec) if a.cells_spec else json.loads(Path(a.qualify).read_text(encoding="utf-8"))["cells"]
    if not cells:
        print("bundle: no cell qualified, nothing to build", flush=True)
        return 0
    out, work = Path(a.out), Path(a.work)
    (out / "models").mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    mi = {}
    for key in sorted({c["model"] for c in cells}):
        prep = prepare(key, work)
        onnx, meta = export_int8(key, prep, work)
        d = out / "models" / key
        d.mkdir(parents=True, exist_ok=True)
        shutil.copy2(onnx, d / "model_quantized.onnx")
        for f in TOKENIZER_FILES:
            if (Path(prep["path"]) / f).exists():
                shutil.copy2(Path(prep["path"]) / f, d / f)
        if not (d / "tokenizer.json").exists():
            raise SystemExit(f"tokenizer.json missing from the pinned snapshot of {key}")
        shutil.copy2(Path(prep["path"]) / "README.md", d / "MODEL_CARD.md")
        mi[key] = {**prep["info"], "onnx_sha256": sha256_file(onnx), "onnx_mb": round(onnx.stat().st_size / 1048576, 1), "quantisation": meta}
    (out / "bench_pairs.json").write_text(json.dumps(build_pairs(), ensure_ascii=False), encoding="utf-8")
    (out / "cells.json").write_text(json.dumps({"cells": [{**c, "model_dir": f"models/{c['model']}"} for c in cells]}, indent=1), encoding="utf-8")
    (out / "bundle_meta.json").write_text(json.dumps({"models": mi, "cells": cells}, indent=1), encoding="utf-8")
    shutil.copy2(HERE / "n1_bench_local.py", out / "n1_bench.py")
    (out / "README.md").write_text(bundle_readme(mi, cells), encoding="utf-8")
    print("bundle built:", json.dumps({"models": {k: v["onnx_mb"] for k, v in mi.items()}, "cells": [c["id"] for c in cells]}), flush=True)
    return 0


def bundle_readme(mi: dict, cells: list[dict]) -> str:
    L = ["# N1 bench bundle v2 (E-RET-PB7): int8 cross-encoder rerank speed on a CPU host", "",
         "Public benchmark bundle: int8 ONNX cross-encoders and a C-MTEB T2Reranking sample. Not a software release. Nothing here touches the project's own corpus.", "",
         "## What it measures", "",
         "`n1_bench.py` (onnxruntime, tokenizers, numpy; no torch, no transformers), one process, 4 threads by default. For every cell of `cells.json` (model, depth K, "
         "truncation L) it times whole queries the way the rerank stage runs them: K passages, tokenise + forward in batches of 8 with dynamic padding. Two variants per cell:", "",
         "- `full_L`: every pair is exactly L tokens (long public passages cut at L). Worst case for that cell.",
         "- `matched`: every pair is cut at T tokens, the mean padded pair length measured in the corpus run on the CI runner (only when T < L). Same compute per pair "
         "as the real workload, up to the length distribution.", "",
         "p50 / p95 / min / max over up to 24 timed queries per variant after one untimed warm-up. Hard caps inside the script: total runtime <= 150 s (variants stop early "
         "and the result says `partial`) and memory <= 2.5 GB (VmHWM; the run aborts and writes what it has). Exit codes: 0 complete, 3 partial, 4 memory abort, 5 a sanity check failed. "
         "The script prints no passage text.", "",
         "## Run (production host, CPU only, nothing is pulled: the image is `python:3.11-slim`)", "", "```bash",
         "tar xzf n1_bench_bundle_v2.tar.gz && cd n1_bench_bundle_v2 && sha256sum -c MANIFEST.sha256 && mkdir -p out",
         "docker run --rm --network none --memory 3g -e PIP_DISABLE_PIP_VERSION_CHECK=1 \\",
         "  -v \"$PWD\":/bundle:ro -v \"$PWD/out\":/out python:3.11-slim \\",
         "  bash -c 'pip install --no-index --find-links /bundle/wheels -r /bundle/requirements.txt > /dev/null && python /bundle/n1_bench.py --bundle /bundle --threads 4 --out /out/n1_result.json --table /out/n1_result.txt'",
         "```", "",
         "`requirements.txt` pins every wheel in `wheels/` (CPython 3.11, linux aarch64, resolved in CI): the install is offline. Compare with the N2 reference in the release notes "
         "(same image, same command, 4 threads, 4-vCPU Neoverse-N2 CI runner).", "", "## Cells", "", "| id | model dir | K | L | matched T |", "|---|---|---|---|---|"]
    L += [f"| {c['id']} | models/{c['model']} | {c['K']} | {c['L']} | {c.get('matched_T')} |" for c in cells]
    L += ["", "## Models and licences", ""]
    for k, m in mi.items():
        L.append(f"- `models/{k}/model_quantized.onnx`: {m['repo']} at `{m['revision']}`, licence {m['licence']}, {m['onnx_mb']} MB, sha256 `{m['onnx_sha256']}`; "
                 f"quantisation: {m['quantisation'].get('quantizer', m['quantisation'].get('route'))}. Tokenizer files and the model card are next to it.")
    L += ["- Data `bench_pairs.json`: C-MTEB/T2Reranking (revision `" + DATASET_REV + "`, file sha256 `" + DATASET_SHA256 + "`, first " + str(BENCH_ROWS) + " dev rows); the HF mirror card "
          "states no licence, the upstream T2Ranking README says Apache-2.0.",
          "- Wheels in `wheels/` keep their own licences (onnxruntime MIT, numpy BSD-3-Clause, tokenizers Apache-2.0, others as published on PyPI).", ""]
    return "\n".join(L)


def notes_cmd(a) -> int:
    meta = json.loads(Path(a.meta).read_text(encoding="utf-8"))
    cells = meta["cells"]
    ref = Path(a.ref).read_text(encoding="utf-8") if a.ref and Path(a.ref).exists() else "(the N2 reference run did not produce a table)"
    L = ["Public benchmark bundle v2 (E-RET-PB7): int8 ONNX cross-encoders + C-MTEB T2Reranking sample. Not a software release.", "",
         f"Asset n1_bench_bundle_v2.tar.gz, sha256 {a.sha}. Built by run {a.run_id} at {a.commit}.", "", "Models (official repos, pinned by commit, licence read from the pinned model card in the job):"]
    L += [f"- {k}: {m['repo']} @ {m['revision']}, {m['licence']}, int8 {m['onnx_mb']} MB, sha256 {m['onnx_sha256']}" for k, m in meta["models"].items()]
    L += ["", "Cells and their N2 numbers on the real 198 questions (hybrid RRF pool, 4-vCPU Neoverse-N2 CI runner, tokenise + forward per query, batch 8, dynamic padding):", "",
          "| cell | hit@5 / 198 | RRF vs cell b / c / p | N2 p50 s | N2 p95 s | mean pair tokens (padded) |", "|---|---|---|---|---|---|"]
    for c in cells:
        n = c.get("n2") or {}
        L.append(f"| {c['id']} | {n.get('hit5', '-')} | {n.get('b', '-')} / {n.get('c', '-')} / {n.get('p', '-')} | {n.get('p50_s', '-')} | {n.get('p95_s', '-')} | "
                 f"{n.get('pair_tokens', '-')} ({n.get('padded_tokens', '-')}) |")
    L += ["", "Bundle bench on public text, N2 reference (python:3.11-slim, --network none, 4 threads, same command as README.md):", "```", ref.rstrip(), "```", "",
          "Reading N1: run the same command on the production host. For each cell, N1 p50 on the real workload is estimated by N2 corpus p50 x (N1 matched p50 / N2 matched p50); "
          "`full_L` is the worst case for the cell."]
    Path(a.out).write_text("\n".join(L) + "\n", encoding="utf-8")
    return 0


# ---------------------------------------------------------------- selftest
class FakeScorer:
    """Scores 1.0 for the passage that is relevant to the query, else 0.0; ties keep pool order. No model."""

    def __init__(self, rel_by_query):
        self.rel, self.lens, self.pads, self.calls = rel_by_query, None, None, 0

    def score_query(self, query, docs, length, b=8):
        self.calls += 1
        return [1.0 if d == self.rel[query] else 0.0 for d in docs]


def _fake_cells(prec="int8", hit=45, c_over_b=(1, 20), p50=0.4) -> dict:
    return {"id": "x", "model": "m", "precision": prec, "K": 10, "L": 256, "queries": 100, "hit5": {"k": hit, "n": 100}, "latency_s": {"p50": p50, "p95": p50 * 2},
            "vs_rrf": {"b": c_over_b[0], "c": c_over_b[1], "p": 0.001}}


def selftest(_a=None):
    # arms and cells specs
    assert parse_arms("gte:int8,gte:fp32,bge:int8,mmarco12:int8") == [("gte", "int8"), ("gte", "fp32"), ("bge", "int8"), ("mmarco12", "int8")]
    for bad in ("bge:fp32", "nope:int8", "gte"):
        try:
            parse_arms(bad)
            raise AssertionError("bad arm accepted: " + bad)
        except SystemExit:
            pass
    assert parse_cells("10x256,25x512") == [(10, 256), (25, 512)] and CELLS[0] == PRIMARY[2:] and len(set(CELLS)) == 4
    assert PRIMARY == ("gte", "int8", 10, 256) and ("mmarco6" not in MODELS) and all(len(m["rev"]) == 40 for m in MODELS.values())
    # qualify rule: significant AND better AND int8 AND p50 inside the bar
    ok = _fake_cells()
    ok["vs_rrf"]["p"] = 0.01
    assert qualifies(ok)
    for mut in ({"vs_rrf": {"b": 1, "c": 20, "p": 0.05}}, {"vs_rrf": {"b": 20, "c": 1, "p": 0.001}}, {"latency_s": {"p50": 0.5001, "p95": 1}}, {"latency_s": {"p50": None, "p95": None}}):
        assert not qualifies({**ok, **mut}), mut
    assert qualifies({**ok, "latency_s": {"p50": 0.5, "p95": 1}}) and not qualifies({**ok, "vs_rrf": None})
    # bundle choice: int8 only, at most 3, highest hit@5 then lowest p50
    cs = []
    for i, (h, t, pr) in enumerate([(50, 0.4, "int8"), (60, 0.45, "int8"), (60, 0.30, "int8"), (55, 0.2, "int8"), (99, 0.1, "fp32"), (70, 0.9, "int8")]):
        cs.append({**ok, "id": f"c{i}", "precision": pr, "hit5": {"k": h, "n": 100}, "latency_s": {"p50": t, "p95": t}})
    assert [c["id"] for c in pick_bundle(cs)] == ["c2", "c1", "c3"], pick_bundle(cs)
    assert pick_bundle([]) == []
    # fake pools and the cell runner with a fake scorer: hits, ceilings, McNemar orientation, empty pool
    pk = fake_pk()
    rel = {q: r for q, r, _ in PUB}
    assert pk["n"] == 6 and all(len(d) == 25 and len(set(m)) == 25 for d, m in zip(pk[RRF]["docs"], pk[RRF]["mems"])) and pk[RRF]["rank"] == [1, 3, 7, 12, 4, 20]
    assert all(pk[RRF]["docs"][g][pk[RRF]["rank"][g] - 1] == PUB[g][1] and pk[RRF]["mems"][g][pk[RRF]["rank"][g] - 1] == f"g{g}" for g in range(6))
    base = [int(r is not None and r <= 5) for r in pk[RRF]["rank"]]
    assert base == [1, 1, 0, 0, 1, 0]
    sc = FakeScorer(rel)
    c10, b10 = run_cell(sc, pk, "m", "int8", 10, 256, base)
    assert b10 == [1, 1, 1, 0, 1, 0] and c10["hit5"]["k"] == 4 and c10["pool_at_K"]["k"] == 4 and c10["id"] == "m:int8:K10:L256", c10
    assert (c10["vs_rrf"]["N"], c10["vs_rrf"]["b"], c10["vs_rrf"]["c"]) == (6, 0, 1) and c10["timed"] == 6 and c10["latency_s"]["n"] == 6 and c10["tokens"] is None
    assert sc.calls == 7  # one warm-up + six timed queries
    c25, b25 = run_cell(sc, pk, "m", "int8", 25, 512, base)
    assert b25 == [1] * 6 and c25["pool_at_K"]["k"] == 6 and (c25["vs_rrf"]["b"], c25["vs_rrf"]["c"]) == (0, 3), c25
    pk2 = fake_pk()
    pk2[RRF]["docs"][3], pk2[RRF]["mems"][3], pk2[RRF]["rank"][3] = [], [], None
    c, b = run_cell(FakeScorer(rel), pk2, "m", "int8", 10, 256, base)
    assert b[3] == 0 and c["timed"] == 5 and c["latency_s"]["n"] == 5
    # rendering and merge on fake parts (including a missing part, the pre-registered primary and the fp32 fallback)
    def part(name, arms):
        return {"job": "grid", "part": name, "fake_pool": True, "env": {"machine": "x"}, "config": {}, "rrf": {"hit5": H.rate(3, 6), "hit5_by_type": {"state": H.rate(2, 3), "fact": H.rate(1, 3)},
                "pool_at": {"10": H.rate(3, 6), "25": H.rate(6, 6)}}, "models": {m: {"repo": MODELS[m]["repo"], "revision": MODELS[m]["rev"], "licence": "apache-2.0", "card_flags": []}
                for m in {a_["model"] for a_ in arms}}, "skipped": [{"repo": "r", "exists": False}], "arms": arms, "fp32_vs_int8": []}
    a1 = {"model": "gte", "precision": "int8", "status": "ok", "route": "r", "sanity": True, "cells": [c10, c25]}
    a2 = {"model": "bge", "precision": "int8", "status": "dropped", "reason": "licence", "cells": []}
    res, q = merge_parts([part("gte", [a1]), part("ref", [a2])], ["gte", "ref", "extra"])
    assert res["missing_parts"] == ["extra"] and res["rrf_identical_across_parts"] and res["primary"]["cell_used"] is None and q["cells"] == [], (res["primary"], q)
    c10b = dict(c10, id="gte:int8:K10:L256", model="gte", vs_rrf={**c10["vs_rrf"], "p": 0.001, "b": 1, "c": 9}, latency_s={"n": 6, "p50": 0.31, "p95": 0.4, "mean": 0.3, "max": 0.5},
                tokens={"pair_mean": 100.2, "padded_mean": 150.1, "truncated_share": 0.1})
    a1b = dict(a1, cells=[c10b, dict(c25, id="gte:int8:K25:L512", model="gte", latency_s={"n": 6, "p50": 3.0, "p95": 4, "mean": 3, "max": 5})])
    res, q = merge_parts([part("gte", [a1b])], ["gte"])
    assert res["primary"]["cell_used"] == "gte:int8:K10:L256" and not res["primary"]["fp32_fallback"] and res["bundle_cells"] == ["gte:int8:K10:L256"], res["bundle_cells"]
    assert q["cells"][0]["matched_T"] == 151 and q["cells"][0]["n2"]["p50_s"] == 0.31 and q["dropped_by_cap"] == []
    a1c = dict(a1, precision="fp32", cells=[dict(c10b, id="gte:fp32:K10:L256", precision="fp32")])
    res, q = merge_parts([part("gte", [a1c])], ["gte"])
    assert res["primary"]["fp32_fallback"] and res["primary"]["cell_used"] == "gte:fp32:K10:L256" and res["bundle_cells"] == [] and res["qualifying"] == [], res["primary"]
    txt = render_merge(res) + render_grid(part("gte", [a1b]))
    assert "PRIMARY" in txt and "fp32 used" in txt and "none qualified" in txt
    # notes and bundle spec
    sp = parse_spec("gte:int8:10:256:151,bge:int8:25:512")
    assert [c["id"] for c in sp] == ["gte:int8:K10:L256", "bge:int8:K25:L512"] and sp[0]["matched_T"] == 151 and sp[1]["matched_T"] is None
    for bad in ("gte:fp32:10:256", "nope:int8:10:256"):
        try:
            parse_spec(bad)
            raise AssertionError("bad spec accepted")
        except SystemExit:
            pass
    tmp = Path(tempfile.mkdtemp(prefix="eret_local_selftest_"))
    try:
        mp = tmp / "meta.json"
        mp.write_text(json.dumps({"models": {"gte": {"repo": "r", "revision": "v", "licence": "apache-2.0", "onnx_mb": 1.5, "onnx_sha256": "s"}}, "cells": q["cells"] or [dict(sp[0])]}))
        notes_cmd(types.SimpleNamespace(meta=str(mp), ref=None, out=str(tmp / "n.md"), sha="abc", run_id="1", commit="def"))
        assert "sha256 abc" in (tmp / "n.md").read_text() and "did not produce a table" in (tmp / "n.md").read_text()
        # guard red and green: a leaked corpus window is caught; a code-owned label that also occurs in the corpus is exempt (this file's literals)
        import random
        rnd = "".join(random.Random(7).choice("bcdfghjklmnpqrstvwxz") for _ in range(60))  # consonants only: short code literals cannot cover it
        label = cell_id("gte", "int8", 10, 256)
        texts = [rnd, f"notes about {label} scoring"]
        bad, good = tmp / "bad.md", tmp / "good.md"
        bad.write_text("| x | 1 |\nleak: " + rnd[5:55])
        good.write_text(f"| {label} | 12/198 = 0.061 | 0.123456789012 |")
        assert guard_check(texts, [str(bad)]), "guard missed a leaked window"
        assert not guard_check(texts, [str(good)]), "guard flagged clean output or an exempt label"
        assert H.guard_findings(texts, [str(good)], set()), "without the exemption the label must be flagged"
        # a library message recorded under `reason` by the public phase is exempt; the same text under any other key is flagged
        msg = "RuntimeError: " + rnd[10:50] + " not supported"
        (tmp / "m_ok.json").write_text(json.dumps({"arms": [{"reason": msg}]}))
        (tmp / "m_bad.json").write_text(json.dumps({"arms": [{"note": msg}]}))
        assert not guard_check([rnd], [str(tmp / "m_ok.json")]) and guard_check([rnd], [str(tmp / "m_bad.json")]), "recorded-message exemption is wrong"
        assert H.guard_findings([rnd], [str(tmp / "m_ok.json")], set()), "without the exemption the message must be flagged"
        for nm, obj in (("res", res), ("grid", part("gte", [a1b]))):
            (tmp / f"{nm}.json").write_text(json.dumps(obj, indent=1))
        (tmp / "res.md").write_text(render_merge(res))
        assert not guard_check(texts, [str(tmp / "res.json"), str(tmp / "res.md"), str(tmp / "grid.json")]), "guard flagged a clean report"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # public sanity texts: one relevant passage first, 3 distractors, no duplicates
    assert all(len({rel, *oth}) == 4 for _, rel, oth in PUB)
    print("selftest local_rerank ok")


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    sp.add_parser("selftest")
    g = sp.add_parser("grid")
    g.add_argument("--pools", required=True, help="private pools.json from rrf_rerank.py pools, or `fake` (public toy pools, smoke)")
    g.add_argument("--part", required=True)
    g.add_argument("--arms", required=True)
    g.add_argument("--cells", default=",".join(f"{k}x{l}" for k, l in CELLS))
    g.add_argument("--out", required=True)
    g.add_argument("--summary", required=True)
    g.add_argument("--parity", action="store_true", help="int8 vs fp32 torch on the public groups (loads the fp32 model)")
    g.add_argument("--budget-min", dest="budget_min", type=float, default=300.0)
    g.add_argument("--strict", action="store_true", help="exit 3 when any arm is neither ok nor dropped (the public smoke run)")
    m = sp.add_parser("merge")
    m.add_argument("--parts", required=True)
    m.add_argument("--out", required=True)
    m.add_argument("--expect", default="")
    q = sp.add_parser("guard")
    q.add_argument("--corpus", required=True)
    q.add_argument("--files", nargs="+", required=True)
    b = sp.add_parser("bundle")
    b.add_argument("--out", required=True)
    b.add_argument("--work", required=True)
    b.add_argument("--qualify")
    b.add_argument("--cells-spec", dest="cells_spec")
    n = sp.add_parser("notes")
    for k in ("meta", "out", "sha", "run-id", "commit"):
        n.add_argument("--" + k, required=True)
    n.add_argument("--ref")
    e = sp.add_parser("export-gte")
    e.add_argument("src")
    e.add_argument("dst")
    a = ap.parse_args()
    try:
        if a.cmd == "export-gte":
            return export_gte(a.src, a.dst)
        rc = {"selftest": selftest, "grid": grid_cmd, "merge": merge_cmd, "guard": guard_cmd, "bundle": bundle_cmd, "notes": notes_cmd}[a.cmd](a)
        sys.exit(rc or 0)
    except SystemExit:
        raise
    except Exception as ex:  # noqa: BLE001  (class and source line only: messages and locals can carry corpus text)
        print(f"FAILED {type(ex).__name__} at {where(ex)}", flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
