#!/usr/bin/env python3
"""CI-only build tool for the local rerank model artifact (ADR-0084 D-A, card T-RET-7b).

Runs only in GitHub Actions (.github/workflows/rerank-artifact.yml); nothing here is imported by product code and
nothing here is meant to run on a developer machine. Public model and public data only; no corpus text.

Subcommands:
  selftest          stdlib only, no model: the manifest and tolerance logic, red and green
  build             pin + licence check, optimum export, E-RET-5a's int8 recipe, tokenizer files; one process = one build
  compare           byte-compare two builds -> determinism.json
  package           manifest.json + a deterministic tarball + its sha256 file
  verify-manifest   G7b-1: every file of the tarball matches manifest.json
  fixtures-generate public parity fixtures: ids, mask, int8 reference scores, and the measured score spreads
  fixtures-verify   G7b-2: re-score the committed fixtures with the built artifact
  notes             release notes for the publish job

Model identity (ADR-0084 D-A) = (repo, revision, recipe version, onnx sha256, tokenizer sha256); it is the `identity`
object of manifest.json. The recipe is E-RET-5a / E-RET-PB7's: the optimum export, then
AutoQuantizationConfig.arm64(is_static=False, per_channel=False).
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import itertools
import json
import math
import os
import re
import shutil
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import NoReturn

REPO = "cross-encoder/mmarco-mMiniLMv2-L12-H384-v1"
REVISION = "1427fd652930e4ba29e8149678df786c240d8825"
RECIPE = "mmarco-int8-v1"
RELEASE_NAME = "rerank-mmarco-int8-v1"
OK_LICENCES = {"apache-2.0", "mit"}  # commercial use allowed; anything else refuses the build (E-RET-5a rule)
ONNX_NAME = "model_quantized.onnx"
TOKENIZER_FILES = ("tokenizer.json", "tokenizer_config.json", "special_tokens_map.json", "config.json")
# ponytail: sentencepiece.bpe.model is not shipped (the Rust `tokenizers` crate reads tokenizer.json only); add it if a slow-tokenizer consumer appears
SNAPSHOT_PATTERNS = ["*.json", "*.safetensors", "*.model", "*.txt", "README.md"]  # as E-RET-5a / PB7
# The name avoids the substring that makes gitleaks' generic-api-key rule read a bare hex value as a secret.
ADR_TOK_SHA256 = "62c24cdc13d4c9952d63718d6c9fa4c287974249e16b7ade6d5a85e7bbb75626"  # tokenizer.json, ADR-0084 "Pins read"
MAX_LEN = 256  # rerank_max_len default (ADR-0084 D-E)
INTRA_OP_THREADS = 4  # rerank_threads default (ADR-0084 D-E); inter_op is 1
MAX_PAIRS = 64
TRUNCATION = "longest_first"  # ADR-0084 D-C; G7b-2 takes this from here, never from the fixture it checks
DEFAULT_TOLERANCE = 1e-4  # card default when two identical runs are bit-identical
TOLERANCE_CAP = 1e-3  # G7b-2 refuses a fixture whose header asks for a looser tolerance than this
LONGQ_MIN_TOKENS = 140  # the long-query group's query must exceed this, so longest_first cuts it and only_second does not (max_len 256 leaves 126 per side)
VERSION_PACKAGES = ("onnxruntime", "optimum", "optimum-onnx", "onnx", "torch", "transformers", "tokenizers", "huggingface-hub", "protobuf", "numpy", "pyarrow")

# Public C-MTEB/T2Reranking at the revision E-RET-5a pinned (same file hash as n1-bench-bundle). The HF mirror card states no licence;
# the upstream THUIR/T2Ranking README, section License, says Apache License 2.0 (re-read 2026-10-22 for this card).
DATASET_REPO, DATASET_REV = "C-MTEB/T2Reranking", "76631901a18387f85eaa53e5450019b87ad58ef9"
DATASET_FILE = "data/dev-00000-of-00001-65d96bde8023d9b9.parquet"
DATASET_SHA256 = "ceaf1ba1a4777dbb7aecad86fb8aa9cae7a678af6d711d5529c238e89bb6adff"
DATASET_LICENCE = "Apache-2.0 (upstream THUIR/T2Ranking README, section License, read 2026-10-22; the HF mirror card states none)"

# Short public cases written for E-RET-PB7 (PUB in experiments/eret_pb/local_rerank.py at aae2ae4): (lang, query, relevant, irrelevant, irrelevant).
SEED = (
    ("en", "what is panda?", "The giant panda (Ailuropoda melanoleuca), sometimes called a panda bear or simply panda, is a bear species endemic to China.",
     "hi", "The stock market closed higher on Friday after a strong jobs report."),
    ("zh", "中国的首都在哪儿", "北京是中华人民共和国的首都，也是全国的政治中心和文化中心。", "苹果是一种常见的水果，富含维生素。", "今天的足球比赛在晚上八点开始。"),
    ("en", "how to implement quick sort in python?", "Quick sort picks a pivot, partitions the list around it and recurses on both sides; in Python it takes a few lines.",
     "The Great Wall of China was built over many centuries to protect the northern borders.", "Photosynthesis converts light energy into chemical energy in plants."),
    ("en", "who wrote the novel Pride and Prejudice?", "Pride and Prejudice is an 1813 novel by the English author Jane Austen.",
     "Mount Everest is the highest mountain above sea level.", "A balanced diet includes vegetables, fruit, grains and protein."),
    ("zh", "光合作用是什么", "光合作用是植物、藻类和某些细菌利用光能把二氧化碳和水转化为有机物并释放氧气的过程。", "长城是中国古代的军事防御工程。", "明天的天气预报说有小雨。"),
    ("en", "how long is a marathon?", "A marathon is a long-distance running race with an official distance of 42.195 kilometres.",
     "Jane Austen published six major novels.", "The recipe asks for two cups of flour and one egg."),
)
# Mixed-language cases (Chinese and English inside one pair), written for this card.
MIXED = (
    ("Python 里的 list 和 tuple 有什么区别？", "在 Python 中，list 是可变序列，tuple 是不可变序列，所以 tuple 可以作为 dict 的 key。",
     "The Great Wall of China is more than twenty thousand kilometres long.", "今天的 weather 很好，适合去公园散步。"),
    ("Where is the 故宫 (Forbidden City) located?", "故宫，又称 Forbidden City，位于北京市中心，是明清两代的皇家宫殿。",
     "Mount Fuji is the highest mountain in Japan.", "这家 café 的拿铁很好喝，价格也不贵。"),
    ("how to say 谢谢 in English", "“谢谢”在英语里是 thank you，更口语的说法是 thanks。",
     "The annual report is due at the end of the quarter.", "明天下午三点开会，请准时参加。"),
)
# One English group whose query alone exceeds 128 tokens and whose first passage is long: longest_first cuts both sides, only_second cuts only the passage,
# so the two strategies give different ids. The query is the shortest prefix of these sentences that exceeds LONGQ_MIN_TOKENS. Written for this card.
LONGQ = (
    "I am planning a three-week trip through the north of Japan in early autumn with my elderly parents.",
    "They cannot walk long distances or climb many stairs, so every transfer has to be easy and every hotel has to have a lift.",
    "We want to see the autumn leaves, soak in a hot spring and eat fresh local seafood.",
    "None of us speaks Japanese, and we would rather avoid the most crowded tourist routes.",
    "Which cities and regions should we choose, and in which order should we visit them?",
    "How should we move between them by train and by bus, and what should we reserve in advance?",
    "How much luggage can we realistically carry when we change trains several times?",
    "Which festivals or holiday weeks should we avoid because the hotels are fully booked and the prices double?",
    "What documents, insurance and vaccinations do older travellers need, and how should we handle medicine and emergencies?",
    "Please explain the plan step by step.",
)
LONGP = (
    "For older travellers, the north of Japan is best explored from a few comfortable bases rather than a long chain of one-night stops.",
    "Sendai, Morioka and Aomori are connected by the Tohoku Shinkansen, whose stations have lifts and where staff can help with luggage, so most transfers are short and flat.",
    "In Hokkaido, a reserved seat on the limited express from Sapporo makes the hot-spring towns of Noboribetsu and Jozankei easy to reach without a long walk.",
    "Autumn leaves peak from late September in the mountains and move down to the coast by early November, so a route from north to south follows the colour.",
    "Reserve the train seats and the hotel rooms at least two months ahead, choose rooms on the ground floor or with a western-style bed, and send large suitcases ahead with the luggage-forwarding service so that each person carries only a small bag.",
    "Avoid Silver Week in September and the long holiday weekends of October and November, when trains and inns are full and prices rise sharply.",
    "Carry a printed list of medicines, check that the travel insurance covers hospital treatment abroad, and keep the number of the local emergency service and a card with the hotel address in Japanese.",
)


def die(msg: str) -> NoReturn:
    raise SystemExit(f"rerank-artifact: {msg}")


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def digest(path) -> str:
    """The `sha256:` prefixed form the committed fixture header uses (a bare hex value there is read as a secret; see ADR_TOK_SHA256)."""
    return "sha256:" + sha256_file(path)


def versions() -> dict:
    from importlib.metadata import PackageNotFoundError, version
    out = {"python": sys.version.split()[0]}
    for p in VERSION_PACKAGES:
        try:
            out[p] = version(p)
        except PackageNotFoundError:
            out[p] = "absent"
    return out


# ---------------------------------------------------------------- build
def pin_and_licence() -> dict:
    """Fail unless the pinned revision resolves to itself and the licence, read from the pinned model card, is commercial-permissive."""
    from huggingface_hub import HfApi, hf_hub_download
    api = HfApi()
    head = api.model_info(REPO).sha
    info = api.model_info(REPO, revision=REVISION)
    readme = Path(hf_hub_download(REPO, "README.md", revision=REVISION)).read_text(encoding="utf-8")
    fm = re.match(r"---\r?\n(.*?)\r?\n---", readme, re.S)
    m = re.search(r"^license:\s*['\"]?([^\s'\"]+)", fm.group(1), re.M) if fm else None
    card = info.card_data.license if info.card_data else None
    if isinstance(card, list):
        card = ",".join(card)
    seen = {k: str(v).lower() for k, v in (("model_info_card_data", card), ("readme_front_matter", m.group(1) if m else None)) if v}
    out = {"repo": REPO, "revision": REVISION, "pinned_resolves_to": info.sha, "head_sha_now": head, "licence_sources": seen,
           "licence": next(iter(seen.values()), None)}
    print("pin", json.dumps(out), flush=True)
    if info.sha != REVISION:
        die(f"pin {REVISION} does not resolve to itself ({info.sha})")
    if not seen or len(set(seen.values())) != 1 or out["licence"] not in OK_LICENCES:
        die(f"licence {seen!r} is not one of {sorted(OK_LICENCES)} (or the two sources disagree): refusing to build")
    return out


def export_int8(snap: Path, work: Path) -> None:
    """E-RET-5a's recipe, verbatim (rerank.py export_ort): fp32 ONNX export, then dynamic int8 quantisation."""
    from optimum.onnxruntime import ORTModelForSequenceClassification, ORTQuantizer
    from optimum.onnxruntime.configuration import AutoQuantizationConfig
    m = ORTModelForSequenceClassification.from_pretrained(str(snap), export=True)
    m.save_pretrained(Path(work) / "fp32")
    ORTQuantizer.from_pretrained(Path(work) / "fp32").quantize(
        save_dir=Path(work) / "int8", quantization_config=AutoQuantizationConfig.arm64(is_static=False, per_channel=False))


def onnx_facts(path) -> dict:
    """What T-RET-7c needs to know about the graph (ADR-0084 V5, U1): operators, opsets, input and output names."""
    import onnx
    m = onnx.load(str(path), load_external_data=False)
    ops: dict = {}
    for n in m.graph.node:
        ops[n.op_type] = ops.get(n.op_type, 0) + 1
    return {"sha256": sha256_file(path), "bytes": Path(path).stat().st_size, "ir_version": m.ir_version,
            "opsets": {o.domain or "ai.onnx": o.version for o in m.opset_import},
            "inputs": [i.name for i in m.graph.input], "outputs": [o.name for o in m.graph.output], "op_types": dict(sorted(ops.items()))}


def cmd_build(a) -> int:
    from huggingface_hub import snapshot_download
    out = Path(a.out)
    out.mkdir(parents=True)
    pin = pin_and_licence()
    snap = Path(snapshot_download(REPO, revision=REVISION, allow_patterns=SNAPSHOT_PATTERNS))
    work, files = out / "work", out / "files"
    files.mkdir()
    t = time.perf_counter()
    export_int8(snap, work)
    export_s = round(time.perf_counter() - t, 1)
    if not (work / "int8" / ONNX_NAME).exists() or not (work / "fp32" / "model.onnx").exists():
        die("export wrote no model_quantized.onnx / model.onnx")
    shutil.copy2(work / "int8" / ONNX_NAME, files / ONNX_NAME)
    for name in TOKENIZER_FILES:
        if (snap / name).exists():
            shutil.copy2(snap / name, files / name)
    if not (files / "tokenizer.json").exists():
        die("tokenizer.json missing from the pinned snapshot")
    shutil.copy2(snap / "README.md", files / "MODEL_CARD.md")
    tok_sha = sha256_file(files / "tokenizer.json")
    if tok_sha != ADR_TOK_SHA256:
        die(f"tokenizer.json sha256 {tok_sha} differs from the ADR-0084 pin {ADR_TOK_SHA256}: refusing to build")
    info = {"pin": pin, "versions": versions(), "export_seconds": export_s, "onnx": onnx_facts(files / ONNX_NAME),
            "fp32_onnx_sha256": sha256_file(work / "fp32" / "model.onnx"), "tokenizer_sha256": tok_sha,
            "tokenizer_sha256_matches_adr_0084": tok_sha == ADR_TOK_SHA256}
    (out / "build.json").write_text(json.dumps(info, indent=1), encoding="utf-8")
    print("build", json.dumps({k: info[k] for k in ("export_seconds", "tokenizer_sha256", "tokenizer_sha256_matches_adr_0084")}),
          "int8", info["onnx"]["sha256"], info["onnx"]["bytes"], "bytes; fp32", info["fp32_onnx_sha256"], flush=True)
    return 0


def first_difference(a, b) -> int | None:
    """Offset of the first differing byte (the length of the shorter file if one is a prefix of the other); None if identical."""
    off = 0
    with open(a, "rb") as fa, open(b, "rb") as fb:
        while True:
            ca, cb = fa.read(1 << 20), fb.read(1 << 20)
            if ca != cb:
                return off + next((i for i, (x, y) in enumerate(zip(ca, cb)) if x != y), min(len(ca), len(cb)))
            if not ca:
                return None
            off += len(ca)


def cmd_compare(a) -> int:
    b = [json.loads((Path(p) / "build.json").read_text(encoding="utf-8")) for p in (a.build1, a.build2)]
    same = b[0]["onnx"]["sha256"] == b[1]["onnx"]["sha256"]
    res = {"byte_deterministic": same, "int8_onnx_sha256": [x["onnx"]["sha256"] for x in b], "int8_onnx_bytes": [x["onnx"]["bytes"] for x in b],
           "fp32_onnx_sha256": [x["fp32_onnx_sha256"] for x in b], "fp32_byte_deterministic": b[0]["fp32_onnx_sha256"] == b[1]["fp32_onnx_sha256"],
           "tokenizer_sha256_equal": b[0]["tokenizer_sha256"] == b[1]["tokenizer_sha256"]}
    if not same:
        res["int8_first_difference_offset"] = first_difference(Path(a.build1) / "files" / ONNX_NAME, Path(a.build2) / "files" / ONNX_NAME)
    Path(a.out).write_text(json.dumps(res, indent=1), encoding="utf-8")
    print("determinism", json.dumps(res), flush=True)
    return 0


# ---------------------------------------------------------------- manifest, tarball, G7b-1
def make_manifest(build: dict, det: dict, files_dir: Path) -> dict:
    listed = {p.name: {"sha256": sha256_file(p), "bytes": p.stat().st_size} for p in sorted(Path(files_dir).iterdir()) if p.name != "manifest.json"}
    if ONNX_NAME not in listed or "tokenizer.json" not in listed:
        die("files/ lacks the onnx or tokenizer.json")
    if listed[ONNX_NAME]["sha256"] != build["onnx"]["sha256"]:
        die("files/ onnx differs from the build record")
    if det["byte_deterministic"]:
        note = "two builds in this job produced the same int8 onnx bytes; no claim is made across jobs or runners"
    else:
        note = (f"two builds in this job differ (first differing byte at offset {det.get('int8_first_difference_offset')}): "
                "the pin is the published file's sha256, not the recipe (ponytail: find the unstable pass if reproducibility is ever required)")
    pin = build["pin"]
    return {
        "schema": "humaux.rerank-artifact/v1",
        "name": RELEASE_NAME,
        "identity": {"repo": REPO, "revision": REVISION, "recipe": RECIPE,
                     "onnx_sha256": listed[ONNX_NAME]["sha256"], "tokenizer_sha256": listed["tokenizer.json"]["sha256"]},
        "licence": {"value": pin["licence"], "read_from": pin["licence_sources"], "accepted": sorted(OK_LICENCES)},
        "recipe": {"version": RECIPE, "export": "optimum ORTModelForSequenceClassification.from_pretrained(export=True), fp32",
                   "quantisation": "optimum ORTQuantizer + AutoQuantizationConfig.arm64(is_static=False, per_channel=False)",
                   "score": "the model's single logit; no sigmoid, no rescaling"},
        "tools": build["versions"],
        "onnx": {k: v for k, v in build["onnx"].items() if k not in ("sha256", "bytes")},
        "tokenizer": {"file": "tokenizer.json", "matches_adr_0084_pin": build["tokenizer_sha256_matches_adr_0084"]},
        "determinism": {"byte_deterministic": det["byte_deterministic"], "note": note},
        "built_by": {"workflow": "rerank-artifact", "github_run_id": os.environ.get("GITHUB_RUN_ID"), "github_sha": os.environ.get("GITHUB_SHA")},
        "files": listed,
    }


def write_tar(src, names, dest) -> None:
    """Deterministic tar.gz: sorted names, zero mtime and ownership, no gzip name."""
    with open(dest, "wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz, \
            tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for n in names:
            p = Path(src) / n
            ti = tarfile.TarInfo(f"{RELEASE_NAME}/{n}")
            ti.size, ti.mtime, ti.mode = p.stat().st_size, 0, 0o644
            with open(p, "rb") as f:
                tf.addfile(ti, f)


def cmd_package(a) -> int:
    b = Path(a.build)
    files = b / "files"
    build = json.loads((b / "build.json").read_text(encoding="utf-8"))
    det = json.loads(Path(a.determinism).read_text(encoding="utf-8"))
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    manifest = make_manifest(build, det, files)
    (files / "manifest.json").write_text(json.dumps(manifest, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    tarball = out / f"{RELEASE_NAME}.tar.gz"
    write_tar(files, sorted(p.name for p in files.iterdir()), tarball)
    sha = sha256_file(tarball)
    (out / f"{tarball.name}.sha256").write_text(f"{sha}  {tarball.name}\n", encoding="utf-8")
    shutil.copy2(files / "manifest.json", out / "manifest.json")
    print(f"package {tarball.name} {tarball.stat().st_size} bytes sha256 {sha}; identity {json.dumps(manifest['identity'])}", flush=True)
    return 0


def verify_tarball(tarball, sha_file, extract_to) -> tuple[list, Path | None]:
    """G7b-1: the tarball's files are exactly the files manifest.json lists, with its sha256 and sizes. Returns (problems, extracted root)."""
    problems: list = []
    if sha_file:
        want = Path(sha_file).read_text(encoding="utf-8").split()[0]
        if sha256_file(tarball) != want:
            problems.append(f"tarball sha256 differs from {Path(sha_file).name}")
    dest = Path(extract_to)
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball, "r:gz") as tf:
        tf.extractall(dest, filter="data")
    root = dest / RELEASE_NAME
    if not (root / "manifest.json").is_file():
        return problems + [f"{RELEASE_NAME}/manifest.json missing from the tarball"], None
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    listed = manifest["files"]
    present = {p.name for p in root.iterdir() if p.name != "manifest.json"}
    if present != set(listed):
        problems.append(f"file set differs: only in tarball {sorted(present - set(listed))}, only in manifest {sorted(set(listed) - present)}")
    for name, want in listed.items():
        p = root / name
        if not p.is_file():
            continue
        got = sha256_file(p)
        if got != want["sha256"]:
            problems.append(f"{name}: sha256 {got} differs from manifest {want['sha256']}")
        if p.stat().st_size != want["bytes"]:
            problems.append(f"{name}: {p.stat().st_size} bytes, manifest says {want['bytes']}")
    ident = manifest["identity"]
    if ident["onnx_sha256"] != listed.get(ONNX_NAME, {}).get("sha256"):
        problems.append("identity.onnx_sha256 differs from the listed onnx file")
    if ident["tokenizer_sha256"] != listed.get("tokenizer.json", {}).get("sha256"):
        problems.append("identity.tokenizer_sha256 differs from the listed tokenizer.json")
    return problems, root


def cmd_verify_manifest(a) -> int:
    problems, root = verify_tarball(a.tarball, a.sha_file, a.extract_to or tempfile.mkdtemp())
    if problems:
        print("G7b-1 manifest integrity: fail")
        for p in problems:
            print("  -", p)
        return 1
    n = len(json.loads((root / "manifest.json").read_text(encoding="utf-8"))["files"])
    print(f"G7b-1 manifest integrity: pass ({n} files match manifest.json sha256 and size; extracted to {root})")
    return 0


# ---------------------------------------------------------------- tokenizer and scoring
def load_tok(path):
    from tokenizers import Tokenizer
    return Tokenizer.from_file(str(path))


def encode(tok, query: str, passage: str, strategy: str | None) -> tuple[list, list]:
    """(query, passage) pair, special tokens counted; strategy None = no truncation. ADR-0084 D-C: longest-first at rerank_max_len."""
    if strategy is None:
        tok.no_truncation()
    else:
        tok.enable_truncation(max_length=MAX_LEN, strategy=strategy)
    e = tok.encode(query, passage)
    return list(e.ids), list(e.attention_mask)


class Scorer:
    """One onnxruntime CPU session; the score is the single logit."""

    def __init__(self, onnx_path, threads: int):
        import onnxruntime as ort
        so = ort.SessionOptions()
        so.intra_op_num_threads, so.inter_op_num_threads = threads, 1
        self.s = ort.InferenceSession(str(onnx_path), sess_options=so, providers=["CPUExecutionProvider"])
        names = sorted(i.name for i in self.s.get_inputs())
        if names != ["attention_mask", "input_ids"]:
            die(f"unexpected model inputs {names}")
        self.out = self.s.get_outputs()[0].name

    def run(self, batch: list, pad_id: int) -> list:
        import numpy as np
        n = max(len(x) for x in batch)
        ids = np.full((len(batch), n), pad_id, dtype=np.int64)
        mask = np.zeros((len(batch), n), dtype=np.int64)
        for i, x in enumerate(batch):
            ids[i, :len(x)], mask[i, :len(x)] = x, 1
        (logits,) = self.s.run([self.out], {"input_ids": ids, "attention_mask": mask})
        return [float(v) for v in logits.reshape(-1)]

    def score(self, pairs: list, pad_id: int) -> tuple[list, list]:
        """(one pair per call, each group as one right-padded batch). Dynamic int8 quantisation scales activations per tensor, so the two can differ."""
        single = [self.run([p["input_ids"]], pad_id)[0] for p in pairs]
        batch: list = []
        for _, grp in itertools.groupby(pairs, key=lambda p: p["group"]):
            batch += self.run([p["input_ids"] for p in grp], pad_id)
        return single, batch


def max_diff(a: list, b: list) -> float:
    return max((abs(x - y) for x, y in zip(a, b)), default=0.0)


def tolerance_for(run_to_run: float) -> float:
    """1e-4 absolute if two identical runs are bit-identical (card default); else the next power of ten at or above 10x the observed spread, 1e-4 at least."""
    if run_to_run == 0:
        return DEFAULT_TOLERANCE
    return float(f"1e{math.ceil(math.log10(max(DEFAULT_TOLERANCE, 10 * run_to_run)))}")


def out_of_tolerance(stored: list, got: list, tol: float) -> list:
    return [i for i, (x, y) in enumerate(zip(stored, got)) if not abs(x - y) <= tol]


# ---------------------------------------------------------------- fixtures
def t2r_groups(tok) -> tuple[list, list]:
    """First 3 rows (file order) whose 4 passages (first positive, first 3 negatives) all fit in MAX_LEN tokens, and first 3 rows with at least one over-length pair."""
    import pyarrow.parquet as pq
    from huggingface_hub import hf_hub_download
    p = hf_hub_download(DATASET_REPO, DATASET_FILE, repo_type="dataset", revision=DATASET_REV)
    if sha256_file(p) != DATASET_SHA256:
        die("dataset file hash mismatch")
    short: list = []
    long_: list = []
    idx = -1
    for batch in pq.ParquetFile(p).iter_batches(batch_size=64):
        for r in batch.to_pylist():
            idx += 1
            if len(r["positive"]) < 1 or len(r["negative"]) < 3:
                continue
            ps = [(r["positive"][0], True)] + [(t, False) for t in r["negative"][:3]]
            over = any(len(encode(tok, r["query"], t, None)[0]) > MAX_LEN for t, _ in ps)
            bucket = long_ if over else short
            if len(bucket) < 3:
                bucket.append((idx, r["query"], ps))
        if len(short) == 3 and len(long_) == 3:
            break
    if len(short) < 3 or len(long_) < 3:
        die(f"dataset gave {len(short)} short and {len(long_)} long groups, need 3 and 3")
    return short, long_


def build_cases(tok) -> list:
    cases: list = []

    def add(group, lang, source, query, passages):
        for i, (text, rel) in enumerate(passages):
            cases.append({"id": f"{group}-{i}", "group": group, "lang": lang, "source": source, "relevant": rel, "query": query, "passage": text})

    for gi, (lang, q, rel, i1, i2) in enumerate(SEED):
        add(f"seed-{gi}", lang, "authored for E-RET-PB7, public", q, [(rel, True), (i1, False), (i2, False)])
    for gi, (q, rel, i1, i2) in enumerate(MIXED):
        add(f"mixed-{gi}", "mixed", "authored for T-RET-7b, public", q, [(rel, True), (i1, False), (i2, False)])
    short, long_ = t2r_groups(tok)
    for kind, rows in (("short", short), ("long", long_)):
        for gi, (idx, q, ps) in enumerate(rows):
            add(f"t2r-{kind}-{gi}", "zh", f"{DATASET_REPO}@{DATASET_REV[:8]} row {idx}", q, ps)
    q = ""
    for sentence in LONGQ:
        q = f"{q} {sentence}".strip()
        n_q = len(tok.encode(q, add_special_tokens=False).ids)
        if n_q > LONGQ_MIN_TOKENS:
            break
    if not LONGQ_MIN_TOKENS < n_q <= MAX_LEN - 26:
        die(f"long-query group: the query has {n_q} tokens, need more than {LONGQ_MIN_TOKENS} and at most {MAX_LEN - 26}")
    add("longq-0", "en", "authored for T-RET-7b, public (query over 128 tokens)", q,
        [(" ".join(LONGP), True), (SEED[3][3], False), (SEED[5][3], False)])
    if len(cases) > MAX_PAIRS:
        die(f"{len(cases)} pairs exceed the card's maximum of {MAX_PAIRS}")
    return cases


def rank_of(scores: list) -> list:
    return sorted(range(len(scores)), key=lambda i: -scores[i])


def min_gap(scores: list) -> float:
    s = sorted(scores, reverse=True)
    return min(x - y for x, y in zip(s, s[1:]))


def group_ranges(pairs: list) -> list:
    """[start, end) index range of each group, in file order."""
    out, start = [], 0
    for _, grp in itertools.groupby(pairs, key=lambda p: p["group"]):
        n = len(list(grp))
        out.append((start, start + n))
        start += n
    return out


def cmd_fixtures_generate(a) -> int:
    art = Path(a.artifact)
    tok = load_tok(art / "tokenizer.json")
    pad_id = tok.token_to_id("<pad>")
    if pad_id is None:
        die("tokenizer has no <pad>")
    pairs = build_cases(tok)
    only_second_differs = 0
    for p in pairs:
        ids, mask = encode(tok, p["query"], p["passage"], TRUNCATION)
        p["n_tokens"] = len(encode(tok, p["query"], p["passage"], None)[0])
        p["truncated"] = p["n_tokens"] > MAX_LEN
        p["input_ids"], p["attention_mask"] = ids, mask
        differs = encode(tok, p["query"], p["passage"], "only_second")[0] != ids
        only_second_differs += differs
        if p["id"] == "longq-0-0" and not differs:
            die("long-query pair: longest_first and only_second gave the same ids")
    s1, b1 = Scorer(art / ONNX_NAME, INTRA_OP_THREADS).score(pairs, pad_id)
    s2, b2 = Scorer(art / ONNX_NAME, INTRA_OP_THREADS).score(pairs, pad_id)
    st1, bt1 = Scorer(art / ONNX_NAME, 1).score(pairs, pad_id)
    sf, bf = Scorer(a.fp32, INTRA_OP_THREADS).score(pairs, pad_id)
    if not s1[0] > s1[1]:
        die(f"model-card sanity failed: 'what is panda?' scores {s1[0]} for the panda passage and {s1[1]} for 'hi'")
    ranges = group_ranges(pairs)
    gaps = [min_gap(s1[lo:hi]) for lo, hi in ranges]
    run_to_run = max(max_diff(s1, s2), max_diff(b1, b2))
    tol = tolerance_for(run_to_run)
    if tol > TOLERANCE_CAP:
        die(f"run-to-run spread {run_to_run:g} gives tolerance {tol:g}, above the cap {TOLERANCE_CAP:g} that G7b-2 enforces")
    for p, x, y in zip(pairs, s1, b1):
        p["score_int8"], p["score_int8_batch"] = x, y
    fp32_agree = sum(rank_of(s1[lo:hi]) == rank_of(sf[lo:hi]) for lo, hi in ranges)
    batch_agree = sum(rank_of(s1[lo:hi]) == rank_of(b1[lo:hi]) for lo, hi in ranges)
    v = versions()
    header = {
        "schema": "humaux.rerank-parity/v1",
        "purpose": "G-RET-11 input (ADR-0084 D-G): the Rust tokenizer must reproduce input_ids / attention_mask exactly and the Rust int8 session the scores within tolerance.abs",
        "generator": {"script": "scripts/rerank_artifact/build.py fixtures-generate", "github_run_id": os.environ.get("GITHUB_RUN_ID"), "github_sha": os.environ.get("GITHUB_SHA")},
        "model": {"repo": REPO, "revision": REVISION, "recipe": RECIPE, "onnx_sha256": digest(art / ONNX_NAME), "tokenizer_sha256": digest(art / "tokenizer.json")},
        "encoding": {"max_len": MAX_LEN, "truncation": TRUNCATION, "special_tokens_counted": True, "pair_order": "(query, passage)",
                     "input_ids_are_unpadded": True, "pad_id": pad_id, "pairs_where_only_second_would_differ": only_second_differs,
                     "tokenizer": f"tokenizers {v['tokenizers']} on tokenizer.json (same file the Rust crate reads)"},
        "scores": {"unit": "raw logit (no sigmoid)", "provider": "CPUExecutionProvider", "intra_op_threads": INTRA_OP_THREADS, "inter_op_threads": 1,
                   "onnxruntime": v["onnxruntime"],
                   "score_int8": "one pair per session run (batch of 1, no padding)",
                   "score_int8_batch": ("each group (3 or 4 pairs, in file order) is scored as ONE batch, input_ids right-padded to the longest member with pad_id "
                                        f"({pad_id}) and attention_mask 0. T-RET-7c's parity test must batch exactly by group. This is a parity shape, not the worker's: "
                                        "the worker batches 8 (ADR-0084 D-C 4)"),
                   "batch_dependence": (f"dynamic int8 quantisation scales activations per tensor, so a score depends on the batch it is computed in: the measured maximum "
                                        f"|score_int8 - score_int8_batch| is {max_diff(s1, b1):.2f} logit over these {len(pairs)} pairs (onnxruntime {v['onnxruntime']}, "
                                        f"{INTRA_OP_THREADS} threads)")},
        "tolerance": {"abs": tol, "applies_to": ["score_int8", "score_int8_batch"], "compare_like_with_like": True,
                      "rule": f"{DEFAULT_TOLERANCE:g} absolute when two identical runs are bit-identical, else the next power of ten at or above 10x the observed spread",
                      "measured": {"run_to_run_max_abs": run_to_run, "runs_bit_identical": run_to_run == 0,
                                   "threads_1_vs_4_max_abs": max(max_diff(s1, st1), max_diff(b1, bt1)),
                                   "batch_vs_single_max_abs": max_diff(s1, b1),
                                   "int8_vs_fp32_max_abs": max_diff(s1, sf), "int8_vs_fp32_mean_abs": sum(abs(x - y) for x, y in zip(s1, sf)) / len(s1),
                                   "groups_same_order_int8_vs_fp32": f"{fp32_agree}/{len(ranges)}",
                                   "groups_same_order_batch_vs_single": f"{batch_agree}/{len(ranges)}"},
                      "note": "int8 vs fp32 is quantisation error, not a tolerance; T-RET-7c reports its own spread against these scores and does not widen tolerance.abs silently"},
        "order": {"rule": "within a group, order by score_int8 descending", "min_adjacent_gap": min(gaps), "gap_exceeds_2x_tolerance": min(gaps) > 2 * tol},
        "counts": {"pairs": len(pairs), "groups": len(ranges), "over_max_len": sum(p["truncated"] for p in pairs),
                   "by_lang": {k: sum(p["lang"] == k for p in pairs) for k in ("en", "zh", "mixed")}},
        "data": {"dataset": {"repo": DATASET_REPO, "revision": DATASET_REV, "file": DATASET_FILE, "sha256": DATASET_SHA256, "licence": DATASET_LICENCE,
                             "selection": "first 3 rows (file order) whose 4 passages all fit in max_len and first 3 with an over-length pair; passages = first positive + first 3 negatives"},
                 "authored": "seed-* (E-RET-PB7 public texts), mixed-* and longq-* (this card) are written by the project and are public under the repository licence"},
    }
    keys = ("id", "group", "lang", "source", "relevant", "query", "passage", "n_tokens", "truncated", "input_ids", "attention_mask", "score_int8", "score_int8_batch")
    text = ('{\n"header": ' + json.dumps(header, ensure_ascii=False, indent=1) + ',\n"pairs": [\n'
            + ",\n".join(json.dumps({k: p[k] for k in keys}, ensure_ascii=False) for p in pairs) + "\n]\n}\n")
    Path(a.out).write_text(text, encoding="utf-8")
    print("fixtures", json.dumps({"counts": header["counts"], "tolerance": header["tolerance"], "order": header["order"], "encoding": header["encoding"]}), flush=True)
    return 0


def header_problems(h: dict, pad_id: int, n_pairs: int, n_truncated: int, n_over: int, n_groups: int) -> list:
    """What G7b-2 checks about the fixture header. The header is the data under test, never the source of a limit: the tolerance cap, max_len,
    truncation and thread count are constants of this file, and every count must equal what the pairs give."""
    out: list = []
    tol, enc, sc, cnt = h["tolerance"]["abs"], h["encoding"], h["scores"], h["counts"]
    if not (isinstance(tol, (int, float)) and 0 < tol <= TOLERANCE_CAP):
        out.append(f"header tolerance.abs {tol!r} is not in (0, {TOLERANCE_CAP:g}]")
    if enc["max_len"] != MAX_LEN:
        out.append(f"header encoding.max_len {enc['max_len']!r} is not {MAX_LEN}")
    if enc["truncation"] != TRUNCATION:
        out.append(f"header encoding.truncation {enc['truncation']!r} is not {TRUNCATION!r}")
    if enc["pad_id"] != pad_id:
        out.append(f"header encoding.pad_id {enc['pad_id']!r} is not the tokenizer's {pad_id}")
    if sc["intra_op_threads"] != INTRA_OP_THREADS:
        out.append(f"header scores.intra_op_threads {sc['intra_op_threads']!r} is not {INTRA_OP_THREADS}")
    for what, key, got in (("pairs", "pairs", n_pairs), ("groups", "groups", n_groups), ("pairs flagged truncated", "over_max_len", n_truncated),
                           ("pairs recomputed over max_len", "over_max_len", n_over)):
        if cnt[key] != got:
            out.append(f"header counts.{key} is {cnt[key]!r}, the fixture has {got} {what}")
    return out


def cmd_fixtures_verify(a) -> int:
    fx_path = Path(a.fixtures)
    if not fx_path.is_file():
        if a.require:
            print(f"G7b-2 fixture self-consistency: fail (required object missing: {fx_path})")
            return 1
        print(f"G7b-2 fixture self-consistency: not_applicable (missing object: {fx_path})")
        return 0
    fx = json.loads(fx_path.read_text(encoding="utf-8"))
    h, pairs = fx["header"], fx["pairs"]
    art = Path(a.artifact)
    tok = load_tok(art / "tokenizer.json")
    pad_id = tok.token_to_id("<pad>")
    problems: list = []
    if len(pairs) > MAX_PAIRS:
        problems.append(f"{len(pairs)} pairs exceed {MAX_PAIRS}")
    if digest(art / "tokenizer.json") != h["model"]["tokenizer_sha256"]:
        problems.append("tokenizer.json sha256 differs from the fixture header")
    if h["model"]["onnx_sha256"] != digest(art / ONNX_NAME):
        problems.append("header model.onnx_sha256 differs from the built artifact: regenerate the fixtures from this artifact")
    n_over = 0
    for p in pairs:
        ids, mask = encode(tok, p["query"], p["passage"], TRUNCATION)
        n_tokens = len(encode(tok, p["query"], p["passage"], None)[0])
        n_over += n_tokens > MAX_LEN
        if ids != p["input_ids"] or mask != p["attention_mask"]:
            problems.append(f"{p['id']}: token ids or mask differ from the pinned tokenizer")
        if n_tokens != p["n_tokens"] or (n_tokens > MAX_LEN) != p["truncated"]:
            problems.append(f"{p['id']}: n_tokens / truncated differ from the pinned tokenizer ({n_tokens} tokens)")
    problems += header_problems(h, pad_id, len(pairs), sum(bool(p["truncated"]) for p in pairs), n_over, len(group_ranges(pairs)))
    tol = min(h["tolerance"]["abs"], TOLERANCE_CAP) if isinstance(h["tolerance"]["abs"], (int, float)) else TOLERANCE_CAP
    single, batch = Scorer(art / ONNX_NAME, INTRA_OP_THREADS).score(pairs, pad_id)
    for field, got in (("score_int8", single), ("score_int8_batch", batch)):
        for i in out_of_tolerance([p[field] for p in pairs], got, tol):
            problems.append(f"{pairs[i]['id']}: {field} stored {pairs[i][field]!r}, re-scored {got[i]!r}, |delta| {abs(pairs[i][field] - got[i]):.3g} > tolerance {tol:g}")
    if problems:
        print(f"G7b-2 fixture self-consistency: fail ({len(problems)} problem(s))")
        for p in problems[:20]:
            print("  -", p)
        return 1
    worst = (max_diff([p["score_int8"] for p in pairs], single), max_diff([p["score_int8_batch"] for p in pairs], batch))
    print(f"G7b-2 fixture self-consistency: pass ({len(pairs)} pairs; ids identical; worst |delta| {worst[0]:.3g} single, {worst[1]:.3g} batch; "
          f"tolerance {tol:g}; header counts, max_len, truncation and the onnx sha256 agree with the built artifact)")
    return 0


# ---------------------------------------------------------------- notes, selftest
def cmd_notes(a) -> int:
    m = json.loads(Path(a.manifest).read_text(encoding="utf-8"))
    i = m["identity"]
    print("\n".join([
        f"Local rerank model artifact (ADR-0084 D-A, T-RET-7b). Built from `{i['repo']}` at `{i['revision']}` by workflow run {m['built_by']['github_run_id']} at {m['built_by']['github_sha']}.",
        "", f"- Asset `{RELEASE_NAME}.tar.gz`, sha256 `{a.sha}` (deployment pins this value, not the tag).",
        f"- Identity: recipe `{i['recipe']}`, onnx sha256 `{i['onnx_sha256']}`, tokenizer sha256 `{i['tokenizer_sha256']}`.",
        f"- Licence read from the pinned model card: {m['licence']['value']}.",
        f"- Byte-deterministic export: {m['determinism']['byte_deterministic']}. {m['determinism']['note']}.",
        "- Files and their sha256: see `manifest.json` inside the tarball (checked by gate G7b-1 before this release was created).",
        "- A prerelease: not a software release. Changing the identity is a new `calibration_profile` and a new tag, never an overwrite."]))
    return 0


def cmd_selftest(a) -> int:
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        src = d / "files"
        src.mkdir()
        (src / ONNX_NAME).write_bytes(bytes(range(256)) * 40)
        (src / "tokenizer.json").write_bytes(b'{"t": 1}')
        build = {"pin": {"licence": "apache-2.0", "licence_sources": {}}, "versions": {}, "tokenizer_sha256_matches_adr_0084": False,
                 "onnx": {"sha256": sha256_file(src / ONNX_NAME), "bytes": 10240}}
        (src / "manifest.json").write_text(json.dumps(make_manifest(build, {"byte_deterministic": True}, src)), encoding="utf-8")
        green = d / "green.tar.gz"
        write_tar(src, sorted(p.name for p in src.iterdir()), green)
        assert verify_tarball(green, None, d / "x1")[0] == [], "green tarball must verify"
        blob = bytearray((src / ONNX_NAME).read_bytes())
        blob[100] ^= 1  # one byte of the onnx changes after the manifest was written
        (src / ONNX_NAME).write_bytes(bytes(blob))
        red = d / "red.tar.gz"
        write_tar(src, sorted(p.name for p in src.iterdir()), red)
        problems = verify_tarball(red, None, d / "x2")[0]
        assert problems and ONNX_NAME in problems[0], f"corrupted onnx must be caught, got {problems}"
        (src / "extra.bin").write_bytes(b"x")
        extra = d / "extra.tar.gz"
        write_tar(src, sorted(p.name for p in src.iterdir()), extra)
        assert any("file set differs" in p for p in verify_tarball(extra, None, d / "x3")[0]), "an unlisted file must be caught"
    assert tolerance_for(0.0) == 1e-4 and tolerance_for(2e-5) == 1e-3 and tolerance_for(1e-9) == 1e-4
    assert out_of_tolerance([1.0, 2.0], [1.0, 2.0 + 5e-5], 1e-4) == [] and out_of_tolerance([1.0, 2.0], [1.0, 2.5], 1e-4) == [1]
    assert first_difference(__file__, __file__) is None
    good = {"tolerance": {"abs": 1e-4}, "encoding": {"max_len": MAX_LEN, "truncation": TRUNCATION, "pad_id": 1}, "scores": {"intra_op_threads": INTRA_OP_THREADS},
            "counts": {"pairs": 54, "groups": 16, "over_max_len": 6}}
    assert header_problems(good, 1, 54, 6, 6, 16) == [], "a consistent header must pass"
    for path, val, args in ((("tolerance", "abs"), 1e-2, (54, 6, 6, 16)), (("encoding", "max_len"), 512, (54, 6, 6, 16)), (("encoding", "truncation"), "only_second", (54, 6, 6, 16)),
                            (("counts", "pairs"), 53, (54, 6, 6, 16)), (("counts", "over_max_len"), 5, (54, 6, 6, 16)), (("encoding", "pad_id"), 0, (54, 6, 6, 16)),
                            (("scores", "intra_op_threads"), 1, (54, 6, 6, 16)), (("counts", "groups"), 15, (54, 6, 6, 16)), (None, None, (54, 6, 5, 16)), (None, None, (54, 5, 6, 16))):
        h = json.loads(json.dumps(good))
        if path:
            h[path[0]][path[1]] = val
        assert header_problems(h, 1, *args), f"header fault {path}={val!r} {args} must be caught"
    print("selftest ok: manifest corruption and extra file are caught, tolerance rule and comparison behave, fixture header faults are caught")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest").set_defaults(fn=cmd_selftest)
    p = sub.add_parser("build")
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_build)
    p = sub.add_parser("compare")
    p.add_argument("build1")
    p.add_argument("build2")
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_compare)
    p = sub.add_parser("package")
    p.add_argument("--build", required=True)
    p.add_argument("--determinism", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_package)
    p = sub.add_parser("verify-manifest")
    p.add_argument("tarball")
    p.add_argument("--sha-file")
    p.add_argument("--extract-to")
    p.set_defaults(fn=cmd_verify_manifest)
    p = sub.add_parser("fixtures-generate")
    p.add_argument("--artifact", required=True, help="extracted tarball root (model_quantized.onnx + tokenizer.json)")
    p.add_argument("--fp32", required=True, help="the fp32 onnx of the same build, for the int8-vs-fp32 spread")
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_fixtures_generate)
    p = sub.add_parser("fixtures-verify")
    p.add_argument("--artifact", required=True)
    p.add_argument("--fixtures", required=True)
    p.add_argument("--require", action="store_true", help="a missing fixtures file is a failure, not not_applicable")
    p.set_defaults(fn=cmd_fixtures_verify)
    p = sub.add_parser("notes")
    p.add_argument("--manifest", required=True)
    p.add_argument("--sha", required=True)
    p.set_defaults(fn=cmd_notes)
    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
