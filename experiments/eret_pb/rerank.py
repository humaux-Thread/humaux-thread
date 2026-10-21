#!/usr/bin/env python3
"""E-RET-PB1: cross-encoder scoring for the rerank arms (experiment, not product code).

Scoring follows each model card's own transformers snippet and is copied from E-RET-5a (branch exp/e-ret-5a-rerank-bench,
experiments/rerank_bench/bench.py): bge = sequence-classification logit per pair; ONNX int8 = the same bge weights, dynamic int8
quantisation through optimum + onnxruntime; Qwen3-Reranker = P("yes") from the last-position logits.
Imported only by the rerank jobs (needs torch). `export-ort` is the internal CLI the int8 path calls in its own process.
No corpus text is printed here.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from pathlib import Path

import torch

OK_LICENCES = {"apache-2.0", "mit"}  # commercial use allowed; anything else excludes the model (E-RET-5a rule)
QWEN_FORMAT = "<Instruct>: {instruction}\n<Query>: {query}\n<Document>: {doc}"
QWEN_PREFIX = ('<|im_start|>system\nJudge whether the Document meets the requirements based on the Query and the Instruct '
               'provided. Note that the answer can only be "yes" or "no".<|im_end|>\n<|im_start|>user\n')
QWEN_SUFFIX = "<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n"
QWEN_TASK = "Given a web search query, retrieve relevant passages that answer the query"
PANDA = ("The giant panda (Ailuropoda melanoleuca), sometimes called a panda bear or simply panda, "
         "is a bear species endemic to China.")  # bge model card example passage
KIND = {"fp32": "seqcls", "int8": "ort_int8", "qwen": "causal_yesno"}


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def pin_and_licence(repo: str, rev: str) -> dict:
    """Fail unless the pinned revision resolves to itself and the licence allows commercial use (same checks as 5a)."""
    from huggingface_hub import HfApi, hf_hub_download
    api = HfApi()
    head, info = api.model_info(repo).sha, api.model_info(repo, revision=rev)
    readme = Path(hf_hub_download(repo, "README.md", revision=rev)).read_text(encoding="utf-8")
    m = re.search(r"^license:\s*(\S+)", readme, re.M)
    lic = (info.card_data.license if info.card_data else None) or (m.group(1) if m else None)
    out = {"repo": repo, "revision": rev, "pinned_resolves_to": info.sha, "head_sha_now": head, "licence": lic}
    log("pin", out)
    if info.sha != rev:
        raise SystemExit(f"pin {rev} does not resolve to itself ({info.sha})")
    if str(lic).lower() not in OK_LICENCES:
        raise SystemExit(f"licence {lic!r} not in {sorted(OK_LICENCES)}")
    return out


def download(repo: str, rev: str) -> str:
    from huggingface_hub import snapshot_download
    return snapshot_download(repo, revision=rev, allow_patterns=["*.json", "*.safetensors", "*.model", "*.txt", "README.md"])


class Scorer:
    """Scores (query, doc) pairs exactly as the model card's own transformers snippet does."""

    def __init__(self, kind: str, path: str):
        from transformers import AutoModelForCausalLM, AutoModelForSequenceClassification, AutoTokenizer
        self.kind, self.export_s = kind, None
        if kind == "seqcls":
            self.tok = AutoTokenizer.from_pretrained(path)
            self.model = AutoModelForSequenceClassification.from_pretrained(path, torch_dtype=torch.float32)
        elif kind == "ort_int8":
            import onnxruntime as ort
            from optimum.onnxruntime import ORTModelForSequenceClassification
            work = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "ort"
            t = time.perf_counter()
            subprocess.run([sys.executable, __file__, "export-ort", path, str(work)], check=True)
            self.export_s = round(time.perf_counter() - t, 1)
            so = ort.SessionOptions()
            so.intra_op_num_threads, so.inter_op_num_threads = 4, 1
            self.tok = AutoTokenizer.from_pretrained(path)
            self.model = ORTModelForSequenceClassification.from_pretrained(
                str(work / "int8"), file_name="model_quantized.onnx", session_options=so, provider="CPUExecutionProvider")
        else:
            self.tok = AutoTokenizer.from_pretrained(path, padding_side="left")
            self.model = AutoModelForCausalLM.from_pretrained(path, torch_dtype=torch.float32)
            self.no, self.yes = self.tok.convert_tokens_to_ids("no"), self.tok.convert_tokens_to_ids("yes")
            self.pre = self.tok.encode(QWEN_PREFIX, add_special_tokens=False)
            self.suf = self.tok.encode(QWEN_SUFFIX, add_special_tokens=False)
        if kind != "ort_int8":
            self.model.eval()

    def encode(self, pairs, length: int):
        if self.kind != "causal_yesno":
            return self.tok([list(p) for p in pairs], padding=True, truncation=True, max_length=length, return_tensors="pt")
        texts = [QWEN_FORMAT.format(instruction=QWEN_TASK, query=q, doc=d) for q, d in pairs]
        enc = self.tok(texts, padding=False, truncation="longest_first", return_attention_mask=False,
                       max_length=length - len(self.pre) - len(self.suf))
        enc["input_ids"] = [self.pre + ids + self.suf for ids in enc["input_ids"]]
        return self.tok.pad(enc, padding=True, return_tensors="pt", max_length=length)

    def forward(self, enc):
        """Call under torch.inference_mode()."""
        if self.kind == "seqcls":
            return self.model(**enc, return_dict=True).logits.view(-1).float()
        if self.kind == "ort_int8":
            return self.model(**enc).logits.view(-1).float()
        last = self.model(**enc, logits_to_keep=1).logits[:, -1, :]
        return torch.log_softmax(torch.stack([last[:, self.no], last[:, self.yes]], dim=1), dim=1)[:, 1].exp()

    def score_query(self, query: str, docs, length: int, b: int = 8):
        """One end-to-end rerank call (tokenise + forward in batches of b). Returns scores in docs order."""
        out = []
        with torch.inference_mode():
            for i in range(0, len(docs), b):
                out += self.forward(self.encode([(query, d) for d in docs[i:i + b]], length)).tolist()
        return out

    def sanity(self) -> bool:
        """The model card's example must rank as the card implies (bge: panda passage over 'hi'; Qwen: diagonal wins)."""
        if self.kind != "causal_yesno":
            s = self.score_query("what is panda?", ["hi", PANDA], 512)
            return s[1] > s[0]
        s = self.score_query("What is the capital of China?", ["The capital of China is Beijing.", "Explain gravity"], 512)
        return s[0] > 0.5 > s[1]


def export_ort(src: str, dst: str):
    """fp32 ONNX export, then dynamic int8 quantisation (optimum). Separate process so the serving peak RSS excludes it."""
    from optimum.onnxruntime import ORTModelForSequenceClassification, ORTQuantizer
    from optimum.onnxruntime.configuration import AutoQuantizationConfig
    m = ORTModelForSequenceClassification.from_pretrained(src, export=True)
    m.save_pretrained(Path(dst) / "fp32")
    ORTQuantizer.from_pretrained(Path(dst) / "fp32").quantize(
        save_dir=Path(dst) / "int8", quantization_config=AutoQuantizationConfig.arm64(is_static=False, per_channel=False))


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "export-ort":
        export_ort(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit("usage: rerank.py export-ort SRC DST")
