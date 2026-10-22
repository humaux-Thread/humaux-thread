# ADR-0084 — Local rerank lane: a local int8 cross-encoder behind a retrieval-worker RPC, on the hybrid pool

- Status: Accepted (2026-10-22). Card T-RET-7a (docs only). Decisions D-A to D-G are the design lead's, taken from the
  owner's decision of 2026-10-22 and from E-RET-5g and the N1 timing; the facts under "What was verified" are this
  card's. The code lands in T-RET-7b to T-RET-7d; until then every sentence below about behaviour is **planned**.
- Amended 2026-10-22 (card T-RET-7c, the lead's decision): **the five rerank registry entries (D-E) move from T-RET-7d to
  T-RET-7c.** The worker needs `rerank_enabled` (load the model or not, D-B) and `rerank_threads` (the session build, D-B)
  from its own registry read before any call, so the entries must exist when the worker lands. T-RET-7d keeps the gateway
  client, D-C steps 1 to 3, 5 and 6, the G55-6 forbidden-name set and the provenance constructor.
- Amended 2026-10-22 (card ds-ret-189, #187 review): **the `rerank_depth <= cand_k` ceiling (D-C 1, D-E) applies only
  while `rerank_enabled` is true** (#166), so a disabled lane keeps the registry default depth at any `cand_k`; the
  values file leaves the two worker keys empty, and empty means unset so the registry defaults apply (#185).
- Amended 2026-10-23 (card T-RET-7d-1, the lead's ruling): **T-RET-7d splits in two, the contract first.** T-RET-7d-1 is
  the module contract that D-C 3 and D-D need before any wiring: the D-D serve rule and the D-C 3 data path below, with
  no gateway change. T-RET-7d-2 keeps the rest of the T-RET-7d row (below, "Cards"): the gateway client and its
  bootstrap wiring with the deployment model pin, D-C steps 1 to 3, 5 and 6 in `gateway::recall`, the G55-6 names not
  already caught, the provenance constructor, both fault tests on the real path, G-RET-12, G-RET-13, G-RET-15, the
  in-cell test and U7.
- Amended 2026-10-23 (T-RET-7d-1), **D-D serve rule.** A `provenance` component that is `cannot_establish` is served,
  not refused. Baseline §23.3 (the provenance table and the paragraph after it) keeps `is_valid` as "complete
  provenance, eligible for result statistics", false for any `cannot_establish`, and says the failure diagnostic still
  serialises with all six fields, with no second validity notion. `retrieval::envelope` therefore splits
  `ProvenanceBlock::is_valid` into its two conjuncts inside the one definition (structural integrity; every component
  established), and `outcome_block_under` refuses only a structural breach with `ErrorCode::Internal`: another
  request's fingerprint or profile, an empty `binary_build`, a blank or placeholder `used` id, a `not_applicable`
  projection or embedding on a semantic branch. Before this, every D-D row whose `rerank_model_id` reads
  `cannot_establish` would have answered `Internal` instead of the fused order. No `ErrorCode` is added.
- Amended 2026-10-23 (T-RET-7d-1), **D-C 3 data path.** The chunk of a Memory is identified by the PostgreSQL registry,
  not by Qdrant: `projection.private_memory_points` carries `card_profile_hash` and `chunk_ordinal` for every point
  (ADR-0068 D-C), while the point id is a one-way digest and the point payload holds no ordinal. So:
  `ResolvedPrivateMemoryPoint` gains `slot: Option<CardSlot>` (`projection::note_chunks::CardSlot`, `Legacy` or
  `Chunk { ordinal }`; `None` for a profile this build does not know, ADR-0068 D-I);
  `MaterializedPrivateReadServing.point_slots` holds, for each Memory, the slot of the first candidate point that
  resolved to it (the fused list holds one point per Memory: the dense leg's when both legs found it, the sparse leg's
  otherwise, `gateway::recall::fuse_rrf`); `materialize_private_read_serving_about` takes a `GatedTexts` argument and,
  for `Read`, returns `gated_texts`: `(title, body)` from `private.memory_text_v` (ADR-0085) of exactly the Memory items
  the gate returned, read inside the hydrate transaction; and `projection::note_chunks::rerank_document(title, body,
  slot)` builds the document: `chunk_card_text` for a chunk slot (the card text that was embedded), title prefix +
  separator + the whole body for a legacy slot (which holds the body whole). The gateway passes `Skip` until T-RET-7d-2
  turns the lane on, so a recall with the lane off reads no text. A Memory whose slot is `None`, or whose text cannot be
  read, has no document: T-RET-7d-2 does not send it and keeps it after the scored ones in fused order (D-C 5).
- Amended 2026-10-23 (T-RET-7d-1, review of PR #204), **G-RET-13 and the text read.** The first shape of the D-C 3 data
  path read the texts in a second snapshot through a public function. `private.memory_text_v` applies RLS only: it does
  not exclude tombstoned, archived, superseded or secret-backed Memories, which the hydrate gate does. So a Memory
  forgotten (tombstoned) between the gate and that read, and any id the gate had refused, would have had its title and
  body returned and sent to the worker. There is now one snapshot and one gate: the text read is a private step of the
  hydrate transaction (`gated_memory_texts`), its ids are taken from the gated items and from nowhere else, and no
  function in `adapters::retrieve` returns a Memory text. (`adapters::memory_repo::memory_texts_in_txn` is still public and
  predates #204; a source scan, `bins/gateway/tests/no_memory_text_reader.rs`, fails if anything under `bins/gateway/src`
  names it or the view.) The archive-or-forget race is gone by construction.
- Amended 2026-10-23 (card T-RET-7d-2): **the wiring lands.** `gateway::rerank_client` (the port, the UDS client of
  `POST /v1/rerank` and the lane that carries the pin), the rerank stage of `gateway::recall`, the bootstrap (the five
  `HUMAUX_GATEWAY_RERANK_*` pin keys, read only while `rerank_enabled` is true, and the U7 check) and `retrieval::rerank`
  (the pure order-only step, `settle`, the one `RerankModelId` constructor, the one place the two rerank codes are
  emitted). Interpretations the table of D-D left open: the rerank RPC's wait is part of the `rerank` stage lap;
  `reranked_count` is the cross-encoder's while the branch is selected and the mood rerank's otherwise; a selected branch
  whose visible Memories have no document (an unknown slot, no readable body) has nothing to score and reads
  `not_applicable` with an operator line (no call, no degradation); a visible Memory with no document keeps its fused
  place after the scored ones; overlay items of a token read keep their positions among the Memory items.

- Supersedes: the "no reranker" record of ADR-0083 (its Evidence bullet and its Alternatives rejected entry), which the
  owner took earlier the same day. ADR-0083 now points here. Its legs and its fusion are unchanged.
- Relates to: Baseline §7.2, §19 (Rerank Provider Failover), §23.1③, §23.3, §50, §51, §52.3, §53.2, §53.4, §57.1,
  §67.2, §78.1; ADR-0012 (the UDS RPC and its peer-credential gate); ADR-0081 D-E and D-F; ADR-0083 D-C and D-D.

## Context

- Hybrid recall (ADR-0083, planned T-RET-6c) fuses a dense leg and a Qdrant `bm25` leg into one Memory-level RRF list,
  cuts it to `cand_k`, and runs the PostgreSQL hydrate gate. Nothing reorders that list afterwards except the mood
  rerank of the visible set.
- The Baseline today says the standard deployment has **no built-in neural model**: §4.2 (the retrieval-worker "loads no
  model weights"), §7.2 ("no built-in neural reranker / embedding model") and §67.2 ("retrieval-worker no longer keeps
  model weights resident"). Rerank is a cloud route there. `retrieval::rerank` is a placeholder module, and the two
  rerank `DegradeCode` variants have no emit site (`testkit/fault/dormant.toml`, both rows owned by M11).
- The owner decided on 2026-10-22 that production rerank is a **local** int8 cross-encoder that reorders the top 25 of the
  hybrid RRF pool. That replaces the same day's earlier decision to run without a reranker. The cloud rerank arms
  (E-RET-5d, E-RET-5f) and the Jev arm (E-RET-5c) were measured and not chosen; their numbers are in ADR-0083's
  Alternatives rejected.

## Evidence

Aggregates only; the corpus behind them is private and never enters this repository. N = 198 development questions, one
correct Memory each; hit@5 counts questions. "b / c" is the paired McNemar split (b = RRF right and the cell wrong, c =
the reverse), exact p.

- **E-RET-5g**: CI run 39724084843 (workflow `eret-local`, head aae2ae4, branch `exp/e-ret-pb-local-rerank`, conclusion
  success). Its log shows the reproduction gate on: RRF alone hit@5 96, pool@25 147. Method: the RRF pool of E-RET-5f
  (run 39629912275), input = title + newline + best chunk, the (query, document) pair cut to L tokens by the
  tokenizer, batches of 8 with dynamic padding, 4 intra-op threads, 1 inter-op.
- **N1 timing**: public bundle `n1-bench-bundle-v2`, run by the lead with the owner's approval on 2026-10-22 on the
  4-vCPU Neoverse-N1 production host (Baseline §67.2), not a CI run, with live services running and `--cpu-shares 512`.

| setup (hit@5 over 198) | hit@5 | against RRF alone (b / c, p) | N2 CI runner p50 | N1 production host |
|---|---|---|---|---|
| RRF alone (pool@25 is 147) | 96 | | | |
| **mmarco-mMiniLMv2-L12-H384-v1 int8, K 25, L 256** | **130** | 12 / 46, p 8.2e-6 | 0.67 s | p50 1.19 to 1.21 s; p95 1.3 to 3.9 s (spikes under CPU contention) |
| same, K 10, L 256 | 115 | 5 / 24, p 5.5e-4 | | p50 about 0.5 s |
| same, K 25, L 512 | 128 | 14 / 46, p 4.2e-5 | | |
| gte-multilingual-reranker-base int8, K 25, L 256 | 141 | | 2.08 s | |
| bge-reranker-base int8 | not significant | | | |
| gte int8 against gte fp32 (the only fp32 cells in the run) | not significant (K 25 L 256: 141 against 137) | | 2.08 s against 8.20 s | |

The b / c rows for K 10 and L 512 are read from the same run's log. In the L 256 cells 61.5% of the pairs reach the
256-token cap (mean pair 217.7 tokens); L 512 did not do better (128 against 130).

Caveats that bound these numbers:

1. The 198 questions are a **development set**: they tuned the old system, and the model was picked among three
   candidates on the same questions that score it. They justify building the lane; they do not confirm the 130. The
   sealed set of ADR-0081 re-measures later.
2. Rerank reorders a pool; it cannot add to it. Pool@25 is 147, so 130 is bounded by the retrieval before it.
3. **Every number above was measured through Python**: `onnxruntime` 1.30.0 and `tokenizers` 0.22.2 (the pins in the
   workflow `eret-local.yml` and the bundle's wheels). Nothing here was measured through the Rust path this ADR decides
   (`ort` plus the `tokenizers` crate 0.23.2). G-RET-11 checks the scores; T-RET-7c re-measures latency (U2).
4. The grid pre-registered an N1 target of rerank-stage p50 at most 1 s and p95 at most 2 s, and an N2 screening bar of
   p50 at most 0.5 s (docstring and constants of `experiments/eret_pb/local_rerank.py` at aae2ae4). K 25 sits above all
   of them (N2 0.67 s; N1 p50 1.19 to 1.21 s, p95 up to 3.9 s). K 10 is the registry-only way back (D-E).

## What was verified

First-hand sources, read on 2026-10-22; versions are the ones named. Crate metadata is
`https://crates.io/api/v1/crates/<name>/<version>` (and `/dependencies` under it); `ort` files are
`https://raw.githubusercontent.com/pykeio/ort/v2.0.0-rc.15/<path>`; `tokenizers` files are
`https://raw.githubusercontent.com/huggingface/tokenizers/v0.23.2/tokenizers/<path>`.

| # | Question | Answer | Source |
|---|---|---|---|
| V1 | `ort`: current stable version | **There is none.** The newest release is `2.0.0-rc.15` (published 2026-10-19, MSRV 1.92; the repo pins Rust 1.99.0). Every 1.x release is yanked. rc.15's release notes report over 30 fixed instances of undefined behaviour plus memory leaks and memory-safety bugs, urge upgrading from earlier rcs, and list API breaks against them. So the pin is exact (`=2.0.0-rc.15`) and a bump is a reviewed change. | crates.io `ort` (version list, `2.0.0-rc.15`); `https://github.com/pykeio/ort/releases/tag/v2.0.0-rc.15`; `rust-toolchain.toml` |
| V2 | `ort`: licence | `MIT OR Apache-2.0`, and the same for `ort-sys` 2.0.0-rc.15. | crates.io `ort` and `ort-sys` 2.0.0-rc.15 |
| V3 | `ort`: `aarch64-unknown-linux-gnu` | **Supported.** `ort-sys/build/download/dist.tsv` has a prebuilt row for it (CPU-only feature set `none`, ONNX Runtime 1.31.0, archive on `cdn.pyke.io` with a sha256). Pyke's Linux builds are compiled with Clang and depend on `libc++`. CI and the production host are both linux/arm64 (`ci.yml`, Baseline §67.2). | `dist.tsv`; `docs/content/misc/prebuilt-binaries.mdx` |
| V4 | `ort`: how the native library is obtained, and which ONNX Runtime it pairs with | Default features are `std, ndarray, tracing, download-binaries, tls-native, copy-dylibs, api-31`: `download-binaries` fetches pyke's prebuilt archive over HTTPS **at build time** and checks it against `dist.tsv`. The alternative is `load-dynamic`: no link-time dependency; the library is loaded at run time from `ORT_DYLIB_PATH` or `ort::init_from(path)`, and the docs recommend it. Pairing: `ort` 2.0.0 and later pairs with ONNX Runtime **1.31.0**; the `api-17` to `api-31` features select the lowest ONNX Runtime the code may assume, and the docs say `ort` supports 1.17 to 1.31 and runs on an older library than its own pairing when that library is linked manually. | crates.io `ort` 2.0.0-rc.15 (`features`); `docs/content/setup/linking.mdx`, `cargo-features.mdx`, `multiversion.mdx`, `misc/version-mapping.mdx` |
| V5 | Does the int8 dynamic-quantised model of E-RET-5a's recipe run on it? | **Not shown by documentation; see U1.** `ort` is a wrapper over the ONNX Runtime C API (its README), so operator support is ONNX Runtime's. The ONNX Runtime 1.31.0 CPU provider lists `MatMulInteger` (opset 10+, int8 or uint8 inputs, int32 out) and `DynamicQuantizeLinear` (opset 11+, uint8 out); its quantisation guide says CPU runs U8U8, U8S8 and S8S8 and that the operator-oriented format uses ops such as `MatMulInteger`. The artifact itself is built in T-RET-7b and its operator list is not read here. | `https://github.com/pykeio/ort/blob/v2.0.0-rc.15/README.md`; `https://raw.githubusercontent.com/microsoft/onnxruntime/v1.31.0/docs/OperatorKernels.md` (CPUExecutionProvider section); `https://onnxruntime.ai/docs/performance/model-optimizations/quantization.html` |
| V6 | Microsoft's own build for the shipped library | The official release assets include `onnxruntime-linux-aarch64-1.30.0.tgz` (published 2026-09-10, 10,269,495 bytes) and `onnxruntime-linux-aarch64-1.31.0.tgz` (2026-10-09). GitHub records a sha256 for each asset (1.30.0 is in the pins table). | GitHub API, `microsoft/onnxruntime` releases `v1.30.0`, `v1.31.0` |
| V7 | `tokenizers`: version and licence | Stable **0.23.2** (published 2026-09-03), `Apache-2.0`. `1.0.0-rc.3` (2026-10-19) is a pre-release and a different crate family (`tk-serialize`, `tk-encode`, `tk-train`); it is not evaluated. The experiments ran the Python wheel 0.22.2. | crates.io `tokenizers` (version list, 0.23.2, 1.0.0-rc.3) |
| V8 | `tokenizers`: features needed to load the model's `tokenizer.json`, and is `onig` or a C dependency required? | Loading a file (`Tokenizer::from_file`) needs no optional feature (`http` is for `from_pretrained` only). One regex backend must be enabled or the build stops with `compile_error!`: `onig` (default, the C library Oniguruma) or `fancy-regex` (pure Rust); it is chosen in `src/utils/mod.rs`. The defaults `progressbar` (`indicatif`) and `esaxx_fast` (a C++ build through `esaxx-rs/cpp`; `esaxx_rs` is referenced only by the Unigram **trainer**, `src/models/unigram/trainer.rs`) are not needed to run a tokenizer. The pinned `tokenizer.json` holds a `Precompiled` normalizer, a `Sequence[WhitespaceSplit, Metaspace]` pre-tokenizer, a Unigram model and a `TemplateProcessing` post-processor (pair = `<s> A </s> </s> B </s>`), `truncation` and `padding` null: **no regex-based component**. So `default-features = false, features = ["fancy-regex"]` loads it with no C or C++ build. The default truncation strategy is `LongestFirst`, as Python's `truncation=True`. | `tokenizers/Cargo.toml`, `src/utils/mod.rs`, `src/utils/truncation.rs` at v0.23.2; docs.rs `tokenizers` 0.23.2 feature list; the model's `tokenizer.json` at the pinned revision (head of the file read, nothing stored) |
| V9 | cargo-deny against `deny.toml` as it stands | **Licences, sources, wildcard ban: pass. Advisories: one blocker.** See "cargo-deny" below. | `deny.toml`; `ci.yml` (cargo-deny 0.20.2, `--workspace --all-features`); crates.io metadata; `https://api.osv.dev/v1/querybatch`; cargo-deny 0.20.2 `src/advisories/cfg.rs` |
| V10 | What the two rerank `DegradeCode` variants mean today | `RerankProviderTimeout`: "Rerank provider call timed out; fell back to unranked/heuristic order" (rustdoc, `telemetry/degrade.rs`); §53.4 registers its injection as a read timeout injected into the rerank provider with the fallback ranking still returned; §23.3 reads it as 12 of 25 candidates really reranked and the rest in fallback order. `RerankModelMismatch`: "Rerank model actually used differs from the one requested" (the same rustdoc). Both are `FailOpen` in the direction table and dormant. Only the word "provider" does not fit a local worker (D-D). | Baseline §53.2, §53.4, §23.3; `crates/telemetry/src/degrade.rs`; `crates/testkit/tests/fault/dormant.toml` |

### cargo-deny

Method: the dependency closure was resolved from crates.io metadata for `ort` 2.0.0-rc.15 (`default-features = false`,
features `std`, `load-dynamic`, `tracing`, `api-31`) and `tokenizers` 0.23.2 (`default-features = false`, feature
`fancy-regex`), taking the newest non-yanked version that satisfies each requirement, all target platforms (the repo's
`[graph]` sets no targets). This is an analysis from metadata, **not a cargo-deny run**; the verdict is T-RET-7c's CI run.

- 83 crates in the closure (the two crates included); 32 of the names are new to `Cargo.lock`. None is yanked.
- **Licences** (`[licenses] allow`): every one of the 83 satisfies the allow-list through an allowed alternative or
  exactly (48 `MIT OR Apache-2.0`, plus `MIT`, `Apache-2.0`, `ISC` for `libloading`, `Zlib`/`BSD-2-Clause` alternatives,
  and `(MIT OR Apache-2.0) AND Unicode-3.0` for `unicode-ident`). The `ort` closure adds only `ort`, `ort-sys`,
  `libloading` and crates the lock already has.
- **Sources**: crates.io only. **Wildcards**: none, if the manifests give versions. **Duplicate versions** are `warn`
  only (`multiple-versions = "warn"`): for example `base64` 0.13, `nom` 7 and `fancy-regex` 0.17 would sit beside the
  locked newer ones.
- **No C or C++ build, no network at build time**: `cc`, `onig_sys`, `bindgen`, `openssl-sys` and `ureq` are not in the
  closure. The `ort` default features would bring `ureq` and a TLS stack and fetch the library during `cargo build`.
- **Advisories: `paste` 1.0.15 is a normal dependency of `tokenizers` 0.23.2** (and 0.23.1) and carries RUSTSEC-2024-0436
  ("no longer maintained", no patched version). OSV reports no other advisory for the 83 crates. cargo-deny 0.20.2 defaults
  `unmaintained` to `all` (`src/advisories/cfg.rs`), `deny.toml` does not set it, so **the check would fail as it
  stands.** What would change, not changed here: an entry in `[advisories].ignore` for that id with a reason, an expiry
  date and a removal card, which is the form `deny.toml`'s own comment asks for, in T-RET-7c's PR. Not recommended:
  `unmaintained = "workspace"` (it relaxes §78.5 for every crate). `tokenizers` 1.0.0-rc.3 has no `paste` but is a
  pre-release in a new crate family.

### Pins read (starting values; T-RET-7b and T-RET-7c recompute them from the files)

The model revision `1427fd652930e4ba29e8149678df786c240d8825` of `cross-encoder/mmarco-mMiniLMv2-L12-H384-v1` was also
the repository head on 2026-10-22, and its card metadata names Apache-2.0.

| Object | Size in bytes | sha256 |
|---|---|---|
| `tokenizer.json` at that revision | 17,082,660 | `62c24cdc13d4c9952d63718d6c9fa4c287974249e16b7ade6d5a85e7bbb75626` |
| `onnxruntime-linux-aarch64-1.30.0.tgz` (official release asset) | 10,269,495 | `e16a27a8ed330bbc698df7330b0cf56e722f354e3bcc92118682c74ef3c3e3da` |

The model is an XLM-RoBERTa sequence classifier with one output and an identity activation (`config.json`,
`sbert_ce_default_activation_function`), so the score is the raw logit; its tokenizer limit is 512 tokens
(`tokenizer_config.json`).

### UNKNOWN, with the fallback each carries

| # | Not known today | Fallback | Resolved by |
|---|---|---|---|
| U1 | Whether the int8 graph built by E-RET-5a's recipe loads and scores on `ort` rc.15 with the ONNX Runtime 1.30.0 tarball, and matches the Python scores (V5 shows operator support for two integer ops only) | T-RET-7c stops and reports; the same pin's fp32 export is the alternative, and the owner decides. fp32 was measured for gte only (K 25 L 256: 137 against int8's 141, 8.20 s against 2.08 s p50 on N2, about 4× slower); mmarco fp32 accuracy and latency are unmeasured. At about 4× the N1 int8 p50 (1.2 s) it would sit near 4.7 s, above `rerank_timeout_ms` 4000, so the fp32 fallback needs `rerank_depth` 10 or a re-measure before `rerank_enabled` | T-RET-7c, G-RET-11 |
| U2 | Latency of the Rust path on N1: all N1 numbers came through Python (`onnxruntime` 1.30.0 wheel, `tokenizers` 0.22.2) | Re-run the bundle's method against the shipped library before `rerank_enabled` is set; if p50 or p95 moves materially, `rerank_depth` 10 is a registry change (D-E) | T-RET-7c |
| U3 | Whether the tarball's `libonnxruntime.so` resolves all its shared-library needs on the runtime base `gcr.io/distroless/cc-debian13` (distroless's `cc/config.bzl` on `main` lists `libstdc++6`, `libgcc-s1`, `libgomp1`; the base digest the repo pins, 2026-10-07, was not inspected) | Copy the missing libraries from the Debian 13 builder into the image; or ship pyke's build with `libc++` (rejected on supply chain, D-B) | T-RET-7c, G-RET-11 run inside the image |
| U4 | Resident memory of the loaded session in `retrieval-rpc` | Measure on the same-spec runner and set the compose memory limit (the §67.2 A5 rule) | T-RET-7c |
| U5 | The tolerance of G-RET-11 | Measure the int8 run-to-run difference on the public fixtures and state the number with the gate; none is guessed here | T-RET-7b, T-RET-7c |
| U6 | Whether the rerank RPC passes the closed `IntraCellResource` registry through the existing `RETRIEVAL_EMBEDDING_RPC` entry or needs its own (the registry has three entries today) | A second entry; the embedding RPC's wire does not change either way | T-RET-7c contract review |
| U7 | Whether the gateway's end-to-end recall deadline leaves room for `rerank_timeout_ms` after the other stages (the deadline is not read here) | Lower `rerank_timeout_ms` (registry only) | T-RET-7d. **Settled (T-RET-7d-2), by reasoning from the shipped values, not a measurement:** the handler deadline is `HUMAUX_GATEWAY_HANDLER_TIMEOUT_SECONDS`, 20 s in `values/gateway.env`, against `rerank_timeout_ms` 4000. The stages before the rerank are bounded one by one (the embedding RPC by the handler deadline it is handed, Qdrant by the transport timeout with the sparse leg cut at 1000 ms, PostgreSQL by the 10 s statement timeout), so their worst-case sum can exceed 16 s and room is not guaranteed in the worst case; in the measured case it is, a few milliseconds per stage on the CI fixture (ADR-0083 U7). So: bootstrap refuses a profile whose `rerank_enabled` is true and whose `rerank_timeout_ms` is not below the handler timeout (`check_rerank_timeout`), and the wait is capped at run time by the handler budget left (`recall::rerank_wait`), so a late worker cannot outlive the handler. The registered 4000 ms stands; lowering it stays a registry-only change. Not measured here: the N1 end-to-end recall with the lane on (U2's N1 re-run is the lead's) |

## Decisions

### D-A Model and artifact

- **Model**: `cross-encoder/mmarco-mMiniLMv2-L12-H384-v1` at revision `1427fd652930e4ba29e8149678df786c240d8825`
  (Apache-2.0), exported to ONNX and quantised to **int8 with E-RET-5a's recipe**: the `optimum` export, then
  `AutoQuantizationConfig.arm64(is_static=False, per_channel=False)`. The score is the model's single logit; there is no
  sigmoid and no rescaling.
- **The artifact is built in CI from that pin** and published as a release asset with its sha256 (T-RET-7b). Deployment
  fetches it by sha256, and the worker refuses to start on a mismatch (G-RET-14). The tokenizer is the revision's
  `tokenizer.json`, published and hash-checked the same way.
- **Model identity** = `(repo, revision, recipe version, onnx sha256, tokenizer sha256)`. Per the Rerank Provider
  Failover rule (§19), any change to it is a new `calibration_profile`. It is also the `reranker fingerprint` that §51
  names for a rerank score cache, should one ever exist (ADR-0081 D-F).

### D-B Where it runs

- **Process.** The `retrieval-worker` hosts a `rerank` RPC on its existing serve socket, the pattern of query embedding
  (ADR-0012: the unix-domain socket, kernel peer credentials, the gateway's uid only). In the production compose that is
  the `retrieval-rpc` service (`--serve-rpc`). `retrieval-serve` (`--serve`, the same binary, no socket) must not load the
  model.
- **Runtime.** Rust ONNX Runtime bindings and the HF tokenizer crate, in the retrieval-worker only:
  - `ort` `=2.0.0-rc.15` with `default-features = false` and `load-dynamic` (V1, V4), plus the `api-30` feature (the
    library below is 1.30.0). Not `download-binaries`.
  - `tokenizers` 0.23.2 with `default-features = false, features = ["fancy-regex"]` (V8).
  - Neither crate enters `domain`, `application`, the gateway or any crate the gateway links, so the gateway binary
    carries no ONNX Runtime and no tokenizer. T-RET-7c declares both in the manifest with the `why` / `used-by` comments
    that dep-map reads.
- **Native library: a pinned, shipped one, not a build-time download.** The image carries Microsoft's official
  `onnxruntime-linux-aarch64-1.30.0.tgz` (V6) with its sha256 pinned in the image build, as the image already does for
  gitleaks (`deploy/images/humaux/Dockerfile`, `HUMAUX_RETRIEVAL_WORKER_GITLEAKS_*`). 1.30.0 is the version every
  measured number ran on; `ort` rc.15's own pairing is 1.31.0, which the docs allow either way (V4). Moving to 1.31.0
  is a pin bump that re-runs G-RET-11 and the N1 bench. Reasons against the download: it is a network fetch inside
  `cargo build` from a CDN whose backend one maintainer controls (`prebuilt-binaries.mdx`), a Clang build that needs
  `libc++` (the distroless `cc` package list has `libstdc++6` and no `libc++`; U3), and a TLS stack in the dependency
  graph. The feasibility questions the documents leave open are U1 and U3; neither makes the shipped library
  infeasible.
- **Threads.** `intra_op` threads are configurable, default 4 (`rerank_threads`); `inter_op` is 1, as measured.
- **Shared fate.** The model runs inside `retrieval-rpc`, which also serves query embedding (the dense leg). An
  out-of-memory kill or a fault in the release-candidate `ort` path takes query embedding down with it. Mitigation: the
  compose restart policy, the U4 memory limit, and `rerank_enabled = false` as the operator's switch to unload the model.
- **`deny.toml` exception for `paste`** (RUSTSEC-2024-0436, unmaintained, no patched version): accepted in T-RET-7c's PR
  as an `[advisories].ignore` entry with this reason (a build-time proc-macro dependency of `tokenizers` 0.23.x; the
  alternative is a pre-release crate family), an expiry of 2027-04-30 and the removal card "move to a `tokenizers`
  release without `paste`". `unmaintained = "workspace"` stays rejected (it relaxes §78.5 for every crate).
- **CPU isolation** (a deployment note, not code here): the `retrieval-rpc` service's compose CPU **weight** sits below
  PostgreSQL and Qdrant. That is the condition the N1 numbers were measured under (`--cpu-shares 512`); the compose
  files use `cpus:` caps today, which are a different mechanism.
- **Not an egress.** The lane runs inside the Cell on plain hydrated text. There is no Processor, no `EgressPermit` and no
  disclosure row; it must not pass through `seal_query()` or `seal_card()` (the two `egress_chars_total` increment points,
  §41.4 and §80.2 D5). It is not a `Reranker` provider route: §7.2's cloud route and its `Sealed*` input types are
  untouched. Request and reply bodies are never logged; a log line carries counts and timings.
- **Policy.** Scoring text with a model is in-Cell text processing, as the sparse leg is. Where
  `in_cell_text_processing_allowed(tenant)` (the one decision ADR-0083 U4 names; true for every tenant today) is false,
  the rerank branch is not selected (D-D).
- **Rejected.**
  - In the gateway process: the HTTP edge stays light and latency-isolated.
  - A Python sidecar: a second runtime in the image and on the supply chain.
  - Pure-Rust `candle`: its speed parity with the measured ORT int8 path is unverified.
  - `ort`'s `download-binaries`: see above.

### D-C Pipeline

1. The RRF fused list (ADR-0083 D-C), cut to `cand_k`. While `rerank_enabled` is true, `cand_k` must be at least
   `rerank_depth` and the registry load refuses a profile that breaks that; while it is false the depth never acts, so
   only `RERANK_FLOOR` applies (#166).
2. The **unchanged** PostgreSQL hydrate gate.
3. The rerank inputs for the first `rerank_depth` **visible** Memories: title + `"\n"` + best chunk. The best chunk is
   the Memory's chunk with the best leg rank, dense first, then sparse (the rule the experiments used). The legs ask Qdrant
   for groups of size 1 (ADR-0083 D-C), so this is the chunk the dense leg returned for that Memory, or, for a Memory only
   the sparse leg found, the chunk the sparse leg returned. The pair (query, document) is cut to `rerank_max_len` tokens by
   the tokenizer's own truncation (longest-first, special tokens counted), never by characters.
4. Score, in batches of 8 with dynamic padding on `rerank_threads` threads, the shape the N1 numbers were measured with.
   One call returns every score or none: a partial reply is a failure (D-D).
5. Order by score, ties by fused rank. Any visible candidate beyond `rerank_depth` keeps its fused order **after** the
   scored ones; with the default registry values there is none (`cand_k` is 25 at `top_k` 5). Rerank never adds, drops
   or duplicates a candidate (G-RET-15).
6. Then the existing steps: `top_k`, the mood rerank, `limit`.

Only authorized, hydrated text is ever scored (G-RET-13). In the §23.3 envelope `reranked_count` is the number of
Memories actually scored (0 on any degradation below) and `provenance.rerank_model_id` renders the D-A identity as one
string built by one constructor in T-RET-7d, which differs whenever any part of the identity differs.

### D-D Degradation

| Situation | Behaviour | `reranked_count` | `provenance.rerank_model_id` (§23.1③) |
|---|---|---|---|
| `rerank_enabled` false, or `in_cell_text_processing_allowed` false | Branch not selected: fused order, no degradation (a policy skip, like the sparse leg's `SKIPPED_BY_POLICY`) | 0 | `not_applicable` |
| Scores for every input arrive within `rerank_timeout_ms` and the worker's identity equals the pin | Rerank order (D-C 5) | the number scored | `used` |
| Timeout or any failure (transport error, non-2xx, malformed reply, a reply whose count or indices differ from the request, a session error) | Fused order, `DegradeCode::RerankProviderTimeout` | 0 | `cannot_establish` |
| The identity the worker reports differs from the pin | Scores **discarded**, fused order, `DegradeCode::RerankModelMismatch` | 0 | `cannot_establish` |

- Both codes are emitted only through `abstain()` (§53.1), so each is logged, counted in `degrade_total` and listed in
  `completeness.degradations`; the result is still returned, so by §52.3 Q1 they are `DegradeCode`s and no `ErrorCode` is
  added. Never silent, and never a switch to another model or to a cloud route.
- **Meaning, §53.** This ADR adds no variant (the set is as §53.2 lists it). `RerankProviderTimeout` means: the rerank
  executor, a cloud provider route or this local worker, returned no scores within the timeout or at all, and the result
  is in fallback order. "Provider" in §53.4 and in the rustdoc reads that way; a failure that is not a timeout shares the
  variant. `RerankModelMismatch` means the model that answered is not the model pinned. Baseline §53.4 is amended to say
  so, and registers the second injection. The rustdoc wording is T-RET-7d's edit.
- §23.3's invariants hold: a rerank-class degradation needs `reranked_count < candidate_count` (0 against at least 1), and
  a full rerank carries none.
- The pin the gateway compares each reply's reported identity with is the model pin in deployment configuration (D-E);
  the worker's own start-up check (G-RET-14) uses the same pin.
- Enabling the lane makes a wrong artifact a start-up failure of `retrieval-rpc`, query embedding included. That is the
  price of refusing to start on a hash mismatch; `rerank_enabled` stays false until the artifact is deployed.

### D-E Configuration (§78.1)

Registry entries, beside `top_k` and the four of ADR-0083 D-D; none is ever caller input:

| Field | Default | Meaning | Checked when the registry loads |
|---|---|---|---|
| `rerank_enabled` | false | turns the lane on for the profile; flipped after the artifact is deployed and U2 is read | |
| `rerank_depth` | 25 | most Memories scored per recall | 1 up to the profile's `cand_k` while `rerank_enabled` is true; 1 or more when it is false (#166) |
| `rerank_max_len` | 256 | token cap of one (query, document) pair | 5 (the four special tokens of a pair and one content token; amended by T-RET-7c) up to the tokenizer's 512 |
| `rerank_timeout_ms` | 4000 | the gateway's wait for the RPC; chosen because p95 under contention on N1 reached 3.9 s | above 0 |
| `rerank_threads` | 4 | intra-op threads of the worker's session | at least 1 |

All five enter `request_profile_fingerprint` (§23.3), so a change moves `profile_fingerprint` and G23-4 refuses to pool
runs across values. `RetrievalRequest` and `build_request` take no parameter for any of them (§55.1); T-RET-7d adds the
five names to the G55-6 ① forbidden-name set, red-recorded by that card. No literal of them appears outside the
registry. Two values act inside the worker: `rerank_threads` when it builds the session and `rerank_max_len` on each call.
How each reaches the worker (its own registry read, or the call) is a contract question for T-RET-7c and T-RET-7d; the
registry stays the only source. **Resolved by T-RET-7c:** `rerank_enabled` and `rerank_threads` reach the worker through its
own registry read at `--serve-rpc` boot: `rerank::rerank_profile` takes the two optional environment keys
`HUMAUX_RETRIEVAL_WORKER_RETRIEVAL_PROFILE_RERANK_ENABLED` and `..._RERANK_THREADS` (the gateway's rule, a registry name
upper-cased with the worker's prefix), builds the raw map and calls the one `resolve_registered_retrieval_profile`, so the
defaults and the bounds are the registry's and appear nowhere else. `rerank_max_len` rides on each call (`max_len`, 5 to 512:
the registry's `RERANK_MAX_LEN_MIN`, one content token above the four special tokens of a pair, and the tokenizer's 512); `rerank_depth` and
`rerank_timeout_ms` act in the gateway only (T-RET-7d). The two environment keys are optional in code and left empty in
`deploy/env/values/retrieval-worker.env` (`KEY=`); empty means unset, so the registry defaults (`false` and `4`) apply
and the values file carries no copy of them (§78.1, #185). An operator who flips the lane sets the same value on the
gateway and on the worker.

**The model pin is not in the registry.** It lives in deployment configuration beside the embedding provider's
variables (`HUMAUX_RETRIEVAL_WORKER_EMBEDDING_*`): the D-A identity, the artifact location and the hashes. As with the
embedding model, the identity is reported per request in `provenance.rerank_model_id`; it is not folded into the profile
fingerprint.

### D-F Thresholds

No relevance cut-off now: the lane only reorders. Per-model thresholds, the owner's earlier preference, are deferred.
The Failover rule stands: a future threshold gate binds to `(provider, model, revision, calibration_profile)` and
stands down loudly until its calibration exists. **Upgrade signal:** a sealed-set calibration exists, and dropping
low-score candidates is shown to help.

### D-G Gates

All are three-state (`pass` / `fail` / `not_applicable`, §57.1) and **all are planned**. Each gate exists only after its
inject, red, fix, green record (§80.1) lands in the card that implements it, and that card adds the record to this ADR.
Module gate ids such as `G-RET-11` fall outside the §80.1 anchor grammar, like `G-RET-1` to `G-RET-10`. A gate that
runs before its object exists (for example without the pinned library in CI) reports `not_applicable` and names that
object.

| Gate | Owner | Criterion | Injected fault |
|---|---|---|---|
| G-RET-11 score parity | T-RET-7c (fixtures and reference scores from T-RET-7b) | On public fixtures, the Rust path (tokenizer, model, int8) matches the Python reference scores within the stated tolerance (U5), including a pair longer than `rerank_max_len`, and the fixture orders agree | encode (document, query) instead of (query, document); skip the pair truncation |
| G-RET-12 timeout degradation | T-RET-7d | With the rerank call stalled past `rerank_timeout_ms` or failing, recall returns the fused order, `degradations` holds `RERANK_PROVIDER_TIMEOUT`, `degrade_total{code="RerankProviderTimeout"}` rises by 1 and `reranked_count` is below `candidate_count` | swallow the timeout and return without `abstain()` |
| G-RET-13 hydrate before rerank | T-RET-7d | A Memory that is tombstoned or not visible to the principal is never among the texts sent to the worker | rerank the fused list first and hydrate after |
| G-RET-14 artifact pin | T-RET-7c | A worker whose model or tokenizer file differs from the pinned sha256 refuses to start (non-zero exit, the mismatching object named) | skip the hash comparison |
| G-RET-15 order only | T-RET-7d | The output set of Memory ids equals the input set (visible, fused); ties follow fused rank; a reply with a different count or index set is a failure, not applied | drop a low-score candidate, or break ties by arrival order |

The `RerankModelMismatch` path has no gate of its own: it is covered by that variant's §53.4 fault test, which T-RET-7d
turns into a real-path test (below).

## Modules and table ownership

No PostgreSQL table changes. The artifact, the model and the library are files; PostgreSQL stays the source of truth.

| Module | Change | Card |
|---|---|---|
| CI workflow and a script for the artifact | build the int8 ONNX from the pin, hash it and the tokenizer, publish the asset; public fixtures with Python reference scores | T-RET-7b |
| `bins/retrieval-worker` (`rpc`, `rerank`, start-up check) | the `rerank` RPC (`POST /v1/rerank`), the session, the tokenizer, the hash check | T-RET-7c |
| `crates/infra-cell` (`IntraCellResource::RETRIEVAL_EMBEDDING_RPC`) | one rustdoc sentence (U6); no variant is added | T-RET-7c |
| worker manifest, `deny.toml`, `deploy/images/humaux/Dockerfile`, `deploy/env/values/retrieval-worker.env` | the two crates; the RUSTSEC-2024-0436 ignore (V9); the library pin; the model pin variables | T-RET-7c |
| `contracts::retrieval_config`, `retrieval::request` (the fingerprint) | the five registry entries and their bounds; all five in `request_profile_fingerprint` | T-RET-7c |
| `gateway::recall`, `retrieval::request` | the client call and D-C steps 3 to 6 | T-RET-7d |
| `retrieval::rerank` (a placeholder today) | the pure ordering step (D-C 5), so G-RET-15 needs no model | T-RET-7d |
| `telemetry::degrade`, `testkit/fault`, `dormant.toml` | the rustdoc wording; both rerank fault tests become real-path (they drive the production function, not `abstain()`); the two M11 dormant rows are deleted | T-RET-7d |
| `retrieval::envelope` | `is_valid` split into its two conjuncts; `outcome_block_under` refuses a structural breach only (D-D serve rule) | T-RET-7d-1 |
| `adapters::private_projection_registry`, `adapters::retrieve`, `projection::note_chunks` | `slot` on a resolved point, `point_slots` and `gated_texts` on the hydrate result, `CardSlot` and `rerank_document` (D-C 3 data path) | T-RET-7d-1 |

## Cards

| Card | Scope | Gates |
|---|---|---|
| T-RET-7a | This ADR; Baseline §4.2, §7.2, §19 Rerank Provider Failover, §23.3, §50, §53.4, §67.2 and the opening list; the rerank lines of ADR-0083 and ADR-0081 (docs only) | none |
| T-RET-7b | CI artifact pipeline (D-A) and the public parity fixtures (the public texts `PUB` in `local_rerank.py` at aae2ae4 are a seed, plus a pair longer than `rerank_max_len`) | none of its own (feeds G-RET-11) |
| T-RET-7c | The retrieval-worker rerank RPC with `ort` and `tokenizers` (D-B), **the five registry entries and the fingerprint (D-E, moved here from T-RET-7d)**, the image pin, the `deny.toml` entry; settles U1 to U6 | G-RET-11, G-RET-14 |
| T-RET-7d | Gateway wiring (D-C to D-E: the client, D-C steps 1 to 3, 5 and 6, the G55-6 forbidden-name set, the provenance constructor); lands after T-RET-6c-2; settles U7. **Split (2026-10-23): T-RET-7d-1 is the D-D serve rule and the D-C 3 data path (amendments above, no gate of its own); T-RET-7d-2 is the rest of this row.** Includes a named test that a tenant whose `in_cell_text_processing_allowed` is false gets no rerank call and fused order (red-recorded with the card) | G-RET-12, G-RET-13, G-RET-15 |

## T-RET-7c record (2026-10-22)

Everything below was measured or recorded by CI (nothing ran locally). Pins used: ONNX Runtime
`onnxruntime-linux-aarch64-1.30.0.tgz` sha256 `e16a27a8ed330bbc698df7330b0cf56e722f354e3bcc92118682c74ef3c3e3da`; release
`rerank-mmarco-int8-v1` tarball sha256 `cd90976aa97eee7a29221a1bd136e3b44545e1df1dec2008b613b67711b82c2f`, holding
`model_quantized.onnx` (`b924df3444fb4fe511152c89ec312fa73b44b901c115456405da54503b4e7edf`) and `tokenizer.json`
(`62c24cdc13d4c9952d63718d6c9fa4c287974249e16b7ade6d5a85e7bbb75626`). Runtime base for the gate: `gcr.io/distroless/cc-debian13`
at the Dockerfile's digest `e792ab3d…`. The route is `POST /v1/rerank` on the serve-rpc router.

| # | Result | Evidence |
|---|---|---|
| U1 | **Yes, the int8 graph loads and matches.** `ort` 2.0.0-rc.15 with the 1.30.0 library loaded the CI-built graph; the Rust tokenizer reproduced `input_ids` and `attention_mask` of all 54 pairs exactly (6 cut at `max_len` 256, including the 150-token-query pair `longq-0-0`); scores against `score_int8_batch` (each group one batch): max abs difference **1.78e-15** over 54 pairs | run 39785216794, job `rerank-parity`, line `G-RET-11 U1` |
| U2 (N2 runner only) | depth 25, `max_len` 256, batches of 8, 4 threads, 20 timed calls after 2 warm-ups, 16 of 25 pairs at the cap, mean pair 218.1 tokens (E-RET-5g: 61.5% at the cap, mean 217.7): **p50 0.690 s, p95 0.709 s**, against Python's N2 p50 0.67 s (+3%). The N1 re-run is the lead's, with the owner's approval | run 39785216794, test `rerank_latency` |
| U3 | **Resolved: the library resolves all its needs on the pinned distroless `cc` base.** The parity and pin tests ran inside that image with the `.so` mounted; nothing was copied from the builder | run 39785216794 |
| U4 | `VmRSS` of the test process: **452,512 kB after the load, 593,100 kB after 22 depth-25 calls** (N2 runner). The worker process adds its own baseline; no compose memory limit is changed here because `rerank_enabled` ships false | run 39785216794 |
| U5 | tolerance stays `tolerance.abs` **1e-4**; the run-to-run spread over 3 parity runs of the 54 pairs was **0** (bit-identical), as in the fixture header | run 39785216794 |
| U6 | **Resolved: the existing `IntraCellResource::RETRIEVAL_EMBEDDING_RPC` entry serves rerank.** The registry keys an endpoint (the socket and its peer gate); rerank is served on the same socket behind the same gate. One rustdoc sentence changed, no variant | `crates/infra-cell/src/resource.rs` |

Other facts: cargo-deny passes with the `paste` ignore (RUSTSEC-2024-0436, expiry 2027-04-30 and the removal card in the
reason string, because cargo-deny 0.20.2 has no expiry field); the registry gate bounds of D-E hold at load; no golden
fingerprint changed; the first PR run (39780781716) was red only on `dep-map --check` (a `Called-by` line of `contracts`)
and the gitleaks scan (the public tokenizer hash assigned to a variable whose name contains "token", now an exact-value
allowlist entry), both fixed in the second run.

### Gate records (§80.1: inject, red, fix, green)

| Gate | Injected fault | Red | Green |
|---|---|---|---|
| G-RET-11 score parity | encode (document, query) instead of (query, document) (branch `red/t-ret-7c-a`, `b181f16`) | run 39789293901, job `rerank-parity`: `rust_path_matches_the_python_reference_scores` fails at `seed-0-0: input_ids` | run 39785216794 (head `e1f220d`) |
| G-RET-11 score parity | truncation by `only_second` instead of `longest_first` (branch `red/t-ret-7c-b`, `96f1e46`) | run 39792222497: fails at **`longq-0-0: input_ids`**, the first pair of the fixture whose ids differ; every earlier over-length pair (short queries) is identical under both strategies, so the long-query group #159 added is what makes this injection red | run 39785216794 |
| G-RET-14 artifact pin | skip the hash comparison in `verify_pinned` (same branch `red/t-ret-7c-a`) | run 39789293901: `a_file_that_differs_from_the_pin_refuses_boot_naming_the_object` fails; the control `matching_hashes_pass_the_pin_and_stop_later` stays green | run 39785216794 |
| Peer layer on `/v1/rerank` (review P1-1, `rpc_readyz`) | merge `rerank_router` after the `.layer(require_gateway_uid)` in `router_with_rerank` (branch `red/t-ret-7c-r3`, `065d8d2`) | targeted run 39817917365: `a wrong peer uid is refused on /v1/rerank` fails with 200 | run 39807211139 (`rpc_readyz` and `rerank-parity` green with the new assertions) and the final PR run |
| Truncation memo (review P1-2, `rerank_parity`) | the memo guard in `Engine::set_max_len` returns once any value is set (branch `red/t-ret-7c-r4`) | ci.yml run 39819641442, job `rerank-parity` (run cancelled after that job; targeted.yml cannot supply the artifacts): `longq-0-0 cut at 128` fails | run 39807211139, job `rerank-parity` |

Wire notes: `rerank_max_len` and the call's `max_len` are bounded 5 to 512 by one constant (`RERANK_MAX_LEN_MIN`, a pair
carries four special tokens and the tokenizer crate subtracts them from `max_len`, so 1 to 4 would underflow inside it): an
operator value of 4 fails at registry load, a call with 4 is `invalid_request`. An undecodable
body or an unknown field is refused by the extractor (HTTP 4xx) before any outcome exists; every semantic error is an
`invalid_request` outcome with the call id.

## T-RET-7d-1 record (2026-10-23)

Recorded by CI (nothing ran locally). The code and the tests below landed in PR #204: r1 to r5 on head 2f9c1ec (green run
39859048051), r6 with the one-snapshot text read after the review of 2731a9c. Each red is one mutation on a throwaway
`red/t-ret-7d-1-rN` branch run through `targeted.yml` on the test named, failing on that test's own assertion; the branches
are deleted. T-RET-7d-1 adds no `G-RET-` id: these are the tests of the contracts amended above (§80.1 inject, red, fix,
green).

| Contract | Test | Injected fault | Red run |
|---|---|---|---|
| D-D serve rule | `retrieval::envelope::tests::a_cannot_establish_component_is_served_with_its_diagnostic_and_is_never_valid` | r1: `outcome_block_under` refuses every `!is_valid` provenance (the old gate): fails at "a structurally sound block is served: Internal" | 39861103125 |
| D-C 3, first point per Memory | `adapters::retrieve::stand_in_tests::the_first_candidate_point_of_a_memory_fixes_its_slot` | r2: a later candidate point overwrites the Memory's slot (Memory 10 reads `Chunk { 0 }`, expected `Chunk { 2 }`) | 39861417814 |
| D-C 3, slot from the registry row | `private_projection_registry::repeated_chunks_share_vector_not_point` | r3: the resolver reports ordinal 0 whatever the row says (both points read `Chunk { 0 }`) | 39861763939 |
| D-C 3, the embedded card text | `projection::note_chunks::tests::rerank_document_is_the_card_text_of_the_slot` | r4: the document is always built from slot 0 | 39862116696 |
| D-C 3, dense point, else sparse | `gateway::recall::tests::the_fused_candidate_is_the_dense_hit_else_the_sparse_hit` | r5: a later leg's point replaces the dense leg's for a Memory both legs found | 39862460586 |
| G-RET-13, the text read is gated | `private_projection_registry::a_tombstoned_memory_never_has_its_text_read_for_rerank` | r6: read `private.memory_text_v` for every resolved candidate instead of the gated items (control and `Skip` pass; the tombstoned Memory's text is read: `([], [memory])`) | 39866008465 |

The structural-breach test (`a_structural_breach_is_still_refused_as_internal`) and the G23-6 tests are unchanged by the
split of `is_valid` and stay green. The green of r6 and of the one-snapshot text read: PR CI run 39866395427 (head
5b33857).

## Alternatives rejected

- **No rerank**: the owner's earlier decision of the same day (ADR-0083), replaced by this one.
- **Cloud rerank** (E-RET-5d, E-RET-5f) and **Jev** (E-RET-5c): measured and not chosen; the numbers are in ADR-0083.
- **gte-multilingual-reranker-base int8, K 25, L 256**: 141 against 130, at 2.08 s p50 on the N2 runner against 0.67 s.
- **bge-reranker-base int8**: not significant against RRF.
- **fp32 precision**: measured for gte only, not significantly different from int8 (137 against 141) at about 4× the
  time, so the cheaper precision stays.
- **K 10 as the default**: 115 against 130 for p50 about 0.5 s on N1. Kept as the registry fallback, not the default.
- **L 512**: 128 against 130 in the same run, at about twice the padded tokens per pair (500 against 254 on average).
- **The upstream repository's own `onnx/model_qint8_arm64.onnx`**: it exists at the pinned revision, but it is not the
  artifact E-RET-5g measured and our CI did not build it; the pin must trace to a build we can re-run.
- **In the gateway, a Python sidecar, `candle`, `download-binaries`**: see D-B.

## Deferred items

| Item | Upgrade signal |
|---|---|
| Sealed-set confirmation of RRF against rerank | The sealed set of ADR-0081 exists; re-measure both |
| Per-model thresholds, dropping low-score candidates | D-F |
| A rerank pair-score cache (ADR-0081 D-F) | A measured repeat rate and a new owner decision; the key term is the D-A identity |
| `rerank_depth` 10 | N1 p95 under contention proves unacceptable (a registry change) |
| ONNX Runtime 1.31.0, or an `ort` stable release | `ort` 2.0.0 is published, or a security note names a fix; re-run G-RET-11 and the N1 bench |
| `tokenizers` 1.x and dropping the `paste` ignore | A stable 1.x without `paste` passes G-RET-11 |

## References

- Experiment records: E-RET-5g, CI run 39724084843 (head aae2ae4, branch `exp/e-ret-pb-local-rerank`); the grid source is
  `experiments/eret_pb/local_rerank.py` and `rerank.py` on that branch; the N1 bench is the public bundle
  `n1-bench-bundle-v2`.
- `ort` 2.0.0-rc.15 at tag `v2.0.0-rc.15` (commit 5c564c58): `docs/content/setup/linking.mdx`, `cargo-features.mdx`,
  `multiversion.mdx`, `docs/content/misc/version-mapping.mdx`, `prebuilt-binaries.mdx`, `ort-sys/build/download/dist.tsv`;
  docs.rs `ort` 2.0.0-rc.15 (`init_from`, `SessionBuilder::with_intra_threads`, `commit_from_file`).
- `tokenizers` 0.23.2 at tag `v0.23.2`: `tokenizers/Cargo.toml`, `src/utils/mod.rs`, `src/utils/truncation.rs`,
  `src/models/unigram/trainer.rs`; docs.rs `tokenizers` 0.23.2.
- ONNX Runtime 1.31.0: `docs/OperatorKernels.md` at tag `v1.31.0`; the quantisation guide on onnxruntime.ai; release assets
  of `v1.30.0` and `v1.31.0`.
- cargo-deny 0.20.2: `src/advisories/cfg.rs`; RustSec RUSTSEC-2024-0436 (`paste`); OSV `querybatch`, read 2026-10-22.
- Model: the Hugging Face repository `cross-encoder/mmarco-mMiniLMv2-L12-H384-v1` at the pinned revision (`config.json`,
  `tokenizer_config.json`, `tokenizer.json`, the file tree).
- Distroless `cc` image contents: `cc/config.bzl` on `main` of `GoogleContainerTools/distroless`, read 2026-10-22.
