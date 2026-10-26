# ADR-0122 — Open-source local deployment: one compose standard, measured profiles, offline conformance, and e5-small embedding via `ort`

- Status: Accepted (2026-10-23). Card M23-1 (docs only, wave F, module M23). Content authority: module design note M23
  v2, §3 (C-M23-1/C-M23-2/C-M23-3), §7 D12–D18, §9, §13 and the owner answers of 2026-10-23. This ADR records those
  decisions and re-decides none of them. No code, migration, gate or deployment lands with it.
- Amends: Baseline §7.2 (the standard deployment now includes a local embedding model beside the local rerank lane)
  and §67.2 (its component and memory-budget prose) (note :153).
- Relates to: Baseline §7.2, §67, §67.2, §44, §16.3, §17, §78.2; ADR-0084 (local rerank lane); ADR-0086 (collection
  spec per embedding generation); ADR-0121 (knowledge export, the export leg of conformance); module design note M10
  (C7); M24 (CI jobs).

## Context

- Open source today has no LICENSE/NOTICE, no offline profile, no conformance command and no R11 harness (note :43).
- The rerank lane is ADR-0084; the pending `ort` 2.0.0-rc.15 load-dynamic change carries ORT 1.30.0 and an int8
  rerank model added by `ADD --checksum`, and may not merge as is (U1) (note :41-42, :223). Local embedding does not
  exist: `adapters.rs::embedding_provider_for` is DashScope only (note :42).
- Still in force: OSS users deploy locally to a standard (`29f37ded` → charter `829c952f`); Linux arm64 containers +
  compose, launchd/systemd rejected (`2614a613`) (note :8-10). Q2 is a lead default of arm64 + amd64 OSS images that
  the owner could veto (note :10-11); the owner answered it on 2026-10-23 as arm64 + amd64 (note :253).

## Decisions

### D-A OSS is a Compose release archive plus one standard

`oss.yml` carries gateway, retrieval-worker, private-worker (BYOK-only distill), optional consolidation,
maintenance-serve, `dr serve`, pg and qdrant, with an observability profile and telemetry off (note :145-147). The
archive is the compose file, `release.lock`, `config.example`, env examples, a secrets README, backup/restore/upgrade
docs, conformance, and LICENSE/NOTICE/SBOM; there is no Redis, MinIO, LLM server or billing (note :147-148). Rejected:
Helm first; static binary default (note :148).

### D-B Profiles are measured, and only then supported

The small profile is 2 vCPU / 8 GiB / 20 GiB; the recommended profile is 4 / 16 / 40; the profiles are supported
after X-M23-3 and conformance (note :149). The profile numbers live in `docs/deploy/STANDARD.md` (C-M23-1), which
owns them (note :51, :245).

### D-C Offline conformance, no egress and zero telemetry

Conformance includes the knowledge export → restore → local re-embed leg, with no egress and zero telemetry
(note :150).

### D-D Local embedding: e5-small via `ort`

The local embedder is e5-small loaded through `ort` (note :151). It is MIT, so the distribution ships the licence and
attribution (note :151). Inputs use `query:`/`passage:` prefixes, mean pooling with L2 normalisation, 384 dimensions,
at most 512 tokens, with its own fingerprint and generation (note :151-152). The artifact is built in GitHub Actions
and added by `ADD --checksum` (note :152). The rerank and ORT pins are recorded in `release.lock` (note :153). This is
the amendment of §7.2/§67.2 named by the note (note :153).

### D-E arm64 and amd64 OSS images

D16 made arm64 + amd64 the Q2 lead default with an owner veto (note :154); the owner answered Q2 on 2026-10-23 as
both architectures (note :253). Production stays arm64; amd64 adds the ORT x64 tarball pin, and int8 parity
(G-M23-10) runs on both architectures (note :154-155). The recorded veto condition: arm64 only and M23-16 dropped,
nothing else changes (note :155).

### D-F R11 storage harness: `xtask storage-measure`

The harness reports B_all-in as PGDATA + Qdrant + the latest knowledge export (no WAL archive), at N = 0, 1k, 10k and
50k, with one lever per run (note :156-157). Its contract is C-M23-3, a JSON report (note :52).

### D-G OSS export tree without publishing

The OSS export tree is built and gated without publishing the repository (note :157); publishing stays an owner act
(note :241).

## Contracts

- **C-M23-1** `docs/deploy/STANDARD.md`: the local deployment standard (note :51).
- **C-M23-2** `release.lock`: image digests, schema range, model and ORT hashes (note :51).
- **C-M23-3** `xtask storage-measure` JSON (note :52).
- Consumed: M24 `experiment.yml` and image jobs (note :55).

## Consequences

- Positive: one compose archive plus one standard (note :145-148); profile numbers in one place (note :149, :245);
  conformance covers the export/restore/re-embed leg with no egress (note :150); OSS local re-embed is free CPU
  (note :105); int8 parity runs on both architectures (note :154-155); storage claims are measured (note :156-157).
- Cost: the profiles are supported only after X-M23-3 and conformance (note :149); amd64 adds the ORT x64 tarball
  pin and a parity run (note :154-155); the e5 licence and attribution ship with the release (note :151).
- Neutral for this card: no compose file, image, config key or gate is added; the gates below belong to later cards.

## Gates

Planned, implementer-owned and tri-state (§57.1); none exists here. DB/compose tests treat missing Docker in CI as
fail (ADR-0050) (note :165).

| gate | test file | inject | expected red |
|---|---|---|---|
| G-M23-10 e5 parity | `bins/retrieval-worker/tests/local_embed_parity.rs` (arm64 + amd64) | drop query prefix / normalisation | vectors off the pinned fixture (note :177) |
| G-M23-14 offline conformance | `bins/admin/tests/conformance_offline.rs` | DashScope call on local path; open egress | conformance red (B24 red 19) (note :181) |
| G-M23-15 artifact pins | `deploy-check --release` test | change one model/ORT byte or sha | release refused (note :182) |
| G-M23-16 no live values | deploy-env gate | `live` key in a values file | gate red (note :183) |
| G-M23-17 export tree | M24 job `oss-export` | cloud crate dep on a core path | exported-tree build red (note :184) |
| G-M23-18 R11 honesty | `xtask/tests/storage_measure.rs` | omit export dir / subtract empty baseline | report ≠ fixture totals (note :185) |

## Owner-gated (listed, not decided)

- **Q2** (defaulted): arm64 + amd64 OSS images; veto → arm64 only (drop M23-16) (note :235). Owner answer 2026-10-23:
  "OSS images are arm64 + amd64." (note :253).
- Red lines (owner only, not decided here): "Publishing the OSS repo." — "Also: live keys in any env."
  (note :241).

## Open research

- **U1** The `ort` load-dynamic change may not merge as is (note :223). Fallback: the local embedding card brings the
  ORT layer under the same pins (note :223).
- **U2** `remember.put` without BYOK in OSS (note :224). Fallback: STANDARD.md says raw `remember.put` needs BYOK;
  conformance uses note/put paths (note :224-225).
- Measurements that gate the cards, not open questions: X-M23-2 (e5-small int8 vs fp32 on arm64 and amd64: recall@10 /
  nDCG@10 zh/en/cross, beats BM25-only; p50/p95; RSS → M23-9; no official int8 loss number exists) (note :215-216);
  X-M23-3 (OSS profiles with the 10k fixture: RSS per service, idle and under conformance → M23-10) (note :217).

## Alternatives rejected

- Helm first; static binary default (note :148).

## References

Module design note M23 v2, §3, §6, §7 D12–D18, §9, §11, §12, §13 and the owner answers of 2026-10-23; module design
note M10 (C7); Baseline §7.2, §16.3, §17, §44, §67.2, §78.2; ADR-0084; ADR-0086; ADR-0121.
