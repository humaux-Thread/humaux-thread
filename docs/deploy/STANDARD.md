# Humaux Thread — local deployment standard

Status: contract C-M23-1 of module M23 (note :51). This document owns the profile numbers (note :245). No marketing
prose; the values below are the release contract.

## 1. Release form

The open-source release is a Compose archive plus this standard (note :145). The archive contains the compose file
(note :145), `release.lock`, `config.example`, env examples, a secrets README, backup/restore/upgrade documentation,
conformance and `LICENSE`/`NOTICE`/`SBOM` (note :147). It contains no Redis, MinIO, LLM server or billing component
(note :148).

Rejected for this standard: Helm first; static binary default (note :148).

## 2. Services in the compose file

The compose file carries gateway, retrieval-worker, private-worker (BYOK-only distill), optional consolidation,
maintenance-serve, `dr serve`, PostgreSQL and Qdrant (note :145-147). Observability is a profile; telemetry is off
(note :146-147).

There is no service for Redis, MinIO, an LLM server or billing (note :148).

## 3. Profiles

Profiles are measured before they are supported (note :149).

| profile | vCPU | RAM | disk | status | basis |
|---|---|---|---|---|---|
| small | 2 | 8 GiB | 20 GiB | supported after X-M23-3 and conformance | <!-- note :149 --> |
| recommended | 4 | 16 GiB | 40 GiB | supported after X-M23-3 and conformance | <!-- note :149 --> |

## 4. Architectures

OSS images are arm64 + amd64 (note :154). Production stays arm64 (note :155). The amd64 image adds the ORT x64
tarball pin, and int8 parity runs on both architectures (note :154-155). The recorded veto condition is arm64 only and
M23-16 dropped, nothing else changes (note :155).

## 5. Local embedding model

The local embedder is e5-small loaded through `ort` (note :151). The distribution ships its MIT licence and
attribution (note :151). Inputs use `query:`/`passage:` prefixes, mean pooling with L2 normalisation, 384 dimensions and at most 512 tokens, with its own fingerprint and generation. <!-- note :151-152 --> The artifact is built in
GitHub Actions and added by `ADD --checksum` (note :152). The rerank and ORT pins are recorded in `release.lock`, not
here (note :153).

## 6. Offline conformance

Conformance includes the knowledge export → restore → local re-embed leg (note :150). The local path has no egress and
zero telemetry (note :150).

## 7. BYOK boundary

A raw `remember.put` needs BYOK in the OSS deployment (note :224). Conformance exercises the note/put paths (note
:224-225).

## 8. Pins

`release.lock` is the only pin list: image digests, schema range, and model and ORT hashes (note :51). Profile values
are owned by this document (note :245); a value not stated here or pinned in `release.lock` is TBD (note :51).
