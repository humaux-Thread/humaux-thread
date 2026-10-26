# ADR-0118 — Secret scanning of extracted text before publish or send

- Status: Accepted (2026-10-26). Card M17-1 (docs only, wave D, module M17). ADR-M17-d (this ADR). Records module design
  note M17 v2 D9 (note :137) and the precision in the research findings (note :11-13). Content authority: the lead ruling that
  Gitleaks is an allowed pinned external (note :10) and the owner's 2026-10-23 ruling, owner (49166827). This ADR records
  them and re-decides none. No code, migration or gate lands with it.
- Relates to: Baseline §7.4, §28, §45.1, §52, §78.1, §80.1; ADR-0115 (publish transaction), ADR-0117 (self-check),
  ADR-0119 (sandbox runner, where the scanner runs).

## Context

- M17 needs a pinned Gitleaks binary for private text before it is published or
  sent to a model (note :137-138).
- The precision in the research findings matters to the design (note :11-13): Gitleaks `--max-archive-depth` defaults to 0
  and `--max-target-megabytes` skips silently, so archives are not scanned by handing the file over.
- The scanner is an external binary, so it needs a pinned hash and an allow-list entry beside PostgreSQL, Qdrant and ORT
  (note :137-138).

## Decisions

### D-A (D9) Pinned Gitleaks in the sandbox, with a server-owned config

The pinned Gitleaks binary (sha in `release.lock`, listed on the allowed-externals list beside PostgreSQL, Qdrant and ORT;
lead ruling) runs as `gitleaks stdin` inside the sandbox runner, with a server-owned config (note :137-139).

### D-B (D9) Scan points

Scanned: the full text stream per unit **before** blocking (a secret cannot straddle a block), filenames, metadata, the
text parts of outgoing payloads, model outputs, and embedding inputs (note :138-140).

### D-C (D9) A skip is `unknown`, never clean

`gitleaks:allow` and file-supplied ignores are ignored. We feed extracted member text ourselves, because archive depth
default 0 never opens archives. Any skip, size limit or timeout → `scan_state = unknown`, never clean (note :140-142).

A hit is redacted to `[REDACTED:<rule>]` before publish or send; counts are kept, values never. Pixels and audio stay
`uninspected_modalities` (D7) (note :142-143).

## Consequences

- Positive: text is scanned as one stream per unit, so a secret split across two blocks is still found (note :139); a scan
  that did not run cannot be mistaken for a passing one.
- Cost: the scanner is a runtime external, so it needs the pinned hash, the allow-list entry and the sandbox; a skip, a
  size limit or a timeout records `scan_state = unknown`, never clean (note :141-142), and with no pinned aarch64 build
  publish needs the user's acceptance (U6, note :308).
- Asks M16: consume C-M17-3 (frames, limits, POISON, start-up probe) as the sandbox runner contract (note :185-186).
- Neutral: no code, migration, config key or wire format changes with this card.

## Gates

Planned, implementer-owned, tri-state (§57.1); none exists in this card (note :222, :249).

| gate | owner card | test file | injected fault | expected red |
|---|---|---|---|---|
| A-1 build boundary | M17-16 | `xtask architecture_check` (allowed externals) | add an unlisted binary/.py in a runtime image | unlisted external ships |
| A-2 impostor scanner | M17-16 | `bins/worker/tests/scan.rs` | swap gitleaks binary byte | scan runs with sha mismatch |
| A-9 secret across boundary | M17-16 | `scan.rs` | scan per block | key split over 2 blocks not found |
| A-10 scan bypass | M17-16 | `scan.rs` | honour `gitleaks:allow`; treat skip as clean | allowed/oversized secret reported clean |
| C-5 secret in output | M17-16 | `scan.rs` | skip output scan | model-echoed key published |

Each needs its inject → red → fix → green record (§80.1) in the implementing card. A-9 injects per-block scanning and
expects the straddling key to be missed (note :139, :266).

## Owner-gated (listed, not decided)

Red lines, owner only (note :310-313): real model spend in production (probes, extraction, legacy re-extraction on
users' keys; CI uses fakes and test keys); deleting legacy originals in the old MinIO; live keys of any provider or
store. Open owner questions: none (lead rulings applied; v1 Q1 closed by "no originals") (note :313).

## Open research

- **U6.** A pinned Gitleaks aarch64 build → if absent, the secret scan is `unknown` and publish needs the user's
  acceptance (note :308).

## Alternatives rejected

Honouring `gitleaks:allow` or file-supplied ignore files (note :140); treating a skip, a size limit or a timeout as clean
(note :141-142); handing archives to Gitleaks' own extractor instead of feeding extracted member text (archive depth 0;
note :141, :12-13); storing values instead of `[REDACTED:<rule>]` with counts (note :142-143); scanning per block instead
of per unit stream (gate A-9, note :266).

## References

- Module design note M17 v2 §4 (D9), §5 (sandbox runner contract), §8 (cards), §9 (gates), §11 (UNKNOWNs with
  fallbacks), §12 (owner red lines and the allowed-pinned-external ruling).
- Baseline §7.4, §28, §45.1, §52, §78.1, §80.1.
- ADR-0115 (publish), ADR-0117 (self-check), ADR-0119 (sandbox runner).
