# ADR-0120 — Every published block is embedded, and artifact search re-checks PostgreSQL

- Status: Accepted (2026-10-26). Card M17-1 (docs only, wave D, module M17). ADR-M17-f (this ADR). Records module design
  note M17 v2 D14 (note :163). Content authority: owner (0b2bd5aa) on embedding all content and owner (829c952f) on
  ≤ 10 KB all-in per memory (R11), both still binding (note :15-16, :163). This ADR records them and re-decides none. No code,
  migration or gate lands with it.
- Relates to: Baseline §8.3.1, §17, §22.1, §78.1, §80.1; ADR-0086 (collection spec per embedding generation), ADR-0115
  (blocks and the PUBLISH transaction), ADR-0117 (self-check); M10 (projection families), M11 (retrieval lanes), M23
  (storage measurement harness).

## Context

- Blocks become the only text (ADR-0115 D-C, note :77-78); the original is gone after the purge (note :65-66).
- `artifact.search` does not exist; recall marks artifact Evidence `artifact_unavailable` today (note :42-43).
- The owner ruled that all content is embedded, owner (0b2bd5aa), and that a memory stays ≤ 10 KB all-in, owner
  (829c952f) (R11); R11 is what X-M17-2 measures (note :15-16, :55, :166).

## Decisions

### D-A (D14) Every published block is embedded

Family `document_blocks_v1` (M10 generation, ids-only payload) plus the `artifact.search` lane (M11), with a PostgreSQL
re-check of the receipt, the extraction and the tombstone. Hydration is from `document_nodes.body` — no object read (note
:163-166).

### D-B (D14) R11 is measured on M23's harness

X-M17-2 measures ΔPG + indexes + Qdrant + backup + WAL + audit per new memory with M23's harness; 512-d f16 is evaluated
with M10 (1024-d f32 + 1.5 KB + backup is already ≈ 11.2 KB) (note :166-167).

## Consequences

- Positive: search runs on a family whose payload is ids only, so a tombstoned or foreign block cannot be answered from
  the vector store alone — the PG re-check decides; hydrate reads PostgreSQL, so nothing needs the temp prefix.
- Cost: every published block is a point, so block size and point count are a storage budget (note :165-167); the 512-d
  f16 variant waits for the M10 evaluation (note :166); the ≤ 10 KB all-in cap is the owner's target and X-M17-2 has not
  measured it (note :15-16, :298).
- Asks M10: the `document_blocks_v1` generation and the 512-d f16 evaluation (note :164, :166).
- Asks M11: the `artifact.search` lane with the PostgreSQL re-check (note :165).
- Asks M23: the harness that measures per-memory bytes (note :166).
- Neutral: no code, migration, config key or wire format changes with this card.

## Gates

Planned, implementer-owned, tri-state (§57.1); none exists in this card (note :249).

| gate | owner card | test file | injected fault | expected red |
|---|---|---|---|---|
| G-M17-11 search re-check | M17-13 | `crates/adapters/tests/artifact_search.rs` | skip PG re-check | tombstoned/other-user block returned |

C-12 (10 KB) belongs to ADR-0115's block cap and to cards M17-4a and M17-13 (note :224, :242, :288).

## Owner-gated (listed, not decided)

Red lines, owner only (note :310-313): real model spend in production; deleting legacy originals in the old MinIO; live
keys of any provider or store. The owner decision still binding here is BYOK for every non-embedding model call,
owner (530f7467) (note :16). Open owner questions: none (lead rulings applied; v1 Q1 closed by "no originals") (note :313).

## Open research

- **X-M17-2 / R11.** Bytes per memory including block points, and 1024-d f32 against 512-d f16, are unmeasured (note
  :298); the owner's ≤ 10 KB all-in per memory, owner (829c952f), is the target to measure against (note :15-16, :55).
  M17-13's dimensions wait for that measurement with M10 (note :298).

## Alternatives rejected

D14 states no rejected alternative (note :163-167).

## References

- Module design note M17 v2 §4 (D14), §5 (C-M17-4 and the M10/M11 guests), §8 (cards M17-13), §9 (gates), §10 (X-M17-2),
  §11 (UNKNOWNs with fallbacks), §12 (owner red lines).
- Baseline §8.3.1, §17, §22.1, §78.1, §80.1.
- ADR-0086 (collection spec per generation), ADR-0115 (blocks), ADR-0117 (self-check).
