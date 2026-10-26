# ADR-0117 — Extraction self-check before publish

- Status: Accepted (2026-10-26). Card M17-1 (docs only, wave D, module M17). ADR-M17-c (this ADR). Records module design
  note M17 v2 D8 (note :131) and the publish constraint D2 states for it (note :72-74). Content authority: the owner's
  2026-10-23 ruling, owner (49166827), and the lead rulings at note :9-11. This ADR records them and re-decides none. No
  code, migration or gate lands with it.
- Relates to: Baseline §8.4, §10.1, §28, §52, §57.1, §78.1, §80.1; ADR-0079 (receipt and coverage), ADR-0115 (the PUBLISH
  transaction and blocks), ADR-0116 (unit outcomes), ADR-0119 (sandbox), ADR-0120 (block embedding).

## Context

- There is no document publish path today (note :35-46). The note's receipt gains `unit_outcomes`, `scan_state` and
  `confidence_label` at PUBLISH (note :72-73).
- The quality question is asymmetric: the model's "done" is not evidence of coverage, and the independent local manifest
  is (note :131).
- Confidence has no calibration in v1; the note fixes the label set and starts at `unknown` (note :135-136).

## Decisions

### D-A (D8) The self-check reads the local manifest, never the model's "done"

The checks, per extraction (note :131-136):

- manifest coverage — every unit has an outcome;
- non-empty per unit — empty is not success;
- anomalies — U+FFFD, duplicates, text-layer against OCR diff, truncation by `finish_reason`;
- structure — table cell counts, formulas, footnotes, column order;
- time coverage — segment gaps and overlaps;
- response integrity — schema, unit ids, finish reason.

Blank units (no text, no image) are never sent (note :135). Words-per-page is a signal only (note :135).

Confidence label ∈ {unknown, model_self_reported, provider_score, empirically_calibrated}; v1 is `unknown` until
X-M17-1 calibrates it (note :135-136).

## Consequences

- Positive: a publish answers "every unit has an outcome and a non-empty result" from a local artefact, not from the
  model's own claim; an unreadable unit stays a visible gap instead of becoming text.
- Cost: the self-check needs an independent local manifest (note :131); the confidence label stays `unknown` in v1, so no
  caller may read it as calibrated (note :136).
- Neutral: no code, migration, config key or wire format changes with this card.

## Gates

Planned, implementer-owned, tri-state (§57.1); none exists in this card (note :222, :249).

| gate | owner card | test file | injected fault | expected red |
|---|---|---|---|---|
| B-3 missing unit | M17-22; M17-18 (pages); M17-20 (attachments) | `bins/worker/tests/publish.rs` | trust model "done" | 10-page manifest, 9 outputs, published COMPLETE |
| B-4 blank-page hallucination | M17-22 | `publish.rs` | send blank units | invented text published for a blank page |
| C-3 two accepted revisions | M17-22 | `publish.rs` | drop partial unique | two PUBLISHED extractions for one session |
| B-6 mojibake/order | M17-18 | `pdf.rs` tests | skip anomaly check | U+FFFD text layer published as LOCAL_TEXT complete |
| B-7 table/formula | M17-19 | `ooxml.rs` tests | flatten cells | merged-cell table loses cell count silently |
| B-8 audio coverage | M17-21 | `audio.rs` | drop one segment | time gap published as complete |

Each needs its inject → red → fix → green record (§80.1) in the implementing card. Publish-by-coverage, `accept_partial`
and the review window belong to card M17-22 (note :231).

## Owner-gated (listed, not decided)

Red lines, owner only (note :310-313): real model spend in production (probes, extraction, legacy re-extraction on
users' keys; CI uses fakes and test keys); deleting legacy originals in the old MinIO; live keys of any provider or
store. Open owner questions: none (lead rulings applied; v1 Q1 closed by "no originals") (note :313).

## Open research

- **U5.** Our model mix's quality on the X-M17-1 classes → confidence `unknown` until measured (note :307).
- **X-M17-1.** Extraction quality — zh two-column, scans, tables, formulas, UI small text, chat screenshots,
  accented/overlapping speech; synthetic in CI and the owner's data on the server — measures CER, unit coverage, gaps,
  tokens/latency per unit, by model. Prompt versions are frozen in M17-12/-18/-21 (note :297). Until it runs, the label
  stays `unknown` (note :136).

## Alternatives rejected

The model's "done" as a self-check input (note :131); sending blank units (note :135); words-per-page as a quality
verdict rather than a signal (note :135); a calibrated confidence label in v1 (note :136).

## References

- Module design note M17 v2 §4 (D8, with D2's publish constraint), §5 (consumed contracts), §8 (cards), §9 (gates), §10
  (experiments X-M17-1), §11 (UNKNOWNs with fallbacks), §12 (owner red lines).
- Baseline §8.4, §10.1, §28, §52, §57.1, §78.1, §80.1.
- ADR-0079 (receipt coverage), ADR-0115 (PUBLISH transaction), ADR-0116 (unit outcomes).
