# ADR-0116 — Capability probes, per-tenant consent and the degradation of BYOK extraction

- Status: Accepted (2026-10-26). Card M17-1 (docs only, wave D, module M17). ADR-M17-b (this ADR). Records module design
  note M17 v2 D6 (note :113) and the untagged M17 decisions that serve the same topic, D7 (:123) and D13 (:159). Content
  authority: the owner's 2026-10-23 ruling that processing uses the user's own model, owner (49166827) (note :7-9), the
  lead rulings at note :9-11, and the owner decisions still binding (BYOK for every non-embedding model call, owner (530f7467),
  note :16). This ADR records them and re-decides none. No code, migration or gate lands with it.
- Relates to: Baseline §7.1, §7.2, §7.4, §10.1, §11.2, §11.2.1, §11.5.1, §45.1, §52, §57.1, §78.1, §78.2, §80.1;
  ADR-0115 (per-type routes), ADR-0117 (self-check before publish), ADR-0119 (sandbox runner); module M04 (spend and
  cost), M15 D5 (policy reader, egress and SSRF rules), private-worker RPC.

## Context

- The vision plumbing exists without a caller: `PrivateReasoningPurpose::Vision` (`application/src/consolidate.rs`:100),
  private-worker dispatch (`inference_rpc.rs`:232/:370), `VisionReasoningRequest{artifact_refs}` (`adapters/src/byok.rs`
  :527) (note :44-45).
- Existing substrate (note :39-41): `control.user_reasoning_profiles(capabilities ⊆ {TEXT, VISION, STRUCTURED_OUTPUT,
  TOKEN_USAGE}, profile_version)` (migration 0048) — `profile_version` already changes with key, provider, model and
  endpoint; `control.memory_automation_policies(max_byok_tokens_per_period)` (0050); `control.egress_policies(tenant_id
  PK, … DEFAULT false)` (0051).
- The gap (note :53): the capability set lacks audio and PDF input, and there are no probes, no consent, no disclosure
  row and no budget for an extraction call.

## Decisions

### D-A (D6) Capability probes and degradation

New `control.reasoning_capability_probes(tenant, profile_id, profile_version, adapter_version, modality {IMAGE, PDF,
AUDIO}, level {DOCUMENTED, PROBED, LIMIT_CHECKED}, result {OK, UNSUPPORTED, UNKNOWN}, limits jsonb, probed_at)`; the
`capabilities` CHECK gains `AUDIO_IN` and `PDF_IN` (note :113-116).

A probe is a synthetic fixture whose answer exists only in that modality (a random code in an image, a known word in
audio). An HTTP 200, `/models` or the model's claim are never proof (an Anthropic-compatible endpoint ignores
`input_audio`/`file`). Limits are per model (the Qwen limits are per model) (note :116-119).

Errors are classed 401/403 AUTH, quota QUOTA, 429 RATE, timeout SERVICE — none of them means UNSUPPORTED (§52
`DegradeCode` arms; no new enum) (note :119-120).

Unit outcomes: COMPLETE · PARTIAL (user accepts; gaps visible forever) · WAITING (model/key/budget/consent; the deadline
runs) · REJECTED/EXPIRED (note :120-121).

Base-URL SSRF: no loopback, private or metadata targets, and redirects are re-checked (the M15 egress rule is reused)
(note :121-122).

### D-B (D7) Consent and disclosure

Sending raw pixels, audio or PDF needs per-tenant consent: new columns on `control.egress_policies`
(`raw_image_allowed`, `raw_audio_allowed`, `raw_document_allowed`, DEFAULT false, `consent_text_version`, `granted_by`,
`granted_at`). Without it the unit is `uninspected` and coverage is `unknown` (note :123-125).

Every model call runs: secret scan of the text parts → M15 D5 reader (RUN | SKIP_BUDGET | WAITING_KEY) → M04 reservation
→ an `ops.data_disclosures` row (purpose USER_REASONING) → the private-worker call (note :126-127).

The private-worker reads temp units from a read-only mount of the temp volume by `temp_unit_ref`, which narrows
`VisionReasoningRequest`: no store credential and no URL to the provider. Payloads are inline only — provider Files APIs
are rejected in v1 (residual copies, no verifiable delete) (note :127-129).

Extraction calls carry no tools and a strict JSON schema with unit ids; the output is data (`DATA_ONLY` ceiling, §10.1)
(note :130).

### D-C (D13) Cost and queue

`ops.jobs` with `SKIP LOCKED`, a lease epoch and per-tenant fairness; parse concurrency 1/node, external calls 4 global
and 1 per tenant (config) (note :159-160).

Estimate C = Σ(Tin·Pin + Tout·Pout)/1e6 + audio fees, with prices from the config price table; an unknown price reserves
by token cap against `max_byok_tokens_per_period`. A timeout with an unknown result keeps its reservation; a retry is a
new attempt with a new reservation. Cost events go through M04 C6 (note :160-162).

## Consequences

- Positive: a probe is a synthetic fixture whose answer exists only in that modality; an HTTP 200, `/models` or the
  model's claim are never proof of a modality (note :116-118); consent is per tenant and off by default; each call leaves
  one disclosure row; the spend cap is reserved before the call, not after.
- Cost: probe spend is part of the owner red line on real model spend in production (note :311-312); the consent columns are
  M15/§7.2-owned, so M17 adds guest columns rather than its own table (note :210).
- Consumes M15: the D5 policy reader and the egress/SSRF rule are reused, and `control.egress_policies` gains M17's consent
  columns (note :122, :189-190, :210).
- Consumes M04: C1 spend lease and C6 cost events for extraction (note :162, :190).
- Consumes private-worker: read temp units from a read-only mount by `temp_unit_ref`, with no store credential and no
  provider URL (note :127-129).
- Consumes M01: config keys for parse/external concurrency and the price table (note :159-161, §78.1).
- Neutral: no code, migration, config key or wire format changes with this card.

## Gates

Planned, implementer-owned, tri-state (§57.1); none exists in this card (note :222, :249).

| gate | owner card | test file | injected fault | expected red |
|---|---|---|---|---|
| B-1 ignored compat fields | M17-17 | `probe.rs` (fake Anthropic-compat) | accept HTTP 200 as proof | AUDIO_IN marked OK while audio ignored |
| B-2 error classes | M17-17 | `probe.rs` | map 429/401 to UNSUPPORTED | capability downgraded on rate limit |
| A-13 SSRF | M17-17 | `bins/worker/tests/probe.rs` | skip redirect check | base URL → 169.254.169.254 reached |
| A-11 raw-modality blind spot | M17-12 | `bins/worker/tests/extract.rs` | ignore consent; report coverage FULL | image sent without consent; coverage ≠ unknown |
| A-12 injection | M17-12 | `extract.rs` | give the extraction call tools; ceiling from text | tool call issued; text BehaviorEligible |
| C-2 stale worker | M17-12 | `extract.rs` | skip lease epoch | old attempt commits after re-lease |
| C-4 budget race / unknown cost | M17-12 | `extract.rs` | release on timeout | reservation freed, retry overspends cap |

Each needs its inject → red → fix → green record (§80.1) in the implementing card.

## Owner-gated (listed, not decided)

Red lines, owner only (note :310-313): real model spend in production (probes, extraction, legacy re-extraction on
users' keys; CI uses fakes and test keys); deleting legacy originals in the old MinIO; live keys of any provider or
store. Open owner questions: none (lead rulings applied; v1 Q1 closed by "no originals") (note :313).

## Open research

- **X-M17-4.** Probe reliability — false OK and false UNSUPPORTED across vendors with test keys — is unmeasured until
  that experiment runs; gates: M17-17 (note :300).

## Alternatives rejected

An HTTP 200, `/models` or the model's own claim as proof of a modality (note :117-118); a new error enum for these
failures (the §52 `DegradeCode` arms are reused; note :119-120); provider Files APIs in v1 (residual copies, no
verifiable delete; note :129); a store credential or a provider URL inside the private-worker (note :127-129); tools in
an extraction call (note :130).

## References

- Module design note M17 v2 §4 (D6, D7, D13), §5 (consumed contracts), §6 (table ownership), §8 (cards), §9 (gates), §11
  (UNKNOWNs with fallbacks), §12 (owner red lines).
- Baseline §7.1, §7.2, §7.4, §10.1, §11.2, §11.2.1, §11.5.1, §45.1, §52, §57.1, §78.1, §78.2, §80.1.
- ADR-0115 (per-type routes), ADR-0117 (self-check), ADR-0119 (sandbox).
