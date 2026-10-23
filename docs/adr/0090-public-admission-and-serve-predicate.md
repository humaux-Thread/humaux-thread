# ADR-0090 — Public admission: automatic receipts, contributor-BYOK model checks, one serve predicate

- Status: Accepted (2026-10-23). Card M20-1 (docs only), ADR-M20-c. The decisions are the design lead's record of module
  design note M20 v2 (D3', D4', D5, D6', D8', D9', D15', D16') and of the owner answers of 2026-10-23; this ADR records
  them and does not re-decide. Code lands in M20-5 to M20-12 and M20-20 to M20-23.
- Relates to: Baseline §12.1.1, §12.3, §12.6, §7.1, §7.2, §23.3, §52, §57.1; ADR-0083 (hybrid private recall);
  ADR-0084 (local rerank); ADR-0088 (consent); ADR-0089 (data map); ADR-0091 (withdrawals).

## Context

- §12.1.1 is the Phase 9 exact-byte admission path; its initial claim entered `UNDER_REVIEW`, and the pool served a
  claim only when the §12.6 receipt and closure checks passed. B33 found the serve predicate too weak (no epoch, payload
  hash or authorisation per root; no manifest count), the rules missing surfaces, rights and conflicts, no
  counter-example channel, and rerank treated as if it filtered.
- The owner ruled on 2026-10-23: admission is automatic with no review queue; the payer for model checks is the
  contributor's BYOK domain only; mixed recall becomes default-on after E-M20-4 passes, and the user can switch it off.

## Decisions

### D-A Eligibility is a deterministic predicate over the M07 closure

Selection is the cloud `CONTRIBUTION_SWEEP` (batches of at most 32, one worker, daily cap in config). A candidate is
eligible only if, in the protected context: its kind maps to a phase-1 unit type **and** a category in the shown
notice's scope; `DataClass <= INTERNAL`; it has no affect row; and it has no person, customer or relationship link.
Private applicability (M14 D4 scopes, M18 EXACT/SUBTREE) is never a public licence. M18 acceptance hand-offs reach M20
only after they become canonical memories through M15/M07.

### D-B A unit is complete per type before it is admitted

Common fields: `problem_goal`, `context_constraints`, `environment`, `preconditions`, `approach`, `result`
(`UNKNOWN|SUCCESS|PARTIAL|FAILED`, never inferred from tone: `RULE` or `CONTRIBUTOR` only), `verification_method`,
`failure_conditions`, `alternatives`, `rights`; per-claim evidence stays `public.claims` plus provenance edges.

Phase 1 type rules; each listed field is required and `KNOWN` unless marked `U?`:

| unit type | required fields |
|---|---|
| FIX | repro, expected_vs_actual, root_cause (+ certainty, U?), change, regression_check, rollback (U?), failure_conditions |
| DECISION | goal, candidates (>= 2), constraints, trade_offs, why_not, redecide_triggers |
| RESEARCH | per-claim source + version + locator, fact_or_inference, applicability, limits |
| USAGE | environment, input, steps, expected_output, verification_state, errors (U?), not_applicable_cases |
| CHECKLIST | preconditions, steps, checkpoints, done_criteria, exception_branches, rollback (U?) |
| FAILURE_CASE | hypothesis, attempt, environment, observation, excluded, unknowns |

Phase 2 adds PLAYBOOK and DATA (definition, unit, numerator/denominator, sample, window, baseline, error); phase 3 adds
business and pricing. The rules live in one `match` in `public-pool/src/completeness.rs` with a `RULE_VERSION`, recorded
in the receipt. Fill order: deterministic extraction, a model draft (`assist = MODEL`), optional contributor completion
through `contribute.preview/submit` (never a queue), then the experiment. Stripping every causal condition in order to
publish keeps the item private (`CONDITIONS_STRIPPED`).

### D-C Front gates and rules; every one is a versioned receipt

Unchecked is `NOT_RUN`, never pass. Front gates: **F1** authorisation (AUTO policy, `SHOWN` for the current notice,
category in scope, floor); **F2** rights/licence (text CC BY 4.0, original code MIT, third-party keeps its SPDX;
unknown-licence expression or over-quota quotation blocked); **F3** version and key fields (type-required fields `KNOWN`,
entity ids resolve); **F4** complete lineage and receipt set (visible count = manifest count); **F5** the serve check
(D-E).

Rules: **A1** transferable value plus type completeness; **A2** per-type fields and evidence; **A3** de-identification
over every surface (body, title, tags, entity aliases, code comments, paths, URL queries, quotes, edge text, numbers,
dates, attribution) plus combined identifiability and secrets, trade secrets and contract text, any hit rejects; **A4**
dedupe four ways (same expression = no-op; same evidence = extra root; same problem other conditions = coexisting
variant; opposite result same conditions = both `DISPUTED`, never voted); **A5** model check bound to (input sha, model
id, prompt version, rule version); **A6** independence = three families per claim (control: tenant, so 80 agents = 1;
original evidence: same URL/DOI/hash; observation: same run/environment fingerprint); **A7** poisoning = wrong facts
(contradiction sets `DISPUTED`) and instruction-like injection on any surface, plus a fixed attack regression set.

Receipts are written only by the trusted service role through one definer function (`receipt_sha256` over the bound
inputs); a user agent's PASS is material, not a receipt. Every merge, translation or summary is a new revision,
re-admitted. `ponytail:` grant-based trust; signatures when receipts leave the database.

### D-D The payer is the contributor's BYOK domain; the platform spends nothing

A5 and model drafting run through gateway egress with a platform-fixed endpoint allowlist and prompt. The payer is the
contributor's BYOK domain only. No BYOK means A5 `NOT_RUN` and nothing admitted from that tenant; any platform model
spend is an owner red line. The sponsor-budget path is **not built** (YAGNI). Budget 0 pauses only optional curation
(merge, re-verify, multi-root rebuild text); access control, revocation, invalidation and incident freeze never pause.
Rejected: v1's sponsor-only pool, and a user agent calling its own endpoint (no trusted receipt).

### D-E One serve predicate is the sole public read authority

`public.servable_revision(id)` holds only when: serve `ADMITTED`; its own admission `PASSED`; every receipt of the
current rule manifest is present and current (visible count = manifest count, so a partly invisible set fails closed);
the manifest is complete; at least one root; and every root `ACTIVE` with matching epoch, payload sha and still-valid
authorisation (policy AUTO, notice not superseded-unshown, not withdrawn). It runs as `role_public_disclosure`
(NOBYPASSRLS). States stay separate, never collapsed into one score: serve `ADMITTED|SUSPENDED|WITHDRAWN`; claim
`CLAIMED|SUPPORTED|DISPUTED|REFUTED`; verification `unverified|contributor_reported|reproduced`; time
`current|needs_reverify|historical` (an old version is not wrong).

### D-F The read lane: recall separately, filter before rerank, mix behind a flag

Entries: search ("fix X on version Y") and project-context recommendation ("I am building X": the private side maps M18
project facets or M14 GOAL to a task map and stage locally; the public query carries only concept ids, public entity ids
and an A3-scrubbed query, never customer or private task text).

Pipeline: (1) load private constraints (M14 GOAL/CONSTRAINTS/REJECTIONS, mandatory rules) regardless of relevance;
(2) recall private (ADR-0083) and public (dense + BM25 on `public_knowledge_v1`) separately, plus a counter-example
channel (FAILURE_CASE, DISPUTED/REFUTED, failure_conditions); (3) PostgreSQL checks: private hydrate gate, public D-E
plus applicability `MATCH|INCOMPATIBLE|UNKNOWN`; (4) bounded top-up 50, 100, 200 within a per-request budget;
(5) aggregate per revision; (6) memory/revision-level RRF k 60 to 25 with quotas at most 5 private-reserved, 5
public-reserved and 3 counter-examples, 12 shared, no filler; (7) unified local rerank (ADR-0084, K 25); (8) the
coordinator check before flush (ADR-0091).

**Rerank is not a security boundary** (Confundo §6.4: 78 % attack success after `bge-reranker-large`): every filter
precedes it. Public vectors come from admitted public text through the platform's pinned local encoder (M10), never
from private vectors; BYOK vectors cannot query the public space.

Mixed mode is the request flag `include_public`: built off; once E-M20-4 passes it is default-on for every tenant,
labelled, and the user can switch it off (owner answer 2026-10-23); the production switch-on is part of M20 go-live.

### D-G Cards disclose; they do not score

A card carries: why it was shown, whose it is (own or public "contributor"), the evidence nature, matched, missing and
incompatible conditions, freshness, counter-examples, and the next action. No combined trust score. UNKNOWN
applicability shows a "confirm conditions" area; `REFUTED` or `FAILED` is never rendered as an executable plan.

## Consequences

- Positive: admission is reproducible from receipts; the serve predicate fails closed on a partial set; the public lane
  cannot be steered by private text or a reranker; the model-check credit goes to the contributor's key.
- Cost: a tenant without BYOK contributes nothing (U5, a metric); every merge and translation re-runs admission; the
  mixed lane adds one public Qdrant pair and one servable SQL read (at most 200 ids, <= 75 ms p95), no rerank cost.
- Neutral: nothing compiles or runs for this card; no gate, migration or code in this PR.

## Gates and experiments

Planned, implementer-owned, tri-state (§57.1); none exists in this PR:

| gate | owner card | injected fault | expected red |
|---|---|---|---|
| G-M20-5 eligibility | M20-5 | read direct evidence only; read M14 UNIVERSAL as a licence | a SENSITIVE, affect or customer-linked item, or an applicability-only item, is selected |
| G-M20-6 completeness | M20-7 | drop one required field per type; infer result from tone | a FIX without repro is admitted; `SUCCESS` with `assist = MODEL` |
| G-M20-7 rules (A1 to A7, F1 to F4, one each) | M20-8a, -8b, -11 | remove one rule | a fragment, PII in a title/path/URL query/code comment, an AWS key, an unknown licence, "ignore previous instructions" in an alias, or a missing receipt is admitted |
| G-M20-8 dedupe/conflict | M20-9 | merge variants; vote on a conflict | a variant is lost; one side of a conflict is `SUPPORTED` |
| G-M20-9 families | M20-9 | family = agent; count per unit not per claim | 80 agents become 80; 80 users citing one paper become 80 |
| G-M20-10 payer + receipt | M20-10 | fall back to a platform key; accept an agent PASS; leave the receipt unbound to the prompt version | a platform-key call; a PASS without a trusted receipt; a stale prompt receipt is current |
| G-M20-11 serve predicate | M20-12 | ignore root epoch, payload or authorisation; hide one receipt row | a revoked, edited or de-authorised root is served; a partial receipt set passes |
| G-M20-17 query minimisation | M20-21 | pass raw private task text to the public lane | a customer or project name reaches the public lane's log or query |
| G-M20-18 mixing and rerank boundary | M20-22 | apply the serve check after rerank; add filler when a quota is empty; accept a BYOK vector | an unservable or INCOMPATIBLE item in the top 25; filler present; a foreign vector accepted |
| G-M20-19 cards | M20-23 | render `FAILED` as a plan; add a combined score | an executable step from `FAILED`; a `score` field |
| G-M20-22 anonymity schema | M20-25 | add a contributor or tenant field to the public output | the fingerprint diff is red |

Each needs its own inject → red → fix → green record (§80.1) in the implementing card; a missing database or input is a
fail in CI, never `not_applicable` with exit 0 (ADR-0050). E-M20-1 accepts at 0 from the must-reject classes and at
least 70 % of complete good items admitted (start value). E-M20-4 accepts at 0 forbidden disclosures (never averaged)
and Applicable Recall@25 of "full" at least that of private-only on the same split. Thresholds and budgets are config
entries (§78.1), not literals.

## Open

- **U3** name/org detector: dictionaries plus script/case heuristics reject on any hit; a model only after E-M20-1.
- **U4** thresholds before E-M20-1/2: per-type completeness, sanity floor 80 characters, tau 0.92, `min_families` 1 with
  the label "single case, not independently reproduced".
- **U5** a contributor without a BYOK domain: A5 `NOT_RUN`, nothing admitted from that tenant (a metric).
- **R5** quotation limits for RESEARCH units (how much source text F2 may let through): open.

## Owner-gated (listed, not decided)

Any platform-paid model spend (the sponsor path is not built) and any funded reward; live model or embedding keys
anywhere in M20; the online E-M20-5 run on production and the production switch-on of mixed recall.

## Alternatives rejected

A composite score, a moderation queue, or an LLM-only gate; a user agent's PASS as a receipt; v1's sponsor-only payer
and a user agent calling its own endpoint; applying a filter after rerank or treating rerank as a security boundary;
sending raw private task text to the public lane; a combined trust score on cards.

## References

Module design note M20 v2, D3' to D9', D15', D16', §8 to §10 and §12; batch-33 public-pool research digest (B33);
Baseline §12.1.1, §12.3, §12.6, §7.1, §7.2, §23.3, §52, §57.1; ADR-0083; ADR-0084; ADR-0088; ADR-0089; ADR-0091.
