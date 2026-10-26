# ADR-0096 — Memory applicability and cross-project reuse: widening where a memory applies, never where it is visible

- Status: Accepted (2026-10-23). Card M14-1 (docs only). Content authority: module design M14 §4 D4 and D5, D7, and the
  owner's Q1 answer of 2026-10-22 at the end of that note. The code lands in M14-5 (table and propose/approve doors)
  and M14-6 (the reuse read); until then the statements about behaviour are **planned**.
- Relates to: Baseline §6.1.1 (visibility is not tenant isolation), §6.1.4 (work attribution), §25.4, §52.1, §57.1,
  §78.2, §78.6; ADR-0078 D-A and D-E (N09: identity and attribution are never guessed); ADR-0068 D-E (the `memory_id`
  keyword index); ADR-0080 D-D (the experience list); design notes M07 D5 (taint lattice), M11 (retrieve with an id-set
  filter), M13 (totals), M15 (proposals and rule state), M18 D4 (`tasks.project_id`), M20 v2 D4' (public pool).

## Context

- Nothing stores where a memory may be applied, and no reuse path exists. The owner's requirement (2026-10-15, items
  2–5) is reuse across projects, products and languages — including old Python research reused in Rust — with the
  rule "reuse widens applicability, never visibility".
- N09 R2 (ADR-0078 D-E) is binding: similarity, embeddings, topic names and model output yield candidates only; they
  never enter formal read paths, counts or constraints.
- The public pool (M20 v2 D4') states the other boundary: private applicability is never read as a public licence.

## Decision

### D-A Applicability is a widening of *where*, never of *who* (M14 D4)

- New M14-owned table `private.memory_applicability(tenant_id, memory_id PK/FK, scope, product_subject_id,
  channel_key, qualifiers jsonb, status, assignment_method, decision_evidence_id)`, FORCE RLS with a tenant-leg
  composite FK.
- `scope` is a closed set: `PRODUCT_SPECIFIC` (one product or brand), `CHANNEL_GENERIC` (any project on a channel
  platform), `UNIVERSAL`. A qualifier is a closed schema v1: `implementation_languages[]` and `exclusions[]`; it is not
  free-form JSON.
- Lead ruling (2026-10-24): SUBTREE scope (`project_scope EXACT|SUBTREE`) comes from the M18-0 hierarchy ADR, not from
  M14-5 (`module_design_M20.md:98`: "Private applicability (M14 D4 scopes, M18 EXACT/SUBTREE) is never read as a public
  licence").
- `status` is a closed set: `PROPOSED`, `APPROVED`, `REJECTED`. **No row means project-local**, which is the default:
  applicability never opts a memory in by omission.
- `assignment_method` records how the row was widened and `decision_evidence_id` points at the approval Evidence.
- The table never grants visibility. Every read still passes the M08 all-evidence gate and the principal's RLS; an
  `APPROVED` row on a memory the reader cannot see changes nothing.

### D-B Who may widen it (owner Q1 answer)

- A lesson's applicability may be widened from the **owner console**, or by an **agent acting on the owner's chat
  instruction**, stored with the label `由聊天授权` (authorised in chat). **Agents never widen it on their own.**
- Agents, BYOK and M15 may only `PROPOSE`; approval needs the approval Evidence. A proposal appears in reuse in a
  separate "proposed, not confirmed" bucket and is never auto-approved.
- G-M14-8's failure mode is the other path: an agent widening that arrives **without** the `由聊天授权` label and is
  accepted as an owner/console approval makes a broadened row `APPROVED` (`module_design_M14.md:211`: "by an agent on
  the owner's chat instruction (labelled 由聊天授权)"). That is refused; the chat-authorised path carries the label and
  the owner's instruction, and ADR-0078 D-G's rule stands that an agent relaying the owner's words is weaker proof than
  the owner's own confirmation.

### D-B.1 Approval predicate (lead ruling 2026-10-26)

- The SQL SECURITY DEFINER decision door takes memory id, decision Evidence id, method and APPROVED or REJECTED.
- The existing 0188 `control.assert_write_scope` authenticates the API-key caller inside the transaction.
- Its key's user must hold ACTIVE `control.memberships.role = 'OWNER'` in the applicability row's tenant.
- `AGENT_ON_OWNER_CHAT` (由聊天授权) requires same-tenant Evidence with `origin_class = 'AuthenticatedAgent'`
  and `origin_principal_id = api_key_id`, the principal recorded by the existing remember/ingest writers.
- This proves the agent's authorship of the relayed instruction, not the owner's words; ADR-0078 D-G stays intact.
- Missing Evidence, foreign tenant, different author, wrong origin or non-owner is refused with FORBIDDEN and a sub-reason.
- APPROVED and REJECTED record both method and Evidence; refusal leaves the whole row unchanged; proposals only store PROPOSED.
- OWNER_CONSOLE is refused until the console session binding exists (M14-5b).
- A future console approval requires a trusted owner session plus same-tenant DirectUserInput/UserConfirmed Evidence by that caller.
- A later console approval may supersede a chat approval, never the reverse; applicability changes no visibility or permission.
- Widening applicability is outside ADR-0078 D-G's high-risk list, so it requires no confirm token.

### D-C Language independence

- Empty `implementation_languages` means language-independent, so research written for an older language is reusable
  where the mechanism transfers (old Python research in Rust).
- A non-empty list is a qualifier the target must satisfy. A qualifier that cannot be evaluated (including a "problem
  domain" match, M14 U5, which waits for ADR-0078 D-H's vocabulary) puts the item in the `needs_revalidation` bucket —
  never into the eligible set on a guess.

### D-D Eligibility first, then ranking (M14 D5)

- An item is **eligible** only when all of these hold: it is readable through the M08 all-evidence gate; an `APPROVED`
  applicability row matches the target project (`UNIVERSAL`; `CHANNEL_GENERIC` against the target's `channel_key`;
  `PRODUCT_SPECIFIC` against the target's brand or product); the backing closure's DataClass is below `SENSITIVE`; the
  closure has no affect rows; the memory is active; and its qualifiers are evaluable.
- Only then does ranking run: M11 retrieve restricted to the eligible id set (the `memory_id` keyword index of
  ADR-0068 D-E), with the target project's GOAL text as the query. The filter precedes retrieval, so no forbidden item
  enters the candidate pool and truncation cannot hide an eligible one.
- Each item carries the source project, why it applies, and its qualifiers. Another brand's `PRODUCT_SPECIFIC` item
  appears only in the `detailed` view, labelled "not transferable". Totals come from M13 (`N eligible, showing k`), and
  ADR-0080 D-D experience-list items attach per target when T-KNOW-1 exists.
- The eligible id set is capped at 1,024 (`ponytail:` ceiling; over the cap the answer is
  `needs_more_specific_target`; the upgrade is a Qdrant payload filter on applicability, M10).

### D-E Embedding does not relax eligibility

- The owner's 2026-10-22 decision to embed everything does not make an ineligible item eligible. Embedding is not
  injecting customer or affect material into another project (M07 D5; the CUSTOMER / RELATIONSHIP rule of B20b).
- The target project comes from the same deterministic resolution as ADR-0093 D-D: explicit `project_id`, else the task
  run's project at `now`, else unresolved (no reuse suggestions). `tasks.project_id` is the one writable
  task→project authority (M18 D4), and M14 reads it through M18's port.

### D-F The public pool is a different lane

- M20's public units are a separate pool with its own consent, admission and serve predicate. Applicability is never a
  public licence, no public read consults it, and this ADR builds no public path (M20 v2 D4').

### D-G Ranking is gated by an experiment

- Until E-M14-2 passes, the recommended bucket is the **exact eligible set ordered by recency**, with no semantic
  ranking. E-M14-2 uses at least 120 labelled tasks in zh and en and gates semantic default-on at ≥ 90 % eligible
  recall@5 on positives **and zero forbidden disclosures** (never averaged).
- G-M14-6 and G-M14-7 test eligibility and taint; G-M14-11 reconciles the Rust `scope` and `status` sets with the DB
  CHECK lists (§78.2).

## Rejected (from M14 D4 and D5)

- Similarity-assigned scope: N09 R2 makes model output a candidate, never a formal assignment.
- Visibility widening: the owner's rule and §6.1.1 keep visibility where it was.
- B20's taint booleans: the M07 D5 lattice already expresses taint; a boolean beside it is a second truth.
- Semantic top-k followed by a filter: forbidden items enter the pool, and truncation hides eligible ones.
- B20's 40/30/20/10 bucket quotas: no evaluation supports them.
- Production rerank on this path: the owner rejected production rerank on 2026-10-22.

## Gates

| Gate | Planned test file | Injected fault | Expected red |
|---|---|---|---|
| G-M14-6 reuse eligibility | `crates/adapters/tests/reuse.rs` | drop the product/channel predicate | a hearing-aid product lesson is recommended for fragrance on Alibaba |
| G-M14-7 reuse taint | the same file | check the memory's own class, not the closure | a `SENSITIVE` or affect-derived item is returned |
| G-M14-8 approval provenance | `crates/adapters/tests/applicability.rs` | accept an agent widening WITHOUT the `由聊天授权` label | the broadened row becomes `APPROVED` |
| G-M14-11 enum contracts | `crates/adapters/tests/facet_contract.rs` (extend) | a Rust variant with no CHECK value | the applicability `scope` / `status` sets differ from the CHECK lists |

No gate exists in this PR (docs only). Each exists when M14-5 or M14-6 lands with its §80.1 inject → red → fix → green
record; a missing database in CI is a failure, never `not_applicable`.

## Open numbers and owner-gated items

- E-M14-2's thresholds are **open and measured**, not researched; no result is assumed here. The 1,024-id cap is a
  starting value from the design note.
- Owner-gated: widening an applicability row is the owner's act (console, or an agent on the owner's chat instruction
  labelled `由聊天授权`). An agent widening on its own is a red-line violation, not a configuration choice.
- No production data, live key or email is involved in M14-5 / M14-6.

## Consequences

- A lesson can travel to another project only through an explicit, evidenced decision; the default stays project-local.
- Reuse cannot become a side door to visibility: eligibility is evaluated after the same gate every other read uses.
- The semantic ranking stays off until E-M14-2 proves both recall and the absence of forbidden disclosures.
