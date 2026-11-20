# ADR-0134: Strict read-your-writes for recall

## Status

Accepted · 2026-11-20. This change records the contract. M01-4-TERMINAL owns runtime implementation and acceptance.

## Context

Baseline §15.5 lists recall and context as consumers of the consistency token. §17.5 allows verified projection visibility or PostgreSQL delta overlay to satisfy strict reads. §52.2 distinguishes terminal and degraded projection lag. The canonical recall input already accepts `consistency_token`. The canonical context input rejects the field, and context assembly has no token-aware overlay. The current recall path can take the empty response in [ADR-0053 D-E](0053-production-onboarding-and-empty-activation.md#d-e-reads-pg-authority-for-getenumerate-b-shape-for-recallcontext-on-an-unactivated-family) before token validation.

## Decision

### Validate the token before any strict read can return a result

A recall with a consistency token requests strict read-your-writes. Authenticate the caller and narrow the requested workspace first. Derive the expected stream family from the trusted route. Check the token's signature, expiry, scope and family, and match its registered projection version and exact issued stream row. Match the issued row by stream sequence and commit sequence. The latter binds the issuance audit record and does not order reads. Preserve existing authorization, invalid-token and dependency error mappings.

### Verify coverage through the token

**Invariant.** Strict recall succeeds only if the result covers every committed write in the token's stream through its sequence, inclusive, under the caller's authorization and the existing retrieval semantics. Coverage means the write is visible to retrieval or authoritatively excluded by those rules. The normal query, lifecycle, and result-selection rules still determine which items are returned.

1. **Serving frontier.** Before querying the index, pin a single observation of its active serving checkpoint, including the stream key, projection version and verified query-visible prefix. Query that serving target with the §17.5 read consistency that preserves the observed visibility. The index candidates can satisfy the token only if the observed checkpoint is for the exact token key and proves `projection_highwater >= token.stream_seq`. A newer observation cannot certify candidates returned by an earlier query. A token for a registered retired version can use its own PostgreSQL overlay.
2. **Delta overlay.** Close the uncovered range through the token sequence in the final PostgreSQL snapshot. When using index candidates for token-stream coverage, derive the §15.5 overlay lower bound (`contiguous_done_prefix`) from the same pinned observation. The verified candidate-query prefix and the overlay must cover the range without a gap. In particular, a prefix that advances after the query cannot raise the overlay lower bound for that attempt. When there is no verified candidate-query prefix for the token key, establish the necessary coverage in PostgreSQL. Verify the exact original, non-rebuild token ticket against its canonical Evidence anchor in the outbox, joining on tenant and commit and confirming the stream sequence. Observe the original ticket, anchor and rebuild membership before filtering objects by visibility, tombstones or rebuild membership. The authenticated read role and its RLS policies apply to this observation. An explicitly verified tombstone on the anchored original ticket establishes authoritative suppression. The token anchor establishes the identity of the required write. The overlay still has to cover any earlier committed writes in the uncovered range.

Keep the coverage decision independent of the returned item list. A covered write can be absent from that list because of authorization, lifecycle, tombstones or query filters. Apply the existing final Evidence and Memory gates to every item and keep anchor identities and reasons internal. The exact issued row establishes issuance after the other validation checks pass. If successful reads establish neither a serving frontier nor overlay coverage, the frontier is unsatisfied. A read or authorization failure keeps its existing error mapping.

### Bind the query observation to the final hydration decision

The retrieval PostgreSQL adapter binds the candidate batch to its pre-query serving target and frontier observation. The final `REPEATABLE READ, READ ONLY` transaction validates token issuance, rechecks that target through the sole serving selector, verifies the pinned observation and overlay coverage, authorizes final bodies, and reads the ledger and pipeline under the existing tenant/user settings. Keep the pinned observation for that batch even if the same serving checkpoint has since advanced. Fail closed if the serving target changes. For a stable target with a late frontier advance, use the same-snapshot PG overlay to fill the gap through the token. If the union cannot prove coverage, terminate with `ErrorCode::ProjectionLag`. Use the active serving key for index candidates and the token key for its overlay, and pass both through the existing final materializer. The application maps the disposition before assembling a success envelope.

### Apply the no-serving and wire rules in order

ADR-0053 D-E's empty B response remains the path for an initialized family without serving when the caller supplies no token. A token-bearing request without a serving version goes through token-aware PostgreSQL hydration first, without embedding or index calls. A covered write can return an authorized PG-only overlay with no-serving provenance. A valid unsatisfied token terminates with the existing `ErrorCode::ProjectionLag`. The wire error has no result or degradations (§52.2 and §52.4). Permissive reads that return lagged results retain `DegradeCode::ProjectionLag` through the existing envelope and the strictly greater `LedgerClosure::lagging` threshold. Age alone cannot decide a token's coverage.

For MCP, termination uses the G52-4 tool error format (`result.isError = true`, `result.structuredContent.code = "PROJECTION_LAG"`). “No result” means no successful result items.

### Stage context separately

M01-4-TERMINAL implements recall strict first. The current context schemas and route remain in place for that stage. The §15.5 context requirement remains open under M01-4-CONTEXT-CONTRACT, which owns the input and output contract and client compatibility for token-aware context before runtime delivery. Existing callers that omit a token retain their current contract.

## Acceptance

M01-4-TERMINAL uses one isolated real PostgreSQL fixture for the strict terminal response and permissive degraded result. It also proves strict success through the overlay, the permissive threshold boundary, and token validation on the no-serving path. Injecting a bypass of the strict terminal branch must produce the degraded success the strict test rejects. Restore the branch and record red and green runs on pinned SHAs. G52-4, G52-5, G80-4 and the architecture gates remain in force. Exact-head CI and independent review of the two wire outcomes are required for runtime acceptance.

In a deterministic real PostgreSQL and disposable-index fixture, issue token 42 and hold the serving prefix at 41 while the candidate query runs. The query must return without the only authorized match, whose write is at 42. After the query returns and before final hydration starts, publish that item to the same serving target and advance its checkpoint to 42. Release final hydration only after both writes are visible. Assert that the strict response includes the uniquely matching item through the overlay anchored to the pre-query prefix. With overlay coverage deliberately unavailable, assert terminal `PROJECTION_LAG` and no result or degradations. Mutate the decision to use the later checkpoint for the old candidate batch. The fixture must fail on the successful response missing the write, then pass when the original observation is restored.
