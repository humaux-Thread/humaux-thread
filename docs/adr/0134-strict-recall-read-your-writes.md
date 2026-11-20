# ADR-0134: Strict read-your-writes for recall

## Status

Accepted · 2026-11-20. This change records the contract. M01-4-TERMINAL owns runtime implementation and acceptance.

## Context

Baseline §15.5 lists recall and context as consumers of the consistency token. §17.5 allows verified projection visibility or PostgreSQL delta overlay to satisfy strict reads. §52.2 distinguishes terminal and degraded projection lag. The canonical recall input already accepts `consistency_token`. The canonical context input rejects the field, and context assembly has no token-aware overlay. The current recall path can take the empty response in [ADR-0053 D-E](0053-production-onboarding-and-empty-activation.md#d-e-reads-pg-authority-for-getenumerate-b-shape-for-recallcontext-on-an-unactivated-family) before token validation.

## Decision

### Validate the token before any strict read can return a result

A recall with a consistency token requests strict read-your-writes. Authenticate the caller and narrow the requested workspace first. Derive the expected stream family from the trusted route. Check the token's signature, expiry, scope and family, and match its registered projection version and exact issued stream row. Match the issued row by stream sequence and commit sequence. The latter binds the issuance audit record and does not order reads. Preserve existing authorization, invalid-token and dependency error mappings.

### Verify coverage for the exact write

After validation, either of these conditions satisfies the token:

1. **Serving frontier.** The active serving checkpoint for the exact token stream key, including its projection version, has `projection_highwater >= token.stream_seq`. A checkpoint on another version cannot cover the write. A token for a registered retired version can use its own PostgreSQL overlay.
2. **Delta overlay.** The PostgreSQL read covers the token sequence in the §15.5 overlay. Verify the exact original, non-rebuild ticket against its canonical Evidence anchor in the outbox, joining on tenant and commit and confirming the stream sequence. Observe the original ticket, anchor and rebuild membership before filtering objects by visibility, tombstones or rebuild membership. The authenticated read role and its RLS policies apply to this observation. An explicitly verified tombstone on the anchored original ticket establishes authoritative suppression. A rebuild ticket or an unrelated overlay candidate establishes neither coverage nor suppression.

Keep the coverage decision independent of the returned item list. A covered write can be absent from that list because of authorization, lifecycle, tombstones or query filters. Apply the existing final Evidence and Memory gates to every item and keep anchor identities and reasons internal. The exact issued row establishes issuance after the other validation checks pass. If successful reads establish neither a serving frontier nor overlay coverage, the frontier is unsatisfied. A read or authorization failure keeps its existing error mapping.

### Decide in the final hydration snapshot

The retrieval PostgreSQL adapter owns the coverage read, in the same `REPEATABLE READ, READ ONLY` transaction as token issuance validation, the serving recheck, overlay and final body authorization, ledger and pipeline reads. Use the existing authenticated tenant/user settings and the sole serving selector. An earlier route lookup only selects the index to query. Recheck that selection during final hydration and fail closed if it changes. Use the active serving key for index candidates and the token key for its overlay. Keep both behind the existing final materializer. The application maps the disposition before assembling a success envelope.

### Apply the no-serving and wire rules in order

ADR-0053 D-E's empty B response remains the path for an initialized family without serving when the caller supplies no token. A token-bearing request without a serving version goes through token-aware PostgreSQL hydration first, without embedding or index calls. A covered write can return an authorized PG-only overlay with no-serving provenance. A valid unsatisfied token terminates with the existing `ErrorCode::ProjectionLag`. The wire error has no result or degradations (§52.2 and §52.4). Permissive reads that return lagged results retain `DegradeCode::ProjectionLag` through the existing envelope and the strictly greater `LedgerClosure::lagging` threshold. Age alone cannot decide a token's coverage.

### Stage context separately

M01-4-TERMINAL implements recall strict first. The current context schemas and route remain in place for that stage. The §15.5 context requirement remains open under M01-4-CONTEXT-CONTRACT, which owns the input and output contract and client compatibility for token-aware context before runtime delivery. Existing callers that omit a token retain their current contract.

## Acceptance

M01-4-TERMINAL uses one isolated real PostgreSQL fixture for the strict terminal response and permissive degraded result. It also proves strict success through the overlay, the permissive threshold boundary, and token validation on the no-serving path. Injecting a bypass of the strict terminal branch must produce the degraded success the strict test rejects. Restore the branch and record red and green runs on pinned SHAs. G52-4, G52-5, G80-4 and the architecture gates remain in force. Exact-head CI and independent review of the two wire outcomes are required for runtime acceptance.
