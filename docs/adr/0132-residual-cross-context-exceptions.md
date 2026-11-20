# ADR-0132: Residual cross-context exceptions

## Status

Accepted · 2026-11-19. Source evidence is pinned to `d271690` unless stated otherwise. The case for X-16 incorporates the F1 provenance repair in #608 (`681b2fed`).

## Context

[ADR-0130](0130-bounded-context-modules-ddd-hexagonal.md) D2, D4, D5, D7 and D7a define the hexagonal layers, single-writer boundary, cross-context contracts, retained invariants and application-port acyclicity. [ADR-0131](0131-published-language-in-contract-kernel.md) keeps values with unique domain construction points in their owning contexts. Baseline §§3, 58, 78.3 and 78.6 govern dependencies, the workspace and how architecture changes are recorded.

The residual decision covers 44 exact import keys from B5 pinned (17), B2 lifecycle (16), B1 pinned (4) and B3 kept (7), plus the OPEN-1 writer decision. The actual source dependencies already include cycles through declared context dependencies. The existing pins enforce properties that call sites must retain, including at these boundaries.

## Decision

Assign each row exactly one disposition. Decide rows sharing a pin or a transaction together and record the result per key.

| Disposition | Meaning |
| --- | --- |
| R | Refactor the dependency while preserving the invariant. |
| X | Accept a long-term exception for the exact import key, backed by invariant evidence and a review trigger. |
| M | Revise the context map with a named DDD relation and a `may_depend_on` edge. Require a business purpose, exact public operations, a contract owner, preserved invariants, an acyclicity check over declared and all actual edges (including debt and exceptions), and a reviewable diff. |
| B | Move the boundary and its ownership. |
| H | Hold the decision pending evidence. Fix any real defect before considering X. |

The ruling is **R=28, X=16, M=0, B=0, H=0**. R comprises R-SCAN-CAP (1, consume the published cap), R-MAINT-GUARD (11, consumer-side authorization and audit ports) and R-BMO-QUOTA (16, eight reservation and eight receipt imports, inject quota operations at the composition root and preserve the caller transaction).

Decision closure means H=0. Implementation closure requires every R, M and B to be merged with its gates green. Report X and M counts together with their scope, and report formally authorized dependencies separately from actual decoupling.

Keep the pins. G-M08-2 enforces complete mediation for visibility (Baseline §6.1.1). G-M29-5(a) preserves the atomic attribution commit (ADR-0078 D-D and Baseline §58). G-M09-1 keeps one sequence allocation and stream insert door (M09 §6). The unique construction points preserve canonical evidence encoding (Baseline §§8.1, 48.0①), query/profile binding and projection provenance. Consider moving a pin only with the protected property, proof that its new home enforces it, a counterexample that fails, and a replacement structural pin. R3 also pins the shared egress and completion helpers to their current home (Baseline §11.2.5, `architecture_check.rs:9995–10023,10074–10124`). The scoped back-edge rulings below prioritize their construction invariants over source-graph acyclicity.

### OPEN-1: M07 owns context binding writes

M07 (`knowledge_lifecycle`) is the sole writer of `private.context_bindings`. M14 (`project_continuity`) reads or authorizes and has zero direct write columns on that table. The owner accepts narrow business commands in the caller's transaction: insert with a `BindingGrant`, soft-revoke an already resolved binding ID under tenant and active predicates, or revoke a replacement restricted to TASK, scope ID and MANDATORY mode. The latter two change only `revoked_at`. M14 owns its grants and M09 owns its selection snapshots. Confirmation, quota, authorization, binding and audit retain their transaction boundary.

WRITER-OPEN1 implements the M07-only adapter and same-transaction collaboration with M14 and M09. The contract owners confirm exact columns and predicates. Its gate covers a single binding insert, wrong-scope replacement rejection, rollback leaving neither an orphan grant nor a consumed token, and snapshot/census consistency. The current ownership and write paths are in `docs/architecture/modules.toml` and `crates/adapters/src/context_repo.rs:1746–1835,1942,2014,2593–2666`.

### OPEN-1 amendment (2026-11-19)

This amendment narrows the implementation scope above. WRITER-OPEN1 #619 covers the M09 census write (historical key #4). The four keys below are **pinned-retained**, with exact entries in `xtask/hex_writer_baseline.txt` at `bac92292`. M07 remains the logical owner of `private.context_bindings`, and no second writer exists. The binding mutations remain in the existing shared adapter, where M14 authorizes bindings and owns the separate `private.task_binding_grants` table.

In the confirmed path, the caller consumes the token before applying mutations and commits the binding, applicable grant and Evidence, quota and audit together (`context_repo.rs:2593–2666`). A rollback leaves the token unconsumed and discards those writes. The two short non-confirmed wrappers retain their separate entry points.

| Historical key and exact baseline entry | Invariant | Reason for retaining the current location | Re-review trigger |
| --- | --- | --- | --- |
| #2 `crates/adapters/src/context_repo.rs:insert into private.context_bindings:1` | The sole INSERT requires a sealed `BindingGrant`, minted by M14's `authorize_*` functions in `crates/domain/src/context.rs`. A2 pins the INSERT to this SQL path (`xtask/src/architecture_check.rs:9443`). Confirmed inserts use the token transaction. | A direct move with that type adds M07 → M14, closing a cycle through the declared M14 → M07 edge in `docs/architecture/modules.toml`. The move also crosses the A2 path pin. | Re-review when a cycle-free contract preserves the sealed authorization and a replacement A2 pin still rejects out-of-path INSERT and unauthorized grant construction. HEX-WRITER must still reject a second binding INSERT. Require the confirmed rollback test to preserve token and write atomicity. |
| #3 `crates/adapters/src/context_repo.rs:insert into private.task_binding_grants:1` | A3b pins the grant INSERT (`xtask/src/architecture_check.rs:9548`). An adopted task instruction writes the grant alongside its binding and authorization Evidence in the token transaction. `REFERENCE_ONLY` creates a binding without a grant. | Moving the INSERT to an M14-only adapter would cross A3b's SQL path pin. The existing path keeps grant issuance inside the confirmed binding transaction. | Re-review when an M14 door and replacement A3b pin reject an out-of-path grant INSERT and prove that `REFERENCE_ONLY` creates no grant and a failed confirmation rolls back the binding, grant, Evidence and token consumption. |
| #5 `crates/adapters/src/context_repo.rs:update private.context_bindings:2` | Both soft revocations update only `revoked_at` and require the tenant and an active row. The internal door uses a resolved binding ID. Replacement also requires `TASK`, the matching scope ID and `MANDATORY`. Confirmed revocations use the token transaction and revoke any applicable grant with the binding. | Retained with #2 as the binding mutation group. Moving the revocations alone leaves the sealed INSERT and its A2 pin in the shared adapter and splits the group across adapter locations. Moving the whole group inherits #2's cycle and pin constraints. | Re-review with #2 when the owner door can enforce the same predicates and transaction boundary. Require a wrong-scope replacement to fail without revoking the binding or consuming its token. |
| #6 `crates/adapters/src/context_repo.rs:update private.task_binding_grants:1` | A3b pins the grant UPDATE (`xtask/src/architecture_check.rs:9548`). Replacement or unbind soft-revokes the active grant for the tenant and binding ID in the same transaction as binding revocation and token consumption, preserving I-NONINHERIT. | Moving the UPDATE to an M14-only adapter would cross A3b's SQL path pin. A separate transaction could leave a live grant on a revoked binding. | Re-review when a replacement A3b pin admits one M14 revocation door that proves atomic binding and grant revocation. Require a split-transaction negative control and a rollback check for the binding, grant and token. |

### Restricted writer retention (ADR-0130 close-out)

The four OPEN-1 rows above were recorded in #622. The remaining four keys below keep their exact `HEX-WRITER` entries at `8f4b631`. Each entry covers one existing statement with its current role and predicates.

| Exact baseline entry | Reason for retention and enforcing checks | Re-review trigger |
| --- | --- | --- |
| `crates/adapters/src/forget_repo.rs:update projection.stream_log:1` | The §37.2 maintenance tombstone transition sets only `state`, scoped by the full stream key and sequence. The terminal-state guard makes replay a no-op. Keep the transition on the deletion path alongside the distinct frozen-Evidence accept door in ADR-0092 D-C. `HEX-WRITER` pins the statement and the stream-log transition trigger restricts the maintenance role. | Re-review when a stream-owner command can preserve the full locator, terminal transition and retry behavior. Require replay to update zero rows and a wrong tenant or stream key to leave the target untouched. |
| `crates/adapters/src/maintenance_repo.rs:update control.partition_registry:1` | ADR-0063 D-K grants maintenance updates to `proposed_at` and `proposed_policy_revision` for candidacy under the effective latest policy. This keeps proposal and horizon read in one transaction and leaves detach/drop eligibility to the executor. `HEX-WRITER` pins the statement, column grants limit writes, and the retention integration test rejects stale or unproposed rows. | Re-review when a registry-owner command preserves the UTC cutoff, newest-leaf exclusion and policy-revision checks while keeping proposal separate from detach/drop. |
| `crates/adapters/src/stream_repo.rs:update private.ingest_tickets:1` | ADR-0123 D4 uses the maintenance role to expire a bounded, oldest-first batch of overdue `ISSUED` tickets for one tenant. Keeping the rows preserves the expected count. `HEX-WRITER` pins the statement, RLS scopes maintenance, and G-M21-4 (`ingest_ticket_expiry`) covers tenant isolation, concurrency and terminal states. | Re-review when an ingest-ticket owner door can preserve the database clock, limit, tenant scope, state guard and `SKIP LOCKED` behavior. Recheck the expected count after expiry. |
| `crates/testkit/src/fixture_purge.rs:delete from control.tenants:1` | The final tenant delete belongs to the atomic fixture purge after its FK and identity closure has been removed. `HEX-WRITER` pins the statement. The purge SQL requires an existing `e2e-` fixture and refuses a closure that reaches another tenant. This keeps privileged teardown in testkit. | Re-review when isolated test databases or a replacement fixture teardown preserve non-fixture and cross-tenant refusal, rollback, and orphan-free cleanup. |

### Rejected alternatives

A second independent writer breaks ADR-0130 D4 and makes the transaction ownership split difficult to reverse. A blanket file, module or edge exemption would allow subsequent imports to inherit an unrelated decision. Moving the pins would require replacing their structural proofs and negative controls. No equivalent replacement was established for these rows.

### Gate enforcement

G1′ freezes the exact existing back-edges reversed by a declared path in `xtask/hex_context_cycle_baseline.txt`. HEX-CONTEXT checks the union of declared dependencies and actual edges after excluding only still-applicable frozen back-edges. Both debt and exception imports participate in detection. The actual debt also includes `knowledge_lifecycle -> provider_execution` via the audit imports in `confirm_token_repo.rs` and `memory_governance_repo.rs`. That forms a two-edge cycle with the edge in the BYOK and scanner evidence exceptions. Their declared return path is given in each ruling. The frozen list is shrink-only, and a new symbol on an already frozen edge still needs its own disposition.

G2 (`HEX-CONTEXT-EXCEPTIONS`) requires every exception key to match an actual import, carry a reference present in a `docs/adr/0132-*.md` file and stay disjoint from the debt baseline. Each store is exact with its ceiling equal to the row count. After removing the accepted exception keys from the actual set, HEX-CONTEXT compares the remainder against the debt baseline. A removed import must leave its store and lower its ceiling. See `xtask/src/architecture_check.rs:1975–2140`.

A new exception requires a named ADR-0132 ruling for the exact import. In the same change, move the key from debt to the exception store with its ADR pointer and synchronize the two ceilings. This is the G2 path used for the final two authorization keys below.

### Pins that followed their definitions

- **#647, W1 continuity facet vocabulary.** The definition of `ContinuityFacetKind` moved from `crates/domain/src/continuity.rs` to `crates/domain/src/continuity_types.rs`, owned by `contract_kernel` in `docs/architecture/modules.toml`. W1 now requires `ALL: [Self; 15]` at that definition and checks the re-export at the original `domain::continuity` path (`xtask/src/architecture_check.rs:10433–10443,10486–10493` at `8f4b631`). The closed vocabulary stays at 15.
- **#631, deploy-check pool budget.** `pool_budget_every_binary_topology` follows the moved pool constructors from `consolidation-worker/src/main.rs` to `consolidation-worker/src/bootstrap.rs`. The expected count remains 5 (`bins/maintenance/src/deploy_check.rs:2241–2260` at `8f4b631`).

### ADR-0132 X-1

**Atomic attribution.**

Exact key: `crates/adapters/src/attribution_repo.rs:work_attribution->knowledge_lifecycle:humaux_adapters::memory_repo::MemoryAttribution`

The mandatory port and sole ladder implementation keep memory, evidence links and project attribution in the same transaction (`attribution_repo.rs:128`, `memory_repo.rs:190–239`, G-M29-5(a) at `architecture_check.rs:6100–6120`). Wrapping or relocating this port has no independent boundary to serve and risks changing insertion order. Re-review if the implementation or insert order changes. A second implementation, optional port or premature call must fail.

Alternatives rejected: Inverting or moving the attribution port would introduce another layer at the sole memory insert door and require re-proving the mandatory in-transaction call and its ordering.

### ADR-0132 X-2

**BYOK fingerprint hash.**

Exact key: `crates/adapters/src/byok.rs:provider_execution->knowledge_lifecycle:humaux_domain::evidence::payload_sha256`

BYOK derives its truncated fingerprint from the canonical hash (`byok.rs:163`). The private digest representation, controlled persisted-digest read-back and canonical hash share one owner (`crates/domain/src/evidence.rs:79,116,127`, G80-22). A second encoding or a primitive digest passed at the trust boundary would lose that proof. Re-review when an owner-provided digest interface preserves the private representation, byte equality, read-back and the existing BYOK fingerprint, or when a new symbol uses this edge. The accepted actual edge is `provider_execution -> knowledge_lifecycle`. Its declared return path is `knowledge_lifecycle -> retrieval_read_model -> provider_execution`.

Alternatives rejected: A digest port used only to compute this fingerprint would forward to the existing canonical hash, and a new `may_depend_on` edge would formalize the declared return cycle.

### ADR-0132 X-3

**Consolidation egress authorization.**

Exact key: `crates/adapters/src/consolidation_reasoner.rs:knowledge_curation->public_knowledge:humaux_adapters::contribution_reasoner::authorize_structured_egress`

`consolidation_reasoner.rs:637` calls the single authorization helper (`contribution_reasoner.rs:798`). Centralizing processor resolution and permit creation in the R3-pinned helper preserves the binding between admitted processor and egress. A second helper would duplicate that decision and its location proof. Re-review when a new owner can preserve resolver binding, one provider call and settlement, with negative controls for the wrong processor and a duplicate call.

Alternatives rejected: Moving the egress helper would invalidate the R3 location proof for processor-derived permits, and an authorization port here would forward the same operation without a separate boundary.

### ADR-0132 X-4

**Consolidation timed completion.**

Exact key: `crates/adapters/src/consolidation_reasoner.rs:knowledge_curation->public_knowledge:humaux_adapters::contribution_reasoner::complete_structured_timed`

`consolidation_reasoner.rs:674` calls the shared completion helper (`contribution_reasoner.rs:864`). The R3-pinned helper issues one provider call and captures its outcome for settlement. A separate timing wrapper around another provider call would duplicate that path and its proof. Re-review when a shared owner can retain resolver binding and settlement and reject a duplicate call.

Alternatives rejected: Moving the completion helper would require a replacement R3 proof for the single provider call, and an injected completion port would add a forwarding layer around the same call.

### ADR-0132 X-5

**Contribution source visibility.**

Exact key: `crates/adapters/src/contribution_entry_repo.rs:public_knowledge->retrieval_read_model:humaux_adapters::read_gate::visibility_readable`

`contribution_entry_repo.rs:182,325,340` routes the memory and its backing evidence through the shared visibility gate (Baseline §8.6). Local visibility logic would duplicate complete mediation and risk dropping an evidence check. Re-review if the caller can use `readable_memory_ids` and prove that any invisible backing evidence denies contribution, with the G-M08-2 token pin rechecked.

Alternatives rejected: Moving the pinned visibility call or copying the check into contribution code would require a new complete-mediation proof for both the Memory row and every backing Evidence row.

### ADR-0132 X-6

**Contribution entry stream module.**

Exact key: `crates/adapters/src/contribution_entry_repo.rs:public_knowledge->retrieval_read_model:humaux_adapters::stream_repo`

`contribution_entry_repo.rs:51,840` resolves the stream module for confirmation in the original transaction. Keep release/revoke and their outbox events in the same transaction, using G-M09-1's sequence allocator (`stream_repo.rs:150–155`). An independent allocator or a second transaction would break the allocator or atomicity contract. Re-review when M09 can serve ordinary and anonymous outbox events through a narrow caller-transaction command. A second `nextval` must fail the gate and rollback must leave no outbox row (sequence gaps are valid).

Alternatives rejected: A stream module port would expose broader internals than confirmation needs, and moving the sequence SQL would invalidate G-M09-1’s single-door check.

### ADR-0132 X-7

**Contribution entry sequence allocator.**

Exact key: `crates/adapters/src/contribution_entry_repo.rs:public_knowledge->retrieval_read_model:humaux_adapters::stream_repo::next_commit_seq`

`contribution_entry_repo.rs:840` calls the shared allocator for the confirmation outbox write. Keep release/revoke and their outbox events in the same transaction, using G-M09-1's sequence allocator (`stream_repo.rs:150–155`). An independent allocator or a second transaction would break the allocator or atomicity contract. Re-review when M09 can serve ordinary and anonymous outbox events through a narrow caller-transaction command. A second `nextval` must fail the gate and rollback must leave no outbox row (sequence gaps are valid).

Alternatives rejected: Inverting the allocator behind a port would only forward the caller transaction to the existing sequence door, while moving or duplicating `nextval` would break G-M09-1.

### ADR-0132 X-8

**Contribution release stream module.**

Exact key: `crates/adapters/src/contribution_repo.rs:public_knowledge->retrieval_read_model:humaux_adapters::stream_repo`

`contribution_repo.rs:30,149,213` resolves the stream module for release and revoke. Keep release/revoke and their outbox events in the same transaction, using G-M09-1's sequence allocator (`stream_repo.rs:150–155`). An independent allocator or a second transaction would break the allocator or atomicity contract. Re-review when M09 can serve ordinary and anonymous outbox events through a narrow caller-transaction command. A second `nextval` must fail the gate and rollback must leave no outbox row (sequence gaps are valid).

Alternatives rejected: An outbox port with an independent transaction would break atomicity for release and revoke, and a new `may_depend_on` edge would grant wider access than this shared sequence call requires.

### ADR-0132 X-9

**Contribution release sequence allocator.**

Exact key: `crates/adapters/src/contribution_repo.rs:public_knowledge->retrieval_read_model:humaux_adapters::stream_repo::next_commit_seq`

`contribution_repo.rs:149–163,213–253` allocates then writes the outbox before each commit. Keep release/revoke and their outbox events in the same transaction, using G-M09-1's sequence allocator (`stream_repo.rs:150–155`). An independent allocator or a second transaction would break the allocator or atomicity contract. Re-review when M09 can serve ordinary and anonymous outbox events through a narrow caller-transaction command. A second `nextval` must fail the gate and rollback must leave no outbox row (sequence gaps are valid).

Alternatives rejected: Moving the allocator into the release repository would break G-M09-1, and a forwarding allocator port would leave the ordinary and anonymous outbox writes in the same caller.

### ADR-0132 X-10

**Distill egress authorization.**

Exact key: `crates/adapters/src/distill_reasoner.rs:knowledge_curation->public_knowledge:humaux_adapters::contribution_reasoner::authorize_structured_egress`

`distill_reasoner.rs:750` calls the single authorization helper (`contribution_reasoner.rs:798`). Centralizing processor resolution and permit creation in the R3-pinned helper preserves the binding between admitted processor and egress. A second helper would duplicate that decision and its location proof. Re-review when a new owner can preserve resolver binding, one provider call and settlement, with negative controls for the wrong processor and a duplicate call.

Alternatives rejected: Moving authorization into Distill would duplicate the R3-pinned permit construction and require a second proof that egress uses the admitted processor.

### ADR-0132 X-11

**Distill timed completion.**

Exact key: `crates/adapters/src/distill_reasoner.rs:knowledge_curation->public_knowledge:humaux_adapters::contribution_reasoner::complete_structured_timed`

`distill_reasoner.rs:813` pins the shared completion future (`contribution_reasoner.rs:864`). The R3-pinned helper issues one provider call and captures its outcome for settlement. A separate timing wrapper around another provider call would duplicate that path and its proof. Re-review when a shared owner can retain resolver binding and settlement and reject a duplicate call.

Alternatives rejected: Moving completion into Distill would duplicate the R3-pinned provider invocation and require another proof that its outcome reaches settlement without a second call.

### ADR-0132 X-12

**Scanner evidence digest type.**

Exact key: `crates/local-secret-scan/src/lib.rs:provider_execution->knowledge_lifecycle:humaux_domain::evidence::EvidencePayloadSha256`

`crates/local-secret-scan/src/lib.rs:111,136,399` carries the typed evidence digest through sealing. The private digest representation, controlled persisted-digest read-back and canonical hash share one owner (`crates/domain/src/evidence.rs:79,116,127`, G80-22). A second encoding or a primitive digest passed at the trust boundary would lose that proof. Re-review when an owner-provided digest interface preserves the private representation, byte equality, read-back and the existing BYOK fingerprint, or when a new symbol uses this edge. The accepted actual edge is `provider_execution -> knowledge_lifecycle`. Its declared return path is `knowledge_lifecycle -> retrieval_read_model -> provider_execution`.

Alternatives rejected: Port inversion with a raw digest would discard the owner-minted evidence type, and a new `may_depend_on` edge would formalize the declared return cycle.

### ADR-0132 X-13

**Scanner evidence hashing.**

Exact key: `crates/local-secret-scan/src/lib.rs:provider_execution->knowledge_lifecycle:humaux_domain::evidence::payload_sha256`

`crates/local-secret-scan/src/lib.rs:361` hashes exactly the evidence bytes passed to the scanner. The private digest representation, controlled persisted-digest read-back and canonical hash share one owner (`crates/domain/src/evidence.rs:79,116,127`, G80-22). A second encoding or a primitive digest passed at the trust boundary would lose that proof. Re-review when an owner-provided digest interface preserves the private representation, byte equality, read-back and the existing BYOK fingerprint, or when a new symbol uses this edge. The accepted actual edge is `provider_execution -> knowledge_lifecycle`. Its declared return path is `knowledge_lifecycle -> retrieval_read_model -> provider_execution`.

Alternatives rejected: Moving or wrapping the canonical hash would either duplicate the G80-22 encoding or forward to the same owner, and a new `may_depend_on` edge would formalize the declared return cycle.

### ADR-0132 X-14

**Scanner profile fingerprint.**

Exact key: `crates/local-secret-scan/src/lib.rs:provider_execution->retrieval_read_model:humaux_retrieval::request::ProfileFingerprint`

`crates/local-secret-scan/src/lib.rs:378,415,477` carries the fingerprint into the seal. The private request types bind query bytes, the real profile and seal provenance (`crates/retrieval/src/request.rs:36,150,190,255,304`). A raw string or copied fingerprint would allow an untrusted profile to acquire a seal. Re-review if an owner-provided interface can carry the same unforgeable identity and still rejects wrong-profile and free-string inputs, or when a new symbol uses this edge. The accepted actual edge is `provider_execution -> retrieval_read_model`. Its declared return path is `retrieval_read_model -> provider_execution`.

Alternatives rejected: Passing a caller-supplied string through a port would lose the owner-minted profile identity, and a new `may_depend_on` edge would formalize the declared return cycle.

### ADR-0132 X-15

**Scanner trusted query.**

Exact key: `crates/local-secret-scan/src/lib.rs:provider_execution->retrieval_read_model:humaux_retrieval::request::TrustedRetrievalQuery`

`crates/local-secret-scan/src/lib.rs:461–478` takes text and profile from the same trusted query. The private request types bind query bytes, the real profile and seal provenance (`crates/retrieval/src/request.rs:36,150,190,255,304`). A raw string or copied fingerprint would allow an untrusted profile to acquire a seal. Re-review if an owner-provided interface can carry the same unforgeable identity and still rejects wrong-profile and free-string inputs, or when a new symbol uses this edge. The accepted actual edge is `provider_execution -> retrieval_read_model`. Its declared return path is `retrieval_read_model -> provider_execution`.

Alternatives rejected: A port carrying text and profile separately would lose their binding to the same trusted request, and a new `may_depend_on` edge would formalize the declared return cycle.

### ADR-0132 X-16

**Scanner projection card provenance.**

Exact key: `crates/local-secret-scan/src/lib.rs:provider_execution->retrieval_read_model:humaux_projection::card::RetrievalCard`

Classification row 370 moved from H after #608. The card's source fields are `pub(super)` (`crates/projection/src/card.rs:321–343`) and populated by `build_card` (`card.rs:420–500`) or `chunk_card` (`crates/projection/src/note_chunks.rs:277–305`). The scanner seals the builder-produced view and checks chunk/source identity and class (`crates/local-secret-scan/src/lib.rs:484–541`). A mutable DTO or duplicated builder would permit a mismatch between scanned text, source Memory and classification. Re-review on a new card constructor, changes to seal-bound fields or a new symbol on this edge. Test valid ordinary and chunk cards, wrong-source denial and external mutation rejection. The accepted actual edge is `provider_execution -> retrieval_read_model`. Its declared return path is `retrieval_read_model -> provider_execution`.

Alternatives rejected: A mutable transfer object or scanner-side builder would reopen the provenance defect fixed by #608, and a new `may_depend_on` edge would formalize the declared return cycle.

### ADR-0132 X-17

**Continuity workspace authorization.**

Exact key: `crates/adapters/src/continuity_repo.rs:project_continuity->identity_access:humaux_domain::identity::AuthorizationScope`

#628 and #655 leave this scope at the storage boundary. W1 requires the typed authorization and workspace narrowing on the adapter surface (`xtask/src/architecture_check.rs:10466–10475,10486–10493` at `8f4b631`). Publication narrows the caller's scope before the slot snapshot read, and the reader passes the scoped identity and allowed workspaces to the storage door (`continuity_repo.rs:233–253,391–410`). Keep the owning authorization value so a caller cannot supply an independently assembled workspace list. Re-review when a replacement contract can carry the same narrowed scope and a replacement W1 pin and negative control reject an out-of-scope workspace before any snapshot read.

### ADR-0132 X-18

**Contribution source authorization.**

Exact key: `crates/adapters/src/contribution_entry_repo.rs:public_knowledge->identity_access:humaux_domain::identity::AuthorizationScope`

#657 leaves the typed scope in the contribution adapter for X-5's visibility path. G-M08-2 pins `can_read` to the shared gate and counts the contribution adapter's `visibility_readable` tokens (`xtask/src/architecture_check.rs:6351–6384,6492–6496` at `8f4b631`). The same scope goes through the shared judgement for the source Memory and each backing Evidence row (`contribution_entry_repo.rs:175–193,325–357`). Keep the direct scope because the shared door consumes it and `can_read` must remain the sole judgement. Re-review with X-5 when `readable_memory_ids` or an owner contract preserves complete mediation and a negative control shows invisible backing Evidence still denies contribution.

## Consequences

The original ruling moved 16 keys from debt to the exception store. The close-out amendment moves the final two, leaving 18 exact exceptions, zero CONTEXT debt rows and two frozen back-edges. It authorizes zero new map edges and decouples zero source imports. Removing an accepted dependency shrinks its store and can retire a frozen back-edge when the last actual import on it disappears. All eight retained writer rows are documented above.
