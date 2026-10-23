# ADR-0091 — Public withdrawals: three paths, one disclosure coordinator, one epoch

- Status: Accepted (2026-10-23). Card M20-1 (docs only), ADR-M20-d. The decisions are the design lead's record of module
  design note M20 v2 (D10' withdrawals, D11' coordinator, D12 deletion order) and of the owner's withdraw-all ruling;
  this ADR records them and does not re-decide. Code lands in M20-13 (W1, epoch), M20-14 (coordinator) and M20-15/-16
  (W2, W3, the port).
- Relates to: Baseline §13, §12.1.1, §14, §52, §57.1; ADR-0088 (toggle versus withdraw-all); ADR-0089 (pool epoch and
  data map); ADR-0090 (the serve predicate).

## Context

- §13 has one path, `ACTIVE -> REVOKED`, an append-only revocation fence and closure-based impact analysis. The pool
  serves through `public.servable_revision` (ADR-0090), which re-reads roots on every read.
- B33 found the coordinator in the design covered one outbound surface, and revocation must reach adopters' saved
  copies. M19's erase order matters: purge FKs block unless M20 revokes first (the D12 interface finding).
- The owner's ruling adds withdraw-all as a tenant-wide action, separate from the policy toggle (ADR-0088).

## Decisions

### D-A W1, normal withdrawal (one item or all)

The item or the tenant's roots are marked `WITHDRAWN` and `public.pool_epoch` is bumped; dependants are rebuilt from the
surviving roots. Copies already licensed under CC BY are not recalled: the licence is irrevocable and the licensor may
only stop distributing (CC FAQ), and the notice says so; adopters keep the copies they saved. A toggle is not W1.

### D-B W2, error correction

A new revision is created, the affected claim becomes `REFUTED` or is corrected, and adopters are notified through the
M22 notification door. The old revision is not rewritten in place.

### D-C W3, incident (privacy, IP, secret)

The object is immediately `SUSPENDED` through the coordinator, then the public text, its vectors and the adopters'
saved public snapshots are physically deleted (their own notes stay); content-free facts remain. Account erasure (M19)
is W3 for that tenant's roots. `UNSAFE` and `LICENCE_DISCLOSURE` feedback can trigger the W3 freeze check (ADR-0089
D-F); feedback never deletes a user's own note.

### D-D One coordinator owns every outbound surface

The single-node disclosure coordinator owns `public_read`, mixed recall, cards and exports. A write-preferring
`tokio::sync::RwLock` barrier spans hydrate to flush. A revoke `NOTIFY` makes the write guard drain in-flight reads,
then adopt `public.pool_epoch`, then write `ops.public_revocation_acks(revoke_event, boot_id)`. An ACK is written only
after the drain. A lost listener makes the public lane serve nothing through the existing `DegradeCode`; a reader never
serves with an unknown epoch. `ponytail:` one gateway; multi-node needs a new protocol, not per-boot ACKs alone.

### D-E Deletion order and idempotence

M20's `PublicRevocationPort::revoke_scope` runs **before** M19's purge, because the public FKs point at the private rows.
The port is idempotent on a restore re-apply; the core implementation returns `not_applicable: no public pool`.

### D-F The epoch is checked at serve time, not assumed

`public.pool_epoch` is the pool's current epoch. The serve predicate (ADR-0090 D-E) requires every root's own epoch,
payload sha and authorisation to match; a bumped epoch without a rebuilt serve set fails closed rather than serving a
mix of old and new roots.

## Consequences

- Positive: a withdrawal reaches every surface, not the read path only; adopters lose the public snapshot they saved
  (W3) while keeping their own notes; the CC BY limit is stated instead of being rediscovered; the M19 purge order is
  explicit.
- Cost: one global write-preferring barrier per process; a lost listener stops the public lane by design; multi-node is
  deferred with a named upgrade path.
- Neutral: nothing compiles or runs for this card; no gate, migration or code in this PR.

## Gates

Planned, implementer-owned, tri-state (§57.1); none exists in this PR:

| gate | owner card | injected fault | expected red |
|---|---|---|---|
| G-M20-12 withdrawals | M20-13 (W1), M20-15 (W2, W3) | W1 flips only the direct claim; W3 skips the adopter snapshot; W2 sends no notification | a dependant still servable; snapshot text remains; no notification row |
| G-M20-13 in-flight disclosure | M20-14 | skip the barrier on one surface; ACK before the drain | a response after the ACK contains a revoked unit |
| G-M20-14 lost listener | M20-14 | ignore the disconnect | the public lane serves with an unknown epoch |
| G-M20-15 erasure order | M20-16 | purge before revoke; keep lineage | an FK error; a census above 0; a servable object; a restore resurrects it |

Each needs its own inject → red → fix → green record (§80.1) in the implementing card. The drain budget is at most 2 s
at 80 concurrent reads (E-M20-3, M20-14); a missing database or input is a fail in CI, never `not_applicable` with exit
0 (ADR-0050).

## Open

- **U6** the `DegradeCode` for an unknown epoch is picked from the frozen set in §52; no new variant and no third error
  enum. The implementing card chooses from the existing variants.
- The multi-node protocol is deferred: one gateway is the shipped ceiling (`ponytail:` D-D).

## Owner-gated (listed, not decided)

Publishing real tenant content in production, and therefore any real-tenant W3 run before M20 go-live; M20 go-live as a
whole (after all modules, per the charter).

## Alternatives rejected

Recalling copies already licensed under CC BY (the licence is irrevocable); keeping adopter snapshots on W3 (the public
text must be physically deleted; the adopter's own note stays); purging private rows before the M20 revoke (FK order);
letting the coordinator cover one outbound surface only; per-boot ACKs as the multi-node protocol.

## References

Module design note M20 v2, D10' to D12', §8, §10, §12; batch-33 public-pool research digest (B33); Baseline §13,
§12.1.1, §14, §52, §57.1; ADR-0088; ADR-0089; ADR-0090; the CC FAQ on licence irrevocability (R4 in ADR-0088 is open).
