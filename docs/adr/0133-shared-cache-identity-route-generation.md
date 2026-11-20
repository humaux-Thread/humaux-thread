# ADR-0133 — Shared cache storage and identity-owned route generation

Accepted · 2026-11-20 · M03-4-PRE. Source card M03-4 D4 and G-M03-4/-5. Baseline §§51, 67.2, 73.5.1, 78.1, 83.

## Cache and routing

Reuse the M12 weighted Moka region as an explicitly shared file. The retrieval wrapper keeps its tenant-keyed budgets, single-flight behavior and metrics. Identity will create a separate region in M03-4. Identity's inputs are the complete bounded bearer wire credential hashed with a purpose-separated HMAC key and verified live route tuples. A region can hold a hint while the caller is establishing the tenant. Identity and retrieval never share an instance or keys. This preserves the existing context graph.

A hint has the tenant, principal and routing generation from a successful §73.5.1 check. A hit can select a provisional route. Every invocation must verify the current credential, grant, epochs and route before application work or account charging. Any difference between the hint and live route invalidates the hint. A denial or failed live read cannot confirm a hint.

Evict a stale hint when visited, comparing the live route generation at that visit, and bound unused entries by TTL and byte weight. The gateway registry owns the enable flag, TTL and capacity (D4 ceiling 8 MiB within M12's process budget). An unvisited obsolete entry cannot authorize anything. Add a commit notification listener only if measured stale hints cause material provisional misrouting or displace valid hints within the configured budget. The live check remains mandatory with a listener.

## PostgreSQL ownership

Migration 0309 keeps one gateway-only credential lookup. The lookup projects the tenant's routing generation in the same statement as the credential binding and the existing live facts. The identity-owned tenant generation advances atomically with a revoke, removal or route-relevant credential change, including for both tenants if a binding moves. Tenant state and tenant security-epoch changes advance it in the same row. Membership, workspace and user lifecycle checks remain live for every PAT. The activity projection and verifier-only rehash do not advance the routing generation.

The migration-owner trigger advances only the tenant routing generation. The existing migration owner gets the corresponding FORCE RLS update policy. The trigger is not a runtime-callable write door and application-role grants stay as they are. Application rollback can retain the expanded lookup: existing callers select their existing named fields. Preserve the schema on rollback and forward-fix migration defects.

## Activity projection

The batch door accepts unique or repeated validated key IDs and stamps each eligible row once using the PostgreSQL statement clock. A row whose last stamp is inside the configured window is skipped, including when a concurrent writer advances it. M03-4 will aggregate due keys in memory and flush them via the adapter. The adapter sets asynchronous commit only for the local activity transaction.

The legacy single-key door stays callable in legacy mode, including the configured zero-second mode. The M03-4 gateway registry must refuse to enable batching with an interval below 60 seconds. The batch interval comes from trusted configuration, and the SQL door independently rejects a smaller value. The batch and legacy modes must not be mixed by a gateway. Lifecycle transactions retain their existing commit settings.

## Acceptance

PRE verifies the shared primitive, retained M12 behavior and the 0309 identity contracts against the isolated PG fixture, including generation change after committed revoke, rollback, wrong-tenant candidate rejection and activity-only update bounds. M03-4 adds the production routing and batching call sites and the original G-M03-4/-5 tests at the guarded entry point. The HEX baselines and architecture pins stay in place, with no new dependency edge.
