# ADR-0076 — The cache layer: `humaux-cache` on moka, with its four metric families

- Status: Accepted (2026-10-15). Card M12-1 (module design M12 §2, §6 D1, D3, D4, D5, D7, §8 G-M12-1..5; this is the
  design note's ADR-M12-a).
- Relates to: Baseline §51, §51.1, §51.2, §51.3, §67.2, §41.2, §78.1; ADR-0061 D-A (hand-written encoder, seeded
  series); ADR-0074 (every crate carries a `module_ownership.toml` row and an edition).

## Context

§51 and §67.2 name an in-process `moka` cache with versioned keys and "failure is a miss plus a named metric", and
none existed: no `moka` in the lockfile, no key type, no metric. The first consumer is the query-embedding path of the
gateway (card M12-2); this card ships the crate and its gates without any consumer.

## Decision

- **D-A One crate, `humaux-cache` (home module M12, edition `core`).** `BoundedCache<K, V>` over
  `moka::future::Cache`; `moka` 0.12 with only the `future` feature. Weigher = key bytes + value bytes, TTL from
  `CacheConfig`, single-flight through `try_get_with`. The crate reads no configuration (§78.1): sizes arrive in
  `CacheConfig` (the config keys land with M12-2).
- **D-B Admission is per tenant and never evicts a neighbour.** The per-tenant byte total is charged, under one mutex,
  when a computed value is about to be inserted, and released by moka's eviction listener. An insert over
  `per_tenant_bytes` is not stored and counts `result=bypass`. A leader whose value is not admitted, or whose compute
  failed, stores nothing; callers that joined it compute for themselves (an `Err` is never shared or cached).
- **D-C Four §41.2 families, emitted from `telemetry::cache`.** `cache_requests_total{cache,result}`,
  `cache_evictions_total{cache,cause}`, `cache_bytes{cache}`, `cache_singleflight_waiters{cache}`. The counters live in
  `humaux-telemetry` (the G80-6 witness may depend on library crates only, and the scanner needs one `.inc(` / `.set(`
  per family), so `humaux-cache` depends on `humaux-telemetry`. `cache`, `result` and `cause` are closed enums; the
  `cache` set has one value (`embed_query`) until a second cache lands. `result=error` covers a failed compute and a
  cache-internal fault; both continue the request (§51.3). The families are not rendered by any process yet; the
  gateway wires `telemetry::cache::render` in M12-2.
- **D-D Keys.** `EmbeddingQueryKey` derives `Hash`/`Eq` over every field, so tenant, user, serving-generation
  fingerprint, dimension, mode and the exact input hash each separate entries (G-M12-1, G-M12-2).

## Consequences

- Gates G-M12-1..5 (`crates/cache/tests/`) plus four G80-6 witnesses (`crates/testkit/tests/metrics/cache_*.rs`).
- Ceilings, each marked `ponytail:` in `cache::bounded`: tenant accounting lags moka's maintenance, so a tenant near
  its cap may be bypassed slightly early; a caller cancelled between reservation and insert leaks its reservation
  until restart; waiters of a non-caching leader recompute instead of sharing the failure.
