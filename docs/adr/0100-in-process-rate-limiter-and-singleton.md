# ADR-0100 — In-process rate limiter and gateway singleton

- Status: Proposed (M03-2, 2026-10-26).
- Spec: §67.2, §72.3, §73.3, §78.1, §80.1; module_design_M03.md D1/D7/D8, row M03-2; lead rulings 4/4b.

## Context

The PG rate buckets add transactions to every gateway request. M03 D1 moves only rate decisions into the single gateway. Authentication, entitlement and quota authority stay with their existing doors. PG rate tables/functions remain until M03-3.

## Decision

Use atomic hierarchical token buckets for IP, credential, user, account and operation. New buckets receive one refill-second, capped at burst. The subject cap evicts only fully replenished idle buckets; pressure otherwise fails closed. Values live in the typed config registry (§78.1).

Boot takes a session advisory lock over SHA-256 of a fixed label and the registered deployment value. A detached pool connection owns the lease and closes on Drop. Another gateway in the same deployment refuses boot with `Conflict`; the heartbeat checks that original session and returns `DependencyUnavailable` on loss, causing a nonzero process exit. No SQLx type crosses the adapter boundary.

## Ceilings

Single gateway; restart loses bucket state and starts conservatively. Upgrade to two gateways plus Valkey when a second node is needed or certified gateway CPU exceeds 70% for 15 minutes. B23 account start values are burst 128/refill 20 per second; X-RATE replay remains owner-gated and UNCERTIFIED. The dedicated session adds one connection beyond the reusable pool ceiling (D8).

## Gates

- G-M03-1: `bins/gateway/tests/limiter.rs:42` — exact shared-account cap over 80 credentials. Red [40292383940](https://github.com/humaux/humaux-thread/actions/runs/40292383940): ignoring Account subjects admits 160 instead of 128; the gate assertion fails.
- G-M03-3: `bins/gateway/tests/singleton.rs:78` — actual second process refuses boot, distinct deployments boot, dead-session check and process failure. Red [40293224222](https://github.com/humaux/humaux-thread/actions/runs/40293224222): bypassing advisory acquisition boots two gateways; the second listener triggers the gate assertion.
- G-M03-9: `bins/gateway/tests/admission.rs:78` — policy 429/RATE_LIMITED versus capacity 503/Retry-After, with no handler call on refusal. Red [40293930856](https://github.com/humaux/humaux-thread/actions/runs/40293930856): policy status changed to 503; the gate requires 429 and fails.
