# ADR-0100 — In-process rate limiter and gateway singleton

- Status: Proposed (M03-2, 2026-10-26).
- Spec: §67.2, §72.3, §73.3, §78.1, §80.1; module_design_M03.md D1/D7/D8, row M03-2; lead rulings 4/4b.

## Context

The PG rate buckets add transactions to every gateway request. M03 D1 moves only rate decisions into the single gateway. Authentication, entitlement and quota authority stay with their existing doors. PG rate tables/functions remain until M03-3.

## Decision

Use atomic hierarchical token buckets for IP, credential, user, account and operation. New buckets receive one refill-second, capped at burst. ADR-0065 W-10 is preserved: canonical IPv4 remains unchanged; loopback `::1` and link-local `fe80::/10` retain /128 keys; other IPv6 uses the registered prefix. Five registered subject caps isolate IP, credential, user, account and operation (10,000 each). Pressure probes at most 32 entries per pressured tier using a rotating idle queue; only fully replenished unrequested buckets are evicted, otherwise capacity fails closed with 503, Retry-After and `rate_limit_rejected_total{scope="capacity"}`. The bounded probe ceiling may conservatively refuse despite an idle entry further in the queue; indexed idle deadlines are the upgrade path. Values live in the typed config registry (§78.1).

M03-3 amendment: a full IP tier still refuses logged-in users from a new IP at preflight, because per-tier caps protect only the postauth tiers.

Boot takes a session advisory lock over SHA-256 of a fixed label and the registered deployment value. A detached pool connection owns the lease and closes on Drop. Another gateway in the same deployment refuses boot with `Conflict`; the heartbeat checks that original session and returns `DependencyUnavailable` on loss, causing a nonzero process exit. Each heartbeat is bounded by the registered `HUMAUX_GATEWAY_SESSION_LOCK_TIMEOUT_SECONDS` (start 2 seconds); timeout is session loss. No SQLx type crosses the adapter boundary.

## Ceilings

Single gateway; restart loses bucket state and starts conservatively. Upgrade to two gateways plus Valkey when a second node is needed or certified gateway CPU exceeds 70% for 15 minutes. B23 account start values are burst 128/refill 20 per second; X-RATE replay remains owner-gated and UNCERTIFIED. The dedicated session adds one connection beyond the reusable pool ceiling (D8). `bins/maintenance/src/deploy_check.rs` validates deploy inputs and process isolation, but does not sum per-process pool maxima, so there is no aggregate there to amend; the future D8 budget gate must count gateway pool maximum + 1.

## Gates

- G-M03-1: `bins/gateway/tests/limiter.rs:42` — exact shared-account cap over 80 credentials. Red [40292383940](https://github.com/humaux/humaux-thread/actions/runs/40292383940): ignoring Account subjects admits 160 instead of 128; the gate assertion fails.
- G-M03-3: `bins/gateway/tests/singleton.rs:78` — actual second process refuses boot, distinct deployments boot, dead-session check and process failure. Red [40293224222](https://github.com/humaux/humaux-thread/actions/runs/40293224222): bypassing advisory acquisition boots two gateways; the second listener triggers the gate assertion.
- G-M03-9: `bins/gateway/tests/admission.rs:78` — policy 429/RATE_LIMITED versus capacity 503/Retry-After, with no handler call on refusal. Red [40293930856](https://github.com/humaux/humaux-thread/actions/runs/40293930856): policy status changed to 503; the gate requires 429 and fails.

## Review wiring receipts

- rv-317 item1a: [40310961957](https://github.com/humaux/humaux-thread/actions/runs/40310961957), source `c0d11eef6f03826f442d9cb88f25f827cdb3c699`. Removing only the guard's Account subject compiles, then `guard_limiter::g_m03_1_guard_wiring_all_five_tiers` fails its own account assertion at `bins/gateway/tests/support/guard_limiter.rs:118`: `[200,200,200]` rather than `[200,200,429]` (1 failed, 0 ignored). IP, credential and user cases ran before this assertion.
- rv-317 item1b: [40311942652](https://github.com/humaux/humaux-thread/actions/runs/40311942652), source `cd4849444ea6de52164e12a5539c3662a0f92581`. Dropping only the preflight IP charge compiles, then the same guard test fails its own IP assertion at `bins/gateway/tests/support/guard_limiter.rs:118`: `[200,200,401]` rather than `[200,200,429]` (1 failed, 0 ignored). The third request has no credential, so the lost pre-auth refusal reaches authentication instead.
- rv-317 item2: [40313407249](https://github.com/humaux/humaux-thread/actions/runs/40313407249), source `1fd77896778b2c171c04c9f4607d7e9c97eda02b`. Masking all IPv6 addresses compiles, then `adr_0065_w10_ip_identity_table` fails at `bins/gateway/tests/limiter.rs:136`: `fe80::1/2` collapse to `fe80::`, and `::1` to `::` (1 failed, 0 ignored). Canonical IPv4 and the global /64 rows remain unchanged.
