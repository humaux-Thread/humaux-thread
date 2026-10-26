# ADR-0125 — The auth server lives in the gateway; sign-in is a passwordless email-code page

- Status: Accepted (2026-10-27, lead, under charter). Card M02-7 (`/auth/*` SSR pages and logout; gate G-M02-3, HTTP
  half). Content authority: module design note M02 D1 (:101-104), D2 (:105-110), D6 (:123-128), D9 (:140) and D10
  (:149-155); G-M02-3 (:172) and card row M02-7 (:197). D1 and D2 are the placeholders the note called ADR-M02-a and
  ADR-M02-b; this ADR is both. It records those decisions and re-decides none of them; the rulings below are the
  lead's for this card.
- Relates to: Baseline §72.3, §73.2, §73.6, §74.2, §74.3, §78.1, §83; ADR-0059 D-G (token keys), ADR-0065 D-C
  (admission), ADR-0100 (pre-auth IP tier), the M02-3 auth MAC key, M02-4 (email door), M02-5 (login doors), M02-6
  (console session and signed CSRF).

## Context

- M02 owns who the caller is. The gateway already holds the pieces of a login — `login_repo::{start, verify_code}`
  (M02-5), `session_repo::{issue, authenticate, revoke}`, `application::session::csrf_token` and `protocol::edge::
  verify_csrf` (M02-6), the auth MAC key (M02-3) and the outbox (M02-4) — but nothing in the process speaks HTTP to a
  browser: there is no `/auth/*` route (note :44-46).
- The pre-auth guard is `GatewayGuard::preflight` (network policy, then the `Subject::Ip` bucket). It was bound to the
  MCP request context, which has no public constructor, so a second HTTP surface had no way in.
- The gateway had no configuration for the origin a console POST comes from, the sender of the login mail, the key of
  login codes or the enqueue-time recipient allowlist.

## Decisions

### D1  AS and RS in one gateway process, two namespaces (ADR-M02-a, note :101-104)

One 4-vCPU node gains nothing from a second process. M02 owns `/oauth/*`, `/auth/*` and the AS metadata; M26 owns the
`/mcp` 401, `WWW-Authenticate` and the protected-resource metadata. `/auth/*` is a router (`gateway::auth_pages`)
merged onto the MCP router before admission wraps it, so both share the body bound, the concurrency cap and the queue.
It exists only while `HUMAUX_GATEWAY_AUTH_SURFACE_ENABLED` is true.

Rejected (note :103-104): a separate auth binary (a second release unit and a second pool); M26 owning the AS (an L6
module would own the credential tables).

### D2  Login is an email one-time code, one flow for sign-up and sign-in (ADR-M02-b, note :105-110)

`POST /auth/login` → `login_repo::start`; `POST /auth/code` → `login_repo::verify_code`, then `session_repo::issue`;
`POST /auth/logout` → CSRF verify, then `session_repo::revoke`. It matches the old system's flow, so migrated users
sign in with no password import; the uniform response keeps accounts unenumerable (D273).

Rejected (note :109-110): email plus password first (it needs an old-hash import or a reset wave for every migrated
user; the pure password code stays, unwired, until Q1).

### D3  "The M03 AUTH class" is the existing pre-auth IP tier

There is no new limiter class. `GatewayGuard::preflight_peer(request_id, peer_ip, forwarded, surface)` is the one
entry; `preflight(&McpHttpContext)` is a one-line caller of it. Every `/auth/*` request passes it exactly once, in the
router's outermost layer, before any handler, and a refusal is audited with `resource_id = "auth"`. Denials map to
403, 429 and 503 pages.

### D4  Routes and the value that travels between the two steps

`GET|POST /auth/login`, `GET|POST /auth/code`, `POST /auth/logout`. A start answers one `303` to `/auth/code` for an
unknown, a cooling-down and an issued mailbox; its only variable part is a `__Host-humaux_login` cookie holding
`hex(expiry ‖ canonical mailbox)` signed under the auth key with its own label (`application::signed_token`, label
`humaux.login_pending.v1`), `Max-Age` = the challenge TTL. The mailbox is never in a URL and never in HTML. A code
page without a live cookie redirects to `/auth/login`; a code POST without one is the same rejection as a wrong code.

### D5  No enumeration

`POST /auth/login` answers the same status, headers and body for every mailbox; the cookie value is a function of the
submitted address and the clock, never of the account. Every failed code attempt — wrong, consumed, expired, over the
cap, malformed, no pending cookie — is the one `400` rejection page. The existing ponytail of `login_repo::start` (the
unknown path is one statement faster) stands; its upgrade path is a fixed latency floor.

### D6  Cookies and CSRF

The session cookie is `__Host-humaux_session`, `Secure; HttpOnly; SameSite=Lax; Path=/`, no `Domain`, `Max-Age` from
`SessionPolicy::absolute_ttl`. Every `POST /auth/*` requires the request's `Origin` — its `Referer` when `Origin` is
absent — to equal the configured public origin, else `403` (login CSRF), checked before the body is read or a row is
written. `null`, a repeated `Origin` and a Referer that merely starts with the origin's text all fail. `POST
/auth/logout` additionally needs the M02-6 token for the caller's own session in `x-humaux-csrf-token` and a
`Sec-Fetch-Site` of `same-origin` or `none` (`protocol::edge::verify_csrf`); without them the session stays live.

### D7  Response hardening

On every `/auth/*` response, refusals included: `Cache-Control: no-store`; `Content-Security-Policy: default-src
'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`; `X-Content-Type-Options:
nosniff`; `Referrer-Policy: same-origin`. The pages are semantic HTML (`lang`, `label for`, `autocomplete="email"` /
`"one-time-code"`, `inputmode="numeric"`), no script, no stylesheet, and echo no dynamic text, so nothing needs
escaping.

**Deviation from the ruling's wording, for the lead's veto.** The ruling named `Referrer-Policy: no-referrer`. Under
`no-referrer` a browser serializes the `Origin` of a form POST as `null` (Fetch, "append a request `Origin` header")
and sends no `Referer`, so the D6 check would refuse every real sign-in while every test over a raw socket stayed
green. `same-origin` sends nothing to any other origin, which is the property the header is for. Reverting is the
`REFERRER_POLICY` constant and one assertion in `auth_pages.rs`.

### D8  Configuration (ruling 8)

| key | kind | rule |
|---|---|---|
| `HUMAUX_GATEWAY_PUBLIC_BASE_URL` | value | M02 D9 `PUBLIC_BASE_URL` (note :140). An absolute `https` origin, lowercased, no path; `http` only for `localhost`, `127.0.0.1`, `[::1]`. Not `HUMAUX_GATEWAY_ALLOWED_ORIGINS`, the MCP Host/Origin allowlist. Prod `https://humaux.com`. |
| `HUMAUX_GATEWAY_LOGIN_MAIL_FROM` | value | A bare address. Owner-provided; blank in prod values. |
| `HUMAUX_GATEWAY_LOGIN_CODE_PEPPER` | secret, hex | ≥ 32 bytes and equal to no byte of the credential pepper pair, the consistency-token keys or the auth keys: login codes and API keys rotate independently. Placeholder in `render-secrets.sh`, no value in git. |
| `HUMAUX_GATEWAY_EMAIL_RECIPIENT_ALLOWLIST` | value, CSV | `adapters::email::RecipientAllowlist`, applied at enqueue. M02-4 defined no key for it. Blank allows everyone: the registry cannot tell unset from blank, the sink is the default mode, and the sender enforces the list again at send time. |

All four may be blank while the surface is off (prod stays off); once `HUMAUX_GATEWAY_AUTH_SURFACE_ENABLED` is true
bootstrap refuses to start without the first three, naming the key, and `deploy-check --env` reports `secret_empty`,
`secret_short` and `value_empty` — the M02-3 pattern. The email mode and sink directory are keys of the process that
sends mail (M22-2's worker); the gateway only enqueues, so it gets neither and no test here sends or can send mail.
The subject of the mail is code-level English copy; the body is built by the sender from `template_id` and payload.

The post-login target is the route constant `/` (a path is code, not §78.1 business config); the TTLs and the attempt
cap are `AuthConfig::default()`, the registry default, until a config card names keys for them.

## Consequences

- ponytail: unstyled forms, visual layer lands with the console design-system card (audit-first). The pages are
  functional placeholders for the OAuth flow's end-to-end test (M02-10).
- ponytail: English copy only; i18n arrives with the console card's message catalogue.
- ponytail: console mounts at `/` until the M26 console card names its root; upgrade is that card's constant.
- ponytail: the CSRF token travels in a header only (M02-6), so the logout control is a `fetch` of the console, not a
  bare `<form>`; the page that renders it belongs to M26.
- The configured origin is compared byte for byte; write it as a browser serializes it (no default port).
- `preflight_peer` shares `resource_type = MCP_OPERATION` in the audit row with `/mcp`; `resource_id` tells the surfaces
  apart.

## Gates and red records

- G-M02-3 (HTTP half), `bins/gateway/tests/auth_pages.rs`: `g_m02_3_existing_cooling_down_and_unknown_mailbox_answer_identically`
  (a), `g_m02_3_correct_code_sets_the_session_cookie_and_the_session_authenticates` (b),
  `g_m02_3_consumed_code_replayed_is_rejected` and `g_m02_3_attempt_after_the_cap_is_rejected_even_with_the_right_code`
  (c), `g_m02_3_post_without_the_configured_origin_is_forbidden_and_writes_nothing` (d),
  `g_m02_5_logout_needs_the_session_bound_csrf_token` (e), `g_m02_3_every_route_carries_the_hardening_headers` (f),
  `g_m03_1_the_pre_auth_limiter_applies_to_the_auth_pages` (g). The bootstrap and `deploy_check` rules above are pinned
  by `auth_page_values_are_required_validated_and_distinct_when_the_surface_is_on`, `public_origin_is_strict_and_normalized`
  and `env_login_values_are_required_only_when_the_auth_surface_is_on`.
- Red records (targeted runs on throwaway branches, deleted after recording; each failed on the gate's own assertion):
  - r1 (unknown mailbox answers 404): pending.
  - r2 (Origin check dropped): pending.
  - r3 (`HttpOnly` dropped from the session cookie): pending.
  - r4 (logout skips the CSRF verify): pending.
  - Green: the PR's CI on the unmutated branch.
