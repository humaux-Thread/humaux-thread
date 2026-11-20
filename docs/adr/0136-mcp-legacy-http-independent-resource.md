# ADR-0136 — MCP legacy HTTP as an independent resource

Accepted · 2026-11-20 · M26-LEGACY-WIRE. Baseline §§33.1, 33.6–8. See the [pinned Qwen Code test](https://github.com/QwenLM/qwen-code/blob/2421ad2c3b18d0efce6a50c7576d2c4c735ec644/packages/core/src/tools/mcp-client-v2.test.ts#L352-L445) and its [MCP SDK 1.32.2](https://registry.npmjs.org/@modelcontextprotocol%2fsdk/1.32.2).

## Decision

Provide a separate, default-off `/mcp/legacy` resource with a stateless Streamable HTTP Tools profile. Its independent codec negotiates `2025-06-18` from legacy initialize proposals and requires that exact version header on subsequent POSTs. Requests receive single JSON responses, notifications receive empty 202 responses, and GET and DELETE receive 405. The codec shares the canonical tool catalog, application port, authorization decisions and response contract with native `/mcp`.

With the configured public HTTPS origin `O`, use exactly these pairs. Both advertise the existing authorization server issuer and use the canonical scopes.

| Route | Resource and token audience | Protected resource metadata and challenge target |
| --- | --- | --- |
| Native | `O/mcp` | `O/.well-known/oauth-protected-resource/mcp` |
| Legacy | `O/mcp/legacy` | `O/.well-known/oauth-protected-resource/mcp/legacy` |

The gateway derives the trusted route context from the mount and configured origin. Clients explicitly select the legacy URL and obtain a grant for its exact resource. Authorization codes, grants, refresh tokens and access token audiences remain bound to that resource. The resource server rejects tokens presented to the other route. Service credentials retain their existing authorization semantics.

## Rationale and rollout

Separate routes keep version negotiation independent of resource selection. The Qwen sample negotiates down from `2025-11-25` and completes Tools requests over JSON POST. HTTP+SSE would add a second transport endpoint and a long-lived connection to the authorization and operating surface. Revisit it in a separate card if a required client can only complete the HTTP+SSE two-endpoint flow. Preserve its exact version, failure trace and successful comparison.

WIRE supplies the codec and replay. M26 discovery, M02-12 and M26-LEGACY-MOUNT supply the resource metadata, authorization and route wiring. Enable `HUMAUX_GATEWAY_MCP_LEGACY_ENABLED` only after the replay, discovery and authorization gates pass and the required independent client checks are recorded.

While the flag is off, `/mcp/legacy` and its protected-resource metadata return 404. New `/oauth/authorize` requests for the legacy resource are rejected. During the transition, code exchange and refresh continue to use the resource bound to the existing code or grant under the M02 contract. Any legacy access token remains unusable while the legacy route is closed and is rejected by the native route's exact-audience check. M02-TOKEN-RESOURCE-POLICY owns rejection of old code and refresh credentials after disablement, including after a subsequent re-enable.
