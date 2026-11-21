// Test documented redirect and AS behavior with the official MCP SDK. Never follow a hosted callback.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createRequire } from "node:module";

const require = createRequire(process.env.RUNNER_TEMP + "/oauth-npm/package.json");
const { discoverOAuthServerInfo, registerClient, startAuthorization } = require("@modelcontextprotocol/sdk/client/auth.js");

let stage = "discovery";
try {
    const origin = process.env.OAUTH_TEST_ORIGIN;
    const resource = `${origin}/mcp`;
    const redirect = process.argv[2];
    const info = await discoverOAuthServerInfo(resource);
    assert.equal(info.resourceMetadata?.resource, resource);
    assert.deepEqual(info.resourceMetadata.authorization_servers, [origin]);
    const metadata = info.authorizationServerMetadata;
    assert.equal(metadata?.issuer, origin);
    assert(metadata.code_challenge_methods_supported.includes("S256"));
    assert(metadata.token_endpoint_auth_methods_supported.includes("none"));

    stage = "public DCR";
    const clientInformation = await registerClient(origin, { metadata, clientMetadata: {
        client_name: "Humaux CI documented callback probe",
        redirect_uris: [redirect],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
    } });
    assert.deepEqual(clientInformation.redirect_uris, [redirect]);
    assert.equal(clientInformation.token_endpoint_auth_method, "none");
    assert(!clientInformation.client_secret);

    stage = "PKCE, redirect and RFC 8707 resource";
    const { authorizationUrl } = await startAuthorization(origin, {
        metadata, clientInformation, redirectUrl: redirect, resource, scope: "memory:write", state: randomUUID(),
    });
    assert.equal(authorizationUrl.searchParams.get("code_challenge_method"), "S256");
    assert.equal(authorizationUrl.searchParams.get("resource"), resource);
    async function request(overrides) {
        const url = new URL(authorizationUrl);
        for (const [key, value] of Object.entries(overrides)) url.searchParams.set(key, value);
        return fetch(url, { redirect: "manual" });
    }
    const valid = await request({});
    assert.equal(valid.status, 303);
    assert.equal(valid.headers.get("location"), "/auth/login");
    const invalid = await request({ redirect_uri: `${redirect}/ci-mismatch` });
    assert.equal(invalid.status, 400);
    assert.equal(invalid.headers.get("location"), null);
    for (const [overrides, error] of [[{ resource: `${resource}/ci-mismatch` }, "invalid_target"],
        [{ code_challenge_method: "plain" }, "invalid_request"]]) {
        const refusal = await request(overrides);
        assert.equal(refusal.status, 303);
        const location = new URL(refusal.headers.get("location"));
        assert.equal(`${location.origin}${location.pathname}`, redirect);
        assert.equal(location.searchParams.get("error"), error);
    }
} catch {
    process.stderr.write(`Documented OAuth probe failed: ${stage}\n`);
    process.exitCode = 1;
}
