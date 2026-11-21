// Exercise the pinned Gemini core provider directly. The SDK only sends authorized MCP tool traffic.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { setTimeout } from "node:timers/promises";
import { pathToFileURL } from "node:url";

let stage = "load provider";

async function main() {
    const providerPath = pathToFileURL(process.argv[2]);
    const { MCPOAuthProvider } = await import(providerPath);
    const { MCPOAuthTokenStorage } = await import(new URL("./oauth-token-storage.js", providerPath));
    const require = createRequire(process.env.RUNNER_TEMP + "/oauth-npm/package.json");
    const { Client } = require("@modelcontextprotocol/sdk/client/index.js");
    const { StreamableHTTPClientTransport } = require("@modelcontextprotocol/sdk/client/streamableHttp.js");
    const url = new URL(process.env.OAUTH_TEST_ORIGIN + "/mcp/legacy");
    const name = "humaux-ci-gemini";
    let credentials;
    const storage = {
        async saveToken(_name, token, clientId, tokenUrl, mcpServerUrl) {
            credentials = { token, clientId, tokenUrl, mcpServerUrl };
        },
        async getCredentials() {
            return credentials;
        },
        async deleteCredentials() {
            credentials = undefined;
        },
        isTokenExpired: MCPOAuthTokenStorage.prototype.isTokenExpired,
    };
    const provider = new MCPOAuthProvider(storage);

    async function remember(token) {
        assert(token);
        const transport = new StreamableHTTPClientTransport(url, {
            requestInit: { headers: { Authorization: `Bearer ${token}` } },
        });
        const client = new Client({ name, version: "0.38.2" });
        try {
            await client.connect(transport);
            const list = await client.listTools();
            assert(list.tools.some(tool => tool.name === "remember"));
            const reply = await client.callTool({
                name: "remember",
                arguments: {
                    operation: "put",
                    content: "Synthetic Gemini OAuth acceptance",
                    workspace_id: process.env.OAUTH_TEST_WORKSPACE,
                    idempotency_key: randomUUID(),
                },
            });
            assert(!reply.isError && typeof reply.structuredContent?.evidence_id === "string");
        } finally {
            await client.close();
        }
    }

    stage = "provider authorize and exchange";
    const initial = await provider.authenticate(name, { enabled: true, scopes: ["memory:write"] }, url.href);
    assert(credentials.token.refreshToken && credentials.token.expiresAt);
    stage = "first tools/list and remember";
    await remember(initial.accessToken);
    await setTimeout(Math.max(credentials.token.expiresAt - Date.now(), 0) + 1000);
    stage = "expiry and automatic refresh";
    await remember(await provider.getValidToken(name, { clientId: credentials.clientId }));
}

main().catch(() => {
    process.stderr.write(`Gemini CLI failed: ${stage}\n`);
    // A failed provider can leave its loopback listener alive.
    process.exit(1);
});
