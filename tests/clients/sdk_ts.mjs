// Real TS SDK transport, discovery/DCR/PKCE and refresh. The test supplies only client storage and a callback.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { promisify } from "node:util";

const require = createRequire(process.env.RUNNER_TEMP + "/oauth-npm/package.json");
const { Client } = require("@modelcontextprotocol/sdk/client/index.js");
const { StreamableHTTPClientTransport } = require("@modelcontextprotocol/sdk/client/streamableHttp.js");
const run = promisify(execFile);
const mcp = new URL(process.env.OAUTH_TEST_ORIGIN + "/mcp/legacy");

async function main() {
    let result;
    const listener = createServer((request, response) => {
        const query = new URL(request.url, "http://127.0.0.1").searchParams;
        result = { code: query.get("code"), error: query.get("error") };
        response.end("Callback received");
    });
    await new Promise(resolve => listener.listen(0, "127.0.0.1", resolve));

    const storage = {};
    const provider = {
        redirectUrl: `http://127.0.0.1:${listener.address().port}/callback`,
        clientMetadata: {
            client_name: "Humaux CI TypeScript SDK",
            redirect_uris: [`http://127.0.0.1:${listener.address().port}/callback`],
            grant_types: ["authorization_code", "refresh_token"],
            response_types: ["code"],
            token_endpoint_auth_method: "none",
            scope: "memory:write",
        },
        clientInformation: () => storage.client,
        saveClientInformation: info => { storage.client = info; },
        tokens: () => storage.tokens,
        saveTokens: tokens => { storage.tokens = tokens; },
        saveCodeVerifier: verifier => { storage.verifier = verifier; },
        codeVerifier: () => process.argv.includes("--wrong-verifier") ? "x".repeat(43) : storage.verifier,
        state: () => randomUUID(),
        redirectToAuthorization: async url => { await run(process.env.BROWSER, [url.href]); },
    };
    const transport = new StreamableHTTPClientTransport(mcp, { authProvider: provider });
    const connect = async (client, connection) => {
        await client.connect(connection);
        const catalog = await client.listTools();
        assert(catalog.tools.some(tool => tool.name === "remember"));
        const reply = await client.callTool({
            name: "remember",
            arguments: {
                operation: "put",
                content: "Synthetic OAuth SDK acceptance",
                workspace_id: process.env.OAUTH_TEST_WORKSPACE,
                idempotency_key: randomUUID(),
            },
        });
        assert(!reply.isError && typeof reply.structuredContent?.evidence_id === "string");
    };
    let stage = "first connect";
    try {
        const initial = new Client({ name: "humaux-ci-ts", version: "1.32.2" });
        try {
            await initial.connect(transport);
            throw new Error("fresh client skipped OAuth");
        } catch (error) {
            assert(error.constructor.name === "UnauthorizedError");
        }
        stage = "consent callback";
        assert(result?.code && !result.error);
        stage = "code exchange";
        await transport.finishAuth(result.code);
        stage = "first tools/list and remember";
        await connect(initial, transport);
        await initial.close();
        if (process.argv.includes("--refresh")) {
            stage = "expiry and automatic refresh";
            assert.equal(storage.tokens.expires_in, 300);
            await new Promise(resolve => setTimeout(resolve, 301_000));
            const retry = new StreamableHTTPClientTransport(mcp, { authProvider: provider });
            const refreshed = new Client({ name: "humaux-ci-ts", version: "1.32.2" });
            await connect(refreshed, retry);
            await refreshed.close();
        }
    } catch {
        process.stderr.write(`TypeScript SDK failed: ${stage}\n`);
        process.exitCode = 1;
    } finally {
        await transport.close();
        listener.close();
    }
}
main().catch(() => { process.exitCode = 1; });
