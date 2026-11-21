// The official ZCode adapter owns the OAuth lifecycle and MCP traffic for this row.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { setTimeout } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

let stage = "load built adapter";

async function main() {
    const source = pathToFileURL(process.argv[2] + "/");
    const { createMcpAdapter } = await import(new URL("mcp/index.js", source));
    const { createSharedZCodeCredentialStore } = await import(new URL("auth/shared-credentials.js", source));
    const name = "humaux-ci-zcode";
    const adapter = createMcpAdapter({
        workingDirectory: process.env.RUNNER_TEMP,
        mcpOAuth: {
            credentialStore: createSharedZCodeCredentialStore({
                filePath: process.env.RUNNER_TEMP + "/oauth-zcode-credentials.json",
            }),
            authorizationTimeoutMs: 45000,
            async openAuthorizationUrl({ authorizationUrl }) {
                await promisify(execFile)(process.env.BROWSER, [authorizationUrl]);
            },
        },
    });

    async function remember() {
        const reply = await adapter.callTool({
            serverName: name,
            toolName: "remember",
            arguments: {
                operation: "put",
                content: "Synthetic ZCode OAuth acceptance",
                workspace_id: process.env.OAUTH_TEST_WORKSPACE,
                idempotency_key: randomUUID(),
            },
        });
        assert(!reply.isError && typeof reply.structuredContent?.evidence_id === "string");
    }

    try {
        stage = "connect and authorize";
        const status = await adapter.connectServer(name, {
            type: "http",
            url: process.env.OAUTH_TEST_ORIGIN + "/mcp/legacy",
            timeoutMs: 50000,
            protocolVersion: "legacy",
            oauth: { type: "authorization_code", scope: "memory:write" },
        });
        assert.equal(status.status, "connected");
        stage = "first tools/list and remember";
        assert((await adapter.listTools()).some(tool => tool.name === "remember" || tool.toolName === "remember"));
        await remember();
        await setTimeout(301000);
        stage = "expiry and automatic refresh";
        await remember();
    } finally {
        await adapter.close();
    }
}

main().catch(error => {
    process.stderr.write(`ZCode adapter failed: ${stage}\n`);
    if (stage === "load built adapter" && ["ERR_MODULE_NOT_FOUND", "ERR_DLOPEN_FAILED",
        "ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX", "ERR_PACKAGE_PATH_NOT_EXPORTED"].includes(error?.code)) {
        process.stderr.write(`ZCode adapter loader: ${error.code}\n`);
    }
    process.exit(1);
});
