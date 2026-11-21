"""Drive the pinned Qwen ACP and Kimi terminal clients with a loopback model."""

import asyncio
from contextlib import suppress
from itertools import count
import json
import os
import signal
from urllib.parse import urlsplit

from model_stub import KEY, MODEL


SERVER = "humaux_ci"
PROMPT = "Use the humaux_ci remember tool to store one synthetic CI fact."


def local_env(env):
    # Node and Kimi honor these proxies. The model, gateway and callbacks use NO_PROXY.
    proxy = "http://127.0.0.1:1"
    bypass = "localhost,127.0.0.1,::1"
    return {**env, "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "ALL_PROXY": proxy,
            "http_proxy": proxy, "https_proxy": proxy, "all_proxy": proxy,
            "NO_PROXY": bypass, "no_proxy": bypass, "NODE_USE_ENV_PROXY": "1"}


def select_tool(model, name):
    model.wanted = name
    model.emitted = False


def completed_auth(events):
    return any(event in events for event in (("code", True), ("consent denied", True)))


async def qwen_probe(executable, workspace, url, env, model, events, ttl):
    home = workspace / "qwen"
    home.mkdir()
    (home / "settings.json").write_text(json.dumps({
        "security": {"auth": {"selectedType": "openai"}, "folderTrust": {"enabled": False}},
        "model": {"name": MODEL},
        "modelProviders": {"openai": [{"id": MODEL, "envKey": "OPENAI_API_KEY", "baseUrl": model.url}]},
        "tools": {"visible": [f"mcp__{SERVER}__remember"]},
        # Dynamic discovery uses the client ID Qwen saved during DCR when refreshing.
        "mcpServers": {SERVER: {"httpUrl": url, "trust": True}},
    }))
    env = {**local_env(env), "QWEN_HOME": str(home), "QWEN_RUNTIME_DIR": str(workspace / "runtime"),
           "OPENAI_API_KEY": KEY, "OPENAI_BASE_URL": model.url, "QWEN_USAGE_STATISTICS_ENABLED": "false"}
    process = await asyncio.create_subprocess_exec(
        executable, "--acp", "--approval-mode", "yolo", cwd=workspace, env=env,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        limit=4 * 1024 * 1024, start_new_session=True,
    )
    ids = count(1)

    async def request(method, params):
        number = next(ids)
        message = {"jsonrpc": "2.0", "id": number, "method": method, "params": params}
        process.stdin.write((json.dumps(message) + "\n").encode())
        await process.stdin.drain()
        async with asyncio.timeout(40):
            while line := await process.stdout.readline():
                response = json.loads(line)
                if response.get("id") == number and "method" not in response:
                    return response
        return {}

    async def wait_for(predicate):
        async with asyncio.timeout(35):
            while not predicate():
                if process.returncode is not None:
                    raise EOFError
                await asyncio.sleep(.15)

    stage = "ACP initialize"
    try:
        initial = await request("initialize", {"protocolVersion": 1, "clientCapabilities": {}})
        if "result" not in initial:
            return "FAIL", stage + " returned no result"
        stage = "ACP session/new with configured provider"
        session = await request("session/new", {"cwd": str(workspace), "mcpServers": []})
        session_id = session.get("result", {}).get("sessionId")
        if not session_id:
            message = session.get("error", {}).get("message", "")
            if "Use /auth to sign in or configure a model first." in message:
                return "not_applicable", "Pinned public ACP refused session/new despite configured local OpenAI provider"
            return "FAIL", stage + " returned no session"
        stage = "Qwen native OAuth"
        auth = await request("qwen/control/workspace/mcp/manage", {"serverName": SERVER, "action": "authenticate"})
        if "result" not in auth and not completed_auth(events):
            code = auth.get("error", {}).get("code")
            return "FAIL", f"{stage} returned RPC error {code if type(code) is int else 'unknown'}"
        await wait_for(lambda: completed_auth(events))
        if ("consent denied", True) in events:
            return "FAIL", "Native OAuth denial"
        stage = "Qwen tool discovery"
        await wait_for(lambda: ("tools/list", True) in events)
        # The wire reply arrives before Qwen registers its tools for model turns.
        for _ in range(16):
            catalog = await request("qwen/status/workspace/mcp/tools", {"serverName": SERVER})
            if any(tool.get("name") == f"mcp__{SERVER}__remember" for tool in catalog.get("result", {}).get("tools", [])):
                break
            await asyncio.sleep(.2)
        else:
            return "FAIL", "Qwen native catalog did not contain remember"
        for attempt in (1, 2):
            stage = "Qwen tool turn" if attempt == 1 else "Qwen post-expiry tool turn"
            select_tool(model, "remember")
            for _ in range(3):
                result = await request("session/prompt", {"sessionId": session_id,
                                       "prompt": [{"type": "text", "text": PROMPT}]})
                if "result" not in result:
                    return "FAIL", stage + " returned no result"
                # An early model turn may see the pre-auth catalog. Never replay a tool request.
                if model.emitted:
                    break
                await asyncio.sleep(.3)
            if attempt == 1:
                if ("tools/call", True) not in events:
                    return "FAIL", stage + " produced no successful remember call"
                await asyncio.sleep(ttl + 1)
                stage = "Qwen MCP reconnect after expiry"
                # The transport captures a bearer at connection time. Native reconnect
                # resolves and refreshes the stored credentials without test-side token access.
                await request("qwen/control/workspace/mcp/restart", {"serverName": SERVER})
        return "PASS", "Qwen ACP prompts used the local provider"
    except (OSError, ValueError, TimeoutError, EOFError):
        return "FAIL", stage + " did not complete"
    finally:
        # The npm launcher spawns the ACP process, which inherits the pipe.
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        await process.wait()


async def kimi_probe(executable, workspace, url, env, model, events, ttl):
    home = workspace / "kimi"
    home.mkdir()
    (home / "mcp.json").write_text(json.dumps({"mcpServers": {SERVER: {"url": url}}}))
    (home / "config.toml").write_text('default_permission_mode = "yolo"\n')
    env = {**local_env(env), "KIMI_CODE_HOME": str(home),
           "KIMI_MODEL_NAME": MODEL, "KIMI_MODEL_PROVIDER_TYPE": "openai", "KIMI_MODEL_API_KEY": KEY,
           "KIMI_MODEL_BASE_URL": model.url, "KIMI_MODEL_CAPABILITIES": "tool_use",
           "KIMI_DISABLE_TELEMETRY": "1", "KIMI_CODE_NO_AUTO_UPDATE": "1"}
    expected_origin = env["OAUTH_TEST_ORIGIN"]

    async def turn(prompt, oauth=False):
        process = await asyncio.create_subprocess_exec(
            executable, "-p", prompt, "--output-format", "stream-json", cwd=workspace, env=env,
            stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE, limit=4 * 1024 * 1024, start_new_session=True,
        )
        opened = False
        try:
            async with asyncio.timeout(65 if oauth else 40):
                while line := await process.stderr.readline():
                    # Kimi print mode reports the native tool's URL on its own line.
                    # Only pass the exact fixture's authorize URL to the existing browser shim.
                    address = line.decode(errors="replace").strip()
                    if not oauth or opened or not address.startswith(expected_origin + "/oauth/authorize?"):
                        continue
                    parsed = urlsplit(address)
                    if parsed.fragment or not parsed.query or any(char.isspace() for char in address):
                        continue
                    opened = True
                    browser = await asyncio.create_subprocess_exec(
                        env["BROWSER"], address, env=env, stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    if await browser.wait():
                        return False
                return await process.wait() == 0
        finally:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            await process.wait()

    stage = "Kimi native MCP login"
    try:
        select_tool(model, "authenticate")
        completed = await turn("/mcp-config login humaux_ci", oauth=True)
        if not completed or ("code", True) not in events:
            if (completed and model.turns and not model.emitted and
                    not any(key == "authorize" for key, _ in events)):
                return "not_applicable", "Kimi reached its local model but exposed no MCP authenticate tool and sent no authorize request"
            return "FAIL", stage + " did not complete"
        for attempt in (1, 2):
            stage = "Kimi tool turn" if attempt == 1 else "Kimi post-expiry tool turn"
            select_tool(model, "remember")
            if not await turn(PROMPT) or events.count(("tools/call", True)) < attempt:
                return "FAIL", stage + " produced no successful remember call"
            if attempt == 1:
                await asyncio.sleep(ttl + 1)
        return "PASS", "Kimi native print mode used the local provider"
    except (OSError, ValueError, TimeoutError, EOFError):
        return "FAIL", stage + " did not complete"
