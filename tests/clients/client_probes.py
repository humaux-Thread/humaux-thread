"""Drive the pinned Qwen ACP and Kimi terminal clients with a loopback model."""

import asyncio
from contextlib import suppress
import errno
import fcntl
import json
import os
import pty
import re
import selectors
import signal
import struct
import subprocess
import termios
import time

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
        "mcpServers": {SERVER: {"httpUrl": url, "trust": True,
                                "oauth": {"enabled": True, "scopes": ["memory:write"]}}},
    }))
    env = {**local_env(env), "QWEN_HOME": str(home), "QWEN_RUNTIME_DIR": str(workspace / "runtime"),
           "OPENAI_API_KEY": KEY, "OPENAI_BASE_URL": model.url, "QWEN_USAGE_STATISTICS_ENABLED": "false"}
    process = await asyncio.create_subprocess_exec(
        executable, "--acp", "--approval-mode", "yolo", cwd=workspace, env=env,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        limit=4 * 1024 * 1024, start_new_session=True,
    )

    async def request(number, method, params):
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
        initial = await request(1, "initialize", {"protocolVersion": 1, "clientCapabilities": {}})
        if "result" not in initial:
            return "FAIL", stage + " returned no result"
        stage = "ACP session/new with configured provider"
        session = await request(2, "session/new", {"cwd": str(workspace), "mcpServers": []})
        session_id = session.get("result", {}).get("sessionId")
        if not session_id:
            message = session.get("error", {}).get("message", "")
            if "Use /auth to sign in or configure a model first." in message:
                return "not_applicable", "Pinned public ACP refused session/new despite configured local OpenAI provider"
            return "FAIL", stage + " returned no session"
        stage = "Qwen native OAuth"
        auth = await request(3, "qwen/control/workspace/mcp/manage", {"serverName": SERVER, "action": "authenticate"})
        if "result" not in auth and not completed_auth(events):
            code = auth.get("error", {}).get("code")
            return "FAIL", f"{stage} returned RPC error {code if type(code) is int else 'unknown'}"
        await wait_for(lambda: completed_auth(events))
        if ("consent denied", True) in events:
            return "FAIL", "Native OAuth denial"
        stage = "Qwen tool discovery"
        await wait_for(lambda: ("tools/list", True) in events)
        for number in (4, 5):
            stage = "Qwen tool turn" if number == 4 else "Qwen post-expiry tool turn"
            select_tool(model, "remember")
            result = await request(number, "session/prompt", {"sessionId": session_id,
                                   "prompt": [{"type": "text", "text": PROMPT}]})
            if "result" not in result:
                return "FAIL", stage + " returned no result"
            if number == 4:
                if ("tools/call", True) not in events:
                    return "FAIL", stage + " produced no successful remember call"
                await asyncio.sleep(ttl + 1)
        return "PASS", "Qwen ACP prompts used the local provider"
    except (OSError, ValueError, TimeoutError, EOFError):
        return "FAIL", stage + " did not complete"
    finally:
        # The npm launcher spawns the ACP process, which inherits the pipe.
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        await process.wait()


def kimi_probe(executable, workspace, url, env, model, events, ttl):
    home = workspace / "kimi"
    home.mkdir()
    (home / "mcp.json").write_text(json.dumps({"mcpServers": {SERVER: {"url": url}}}))
    env = {**local_env(env), "KIMI_CODE_HOME": str(home), "TERM": "xterm-256color",
           "KIMI_MODEL_NAME": MODEL, "KIMI_MODEL_PROVIDER_TYPE": "openai", "KIMI_MODEL_API_KEY": KEY,
           "KIMI_MODEL_BASE_URL": model.url, "KIMI_MODEL_CAPABILITIES": "tool_use",
           "KIMI_DISABLE_TELEMETRY": "1", "KIMI_CODE_NO_AUTO_UPDATE": "1"}
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 38, 125, 0, 0))
    process = subprocess.Popen(
        [executable, "--yolo"], cwd=workspace, env=env, stdin=slave, stdout=slave, stderr=slave,
        start_new_session=True,
    )
    os.close(slave)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(master, selectors.EVENT_READ)
            screen = b""
            trusted = False

            def pump(predicate, timeout):
                nonlocal screen, trusted
                deadline = time.monotonic() + timeout
                while not predicate() and time.monotonic() < deadline and process.poll() is None:
                    if not selector.select(min(.2, max(0, deadline - time.monotonic()))):
                        continue
                    try:
                        chunk = os.read(master, 8192)
                    except OSError as error:
                        if error.errno == errno.EIO:
                            break
                        raise
                    if not chunk:
                        break
                    # Keep raw terminal data, including any OAuth URL, in memory only.
                    screen = (screen + chunk)[-65536:]
                    clean = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", screen).lower()
                    if not trusted and b"trust this folder?" in clean:
                        os.write(master, b"\r")
                        trusted = True
                        screen = b""
                return predicate()

            if not pump(lambda: b"no session yet" in screen.lower() or b"type a message" in screen.lower(), 30):
                return "FAIL", "Kimi configured PTY did not reach the input prompt"
            select_tool(model, "authenticate")
            os.write(master, b"/mcp-config login humaux_ci\r")
            if not pump(lambda: completed_auth(events), 50):
                if (model.turns and not model.emitted and
                        not any(key == "authorize" for key, _ in events)):
                    return "not_applicable", "Kimi reached the local model but did not expose its MCP authenticate tool or send authorize"
                return "FAIL", "Kimi MCP login did not complete"
            if ("consent denied", True) in events:
                return "FAIL", "Native OAuth denial"
            if not pump(lambda: ("tools/list", True) in events, 25):
                return "FAIL", "Kimi did not catalogue remember after OAuth"
            # The auth turn must finish before submitting the next terminal command.
            if not pump(lambda: b"Fixture turn complete." in screen, 25):
                return "FAIL", "Kimi OAuth turn did not return to the prompt"
            for expected in (1, 2):
                screen = b""
                select_tool(model, "remember")
                os.write(master, (PROMPT + "\r").encode())
                if not pump(lambda: events.count(("tools/call", True)) >= expected and
                            b"Fixture turn complete." in screen, 40):
                    return "FAIL", "Kimi tool turn did not complete"
                if expected == 1:
                    pump(lambda: False, ttl + 1)
            return "PASS", "Kimi PTY prompts used the local provider"
    finally:
        os.close(master)
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
