"""Credential-free probes for native clients whose public interfaces need an interactive host."""

import asyncio
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


async def qwen_probe(executable, workspace, url, env):
    """Check the public ACP initialize and session/new door without sending a model prompt."""
    env = {**env, "QWEN_HOME": str(workspace / "qwen"), "QWEN_RUNTIME_DIR": str(workspace / "runtime")}
    process = await asyncio.create_subprocess_exec(
        executable, "--acp", cwd=workspace, env=env, stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, limit=4 * 1024 * 1024,
    )

    async def request(number, method, params):
        message = {"jsonrpc": "2.0", "id": number, "method": method, "params": params}
        process.stdin.write((json.dumps(message) + "\n").encode())
        await process.stdin.drain()
        while line := await asyncio.wait_for(process.stdout.readline(), timeout=35):
            response = json.loads(line)
            if response.get("id") == number:
                return response
        return {}

    try:
        initial = await request(1, "initialize", {"protocolVersion": 1, "clientCapabilities": {}})
        if "result" not in initial:
            return "FAIL", "Public ACP initialize returned no result"
        session = await request(2, "session/new", {
            "cwd": str(workspace),
            "mcpServers": [{"type": "http", "name": "humaux_ci", "url": url, "headers": []}],
        })
        error = session.get("error", {})
        message = error.get("message", "")
        if "Use /auth to sign in or configure a model first." in message:
            return "not_applicable", "Public ACP initialize succeeded; session/new requires model configuration or /auth"
        if "Authentication failed:" in message or "Authentication is restricted by policy." in message:
            return "not_applicable", "Public ACP initialize succeeded; session/new refused authentication"
        if "result" in session:
            return "not_applicable", "ACP session/new succeeded; pinned source reserves direct MCP App calls for a trusted managed parent"
        code = error.get("code")
        return "FAIL", f"ACP session/new did not return a session (RPC code {code if type(code) is int else 'unknown'})"
    except (OSError, ValueError, TimeoutError):
        return "FAIL", "Public ACP session probe did not complete"
    finally:
        if process.returncode is None:
            process.kill()
        await process.wait()


def kimi_probe(executable, workspace, url, env):
    """Run the documented /mcp-config login command against an isolated user configuration."""
    home = workspace / "kimi"
    home.mkdir()
    (home / "mcp.json").write_text(json.dumps({"mcpServers": {"humaux_ci": {"url": url}}}))
    env = {**env, "KIMI_CODE_HOME": str(home), "TERM": "xterm-256color"}
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 38, 125, 0, 0))
    process = subprocess.Popen(
        [executable], cwd=workspace, env=env, stdin=slave, stdout=slave, stderr=slave,
        start_new_session=True,
    )
    os.close(slave)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(master, selectors.EVENT_READ)
            deadline = time.monotonic() + 45
            output = b""
            sent = False
            while time.monotonic() < deadline and process.poll() is None:
                if not selector.select(1):
                    continue
                try:
                    chunk = os.read(master, 8192)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                # The PTY can contain authorization URLs. Keep raw bytes in memory only.
                output = (output + chunk)[-65536:]
                screen = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", output).decode(errors="replace").lower()
                compact = re.sub(r"\s+", "", screen)
                for marker in ("pleaselogin", "notloggedin", "run/login", "loginwithkimi",
                               "nomodelconfigured", "noproviderconfigured"):
                    if marker in compact:
                        return "not_applicable", f"Fresh PTY displayed account/model prerequisite ({marker})"
                if not sent and ("❯" in screen or "type a message" in screen or "type /" in screen):
                    os.write(master, b"/mcp-config login humaux_ci\r")
                    sent = True
                if sent and ("authentication successful" in screen or "oauth login successful" in screen):
                    return "not_applicable", "PTY OAuth completed; pinned CLI has no model-free tool-call command in --help"
            return "FAIL", "PTY did not witness an account prerequisite or finish MCP auth within 45 seconds"
    finally:
        os.close(master)
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
