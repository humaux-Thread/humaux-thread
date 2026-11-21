"""Drive the native Claude Code and CodeBuddy MCP OAuth menus in disposable terminals."""

from contextlib import contextmanager, suppress
import errno
import fcntl
import json
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time

from client_probes import PROMPT, SERVER, completed_auth, local_env, select_tool
from model_stub import CLAUDE_MODEL, KEY, MODEL


REMEMBER = f"mcp__{SERVER}__remember"


class Terminal:
    def __init__(self, master, process):
        self.master = master
        self.process = process
        self.screen = b""
        self.colors_replied = set()

    def text(self):
        clean = re.sub(rb"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*\x07)", b"", self.screen)
        return re.sub(r"\s+", "", clean.decode(errors="replace")).lower()

    def wait_for(self, predicate, timeout=10):
        deadline = time.monotonic() + timeout
        while not predicate() and time.monotonic() < deadline and self.process.poll() is None:
            if not select.select([self.master], [], [], .15)[0]:
                continue
            try:
                chunk = os.read(self.master, 8192)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            # Never write PTY output to the CI log: it can contain an OAuth URL.
            self.screen = (self.screen + chunk)[-65536:]
            for slot, color in ((b"10", b"ffff"), (b"11", b"0000")):
                if slot not in self.colors_replied and b"\x1b]" + slot + b";?" in self.screen:
                    os.write(self.master, b"\x1b]" + slot + b";rgb:" + b"/".join([color] * 3) + b"\x1b\\")
                    self.colors_replied.add(slot)
        return predicate()

    def expect(self, pattern, timeout=10):
        return self.wait_for(lambda: re.search(pattern, self.text()), timeout)

    def send(self, data):
        self.screen = b""
        os.write(self.master, data)


@contextmanager
def terminal(command, cwd, env):
    master, slave = pty.openpty()
    try:
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 125, 0, 0))
        # Open /dev/tty and terminal queries against the child PTY, even on a headless runner.
        launcher = [sys.executable, "-c", "import os,sys; os.login_tty(0); os.execv(sys.argv[1], sys.argv[1:])"]
        process = subprocess.Popen([*launcher, *command], cwd=cwd, env=env, stdin=slave, stdout=slave, stderr=slave)
    except OSError:
        os.close(master)
        raise
    finally:
        os.close(slave)
    try:
        yield Terminal(master, process)
    finally:
        os.close(master)
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def open_mcp(ui, claude):
    prompt = r"foragents|forshortcuts|forhelp|automodeon"
    if not claude:
        prompt += r"|humaux-ci-stub"
    if not ui.expect(rf"doyouwanttousethisapikey|doyoutrustthefilesinthisfolder|{prompt}", 30 if claude else 60):
        status = ui.process.poll()
        rendered = "rendered terminal output" if ui.screen else "no terminal output"
        state = "running" if status is None else f"exit {status}"
        return f"startup did not reach the command prompt ({rendered}, process {state})"
    if "doyouwanttousethisapikey" in ui.text():
        if not ui.expect(r"❯no\(recommended\)"):
            return "dummy API key approval prompt did not finish rendering"
        ui.send(b"\x1b[A")
        if not ui.expect("❯yes"):
            return "dummy API key approval was unavailable"
        ui.send(b"\r")
    elif "doyoutrustthefilesinthisfolder" in ui.text():
        if claude:
            return "isolated Claude Code trust preference was not applied"
        # CodeBuddy selects Trust folder only in the empty test workspace.
        if not ui.expect(r"[❯>](?:1\.)?trustfolderonly"):
            return "isolated workspace trust option was unavailable"
        ui.send(b"\r")
    if not ui.expect(prompt, 25):
        return "local model did not reach the interactive prompt"
    ui.send(b"/mcp")
    if not ui.expect(r"/mcp", 5):
        return "terminal did not echo /mcp"
    ui.send(b"\r")
    menu = r"managemcpservers|humaux_cimcpserver|❯authenticate"
    if claude:
        menu += r"|mcpservers[0-9]+server"
    if not ui.expect(menu, 8) and "/mcp" in ui.text():
        ui.send(b"\r")
    if not ui.expect(menu, 8):
        return "/mcp did not open the native menu"
    if ("managemcpservers" in ui.text() or re.search(r"mcpservers[0-9]+server", ui.text())) and "humaux_cimcpserver" not in ui.text():
        if not ui.expect(r"[❯>](?:\.{3}|…)?humaux_ci", 6):
            return "MCP server was missing from the native menu"
        ui.send(b"\r")
    actions = r"authenticate|connectwithoauth"
    if not ui.expect(actions, 8):
        return "native HTTP MCP menu exposed no OAuth action"
    for _ in range(5):
        if ui.expect(rf"❯(?:[0-9]+\.)?(?:{actions})", 2):
            ui.send(b"\r")
            return None
        ui.send(b"\x1b[B")
    return "native MCP OAuth action could not be selected"


def terminal_probe(executable, binary, workspace, url, env, model, events, ttl):
    config = workspace / "config"
    config.mkdir()
    env = {**local_env(env), "TERM": "xterm-256color"}
    # These native interactive clients alter their terminal startup in CI mode.
    env.pop("CI", None)
    env.pop("GITHUB_ACTIONS", None)
    env["GIT_CEILING_DIRECTORIES"] = str(workspace.parent)
    if binary == "claude":
        # First-run connectivity tests use the vendor origin even with a model gateway.
        # These preferences record only UI setup and trust of the empty fixture directory.
        (config / ".claude.json").write_text(json.dumps({"hasCompletedOnboarding": True,
            "customApiKeyResponses": {"approved": [KEY], "rejected": []},
            "projects": {str(workspace): {"hasTrustDialogAccepted": True}}}))
        env.update(CLAUDE_CONFIG_DIR=str(config), ANTHROPIC_API_KEY=KEY,
                   ANTHROPIC_BASE_URL=model.url.removesuffix("/v1"), ANTHROPIC_MODEL=CLAUDE_MODEL,
                   ANTHROPIC_DEFAULT_SONNET_MODEL=CLAUDE_MODEL, ANTHROPIC_DEFAULT_HAIKU_MODEL=CLAUDE_MODEL,
                   ANTHROPIC_DEFAULT_OPUS_MODEL=CLAUDE_MODEL, DISABLE_NONESSENTIAL_TRAFFIC="1",
                   DISABLE_AUTOUPDATER="1", ENABLE_TOOL_SEARCH="false")
        model_id = CLAUDE_MODEL
    else:
        # Model configuration also works in print mode, where the login picker is skipped.
        # The interactive process needs the documented API key and base URL separately.
        # https://www.codebuddy.ai/docs/cli/env-vars#authentication
        env.update(CODEBUDDY_CONFIG_DIR=str(config), OPENAI_API_KEY=KEY,
                   CODEBUDDY_API_KEY=KEY, CODEBUDDY_BASE_URL=model.url.removesuffix("/v1"))
        (config / "settings.json").write_text(json.dumps({"trustedDirectories": [str(workspace)]}))
        model_dir = workspace / ".codebuddy"
        model_dir.mkdir()
        (model_dir / "models.json").write_text(json.dumps({"models": [{"id": MODEL, "name": "Local CI",
            "vendor": "OpenAI", "apiKey": "${OPENAI_API_KEY}", "url": model.url + "/chat/completions",
            "maxInputTokens": 16384, "maxOutputTokens": 256, "supportsToolCall": True}], "availableModels": [MODEL]}))
        model_id = MODEL
    command = [executable, "--model", model_id, "--allowedTools", REMEMBER]
    if binary == "claude":
        command.extend(["--permission-mode", "default"])
    else:
        # https://www.codebuddy.ai/docs/cli/tool-defer-overlay
        command.extend(["--tools", f"WaitForMcpServers,NoDefer({REMEMBER})"])
    try:
        probe = subprocess.run([*command, "-p", "Acknowledge the local CI model."], env=env, cwd=workspace,
                               capture_output=True, timeout=30)
        if probe.returncode or not model.turns:
            return "FAIL", "native CLI did not complete a turn with the configured local model"
        added = subprocess.run([executable, "mcp", "add", "--scope", "local", "--transport", "http", SERVER, url],
                               env=env, cwd=workspace, capture_output=True, timeout=25)
        if added.returncode:
            return "FAIL", f"native mcp add exited {added.returncode}"
        with terminal(command, workspace, env) as ui:
            if problem := open_mcp(ui, binary == "claude"):
                return "FAIL", problem
            if not ui.wait_for(lambda: completed_auth(events), 55):
                return "FAIL", "native MCP browser auth did not complete"
            if ("consent denied", True) in events:
                return "FAIL", "native OAuth denial"
            if not ui.wait_for(lambda: ("tools/list", True) in events, 25):
                return "FAIL", "native menu did not reconnect after OAuth"
            if binary == "claude":
                # Keep the authenticated MCP connection alive for both tool turns.
                if not ui.expect(r"signedinandconnectedtohumaux_ci", 25):
                    return "FAIL", "native menu did not confirm the authenticated connection"
                for attempt in (1, 2):
                    select_tool(model, "remember")
                    ui.send(PROMPT.encode())
                    if not ui.expect(r"usethehumaux_ciremembertool", 5):
                        return "FAIL", "native terminal did not echo the fixture tool prompt"
                    ui.send(b"\r")
                    if not ui.wait_for(lambda: events.count(("tools/call", True)) >= attempt, 50):
                        return "FAIL", "native terminal did not produce a successful remember call"
                    if attempt == 1:
                        if not ui.expect("fixtureturncomplete", 20):
                            return "FAIL", "native terminal did not finish the first tool turn"
                        time.sleep(ttl + 1)
                return "PASS", "local model and native MCP OAuth menu"
        for attempt in (1, 2):
            select_tool(model, "remember")
            for _ in range(2):
                result = subprocess.run([*command, "-p", PROMPT], env=env, cwd=workspace, capture_output=True, timeout=50)
                if result.returncode or model.emitted:
                    break
            if result.returncode or events.count(("tools/call", True)) < attempt:
                return "FAIL", "native print-mode tool turn did not produce a successful remember call"
            if attempt == 1:
                time.sleep(ttl + 1)
        return "PASS", "local model and native MCP OAuth menu"
    except (OSError, subprocess.TimeoutExpired):
        return "FAIL", "native terminal or model command did not complete"
