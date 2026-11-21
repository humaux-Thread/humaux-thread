"""X-M02-2 acceptance against the real gateway and a disposable, migrated PG19 service."""

import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import threading
import time
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request, urlopen
from uuid import UUID
from xml.etree import ElementTree as xml

from browser import NoRedirect, ProxyHandler, build_opener

HERE = Path(__file__).resolve().parent
TEMP = Path(os.environ["RUNNER_TEMP"])
FAULT = os.environ["OAUTH_CLIENT_FAULT"]
GATEWAY = 18170
ROWS = []
TOOLS = ("tools/list", "tools/call")
HOSTED = [
    ("claude.ai", None, "https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp"),
    ("ChatGPT", "https://chatgpt.com/oauth/client.json", "https://chatgpt.com/connector_platform_oauth_redirect"),
    ("Antigravity", "https://antigravity.google/oauth/client-metadata.json", "https://antigravity.google/oauth-callback"),
    ("Cursor Web", None, "https://prod.cursor.com/docs/mcp"),
    ("vscode.dev", None, "https://code.visualstudio.com/docs/agents/reference/mcp-configuration"),
]
CLI = [
    ("Claude Code", "2.1.328", "@anthropic-ai/claude-code", "claude", "MCP OAuth uses the signed-in /mcp UI"),
    ("Codex CLI", "0.169.0", "@openai/codex", "codex", None),
    ("Gemini CLI", "0.38.2", "@google/gemini-cli", "gemini", "MCP auth requires the interactive /mcp auth command"),
    ("Qwen Code", "0.28.3", "@qwen-code/qwen-code", "qwen", "MCP auth requires the interactive /mcp auth command"),
    ("Kimi Code", "2.5.3", "@moonshot-ai/kimi-code", "kimi", "MCP auth requires the interactive /mcp-config login command"),
    ("CodeBuddy Code", "2.185.0", "@tencent-ai/codebuddy-code", "codebuddy", "MCP OAuth requires the interactive /mcp UI"),
    ("ZCode CLI", "0.17.1", None, None, "No pinned Linux ARM64 distribution configured for the desktop-bundled CLI"),
    ("DeepSeek Harness", "0.2.1-rc.5", None, None, "No pinned Linux ARM64 release asset for this version in deepseek-ai/deepseek-harness"),
]


class Wire(BaseHTTPRequestHandler):
    """Capture only CHECKLIST evidence. Never persist or print raw HTTP messages."""

    def log_message(self, *_):
        return

    def handle_request(self):
        parsed = urlsplit(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        headers = {key: value for key, value in self.headers.items()
                   if key.lower() not in {"connection", "accept-encoding"}}
        upstream = HTTPConnection("127.0.0.1", GATEWAY, timeout=35)
        try:
            upstream.request(self.command, self.path, body or None, headers)
            response = upstream.getresponse()
            output = response.read()
            self.record(parsed, body, response, output)
            self.send_response(response.status)
            for name, value in response.getheaders():
                if name.lower() not in {"connection", "transfer-encoding", "content-length", "server", "date"}:
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(output)))
            self.end_headers()
            self.wfile.write(output)
        except (OSError, ValueError):
            return
        finally:
            upstream.close()

    do_GET = do_POST = do_DELETE = handle_request

    def record(self, parsed, body, response, output):
        path = parsed.path
        status = response.status
        origin = f"http://127.0.0.1:{self.server.server_port}"
        resource = origin + "/mcp/legacy"
        event = None
        if path.startswith("/mcp"):
            if status == 401:
                metadata_path = "/.well-known/oauth-protected-resource" + path
                expected = f'resource_metadata="{origin + metadata_path}"'
                event = ("challenge", expected in response.getheader("WWW-Authenticate", ""))
            elif body and status == 200:
                request, reply = json.loads(body), json.loads(output)
                method = request.get("method")
                result = reply.get("result", {})
                if method == "initialize":
                    event = ("protocol", result.get("protocolVersion") == "2025-06-18")
                elif method == "server/discover":
                    event = ("protocol", self.headers.get("MCP-Protocol-Version") == "2026-07-28")
                elif method == "tools/list":
                    event = (method, any(tool["name"] == "remember" for tool in result.get("tools", [])))
                elif method == "tools/call":
                    event = (method, not result.get("isError") and
                             isinstance(result.get("structuredContent", {}).get("evidence_id"), str))
        elif path.startswith("/.well-known/oauth-protected-resource") and status == 200:
            prm = json.loads(output)
            event = ("PRM", prm.get("resource") == resource and prm.get("authorization_servers") == [origin])
        elif path == "/.well-known/oauth-authorization-server" and status == 200:
            metadata = json.loads(output)
            event = ("ASM", metadata.get("issuer") == origin and
                     "S256" in metadata.get("code_challenge_methods_supported", []) and
                     metadata.get("registration_endpoint") == origin + "/oauth/register" and
                     metadata.get("client_id_metadata_document_supported") is True)
        elif path == "/oauth/register":
            event = ("DCR", status == 201)
        elif path == "/oauth/authorize" and self.command == "GET":
            query = parse_qs(parsed.query)
            event = ("authorize", query.get("resource") == [resource] and
                     query.get("code_challenge_method") == ["S256"] and
                     len(query.get("code_challenge", [""])[0]) == 43)
        elif path == "/oauth/authorize" and self.command == "POST":
            query = parse_qs(urlsplit(response.getheader("Location", "")).query)
            event = ("consent", status == 303 and "code" in query)
            if query.get("error") == ["access_denied"]:
                event = ("consent denied", status == 303 and "code" not in query)
        elif path == "/oauth/token":
            form = parse_qs(body.decode())
            grant_type = form.get("grant_type")
            if grant_type == ["authorization_code"]:
                self.server.events.append(("exchange status", status))
                event = ("code", status == 200 and form.get("resource") == [resource] and
                         len(form.get("code_verifier", [""])[0]) >= 43)
            elif grant_type == ["refresh_token"]:
                event = ("refresh", status == 200 and form.get("resource") == [resource])
        if event:
            self.server.events.append(event)


@contextmanager
def witness():
    # One witness per client isolates wire facts. The gateway accepts one public origin, so the
    # clients run serially on the same port with fresh storage.
    with ThreadingHTTPServer(("127.0.0.1", 18171), Wire) as server:
        server.events = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.events
        finally:
            server.shutdown()
            thread.join()


def run(command, env, timeout=70):
    try:
        return subprocess.run(command, env=env, timeout=timeout, capture_output=True, text=True)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(command, 124, "", "")


def required(command, env, title, timeout=70):
    result = run(command, env, timeout)
    if result.returncode:
        # Never print runner or client stdout/stderr, even on errors.
        raise RuntimeError(f"{title} exited {result.returncode}")
    return result.stdout


def query(sql, env):
    return required(["psql", "-XAt", "-v", "ON_ERROR_STOP=1", "-c", sql],
                    {**env, "PGDATABASE": env["HUMAUX_TEST_PG_DSN"]}, "fixture query")


@contextmanager
def gateway():
    env = {**os.environ}
    assert urlsplit(env["HUMAUX_TEST_PG_DSN"]).hostname == "127.0.0.1"
    assert urlsplit(env["HUMAUX_TEST_PG_DSN"]).path == "/humaux_thread_ci"
    assert env["HUMAUX_TEST_DISPOSABLE_CLUSTER"] == "1"
    for line in Path("deploy/env/values/gateway.env").read_text().splitlines():
        if line.startswith(("HUMAUX_GATEWAY_", "HUMAUX_CONTINUITY_", "HUMAUX_BILLING_")):
            key, value = line.split("=", 1)
            env[key] = value
    env["HUMAUX_GATEWAY_CREDENTIAL_PEPPER_HEX"] = secrets.token_hex(32)
    seed = required([
        "cargo", "xtask", "e2e-seed", "--no-lane",
        "--pepper-hex-env", "HUMAUX_GATEWAY_CREDENTIAL_PEPPER_HEX",
        "--scopes", "memory:write,context:read",
        "--processor-id", "87ee52db-a623-4a61-8826-e8539ddf7c2b",
        "--collection", "oauth_clients", "--dimension", "4",
    ], env, "e2e-seed", 120)
    ids = dict(re.findall(r"^(user_id|workspace_id|reasoning_domain_id): ([0-9a-f-]+)$", seed, re.M))
    ids = {key: str(UUID(value)) for key, value in ids.items()}
    email = "oauth-ci@example.test"
    query(f"INSERT INTO control.user_emails(user_id,original_email,canonical_email) "
          f"VALUES ('{ids['user_id']}','{email}','{email}') ON CONFLICT DO NOTHING", env)
    origin = "http://127.0.0.1:18171"
    bindir = TEMP / "oauth-browser"
    bindir.mkdir(exist_ok=True)
    (bindir / "xdg-open").symlink_to(HERE / "browser.py")
    env.update(
        BROWSER=str(HERE / "browser.py"),
        PATH=f"{bindir}:{env['PATH']}",
        OAUTH_TEST_ORIGIN=origin,
        OAUTH_TEST_USER=ids["user_id"],
        OAUTH_TEST_EMAIL=email,
        OAUTH_TEST_WORKSPACE=ids["workspace_id"],
        HUMAUX_GATEWAY_BIND_ADDR=f"127.0.0.1:{GATEWAY}",
        HUMAUX_GATEWAY_ALLOWED_HOSTS="127.0.0.1:18171",
        HUMAUX_GATEWAY_ALLOWED_ORIGINS=origin,
        HUMAUX_GATEWAY_PUBLIC_BASE_URL=origin,
        HUMAUX_GATEWAY_LOGIN_MAIL_FROM=email,
        HUMAUX_GATEWAY_TOKEN_HMAC_KEY=secrets.token_hex(32),
        HUMAUX_GATEWAY_AUTH_HMAC_KEY=secrets.token_hex(32),
        HUMAUX_GATEWAY_LOGIN_CODE_PEPPER=secrets.token_hex(32),
        HUMAUX_GATEWAY_AUTH_SURFACE_ENABLED="true",
        HUMAUX_GATEWAY_AUTH_OAUTH_CIMD_ENABLED="true",
        HUMAUX_GATEWAY_AUTH_OAUTH_ACCESS_TTL_SECONDS="300",
        HUMAUX_GATEWAY_AUTH_LOGIN_CODE_RESEND_COOLDOWN_SECONDS="1",
        HUMAUX_GATEWAY_AUTH_OAUTH_REGISTER_IP_CAPACITY="16",
        HUMAUX_GATEWAY_AUTH_OAUTH_RESOURCE=origin + "/mcp",
        HUMAUX_GATEWAY_MCP_LEGACY_ENABLED="true",
        HUMAUX_GATEWAY_REMEMBER_REASONING_DOMAIN_ID=ids["reasoning_domain_id"],
        HUMAUX_GATEWAY_RETRIEVAL_RPC_SOCKET_PATH="",
    )
    with subprocess.Popen(["target/debug/humaux-gateway"], env=env,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as proc:
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise RuntimeError(f"gateway exited {proc.returncode}")
                try:
                    connection = HTTPConnection("127.0.0.1", GATEWAY, timeout=1)
                    connection.request("GET", "/livez", headers={"Host": "127.0.0.1:18171"})
                    if connection.getresponse().status == 200:
                        break
                except OSError:
                    time.sleep(0.15)
                finally:
                    connection.close()
            else:
                raise RuntimeError("gateway readiness timed out")
            yield env
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()


def record(name, version, status, reason):
    ROWS.append((name, version, status, reason))
    print(f"{name} {version} {status} {reason}", flush=True)


def sdk(name, version, command, env):
    required_events = ["challenge", "PRM", "ASM", "DCR", "authorize", "consent", "code",
                       "protocol", *TOOLS, "refresh"]
    with witness() as events:
        result = run(command, env, timeout=390)
        snapshot = list(events)
    missing = [event for event in required_events if (event, True) not in snapshot]
    if snapshot.count(("tools/call", True)) < 2:
        missing.append("tool recovery")
    if result.returncode or missing:
        why = ("consent denied by fixture; no exchange" if FAULT == "consent" and
               ("consent denied", True) in snapshot and not any(k == "exchange status" for k, _ in snapshot)
               else f"exit {result.returncode}; missing: {', '.join(missing) or 'none'}")
        record(name, version, "FAIL", why)
    else:
        record(name, version, "PASS", "401 → PRM → ASM; DCR; consent callback; S256; equal resources; 2025-06-18; tools and refresh")


def check_pkce(command, env):
    with witness() as events:
        result = run([*command, "--wrong-verifier"], env)
    if ("code", True) in events or ("exchange status", 200) in events:
        record("MCP TypeScript SDK PKCE negative", "1.32.2", "FAIL", "Gateway accepted mismatched verifier")
    elif ("exchange status", 400) in events and ("consent", True) in events and result.returncode != 0:
        record("MCP TypeScript SDK PKCE negative", "1.32.2", "PASS", "Gateway refused mismatched verifier after consent")
    else:
        record("MCP TypeScript SDK PKCE negative", "1.32.2", "FAIL", "Verifier refusal was not witnessed")


def hosted(name, document, redirect, env):
    if document is None:
        record(name, "hosted", "not_applicable", f"No public CIMD URL established; official reference {redirect}")
        return
    try:
        with urlopen(document, timeout=12) as response:
            data = json.loads(response.read(8193))
        assert data["client_id"] == document and redirect in data["redirect_uris"]
    except (OSError, ValueError, KeyError, AssertionError):
        record(name, "hosted", "FAIL", f"Could not confirm public CIMD identity and redirect at {document}")
        return
    origin = env["OAUTH_TEST_ORIGIN"]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(secrets.token_bytes(32)).digest()).decode().rstrip("=")
    params = {
        "client_id": document, "redirect_uri": redirect, "response_type": "code",
        "scope": "memory:write", "state": secrets.token_urlsafe(32), "code_challenge": challenge,
        "code_challenge_method": "S256", "resource": origin + "/mcp",
    }
    http = build_opener(ProxyHandler({}), NoRedirect())

    def authorize(uri):
        url = origin + "/oauth/authorize?" + urlencode({**params, "redirect_uri": uri})
        try:
            with http.open(Request(url), timeout=15) as response:
                return response.status, response.headers.get("Location")
        except HTTPError as response:
            return response.status, response.headers.get("Location")

    with witness():
        valid = authorize(redirect)
        invalid = authorize(redirect + "/oauth-ci-mismatch")
    if valid == (303, "/auth/login") and invalid == (400, None):
        record(name, "hosted", "PASS", f"CIMD and exact HTTPS redirect; SDK consent surrogate; {document}")
    else:
        method = data.get("token_endpoint_auth_method")
        method = method if method in ("none", "private_key_jwt", "client_secret_basic") else "other"
        record(name, "hosted", "FAIL", f"CIMD redirect checks returned {valid[0]}/{invalid[0]}; auth method {method}; {document}")


def cli(name, version, package, binary, unavailable, env):
    if package is None:
        record(name, version, "not_applicable", unavailable)
        return
    prefix = TEMP / ("oauth-cli-" + binary)
    installed = run(["npm", "install", "--prefix", str(prefix), "--no-audit", "--no-fund",
                     f"{package}@{version}"], env, timeout=240)
    executable = str(prefix / "node_modules" / ".bin" / binary)
    version_check = run([executable, "--version"], env) if Path(executable).is_file() else installed
    if installed.returncode or version_check.returncode or version not in version_check.stdout:
        record(name, version, "not_applicable", f"Pinned package {package} install/version probe failed on Linux ARM64")
        return
    if unavailable:
        record(name, version, "not_applicable", f"Binary version verified; {unavailable}")
        return
    # Native CLI login uses CIMD (or the public DCR fallback); this call has no model or vendor login.
    state = prefix / "state"
    state.mkdir(exist_ok=True)
    client_env = {**env, "CODEX_HOME": str(state)}
    mcp_config = state / "config.toml"
    mcp_config.write_text('[mcp_servers.humaux_ci]\nurl = "' + env["OAUTH_TEST_ORIGIN"] + '/mcp/legacy"\n')
    with witness() as events:
        login = run([executable, "mcp", "login", "humaux_ci", "--scopes", "memory:write"], client_env)
    if login.returncode or ("consent", True) not in events or ("exchange status", 200) not in events:
        record(name, version, "FAIL", f"Native mcp login exit {login.returncode}; callback/exchange not confirmed")
    else:
        record(name, version, "not_applicable", "Native mcp login succeeded; model-free tool invocation has not been verified")


def reports():
    output = TEMP / "oauth-results"
    output.mkdir(exist_ok=True)
    suite = xml.Element("testsuite", name="X-M02-2 OAuth clients", tests=str(len(ROWS)),
                        failures=str(sum(row[2] == "FAIL" for row in ROWS)),
                        skipped=str(sum(row[2] == "not_applicable" for row in ROWS)))
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    lines = [f"# X-M02-2 OAuth clients\n\nGateway SHA `{head}`. Fault `{FAULT}`.\n",
             "| Client | Version | Result | Evidence |", "| --- | --- | --- | --- |"]
    for name, version, status, reason in ROWS:
        lines.append(f"| {name} | {version} | {status} | {reason} |")
        case = xml.SubElement(suite, "testcase", name=f"{name} {version}")
        if status != "PASS":
            xml.SubElement(case, "failure" if status == "FAIL" else "skipped", message=reason)
    (output / "clients.md").write_text("\n".join(lines) + "\n")
    xml.ElementTree(suite).write(output / "clients.xml", encoding="utf-8", xml_declaration=True)


def main():
    try:
        with gateway() as env:
            ts = ["node", str(HERE / "sdk_ts.mjs")]
            if FAULT == "pkce":
                check_pkce(ts, env)
            elif FAULT == "consent":
                sdk("MCP TypeScript SDK", "1.32.2", ts, env)
            else:
                sdk("MCP TypeScript SDK", "1.32.2", [*ts, "--refresh"], env)
                check_pkce(ts, env)
                sdk("MCP Python SDK", "1.29.1", [sys.executable, str(HERE / "sdk_python.py")], env)
                for row in HOSTED:
                    hosted(*row, env)
                for row in CLI:
                    cli(*row, env)
    except RuntimeError as error:
        record("CI infrastructure", "PG19", "FAIL", str(error))
    except Exception:
        record("CI infrastructure", "PG19", "FAIL", "Unexpected setup or harness error; raw exception suppressed")
    finally:
        reports()
    return int(any(row[2] == "FAIL" for row in ROWS))


if __name__ == "__main__":
    sys.exit(main())
