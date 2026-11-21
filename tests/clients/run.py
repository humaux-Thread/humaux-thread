"""X-M02-2 acceptance against the real gateway and a disposable, migrated PG19 service."""

import asyncio
import base64
from contextlib import contextmanager
import hashlib
from http.client import HTTPConnection, HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tarfile
import threading
import time
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import ProxyHandler, Request, build_opener
from uuid import UUID, uuid4
from xml.etree import ElementTree as xml

from browser import NoRedirect, postgres_command
from client_probes import kimi_probe, qwen_probe
from model_stub import model_stub

HERE = Path(__file__).resolve().parent
TEMP = Path(os.environ["RUNNER_TEMP"])
FAULT = os.environ["OAUTH_CLIENT_FAULT"]
GATEWAY = 18170
ROWS = []
TOOLS = ("tools/list", "tools/call")
HOSTED = [
    # Anthropic's published identity document declares its client_id and callback below.
    # https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp
    ("claude.ai", "https://claude.ai/oauth/mcp-oauth-client-metadata", "https://claude.ai/api/mcp/auth_callback"),
    ("ChatGPT", "https://chatgpt.com/oauth/client.json", "https://chatgpt.com/connector_platform_oauth_redirect"),
    ("Antigravity", "https://antigravity.google/oauth/client-metadata.json", "https://antigravity.google/oauth-callback"),
    ("Cursor Web", None, "https://prod.cursor.com/docs/mcp"),
    ("vscode.dev", "https://vscode.dev/oauth/client-metadata.json", "https://vscode.dev/redirect"),
]
CLI = [
    ("Claude Code", "2.1.328", "@anthropic-ai/claude-code", "claude", "Clean Linux PTY reached Select login method before /mcp; https://code.claude.com/docs/en/setup"),
    ("Codex CLI", "0.169.0", "@openai/codex", "codex", None),
    ("Qwen Code", "0.28.3", "@qwen-code/qwen-code", "qwen", None),
    ("Kimi Code", "2.5.3", "@moonshot-ai/kimi-code", "kimi", None),
    ("CodeBuddy Code", "2.185.0", "@tencent-ai/codebuddy-code", "codebuddy", "Vendor documents mandatory login before first interactive use; https://www.codebuddy.ai/docs/cli/quickstart"),
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
            self.send_response(response.status)
            for name, value in response.getheaders():
                if name.lower() not in {"connection", "transfer-encoding", "content-length", "server", "date"}:
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(output)))
            self.end_headers()
            self.wfile.write(output)
            try:
                self.record(parsed, body, response, output)
            except (ValueError, TypeError, AttributeError, KeyError):
                # An unrecognized evidence payload must never prevent forwarding the reply.
                pass
        except (OSError, ValueError):
            return
        finally:
            upstream.close()

    do_GET = do_HEAD = do_POST = do_DELETE = handle_request

    def record(self, parsed, body, response, output):
        path = parsed.path
        status = response.status
        origin = f"http://127.0.0.1:{self.server.server_port}"
        resource = origin + "/mcp/legacy"
        event = None
        if path.startswith("/mcp"):
            request = json.loads(body) if body else {}
            method = request.get("method", self.command)
            methods = (*TOOLS, "initialize", "notifications/initialized", "server/discover", "GET", "DELETE")
            method = method if method in methods else "other"
            version = self.headers.get("MCP-Protocol-Version", request.get("params", {}).get("protocolVersion"))
            version = version if version in {"2025-06-18", "2025-11-25", "2026-07-28"} else "absent/other"
            media = response.getheader("Content-Type", "").partition(";")[0]
            media = media if media in {"application/json", "text/event-stream", "text/plain"} else "absent/other"
            self.server.events.append(("MCP HTTP", f"{method} {version} → {status} {media}"))
            if status == 401 and not self.headers.get("Authorization"):
                metadata_path = "/.well-known/oauth-protected-resource" + path
                expected = f'resource_metadata="{origin + metadata_path}"'
                event = ("challenge", expected in response.getheader("WWW-Authenticate", ""))
            elif body and status == 200:
                reply = json.loads(output)
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
            if status != 201:
                submitted = json.loads(body) if body else {}
                method = submitted.get("token_endpoint_auth_method", "absent")
                method = method if method in ("absent", "none", "client_secret_basic") else "other"
                media = response.getheader("Content-Type", "").partition(";")[0]
                oauth_error = json.loads(output).get("error") if media == "application/json" else None
                if oauth_error not in ("invalid_client_metadata", "invalid_redirect_uri"):
                    oauth_error = "other"
                self.server.events.append(("DCR refusal", f"HTTP {status} {oauth_error}, token_endpoint_auth_method={method}"))
        elif path == "/oauth/authorize" and self.command == "GET":
            query = parse_qs(parsed.query)
            self.server.pkce_challenge = query.get("code_challenge", [""])[0]
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
                         s256(form.get("code_verifier", [""])[0]) == self.server.pkce_challenge)
            elif grant_type == ["refresh_token"]:
                event = ("refresh", status == 200 and form.get("resource") == [resource])
        if event:
            self.server.events.append(event)


def s256(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")


@contextmanager
def witness():
    # One witness per client isolates wire facts. The gateway accepts one public origin, so the
    # clients run serially on the same port with fresh storage.
    with ThreadingHTTPServer(("127.0.0.1", 18171), Wire) as server:
        server.events = []
        server.pkce_challenge = ""
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.events
        finally:
            server.shutdown()
            thread.join()


def run(command, env, timeout=70, input_data=None):
    try:
        return subprocess.run(command, env=env, timeout=timeout, capture_output=True, text=True, input=input_data)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(command, 124, "", "")


def required(command, env, title, timeout=70):
    result = run(command, env, timeout)
    if result.returncode:
        # Never print runner or client stdout/stderr, even on errors.
        stage = re.search(r"e2e-seed: fail \(missing required flag (--[a-z-]+)", result.stderr)
        if title == "e2e-seed" and stage:
            raise RuntimeError(f"{title}: missing flag {stage[1]}")
        raise RuntimeError(f"{title} exited {result.returncode}")
    return result.stdout


def query(sql, env):
    return required(postgres_command(env, sql), env, "fixture query")


@contextmanager
def gateway():
    env = {**os.environ}
    assert urlsplit(env["HUMAUX_TEST_PG_DSN"]).hostname == "127.0.0.1"
    assert urlsplit(env["HUMAUX_TEST_PG_DSN"]).path == "/humaux_thread_ci"
    assert env["GITHUB_ACTIONS"] == "true" and env["HUMAUX_TEST_DISPOSABLE_CLUSTER"] == "1"
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
        "--collection", "oauth_clients", "--dimension", "1024",
        "--embedding-provider", "dashscope", "--embedding-region", "cn-beijing",
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
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True) as proc:
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    config = re.search(r"gateway bootstrap configuration (HUMAUX_[A-Z0-9_]+):", proc.stderr.read())
                    detail = f" during {config[1]} validation" if config else ""
                    raise RuntimeError(f"gateway exited {proc.returncode}{detail}")
                try:
                    connection = HTTPConnection("127.0.0.1", GATEWAY, timeout=1)
                    connection.request("GET", "/livez", headers={"Host": "127.0.0.1:18171"})
                    if connection.getresponse().status == 200:
                        break
                except (OSError, HTTPException):
                    pass
                finally:
                    connection.close()
                time.sleep(0.15)
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


def discovery_route(events):
    keys = [key for key, passed in events if passed is True]
    if "PRM" not in keys or "ASM" not in keys:
        return None
    if "challenge" in keys and keys.index("challenge") < keys.index("PRM"):
        return "401 challenge → PRM/ASM"
    return "direct PRM/ASM"


def sdk(name, version, command, env, *, direct_discovery=False, input_data=None):
    required_events = ["PRM", "ASM", "DCR", "authorize", "consent", "code", "protocol", *TOOLS, "refresh"]
    if not direct_discovery:
        required_events.insert(0, "challenge")
    with witness() as events:
        result = run(command, env, timeout=390, input_data=input_data)
        snapshot = list(events)
    missing = [event for event in required_events if (event, True) not in snapshot]
    if snapshot.count(("tools/call", True)) < 2:
        missing.append("tool recovery")
    if result.returncode or missing:
        stages = ("first connect", "consent callback", "code exchange", "first tools/list and remember",
                  "expiry and automatic refresh", "load provider", "provider authorize and exchange",
                  "load built adapter", "connect and authorize")
        stderr_lines = result.stderr.splitlines()
        phase = next((stage for stage in stages for client in ("TypeScript SDK", "Gemini CLI", "ZCode adapter")
                      if f"{client} failed: {stage}" in stderr_lines), None)
        loader_error = re.search(r"^ZCode adapter loader: (ERR_[A-Z_]+)$", result.stderr, re.MULTILINE)
        if phase and loader_error:
            phase += f" ({loader_error[1]})"
        detail = f" at {phase}" if phase else ""
        why = ("consent denied by fixture; no exchange" if FAULT in {"consent", "gemini-consent"} and
               ("consent denied", True) in snapshot and not any(k == "exchange status" for k, _ in snapshot)
               else f"exit {result.returncode}{detail}; missing: {', '.join(missing) or 'none'}")
        if refusal := next((value for key, value in snapshot if key == "DCR refusal"), None):
            why += f"; DCR refused: {refusal}"
        record(name, version, "FAIL", why)
    else:
        record(name, version, "PASS", f"{discovery_route(snapshot)}; DCR; consent callback; S256; equal resources; 2025-06-18; tools and refresh")


def check_pkce(command, env):
    with witness() as events:
        result = run([*command, "--wrong-verifier"], env)
    if ("code", True) in events or ("exchange status", 200) in events:
        record("MCP TypeScript SDK PKCE negative", "1.32.2", "FAIL", "Gateway accepted mismatched verifier")
    elif ("exchange status", 400) in events and ("consent", True) in events and result.returncode != 0:
        record("MCP TypeScript SDK PKCE negative", "1.32.2", "PASS", "Gateway refused mismatched verifier after consent")
    else:
        record("MCP TypeScript SDK PKCE negative", "1.32.2", "FAIL", "Verifier refusal was not witnessed")


def gemini(env):
    name, version = "Gemini CLI", "0.38.2"
    prefix = TEMP / "oauth-cli-gemini"
    install = run(["npm", "install", "--prefix", str(prefix), "--no-audit", "--no-fund",
                   f"@google/gemini-cli-core@{version}"], env, timeout=240)
    if install.returncode:
        status = "FAIL" if FAULT == "gemini-consent" else "not_applicable"
        record(name, version, status, f"Pinned core install failed (npm exit {install.returncode})")
        return
    sdk(name, version, ["node", str(HERE / "gemini.mjs"), str(prefix)], env,
        direct_discovery=True, input_data="y\n")


def zcode(env):
    commit = "fec975905a2abd4c07e35c40d51fa097a2258ec9"
    name, version = "ZCode CLI", commit[:12]
    source = TEMP / "oauth-zcode-src"
    workspace = source / "apps/zcode-cli"
    # The release uses its monorepo lockfile, not the stale standalone CLI lockfile.
    pnpm = ["npm", "exec", "--yes", "--package=pnpm@10.33.2", "--", "pnpm", "-C", str(source)]
    steps = [
        ("git init", ["git", "init", "-q", str(source)], 20),
        ("official source fetch", ["git", "-C", str(source), "fetch", "--depth=1",
                                    "https://github.com/zai-org/ZCode.git", commit], 120),
        ("pinned checkout", ["git", "-C", str(source), "checkout", "-q", "--detach", commit], 60),
        ("root-lockfile adapter dependency install", [*pnpm, "--filter", "zcode-cli", "--filter",
                                                     "@zcode/adapters...", "install", "--frozen-lockfile"], 260),
        ("workspace adapter build", [*pnpm, "--filter", "@zcode/adapters...", "run", "build"], 240),
    ]
    for stage, command, timeout in steps:
        result = run(command, env, timeout=timeout)
        if result.returncode:
            error = re.search(r"ERR_PNPM_[A-Z0-9_]+|error TS[0-9]+", result.stdout + result.stderr)
            category = f", {error[0]}" if error else ""
            record(name, version, "not_applicable", f"{stage} failed (exit {result.returncode}{category}); https://github.com/zai-org/ZCode/tree/{commit}")
            return
    adapter = workspace / "packages/adapters/dist"
    if not (adapter / "mcp/index.js").is_file():
        record(name, version, "not_applicable", "Official workspace build did not produce packages/adapters/dist/mcp/index.js")
        return
    # The built adapter imports workspace exports that still point to TypeScript sources.
    command = [*pnpm, "--filter", "zcode-cli", "exec", "tsx", str(HERE / "zcode.mjs"), str(adapter)]
    zcode_env = {**env, "ZCODE_CREDENTIAL_SECRET": secrets.token_urlsafe(32)}
    sdk(name, version, command, zcode_env, direct_discovery=True)


def deepseek(env):
    name, version = "DeepSeek Harness", "0.2.2-rc.5"
    target = TEMP / "oauth-deepseek"
    target.mkdir()
    result = run(["npm", "pack", "--ignore-scripts", "--json", "--pack-destination", str(target),
                  f"@deepseek-ai/dsh@{version}", f"@deepseek-ai/dsh-mcp-client@{version}",
                  f"@deepseek-ai/dsh-mcp-manager@{version}"], env, timeout=180)
    if result.returncode:
        record(name, version, "not_applicable", f"Could not fetch same-version CLI, client and manager artifacts (npm pack exit {result.returncode})")
        return
    releases = {item["name"]: item for item in json.loads(result.stdout)}
    if len(releases) != 3 or any(item["version"] != version for item in releases.values()):
        record(name, version, "FAIL", "Expected matching CLI, client and manager versions")
        return
    with tarfile.open(target / releases["@deepseek-ai/dsh-mcp-client"]["filename"]) as archive:
        declaration = archive.extractfile("package/lib/types/index.d.ts").read().decode()
    if re.search(r"oauth|authorization.?code", declaration, re.IGNORECASE):
        record(name, version, "FAIL", "Pinned plugin exposes an OAuth declaration; its direct adapter needs a real journey")
        return
    record(name, version, "not_applicable", "Fetched matching CLI/client/manager; MCP client types lack OAuth and tagged manager docs say No OAuth flow; https://github.com/deepseek-ai/deepseek-harness/blob/dsh-v0.2.2-rc.5/packages/mcp/mcp-manager/README.md#known-limitations")


def metadata_http(response):
    media = response.headers.get_content_type() if "Content-Type" in response.headers else "absent"
    if not re.fullmatch(r"[a-z0-9.+-]+(?:/[a-z0-9.+-]+)?", media) or len(media) > 96:
        media = "other"
    redirect = "refused" if 300 <= response.status < 400 and response.headers.get("Location") else "none"
    return f"HTTP {response.status}, content-type={media}, redirect={redirect}"


def hosted(name, document, redirect, env):
    if document is None:
        record(name, "hosted", "not_applicable", f"No public CIMD URL established; official reference {redirect}")
        return
    # Match the gateway's CIMD fetch rule. Record redirect presence without logging Location values.
    fetch = build_opener(NoRedirect())
    facts = "HTTP unavailable, content-type=absent, redirect=unknown"
    try:
        with fetch.open(Request(document, headers={"Accept": "application/json"}), timeout=12) as response:
            facts = metadata_http(response)
            raw = response.read(8193)
    except HTTPError as response:
        with response:
            record(name, "hosted", "FAIL", f"environment: CIMD GET; {metadata_http(response)}, JSON=not read; {document}")
        return
    except (OSError, HTTPException) as error:
        record(name, "hosted", "FAIL", f"environment: CIMD GET {type(error).__name__}; {facts}, JSON=not read; {document}")
        return
    if len(raw) > 8192:
        record(name, "hosted", "FAIL", f"CIMD JSON exceeds size limit; {facts}, JSON=oversize; {document}")
        return
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        record(name, "hosted", "FAIL", f"CIMD JSON parsing failed; {facts}, JSON=invalid; {document}")
        return
    shape = {dict: "object", list: "array", str: "string", bool: "boolean", type(None): "null"}.get(type(data), "number")
    facts = f"{facts}, JSON={shape}"
    client_match = isinstance(data, dict) and data.get("client_id") == document
    redirects = data.get("redirect_uris") if isinstance(data, dict) else None
    callback_match = isinstance(redirects, list) and redirect in redirects
    if not client_match or not callback_match:
        record(name, "hosted", "FAIL", f"CIMD fields: client_id match={client_match}, callback match={callback_match}; {facts}; {document}")
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
        surrogate_passed = any(row[0] == "MCP TypeScript SDK" and row[2] == "PASS" for row in ROWS)
        if surrogate_passed:
            record(name, "hosted", "PASS", f"CIMD and exact HTTPS redirect; consent covered by loopback SDK; {facts}; {document}")
        else:
            record(name, "hosted", "FAIL", f"CIMD and exact HTTPS redirect passed; SDK consent surrogate failed; {facts}; {document}")
    else:
        method = data.get("token_endpoint_auth_method")
        method = method if method in ("none", "private_key_jwt", "client_secret_basic") else "other"
        record(name, "hosted", "FAIL", f"CIMD redirect checks returned {valid[0]}/{invalid[0]}; auth method {method}; {facts}; {document}")


def cli(name, version, package, binary, unavailable, env):
    prefix = TEMP / ("oauth-cli-" + binary)
    installed = run(["npm", "install", "--prefix", str(prefix), "--no-audit", "--no-fund",
                     f"{package}@{version}"], env, timeout=240)
    executable = str(prefix / "node_modules" / ".bin" / binary)
    version_check = run([executable, "--version"], env) if Path(executable).is_file() else installed
    if installed.returncode or version_check.returncode or version not in version_check.stdout:
        status = "FAIL" if FAULT == "qwen-consent" else "not_applicable"
        record(name, version, status, f"Pinned package {package} install/version probe failed on Linux ARM64")
        return
    if unavailable:
        record(name, version, "not_applicable", f"Binary version verified; {unavailable}")
        return
    if binary in {"qwen", "kimi"}:
        workspace = prefix / "probe-workspace"
        workspace.mkdir()
        url = env["OAUTH_TEST_ORIGIN"] + "/mcp/legacy"
        ttl = int(env["HUMAUX_GATEWAY_AUTH_OAUTH_ACCESS_TTL_SECONDS"])
        with witness() as events, model_stub(env["OAUTH_TEST_WORKSPACE"]) as model:
            if binary == "qwen":
                status, reason = asyncio.run(qwen_probe(executable, workspace, url, env, model, events, ttl))
            else:
                status, reason = asyncio.run(kimi_probe(executable, workspace, url, env, model, events, ttl))
        if FAULT == "qwen-consent":
            denied = ("consent denied", True) in events and not any(key == "exchange status" for key, _ in events)
            record(name, version, "FAIL", "consent denied by fixture; no exchange" if denied else
                   f"Consent denial not verified ({reason})")
            return
        if status != "not_applicable":
            missing = [key for key in ("PRM", "ASM", "DCR", "authorize", "consent", "code", "protocol", *TOOLS)
                       if (key, True) not in events]
            after_first_call = events[events.index(("tools/call", True)) + 1:] if ("tools/call", True) in events else []
            if ("refresh", True) not in after_first_call or ("tools/call", True) not in after_first_call:
                missing.append("post-expiry refresh and tool recovery")
            if refusal := next((value for key, value in events if key == "DCR refusal"), None):
                reason += f"; DCR refused: {refusal}"
            if missing:
                status = "FAIL"
                reason += f"; missing: {', '.join(missing)}"
            elif status == "PASS":
                reason = f"{discovery_route(events)}; DCR; consent callback; S256; equal resources; 2025-06-18; local model tools and refresh"
        record(name, version, status, reason)
        return
    # One model-free app-server session can call a configured MCP tool directly.
    config = [
        "-c", "mcp_oauth_credentials_store=\"file\"",
        "-c", f'mcp_servers.humaux_ci.url="{env["OAUTH_TEST_ORIGIN"]}/mcp/legacy"',
    ]
    with witness() as events:
        login = run([executable, *config, "mcp", "login", "humaux_ci", "--scopes", "memory:write",
                     "--oauth-client-registration", "dcr"], env)
        if login.returncode or ("consent", True) not in events or ("exchange status", 200) not in events:
            record(name, version, "FAIL", f"Native mcp login exit {login.returncode}; callback/exchange not confirmed")
            return
        try:
            asyncio.run(asyncio.wait_for(codex_tools(executable, config, env), timeout=360))
        except (AssertionError, KeyError, ValueError, OSError, TimeoutError, RuntimeError) as error:
            reason = str(error) if isinstance(error, CodexRpcError) else type(error).__name__
            trace = ", ".join(value for key, value in events if key == "MCP HTTP")
            record(name, version, "FAIL", f"Native login succeeded; {reason}; MCP HTTP: {trace or 'none'}")
            return
    missing = [key for key in ("PRM", "ASM", "DCR", "authorize", "consent", "code", "protocol", *TOOLS, "refresh")
               if (key, True) not in events]
    if missing or events.count(("tools/call", True)) < 2:
        record(name, version, "FAIL", f"Missing wire evidence: {', '.join(missing) or 'tool recovery'}")
    else:
        record(name, version, "PASS", f"{discovery_route(events)}; native CLI login, app-server tools/list and remember; automatic refresh")


class CodexRpcError(RuntimeError):
    """Keep only fixed diagnostics from a vendor RPC error."""

    def __init__(self, method, error):
        code = error.get("code")
        code = code if type(code) is int else "unknown"
        message = error.get("message", "")
        hints = ("MCP startup failed", "when send initialize request", "HTTP status client error",
                 "Invalid params", "unknown MCP server", "unknown tool", "missing field")
        matched = ", ".join(hint for hint in hints if hint in message)
        super().__init__(f"{method} error {code}" + (f" ({matched})" if matched else ""))


async def codex_tools(executable, config, env):
    process = await asyncio.create_subprocess_exec(
        executable, *config, "app-server", env=env, stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        # mcpServerStatus/list can return 105 KB on one NDJSON line, above asyncio's 64 KiB default.
        limit=4 * 1024 * 1024,
    )
    request_id = 0

    async def send(method, params=None, *, notification=False):
        nonlocal request_id
        message = {"method": method}
        if params is not None:
            message["params"] = params
        if not notification:
            request_id += 1
            message["id"] = request_id
        process.stdin.write((json.dumps(message) + "\n").encode())
        await process.stdin.drain()
        if notification:
            return None
        while line := await process.stdout.readline():
            reply = json.loads(line)
            if reply.get("id") == request_id:
                if "error" in reply:
                    raise CodexRpcError(method, reply["error"])
                return reply["result"]
        raise ValueError("Codex app-server closed")

    try:
        await send("initialize", {"clientInfo": {"name": "humaux-ci", "version": "1"}})
        await send("initialized", notification=True)
        thread = await send("thread/start", {"ephemeral": True})

        async def remember():
            reply = await send("mcpServer/tool/call", {
                "threadId": thread["thread"]["id"], "server": "humaux_ci", "tool": "remember",
                "arguments": {
                    "operation": "put", "content": "Synthetic Codex OAuth acceptance",
                    "workspace_id": env["OAUTH_TEST_WORKSPACE"], "idempotency_key": str(uuid4()),
                },
            })
            assert not reply.get("isError") and reply["structuredContent"]["evidence_id"]

        await send("mcpServerStatus/list", {})
        await remember()
        await asyncio.sleep(301)
        await remember()
    finally:
        if process.returncode is None:
            process.kill()
        await process.wait()


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
            elif FAULT == "gemini-consent":
                gemini(env)
            elif FAULT == "qwen-consent":
                cli(*next(row for row in CLI if row[3] == "qwen"), env)
            else:
                sdk("MCP TypeScript SDK", "1.32.2", [*ts, "--refresh"], env)
                check_pkce(ts, env)
                sdk("MCP Python SDK", "1.29.1", [sys.executable, str(HERE / "sdk_python.py")], env)
                for row in HOSTED:
                    hosted(*row, env)
                gemini(env)
                for row in CLI:
                    cli(*row, env)
                zcode(env)
                deepseek(env)
    except RuntimeError as error:
        record("CI infrastructure", "PG19", "FAIL", str(error))
    except Exception:
        record("CI infrastructure", "PG19", "FAIL", "Unexpected setup or harness error; raw exception suppressed")
    finally:
        reports()
    return int(any(row[2] == "FAIL" for row in ROWS))


if __name__ == "__main__":
    sys.exit(main())
