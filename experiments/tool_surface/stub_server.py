"""Stub MCP server (stdio, newline-delimited JSON-RPC) serving one tool-surface arm and logging every call.

Responsibility: let a real agent host (Claude Code headless) see the arm's tools/list and record which tool/arguments
the model chose; answer calls with small canned results so the episode can finish. No real memory system behind it.
Depends on: variants.py. Used by: run.py via the host's --mcp-config.
Env: STUB_ARM (arm name), STUB_LOG (JSONL path), STUB_CLOUD ("1" to list cloud actions).
Invariant: every tools/call is appended to STUB_LOG before the response is written.
"""
import json
import os
import sys

from variants import build

ARM = os.environ["STUB_ARM"]
LOG = os.environ["STUB_LOG"]
TOOLS, DECODE = build(ARM, include_cloud=os.environ.get("STUB_CLOUD", "1") == "1")


def canned(action_id):
    tool = action_id.split(".")[0]
    if action_id.endswith(("search", ".list", ".cases", ".due", ".pending")):
        body = {"items": [{"ref": "m_1001", "text": "Earlier note relevant to the query."}], "returned_count": 1,
                "total": 1, "total_relation": "exact"}
    elif action_id.endswith(".preview"):
        body = {"proposal_ref": "p_2001", "preview": "1 item would be affected", "requires_user_approval": True}
    elif tool in ("brief",):
        body = {"goal": "Ship the importer", "next_actions": ["write tests"], "open_tasks": [], "last_handoff": None}
    else:
        body = {"ok": True, "ref": "r_3001", "receipt": "committed"}
    return {"content": [{"type": "text", "text": json.dumps(body)}], "structuredContent": body, "isError": False}


def reply(id, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": id}
    msg["error" if error else "result"] = error or result
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    if not line.strip():
        continue
    req = json.loads(line)
    method, id = req.get("method"), req.get("id")
    if id is None:
        continue  # notifications
    if method == "initialize":
        reply(id, {"protocolVersion": req["params"].get("protocolVersion", "2025-06-18"),
                   "capabilities": {"tools": {}}, "serverInfo": {"name": "humaux-thread", "version": "exp"}})
    elif method == "tools/list":
        reply(id, {"tools": TOOLS})
    elif method == "tools/call":
        name, args = req["params"]["name"], req["params"].get("arguments") or {}
        key = (name, args.get("action")) if (name, args.get("action")) in DECODE else (name, None)
        action_id = DECODE.get(key)
        with open(LOG, "a") as f:
            f.write(json.dumps({"tool": name, "args": args, "action_id": action_id}) + "\n")
        if action_id is None:
            reply(id, {"content": [{"type": "text", "text": "Unknown tool or action."}], "isError": True})
        else:
            reply(id, canned(action_id))
    elif method == "ping":
        reply(id, {})
    else:
        reply(id, error={"code": -32601, "message": "method not found"})
