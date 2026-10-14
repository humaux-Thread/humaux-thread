"""Canned tool results shared by the stub MCP server and the direct-API runner (no real backend).

Used by: stub_server.py, run_api.py.
"""
import json


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
