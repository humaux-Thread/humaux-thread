"""Tool-surface arms for X2 (how many tools) and X4 (description style), generated from catalog.ACTIONS.

Responsibility: map every canonical action to (tool name, action value) per arm and render the MCP `tools/list`
payload in the flat profile (root object, `action` enum when a tool has >1 action, union of fields, all optional
except `action`; per-action required fields are enforced by the grader, as the dispatcher would).
Depends on: catalog.py. Used by: stub_server.py (serves a rendered arm), run.py (decodes calls back to action ids).
Invariant: each arm covers every action exactly once (asserted in build()).
"""
import json
import sys

from catalog import ACTIONS

# arm -> {canonical tool group (catalog "tool") or action id: arm tool name}; action-id keys override group keys.
GROUPS = {
    # A: today's object-oriented 8 (remember, recall, memory, context, continuity, artifact, code, coordinate)
    "A8": {"brief": "context", "status": "context", "recall": "recall", "public_read": "recall",
           "remember": "remember", "revise": "memory", "share": "memory", "forget": "memory", "people": "memory",
           "plan": "memory", "review": "memory", "public_contribute": "memory", "public_revoke": "memory",
           "project": "continuity", "project.canvas_get": "coordinate", "project.canvas_patch": "coordinate",
           "project.lock_acquire": "coordinate", "project.lock_release": "coordinate", "checkpoint": "coordinate",
           "task": "coordinate", "files": "artifact", "code": "code"},
    # B: folded 11 (review->revise, lock->project, share+forget->revise, public 3->public, status->brief)
    "B11": {"brief": "brief", "status": "brief", "recall": "recall", "remember": "remember", "revise": "revise",
            "share": "revise", "forget": "revise", "review": "revise", "project": "project",
            "checkpoint": "project", "task": "task", "people": "people", "plan": "plan", "files": "files",
            "code": "code", "public_read": "public", "public_contribute": "public", "public_revoke": "public"},
    # C: design v1 14 rows
    "C14": {"brief": "brief", "recall": "recall", "remember": "remember", "revise": "revise", "share": "revise",
            "forget": "revise", "project": "project", "checkpoint": "project", "project.lock_acquire": "lock",
            "project.lock_release": "lock", "task": "task", "people": "people", "plan": "plan", "files": "files",
            "code": "code", "public_read": "public", "public_contribute": "public", "public_revoke": "public",
            "review": "review", "status": "status"},
    # D: B22 recommended 18 — identity mapping (filled in build())
    "D18": {},
    # E: ~30 fine-grained, split by effect
    "E30": {"brief": "brief", "recall.search": "recall_search", "recall.get": "recall_read",
            "recall.list": "recall_read", "recall.history": "recall_read", "recall.procedure": "recall_read",
            "recall.cases": "recall_cases", "remember": "remember",
            "revise.correct": "revise_content", "revise.supersede": "revise_content", "revise.pin": "revise_state",
            "revise.unpin": "revise_state", "revise.archive": "revise_state", "revise.restore": "revise_state",
            "share": "share", "forget": "forget", "project.get": "project_read", "project.canvas_get": "project_read",
            "project.publish": "project_write", "project.canvas_patch": "project_write",
            "project.lock_acquire": "lock", "project.lock_release": "lock", "checkpoint": "checkpoint",
            "task.create": "task_create", "task.list": "task_list", "task.claim": "task_lease",
            "task.renew": "task_lease", "task.finish": "task_finish", "task.block": "task_flow",
            "task.resume": "task_flow", "task.cancel": "task_flow", "people.resolve": "people_read",
            "people.profile": "people_read", "people.register": "people_write", "people.link_key": "people_write",
            "people.record_affect": "people_write", "plan.due": "plan_read", "plan.list": "plan_read",
            "plan.add": "plan_write", "plan.complete": "plan_write", "plan.reschedule": "plan_write",
            "plan.cancel": "plan_write", "files.status": "files_read", "files.get": "files_read",
            "files.list": "files_read", "files.search": "files_search", "files.attach": "files_write",
            "files.extract": "files_write", "code": "code", "review.pending": "review_read",
            "review.accept": "review_decide", "review.reject": "review_decide", "status": "status",
            "public_read": "public_read", "public_contribute": "public_contribute",
            "public_revoke": "public_revoke"},
    # P: one tool per action
    "P": {},
}
ARMS = list(GROUPS)


def _tool_of(arm, a):
    if arm == "D18":
        return a["tool"]
    if arm == "P":
        return a["id"].replace(".", "_")
    g = GROUPS[arm]
    return g.get(a["id"], g.get(a["tool"]))


def build(arm, include_cloud=True, style="short"):
    """Return (tools_list, decode) where decode maps (tool, action_value) -> action id."""
    acts = [a for a in ACTIONS if include_cloud or not a["cloud"]]
    by_tool = {}
    for a in acts:
        t = _tool_of(arm, a)
        assert t, f"{arm}: unmapped action {a['id']}"
        by_tool.setdefault(t, []).append(a)
    decode, tools = {}, []
    for t, members in by_tool.items():
        props, multi = {}, len(members) > 1
        values = []
        for a in members:
            v = a["id"].replace(".", "_") if multi and arm in ("A8", "B11", "C14") else a["action"]
            if multi and len({m["action"] for m in members}) < len(members):
                v = a["id"].replace(".", "_")
            values.append(v)
            decode[(t, v if multi else None)] = a["id"]
            for k, s in a["params"].items():
                props.setdefault(k, s)
        lines = [f"- {v}: {a['desc']}" for v, a in zip(values, members)]
        if multi:
            desc = f"Humaux Thread {t}. Choose one action:\n" + "\n".join(lines)
            props = {"action": {"type": "string", "enum": values}, **props}
            schema = {"type": "object", "properties": props, "required": ["action"], "additionalProperties": False}
        else:
            desc = f"Humaux Thread: {members[0]['desc']}"
            schema = {"type": "object", "properties": props, "additionalProperties": False}
        effects = {a["effect"] for a in members}
        tools.append({"name": t, "description": desc, "inputSchema": schema, "annotations": {
            "readOnlyHint": effects == {"read"}, "destructiveHint": bool(effects & {"destructive", "widening"})}})
    assert sorted(decode.values()) == sorted(a["id"] for a in acts), f"{arm}: coverage broken"
    return tools, decode


if __name__ == "__main__":
    for arm in ARMS:
        tools, _ = build(arm)
        print(f"{arm:4s} tools={len(tools):3d} list_chars={len(json.dumps(tools)):6d}", file=sys.stderr)
