"""Canonical action catalog for the MCP tool-surface experiment (X2 grouping/tool count, X4 descriptions).

Responsibility: every model-facing action the full system offers, once. The canonical set is the 18-tool surface that
GPT batch 22 recommended (15 OSS + 3 cloud), expressed as (tool, action) pairs; arms in variants.py regroup the same
actions into 8 / 12 / 14 / 18 / ~30 / one-per-action tools, so every arm is graded against the same labels.
Control-plane operations (batch reservation, repository registration/sync, code overlay transport, upload transport)
are deliberately absent: B22 moves them to the client/SDK control plane.
Depends on: nothing (stdlib). Used by: variants.py, stub_server.py, run.py.
Invariant: action ids are unique and stable; scenarios refer to action ids, never to tool names.
"""

S, I, B = {"type": "string"}, {"type": "integer"}, {"type": "boolean"}


def enum(*v):
    return {"type": "string", "enum": list(v)}


def arr(item=None):
    return {"type": "array", "items": item or S}


MEMORY_TYPES = enum("note", "decision", "fix", "preference", "rejection", "lesson", "problem", "outcome",
                    "constraint", "procedure", "state", "reference")
FACETS = enum("goal", "current_state", "decisions", "rejections", "constraints", "known_issues", "next_actions",
              "procedures", "outcomes")
CTX = {"context_ref": S}

# effect: read | additive | mutate | destructive | widening   (tool-level annotations are derived from these)
A = []


def act(id, effect, desc, params=None, required=(), cloud=False):
    p = dict(CTX)
    p.update(params or {})
    A.append({"id": id, "tool": id.split(".")[0], "action": id.split(".")[1], "effect": effect, "desc": desc,
              "params": p, "required": list(required), "cloud": cloud})


# brief (single action)
act("brief.get", "read", "Orientation pack: project goal, state, constraints, rejected approaches, next actions, your "
    "open tasks, last hand-off. Call at session start, after context compaction, or when resuming someone's work.",
    {"task_ref": S})
# recall
act("recall.search", "read", "Search stored knowledge. Call before choosing an approach, before saying something "
    "cannot be done, when an error appears, or when asked what is known.",
    {"query": S, "mode": enum("auto", "semantic", "lexical", "exact"), "subject_ref": S, "limit": I}, ["query"])
act("recall.get", "read", "Read one memory in full by its ref (a hit was truncated or exact wording is needed).",
    {"memory_ref": S}, ["memory_ref"])
act("recall.list", "read", "Enumerate memories by filter with a truthful total. Call when asked for all/every/which.",
    {"memory_type": MEMORY_TYPES, "subject_ref": S, "since": S, "until": S, "cursor": S})
act("recall.history", "read", "Version history of one memory (what it said before, what replaced it).",
    {"memory_ref": S}, ["memory_ref"])
act("recall.procedure", "read", "Full text of a named procedure listed in the brief.", {"name": S}, ["name"])
act("recall.cases", "read", "Past problem-solution episodes similar to the current problem, including approaches that "
    "failed.", {"problem": S}, ["problem"], cloud=True)
# remember (single action)
act("remember.put", "additive", "Record knowledge: a decision, a fix (root cause + solution), a preference, a "
    "rejected approach, a correction from the user, a measured outcome, or an episode (situation, interpretation, "
    "action, outcome). Not for chit-chat or facts already stored.",
    {"text": S, "memory_type": MEMORY_TYPES, "subject_refs": arr(), "idempotency_key": S,
     "episode": {"type": "object", "properties": {"situation": S, "interpretation": S, "action": S, "outcome": S}}},
    ["text"])
# revise
act("revise.correct", "mutate", "Correct the text of a stored memory that is wrong.", {"memory_ref": S, "text": S},
    ["memory_ref", "text"])
act("revise.supersede", "mutate", "Mark an older memory as replaced by a newer one.",
    {"memory_ref": S, "replacement_ref": S}, ["memory_ref", "replacement_ref"])
act("revise.pin", "mutate", "Pin a memory so it is always in the brief (user: always remember this rule).",
    {"memory_ref": S}, ["memory_ref"])
act("revise.unpin", "mutate", "Unpin a memory.", {"memory_ref": S}, ["memory_ref"])
act("revise.archive", "mutate", "Archive an obsolete memory (hidden from recall, kept).", {"memory_ref": S},
    ["memory_ref"])
act("revise.restore", "mutate", "Restore an archived memory.", {"memory_ref": S}, ["memory_ref"])
# share (widening)
act("share.preview", "read", "Preview what sharing a memory with another of the user's workspaces would expose.",
    {"memory_ref": S, "workspace_ref": S}, ["memory_ref", "workspace_ref"])
act("share.grant", "widening", "Share a memory with another of the user's workspaces after preview.",
    {"proposal_ref": S}, ["proposal_ref"])
act("share.revoke", "mutate", "Stop sharing a memory.", {"memory_ref": S, "workspace_ref": S}, ["memory_ref"])
# forget (destructive)
act("forget.preview", "read", "Preview permanently forgetting memories (user asks to delete or forget something).",
    {"memory_refs": arr(), "subject_ref": S}, [])
act("forget.commit", "destructive", "Permanently forget after preview and user approval.", {"proposal_ref": S},
    ["proposal_ref"])
act("forget.status", "read", "Status of a forget operation.", {"operation_ref": S}, ["operation_ref"])
# project
act("project.get", "read", "Authoritative project continuity facets (goal, state, decisions, rejections, next "
    "actions).", {"project_ref": S})
act("project.publish", "mutate", "Replace one project facet (goal, constraints, known issues changed).",
    {"facet": FACETS, "body": S, "base_revision": S}, ["facet", "body"])
act("project.canvas_get", "read", "Read the shared task canvas.", {})
act("project.canvas_patch", "mutate", "Patch your element of the shared task canvas.",
    {"element": S, "todo": arr(), "doing": arr(), "done": arr(), "canvas_revision": S}, ["element"])
act("project.lock_acquire", "mutate", "Lock a shared resource before changing it.", {"resource": S, "ttl_seconds": I},
    ["resource"])
act("project.lock_release", "mutate", "Release a lock.", {"resource": S}, ["resource"])
# checkpoint (single action)
act("checkpoint.save", "mutate", "Save progress on your task: done steps, current step, next steps; disposition "
    "continue (keep working) or yield (stopping: usage limit, end of session — hands off to the next agent).",
    {"task_ref": S, "done": arr(), "doing": S, "next_actions": arr(), "disposition": enum("continue", "yield")},
    ["next_actions", "disposition"])
# task
act("task.create", "additive", "Create a task for work that should be tracked or delegated.",
    {"title": S, "description": S}, ["title"])
act("task.list", "read", "List tasks and who holds them.", {"status": S})
act("task.claim", "mutate", "Claim a task (take ownership with a lease) before starting work others may pick up.",
    {"task_ref": S})
act("task.renew", "mutate", "Renew your task lease during long work.", {"task_ref": S}, ["task_ref"])
act("task.finish", "mutate", "Finish your task: outcome done or failed, with evidence.",
    {"task_ref": S, "outcome": enum("done", "failed"), "summary": S, "evidence": S}, ["task_ref", "outcome", "summary"])
act("task.block", "mutate", "Mark your task blocked on the user or another task.", {"task_ref": S, "reason": S},
    ["task_ref", "reason"])
act("task.resume", "mutate", "Resume a blocked task.", {"task_ref": S}, ["task_ref"])
act("task.cancel", "mutate", "Cancel a task that is no longer needed.", {"task_ref": S}, ["task_ref"])
# people
act("people.resolve", "read", "Find which registered person/organisation/customer a name or identifier refers to.",
    {"name_or_key": S}, ["name_or_key"])
act("people.register", "additive", "Register a new person, organisation or customer.",
    {"name": S, "kind": enum("person", "organisation", "customer"), "roles": arr()}, ["name", "kind"])
act("people.link_key", "mutate", "Attach an identifier (email, handle, phone) to a registered person.",
    {"subject_ref": S, "key_kind": S, "value": S}, ["subject_ref", "key_kind", "value"])
act("people.profile", "read", "Everything known about a person/organisation: facts, timeline, affect, open "
    "follow-ups. Call before talking to or about them.", {"subject_ref": S}, ["subject_ref"])
act("people.record_affect", "additive", "Record an interpreted emotional reading of a person, with evidence.",
    {"subject_ref": S, "affect": S, "evidence": S}, ["subject_ref", "affect"])
# plan
act("plan.add", "additive", "Add a plan, reminder or follow-up with a due time.",
    {"text": S, "due": S, "kind": enum("plan", "reminder", "follow_up"), "subject_ref": S}, ["text", "due"])
act("plan.due", "read", "Plans and reminders that are due.", {"within_days": I})
act("plan.list", "read", "List plans and reminders.", {"kind": S})
act("plan.complete", "mutate", "Mark a plan or reminder done.", {"plan_ref": S}, ["plan_ref"])
act("plan.reschedule", "mutate", "Move a plan or reminder to a new due time.", {"plan_ref": S, "due": S},
    ["plan_ref", "due"])
act("plan.cancel", "mutate", "Cancel a plan or reminder.", {"plan_ref": S}, ["plan_ref"])
# files
act("files.attach", "additive", "Attach a file the user gave (screenshot, email export, document) as evidence.",
    {"filename": S, "content_type": S, "artifact_ref": S}, ["filename"])
act("files.status", "read", "Status of an attached file.", {"artifact_ref": S}, ["artifact_ref"])
act("files.get", "read", "Metadata and link of a stored file.", {"artifact_ref": S}, ["artifact_ref"])
act("files.list", "read", "List stored files.", {"cursor": S})
act("files.search", "read", "Search stored files and documents.", {"query": S}, ["query"])
act("files.extract", "additive", "Extract text from a stored image or document (OCR with the user's own model key).",
    {"artifact_ref": S}, ["artifact_ref"])
# code
act("code.search", "read", "Search code for where something is implemented.", {"query": S, "repository_ref": S},
    ["query"])
act("code.symbol", "read", "Definition of a named symbol.", {"symbol": S, "repository_ref": S}, ["symbol"])
act("code.relations", "read", "Callers and callees of a symbol.", {"symbol": S, "repository_ref": S}, ["symbol"])
act("code.impact", "read", "What may break if a symbol changes.", {"symbol": S, "repository_ref": S}, ["symbol"])
act("code.index_status", "read", "Whether the code index is current.", {"repository_ref": S})
# review
act("review.pending", "read", "Items waiting for the user's decision: proposed rules, merges, contradictions, stale.",
    {"kind": enum("rule", "merge", "contradiction", "stale")})
act("review.accept", "mutate", "Accept a pending item the user approved.", {"proposal_ref": S}, ["proposal_ref"])
act("review.reject", "mutate", "Reject a pending item.", {"proposal_ref": S}, ["proposal_ref"])
# status
act("status.account", "read", "Plan, quota, usage, edition.", {})
act("status.health", "read", "Processing completeness and health (was everything processed?).", {})
act("status.operation", "read", "Status of a long-running operation by ref.", {"operation_ref": S},
    ["operation_ref"])
# cloud public pool
act("public_read.search", "read", "Search the public knowledge pool shared by all users.", {"query": S}, ["query"],
    cloud=True)
act("public_read.get", "read", "Read one public entry.", {"entry_ref": S}, ["entry_ref"], cloud=True)
act("public_read.status", "read", "Status of the user's public contributions.", {}, cloud=True)
act("public_contribute.preview", "read", "Preview the de-identified form of a memory proposed for the public pool.",
    {"memory_ref": S}, ["memory_ref"], cloud=True)
act("public_contribute.submit", "widening", "Submit a previewed contribution to the public pool.",
    {"proposal_ref": S}, ["proposal_ref"], cloud=True)
act("public_contribute.status", "read", "Status of a contribution.", {"proposal_ref": S}, ["proposal_ref"], cloud=True)
act("public_revoke.preview", "read", "Preview withdrawing a public contribution.", {"contribution_ref": S},
    ["contribution_ref"], cloud=True)
act("public_revoke.commit", "destructive", "Withdraw a public contribution after preview.", {"proposal_ref": S},
    ["proposal_ref"], cloud=True)
act("public_revoke.status", "read", "Status of a withdrawal.", {"operation_ref": S}, ["operation_ref"], cloud=True)

ACTIONS = A
BY_ID = {a["id"]: a for a in A}
assert len(BY_ID) == len(A), "duplicate action id"
