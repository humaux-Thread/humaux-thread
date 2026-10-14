"""Direct-API runner for the tool-surface experiment (MiniMax via its Anthropic-compatible Messages endpoint).

Responsibility: one episode = the arm's tool list + a short system line + one user message, then up to MAX_TURNS
tool round-trips answered with canned results; graded with run.grade() (episode metric: expected action reached with
valid args, only reads before it, no wrong write). ~10x fewer tokens than headless Claude Code (no host prompt).
Quota guard (owner's shared MiniMax plan, lesson 2026-10-15): before every batch read /v1/token_plan/remains and stop
when the 5-hour window < MIN_WINDOW % or the weekly window < MIN_WEEKLY %, or when this run's input tokens exceed
TOKEN_BUDGET. A stop is recorded, never silently skipped.
Depends on: catalog.py, variants.py, scenarios.py, canned.py, run.py (grade/summarize). Env: MINIMAX_API_KEY,
MINIMAX_BASE (default https://api.minimaxi.com/anthropic), MINIMAX_MODEL (default MiniMax-M3). Never prints the key.
Used by: .github/workflows/exp-tool-surface.yml.
"""
import argparse
import concurrent.futures as cf
import json
import os
import time
import random
import urllib.error
import urllib.request

from canned import canned
from run import grade, summarize
from scenarios import CASES
from variants import ARMS, build

SYSTEM = ("The user's persistent memory and task system, Humaux Thread, is available through these tools. "
          "Use them when they help with the user's request; otherwise just answer.")
MAX_TURNS = 5


def post(url, body, key, timeout=120, tries=7):
    """POST with backoff on 429/5xx (run 38642028234: 103 episodes lost to HTTP 429 at 3 workers)."""
    data = json.dumps(body).encode()
    for attempt in range(tries):
        req = urllib.request.Request(url, data=data, method="POST", headers={
            "content-type": "application/json", "x-api-key": key, "authorization": f"Bearer {key}",
            "anthropic-version": "2023-06-01"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503, 529) or attempt == tries - 1:
                raise
            wait = float(e.headers.get("retry-after") or 0) or min(60, 2 ** attempt * 2)
            time.sleep(wait + random.uniform(0, 1.5))


def quota(key):
    """(5-hour %, weekly %) remaining, or None when the endpoint cannot be read with this key."""
    try:
        req = urllib.request.Request("https://www.minimaxi.com/v1/token_plan/remains",
                                     headers={"authorization": f"Bearer {key}"})
        with urllib.request.urlopen(req, timeout=15) as r:
            m = json.loads(r.read())["model_remains"][0]
        return m["current_interval_remaining_percent"], m["current_weekly_remaining_percent"]
    except Exception:
        return None


def episode(case, arm, rep, tools, decode, cfg):
    api_tools = [{"name": t["name"], "description": t["description"], "input_schema": t["inputSchema"]}
                 for t in tools]
    messages = [{"role": "user", "content": case["prompt"]}]
    calls, usage_in, first_in, err, t0 = [], 0, None, None, time.time()
    try:
        for _ in range(MAX_TURNS):
            out = post(f"{cfg['base']}/v1/messages", {"model": cfg["model"], "max_tokens": 1024, "system": SYSTEM,
                                                       "tools": api_tools, "messages": messages}, cfg["key"])
            u = out.get("usage") or {}
            turn_in = (u.get("input_tokens") or 0) + (u.get("cache_read_input_tokens") or 0)
            usage_in += turn_in
            if first_in is None:
                first_in = turn_in  # ≈ system line + this arm's tool list + the user message: the context cost
            uses = [b for b in out.get("content", []) if b.get("type") == "tool_use"]
            if not uses:
                break
            messages.append({"role": "assistant", "content": out["content"]})
            results = []
            for b in uses:
                args = b.get("input") or {}
                key = (b["name"], args.get("action")) if (b["name"], args.get("action")) in decode else (b["name"], None)
                aid = decode.get(key)
                calls.append({"tool": b["name"], "args": args, "action_id": aid})
                body = canned(aid) if aid else {"content": [{"type": "text", "text": "Unknown tool or action."}]}
                results.append({"type": "tool_result", "tool_use_id": b["id"],
                                "content": body["content"][0]["text"], "is_error": aid is None})
            messages.append({"role": "user", "content": results})
    except Exception as e:  # recorded as a failed episode, never dropped
        err = f"{type(e).__name__}: {str(e)[:160]}"
    row = grade(case, arm, rep, cfg["label"], calls, {"usage": {"input_tokens": usage_in}}, err, time.time() - t0)
    row["first_turn_input_tokens"] = first_in
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arms", default=",".join(ARMS))
    ap.add_argument("--reps", type=int, default=1)
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--min-window", type=float, default=50.0)
    ap.add_argument("--min-weekly", type=float, default=25.0)
    ap.add_argument("--token-budget", type=int, default=12_000_000)
    ap.add_argument("--out", default="results")
    a = ap.parse_args()
    cfg = {"key": os.environ["MINIMAX_API_KEY"], "base": os.environ.get("MINIMAX_BASE", "https://api.minimaxi.com/anthropic"),
           "model": os.environ.get("MINIMAX_MODEL", "MiniMax-M3")}
    cfg["label"] = cfg["model"].lower()
    os.makedirs(a.out, exist_ok=True)
    path = os.path.join(a.out, f"results_{cfg['label']}_api.jsonl")
    rows, spent, stop = [], 0, None
    with open(path, "w") as f:
        for rep in range(a.reps):
            for arm in a.arms.split(","):          # one batch = one arm × all cases
                q = quota(cfg["key"])
                if q and (q[0] < a.min_window or q[1] < a.min_weekly):
                    stop = f"quota guard before {arm} rep {rep}: 5h {q[0]}% weekly {q[1]}%"
                    break
                if spent > a.token_budget:
                    stop = f"token budget reached before {arm} rep {rep}: {spent} input tokens"
                    break
                tools, decode = build(arm)
                with cf.ThreadPoolExecutor(a.workers) as ex:
                    for row in ex.map(lambda c: episode(c, arm, rep, tools, decode, cfg), CASES):
                        rows.append(row)
                        spent += row["input_tokens"]
                        f.write(json.dumps(row, ensure_ascii=False) + "\n")
                        f.flush()
                print(f"{arm} rep {rep}: done, run input tokens so far {spent}, quota {q}", flush=True)
            if stop:
                break
    md = summarize(rows, cfg["label"] + " (direct API)")
    # Context cost per arm (owner 2026-10-15: 70+ tools eat the agent's context): the smallest first-turn input seen
    # for the arm is the tool list + system line + the shortest prompt.
    md += "\n| arm | tool-list context (first-turn input tokens, min / median) |\n|---|---|\n"
    for arm in a.arms.split(","):
        v = sorted(r["first_turn_input_tokens"] for r in rows if r["arm"] == arm and r.get("first_turn_input_tokens"))
        if v:
            md += f"| {arm} | {v[0]} / {v[len(v) // 2]} |\n"
    md += f"\nrun input tokens: {spent}; stop: {stop or 'none'}; final quota: {quota(cfg['key'])}\n"
    open(os.path.join(a.out, f"summary_{cfg['label']}_api.md"), "w").write(md)
    print(md)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        open(os.environ["GITHUB_STEP_SUMMARY"], "a").write(md)


if __name__ == "__main__":
    main()
