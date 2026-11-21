"""Serve deterministic OpenAI Chat Completions to the native clients over loopback."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from uuid import uuid4


MODEL = "humaux-ci-stub"
KEY = "dummy-key"


class ModelHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, body, media="application/json"):
        self.send_response(200)
        self.send_header("Content-Type", media)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path != "/v1/models" or self.headers.get("Authorization") != f"Bearer {KEY}":
            self.send_error(404)
            return
        self.reply(json.dumps({"object": "list", "data": [{"id": MODEL, "object": "model"}]}).encode())

    def do_POST(self):
        if self.path != "/v1/chat/completions" or self.headers.get("Authorization") != f"Bearer {KEY}":
            self.send_error(404)
            return
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if body.get("model") != MODEL:
            self.send_error(400)
            return
        self.server.turns += 1
        names = [tool.get("function", {}).get("name", "") for tool in body.get("tools", [])]
        prefix = "mcp__humaux_ci__"
        wanted = self.server.wanted
        candidates = {wanted, f"humaux_ci__{wanted}", f"{prefix}{wanted}"}
        name = next((name for name in names if name in candidates), None)
        # A model can only ask the real CLI to call a tool it received in its catalog.
        if name and not self.server.emitted:
            arguments = {"operation": "put", "content": "Synthetic native OAuth acceptance",
                         "workspace_id": self.server.workspace, "idempotency_key": str(uuid4())}
            call = {"id": "call_" + uuid4().hex, "type": "function", "function": {
                "name": name, "arguments": json.dumps(arguments if wanted == "remember" else {}),
            }}
            self.server.emitted = True
            reply = {"role": "assistant", "content": None, "tool_calls": [call]}
            deltas = [{"role": "assistant"}, {"tool_calls": [{"index": 0, **call}]}]
            finish = "tool_calls"
        else:
            reply = {"role": "assistant", "content": "Fixture turn complete."}
            deltas = [reply]
            finish = "stop"
        envelope = {"id": "chatcmpl-" + uuid4().hex, "created": 1, "model": MODEL}
        usage = {"prompt_tokens": 8, "completion_tokens": 3, "total_tokens": 11}
        if not body.get("stream"):
            self.reply(json.dumps({**envelope, "object": "chat.completion", "usage": usage,
                                   "choices": [{"index": 0, "message": reply, "finish_reason": finish}]}).encode())
            return
        envelope["object"] = "chat.completion.chunk"
        chunks = [{**envelope, "choices": [{"index": 0, "delta": delta, "finish_reason": None}]}
                  for delta in deltas]
        chunks.append({**envelope, "choices": [{"index": 0, "delta": {}, "finish_reason": finish}]})
        chunks.append({**envelope, "choices": [], "usage": usage})
        stream = "".join(f"data: {json.dumps(chunk)}\n\n" for chunk in chunks) + "data: [DONE]\n\n"
        self.reply(stream.encode(), "text/event-stream")


@contextmanager
def model_stub(workspace):
    with ThreadingHTTPServer(("127.0.0.1", 0), ModelHandler) as server:
        server.url = f"http://127.0.0.1:{server.server_port}/v1"
        server.workspace = workspace
        server.turns = 0
        server.wanted = None
        server.emitted = False
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join()
