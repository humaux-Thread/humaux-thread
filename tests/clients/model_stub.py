"""Serve deterministic OpenAI and Anthropic model replies over loopback."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from urllib.parse import urlsplit
from uuid import uuid4


MODEL = "humaux-ci-stub"
CLAUDE_MODEL = "claude-sonnet-4-6"
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
        path = urlsplit(self.path).path
        anthropic = path in {"/v1/messages", "/v1/messages/count_tokens"}
        allowed = self.headers.get("x-api-key") == KEY if anthropic else self.headers.get("Authorization") == f"Bearer {KEY}"
        if not allowed or (not anthropic and path != "/v1/chat/completions"):
            self.send_error(404)
            return
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if path == "/v1/messages/count_tokens":
            self.reply(b'{"input_tokens":8}')
            return
        if body.get("model") != (CLAUDE_MODEL if anthropic else MODEL):
            self.send_error(400)
            return
        self.server.turns += 1
        names = [tool.get("name") if anthropic else tool.get("function", {}).get("name") for tool in body.get("tools", [])]
        prefix = "mcp__humaux_ci__"
        wanted = self.server.wanted
        candidates = {wanted, f"humaux_ci__{wanted}", f"{prefix}{wanted}"}
        name = next((name for name in names if name in candidates), None)
        # A model can only ask the real CLI to call a tool it received in its catalog.
        if self.server.emitted:
            name = None
        arguments = {"operation": "put", "content": "Synthetic native OAuth acceptance",
                     "workspace_id": self.server.workspace, "idempotency_key": str(uuid4())} if wanted == "remember" else {}
        if name:
            self.server.emitted = True
        if anthropic:
            self.messages(name, arguments, body.get("stream"))
            return
        if name:
            call = {"id": "call_" + uuid4().hex, "type": "function", "function": {
                "name": name, "arguments": json.dumps(arguments),
            }}
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

    def messages(self, name, arguments, streaming):
        message = {"type": "message", "id": "msg_" + uuid4().hex, "role": "assistant", "model": CLAUDE_MODEL,
                   "content": [], "stop_reason": None, "stop_sequence": None,
                   "usage": {"input_tokens": 8, "output_tokens": 3}}
        if name:
            block = {"type": "tool_use", "id": "toolu_" + uuid4().hex, "name": name, "input": {}}
            delta = {"type": "input_json_delta", "partial_json": json.dumps(arguments)}
            completed = {**block, "input": arguments}
            stop_reason = "tool_use"
        else:
            block = {"type": "text", "text": ""}
            delta = {"type": "text_delta", "text": "Fixture turn complete."}
            completed = {**block, "text": delta["text"]}
            stop_reason = "end_turn"
        if not streaming:
            self.reply(json.dumps({**message, "content": [completed], "stop_reason": stop_reason}).encode())
            return
        events = [
            {"type": "message_start", "message": message},
            {"type": "content_block_start", "index": 0, "content_block": block},
            {"type": "content_block_delta", "index": 0, "delta": delta},
            {"type": "content_block_stop", "index": 0},
            {"type": "message_delta", "delta": {"stop_reason": stop_reason, "stop_sequence": None},
             "usage": {"output_tokens": 3}},
            {"type": "message_stop"},
        ]
        self.reply("".join(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n" for event in events).encode(),
                   "text/event-stream")


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
