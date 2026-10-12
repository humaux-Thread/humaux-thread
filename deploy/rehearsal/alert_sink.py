#!/usr/bin/env python3
# deploy/rehearsal/alert_sink.py <port> <jsonl> — the clean-node rehearsal's Alertmanager webhook receiver (ADR-0066 §5,
# the twin of rehearse.sh's ADR-0061 D-K sink). Runs as prod.yml's `alert-sink` (profile rehearsal) in the shared
# network namespace, so 127.0.0.1:<port> is reachable from Alertmanager and from nothing outside the node.
# Every POST body becomes one compact JSON line {"path", "body"} appended to <jsonl> (the evidence dir); the Watchdog
# receipt carries the deployed git sha (watchdog_carries_sha). Stdlib only; no secret is read or written.
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

port, out = int(sys.argv[1]), sys.argv[2]


class Sink(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        try:
            body = json.loads(raw)
        except ValueError:
            body = raw.decode("utf-8", "replace")
        with open(out, "a") as f:
            f.write(json.dumps({"path": self.path, "body": body}, separators=(",", ":")) + "\n")
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


HTTPServer(("127.0.0.1", port), Sink).serve_forever()
