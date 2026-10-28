#!/usr/bin/env python3
"""Fake Home Assistant Supervisor for the smoke tests.

Answers every request with 200 and appends it (method, path, Authorization
header, JSON body) as one JSON line to <requests.jsonl>. The add-on's
cert-monitor reaches it through SUPERVISOR_URL (test-only override).

usage: fake-supervisor.py <port> <requests.jsonl>
"""
from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1])
LOG = sys.argv[2]


class Handler(BaseHTTPRequestHandler):
    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw) if raw else None
        except ValueError:
            body = raw.decode("utf-8", "replace")
        record = {
            "method": self.command,
            "path": self.path,
            "authorization": self.headers.get("Authorization", ""),
            "body": body,
        }
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
        out = b"[]"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST = _handle

    def log_message(self, *args: object) -> None:  # quiet
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
