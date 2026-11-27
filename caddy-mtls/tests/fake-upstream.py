#!/usr/bin/env python3
"""Fake upstream for the smoke tests: answers a reverse proxy the way Home
Assistant Core does (homeassistant/components/http/forwarded.py).

usage: fake-upstream.py <port> <state-dir>

  * A request that carries X-Forwarded-For is answered 400 with aiohttp's
    body "400: Bad Request" (text/plain; charset=utf-8) unless the file
    <state-dir>/trust exists - Home Assistant without / with a trusted proxy.
    Each refusal appends one line to <state-dir>/refused.log (Home Assistant
    logs one ERROR line per refused request).
  * Every other request is answered 200 with a JSON echo of the request:
    method, path, peer address and all headers.
  * Every request is appended to <state-dir>/requests.jsonl (method, path,
    peer, the forwarding headers, refused or not).

HTTP/1.1 with keep-alive, like Home Assistant's server, so that the add-on's
monitor can keep its control connection open. Listens on 127.0.0.1 only.
"""
from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT = int(sys.argv[1])
STATE = Path(sys.argv[2])
STATE.mkdir(parents=True, exist_ok=True)
FORWARDING = ("X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Real-IP", "Forwarded", "Via")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # One write per response (headers and body), as aiohttp does: two small
    # writes would wait for the proxy's delayed ACK (Nagle).
    wbufsize = 64 * 1024

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        forwarded = {name: self.headers.get_all(name) for name in FORWARDING if name in self.headers}
        refused = "X-Forwarded-For" in self.headers and not (STATE / "trust").exists()
        record = {
            "method": self.command,
            "path": self.path,
            "peer": self.client_address[0],
            "forwarded": forwarded,
            "refused": refused,
        }
        with open(STATE / "requests.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
        if refused:
            with open(STATE / "refused.log", "a", encoding="utf-8") as fh:
                fh.write(
                    f"A request from a reverse proxy was received from {self.client_address[0]}, "
                    "but your HTTP integration is not set-up for reverse proxies\n"
                )
            self._send(400, b"400: Bad Request", "text/plain; charset=utf-8")
            return
        echo = {
            "method": self.command,
            "path": self.path,
            "peer": self.client_address[0],
            "headers": {name: self.headers.get_all(name) for name in self.headers.keys()},
        }
        self._send(200, json.dumps(echo).encode(), "application/json")

    do_GET = do_POST = do_HEAD = _handle

    def log_message(self, *args: object) -> None:  # quiet
        pass


class Server(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    Server(("127.0.0.1", PORT), Handler).serve_forever()
