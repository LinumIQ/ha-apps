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
    peer, the forwarding headers, the names of all headers in lower case,
    refused or not).
  * A websocket upgrade (Upgrade: websocket, Sec-WebSocket-Key) that is not
    refused is answered "101 Switching Protocols" (with the RFC 6455 accept
    value); the connection is closed after a second.

HTTP/1.1 with keep-alive, like Home Assistant's server, so that the add-on's
monitor can keep its control connection open. Listens on 127.0.0.1 only.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT = int(sys.argv[1])
STATE = Path(sys.argv[2])
STATE.mkdir(parents=True, exist_ok=True)
FORWARDING = ("X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Real-IP", "Forwarded", "Via")
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


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
            "header_names": sorted({name.lower() for name in self.headers.keys()}),
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
        ws_key = self.headers.get("Sec-WebSocket-Key")
        if (self.headers.get("Upgrade") or "").lower() == "websocket" and ws_key:
            accept = base64.b64encode(hashlib.sha1((ws_key + WS_GUID).encode()).digest()).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            self.wfile.flush()
            time.sleep(1)
            self.close_connection = True
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
