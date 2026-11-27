#!/usr/bin/env python3
"""Minimal Home Assistant websocket client for tests/real-core.sh (standard
library only).

usage: real-core-ws.py <url> <token> [--cert FILE --key FILE] [--connect HOST:PORT]
                       <command> [<json>]

  <url>       ws://homeassistant:8123/api/websocket or
              wss://<domain>/api/websocket (through the add-on)
  --connect   connect to HOST:PORT instead of the URL's host (keeps the URL's
              host as SNI and Host header, like curl --resolve)
  command     ping            auth, then ping -> prints "pong"
              call <json>     auth, then send <json> (an "id" is added) and
                              print the result as JSON
  Exit 0 on success; prints the error and exits 1 otherwise.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import ssl
import struct
import sys
from urllib.parse import urlsplit


class WebSocket:
    def __init__(self, url: str, connect: str | None, cert: str | None, key: str | None) -> None:
        parts = urlsplit(url)
        secure = parts.scheme == "wss"
        host = parts.hostname or ""
        port = parts.port or (443 if secure else 80)
        if connect:
            chost, _, cport = connect.rpartition(":")
            addr = (chost.strip("[]"), int(cport))
        else:
            addr = (host, port)
        sock = socket.create_connection(addr, timeout=15)
        if secure:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if cert:
                ctx.load_cert_chain(cert, key)
            sock = ctx.wrap_socket(sock, server_hostname=host)
        self.sock = sock
        self.buf = b""
        nonce = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET {parts.path or '/'} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {nonce}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        sock.sendall(request.encode())
        head = self._read_until(b"\r\n\r\n")
        status = head.split(b"\r\n", 1)[0].decode(errors="replace")
        if " 101 " not in status:
            raise RuntimeError(f"handshake failed: {status}")
        self.next_id = 1

    def _read_until(self, marker: bytes) -> bytes:
        while marker not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RuntimeError("connection closed")
            self.buf += chunk
        head, self.buf = self.buf.split(marker, 1)
        return head

    def _read_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RuntimeError("connection closed")
            self.buf += chunk
        data, self.buf = self.buf[:n], self.buf[n:]
        return data

    def send(self, message: dict) -> None:
        payload = json.dumps(message).encode()
        header = bytearray([0x81])
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += struct.pack("!H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack("!Q", n)
        mask = os.urandom(4)
        header += mask
        self.sock.sendall(bytes(header) + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def recv(self) -> dict:
        message = b""
        while True:
            b1, b2 = self._read_exact(2)
            opcode, n = b1 & 0x0F, b2 & 0x7F
            if n == 126:
                n = struct.unpack("!H", self._read_exact(2))[0]
            elif n == 127:
                n = struct.unpack("!Q", self._read_exact(8))[0]
            data = self._read_exact(n)
            if opcode == 8:
                raise RuntimeError("server closed the websocket")
            if opcode in (1, 0):
                message += data
                if b1 & 0x80:
                    return json.loads(message)

    def auth(self, token: str) -> None:
        hello = self.recv()
        if hello.get("type") != "auth_required":
            raise RuntimeError(f"unexpected greeting: {hello}")
        self.send({"type": "auth", "access_token": token})
        answer = self.recv()
        if answer.get("type") != "auth_ok":
            raise RuntimeError(f"auth failed: {answer}")

    def call(self, message: dict) -> dict:
        message = dict(message, id=self.next_id)
        self.next_id += 1
        self.send(message)
        while True:
            answer = self.recv()
            if answer.get("id") == message["id"]:
                return answer


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("token")
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--connect")
    parser.add_argument("command", choices=("ping", "call"))
    parser.add_argument("json", nargs="?")
    args = parser.parse_args()
    try:
        ws = WebSocket(args.url, args.connect, args.cert, args.key)
        ws.auth(args.token)
        if args.command == "ping":
            answer = ws.call({"type": "ping"})
            if answer.get("type") != "pong":
                raise RuntimeError(f"no pong: {answer}")
            print("pong")
        else:
            print(json.dumps(ws.call(json.loads(args.json or "{}"))))
    except (OSError, RuntimeError, ValueError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
