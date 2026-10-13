"""
FRP Tunnel - frpc log watcher (stdlib only).

The frpc s6 service runs this script as a coprocess and points frpc's stdout
and stderr at it right before it execs frpc::

    coproc WATCH { exec python3 /usr/lib/frp-mgr/frpclog.py >&3 3>&-; }
    exec >&"${WATCH[1]}" 2>&1

Every line is passed on to the add-on log unchanged. Login events are
recorded in ``/run/frp-mgr/frpc-status.json`` (``$FRP_STATUS_FILE``; root
0600, no secrets) for the pairing panel:

``fingerprint``
    ``config.config_fingerprint`` of the ``frpc.toml`` + pinned CA frpc was
    started with (computed when the watcher starts, i.e. right before frpc
    reads them). The panel only trusts a status whose fingerprint matches
    the files that are current now.
``state``
    ``starting`` -> ``connecting`` (``try to connect to server...``) ->
    ``connected`` (``login to server success``) or ``failed``
    (``connect to server error: ...``).
``logged_in_at``
    Time of the last successful login with this fingerprint - with a pinned
    CA, the proof that frpc verified the tunnel server with it.
``login_failures`` / ``network_failures``
    Consecutive failed logins since the last success: ones that reached the
    server (TLS verification, authentication, protocol errors) and ones that
    did not (connection refused, timeout, DNS). The panel re-fetches the
    tunnel configuration after repeated login failures.
``last_error``
    The last frpc error, sanitised.

Counters survive frpc restarts as long as the configuration (fingerprint)
stays the same. A failure in here never stops the pass-through: frpc must
never block on, or be killed by, its log pipe.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, BinaryIO, Callable, Dict, Optional, Tuple

import config as cfg

STATUS_VERSION = 1
DEFAULT_STATUS_FILE = "/run/frp-mgr/frpc-status.json"

# frpc 0.65 log messages (client/service.go).
_CONNECTING = "try to connect to server"
_SUCCESS = "login to server success"
_FAILURE_RE = re.compile(r"(?:connect to server error|login to the server failed): ?(.*)")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
#: Errors raised before anything reached frps (no TLS handshake took place).
_NETWORK_ERRORS = (
    "connection refused", "i/o timeout", "no such host", "network is unreachable",
    "no route to host", "server misbehaving", "temporary failure in name resolution",
    "connection timed out", "host is unreachable",
)


def default_status_path() -> Path:
    return Path(os.environ.get("FRP_STATUS_FILE", DEFAULT_STATUS_FILE))


def classify(line: str) -> Optional[Tuple[str, str]]:
    """``(kind, reason)`` for a frpc log line: kind ``success``,
    ``connecting``, ``login`` (failed login that reached the server) or
    ``network`` (failed before that); None for any other line."""
    line = _ANSI_RE.sub("", line)
    if _SUCCESS in line:
        return "success", ""
    match = _FAILURE_RE.search(line)
    if match:
        reason = match.group(1).strip()
        lowered = reason.lower()
        return ("network" if any(err in lowered for err in _NETWORK_ERRORS) else "login"), reason
    if _CONNECTING in line:
        return "connecting", ""
    return None


def read_status(path: Path) -> Dict[str, Any]:
    """The watcher's status file, {} when missing or unreadable."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) and data.get("version") == STATUS_VERSION else {}


def _count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


class Watcher:
    """Turns frpc log lines into the status file (see module docstring)."""

    def __init__(self, path: Path, fingerprint: Optional[str],
                 clock: Callable[[], float] = time.time) -> None:
        self.path = path
        self.clock = clock
        now = clock()
        previous = read_status(path)
        same = fingerprint is not None and previous.get("fingerprint") == fingerprint
        carried = previous if same else {}
        self.status: Dict[str, Any] = {
            "version": STATUS_VERSION,
            "fingerprint": fingerprint,
            "pid": os.getpid(),
            "started_at": now,
            "updated_at": now,
            "state": "starting",
            "logged_in_at": carried.get("logged_in_at"),
            "login_failures": _count(carried.get("login_failures")),
            "network_failures": _count(carried.get("network_failures")),
            "last_error": carried.get("last_error") or "",
            "last_error_kind": carried.get("last_error_kind") or "",
            "last_error_at": carried.get("last_error_at"),
        }
        self.write()

    def feed(self, line: str) -> bool:
        """Account for one log line; True if the status changed."""
        event = classify(line)
        if event is None:
            return False
        kind, reason = event
        now = self.clock()
        status = self.status
        if kind == "success":
            status.update(state="connected", logged_in_at=now, login_failures=0, network_failures=0)
        elif kind == "connecting":
            status["state"] = "connecting"
        else:
            status["state"] = "failed"
            key = "login_failures" if kind == "login" else "network_failures"
            status[key] = status[key] + 1
            status.update(last_error=cfg.sanitize_text(reason, 200), last_error_kind=kind,
                          last_error_at=now)
        status["updated_at"] = now
        self.write()
        return True

    def write(self) -> None:
        """Atomically replace the status file - unless a newer watcher (frpc
        was restarted meanwhile) already owns it. Never raises."""
        try:
            current = read_status(self.path)
            if (current.get("pid") != self.status["pid"]
                    and isinstance(current.get("started_at"), (int, float))
                    and current["started_at"] > self.status["started_at"]):
                return
            self.path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            cfg.atomic_write(self.path, json.dumps(self.status, sort_keys=True) + "\n")
        except (OSError, ValueError, TypeError):
            pass


def run(source: BinaryIO, sink: BinaryIO, watcher: Watcher) -> None:
    """Copy ``source`` to ``sink`` line by line (flushed), feeding the
    watcher; returns at EOF."""
    for raw in iter(source.readline, b""):
        try:
            sink.write(raw)
            sink.flush()
        except (OSError, ValueError):
            pass  # keep draining: frpc must never block on its log pipe
        try:
            watcher.feed(raw.decode("utf-8", errors="replace"))
        except Exception:  # noqa: BLE001 - the pass-through must survive anything
            pass


def main() -> int:
    paths = cfg.default_paths()
    watcher = Watcher(default_status_path(), cfg.config_fingerprint(paths))
    run(sys.stdin.buffer, sys.stdout.buffer, watcher)
    return 0


if __name__ == "__main__":
    sys.exit(main())
