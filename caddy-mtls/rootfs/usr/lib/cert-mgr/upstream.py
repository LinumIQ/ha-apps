"""
Caddy mTLS Proxy - the connection to the upstream (Home Assistant Core).

Home Assistant answers a request that carries ``X-Forwarded-For`` with
"400: Bad Request" unless its HTTP settings trust the proxy, and logs one
ERROR line per such request (Core 2026.11:
homeassistant/components/http/forwarded.py). Caddy's ``reverse_proxy`` sends
that header on every request. This module

  * asks the upstream whether it accepts forwarded requests from this add-on
    (``probe``: a control request without forwarding headers, then the same
    request with them; a differential 400 means "refused");
  * decides whether Caddy passes the visitor's address on (mode ``pass``) or
    removes every forwarding header (mode ``strip``) - ``decide``, from the
    option ``forwarded_headers`` (auto | always | never), ``mtls_enabled``
    and the last decisive probe result;
  * switches Caddy at run time: both ``reverse_proxy`` blocks of the
    Caddyfile import SNIPPET_FILE, which is rewritten atomically before a
    forced ``caddy reload``. One file lock (LOCK_FILE) covers probe, write
    and reload: the monitor and the panel can both do it.

Every refused test request writes an ERROR line into Home Assistant's log,
so the test request is only sent at the start, when the upstream answers
again after it was unreachable (or after it closed the connection the
monitor keeps open to it: a restart), on "Check again" in the panel and -
only while Home Assistant accepts forwarded requests, which it then does not
log - once a minute in mode ``pass`` under ``auto``. The control request (no
forwarding header) is never logged by Home Assistant; the monitor sends it
every few seconds to watch the upstream. A control request that times out
means "slow", not "down": the upstream counts as unreachable after a failed
connect or after two failures in a row. A test request that times out is
retried at the normal interval, and after SLOW_TESTS_MAX in a row only at
the next event (a restart of the upstream, "Check again", the add-on's
start).

Shared by init-caddy (``upstream.py start``, before Caddy starts), the
monitor (monitor.py) and the panel (app.py). Standard library only.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import http.client
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

import caddyctl

STATE_FILE = Path(os.environ.get("CADDY_MTLS_UPSTREAM_STATE", "/data/upstream.json"))
SNIPPET_FILE = Path(os.environ.get("CADDY_MTLS_FORWARD_SNIPPET", "/etc/caddy/forwarded-headers.caddy"))
LOCK_FILE = Path(os.environ.get("CADDY_MTLS_UPSTREAM_LOCK", "/run/caddy-mtls/upstream.lock"))
CADDY_BIN = os.environ.get("CADDY_BIN", "/usr/bin/caddy")
CADDYFILE = Path(os.environ.get("CADDYFILE", "/etc/caddy/Caddyfile"))
CADDY_ADMIN = os.environ.get("CADDY_ADMIN", "localhost:2019")

OPTIONS = ("auto", "always", "never")
PASS = "pass"
STRIP = "strip"

ACCEPTED = "accepted"
REFUSED = "refused"
UNREACHABLE = "unreachable"
REACHABLE = "reachable"  # a control request only: the upstream answers
#: Connected, but no answer in time (or the connection closed without one):
#: no decision, no state change - unreachable only after FAILURES_UNREACHABLE
#: such failures in a row (the monitor's watch) or a failed connect.
SLOW = "slow"
UNKNOWN = "unknown"
#: The card state while the last mode change could not be applied to Caddy.
RELOAD_FAILED = "reload_failed"
#: The card state after SLOW_TESTS_MAX test requests in a row without an
#: answer in time while nothing is decided: the add-on stopped retrying.
TOO_SLOW = "too_slow"
FAILURES_UNREACHABLE = 2
#: Test requests in a row without an answer in time after which the add-on
#: stops sending them on its own (until the next event).
SLOW_TESTS_MAX = 3
#: The longest error text of a failed Caddy reload that is kept (state file,
#: log, card).
RELOAD_ERROR_MAX = 500

#: The request of the probe; Home Assistant's frontend serves it without
#: authentication and without logging.
PROBE_PATH = "/manifest.json"
#: The visitor address of the test request (TEST-NET-1, RFC 5737).
TEST_CLIENT = "192.0.2.1"
#: Seconds per connection / request of the probe; the whole probe (two
#: requests and a name lookup) ends within PROBE_DEADLINE.
REQUEST_TIMEOUT = 2.0
PROBE_DEADLINE = 5.0
#: The same while the add-on runs (the monitor's watch, "Check again"):
#: Home Assistant can take a few seconds to answer while it starts. A pause
#: shorter than WATCH_TIMEOUT + the control interval never makes two
#: control requests in a row fail.
WATCH_TIMEOUT = 5.0
USER_AGENT = "caddy-mtls-upstream-check"

#: The network Home Assistant's own documentation of its proxy add-ons
#: recommends for trusted_proxies: the add-on range of Supervisor's network.
HA_ADDON_NETWORK = ip_network("172.30.33.0/24")

#: The forwarding headers. Caddy sets X-Forwarded-For/-Proto/-Host itself (a
#: client's own values are replaced: no proxy is trusted); X-Real-IP is set by
#: the add-on in mode pass; Forwarded (RFC 7239) only comes from clients.
STRIPPED_HEADERS = ("X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Real-IP", "Forwarded")


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Settings:
    """What the add-on was started with (init-caddy's runtime.json)."""

    domain: str
    host: str
    port: int
    mtls: bool
    option: str = "auto"
    #: Header authentication is on (2.3.0): a holder of the key gets in like
    #: a holder of a client certificate. Only the texts follow it; the
    #: forwarding rules depend on ``mtls`` alone.
    header_auth: bool = False

    @property
    def visitors(self) -> str:
        """Who gets through the public port, for texts ("every device ...")."""
        return "with a client certificate or the header key" if self.header_auth else "with a client certificate"

    @property
    def target(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"

    @property
    def is_home_assistant(self) -> bool:
        return self.host == "homeassistant"

    @classmethod
    def from_runtime(cls, data: dict[str, Any]) -> Settings | None:
        """From runtime.json (None if it lacks the upstream: an add-on
        version before 2.2.0 wrote it, or init-caddy has not run)."""
        host = data.get("upstream_host")
        port = data.get("upstream_port")
        if not isinstance(host, str) or not host or not isinstance(port, int) or not 0 < port < 65536:
            return None
        option = data.get("forwarded_headers")
        header_auth = data.get("header_auth")
        return cls(
            domain=str(data.get("domain") or ""),
            host=host,
            port=port,
            mtls=bool(data.get("mtls_enabled")),
            option=option if option in OPTIONS else "auto",
            header_auth=isinstance(header_auth, dict) and header_auth.get("enabled") is True,
        )

    @classmethod
    def load(cls, runtime_file: Path | None = None) -> Settings | None:
        path = runtime_file or Path(os.environ.get("CADDY_MTLS_RUNTIME_FILE", "/run/caddy-mtls/runtime.json"))
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            return None
        return cls.from_runtime(data) if isinstance(data, dict) else None


@dataclass
class ProbeResult:
    """One look at the upstream: a control request, and with ``test`` the
    same request with forwarding headers."""

    result: str  # accepted | refused | unreachable | reachable (no test sent) | slow
    control_status: int | None = None
    test_status: int | None = None
    error: str = ""
    source_address: str = ""
    test_sent: bool = False
    #: Why it is unreachable / slow: connect (no connection: Caddy answers
    #: 502), timeout (connected, no answer in time: Caddy waits), closed (the
    #: connection closed without an answer), http (it answered 5xx).
    kind: str = ""


@dataclass
class State:
    """What the add-on knows about the upstream (persisted in STATE_FILE,
    so that the last decisive result survives a restart while the upstream
    is down - e.g. at host boot, when the add-on starts before Core)."""

    upstream: str = ""
    #: The last outcome: accepted | refused | unreachable | unknown.
    result: str = UNKNOWN
    #: The last accepted / refused of this upstream (kept while unreachable).
    decisive: str | None = None
    #: The mode decided ...
    mode: str = PASS
    #: ... whether Caddy runs with it (False: the reload failed, retried) ...
    applied: bool = True
    #: ... and the mode Caddy really runs (None: the same as ``mode``; the
    #: snippet file always holds this one).
    running: str | None = None
    reload_error: str = ""
    reachable: bool | None = None
    #: A test request is owed (the upstream came back, the test was slow).
    test_due: bool = False
    #: Visitor addresses are hidden because the upstream stopped trusting the
    #: add-on at run time (it had accepted forwarded requests before; not at
    #: the start, not at a first decision): the monitor's "addresses hidden"
    #: notification while Caddy runs strip. Set when that is decided (also
    #: if the reload fails and is retried); cleared at the next start and
    #: when addresses are passed on again.
    hidden_at_runtime: bool = False
    #: Test requests in a row without an answer in time (SLOW_TESTS_MAX: no
    #: more until the next event).
    slow_tests: int = 0
    checked_at: float | None = None  # the last test request
    seen_at: float | None = None  # the last answer of the upstream
    changed_at: float | None = None  # the last mode switch
    error: str = ""
    #: ProbeResult.kind of ``error``.
    error_kind: str = ""
    control_status: int | None = None
    test_status: int | None = None
    source_address: str = ""

    @property
    def running_mode(self) -> str:
        return self.running or self.mode

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> State:
        known = {f for f in cls.__dataclass_fields__}  # noqa: C416
        state = cls(**{k: v for k, v in data.items() if k in known})
        if state.result not in (ACCEPTED, REFUSED, UNREACHABLE, UNKNOWN):
            state.result = UNKNOWN
        if state.decisive not in (ACCEPTED, REFUSED):
            state.decisive = None
        if state.mode not in (PASS, STRIP):
            state.mode = PASS
        if state.running not in (PASS, STRIP):
            state.running = None
        if not isinstance(state.slow_tests, int) or state.slow_tests < 0:
            state.slow_tests = 0
        return state


@dataclass
class Outcome:
    """The result of ``check`` / ``watch_once``."""

    state: State
    previous_mode: str
    previous_card: str
    card: str
    probe: ProbeResult | None = None
    reload_error: str = ""
    #: The mode Caddy runs changed.
    switched: bool = field(default=False)
    #: A test request was sent.
    tested: bool = False
    #: The monitor's control request was answered (None: none was sent).
    answered: bool | None = None


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------

def classify(control_status: int | None, test_status: int | None, error: str = "") -> str:
    """accepted / refused / unreachable from the two answers (generic: any
    upstream that answers the same with and without the headers accepts)."""
    if control_status is None or control_status >= 500:
        return UNREACHABLE
    if test_status is None:
        return REACHABLE
    if control_status != 400 and test_status == 400:
        return REFUSED
    return ACCEPTED


def decide(option: str, mtls: bool, decisive: str | None) -> str:
    """The effective mode.

    Without mTLS: always pass, whatever the option. The visitors are then
    unauthenticated internet clients that must never look like a local
    address to the upstream; auto stays at pass (the 400 is explained in the
    panel and a notification), and init-caddy refuses to start with
    ``never`` (this is the second line).

    With mTLS: always -> pass; never -> strip; auto -> pass unless the
    upstream refused the last test request. Visitors on the public port have
    a client certificate (or, with header authentication, the header key:
    treated like a certificate) and visitors on the local-network port come
    from private addresses, so showing them to Home Assistant under the
    add-on's address is acceptable. While the upstream is unreachable the
    last decisive result counts (none yet: pass).
    """
    if not mtls:
        return PASS
    if option == "always":
        return PASS
    if option == "never":
        return STRIP
    return STRIP if decisive == REFUSED else PASS


def card_state(settings: Settings, state: State | None) -> str:
    """The state the panel card and the log show: unknown, too_slow (not
    known, and the add-on stopped retrying slow tests), reload_failed (the
    last mode change could not be applied: red, whatever else),
    unreachable, never, accepted, strip (refused, works without addresses)
    or broken (refused, every request answered 400). Always from the mode
    Caddy really runs."""
    if state is None:
        return UNKNOWN
    if not state.applied:
        return RELOAD_FAILED
    if state.reachable is False:
        return UNREACHABLE
    not_known = TOO_SLOW if gave_up(state) else UNKNOWN
    if state.reachable is None:
        return not_known
    if settings.option == "never":
        return "never"
    if state.decisive == REFUSED:
        return STRIP if state.running_mode == STRIP else "broken"
    if state.decisive == ACCEPTED and state.running_mode == PASS:
        return ACCEPTED
    return not_known


def gave_up(state: State | None) -> bool:
    """SLOW_TESTS_MAX test requests in a row got no answer in time: the
    add-on sends none on its own until the next event."""
    return state is not None and state.slow_tests >= SLOW_TESTS_MAX


def is_broken(settings: Settings, state: State | None) -> bool:
    """Every request is answered 400: the upstream refuses forwarded
    requests and Caddy (really) passes the addresses on."""
    return (
        state is not None
        and state.reachable is True
        and settings.option != "never"
        and state.decisive == REFUSED
        and state.running_mode == PASS
    )


def is_hidden(state: State | None) -> bool:
    """Visitor addresses are hidden since a switch at run time."""
    return state is not None and state.hidden_at_runtime and state.running_mode == STRIP


def card_title(settings: Settings) -> str:
    """The title of the panel card for this upstream."""
    return "Home Assistant connection" if settings.is_home_assistant else "Upstream connection"


def unreachable_effect(kind: str) -> str:
    """What visitors get while the upstream is unreachable."""
    if kind == "connect":
        return "visitors get 502 Bad Gateway"
    if kind == "http":
        return "visitors get its error answers"
    return "visitors' requests wait for it or fail"


def unreachable_reason(state: State | None) -> tuple[str, str]:
    """Why the upstream counts as unreachable, for a sentence that starts
    with its name: (verb, detail in brackets). A 5xx is an answer: "answers
    with an error (HTTP 503)"; otherwise "does not answer (<error>)"."""
    if state is not None and state.error_kind == "http":
        return "answers with an error", (f"HTTP {state.control_status}" if state.control_status
                                         else state.error or "HTTP 5xx")
    return "does not answer", (state.error if state is not None and state.error else "no answer")


def trusted_proxy_suggestion(source_address: str) -> str:
    """What to enter as trusted proxy: Home Assistant's documented add-on
    network when the add-on's address lies in it, else the address itself."""
    try:
        addr = ip_address(source_address.split("%", 1)[0])
    except ValueError:
        return str(HA_ADDON_NETWORK)
    if addr.version == 4 and addr in HA_ADDON_NETWORK:
        return str(HA_ADDON_NETWORK)
    return str(addr)


def yaml_block(suggestion: str) -> str:
    """The configuration.yaml block (Home Assistant before 2026.7)."""
    return (
        "http:\n"
        "  use_x_forwarded_for: true\n"
        "  trusted_proxies:\n"
        f"    - {suggestion}\n"
    )


def render_snippet(mode: str) -> str:
    """The header lines of the reverse_proxy blocks for a mode."""
    lines = [
        f"# Forwarding headers, mode {mode} - written by the Caddy mTLS Proxy add-on",
        "# (option forwarded_headers) at the start and when the mode changes.",
    ]
    if mode == PASS:
        # X-Forwarded-For/-Proto/-Host come from Caddy itself.
        lines += ["header_up X-Real-IP {remote_host}", "header_up -Forwarded"]
    else:
        lines += [f"header_up -{name}" for name in STRIPPED_HEADERS]
    return "\n".join(lines) + "\n"


def upstream_name(settings: Settings, start: bool = False) -> str:
    """How texts name the upstream (``start``: at the start of a sentence)."""
    if settings.is_home_assistant:
        return "Home Assistant"
    return f"{'The' if start else 'the'} upstream {settings.target}"


def fix_steps(settings: Settings, suggestion: str) -> list[str]:
    """How to make the upstream trust the add-on (plain text steps).
    Home Assistant 2026.7 and later keep the HTTP settings in the UI: an
    ``http:`` block in configuration.yaml is imported once and ignored
    afterwards (homeassistant/components/http/config.py)."""
    if not settings.is_home_assistant:
        return [
            f"Let {settings.target} trust {suggestion} as a reverse proxy "
            "(the X-Forwarded-For header), then restart it.",
        ]
    return [
        "In Home Assistant, open Settings > System > Network.",
        f'In the "HTTP server" card, open "Reverse proxy", turn on "Trust X-Forwarded-For" '
        f'and add {suggestion} to "Trusted proxies".',
        'Select "Save", then "Save and restart".',
        'When Home Assistant is back, select "Confirm" in the dialog "Confirm new HTTP server '
        'configuration" within 5 minutes (otherwise Home Assistant restores the previous '
        "settings and restarts again).",
    ]


def strip_consequences(settings: Settings, source: str) -> list[str]:
    """What it means that the upstream sees every visitor as the add-on
    (Core 2026.11: http/auth_util.py, webhook/__init__.py, http/ban.py,
    auth/providers/trusted_networks.py all use the address they see)."""
    source = source or "this add-on's address"
    if not settings.is_home_assistant:
        return [f"The upstream sees every visitor as {source}; its logs cannot tell visitors apart."]
    return [
        f"Logins, the notifications about failed logins and the logs of Home Assistant "
        f"show {source} instead of the visitor's address.",
        f"Home Assistant counts {source} as a device in the local network: users marked "
        '"Can only log in from the local network" can log in, and webhooks marked '
        '"Only accessible from the local network" accept requests, from every device '
        f"{settings.visitors}.",
        f"If you set a limit of login attempts (HTTP server > IP banning), too many failed "
        f"logins ban {source} - that is everyone who uses this add-on - until you delete "
        "it from ip_bans.yaml and restart Home Assistant.",
        f"If you use the trusted networks login provider and its networks include {source}, "
        f"every device {settings.visitors} logs in without a password.",
    ]


def local_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z").strip()


def card_context(settings: Settings | None, state: State | None) -> dict[str, Any]:
    """The variables of the panel's "Home Assistant connection" card
    (templates/_upstream.html)."""
    if settings is None:
        return {"card": UNKNOWN, "settings": None, "state": None}
    source = (state.source_address if state else "") or ""
    suggestion = trusted_proxy_suggestion(source)
    down, down_detail = unreachable_reason(state)
    return {
        "card": card_state(settings, state),
        "settings": settings,
        "state": state,
        "name": upstream_name(settings),
        "Name": upstream_name(settings, start=True),
        "title": card_title(settings),
        "source": source or "this add-on's address",
        "suggestion": suggestion,
        "steps": fix_steps(settings, suggestion),
        "yaml": yaml_block(suggestion),
        "consequences": strip_consequences(settings, source),
        "effect": unreachable_effect(state.error_kind if state else ""),
        "down": down,
        "down_detail": down_detail,
        "slow_tests_max": SLOW_TESTS_MAX,
        "broken": is_broken(settings, state),
        "time": local_time,
    }


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

def _resolve(host: str, port: int, timeout: float) -> list[tuple[Any, ...]]:
    """getaddrinfo with a deadline (it cannot be interrupted itself)."""
    result: dict[str, Any] = {}

    def run() -> None:
        try:
            result["infos"] = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as err:
            result["error"] = err

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise OSError(f"name lookup of {host} timed out")
    if "error" in result:
        raise result["error"]
    return result["infos"]


class _Conn(http.client.HTTPConnection):
    """An HTTP connection to one resolved address."""

    def __init__(self, family: int, sockaddr: tuple[Any, ...], timeout: float) -> None:
        super().__init__(str(sockaddr[0]), int(sockaddr[1]), timeout=timeout)
        self._family = family
        self._sockaddr = sockaddr

    def connect(self) -> None:
        sock = socket.socket(self._family, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self._sockaddr)
        except OSError:
            sock.close()
            raise
        self.sock = sock

    @property
    def local_address(self) -> str:
        if self.sock is None:
            return ""
        return str(self.sock.getsockname()[0]).split("%", 1)[0]


class ConnectError(OSError):
    """No connection: the name lookup or the TCP connect failed (refused,
    no route, timed out)."""


def _connect(settings: Settings, timeout: float) -> _Conn:
    try:
        infos = _resolve(settings.host, settings.port, timeout)
    except OSError as err:
        raise ConnectError(str(err) or f"name lookup of {settings.host} failed") from err
    errors: list[str] = []
    for family, _, _, _, sockaddr in infos:
        conn = _Conn(family, sockaddr, timeout)
        try:
            conn.connect()
            return conn
        except OSError as err:
            errors.append(str(err) or type(err).__name__)
    raise ConnectError("; ".join(errors) or f"no address for {settings.host}")


_KEEP_ALIVE_TIMEOUT = re.compile(r"(?:^|,)\s*timeout\s*=\s*(\d+)", re.I)


def _get(conn: _Conn, settings: Settings, extra: dict[str, str] | None = None
         ) -> tuple[int, bool, float | None]:
    """GET PROBE_PATH; (status, connection kept open, the idle timeout the
    upstream announces in a Keep-Alive header or None)."""
    headers = {"Host": settings.domain or settings.host, "User-Agent": USER_AGENT, "Accept": "*/*"}
    headers.update(extra or {})
    conn.request("GET", PROBE_PATH, headers=headers)
    resp = conn.getresponse()
    resp.read(256 * 1024)
    if not resp.isclosed():
        resp.close()
    match = _KEEP_ALIVE_TIMEOUT.search(resp.getheader("Keep-Alive") or "")
    return resp.status, not resp.will_close, float(match.group(1)) if match else None


def _no_answer(err: BaseException) -> str:
    """ProbeResult.kind of an error after the connection was made."""
    return "timeout" if isinstance(err, TimeoutError) else "closed"


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _error_text(err: BaseException) -> str:
    return _clip(str(err) or type(err).__name__, 200)


def probe(settings: Settings, test: bool = True, timeout: float | None = None,
          deadline: float | None = None) -> ProbeResult:
    """Control request, then (with ``test``) the test request; both on new
    connections. Ends within about ``deadline`` seconds. No connection:
    UNREACHABLE; connected but no answer in time: SLOW (no decision)."""
    timeout = REQUEST_TIMEOUT if timeout is None else timeout
    deadline = PROBE_DEADLINE if deadline is None else deadline
    start = time.monotonic()
    result = ProbeResult(result=UNREACHABLE)
    try:
        conn = _connect(settings, timeout)
    except ConnectError as err:
        result.error, result.kind = _error_text(err), "connect"
        return result
    try:
        result.source_address = conn.local_address
        result.control_status, _, _ = _get(conn, settings)
    except (OSError, http.client.HTTPException) as err:
        result.result, result.error, result.kind = SLOW, _error_text(err), _no_answer(err)
        return result
    finally:
        conn.close()
    if result.control_status >= 500:
        result.error, result.kind = f"answered HTTP {result.control_status}", "http"
        return result
    if not test:
        result.result = REACHABLE
        return result
    remaining = deadline - (time.monotonic() - start)
    if remaining <= 0.2:
        result.error = "no time left for the test request"
        result.result = REACHABLE
        return result
    try:
        conn = _connect(settings, min(timeout, remaining))
    except ConnectError as err:
        result.result, result.error, result.kind = UNREACHABLE, _error_text(err), "connect"
        return result
    try:
        result.test_sent = True
        result.test_status, _, _ = _get(conn, settings, {
            "X-Forwarded-For": TEST_CLIENT,
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": settings.domain or settings.host,
        })
    except (OSError, http.client.HTTPException) as err:
        result.result, result.error, result.kind = SLOW, _error_text(err), _no_answer(err)
        return result
    finally:
        conn.close()
    result.result = classify(result.control_status, result.test_status)
    return result


class ControlChannel:
    """The monitor's watch on the upstream: a control request on one
    kept-alive connection.

    * Restart: the upstream closes a connection it had kept open (Home
      Assistant's server keeps idle connections for an hour - aiohttp's
      default - and the watch asks every few seconds): it went away in
      between, probably restarted - the moment a changed HTTP configuration
      takes effect. Reported as ``came_back`` with the next answer, also when
      the connection had not been reused yet.
    * Upstreams that close connections themselves are told apart: one that
      answers "Connection: close" (or HTTP/1.0) or announces an idle timeout
      shorter than the watch interval (``Keep-Alive: timeout=N``) is never
      kept, so it cannot look restarted; one whose kept connection is gone at
      ``max_lost`` polls in a row without a successful reuse in between
      closes idle connections itself - from then on a lost connection means
      nothing until a reuse succeeds again. ``max_lost`` is 3 for Home
      Assistant (its server keeps idle connections for an hour; two quick
      restarts in a row are both noticed) and 2 for other upstreams (at most
      one false "restart" after a start).
    * Slow is not down: a timeout or a connection closed without an answer
      is a failure; the upstream is UNREACHABLE after a failed connect or
      FAILURES_UNREACHABLE failures in a row, SLOW before that.
    """

    def __init__(self, settings: Settings, timeout: float | None = None,
                 interval: float = 12.0) -> None:
        self.settings = settings
        self.timeout = WATCH_TIMEOUT if timeout is None else timeout
        self.interval = interval
        self._conn: _Conn | None = None
        self._failures = 0
        self._pending_restart = False
        self._lost_streak = 0
        self._idle_closer = False
        self._short_keepalive = False
        self.max_lost = 3 if settings.is_home_assistant else 2

    def close(self) -> None:
        self._drop()

    def _drop(self) -> None:
        if self._conn is not None:
            self._conn.close()
        self._conn = None

    def check(self) -> tuple[ProbeResult, bool]:
        """(result REACHABLE, SLOW or UNREACHABLE, came_back: the first
        answer after the upstream closed the connection it kept open)."""
        if self._conn is not None:
            old = self._conn
            source = old.local_address
            try:
                status, keep, keep_alive = _get(old, self.settings)
            except TimeoutError as err:
                # Slow. The connection is dropped by us (a late answer would
                # be read as the next one's) - no sign of a restart.
                self._drop()
                return self._failure(ProbeResult(result=SLOW, error=_error_text(err), kind="timeout",
                                                 source_address=source))
            except (OSError, http.client.HTTPException):
                # The upstream closed the connection it had kept open.
                self._drop()
                self._lost()
            else:
                self._lost_streak = 0
                self._idle_closer = False
                if not keep or self._announces_short(keep_alive):
                    self._drop()
                return self._answer(status, source)
        try:
            conn = _connect(self.settings, self.timeout)
        except ConnectError as err:
            self._failures += 1
            return ProbeResult(result=UNREACHABLE, error=_error_text(err), kind="connect"), False
        source = conn.local_address
        try:
            status, keep, keep_alive = _get(conn, self.settings)
        except (OSError, http.client.HTTPException) as err:
            conn.close()
            return self._failure(ProbeResult(result=SLOW, error=_error_text(err), kind=_no_answer(err),
                                             source_address=source))
        if keep and status < 500 and not self._announces_short(keep_alive):
            self._conn = conn
        else:
            conn.close()
        return self._answer(status, source)

    @property
    def restart_pending(self) -> bool:
        """The upstream closed the kept connection and has not answered
        since (it is restarting)."""
        return self._pending_restart

    def _announces_short(self, keep_alive: float | None) -> bool:
        if keep_alive is not None and keep_alive <= self.interval:
            self._short_keepalive = True
        return self._short_keepalive

    def _lost(self) -> None:
        if self._idle_closer or self._short_keepalive:
            return
        self._lost_streak += 1
        if self._lost_streak >= self.max_lost:
            self._idle_closer = True
            self._pending_restart = False
            return
        self._pending_restart = True

    def _failure(self, result: ProbeResult) -> tuple[ProbeResult, bool]:
        self._failures += 1
        if self._failures >= FAILURES_UNREACHABLE:
            result.result = UNREACHABLE
        return result, False

    def _answer(self, status: int, source: str) -> tuple[ProbeResult, bool]:
        if status >= 500:
            return self._failure(ProbeResult(result=SLOW, control_status=status, kind="http",
                                             error=f"answered HTTP {status}", source_address=source))
        self._failures = 0
        came_back, self._pending_restart = self._pending_restart, False
        return ProbeResult(result=REACHABLE, control_status=status, source_address=source), came_back


# ---------------------------------------------------------------------------
# State, snippet, reload
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def locked(timeout: float = 60.0) -> Iterator[None]:
    """The add-on-wide lock around probe + snippet + reload (file lock: the
    monitor and the panel are different processes)."""
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOCK_FILE, "a+") as fh:
        end = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= end:
                    raise TimeoutError("the upstream check is busy") from None
                time.sleep(0.1)
        try:
            yield
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def load_state(settings: Settings | None = None) -> State | None:
    """The persisted state; the decisive result only counts for the same
    upstream. None: nothing persisted yet."""
    try:
        data = json.loads(STATE_FILE.read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    state = State.from_dict(data)
    if settings is not None and state.upstream != settings.target:
        state = State(upstream=settings.target, mode=state.mode, applied=state.applied)
    return state


def _write_atomic(path: Path, text: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def save_state(state: State) -> None:
    _write_atomic(STATE_FILE, json.dumps(asdict(state), indent=1) + "\n", 0o600)


def write_snippet(mode: str, *, mtls: bool) -> None:
    """Write the snippet for ``mode``. Without mTLS always the pass lines,
    whatever the caller asks (B-1: the add-on never hides visitor addresses
    while mTLS is off - this is the last line)."""
    _write_atomic(SNIPPET_FILE, render_snippet(mode if mtls else PASS), 0o644)


def snippet_mode() -> str | None:
    """The mode the snippet file holds (None: missing or foreign)."""
    try:
        text = SNIPPET_FILE.read_text()
    except OSError:
        return None
    for mode in (PASS, STRIP):
        if text == render_snippet(mode):
            return mode
    return None


def caddy_reload() -> tuple[bool, str]:
    """``caddy reload --force`` of the Caddyfile (the snippet is imported at
    adapt time; --force: Caddy skips an unchanged config otherwise), through
    caddyctl.reload: it regenerates the list of active client certificates
    first (header authentication, 2.3.0) - see the comment there on what a
    reload re-reads."""
    ok, message = caddyctl.reload(caddy_bin=CADDY_BIN, caddyfile=CADDYFILE, admin=CADDY_ADMIN)
    return ok, ("reloaded" if ok else _cli_error(message))


def _cli_error(output: str) -> str:
    """The error of a failed Caddy CLI call without its timestamps (stable
    across retries, so it is logged once): the "msg" of its last JSON log
    line of level error (Caddy 2.11), else its last "Error:" line, else the
    last line."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    for line in reversed(lines):
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and entry.get("level") == "error" and entry.get("msg"):
            return str(entry["msg"])
    return next((line for line in reversed(lines) if line.startswith("Error:")),
                lines[-1] if lines else "caddy reload failed")


Reload = Callable[[], tuple[bool, str]]


def _apply(settings: Settings, state: State, result: ProbeResult | None, now: float,
           reload: Reload | None) -> Outcome:
    """Record a probe result (SLOW or None: no information), decide, write
    the snippet and reload Caddy when the mode changed (or the last reload
    failed). After a failed reload the snippet goes back to the mode Caddy
    runs (so that another reload, e.g. for a client, cannot apply the new
    mode unnoticed) and ``running`` keeps it: the card, the log and the
    notifications follow what Caddy runs. Without mTLS that is always pass.
    Caller holds the lock."""
    previous_running = state.running_mode
    previous_decisive = state.decisive
    previous_card = card_state(settings, state)
    state.upstream = settings.target
    info = result if result is not None and result.result != SLOW else None
    if info is not None:
        if info.source_address:
            state.source_address = info.source_address
        state.control_status = info.control_status
        if info.result == UNREACHABLE:
            state.reachable = False
            state.result = UNREACHABLE
            state.error = info.error
            state.error_kind = info.kind
        else:
            state.reachable = True
            state.seen_at = now
            state.error = ""
            state.error_kind = ""
            if info.result in (ACCEPTED, REFUSED):
                state.decisive = info.result
                state.result = info.result
                state.checked_at = now
                state.test_status = info.test_status
                state.test_due = False
                state.slow_tests = 0
            elif state.result in (UNREACHABLE, UNKNOWN):
                state.result = state.decisive or UNKNOWN
    mode = decide(settings.option, settings.mtls, state.decisive)
    outcome = Outcome(state=state, previous_mode=previous_running, previous_card=previous_card,
                      card=previous_card, probe=result)
    if (reload is not None and previous_decisive == ACCEPTED and state.decisive == REFUSED
            and mode == STRIP and previous_running == PASS):
        # The upstream trusted the add-on and stopped (B2-1: not a first
        # decision at run time, which had nothing to lose).
        state.hidden_at_runtime = True
    if (mode != state.mode or mode != previous_running or not state.applied
            or snippet_mode() != mode):
        write_snippet(mode, mtls=settings.mtls)
        state.mode = mode
        ok, message = (True, "") if reload is None else reload()
        if ok:
            if mode != previous_running:
                state.changed_at = now
                outcome.switched = True
            state.running = mode
            state.applied = True
            state.reload_error = ""
        else:
            # Back to what Caddy runs - never strip without mTLS (B2-2).
            back = previous_running if settings.mtls else PASS
            write_snippet(back, mtls=settings.mtls)
            state.running = back
            state.applied = False
            state.reload_error = _clip(message, RELOAD_ERROR_MAX)
            outcome.reload_error = state.reload_error
    if state.mode == PASS and state.running_mode == PASS:
        state.hidden_at_runtime = False
    save_state(state)
    outcome.card = card_state(settings, state)
    return outcome


def check(settings: Settings, *, test: bool = True, reload: Reload | None = caddy_reload,
          now: float | None = None, prober: Callable[..., ProbeResult] = probe) -> Outcome:
    """Probe (with ``test``: also the test request), decide and apply.
    "Check again": the slow tests count anew."""
    with locked():
        state = load_state(settings) or State(upstream=settings.target)
        result = prober(settings, test=test, timeout=WATCH_TIMEOUT, deadline=2 * WATCH_TIMEOUT + 1)
        state.slow_tests = 1 if result.result == SLOW else 0
        outcome = _apply(settings, state, result, time.time() if now is None else now, reload)
        outcome.tested = result.test_sent
        return outcome


def watch_once(settings: Settings, channel: ControlChannel, *, reload: Reload | None = caddy_reload,
               now: float | None = None, prober: Callable[..., ProbeResult] = probe,
               force_test: bool = False) -> Outcome:
    """The monitor's regular look: the control request on the kept-alive
    channel. When it answers and the upstream came back (it was unreachable
    or not checked, or it closed the kept connection: a restart), a test is
    still owed, nothing is decided yet, or ``force_test`` (the periodic test
    while passing addresses on): also the test request. A slow answer
    changes nothing; a test request without an answer in time counts, and
    after SLOW_TESTS_MAX in a row only a restart of the upstream (or its
    return after it was unreachable) sends the next one (B2-3)."""
    with locked():
        state = load_state(settings) or State(upstream=settings.target)
        control, came_back = channel.check()
        result: ProbeResult | None = control
        tested = False
        if control.result == REACHABLE:
            if came_back or state.reachable is False:
                state.slow_tests = 0  # an event: back, or restarted
            owed = came_back or state.test_due or state.reachable is not True or state.decisive is None
            if force_test or (owed and not gave_up(state)):
                state.test_due = True
                result = prober(settings, test=True, timeout=WATCH_TIMEOUT, deadline=2 * WATCH_TIMEOUT + 1)
                tested = result.test_sent
                if result.result == SLOW:
                    state.slow_tests += 1
        outcome = _apply(settings, state, result, time.time() if now is None else now, reload)
        outcome.tested = tested
        outcome.answered = control.result == REACHABLE
        return outcome


def retry_apply(settings: Settings, *, reload: Reload | None = caddy_reload,
                now: float | None = None) -> Outcome:
    """Apply the current decision again without asking the upstream (after
    a failed reload)."""
    with locked():
        state = load_state(settings) or State(upstream=settings.target)
        return _apply(settings, state, None, time.time() if now is None else now, reload)


# ---------------------------------------------------------------------------
# init-caddy
# ---------------------------------------------------------------------------

def start(settings: Settings, now: float | None = None) -> dict[str, Any]:
    """The check at the add-on's start (Caddy is not running yet: the snippet
    is written, Caddy loads it when it starts). Returns the facts for
    init-caddy's log notice."""
    with locked():
        state = load_state(settings) or State(upstream=settings.target)
        # This start's facts only: reachability is unknown until the probe
        # says so; the decisive result (the last known mode) stays; the
        # "addresses hidden at run time" notification ends with the restart.
        state.reachable = None
        state.result = UNKNOWN if state.decisive is None else state.decisive
        state.hidden_at_runtime = False
        state.test_due = False
        state.slow_tests = 0
        result = probe(settings, test=True)
        if result.result == SLOW:
            state.error, state.error_kind = result.error, result.kind
        outcome = _apply(settings, state, result, time.time() if now is None else now, None)
    st = outcome.state
    return {
        "card": outcome.card,
        "result": result.result,
        "mode": st.mode,
        "decisive": st.decisive,
        "source_address": st.source_address,
        "suggestion": trusted_proxy_suggestion(st.source_address),
        "error": st.error,
        "error_kind": st.error_kind,
        "effect": unreachable_effect(st.error_kind),
        "control_status": result.control_status,
        "test_status": result.test_status,
        "target": settings.target,
        "is_home_assistant": settings.is_home_assistant,
    }


def _main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    sub = parser.add_subparsers(dest="command", required=True)
    start_cmd = sub.add_parser("start", help="probe at the add-on's start, write the snippet")
    start_cmd.add_argument("--domain", required=True)
    start_cmd.add_argument("--host", required=True)
    start_cmd.add_argument("--port", required=True, type=int)
    start_cmd.add_argument("--mtls", required=True, choices=("true", "false"))
    start_cmd.add_argument("--option", required=True, choices=OPTIONS)
    args = parser.parse_args(argv)
    settings = Settings(domain=args.domain, host=args.host, port=args.port,
                        mtls=args.mtls == "true", option=args.option)
    print(json.dumps(start(settings)))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
