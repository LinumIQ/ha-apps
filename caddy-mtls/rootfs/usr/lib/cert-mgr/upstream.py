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
again after it was unreachable (or after the monitor's keep-alive connection
to it broke: a restart), on "Check again" in the panel and - only while Home
Assistant accepts forwarded requests, which it then does not log - once a
minute in mode ``pass`` under ``auto``. The control request (no forwarding
header) is never logged by Home Assistant; the monitor sends it every few
seconds to watch the upstream otherwise.

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
UNKNOWN = "unknown"

#: The request of the probe; Home Assistant's frontend serves it without
#: authentication and without logging.
PROBE_PATH = "/manifest.json"
#: The visitor address of the test request (TEST-NET-1, RFC 5737).
TEST_CLIENT = "192.0.2.1"
#: Seconds per connection / request of the probe; the whole probe (two
#: requests and a name lookup) ends within PROBE_DEADLINE.
REQUEST_TIMEOUT = 2.0
PROBE_DEADLINE = 5.0
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
        return cls(
            domain=str(data.get("domain") or ""),
            host=host,
            port=port,
            mtls=bool(data.get("mtls_enabled")),
            option=option if option in OPTIONS else "auto",
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

    result: str  # accepted | refused | unreachable | reachable (no test sent)
    control_status: int | None = None
    test_status: int | None = None
    error: str = ""
    source_address: str = ""
    test_sent: bool = False


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
    #: The mode written to SNIPPET_FILE ...
    mode: str = PASS
    #: ... and whether Caddy runs with it (False: the reload failed).
    applied: bool = True
    reachable: bool | None = None
    checked_at: float | None = None  # the last test request
    seen_at: float | None = None  # the last answer of the upstream
    changed_at: float | None = None  # the last mode switch
    error: str = ""
    control_status: int | None = None
    test_status: int | None = None
    source_address: str = ""

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
    switched: bool = field(default=False)


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

    always: pass. never: strip. auto: pass unless the upstream refused the
    last test request and mTLS is on - every visitor on the public port has
    a client certificate, so showing them to Home Assistant under the
    add-on's address is acceptable. Without mTLS the visitors are
    unauthenticated internet clients that must never look like a local
    address to Home Assistant, so auto stays at pass (and the 400 is
    explained in the panel and a notification). While the upstream is
    unreachable the last decisive result counts (none yet: pass).
    """
    if option == "always":
        return PASS
    if option == "never":
        return STRIP
    if not mtls:
        return PASS
    return STRIP if decisive == REFUSED else PASS


def card_state(settings: Settings, state: State | None) -> str:
    """The state the panel card, the log and the notification show:
    unknown, unreachable, never, accepted, strip (refused, works without
    addresses) or broken (refused, every request answered 400)."""
    if state is None or (state.result == UNKNOWN and state.reachable is None):
        return UNKNOWN
    if state.reachable is False:
        return UNREACHABLE
    if settings.option == "never":
        return "never"
    if state.decisive == REFUSED:
        return STRIP if state.mode == STRIP else "broken"
    if state.decisive == ACCEPTED:
        return ACCEPTED
    return UNKNOWN


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


def upstream_name(settings: Settings) -> str:
    """How texts name the upstream."""
    return "Home Assistant" if settings.is_home_assistant else f"the upstream {settings.target}"


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
        "with a client certificate.",
        f"If you set a limit of login attempts (HTTP server > IP banning), too many failed "
        f"logins ban {source} - that is everyone who uses this add-on - until you delete "
        "it from ip_bans.yaml and restart Home Assistant.",
        f"If you use the trusted networks login provider and its networks include {source}, "
        "every device with a client certificate logs in without a password.",
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
    return {
        "card": card_state(settings, state),
        "settings": settings,
        "state": state,
        "name": upstream_name(settings),
        "source": source or "this add-on's address",
        "suggestion": suggestion,
        "steps": fix_steps(settings, suggestion),
        "yaml": yaml_block(suggestion),
        "consequences": strip_consequences(settings, source),
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


def _connect(settings: Settings, timeout: float) -> _Conn:
    errors: list[str] = []
    for family, _, _, _, sockaddr in _resolve(settings.host, settings.port, timeout):
        conn = _Conn(family, sockaddr, timeout)
        try:
            conn.connect()
            return conn
        except OSError as err:
            errors.append(str(err))
    raise OSError("; ".join(errors) or f"no address for {settings.host}")


def _get(conn: _Conn, settings: Settings, extra: dict[str, str] | None = None) -> tuple[int, bool]:
    """GET PROBE_PATH; (status, connection kept open)."""
    headers = {"Host": settings.domain or settings.host, "User-Agent": USER_AGENT, "Accept": "*/*"}
    headers.update(extra or {})
    conn.request("GET", PROBE_PATH, headers=headers)
    resp = conn.getresponse()
    resp.read(256 * 1024)
    if not resp.isclosed():
        resp.close()
    return resp.status, not resp.will_close


def _error_text(err: BaseException) -> str:
    text = str(err) or type(err).__name__
    return text if len(text) <= 200 else text[:197] + "..."


def probe(settings: Settings, test: bool = True, timeout: float = REQUEST_TIMEOUT,
          deadline: float = PROBE_DEADLINE) -> ProbeResult:
    """Control request, then (with ``test``) the test request; both on new
    connections. Ends within about ``deadline`` seconds."""
    start = time.monotonic()
    result = ProbeResult(result=UNREACHABLE)
    try:
        conn = _connect(settings, timeout)
        try:
            result.source_address = conn.local_address
            result.control_status, _ = _get(conn, settings)
        finally:
            conn.close()
    except (OSError, http.client.HTTPException) as err:
        result.error = _error_text(err)
        return result
    if result.control_status >= 500:
        result.error = f"answered HTTP {result.control_status}"
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
        try:
            result.test_sent = True
            result.test_status, _ = _get(conn, settings, {
                "X-Forwarded-For": TEST_CLIENT,
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": settings.domain or settings.host,
            })
        finally:
            conn.close()
    except (OSError, http.client.HTTPException) as err:
        result.error = _error_text(err)
        result.result = UNREACHABLE
        return result
    result.result = classify(result.control_status, result.test_status)
    return result


class ControlChannel:
    """The monitor's watch on the upstream: a control request on one kept-
    alive connection. A connection that worked for at least one reuse and
    then broke means the upstream went away in between (Home Assistant's
    server keeps idle connections for an hour - aiohttp's default - and the
    watch asks every few seconds): ``interrupted``, i.e. probably restarted
    - the moment a changed HTTP configuration takes effect. An upstream that
    never keeps connections open is watched by its reachability alone."""

    def __init__(self, settings: Settings, timeout: float = REQUEST_TIMEOUT) -> None:
        self.settings = settings
        self.timeout = timeout
        self._conn: _Conn | None = None
        self._keepalive_proven = False

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
        self._conn = None
        self._keepalive_proven = False

    def check(self) -> tuple[ProbeResult, bool]:
        """(result REACHABLE or UNREACHABLE, interrupted)."""
        lost = False
        if self._conn is not None:
            old = self._conn
            source = old.local_address
            try:
                status, keep = _get(old, self.settings)
            except (OSError, http.client.HTTPException):
                lost = True
                old.close()
                self._conn = None
            else:
                self._keepalive_proven = True
                if not keep:
                    old.close()
                    self._conn = None
                return self._result(status, source), False
        interrupted = lost and self._keepalive_proven
        self._keepalive_proven = False
        try:
            conn = _connect(self.settings, self.timeout)
        except OSError as err:
            return ProbeResult(result=UNREACHABLE, error=_error_text(err)), interrupted
        source = conn.local_address
        try:
            status, keep = _get(conn, self.settings)
        except (OSError, http.client.HTTPException) as err:
            conn.close()
            return ProbeResult(result=UNREACHABLE, error=_error_text(err)), interrupted
        if keep and status < 500:
            self._conn = conn
        else:
            conn.close()
        return self._result(status, source), interrupted

    @staticmethod
    def _result(status: int, source: str) -> ProbeResult:
        if status >= 500:
            return ProbeResult(result=UNREACHABLE, control_status=status,
                               error=f"answered HTTP {status}", source_address=source)
        return ProbeResult(result=REACHABLE, control_status=status, source_address=source)


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


def write_snippet(mode: str) -> None:
    _write_atomic(SNIPPET_FILE, render_snippet(mode), 0o644)


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
    adapt time; --force: Caddy skips an unchanged config otherwise)."""
    if not CADDYFILE.exists():
        return False, f"Caddyfile not found at {CADDYFILE}"
    try:
        proc = subprocess.run(
            [CADDY_BIN, "reload", "--force", "--config", str(CADDYFILE),
             "--adapter", "caddyfile", "--address", CADDY_ADMIN],
            capture_output=True, text=True, check=False, timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as err:
        return False, str(err)
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout or "caddy reload failed").strip()
    return True, "reloaded"


Reload = Callable[[], tuple[bool, str]]


def _apply(settings: Settings, state: State, result: ProbeResult | None, now: float,
           reload: Reload | None) -> Outcome:
    """Record a probe result, decide, write the snippet and reload Caddy
    when the mode changed (or the last reload failed). Caller holds the
    lock."""
    previous_mode = state.mode
    previous_card = card_state(settings, state)
    state.upstream = settings.target
    if result is not None:
        if result.source_address:
            state.source_address = result.source_address
        state.control_status = result.control_status
        if result.result == UNREACHABLE:
            state.reachable = False
            state.result = UNREACHABLE
            state.error = result.error
        else:
            state.reachable = True
            state.seen_at = now
            state.error = ""
            if result.result in (ACCEPTED, REFUSED):
                state.decisive = result.result
                state.result = result.result
                state.checked_at = now
                state.test_status = result.test_status
            elif state.result in (UNREACHABLE, UNKNOWN):
                state.result = state.decisive or UNKNOWN
    mode = decide(settings.option, settings.mtls, state.decisive)
    outcome = Outcome(state=state, previous_mode=previous_mode, previous_card=previous_card,
                      card=previous_card, probe=result)
    if mode != previous_mode or not state.applied or snippet_mode() != mode:
        write_snippet(mode)
        state.mode = mode
        if mode != previous_mode:
            state.changed_at = now
            outcome.switched = True
        if reload is None:
            state.applied = True
        else:
            ok, message = reload()
            state.applied = ok
            if not ok:
                outcome.reload_error = message
    save_state(state)
    outcome.card = card_state(settings, state)
    return outcome


def check(settings: Settings, *, test: bool = True, reload: Reload | None = caddy_reload,
          now: float | None = None, prober: Callable[..., ProbeResult] = probe) -> Outcome:
    """Probe (with ``test``: also the test request), decide and apply."""
    with locked():
        state = load_state(settings) or State(upstream=settings.target)
        result = prober(settings, test=test)
        return _apply(settings, state, result, time.time() if now is None else now, reload)


def watch_once(settings: Settings, channel: ControlChannel, *, reload: Reload | None = caddy_reload,
               now: float | None = None, prober: Callable[..., ProbeResult] = probe) -> Outcome:
    """The monitor's regular look: the control request on the kept-alive
    channel; when the upstream answers again (it was unreachable or not
    checked, or the channel broke: a restart) also the test request."""
    with locked():
        state = load_state(settings) or State(upstream=settings.target)
        control, interrupted = channel.check()
        result = control
        if control.result == REACHABLE and (state.reachable is not True or interrupted
                                            or state.decisive is None):
            result = prober(settings, test=True)
        return _apply(settings, state, result, time.time() if now is None else now, reload)


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
        result = probe(settings, test=True)
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
    snippet_cmd = sub.add_parser("snippet", help="write the snippet for a mode (fallback)")
    snippet_cmd.add_argument("--mode", required=True, choices=(PASS, STRIP))
    args = parser.parse_args(argv)
    if args.command == "snippet":
        write_snippet(args.mode)
        return 0
    settings = Settings(domain=args.domain, host=args.host, port=args.port,
                        mtls=args.mtls == "true", option=args.option)
    print(json.dumps(start(settings)))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
