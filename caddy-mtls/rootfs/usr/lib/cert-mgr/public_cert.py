"""
Caddy mTLS Proxy - status of the public (ACME) server certificate.

Shared by the certificate manager panel (app.py: the "Public certificate"
card) and the expiry monitor (monitor.py: a Home Assistant notification while
there is none). Standard library only.

Sources:
  * ``/run/caddy-mtls/runtime.json``, written by init-caddy at every start:
    the domain, the published host ports, the ACME mode and the start time.
  * Caddy's storage, ``<storage>/certificates/<issuer>/<key>/<key>.crt``:
    the certificate Caddy serves (the source of truth for "a certificate
    exists"), read with ``openssl x509``.
  * ``<storage>/log/acme.log``: Caddy's certificate events (JSON lines of the
    loggers tls.obtain, tls.renew, tls.issuance and http.acme_client), for
    the last error. Only events since the current start count.

States (``Status.state``):
  ``ok``               a valid certificate exists;
  ``renewal_failing``  a valid certificate exists, but renewing it failed
                       after it was stored;
  ``missing``          no valid certificate, and an ACME error since the
                       start or no certificate for ``PENDING_SECONDS``;
  ``pending``          no certificate yet, no error yet (just started);
  ``unknown``          no runtime file (init-caddy has not run).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import ssl
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

RUNTIME_FILE = Path(os.environ.get("CADDY_MTLS_RUNTIME_FILE", "/run/caddy-mtls/runtime.json"))
DEFAULT_STORAGE = "/data/caddy"
DEFAULT_ACME_LOG = "/data/caddy/log/acme.log"
OPENSSL_BIN = os.environ.get("OPENSSL_BIN", "openssl")

#: Without a certificate, the state turns from "pending" to "missing" after
#: this many seconds even if Caddy has not logged an error yet.
PENDING_SECONDS = 120

#: How much of the end of acme.log is read (Caddy rolls it at 1 MiB).
LOG_TAIL_BYTES = 512 * 1024

_SUCCESS_MESSAGES = {"certificate obtained successfully", "certificate renewed successfully"}
_ERROR_LEVELS = {"error", "fatal", "panic", "dpanic"}
_ACME_ERROR_PREFIX = "urn:ietf:params:acme:error:"
# An ACME problem as certmagic prints it in "error" strings, e.g.
# "HTTP 400 urn:ietf:params:acme:error:connection - 86.62.32.88: Error getting
# validation data" (optionally after "[<domain>] Obtain: ").
_PROBLEM_IN_TEXT = re.compile(
    r"HTTP \d+ urn:ietf:params:acme:error:(?P<type>[A-Za-z0-9_.-]+) - (?P<detail>.*)", re.S
)


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Runtime:
    """Facts of the current start (init-caddy's runtime.json)."""

    domain: str
    started_at: float
    host_ports_known: bool = False
    http_host_port: int | None = None
    https_host_port: int | None = None
    acme_dns_provider: str = "none"
    acme_ca: str = ""
    acme_log: str = DEFAULT_ACME_LOG
    caddy_storage: str = DEFAULT_STORAGE

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Runtime:
        def port(value: Any) -> int | None:
            return value if isinstance(value, int) and 0 < value < 65536 else None

        return cls(
            domain=str(data.get("domain") or ""),
            started_at=float(data.get("started_at") or 0),
            host_ports_known=bool(data.get("host_ports_known")),
            http_host_port=port(data.get("http_host_port")),
            https_host_port=port(data.get("https_host_port")),
            acme_dns_provider=str(data.get("acme_dns_provider") or "none"),
            acme_ca=str(data.get("acme_ca") or ""),
            acme_log=str(data.get("acme_log") or DEFAULT_ACME_LOG),
            caddy_storage=str(data.get("caddy_storage") or DEFAULT_STORAGE),
        )


@dataclass(frozen=True)
class Certificate:
    """The leaf certificate of a .crt file in Caddy's storage."""

    path: str
    subject_cn: str
    issuer_cn: str
    issuer_org: str
    not_after: datetime
    fingerprint_sha256: str  # lowercase hex, no separators
    mtime: float

    @property
    def issuer(self) -> str:
        if self.issuer_org and self.issuer_cn and self.issuer_cn != self.issuer_org:
            return f"{self.issuer_org} ({self.issuer_cn})"
        return self.issuer_org or self.issuer_cn or "unknown issuer"

    def days_left(self, now: float) -> int:
        return int((self.not_after.timestamp() - now) // 86400)


@dataclass(frozen=True)
class AcmeEvent:
    """One line of Caddy's acme.log."""

    ts: float
    logger: str
    level: str
    msg: str
    identifier: str = ""
    error: str = ""
    problem_type: str = ""
    challenge_type: str = ""
    attempt: int | None = None
    retrying_in: float | None = None

    @property
    def is_error(self) -> bool:
        return self.level in _ERROR_LEVELS

    @property
    def is_success(self) -> bool:
        return self.msg in _SUCCESS_MESSAGES

    @property
    def text(self) -> str:
        """The error as a user would want to read it."""
        parts = [p for p in (self.problem_type, self.error) if p]
        return ": ".join(parts) if parts else self.msg


@dataclass
class Status:
    state: str
    runtime: Runtime | None
    certificate: Certificate | None = None
    last_error: AcmeEvent | None = None
    challenges: list[AcmeEvent] = field(default_factory=list)
    retry: AcmeEvent | None = None
    served: bool | None = None  # live probe: None = not checked
    now: float = 0.0

    @property
    def domain(self) -> str:
        return self.runtime.domain if self.runtime else ""

    @property
    def has_valid_certificate(self) -> bool:
        return self.state in ("ok", "renewal_failing")

    @property
    def next_attempt(self) -> float | None:
        if self.retry and self.retry.retrying_in is not None:
            return self.retry.ts + self.retry.retrying_in
        return None


# ---------------------------------------------------------------------------
# Reading the sources
# ---------------------------------------------------------------------------

def read_runtime(path: Path | None = None) -> Runtime | None:
    try:
        data = json.loads((path or RUNTIME_FILE).read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not data.get("domain"):
        return None
    return Runtime.from_dict(data)


_SAFE_KEY_RE = re.compile(r"[^\w@.\-]")


def storage_key(domain: str) -> str:
    """Caddy's (certmagic's) storage key of a domain name (StorageKeys.Safe)."""
    key = domain.lower().strip()
    for old, new in ((" ", "_"), ("+", "_plus_"), ("*", "wildcard_"), (":", "-"), ("..", "")):
        key = key.replace(old, new)
    return _SAFE_KEY_RE.sub("", key)


def _rfc2253_field(dn: str, name: str) -> str:
    """The value of the first ``name=`` attribute of an RFC 2253 DN."""
    for part in re.split(r"(?<!\\),", dn):
        key, sep, value = part.strip().partition("=")
        if sep and key.strip().upper() == name:
            return value.strip().replace("\\,", ",").replace("\\", "")
    return ""


def parse_certificate(path: Path) -> Certificate | None:
    """Issuer, subject, notAfter and fingerprint of the first certificate."""
    try:
        proc = subprocess.run(
            [
                OPENSSL_BIN, "x509", "-in", str(path), "-noout",
                "-subject", "-issuer", "-enddate", "-fingerprint", "-sha256",
                "-nameopt", "RFC2253", "-dateopt", "iso_8601",
            ],
            capture_output=True, text=True, check=False, timeout=10,
        )
        mtime = path.stat().st_mtime
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    fields: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            fields[key.strip().lower()] = value.strip()
    raw_date = fields.get("notafter", "")
    try:
        not_after = datetime.strptime(raw_date, "%Y-%m-%d %H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            not_after = datetime.strptime(raw_date, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    fingerprint = next(
        (v for k, v in fields.items() if k.endswith("fingerprint")), ""
    ).replace(":", "").lower()
    return Certificate(
        path=str(path),
        subject_cn=_rfc2253_field(fields.get("subject", ""), "CN"),
        issuer_cn=_rfc2253_field(fields.get("issuer", ""), "CN"),
        issuer_org=_rfc2253_field(fields.get("issuer", ""), "O"),
        not_after=not_after,
        fingerprint_sha256=fingerprint,
        mtime=mtime,
    )


def find_certificate(domain: str, storage: str = DEFAULT_STORAGE) -> Certificate | None:
    """The domain's certificate in Caddy's storage (any issuer); the one that
    expires last if several issuers have one."""
    key = storage_key(domain)
    if not key:
        return None
    best: Certificate | None = None
    for path in sorted(Path(storage, "certificates").glob(f"*/{key}/{key}.crt")):
        cert = parse_certificate(path)
        if cert and (best is None or cert.not_after > best.not_after):
            best = cert
    return best


def _float(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        # A Go duration string such as "1m0s" or "2m30.5s".
        total, matched = 0.0, False
        for number, unit in re.findall(r"([0-9.]+)(h|ms|m|s)", value):
            matched = True
            total += float(number) * {"h": 3600, "m": 60, "s": 1, "ms": 0.001}[unit]
        if matched:
            return total
    return None


def _event_ts(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def parse_event(line: str) -> AcmeEvent | None:
    try:
        data = json.loads(line)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    ts = _event_ts(data.get("ts"))
    if ts is None:
        return None
    problem = data.get("problem") if isinstance(data.get("problem"), dict) else {}
    problem_type = str(problem.get("type") or "")
    if problem_type.startswith(_ACME_ERROR_PREFIX):
        problem_type = problem_type[len(_ACME_ERROR_PREFIX):]
    error = str(problem.get("detail") or data.get("error") or "")
    if not problem_type and (match := _PROBLEM_IN_TEXT.search(error)):
        problem_type, error = match.group("type"), match.group("detail")
    identifiers = data.get("identifiers")
    identifier = data.get("identifier") or (
        identifiers[0] if isinstance(identifiers, list) and identifiers else ""
    )
    attempt = data.get("attempt")
    return AcmeEvent(
        ts=ts,
        logger=str(data.get("logger") or ""),
        level=str(data.get("level") or "").lower(),
        msg=str(data.get("msg") or ""),
        identifier=str(identifier or ""),
        error=error,
        problem_type=problem_type,
        challenge_type=str(data.get("challenge_type") or ""),
        attempt=attempt if isinstance(attempt, int) else None,
        retrying_in=_float(data.get("retrying_in")),
    )


def read_events(path: Path, since: float = 0.0, tail_bytes: int = LOG_TAIL_BYTES) -> list[AcmeEvent]:
    """The events of acme.log at or after ``since`` (oldest first)."""
    try:
        with path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - tail_bytes))
            data = fh.read()
    except OSError:
        return []
    lines = data.decode("utf-8", "replace").splitlines()
    if size > tail_bytes and lines:
        lines = lines[1:]  # the first line is probably cut
    events = [e for e in (parse_event(line) for line in lines) if e is not None]
    return [e for e in events if e.ts >= since]


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def _matches(event: AcmeEvent, domain: str) -> bool:
    return not event.identifier or event.identifier.lower() == domain.lower()


def evaluate(
    runtime: Runtime | None,
    certificate: Certificate | None,
    events: list[AcmeEvent],
    now: float,
) -> Status:
    """The certificate state from the certificate in storage and the events
    since the start (see the module docstring)."""
    if runtime is None:
        return Status(state="unknown", runtime=None, now=now)
    events = [e for e in events if e.ts >= runtime.started_at and _matches(e, runtime.domain)]
    last_success = max((e.ts for e in events if e.is_success), default=0.0)
    after_success = [e for e in events if e.ts > last_success]
    errors = [e for e in after_success if e.is_error]
    retries = [e for e in after_success if e.msg == "will retry"]
    challenges: dict[str, AcmeEvent] = {}
    for e in after_success:
        if e.is_error and e.challenge_type:
            challenges[e.challenge_type] = e
    status = Status(
        state="pending",
        runtime=runtime,
        certificate=certificate,
        retry=retries[-1] if retries else None,
        now=now,
    )
    valid = certificate is not None and certificate.not_after.timestamp() > now
    if valid:
        # Renewing: only tls.renew errors after the certificate was stored
        # count (tls.obtain errors cannot concern an existing certificate).
        renew_errors = [
            e for e in errors
            if e.logger.startswith("tls.renew") and e.ts > certificate.mtime
        ]
        if renew_errors:
            status.state = "renewal_failing"
            status.last_error = _summary_error(renew_errors)
            status.challenges = sorted(
                (c for c in challenges.values() if c.ts > certificate.mtime), key=lambda c: c.ts
            )
        else:
            status.state = "ok"
            status.retry = None
        return status
    if errors:
        status.state = "missing"
        status.last_error = _summary_error(errors)
        status.challenges = sorted(challenges.values(), key=lambda c: c.ts)
    elif now - runtime.started_at >= PENDING_SECONDS:
        status.state = "missing"
    return status


def _summary_error(errors: list[AcmeEvent]) -> AcmeEvent:
    """The most telling recent error: the issuer's last verdict ("could not
    get certificate from issuer"), else the obtain / renew loop's last error
    ("will retry", which repeats it with a "[<domain>] Obtain:" prefix), else
    the last error at all."""
    for wanted in (
        lambda e: e.msg == "could not get certificate from issuer",
        lambda e: e.logger.startswith(("tls.obtain", "tls.renew")),
    ):
        matching = [e for e in errors if wanted(e)]
        if matching:
            return matching[-1]
    return errors[-1]


# ---------------------------------------------------------------------------
# Live probe
# ---------------------------------------------------------------------------

def probe_fingerprint(domain: str, host: str = "127.0.0.1", port: int = 443, timeout: float = 3.0) -> str | None:
    """SHA-256 fingerprint of the certificate Caddy presents for ``domain``.

    The client sends no certificate: with mTLS, Caddy still presents its
    certificate (TLS 1.3) and refuses the connection only afterwards.
    """
    server_name = domain.replace("*", "probe")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=server_name) as tls:
                der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, ValueError):
        return None
    return hashlib.sha256(der).hexdigest() if der else None


def current_status(now: float | None = None, probe: bool = False) -> Status:
    """The state right now, from the runtime file, the storage and the log."""
    now = time.time() if now is None else now
    runtime = read_runtime()
    if runtime is None:
        return Status(state="unknown", runtime=None, now=now)
    certificate = find_certificate(runtime.domain, runtime.caddy_storage)
    events = read_events(Path(runtime.acme_log), since=runtime.started_at)
    status = evaluate(runtime, certificate, events, now)
    if probe and certificate is not None:
        served = probe_fingerprint(runtime.domain)
        status.served = served is not None and served == certificate.fingerprint_sha256
    return status


# ---------------------------------------------------------------------------
# Texts (panel and notification)
# ---------------------------------------------------------------------------

def local_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z").strip()


def checklist(status: Status) -> list[str]:
    """What to check while there is no certificate (plain text items)."""
    rt = status.runtime
    domain = status.domain or "your domain"
    items: list[str] = []
    if rt is None:
        return items

    def forward(public: int, host_port: int | None, what: str) -> str:
        if host_port:
            return (
                f"Your router forwards external TCP port {public} to this "
                f"Home Assistant host, port {host_port} ({what})."
            )
        if rt.host_ports_known:
            return (
                f"Container port {public}/tcp is not published: set a host port "
                f"for it in the app's Network settings, then forward external "
                f"TCP port {public} to it ({what})."
            )
        return (
            f"Your router forwards external TCP port {public} to this Home "
            f"Assistant host, port {8080 if public == 80 else 8443} or whatever "
            f"the app's Network settings show for {public}/tcp ({what})."
        )

    if rt.acme_dns_provider == "none":
        items.append(forward(80, rt.http_host_port, "Let's Encrypt checks port 80"))
        items.append(forward(443, rt.https_host_port, "HTTPS"))
    else:
        items.append(
            f"The DNS provider '{rt.acme_dns_provider}' manages the zone of "
            f"{domain} and dns_api_token may edit its records (DNS-01 challenge)."
        )
        items.append(forward(443, rt.https_host_port, "HTTPS"))
    items.append(
        f"{domain} resolves to your public IP address (DNS A / AAAA record, "
        f"DynDNS up to date)."
    )
    items.append(
        "No other device or service answers on these ports: no second port "
        "forwarding for 80 / 443 in the router."
    )
    if rt.http_host_port == 80 or rt.https_host_port == 443:
        items.append(
            "Home Assistant itself does not use host port 80 / 443 (Settings > "
            "System > Network), or the app could not publish it."
        )
    items.append(
        "Your internet connection has a public IPv4 address (no carrier-grade "
        "NAT / DS-Lite), or the domain's AAAA record reaches this host."
    )
    return items


def retry_hint(status: Status) -> str:
    when = status.next_attempt
    upcoming = f" (next attempt around {local_time(when)})" if when and when > status.now else ""
    return (
        f"Caddy retries automatically with growing delays{upcoming}. After "
        "fixing the forwarding, restart the app to retry immediately."
    )
