"""
FRP Tunnel - configuration logic shared by the pairing panel and frpc/run.

This module is deliberately free of third-party imports (stdlib only) so it can be
unit-tested on any Python 3.9+ and executed by the ``frpc`` s6 service:

    python3 /usr/lib/frp-mgr/config.py render

renders ``/data/frpc.toml`` from the persisted pairing state on every frpc
(re)start.

Where each frpc setting comes from (highest precedence first):

1. **Add-on option** (advanced override in ``/data/options.json``) - only
   when the user explicitly set it (key present and non-empty) and it passes
   validation.
2. **Server-provided value** - ``server_addr`` / ``server_port`` /
   ``domain_base`` as returned by ``GET``/``POST /api/device/tunnel`` and
   persisted (validated) in ``/data/frp-state.json``.
3. **Built-in default** - ``linumiq.net`` / ``7000``; ``domain_base`` falls
   back to the effective ``server_addr`` (the pre-2.1 behaviour, which keeps
   servers that do not return ``domain_base`` working) and finally to
   ``linumiq.net``.

``app_base``, ``api_base``, ``local_host``, ``local_port``, ``log_level`` and
``verify_server`` are never server-provided: option, then default.

Server verification (contract v2.2): the server also sends ``server_name``
(the host name in the frps certificate) and ``server_ca_pem`` (the private CA
that signed it). A valid CA is persisted in the state, written to
``/data/frps-ca.pem`` and pinned in ``frpc.toml`` (``trustedCaFile`` +
``serverName``), unless the ``verify_server`` option is explicitly ``false``.
Unlike the endpoint values, the CA and ``server_name`` are *kept* when a later
response omits them (or sends garbage): a server rollback must never silently
downgrade frpc to an unverified connection. Without any CA (servers older
than v2.2) the connection is TLS-encrypted but unverified, and the panel says
so.

The module also holds the (pure) validators for everything the backend sends
during pairing (``parse_pairing_response``), the log/flash sanitiser
(``sanitize_text``) and the cross-process state lock shared by the panel and
the ``render`` CLI (``state_lock``).

Secrets (frp tunnel token, device token, device code) are never logged.
"""
from __future__ import annotations

import base64
import binascii
import fcntl
import ipaddress
import json
import logging
import os
import re
import ssl
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, Mapping, Optional, Tuple
from urllib.parse import urlsplit

LOG = logging.getLogger("frp-mgr.config")

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_APP_BASE = "https://app.linumiq.net"
DEFAULT_API_BASE = "https://api.linumiq.net"
DEFAULT_SERVER_ADDR = "linumiq.net"
DEFAULT_SERVER_PORT = 7000
DEFAULT_DOMAIN_BASE = "linumiq.net"
DEFAULT_LOCAL_HOST = "homeassistant"
DEFAULT_LOCAL_PORT = 8123
DEFAULT_LOG_LEVEL = "info"

#: Add-on ``log_level`` values (the base image's bashio levels; ``warn`` is
#: accepted for configs written by <= 2.0.x) mapped to frpc log levels.
LOG_LEVELS = {
    "trace": "trace",
    "debug": "debug",
    "info": "info",
    "notice": "info",
    "warning": "warn",
    "warn": "warn",
    "error": "error",
    "fatal": "error",
}

#: Endpoint keys the server may provide in the tunnel response (contract
#: v2.1). The response is authoritative for them: a key the server stops
#: sending is dropped from the state.
SERVER_KEYS = ("server_addr", "server_port", "domain_base")

#: TLS trust keys of the tunnel response (contract v2.2). Kept when a later
#: response omits them (never a silent downgrade to an unverified frps).
TLS_KEYS = ("server_name", "server_ca_pem")

#: Limits for a server-provided CA bundle.
CA_PEM_MAX_CHARS = 64 * 1024
CA_MAX_CERTS = 8

#: Group of the unprivileged user frpc runs as inside the image. frpc.toml
#: and frps-ca.pem are written root:frpc 0640 when the group exists (0600
#: otherwise, e.g. in unit tests).
FRPC_GROUP = "frpc"

#: tls_mode values (Settings.tls_mode).
TLS_VERIFIED = "verified"
TLS_UNVERIFIED = "unverified"  # no CA known (server older than v2.2)
TLS_DISABLED = "disabled"      # verify_server: false

#: Exit codes of the ``render`` CLI. frpc/run starts frpc only on EXIT_OK.
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NOT_PAIRED = 3

STATE_VERSION = 2

#: RFC 8628 defaults when the device-code response omits them.
DEFAULT_POLL_INTERVAL = 5
DEFAULT_EXPIRES_IN = 600
#: Accepted ranges (seconds) for server-provided pairing timings.
POLL_INTERVAL_RANGE = (1, 60)
EXPIRES_IN_RANGE = (1, 3600)

#: How long the ``render`` CLI waits for the state lock (the panel holds it
#: across backend calls, which time out after 15 s each).
CLI_LOCK_TIMEOUT = 60.0


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Paths:
    """Locations of the add-on's persistent files (all under /data)."""

    data_dir: Path

    @property
    def options(self) -> Path:
        return self.data_dir / "options.json"

    @property
    def state(self) -> Path:
        return self.data_dir / "frp-state.json"

    @property
    def frpc_toml(self) -> Path:
        return self.data_dir / "frpc.toml"

    @property
    def pairing(self) -> Path:
        return self.data_dir / "frp-pairing.json"

    @property
    def frps_ca(self) -> Path:
        return self.data_dir / "frps-ca.pem"

    @property
    def lock(self) -> Path:
        return self.data_dir / ".frp-state.lock"


def default_paths() -> Paths:
    """Paths rooted at ``$FRP_DATA_DIR`` (default ``/data``)."""
    return Paths(Path(os.environ.get("FRP_DATA_DIR", "/data")))


# ---------------------------------------------------------------------------
# Validation / normalisation. Every function returns the normalised value or
# None when the input is unusable. re.fullmatch is used throughout so that a
# trailing newline can never slip through into the TOML file.
# ---------------------------------------------------------------------------

_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_SUBDOMAIN_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
# Printable ASCII without space, '"' and '\' - safe inside a TOML string.
_TOKEN_RE = re.compile(r"[\x21\x23-\x5b\x5d-\x7e]{8,1024}")
_PORT_RE = re.compile(r"[0-9]{1,5}")
# RFC 8628 user code as issued by the LinumIQ dashboard: XXXX-XXXX.
_USER_CODE_RE = re.compile(r"[A-Z0-9]{4}-[A-Z0-9]{4}")
# Opaque device code: URL-safe characters only (the dashboard sends 64 hex).
_DEVICE_CODE_RE = re.compile(r"[A-Za-z0-9._~-]{16,512}")
# RFC 3986 characters only (no space, quotes, '<', '>', '\\', '`', '{', '}',
# '|', '^' or controls) - browsers rewrite '\\' and drop tabs/newlines.
_URL_RE = re.compile(r"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{1,2048}")


def _is_ip(value: str) -> bool:
    """IPv4/IPv6 literal. Scoped IPv6 (``fe80::1%eth0``) is rejected: Python
    accepts any text after '%' as the zone ID."""
    if "%" in value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_valid_hostname(value: Any) -> bool:
    """RFC 1123 host name (letters, digits, '-', dot-separated labels)."""
    if not isinstance(value, str) or not value or len(value) > 253:
        return False
    return all(_LABEL_RE.fullmatch(label) for label in value.split("."))


def normalize_host(value: Any) -> Optional[str]:
    """Host name or IP literal for ``serverAddr`` / ``localIP``."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if _is_ip(value):
        return value
    if is_valid_hostname(value):
        return value.lower()
    return None


def normalize_domain_base(value: Any) -> Optional[str]:
    """A DNS suffix such as ``linumiq.net`` or ``dev.linumiq.net``.

    At least two labels, not an IP literal, and the top-level label must
    contain a letter.
    """
    if not isinstance(value, str):
        return None
    value = value.strip().lower().rstrip(".")
    if not is_valid_hostname(value) or _is_ip(value):
        return None
    labels = value.split(".")
    if len(labels) < 2 or labels[-1].isdigit():
        return None
    return value


def normalize_port(value: Any) -> Optional[int]:
    """TCP port 1-65535 (int or decimal string; bools rejected)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        port = value
    elif isinstance(value, str) and _PORT_RE.fullmatch(value.strip()):
        port = int(value.strip())
    else:
        return None
    return port if 1 <= port <= 65535 else None


def normalize_subdomain(value: Any) -> Optional[str]:
    """A single lowercase DNS label as assigned by the server."""
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    return value if _SUBDOMAIN_RE.fullmatch(value) else None


def normalize_token(value: Any) -> Optional[str]:
    """frp tunnel token: 8-1024 printable ASCII chars, no quotes/space."""
    if isinstance(value, str) and _TOKEN_RE.fullmatch(value):
        return value
    return None


def normalize_base_url(value: Any) -> Optional[str]:
    """http(s) base URL without trailing slash, query or fragment."""
    if not isinstance(value, str):
        return None
    value = value.strip().rstrip("/")
    if not _URL_RE.fullmatch(value):  # RFC 3986 characters only (no controls)
        return None
    try:
        parts = urlsplit(value)
        port = parts.port  # raises ValueError on garbage
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or parts.query or parts.fragment:
        return None
    if "@" in parts.netloc:  # user info (credentials) in the URL
        return None
    host = parts.hostname or ""
    if not (is_valid_hostname(host) or _is_ip(host)):
        return None
    if port is not None and not 1 <= port <= 65535:
        return None
    return value


def normalize_log_level(value: Any) -> Optional[str]:
    """Add-on log level -> frpc log level (trace|debug|info|warn|error)."""
    if isinstance(value, str):
        return LOG_LEVELS.get(value.strip().lower())
    return None


def normalize_bool(value: Any) -> Optional[bool]:
    """A JSON boolean (Supervisor's ``bool``); "true"/"false" strings too."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


# -- server verification (contract v2.2) -------------------------------------

_PEM_BLOCK_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]{1,40})-----([^-]*)-----END ([A-Z0-9 ]{1,40})-----")
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]+={0,2}")


def normalize_ca_pem(value: Any) -> Optional[str]:
    """One or more X.509 **CA** certificates in PEM form, normalised.

    Accepted: up to ``CA_MAX_CERTS`` ``CERTIFICATE`` blocks (at most
    ``CA_PEM_MAX_CHARS`` characters, only whitespace around them) that
    OpenSSL parses and recognises as CA certificates (``X509_check_ca``:
    basicConstraints CA:TRUE, or a v1 self-signed root). Anything else -
    other PEM block types such as private keys, junk between the blocks, a
    leaf certificate, broken base64 or DER - yields None. The result is
    re-encoded from the DER (64-column base64, ``\\n`` line ends, duplicates
    removed), so the file written from it is canonical.
    """
    if not isinstance(value, str) or len(value) > CA_PEM_MAX_CHARS:
        return None
    ders: list = []
    pos = 0
    for match in _PEM_BLOCK_RE.finditer(value):
        if value[pos:match.start()].strip():
            return None
        if match.group(1) != "CERTIFICATE" or match.group(3) != "CERTIFICATE":
            return None
        body = "".join(match.group(2).split())
        if not _BASE64_RE.fullmatch(body):
            return None
        try:
            der = base64.b64decode(body, validate=True)
        except (binascii.Error, ValueError):
            return None
        if der not in ders:
            ders.append(der)
        pos = match.end()
    if value[pos:].strip() or not ders or len(ders) > CA_MAX_CERTS:
        return None
    pem = "".join(ssl.DER_cert_to_PEM_cert(der) for der in ders)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        ctx.load_verify_locations(cadata=pem)
    except (ssl.SSLError, ValueError):
        return None
    stats = ctx.cert_store_stats()
    if stats.get("x509") != len(ders) or stats.get("x509_ca") != len(ders):
        return None
    return pem


def describe_ca(pem: Any) -> list:
    """``[{"subject", "not_after", "expired"}]`` for a (valid) CA bundle, for
    display; ``[]`` when it is unusable. Never raises."""
    pem = normalize_ca_pem(pem)
    if pem is None:
        return []
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    out = []
    try:
        ctx.load_verify_locations(cadata=pem)
        certs = ctx.get_ca_certs()
    except (ssl.SSLError, ValueError):  # pragma: no cover - validated above
        return []
    now = time.time()
    for cert in certs:
        names = {key: value for rdn in cert.get("subject", ()) for key, value in rdn}
        subject = names.get("commonName") or names.get("organizationName") or "?"
        try:
            expires = ssl.cert_time_to_seconds(cert.get("notAfter", ""))
        except (ValueError, TypeError):
            expires = None
        out.append({
            "subject": sanitize_text(subject, 80),
            "not_after": (datetime.fromtimestamp(expires, timezone.utc).strftime("%Y-%m-%d")
                          if expires is not None else ""),
            "expired": expires is not None and expires < now,
        })
    return out


# A masked account e-mail as sent by the dashboard ("g***@linumiq.com"). Only
# characters that are harmless in a log line or the panel.
_MASKED_EMAIL_RE = re.compile(r"[A-Za-z0-9.*_+~'-]{1,64}@[A-Za-z0-9.*-]{1,253}")


def normalize_masked_email(value: Any) -> Optional[str]:
    if isinstance(value, str) and _MASKED_EMAIL_RE.fullmatch(value.strip()):
        return value.strip()
    return None


# -- device pairing (RFC 8628 device-code response) -------------------------

def normalize_user_code(value: Any) -> Optional[str]:
    """``XXXX-XXXX`` (A-Z, 0-9), exactly as issued - no normalisation."""
    if isinstance(value, str) and _USER_CODE_RE.fullmatch(value):
        return value
    return None


def normalize_device_code(value: Any) -> Optional[str]:
    """Opaque device code: 16-512 URL-safe characters ``[A-Za-z0-9._~-]``."""
    if isinstance(value, str) and _DEVICE_CODE_RE.fullmatch(value):
        return value
    return None


def normalize_int_in_range(value: Any, low: int, high: int) -> Optional[int]:
    """A JSON integer within [low, high]; bools, floats and strings rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if low <= value <= high else None


def normalize_poll_interval(value: Any) -> Optional[int]:
    return normalize_int_in_range(value, *POLL_INTERVAL_RANGE)


def normalize_expires_in(value: Any) -> Optional[int]:
    return normalize_int_in_range(value, *EXPIRES_IN_RANGE)


def normalize_verification_uri(value: Any, app_base: Any) -> Optional[str]:
    """A verification link the panel may show (and the browser may open).

    Only RFC 3986 characters; scheme ``https`` (``http`` only when
    ``app_base`` itself is ``http``, i.e. an explicit development override);
    no user info; and the host must equal ``app_base``'s host. Anything else
    (``javascript:``, another host, ...) is rejected.
    """
    base = normalize_base_url(app_base)
    if base is None or not isinstance(value, str) or not _URL_RE.fullmatch(value):
        return None
    base_parts = urlsplit(base)
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return None
    allowed = {"https", "http"} if base_parts.scheme == "http" else {"https"}
    if parts.scheme not in allowed or "@" in parts.netloc:
        return None
    if port is not None and not 1 <= port <= 65535:
        return None
    host = (parts.hostname or "").lower()
    if not host or host != (base_parts.hostname or "").lower():
        return None
    return value


class PairingResponseError(ValueError):
    """The backend's device-code response is unusable or unsafe to show."""


#: Keys kept from a device-code response (and stored in frp-pairing.json).
PAIRING_KEYS = (
    "device_code", "user_code", "verification_uri", "verification_uri_complete",
    "interval", "expires_in",
)


def parse_pairing_response(body: Any, app_base: Any) -> Dict[str, Any]:
    """Validate a ``POST /api/device/code`` response (or a stored pairing).

    Returns a dict with exactly ``PAIRING_KEYS`` (``verification_uri*`` may
    be None when the server omits them; ``interval`` / ``expires_in`` default
    to 5 / 600 s when omitted). Raises PairingResponseError - with a message
    that never contains the offending value - when any present value is
    invalid, so the panel never renders untrusted text or links.
    """
    if not isinstance(body, Mapping):
        raise PairingResponseError("the response is not a JSON object")
    device_code = normalize_device_code(body.get("device_code"))
    if device_code is None:
        raise PairingResponseError("missing or invalid device_code")
    user_code = normalize_user_code(body.get("user_code"))
    if user_code is None:
        raise PairingResponseError("missing or invalid user_code (expected XXXX-XXXX)")

    out: Dict[str, Any] = {"device_code": device_code, "user_code": user_code}
    for key, normalize, default, (low, high) in (
        ("interval", normalize_poll_interval, DEFAULT_POLL_INTERVAL, POLL_INTERVAL_RANGE),
        ("expires_in", normalize_expires_in, DEFAULT_EXPIRES_IN, EXPIRES_IN_RANGE),
    ):
        raw = body.get(key)
        if raw is None:
            out[key] = default
            continue
        value = normalize(raw)
        if value is None:
            raise PairingResponseError(f"invalid {key} (expected an integer {low}-{high})")
        out[key] = value

    host = urlsplit(normalize_base_url(app_base) or "").hostname or "?"
    for key in ("verification_uri", "verification_uri_complete"):
        raw = body.get(key)
        if raw is None or raw == "":
            out[key] = None
            continue
        value = normalize_verification_uri(raw, app_base)
        if value is None:
            raise PairingResponseError(f"{key} is not an https link on {host}")
        out[key] = value
    return out


# -- log / message hygiene ----------------------------------------------------

_REDACTED = "<redacted>"


def sanitize_text(value: Any, limit: int = 200, secrets: Iterable[Any] = ()) -> str:
    """Make backend/user text safe to log or show in a banner.

    Known secrets are replaced by ``<redacted>`` (also their stripped and
    escaped forms, as they appear in exception messages), every
    non-printable character (CR, LF, tabs, other controls, bidi overrides,
    line separators) becomes a space, whitespace runs are collapsed and the
    result is cut to ``limit`` characters.
    """
    text = value if isinstance(value, str) else str(value)
    for secret in secrets:
        if not isinstance(secret, str) or not secret:
            continue
        for form in {secret, secret.strip(), secret.encode("unicode_escape").decode("ascii"),
                     repr(secret)[1:-1]}:
            if len(form) >= 4:
                text = text.replace(form, _REDACTED)
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: max(limit - 3, 0)].rstrip() + "..."
    return text


_OPTION_NORMALIZERS: Dict[str, Callable[[Any], Any]] = {
    "log_level": normalize_log_level,
    "verify_server": normalize_bool,
    "app_base": normalize_base_url,
    "api_base": normalize_base_url,
    "server_addr": normalize_host,
    "server_port": normalize_port,
    "domain_base": normalize_domain_base,
    "local_host": normalize_host,
    "local_port": normalize_port,
}

_SERVER_NORMALIZERS: Dict[str, Callable[[Any], Any]] = {
    "server_addr": normalize_host,
    "server_port": normalize_port,
    "domain_base": normalize_domain_base,
}


def _is_unset(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

def read_json(path: Path) -> Dict[str, Any]:
    """Read a JSON object; missing/corrupt/non-object files yield {}."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        LOG.error("Cannot read %s: %s", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def atomic_write(path: Path, text: str, mode: int = 0o600, gid: Optional[int] = None) -> None:
    """Write ``text`` to ``path`` atomically (temp file + rename), chmod mode
    (and chgrp ``gid`` when given). The temp file is created 0600, so the
    content is never readable by others in between."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        # chmod while the file is still root:root, then chgrp (no
        # CAP_FSETID probe, which the AppArmor profile does not grant).
        os.chmod(tmp, mode)
        if gid is not None:
            os.chown(tmp, -1, gid)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_json(path: Path, data: Mapping[str, Any]) -> None:
    atomic_write(path, json.dumps(dict(data), indent=2, sort_keys=True) + "\n")


def remove_file(path: Path) -> bool:
    """Delete ``path`` if it exists. Returns True if it existed; other
    OSErrors propagate (the caller must not report success)."""
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    return True


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def frpc_file_access() -> Tuple[int, Optional[int]]:
    """``(mode, gid)`` for files frpc must read: 0640 root:frpc in the image
    (frpc runs as the unprivileged ``frpc`` user), 0600 when that group does
    not exist (unit tests, other environments)."""
    try:
        import grp  # noqa: PLC0415 - POSIX only

        return 0o640, grp.getgrnam(FRPC_GROUP).gr_gid
    except (ImportError, KeyError):
        return 0o600, None


def ensure_access(path: Path, mode: int, gid: Optional[int]) -> bool:
    """chmod/chgrp an existing file if needed (e.g. a frpc.toml written 0600
    by 2.1.x). Returns True if something was changed."""
    st = path.stat()
    changed = False
    if (st.st_mode & 0o7777) != mode:
        os.chmod(path, mode)
        changed = True
    if gid is not None and st.st_gid != gid:
        os.chown(path, -1, gid)
        changed = True
    return changed


# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

#: What a valid value looks like, per option (shown in the panel banner).
OPTION_HINTS = {
    "log_level": "one of trace, debug, info, notice, warning, error, fatal",
    "verify_server": "true or false",
    "app_base": "an http(s) URL without user info, query or fragment",
    "api_base": "an http(s) URL without user info, query or fragment",
    "server_addr": "a host name (letters, digits, '-', dot-separated labels) or an IP address",
    "server_port": "a port 1-65535",
    "domain_base": "a DNS suffix with at least two labels, e.g. dev.linumiq.net",
    "local_host": "a host name (letters, digits, '-', dot-separated labels) or an IP address",
    "local_port": "a port 1-65535",
}


_URL_USERINFO_RE = re.compile(r"(^[^/]*//)[^/@]*@")


def parse_options_report(raw: Any) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """Like ``parse_options`` but also return ``{key: message}`` for every
    explicitly set option that is invalid (messages are safe to display)."""
    out: Dict[str, Any] = {}
    errors: Dict[str, str] = {}
    if not isinstance(raw, Mapping):
        return out, errors
    for key, normalize in _OPTION_NORMALIZERS.items():
        value = raw.get(key)
        if _is_unset(value):
            continue
        norm = normalize(value)
        if norm is None:
            shown = value
            if isinstance(shown, str):  # never echo URL credentials
                shown = _URL_USERINFO_RE.sub(r"\1***@", shown)
            shown = sanitize_text(repr(shown), limit=60)
            errors[key] = f"{key}={shown} is invalid (expected {OPTION_HINTS[key]}); it is ignored."
            LOG.error("Invalid add-on option: %s", errors[key])
            continue
        out[key] = norm
    return out, errors


def parse_options(raw: Mapping[str, Any]) -> Dict[str, Any]:
    """Return only the options the user explicitly set *and* that are valid.

    A key that is absent, null or an empty/whitespace string counts as "not
    set" (the equivalent of ``bashio::config.has_value`` failing). Invalid
    values are logged and ignored so that the next precedence layer applies.
    """
    return parse_options_report(raw)[0]


def load_options_report(paths: Paths) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """Read options.json; a missing file is fine (built-in defaults), an
    unreadable or malformed one is reported under the key ``options.json``."""
    try:
        raw = json.loads(paths.options.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, {}
    except (OSError, ValueError) as exc:
        msg = f"{paths.options} cannot be read ({sanitize_text(exc, 120)}); built-in defaults are used."
        LOG.error("%s", msg)
        return {}, {"options.json": msg}
    if not isinstance(raw, Mapping):
        msg = f"{paths.options} is not a JSON object; built-in defaults are used."
        LOG.error("%s", msg)
        return {}, {"options.json": msg}
    return parse_options_report(raw)


def load_options(paths: Paths) -> Dict[str, Any]:
    return load_options_report(paths)[0]


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class TunnelResponseError(ValueError):
    """The backend's tunnel response is unusable (missing/invalid fields)."""


def apply_tunnel_response(
    state: Mapping[str, Any], body: Any
) -> Tuple[Dict[str, Any], list]:
    """Merge a ``/api/device/tunnel`` response into the pairing state.

    ``subdomain`` and ``token`` are mandatory. ``server_addr``,
    ``server_port`` and ``domain_base`` are optional: the response is
    authoritative, so a key the server no longer sends (or sends with an
    invalid value) is removed from the state and the next precedence layer
    applies. ``account_email_masked`` (shown in the panel) likewise.

    ``server_ca_pem`` / ``server_name`` (v2.2) replace the stored values when
    they are present and valid, and are otherwise *kept*: a response without
    a CA (server rollback) or with an invalid one never removes a pinned CA.
    ``server_ca_note`` records why the stored CA was kept ("missing" /
    "invalid") so the panel can warn. Returns ``(new_state, warnings)``;
    raises TunnelResponseError.
    """
    if not isinstance(body, Mapping):
        raise TunnelResponseError("Backend returned a malformed tunnel response.")
    subdomain = normalize_subdomain(body.get("subdomain"))
    if subdomain is None:
        raise TunnelResponseError("Backend returned a missing or invalid subdomain.")
    token = normalize_token(body.get("token"))
    if token is None:
        raise TunnelResponseError("Backend returned a missing or invalid tunnel token.")

    new: Dict[str, Any] = dict(state)
    new["subdomain"] = subdomain
    new["token"] = token
    warnings = []
    for key, normalize in _SERVER_NORMALIZERS.items():
        new.pop(key, None)
        value = body.get(key)
        if _is_unset(value):
            continue
        norm = normalize(value)
        if norm is None:
            warnings.append(f"Ignored invalid server-provided {key}.")
            continue
        new[key] = norm

    new.pop("server_ca_note", None)
    raw_ca = body.get("server_ca_pem")
    if _is_unset(raw_ca):
        if new.get("server_ca_pem"):
            new["server_ca_note"] = "missing"
            warnings.append("The server sent no server_ca_pem; the last known frps CA stays pinned.")
    else:
        ca = normalize_ca_pem(raw_ca)
        if ca is None:
            new["server_ca_note"] = "invalid"
            warnings.append(
                "Ignored an invalid server-provided server_ca_pem"
                + ("; the last known frps CA stays pinned." if new.get("server_ca_pem") else ".")
            )
        else:
            new["server_ca_pem"] = ca
    raw_name = body.get("server_name")
    if not _is_unset(raw_name):
        name = normalize_host(raw_name)
        if name is None:
            warnings.append("Ignored invalid server-provided server_name.")
        else:
            new["server_name"] = name

    new.pop("account_email_masked", None)
    raw_email = body.get("account_email_masked")
    if not _is_unset(raw_email):
        email = normalize_masked_email(raw_email)
        if email is None:
            warnings.append("Ignored invalid server-provided account_email_masked.")
        else:
            new["account_email_masked"] = email

    new["version"] = STATE_VERSION
    new["updated_at"] = utc_now()
    return new, warnings


def is_paired(state: Mapping[str, Any]) -> bool:
    """Paired = device token + subdomain + frp token are all known."""
    return bool(
        state.get("device_token")
        and normalize_subdomain(state.get("subdomain"))
        and normalize_token(state.get("token"))
    )


_TABLE_RE = re.compile(r"\s*\[\[?\s*([A-Za-z0-9_.\-]+)\s*\]\]?\s*(?:#.*)?")
_LEGACY_TOKEN_RE = re.compile(r'\s*token\s*=\s*"([^"\\]*)"\s*(?:#.*)?')


def extract_legacy_token(toml_text: str) -> Optional[str]:
    """Find ``[metadatas] token = "..."`` in an frpc.toml written by <= 2.0.x."""
    table = ""
    for line in toml_text.splitlines():
        header = _TABLE_RE.fullmatch(line)
        if header:
            table = header.group(1)
            continue
        if table == "metadatas":
            match = _LEGACY_TOKEN_RE.fullmatch(line)
            if match:
                return normalize_token(match.group(1))
    return None


def migrate_legacy_state(paths: Paths, state: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    """Add-on <= 2.0.x kept the frp token only in frpc.toml - copy it over."""
    if not state.get("device_token") or state.get("token"):
        return state, False
    try:
        text = paths.frpc_toml.read_text(encoding="utf-8")
    except OSError:
        return state, False
    token = extract_legacy_token(text)
    if not token:
        return state, False
    new = dict(state)
    new["token"] = token
    new["version"] = STATE_VERSION
    LOG.info("Migrated tunnel token from legacy frpc.toml into the state file.")
    return new, True


def load_state(paths: Paths, persist_migration: bool = True) -> Dict[str, Any]:
    state = read_json(paths.state)
    state, migrated = migrate_legacy_state(paths, state)
    if migrated and persist_migration:
        write_json(paths.state, state)
    return state


@contextmanager
def state_lock(paths: Paths, timeout: Optional[float] = None) -> Iterator[None]:
    """Exclusive cross-process lock (flock on ``/data/.frp-state.lock``).

    Held by the panel around every state change (pair, refresh, subdomain
    change, unpair) and by the ``render`` CLI of the frpc service, so frpc can
    never be started from a state that is being torn down. Not re-entrant:
    ``render_from_disk`` itself does not take it. Raises TimeoutError (an
    OSError) when ``timeout`` seconds pass without getting the lock.
    """
    paths.data_dir.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(paths.lock), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if timeout is None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        else:
            deadline = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"{paths.lock} is busy") from None
                    time.sleep(0.1)
        yield
    finally:
        os.close(fd)  # releases the lock


# ---------------------------------------------------------------------------
# Effective settings (precedence)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Settings:
    app_base: str
    api_base: str
    server_addr: str
    server_port: int
    domain_base: str
    local_host: str
    local_port: int
    log_level: str
    #: key -> "option" | "server" | "default" | "server_addr"
    sources: Dict[str, str] = field(default_factory=dict)
    #: verify_server option (default True).
    verify_server: bool = True
    #: Name the frps certificate must be valid for (server-provided
    #: server_name, else the effective server_addr).
    server_name: str = ""
    #: Validated CA bundle from the state (None: none known).
    ca_pem: Optional[str] = field(default=None, repr=False)

    @property
    def tls_mode(self) -> str:
        """TLS_VERIFIED, TLS_UNVERIFIED (no CA known) or TLS_DISABLED."""
        if not self.verify_server:
            return TLS_DISABLED
        return TLS_VERIFIED if self.ca_pem else TLS_UNVERIFIED

    def describe_tls(self) -> str:
        mode = self.tls_mode
        if mode == TLS_VERIFIED:
            return f"tls=verified (CA from server, serverName={self.server_name})"
        if mode == TLS_DISABLED:
            return "tls=on, frps certificate NOT verified (verify_server=false)"
        return "tls=on, frps certificate NOT verified (the server provided no CA)"

    def describe(self) -> str:
        """One-line, secret-free summary for logs."""
        src = self.sources
        return (
            f"server={self.server_addr}:{self.server_port} "
            f"(addr from {src.get('server_addr')}, port from {src.get('server_port')}), "
            f"domain_base={self.domain_base} (from {src.get('domain_base')}), "
            f"local={self.local_host}:{self.local_port}, {self.describe_tls()}"
        )


def effective_settings(options: Mapping[str, Any], state: Mapping[str, Any]) -> Settings:
    """Apply option > server > default precedence (see module docstring)."""
    sources: Dict[str, str] = {}

    def pick(key: str, default: Any) -> Any:
        if key in options:
            sources[key] = "option"
            return options[key]
        if key in _SERVER_NORMALIZERS and not _is_unset(state.get(key)):
            value = _SERVER_NORMALIZERS[key](state.get(key))
            if value is not None:
                sources[key] = "server"
                return value
        sources[key] = "default"
        return default

    server_addr = pick("server_addr", DEFAULT_SERVER_ADDR)
    server_port = pick("server_port", DEFAULT_SERVER_PORT)
    derived = normalize_domain_base(server_addr)
    domain_base = pick("domain_base", derived or DEFAULT_DOMAIN_BASE)
    if sources["domain_base"] == "default" and derived:
        sources["domain_base"] = "server_addr"

    verify_server = pick("verify_server", True)
    # Re-validated on every use: the state file may be old or tampered with.
    ca_pem = normalize_ca_pem(state.get("server_ca_pem")) if state.get("server_ca_pem") else None
    server_name = normalize_host(state.get("server_name")) or server_addr

    return Settings(
        app_base=pick("app_base", DEFAULT_APP_BASE),
        api_base=pick("api_base", DEFAULT_API_BASE),
        server_addr=server_addr,
        server_port=server_port,
        domain_base=domain_base,
        local_host=pick("local_host", DEFAULT_LOCAL_HOST),
        local_port=pick("local_port", DEFAULT_LOCAL_PORT),
        log_level=pick("log_level", DEFAULT_LOG_LEVEL),
        sources=sources,
        verify_server=verify_server,
        server_name=server_name,
        ca_pem=ca_pem,
    )


# ---------------------------------------------------------------------------
# frpc.toml rendering
# ---------------------------------------------------------------------------

def toml_str(value: str) -> str:
    """TOML basic string (escapes quotes, backslashes and control chars)."""
    out = ['"']
    for ch in value:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif code < 0x20 or code == 0x7F:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def public_hostname(settings: Settings, subdomain: str) -> str:
    return f"{subdomain}.{settings.domain_base}"


def render_frpc_toml(
    settings: Settings, subdomain: str, token: str, ca_file: Optional[str] = None
) -> str:
    """Render the frpc v0.65 TOML configuration.

    ``ca_file`` (the path ``settings.ca_pem`` was written to) is required
    when ``settings.tls_mode`` is TLS_VERIFIED.
    """
    sub = normalize_subdomain(subdomain)
    tok = normalize_token(token)
    if sub is None or tok is None:
        raise ValueError("invalid subdomain or token")
    if settings.tls_mode == TLS_VERIFIED:
        if not ca_file or normalize_host(settings.server_name) is None:
            raise ValueError("server verification needs a CA file and a valid server name")
        tls_lines = [
            "# Verify the frps certificate: it must chain to the CA provided by the",
            "# LinumIQ server (pinned in the state file) and be valid for serverName.",
            f"transport.tls.trustedCaFile = {toml_str(ca_file)}",
            f"transport.tls.serverName = {toml_str(settings.server_name)}",
        ]
    elif settings.tls_mode == TLS_DISABLED:
        tls_lines = ["# The frps certificate is NOT verified (add-on option verify_server: false)."]
    else:
        tls_lines = ["# The frps certificate is NOT verified (the server provided no CA)."]
    lines = [
        "# Generated by the FRP Tunnel add-on from /data/frp-state.json and the",
        "# add-on options. Re-rendered on every frpc (re)start: do not edit.",
        f"serverAddr = {toml_str(settings.server_addr)}",
        f"serverPort = {int(settings.server_port)}",
        "loginFailExit = false",
        "",
        "# Encrypt the frpc <-> frps connection (control + proxied traffic).",
        "transport.tls.enable = true",
        *tls_lines,
        "",
        "# Per-tunnel credential, validated by the frps auth plugin (metas.token).",
        "[metadatas]",
        f"token = {toml_str(tok)}",
        "",
        "[log]",
        'to = "console"',
        f"level = {toml_str(settings.log_level)}",
        "",
        "[[proxies]]",
        f"name = {toml_str(sub)}",
        'type = "http"',
        f"customDomains = [{toml_str(public_hostname(settings, sub))}]",
        f"localIP = {toml_str(settings.local_host)}",
        f"localPort = {int(settings.local_port)}",
        "",
    ]
    return "\n".join(lines)


class RenderResult:
    RENDERED = "rendered"
    UNCHANGED = "unchanged"
    NOT_PAIRED = "not_paired"


def ensure_searchable(directory: Path, gid: Optional[int]) -> bool:
    """frpc (group ``gid``) must be able to reach the files it reads in
    ``directory`` (/data). Supervisor creates the add-on's data directory
    0755; should it not be searchable for frpc, ``o+x`` is added - search
    only, no listing, and every file keeps its own mode (the state file stays
    0600). Returns True if the mode was changed."""
    if gid is None:
        return False
    st = directory.stat()
    if st.st_mode & 0o001 or (st.st_gid == gid and st.st_mode & 0o010):
        return False
    os.chmod(directory, (st.st_mode & 0o7777) | 0o001)
    LOG.warning("%s was not searchable for frpc; added o+x.", directory)
    return True


def _write_if_changed(path: Path, text: str, mode: int, gid: Optional[int]) -> bool:
    """Atomically (re)write ``path`` unless it already holds ``text``; fix
    its mode/group either way. Returns True if the content changed."""
    try:
        current = path.read_text(encoding="utf-8")
    except OSError:
        current = None
    if current == text:
        ensure_access(path, mode, gid)
        return False
    atomic_write(path, text, mode, gid)
    return True


def render_from_disk(
    paths: Optional[Paths] = None, options: Optional[Mapping[str, Any]] = None
) -> Tuple[str, Optional[Settings]]:
    """(Re)write frpc.toml (and frps-ca.pem) from options + state (options
    are read from options.json unless given). Raises ValueError if the state
    is paired but unusable.

    Without a valid pairing (state file missing, corrupt or incomplete) a
    leftover frpc.toml and frps-ca.pem are deleted, so the old token can
    never be used. frps-ca.pem exists only while frpc.toml references it.
    Returns RENDERED when either file changed (frpc must restart). The caller
    should hold ``state_lock``.
    """
    paths = paths or default_paths()
    if options is None:
        options = load_options(paths)
    state = load_state(paths)
    if not is_paired(state):
        remove_file(paths.frpc_toml)
        remove_file(paths.frps_ca)
        return RenderResult.NOT_PAIRED, None
    settings = effective_settings(options, state)
    mode, gid = frpc_file_access()
    ensure_searchable(paths.data_dir, gid)
    changed = False
    if settings.tls_mode == TLS_VERIFIED:
        assert settings.ca_pem is not None
        changed = _write_if_changed(paths.frps_ca, settings.ca_pem, mode, gid)
        text = render_frpc_toml(settings, state["subdomain"], state["token"], str(paths.frps_ca))
    else:
        changed = remove_file(paths.frps_ca)
        text = render_frpc_toml(settings, state["subdomain"], state["token"])
    changed = _write_if_changed(paths.frpc_toml, text, mode, gid) or changed
    return (RenderResult.RENDERED if changed else RenderResult.UNCHANGED), settings


# ---------------------------------------------------------------------------
# CLI (used by the frpc s6 service)
# ---------------------------------------------------------------------------

def _cli(argv: list) -> int:
    logging.basicConfig(
        level=os.environ.get("FRP_MGR_LOG_LEVEL", "INFO").upper(),
        format="[%(asctime)s] %(levelname)s: (frpc-render) %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )
    if argv[1:] != ["render"]:
        print("usage: config.py render", file=sys.stderr)
        return EXIT_ERROR
    paths = default_paths()
    try:
        with state_lock(paths, timeout=CLI_LOCK_TIMEOUT):
            result, settings = render_from_disk(paths)
    except (OSError, ValueError) as exc:
        # Messages never contain secrets (paths / validation errors only).
        LOG.error("Cannot render frpc.toml: %s", sanitize_text(exc))
        return EXIT_ERROR
    if result == RenderResult.NOT_PAIRED:
        return EXIT_NOT_PAIRED
    assert settings is not None
    LOG.info("frpc.toml %s: %s", result, settings.describe())
    if settings.tls_mode != TLS_VERIFIED:
        LOG.warning("The frps server certificate is not verified (%s); see the add-on documentation.",
                    "verify_server is false" if settings.tls_mode == TLS_DISABLED
                    else "the LinumIQ server provided no CA")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(_cli(sys.argv))
