"""
Caddy mTLS Proxy - reloading the running Caddy, and the list of active
client certificates for the header authentication gate (since 2.3.0).

With header authentication and mTLS on, the public site requests a client
certificate without requiring it (``verify_if_given``): a certificate that is
presented is still checked in the handshake by the leaf verifier against the
folder ACTIVE_DIR (revocation), and the HTTP gate admits a request without
the header key only if the connection's certificate has the SHA-256
fingerprint of an active client - not merely "a certificate was presented",
which a certificate accepted by ANOTHER site's client authentication could
satisfy (REPORT-I I-7). Both checks must agree.

One source of truth: the fingerprints are derived from exactly the files the
leaf verifier loads (Caddy 2.11.9 modules/caddytls/leaffolderloader.go: every
file below the folder whose name ends in .pem, case-insensitively, following
symlinks; all its PEM blocks must be CERTIFICATE and together one DER
certificate), never kept separately. ``write_fingerprints`` renders them into
FINGERPRINT_FILE (imported by the gate's matcher), atomically. It runs in
init-caddy before rendering and in ``reload`` immediately before EVERY
``caddy reload`` the add-on performs (the panel: client add / revoke /
regenerate, CA regenerate; upstream.py: the forwarding mode). If it fails,
Caddy is reloaded all the same - with the previous list, which is the safe
direction: the reload refreshes the leaf verifier (a revoked certificate is
refused in the handshake), and a stale list can only refuse a new client,
never admit a revoked one. The failure is logged and reported (see
``reload``).

The value Caddy reports for "no certificate" is the SHA-256 of empty input
(EMPTY_SHA256): it is never written, whatever the folder holds. No active
client: the sentinel NO_CLIENT, which can never be a fingerprint.

Standard library only (plus the openssl CLI, which must parse each
certificate).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

import customconf
import headerauth

LOG = logging.getLogger("caddyctl")

ACTIVE_DIR = Path(os.environ.get("CADDY_MTLS_ACTIVE_DIR", "/data/certs/active"))
FINGERPRINT_FILE = Path(os.environ.get("CADDY_MTLS_FINGERPRINT_FILE", "/etc/caddy/client-fingerprints.caddy"))
CADDY_BIN = os.environ.get("CADDY_BIN", "/usr/bin/caddy")
CADDYFILE = Path(os.environ.get("CADDYFILE", "/etc/caddy/Caddyfile"))
CADDY_ADMIN = os.environ.get("CADDY_ADMIN", "127.0.0.1:2019")
OPENSSL_BIN = os.environ.get("OPENSSL_BIN", "openssl")
OPTIONS_FILE = headerauth.OPTIONS_FILE

#: The whole environment of every caddy invocation that reads the Caddyfile
#: (2.3.0): a snippet's {$VAR} is expanded by the process that adapts it, so
#: init-caddy (validate, adapt), the caddy service (run) and every reload
#: here must adapt in the same environment - what Caddy needs (its data and
#: configuration locations come from HOME / XDG_*), plus the DNS provider
#: variables as the caddy service exports them, and nothing else (no
#: Supervisor token, no CADDY_MTLS_* internals). The same names as
#: CADDY_ENV_NAMES in lib/dns-provider.sh (test_caddyctl compares both).
CADDY_ENV_NAMES = ("PATH", "HOME", "TZ", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
                   "DNS_API_TOKEN", "DNS_AWS_ACCESS_KEY_ID", "DNS_AWS_SECRET_ACCESS_KEY")
DNS_ENV_NAMES = ("DNS_API_TOKEN", "DNS_AWS_ACCESS_KEY_ID", "DNS_AWS_SECRET_ACCESS_KEY")

#: {http.request.tls.client.fingerprint} of a connection without a client
#: certificate (Caddy hashes an empty certificate: replacer.go).
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
#: The list's only value when no client is active: never 64 hex characters.
NO_CLIENT = "no-active-client"
FINGERPRINT_RE = re.compile(r"[0-9a-f]{64}")
_PEM_BLOCK = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n(.*?)-----END \1-----", re.S)


class FingerprintError(OSError):
    """The list could not be written (Caddy is reloaded with the previous
    one; the failure is reported)."""


def _der_of(path: Path) -> bytes:
    """The DER bytes Caddy's loader would parse (every PEM block must be a
    CERTIFICATE; their contents concatenated). Raises ValueError."""
    data = path.read_bytes()
    blocks = _PEM_BLOCK.findall(data)
    if not blocks:
        raise ValueError("no CERTIFICATE PEM block")
    der = b""
    for kind, body in blocks:
        if kind != b"CERTIFICATE":
            raise ValueError(f"a {kind.decode()} PEM block")
        try:
            der += base64.b64decode(b"".join(body.split()), validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("a PEM block that is not base64") from None
    if not der:
        raise ValueError("an empty PEM block")
    return der


def _openssl_fingerprint(der: bytes) -> str:
    """The SHA-256 fingerprint openssl computes for a DER certificate
    (lower-case hex), or "" if openssl does not parse it."""
    try:
        proc = subprocess.run(
            [OPENSSL_BIN, "x509", "-inform", "DER", "-noout", "-fingerprint", "-sha256"],
            input=der, capture_output=True, check=False, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if proc.returncode != 0:
        return ""
    text = proc.stdout.decode("ascii", "replace").strip()
    return text.partition("=")[2].replace(":", "").lower()


def _candidates(folder: Path) -> list[Path]:
    """The files the leaf folder loader reads (sorted, for a stable list)."""
    found: list[Path] = []
    for root, dirs, files in os.walk(folder):
        dirs.sort()
        for name in files:
            if name.lower().endswith(".pem"):
                found.append(Path(root, name))
    return sorted(found)


def active_fingerprints(folder: Path | None = None) -> tuple[list[str], list[str]]:
    """(fingerprints, warnings): one entry per file of ``folder`` that is a
    certificate - parsed by openssl, 64 lower-case hex characters, equal to
    the SHA-256 of the file's DER (so a file with more than one certificate
    or trailing data gives none) and never EMPTY_SHA256. A missing folder:
    no entries. An unreadable folder: FingerprintError."""
    folder = ACTIVE_DIR if folder is None else folder
    if not folder.exists():
        return [], []
    if not folder.is_dir():
        raise FingerprintError(f"{folder} is not a folder")
    fingerprints: list[str] = []
    warnings: list[str] = []
    try:
        paths = _candidates(folder)
    except OSError as err:
        raise FingerprintError(f"cannot read {folder}: {err}") from err
    for path in paths:
        try:
            der = _der_of(path)
        except (OSError, ValueError) as err:
            warnings.append(f"{path}: left out ({err})")
            continue
        digest = hashlib.sha256(der).hexdigest()
        parsed = _openssl_fingerprint(der)
        if not parsed:
            warnings.append(f"{path}: left out (openssl does not parse it as a certificate)")
        elif parsed != digest:
            warnings.append(f"{path}: left out (more than one certificate or trailing data)")
        elif not FINGERPRINT_RE.fullmatch(digest) or digest == EMPTY_SHA256:
            warnings.append(f"{path}: left out (not a certificate fingerprint)")
        elif digest not in fingerprints:
            fingerprints.append(digest)
    return fingerprints, warnings


def render_fingerprints(fingerprints: list[str]) -> str:
    """The imported matcher line: the request's certificate is NOT one of
    the active ones (NO_CLIENT if there are none)."""
    values = [fp for fp in fingerprints if FINGERPRINT_RE.fullmatch(fp) and fp != EMPTY_SHA256]
    lines = [
        "# The active client certificates (SHA-256 of each certificate in",
        f"# {ACTIVE_DIR}) - written by the Caddy mTLS Proxy add-on before every",
        "# (re)load of Caddy. Matches a request whose connection has none of them.",
        "not vars {http.request.tls.client.fingerprint} " + " ".join(values or [NO_CLIENT]),
    ]
    return "\n".join(lines) + "\n"


def write_fingerprints(folder: Path | None = None, path: Path | None = None) -> tuple[list[str], list[str]]:
    """Regenerate the list file from ``folder`` (write + rename, mode 644;
    defaults ACTIVE_DIR, FINGERPRINT_FILE). Raises FingerprintError."""
    path = FINGERPRINT_FILE if path is None else path
    fingerprints, warnings = active_fingerprints(folder)
    text = render_fingerprints(fingerprints)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="ascii") as fh:
                fh.write(text)
            os.chmod(tmp, 0o644)
            os.replace(tmp, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
    except OSError as err:
        raise FingerprintError(f"cannot write {path}: {err}") from err
    return fingerprints, warnings


# ---------------------------------------------------------------------------
# Caddy's environment
# ---------------------------------------------------------------------------

def dns_env(provider: str, token: str) -> dict[str, str]:
    """The variables lib/dns-provider.sh's dns_provider_export exports for
    the options acme_dns_provider / dns_api_token (the same rules; nothing
    for a token that does not fit - init-caddy refuses to start then)."""
    if provider in ("cloudflare", "hetzner") and token:
        return {"DNS_API_TOKEN": token}
    if provider == "route53":
        key_id, colon, secret = token.partition(":")
        if colon and key_id and secret:
            return {"DNS_AWS_ACCESS_KEY_ID": key_id, "DNS_AWS_SECRET_ACCESS_KEY": secret}
    return {}


def caddy_env(environ: Mapping[str, str] | None = None, options_file: Path | None = None) -> dict[str, str]:
    """The environment for a caddy invocation that reads the Caddyfile:
    CADDY_ENV_NAMES' own variables from ``environ`` (default os.environ),
    the DNS provider variables from the add-on's options (the panel's own
    environment has none of them)."""
    environ = os.environ if environ is None else environ
    env = {name: environ[name] for name in CADDY_ENV_NAMES if name not in DNS_ENV_NAMES and name in environ}
    try:
        options = json.loads((OPTIONS_FILE if options_file is None else options_file).read_text())
    except (OSError, ValueError):
        options = {}
    if isinstance(options, dict):
        env.update(dns_env(str(options.get("acme_dns_provider") or "none"), str(options.get("dns_api_token") or "")))
    return env


# ---------------------------------------------------------------------------
# Reload
# ---------------------------------------------------------------------------

# Every run-time reload of the add-on goes through ``reload_detailed``. The
# Caddyfile it reloads imports only files the add-on wrote itself: the
# forwarding snippet, the fingerprint list and the COPIES of the custom
# Caddyfile snippets in /etc/caddy/custom/ (never the user's files in
# /config/caddy/), which init-caddy checked at the start (caddy validate
# plus customconf.py's integrity check) and nothing changes afterwards. But
# files a snippet REFERS to (a site's tls certificate and key, a trust_pool
# file, CA files of a transport, ...) are read by Caddy at every reload, and
# can break after the start. So while custom files are in use, init-caddy
# keeps the add-on's own rendering (customconf.FALLBACK_FILE): a reload that
# Caddy refuses (caddy_judged - not one that timed out or never reached
# Caddy) is retried with it, and if that works the custom files are dropped
# for the rest of the run (customconf.drop) - the change being applied (a
# revocation) takes effect. All of it under one lock (customconf.reload_lock)
# shared by the panel and the monitor. A change that makes a reload read
# anything else must keep that guarantee.

Runner = Callable[..., subprocess.CompletedProcess]


@dataclass(frozen=True)
class ReloadResult:
    """What ``reload_detailed`` did."""

    #: Caddy took the configuration.
    reloaded: bool
    #: Why the fingerprint list could not be written ("" when it was).
    list_error: str = ""
    #: Caddy's output (scrubbed of the header key) when it did not reload.
    caddy_error: str = ""
    #: The custom files were dropped to make the reload work: the message
    #: for the user ("" when not).
    dropped: str = ""

    @property
    def ok(self) -> bool:
        return self.reloaded and not self.list_error

    @property
    def message(self) -> str:
        """What happened, for the log, the panel and the state file."""
        if self.ok:
            return self.dropped or "reloaded"
        if not self.list_error:
            return self.caddy_error
        what = f"the list of active client certificates could not be written ({self.list_error})"
        if self.reloaded:
            return (f"{what}; Caddy was reloaded with the previous list: revoked certificates are refused; "
                    "with a header key set, a new or regenerated client certificate gets 403 until the "
                    "list can be written (at the latest after a restart of the add-on)")
        return f"{what}, and Caddy could not be reloaded: {self.caddy_error}"

    @property
    def banner(self) -> str:
        """``message`` for the panel's banner: Caddy's output reduced to its
        cause (customconf.caddy_message); the log keeps the full output."""
        if self.caddy_error and not self.ok:
            return self.message.replace(self.caddy_error, customconf.caddy_message(self.caddy_error))
        return self.message


#: What the Caddy CLI prints when it could not talk to the admin endpoint at
#: all (see caddy_judged).
_NOT_REACHED = "sending configuration to instance: performing request:"


def caddy_judged(output: str) -> bool:
    """Did ``caddy reload`` run to its end and get a verdict on the
    configuration (so that retrying with the add-on's own one can help)?
    False only for the one sign that the running Caddy was never reached:
    Caddy 2.11.9's cmd/commandfuncs.go (cmdReload) wraps the error of
    AdminAPIRequest as "sending configuration to instance: %v", and
    cmd/main.go (AdminAPIRequest) wraps a failed HTTP request as
    "performing request: %v" - e.g. (the binary's real output, as an error
    log line) ``sending configuration to instance: performing request: Post
    "http://127.0.0.1:2019/load": dial tcp 127.0.0.1:2019: connect:
    connection refused`` (also reset, EOF). Caddy's answer to a refused
    configuration is "sending configuration to instance: caddy responded
    with error: HTTP 400: ...", the adapter's own errors ("adapting config
    using caddyfile: ...") come before any request. Everything else - an
    output this code does not know included - counts as judged: a
    revocation matters more than a snippet. (A CLI that did not finish or
    could not be started is decided by the caller.)"""
    return _NOT_REACHED not in output


def reload_detailed(*, caddy_bin: str | None = None, caddyfile: Path | None = None, admin: str | None = None,
                    timeout: float = 60, run: Runner | None = None,
                    regenerate: Callable[[], object] | None = None, fallback: Path | None = None,
                    lock: Path | None = None, env: Mapping[str, str] | None = None) -> ReloadResult:
    """Under the reload lock: regenerate the fingerprint list, then ``caddy
    reload --force`` (Caddy skips an unchanged config otherwise: a client
    change touches only the active folder and the list) - also when the list
    could not be written: the reload must not depend on it (revocation), and
    the previous list can only refuse too much. If Caddy refused the
    configuration (caddy_judged: the CLI ran to its end and reached Caddy)
    and the fallback file exists (custom files in use), reload with it; when
    that works, the custom files are dropped for this run (customconf.drop)
    and the reload counts as done. A CLI that timed out, could not be
    started or did not reach the admin endpoint is reported as a failure,
    nothing dropped. Every caddy call gets ``env`` (default caddy_env()). A
    list failure, a drop and a failed fallback are logged here."""
    caddy_bin = CADDY_BIN if caddy_bin is None else caddy_bin
    caddyfile = CADDYFILE if caddyfile is None else caddyfile
    admin = CADDY_ADMIN if admin is None else admin
    run = subprocess.run if run is None else run
    regenerate = write_fingerprints if regenerate is None else regenerate
    fallback = customconf.FALLBACK_FILE if fallback is None else fallback
    env = caddy_env() if env is None else env

    def caddy_reload(config: Path) -> tuple[bool, str, bool]:
        """(reloaded, Caddy's output when not, whether Caddy judged it)."""
        try:
            proc = run(
                [caddy_bin, "reload", "--force", "--config", str(config),
                 "--adapter", "caddyfile", "--address", admin],
                capture_output=True, text=True, check=False, timeout=timeout, env=dict(env),
            )
        except (OSError, subprocess.SubprocessError) as err:
            # Did not finish (TimeoutExpired) or could not be started.
            return False, headerauth.scrub(str(err)), False
        if proc.returncode != 0:
            output = headerauth.scrub(proc.stderr or proc.stdout or "caddy reload failed")
            return False, output, caddy_judged(output)
        return True, "", True

    with customconf.reload_lock(lock):
        if not caddyfile.exists():
            return ReloadResult(False, caddy_error=f"Caddyfile not found at {caddyfile}")
        list_error = ""
        try:
            regenerate()
        except FingerprintError as err:
            list_error = str(err)
        reloaded, caddy_error, judged = caddy_reload(caddyfile)
        dropped = ""
        if not reloaded and judged and fallback.exists():
            cause = customconf.caddy_message(caddy_error)
            fallback_ok, fallback_error, _ = caddy_reload(fallback)
            if fallback_ok:
                dropped = customconf.drop(cause, when="reload", caddyfile=caddyfile, fallback=fallback)
                reloaded, caddy_error = True, ""
                LOG.warning("%s", dropped)
                if fallback.exists():
                    LOG.error("The Caddyfile could not be replaced by the add-on's own configuration; Caddy runs "
                              "it all the same, and the next reload falls back again.")
            else:
                LOG.error("Caddy could not reload with the custom Caddyfile snippets (%s), nor with the add-on's own "
                          "configuration without them (%s): nothing was dropped.",
                          cause, customconf.caddy_message(fallback_error))
        result = ReloadResult(reloaded, list_error, caddy_error, dropped)
    if list_error:
        LOG.error("%s", result.message)
    return result


def reload(**kwargs: object) -> tuple[bool, str]:
    """``reload_detailed`` as (ok, message): ok only when Caddy reloaded AND
    the fingerprint list was written (the panel reports anything else; see
    ReloadResult.message for what happened - with ok, "reloaded" or the
    message that the custom files were dropped)."""
    result = reload_detailed(**kwargs)  # type: ignore[arg-type]
    return result.ok, result.message


def _main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    sub = parser.add_subparsers(dest="command", required=True)
    fp = sub.add_parser("fingerprints", help="write the list of active client certificates")
    fp.add_argument("--folder", type=Path, default=None)
    fp.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)
    try:
        fingerprints, warnings = write_fingerprints(args.folder, args.output)
    except FingerprintError as err:
        print(f"ERROR {err}", file=sys.stderr)
        return 1
    for warning in warnings:
        print(f"WARNING {warning}", file=sys.stderr)
    print(len(fingerprints))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
