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
regenerate, CA regenerate; upstream.py: the forwarding mode). If it fails, the
reload does not happen and counts as failed. A stale list can only refuse a
new client, never admit a revoked one: the leaf verifier refuses that one in
the handshake.

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
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

import headerauth

ACTIVE_DIR = Path(os.environ.get("CADDY_MTLS_ACTIVE_DIR", "/data/certs/active"))
FINGERPRINT_FILE = Path(os.environ.get("CADDY_MTLS_FINGERPRINT_FILE", "/etc/caddy/client-fingerprints.caddy"))
CADDY_BIN = os.environ.get("CADDY_BIN", "/usr/bin/caddy")
CADDYFILE = Path(os.environ.get("CADDYFILE", "/etc/caddy/Caddyfile"))
CADDY_ADMIN = os.environ.get("CADDY_ADMIN", "localhost:2019")
OPENSSL_BIN = os.environ.get("OPENSSL_BIN", "openssl")

#: {http.request.tls.client.fingerprint} of a connection without a client
#: certificate (Caddy hashes an empty certificate: replacer.go).
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
#: The list's only value when no client is active: never 64 hex characters.
NO_CLIENT = "no-active-client"
FINGERPRINT_RE = re.compile(r"[0-9a-f]{64}")
_PEM_BLOCK = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n(.*?)-----END \1-----", re.S)


class FingerprintError(OSError):
    """The list could not be written (the reload must not go ahead)."""


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
# Reload
# ---------------------------------------------------------------------------

# Every run-time reload of the add-on goes through ``reload``. It re-reads
# only files the add-on wrote itself at the start or rewrites at run time:
# the generated Caddyfile, the forwarding snippet, this fingerprint list and
# the COPIES of the custom Caddyfile snippets in /etc/caddy/custom/ (never
# the user's files in /config/caddy/). init-caddy checked those copies at the
# start (caddy validate plus the integrity check of customconf.py), and
# nothing changes them afterwards - so the check at the start covers every
# reload. A change here that makes a reload read anything else must check it
# again.

Runner = Callable[..., subprocess.CompletedProcess]


def reload(*, caddy_bin: str | None = None, caddyfile: Path | None = None, admin: str | None = None,
           timeout: float = 60, run: Runner | None = None,
           regenerate: Callable[[], object] | None = None) -> tuple[bool, str]:
    """Regenerate the fingerprint list, then ``caddy reload --force`` (Caddy
    skips an unchanged config otherwise: a client change touches only the
    active folder and the list). (ok, Caddy's output scrubbed of the header
    key, or why it did not run)."""
    caddy_bin = CADDY_BIN if caddy_bin is None else caddy_bin
    caddyfile = CADDYFILE if caddyfile is None else caddyfile
    admin = CADDY_ADMIN if admin is None else admin
    run = subprocess.run if run is None else run
    regenerate = write_fingerprints if regenerate is None else regenerate
    if not caddyfile.exists():
        return False, f"Caddyfile not found at {caddyfile}"
    try:
        regenerate()
    except FingerprintError as err:
        return False, f"the list of active client certificates could not be written ({err}); Caddy was not reloaded"
    try:
        proc = run(
            [caddy_bin, "reload", "--force", "--config", str(caddyfile),
             "--adapter", "caddyfile", "--address", admin],
            capture_output=True, text=True, check=False, timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as err:
        return False, headerauth.scrub(str(err))
    if proc.returncode != 0:
        return False, headerauth.scrub(proc.stderr or proc.stdout or "caddy reload failed")
    return True, "reloaded"


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
