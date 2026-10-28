"""
Caddy mTLS Proxy - certificate management web UI.

Runs on the Home Assistant ingress port (8099), only reachable via the
Supervisor's ingress proxy at 172.30.32.2. Provides a dashboard with the
state of the public (Let's Encrypt) server certificate (public_cert.py,
refreshed every 30 s), the CA and client certificate metadata, client bundle
downloads, regenerating or revoking individual client certs, and (with a
typed confirmation) regenerating the entire CA (the mTLS CA - the public
server certificate is Caddy's).

All mutations:
  1. Run the matching shell helper inside the existing cert-helpers.sh
     library so behaviour is identical to the s6 init oneshot.
  2. Refresh /data/state.json so sensors and the UI stay in sync.
  3. Trigger `caddy reload` against the local admin API so the new
     allowlist / certs are picked up without dropping connections.

The app is intentionally dependency-light (FastAPI + Jinja2 only) and
keeps shell-out calls explicit so they can be audited.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from fastapi import FastAPI, Form, HTTPException, Request, status
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

import public_cert

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LOG = logging.getLogger("cert-mgr")
logging.basicConfig(
    level=os.environ.get("CERT_MGR_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

CERT_DIR = Path(os.environ.get("CERT_DIR", "/data/certs"))
STATE_FILE = Path(os.environ.get("STATE_FILE", "/data/state.json"))
CADDY_ADMIN = os.environ.get("CADDY_ADMIN", "localhost:2019")
CADDY_BIN = os.environ.get("CADDY_BIN", "/usr/bin/caddy")
CADDYFILE = Path(os.environ.get("CADDYFILE", "/etc/caddy/Caddyfile"))
HELPER_SCRIPT = Path("/etc/s6-overlay/scripts/lib/cert-helpers.sh")
STATE_SCRIPT = Path("/etc/s6-overlay/scripts/lib/state.sh")

# Home Assistant Supervisor's ingress proxy IP. Refuse anything else.
ALLOWED_CLIENT_IPS = {
    s.strip()
    for s in os.environ.get("ALLOWED_INGRESS_IPS", "172.30.32.2,127.0.0.1").split(",")
    if s.strip()
}

# Templates / static
HERE = Path(__file__).parent
templates = Jinja2Templates(directory=str(HERE / "templates"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bash_invoke(snippet: str) -> tuple[int, str, str]:
    """Run a bash snippet that has cert-helpers.sh + state.sh sourced.

    The current process environment (CERT_DIR, CA_*, CLIENT_CERT_PASSWORD,
    OPENSSL_CA_CNF, DOMAIN, ...) is inherited so the helpers see the same
    config as the init oneshot.
    """
    full = (
        "set -e\n"
        f"source {shlex.quote(str(HELPER_SCRIPT))}\n"
        f"source {shlex.quote(str(STATE_SCRIPT))}\n"
        f"{snippet}\n"
    )
    LOG.debug("bash: %s", snippet)
    proc = subprocess.run(
        ["bash", "-c", full],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        LOG.warning(
            "bash failed (rc=%d): stdout=%s stderr=%s",
            proc.returncode,
            proc.stdout.strip(),
            proc.stderr.strip(),
        )
    return proc.returncode, proc.stdout, proc.stderr


def _read_state() -> dict[str, Any]:
    if not STATE_FILE.exists():
        return {"version": 1, "ca": None, "server": None, "clients": []}
    try:
        return json.loads(STATE_FILE.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        LOG.error("Failed to read state: %s", exc)
        return {"version": 1, "ca": None, "server": None, "clients": []}


def _caddy_reload() -> tuple[bool, str]:
    """Reload Caddy via the admin API.

    Uses the `caddy` CLI which knows how to convert the Caddyfile to JSON
    and POST it to /load on the admin endpoint.

    ``--force`` is required: client changes never change the Caddyfile (the
    leaf verifier only names the ``active/`` folder, whose files Caddy reads
    when the config is loaded), and Caddy skips an unchanged config ("config
    is unchanged") - without it, added clients were refused and revoked ones
    still accepted until the add-on restarted.
    """
    if not CADDYFILE.exists():
        return False, f"Caddyfile not found at {CADDYFILE}"
    proc = subprocess.run(
        [
            CADDY_BIN,
            "reload",
            "--force",
            "--config",
            str(CADDYFILE),
            "--adapter",
            "caddyfile",
            "--address",
            CADDY_ADMIN,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return False, proc.stderr or proc.stdout or "caddy reload failed"
    return True, "reloaded"


def _validate_client_name(name: str) -> str:
    """Validate and normalise a client name.

    Allowed characters keep the cert filename safe and predictable.
    """
    err = _client_name_error(name)
    if err:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, err)
    return (name or "").strip()


#: Client names: 1-64 characters - letters, digits, ".", "_", "-" - not
#: starting with a dot. That rules out "." and ".." (browsers drop such path
#: segments, so the client's revoke / regenerate / download URLs would never
#: reach it) and hidden files. The same rule as the client_names option's
#: schema (config.yaml) and init-caddy (client_name_valid in cert-helpers.sh).
CLIENT_NAME_RE = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}")


def _client_name_error(name: str) -> str | None:
    """Return a human-readable error if the name is invalid, else None."""
    name = (name or "").strip()
    if not name:
        return "Client name is required."
    if len(name) > 64:
        return "Client name is too long (max 64 characters)."
    if CLIENT_NAME_RE.fullmatch(name):
        return None
    if name.startswith("."):
        return "Client name must not start with a dot."
    return (
        "Client name may only contain letters, digits, dash, underscore "
        "and dot."
    )


def _find_client(state: dict[str, Any], name: str) -> dict[str, Any] | None:
    """The state.json entry of a client, or None."""
    return next(
        (
            c
            for c in state.get("clients", [])
            if isinstance(c, dict) and c.get("name") == name
        ),
        None,
    )


class FlashError(Exception):
    """User-facing error that should be shown as a banner on the dashboard.

    Mutation handlers raise this instead of HTTPException so the user sees
    a styled message in the iframe rather than a raw JSON payload. The
    matching exception handler converts it to a 303 redirect back to ``/``
    with the message in the query string.
    """

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

# No /docs, /redoc or /openapi.json: the panel is not an API for others.
app = FastAPI(
    title="Caddy mTLS - Cert Manager",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.exception_handler(FlashError)
async def _flash_error_handler(request: Request, exc: FlashError) -> RedirectResponse:
    """Convert a FlashError into a 303 redirect to the dashboard with a banner."""
    return _redirect_home(request, error=exc.message)



class IngressOnlyMiddleware(BaseHTTPMiddleware):
    """Reject any request not coming from the Supervisor ingress proxy.

    Also collapses repeated leading slashes in the request path. Home
    Assistant's ingress proxy can forward requests with a doubled slash
    (e.g. ``GET //`` for the iframe root) which would otherwise miss our
    routes and return 404.
    """

    async def dispatch(self, request: Request, call_next):
        # /_health is allowed from anywhere so the s6 healthcheck works.
        if request.url.path == "/_health":
            return await call_next(request)
        client_host = request.client.host if request.client else ""
        if client_host not in ALLOWED_CLIENT_IPS:
            LOG.warning("Rejecting request from %s for %s", client_host, request.url.path)
            return PlainTextResponse(
                "Forbidden: cert manager is only reachable via Home Assistant ingress.",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        # Collapse runs of leading slashes (//foo -> /foo, // -> /)
        path = request.scope.get("path", "")
        if path.startswith("//"):
            new_path = "/" + path.lstrip("/")
            request.scope["path"] = new_path
            request.scope["raw_path"] = new_path.encode("ascii")
        return await call_next(request)


app.add_middleware(IngressOnlyMiddleware)

if (HERE / "static").is_dir():
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")


# ---------------------------------------------------------------------------
# Routes - read-only
# ---------------------------------------------------------------------------

@app.get("/_health", response_class=PlainTextResponse)
async def health() -> str:
    return "ok"


def _public_cert_context() -> dict[str, Any]:
    """Template variables of the "Public certificate" card."""
    status = public_cert.current_status(probe=True)
    return {
        "pc": status,
        "pc_checklist": public_cert.checklist(status),
        "pc_retry_hint": public_cert.retry_hint(status),
        "pc_time": public_cert.local_time,
    }


# Sync (def) routes run in the thread pool: they read files and call openssl.
@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> Any:
    state = _read_state()
    ca_crt_exists = (CERT_DIR / "mTLS-CA.crt").exists()
    crl_exists = (CERT_DIR / "mTLS-CA.crl").exists()
    flash_error = request.query_params.get("error") or None
    flash_ok = request.query_params.get("ok") or None
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "state": state,
            "ca_crt_exists": ca_crt_exists,
            "crl_exists": crl_exists,
            "flash_error": flash_error,
            "flash_ok": flash_ok,
            **_public_cert_context(),
        },
    )


@app.get("/public-cert", response_class=HTMLResponse)
def public_cert_card(request: Request) -> Any:
    """The "Public certificate" card alone (the dashboard reloads it every
    30 s)."""
    return templates.TemplateResponse(request, "_public_cert.html", _public_cert_context())


@app.get("/api/public-cert")
def api_public_cert() -> dict[str, Any]:
    status = public_cert.current_status(probe=True)
    cert = status.certificate
    err = status.last_error
    return {
        "state": status.state,
        "domain": status.domain,
        "certificate": None if cert is None else {
            "issuer": cert.issuer,
            "subject_cn": cert.subject_cn,
            "not_after": cert.not_after.isoformat(),
            "days_left": cert.days_left(status.now),
            "fingerprint_sha256": cert.fingerprint_sha256,
            "served": status.served,
        },
        "last_error": None if err is None else {
            "ts": err.ts, "logger": err.logger, "text": err.text,
        },
        "challenges": [
            {"type": c.challenge_type, "ts": c.ts, "text": c.text} for c in status.challenges
        ],
        "next_attempt": status.next_attempt,
        "http_host_port": status.runtime.http_host_port if status.runtime else None,
        "https_host_port": status.runtime.https_host_port if status.runtime else None,
        "checklist": public_cert.checklist(status),
    }


@app.get("/api/state")
async def api_state() -> dict[str, Any]:
    return _read_state()


@app.get("/download/ca")
async def download_ca():
    p = CERT_DIR / "mTLS-CA.crt"
    if not p.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "CA certificate not found")
    return FileResponse(str(p), media_type="application/x-pem-file", filename="mTLS-CA.crt")


@app.get("/download/crl")
async def download_crl():
    p = CERT_DIR / "mTLS-CA.crl"
    if not p.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "CRL not found")
    return FileResponse(str(p), media_type="application/pkix-crl", filename="mTLS-CA.crl")


@app.get("/download/client/{name}")
async def download_client(name: str):
    name = _validate_client_name(name)
    p = CERT_DIR / f"mTLS-client-{name}.p12"
    if not p.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "client bundle not found")
    return FileResponse(
        str(p),
        media_type="application/x-pkcs12",
        filename=f"mTLS-client-{name}.p12",
    )


# ---------------------------------------------------------------------------
# Routes - mutations
# ---------------------------------------------------------------------------

def _redirect_home(
    request: Request,
    *,
    error: str | None = None,
    ok: str | None = None,
) -> RedirectResponse:
    """Redirect back to the dashboard, staying inside the ingress iframe.

    Home Assistant's Supervisor proxies ingress traffic and adds the
    ``X-Ingress-Path`` header (e.g. ``/api/hassio_ingress/<token>``).
    A bare ``Location: /`` would resolve at the parent origin and break
    the iframe out to the HA root, so we prepend the ingress prefix when
    present.

    An ``error`` or ``ok`` flash message is forwarded as a query string
    parameter and rendered as a banner on the dashboard.
    """
    ingress_prefix = request.headers.get("X-Ingress-Path", "").rstrip("/")
    qs = ""
    params: dict[str, str] = {}
    if error:
        params["error"] = error
    if ok:
        params["ok"] = ok
    if params:
        qs = "?" + urlencode(params)
    return RedirectResponse(
        url=f"{ingress_prefix}/{qs}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.post("/api/clients")
async def add_client(request: Request, name: str = Form(...)):
    err = _client_name_error(name)
    if err:
        raise FlashError(err)
    name = name.strip()

    existing = _find_client(_read_state(), name)
    if existing is not None:
        if existing.get("status") == "revoked":
            raise FlashError(
                f"A client named '{name}' already exists and is revoked. "
                "Choose a different name to create a new client."
            )
        raise FlashError(
            f"A client named '{name}' already exists. "
            "Use Regenerate to rotate it, or choose a different name."
        )
    if (CERT_DIR / f"mTLS-client-{name}.p12").exists():
        # Defensive: state and disk are out of sync.
        raise FlashError(
            f"A certificate file for '{name}' already exists on disk. "
            "Choose a different name."
        )

    rc, _, err_out = _bash_invoke(
        f"generate_client_cert {shlex.quote(name)}\n"
        f"state_refresh_client {shlex.quote(name)}\n"
        "state_sync_active_dir\n"
        f"generate_crl\n"
        f"state_refresh_crl\n"
    )
    if rc != 0:
        LOG.error("add_client('%s') failed: %s", name, err_out.strip())
        raise FlashError(
            f"Failed to create client '{name}'. See add-on logs for details."
        )

    ok_reload, msg = _caddy_reload()
    if not ok_reload:
        LOG.error("caddy reload after add_client failed: %s", msg)
        raise FlashError(
            f"Client '{name}' was created, but reloading Caddy failed. "
            "Check the add-on logs."
        )
    return _redirect_home(request, ok=f"Client '{name}' created.")


@app.post("/api/clients/{name}/revoke")
async def revoke_client(request: Request, name: str, reason: str = Form("unspecified")):
    err = _client_name_error(name)
    if err:
        raise FlashError(err)
    name = name.strip()
    existing = _find_client(_read_state(), name)
    if existing is None and not (CERT_DIR / f"mTLS-client-{name}.crt").exists():
        raise FlashError(f"Client '{name}' was not found.")
    if existing is not None and existing.get("status") == "revoked":
        raise FlashError(f"Client '{name}' is already revoked.")
    # The helper revokes the client's own certificate file; the serial is
    # only needed when that file is missing (fallback: the CA database's
    # copy in ca-db/newcerts).
    serial = str((existing or {}).get("serial") or "")

    rc, _, err_out = _bash_invoke(
        f"revoke_client_by_name {shlex.quote(name)} {shlex.quote(reason)} {shlex.quote(serial)}\n"
        f"state_mark_revoked {shlex.quote(name)} {shlex.quote(reason)}\n"
        f"generate_crl\n"
        f"state_refresh_crl\n"
    )
    if rc != 0:
        LOG.error("revoke_client('%s') failed: %s", name, err_out.strip())
        raise FlashError(
            f"Failed to revoke client '{name}'. See add-on logs for details."
        )

    ok_reload, msg = _caddy_reload()
    if not ok_reload:
        LOG.error("caddy reload after revoke_client failed: %s", msg)
        raise FlashError(
            f"Client '{name}' was revoked, but reloading Caddy failed. "
            "Check the add-on logs."
        )
    return _redirect_home(request, ok=f"Client '{name}' revoked.")


@app.post("/api/clients/{name}/regenerate")
async def regenerate_client(request: Request, name: str):
    """Revoke the existing cert (if active) and issue a new one under the same name."""
    err = _client_name_error(name)
    if err:
        raise FlashError(err)
    name = name.strip()
    crt = CERT_DIR / f"mTLS-client-{name}.crt"
    p12 = CERT_DIR / f"mTLS-client-{name}.p12"

    existing = _find_client(_read_state(), name)
    if existing is None or existing.get("status") != "active":
        raise FlashError(
            f"Cannot regenerate '{name}': no active client with this name."
        )
    serial = str(existing.get("serial") or "")

    # Revoke the old serial in the CA db / CRL but keep the client's state
    # entry "active" - the user is rotating, not removing. (The helper revokes
    # the certificate file, or the CA database's copy of the serial if the
    # file is missing.)
    snippet = (
        f"revoke_client_by_name {shlex.quote(name)} superseded {shlex.quote(serial)}\n"
    )
    # Remove the previous on-disk artefacts so generate_client_cert will issue fresh.
    snippet += (
        f"rm -f {shlex.quote(str(crt))} {shlex.quote(str(p12))} {shlex.quote(str(CERT_DIR / f'mTLS-client-{name}.key'))}\n"
        f"generate_client_cert {shlex.quote(name)}\n"
        f"state_refresh_client {shlex.quote(name)}\n"
        "state_sync_active_dir\n"
        f"generate_crl\n"
        f"state_refresh_crl\n"
    )
    rc, _, err_out = _bash_invoke(snippet)
    if rc != 0:
        LOG.error("regenerate_client('%s') failed: %s", name, err_out.strip())
        raise FlashError(
            f"Failed to regenerate client '{name}'. See add-on logs for details."
        )

    ok_reload, msg = _caddy_reload()
    if not ok_reload:
        LOG.error("caddy reload after regenerate_client failed: %s", msg)
        raise FlashError(
            f"Client '{name}' was regenerated, but reloading Caddy failed. "
            "Check the add-on logs."
        )
    return _redirect_home(request, ok=f"Client '{name}' regenerated.")


@app.post("/api/ca/regenerate")
async def regenerate_ca(request: Request, confirm: str = Form(...)):
    """Wipe everything and regenerate the CA + the active clients.

    Guarded by the user typing the literal string `REGENERATE-CA`.

    Only clients with status ``active`` get new certificates. Revoked clients
    stay in state.json as history (status, serial and reason of the old CA;
    their files are wiped with the rest) - they are never re-issued, and
    their names stay taken.
    """
    if confirm != "REGENERATE-CA":
        raise FlashError(
            "CA regeneration was not confirmed. Type REGENERATE-CA exactly to proceed."
        )
    domain = os.environ.get("DOMAIN", "")
    if not domain:
        LOG.error("regenerate_ca: DOMAIN env var not set")
        raise FlashError(
            "Cannot regenerate CA: the DOMAIN configuration option is not set."
        )

    clients = [
        c
        for c in _read_state().get("clients", [])
        if isinstance(c, dict) and isinstance(c.get("name"), str) and c["name"]
    ]
    reissue: list[str] = []
    previous: list[dict[str, Any]] = []
    for c in clients:
        if c.get("status") != "active":
            previous.append(c)  # history: kept as it is
        elif _client_name_error(c["name"]) is None and c["name"] not in reissue:
            reissue.append(c["name"])
            previous.append(c)
        else:
            LOG.warning(
                "regenerate_ca: not re-issuing client %r (invalid or duplicate name)",
                c["name"],
            )

    # The previous client list goes to the shell helper as a file: no size
    # limit of a command-line argument applies.
    with tempfile.NamedTemporaryFile(
        "w", prefix="cert-mgr-clients-", suffix=".json", delete=False
    ) as fh:
        json.dump(previous, fh)
        previous_file = fh.name

    snippet = (
        "wipe_cert_dir\n"
        "state_reset\n"
        "generate_ca\n"
        "state_refresh_ca\n"
    )
    for cname in reissue:
        snippet += f"generate_client_cert {shlex.quote(cname)}\n"
        snippet += f"state_refresh_client {shlex.quote(cname)}\n"
    snippet += (
        f"state_restore_clients {shlex.quote(previous_file)}\n"
        "state_sync_active_dir\n"
        "generate_crl\n"
        "state_refresh_crl\n"
    )
    try:
        rc, _, err_out = _bash_invoke(snippet)
    finally:
        os.unlink(previous_file)
    if rc != 0:
        LOG.error("regenerate_ca failed: %s", err_out.strip())
        raise FlashError(
            "Failed to regenerate the CA. See add-on logs for details."
        )

    ok_reload, msg = _caddy_reload()
    if not ok_reload:
        LOG.error("caddy reload after regenerate_ca failed: %s", msg)
        raise FlashError(
            "CA was regenerated, but reloading Caddy failed. Check the add-on logs."
        )
    return _redirect_home(request, ok="CA regenerated.")

