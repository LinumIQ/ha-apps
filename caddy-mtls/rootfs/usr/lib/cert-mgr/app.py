"""
Caddy mTLS Proxy - certificate management web UI.

Runs on the Home Assistant ingress port (8099), only reachable via the
Supervisor's ingress proxy at 172.30.32.2. Provides a dashboard to view
certificate metadata, download client bundles, regenerate or revoke
individual client certs, regenerate the server cert, and (with a typed
confirmation) regenerate the entire CA.

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
import shlex
import subprocess
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
    """
    if not CADDYFILE.exists():
        return False, f"Caddyfile not found at {CADDYFILE}"
    proc = subprocess.run(
        [
            CADDY_BIN,
            "reload",
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


def _client_name_error(name: str) -> str | None:
    """Return a human-readable error if the name is invalid, else None."""
    name = (name or "").strip()
    if not name:
        return "Client name is required."
    if len(name) > 64:
        return "Client name is too long (max 64 characters)."
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
    if not set(name).issubset(allowed):
        return (
            "Client name may only contain letters, digits, dash, underscore "
            "and dot."
        )
    return None


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

app = FastAPI(title="Caddy mTLS - Cert Manager", docs_url=None, redoc_url=None)


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


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> Any:
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
        },
    )


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

    state = _read_state()
    existing = next(
        (c for c in state.get("clients", []) if c.get("name") == name),
        None,
    )
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
        f"populate_active_dir $(state_active_clients | tr '\\n' ' ')\n"
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
    if not (CERT_DIR / f"mTLS-client-{name}.crt").exists():
        raise FlashError(f"Client '{name}' was not found.")

    rc, _, err_out = _bash_invoke(
        f"revoke_client_by_name {shlex.quote(name)} {shlex.quote(reason)}\n"
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

    state = _read_state()
    existing = next(
        (c for c in state.get("clients", []) if c.get("name") == name),
        None,
    )
    if existing is None or existing.get("status") != "active":
        raise FlashError(
            f"Cannot regenerate '{name}': no active client with this name."
        )

    snippet = ""
    if crt.exists():
        # Revoke the old serial in the CA db / CRL but keep the client's
        # state entry "active" - the user is rotating, not removing.
        snippet += f"revoke_client_by_name {shlex.quote(name)} superseded\n"
    # Remove the previous on-disk artefacts so generate_client_cert will issue fresh.
    snippet += (
        f"rm -f {shlex.quote(str(crt))} {shlex.quote(str(p12))} {shlex.quote(str(CERT_DIR / f'mTLS-client-{name}.key'))}\n"
        f"generate_client_cert {shlex.quote(name)}\n"
        f"state_refresh_client {shlex.quote(name)}\n"
        f"populate_active_dir $(state_active_clients | tr '\\n' ' ')\n"
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
    """Wipe everything and regenerate CA + the previously known clients.

    Guarded by the user typing the literal string `REGENERATE-CA`.
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

    state = _read_state()
    client_names = [c["name"] for c in state.get("clients", []) if c.get("name")]

    snippet = (
        "wipe_cert_dir\n"
        "state_reset\n"
        "generate_ca\n"
        "state_refresh_ca\n"
    )
    for cname in client_names:
        snippet += f"generate_client_cert {shlex.quote(cname)}\n"
        snippet += f"state_refresh_client {shlex.quote(cname)}\n"
    snippet += (
        "populate_active_dir $(state_active_clients | tr '\\n' ' ')\n"
        "generate_crl\n"
        "state_refresh_crl\n"
    )
    rc, _, err_out = _bash_invoke(snippet)
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

