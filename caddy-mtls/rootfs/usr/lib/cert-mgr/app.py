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
    name = (name or "").strip()
    if not name:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "client name is required")
    if len(name) > 64:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "client name too long")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
    if not set(name).issubset(allowed):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "client name may only contain letters, digits, dash, underscore and dot",
        )
    return name


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = FastAPI(title="Caddy mTLS - Cert Manager", docs_url=None, redoc_url=None)


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
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "state": state,
            "ca_crt_exists": ca_crt_exists,
            "crl_exists": crl_exists,
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

def _redirect_home() -> RedirectResponse:
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/api/clients")
async def add_client(name: str = Form(...)):
    name = _validate_client_name(name)
    if (CERT_DIR / f"mTLS-client-{name}.p12").exists():
        raise HTTPException(status.HTTP_409_CONFLICT, f"client '{name}' already exists")

    rc, _, err = _bash_invoke(
        f"generate_client_cert {shlex.quote(name)}\n"
        f"state_refresh_client {shlex.quote(name)}\n"
        f"populate_active_dir $(state_active_clients | tr '\\n' ' ')\n"
        f"generate_crl\n"
        f"state_refresh_crl\n"
    )
    if rc != 0:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, f"add_client failed: {err}")

    ok, msg = _caddy_reload()
    if not ok:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, f"caddy reload failed: {msg}")
    return _redirect_home()


@app.post("/api/clients/{name}/revoke")
async def revoke_client(name: str, reason: str = Form("unspecified")):
    name = _validate_client_name(name)
    if not (CERT_DIR / f"mTLS-client-{name}.crt").exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"client '{name}' not found")

    rc, _, err = _bash_invoke(
        f"revoke_client_by_name {shlex.quote(name)} {shlex.quote(reason)}\n"
        f"state_mark_revoked {shlex.quote(name)} {shlex.quote(reason)}\n"
        f"generate_crl\n"
        f"state_refresh_crl\n"
    )
    if rc != 0:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, f"revoke failed: {err}")

    ok, msg = _caddy_reload()
    if not ok:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, f"caddy reload failed: {msg}")
    return _redirect_home()


@app.post("/api/clients/{name}/regenerate")
async def regenerate_client(name: str):
    """Revoke the existing cert (if active) and issue a new one under the same name."""
    name = _validate_client_name(name)
    crt = CERT_DIR / f"mTLS-client-{name}.crt"
    p12 = CERT_DIR / f"mTLS-client-{name}.p12"

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
    rc, _, err = _bash_invoke(snippet)
    if rc != 0:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, f"regenerate failed: {err}")

    ok, msg = _caddy_reload()
    if not ok:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, f"caddy reload failed: {msg}")
    return _redirect_home()


@app.post("/api/ca/regenerate")
async def regenerate_ca(confirm: str = Form(...)):
    """Wipe everything and regenerate CA + the previously known clients.

    Guarded by the user typing the literal string `REGENERATE-CA`.
    """
    if confirm != "REGENERATE-CA":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "confirmation string must be exactly 'REGENERATE-CA'",
        )
    domain = os.environ.get("DOMAIN", "")
    if not domain:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "DOMAIN env var not set")

    state = _read_state()
    client_names = [c["name"] for c in state.get("clients", []) if c.get("name")]

    snippet = (
        "wipe_cert_dir\n"
        "state_reset\n"
        "generate_ca\n"
        "state_refresh_ca\n"
    )
    for name in client_names:
        snippet += f"generate_client_cert {shlex.quote(name)}\n"
        snippet += f"state_refresh_client {shlex.quote(name)}\n"
    snippet += (
        "populate_active_dir $(state_active_clients | tr '\\n' ' ')\n"
        "generate_crl\n"
        "state_refresh_crl\n"
    )
    rc, _, err = _bash_invoke(snippet)
    if rc != 0:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, f"CA regen failed: {err}")

    ok, msg = _caddy_reload()
    if not ok:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, f"caddy reload failed: {msg}")
    return _redirect_home()
