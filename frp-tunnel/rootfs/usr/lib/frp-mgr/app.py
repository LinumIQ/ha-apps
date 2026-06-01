"""
FRP Tunnel - device pairing management web UI.

Runs on the Home Assistant ingress port (8099), only reachable via the
Supervisor's ingress proxy at 172.30.32.2. Provides a browser-based
device-authorization pairing flow so users never touch tokens or
subdomains in the add-on configuration.

Pairing flow:
  1. User clicks "Start pairing" → POST /api/device/code at APP_BASE.
  2. Panel shows the user_code + a link to verification_uri_complete.
  3. User opens the link in a browser, signs in, approves the device.
  4. Panel polls /api/device/token until approved.
  5. On success: panel fetches tunnel details, writes /data/frpc.toml,
     and triggers frpc to start.

All state lives in /data/frp-state.json (device_token + tunnel info)
and /data/frpc.toml (generated frpc config). Tokens are NEVER logged.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urljoin
from urllib.request import Request as URLRequest
from urllib.request import urlopen
from urllib.error import HTTPError, URLError

from fastapi import FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LOG = logging.getLogger("frp-mgr")
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

APP_BASE = os.environ.get("APP_BASE", "https://app.linumiq.net").rstrip("/")
API_BASE = os.environ.get("API_BASE", "https://api.linumiq.net").rstrip("/")
SERVER_ADDR = os.environ.get("SERVER_ADDR", "linumiq.net")
SERVER_PORT = int(os.environ.get("SERVER_PORT", "7000"))
LOCAL_HOST = os.environ.get("LOCAL_HOST", "homeassistant")
LOCAL_PORT = int(os.environ.get("LOCAL_PORT", "8123"))

CONFIG_FILE = Path("/data/frpc.toml")
STATE_FILE = Path("/data/frp-state.json")
PAIRING_FILE = Path("/data/frp-pairing.json")

# Home Assistant Supervisor's ingress proxy IP. Refuse anything else.
ALLOWED_CLIENT_IPS = {
    s.strip()
    for s in os.environ.get("ALLOWED_INGRESS_IPS", "172.30.32.2,127.0.0.1").split(",")
    if s.strip()
}

# Reserved subdomains that the API also rejects, but we catch early for UX.
RESERVED_SUBDOMAINS = frozenset(
    {"app", "api", "www", "admin", "auth", "mail", "static"}
)

# Templates / static
HERE = Path(__file__).parent
templates = Jinja2Templates(directory=str(HERE / "templates"))


# ---------------------------------------------------------------------------
# Helpers — HTTP (stdlib urllib, no extra deps)
# ---------------------------------------------------------------------------

def _http_json(
    method: str,
    url: str,
    body: dict[str, Any] | None = None,
    bearer: str | None = None,
    timeout: int = 15,
) -> tuple[int, Any]:
    """Make a JSON request. Returns (status_code, parsed_json_body or text)."""
    data = None
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    try:
        req = URLRequest(url, data=data, headers=headers, method=method)
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except HTTPError as exc:
        try:
            err_raw = exc.read().decode("utf-8")
            err_json = json.loads(err_raw)
        except Exception:
            err_json = exc.reason or "unknown error"
        return exc.code, err_json
    except URLError as exc:
        LOG.error("HTTP %s %s failed: %s", method, url, exc)
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            f"Cannot reach backend: {exc.reason}",
        )
    except Exception as exc:
        LOG.error("HTTP %s %s unexpected: %s", method, url, exc)
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            f"Backend request failed: {exc}",
        )


# ---------------------------------------------------------------------------
# Helpers — state
# ---------------------------------------------------------------------------

def _read_state() -> dict[str, Any]:
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        LOG.error("Failed to read state: %s", exc)
        return {}


def _write_state(data: dict[str, Any]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(data))
    STATE_FILE.chmod(0o600)


def _read_pairing() -> dict[str, Any]:
    if not PAIRING_FILE.exists():
        return {}
    try:
        return json.loads(PAIRING_FILE.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        LOG.error("Failed to read pairing: %s", exc)
        return {}


def _write_pairing(data: dict[str, Any]) -> None:
    PAIRING_FILE.parent.mkdir(parents=True, exist_ok=True)
    PAIRING_FILE.write_text(json.dumps(data))
    PAIRING_FILE.chmod(0o600)


def _clear_pairing() -> None:
    try:
        PAIRING_FILE.unlink(missing_ok=True)
    except OSError:
        pass


def _is_paired() -> bool:
    state = _read_state()
    return bool(state.get("device_token")) and CONFIG_FILE.exists()


def _write_frpc_toml(subdomain: str, token: str) -> None:
    """Write the frpc configuration TOML file."""
    toml = (
        f"# Auto-generated by frp-mgr pairing panel. Do not edit by hand.\n"
        f"serverAddr = \"{SERVER_ADDR}\"\n"
        f"serverPort = {SERVER_PORT}\n"
        f"loginFailExit = false\n"
        f"\n"
        f"[metadatas]\n"
        f"token = \"{token}\"\n"
        f"\n"
        f"[log]\n"
        f"to = \"console\"\n"
        f"level = \"info\"\n"
        f"\n"
        f"[[proxies]]\n"
        f"name = \"{subdomain}\"\n"
        f"type = \"http\"\n"
        f"customDomains = [\"{subdomain}.{SERVER_ADDR}\"]\n"
        f"localIP = \"{LOCAL_HOST}\"\n"
        f"localPort = {LOCAL_PORT}\n"
    )
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(toml)
    CONFIG_FILE.chmod(0o600)


def _restart_frpc() -> None:
    """Tell s6 to restart the frpc service so it picks up the new config."""
    try:
        subprocess.run(
            ["s6-svc", "-r", "/run/service/frpc"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        LOG.info("frpc restart triggered via s6-svc -r")
    except Exception as exc:
        LOG.warning("s6-svc -r frpc failed (non-fatal): %s", exc)


def _frpc_status() -> str:
    """Best-effort check whether frpc is running."""
    if not CONFIG_FILE.exists():
        return "stopped"
    try:
        proc = subprocess.run(
            ["s6-svstat", "/run/service/frpc"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        output = proc.stdout.lower()
        if "up" in output:
            return "running"
        return "stopped"
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Helpers — validation
# ---------------------------------------------------------------------------

_SUBDOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$")


def _validate_subdomain(subdomain: str) -> str:
    """Normalise and validate a subdomain. Raises FlashError on problem."""
    subdomain = (subdomain or "").strip().lower()
    if not subdomain:
        raise FlashError("Subdomain is required.")
    if not _SUBDOMAIN_RE.match(subdomain):
        raise FlashError(
            "Subdomain must be 3-32 characters: lowercase a-z, 0-9 "
            "and '-', not starting or ending with '-'."
        )
    if subdomain in RESERVED_SUBDOMAINS:
        raise FlashError(
            f"'{subdomain}' is reserved and cannot be used."
        )
    return subdomain


# ---------------------------------------------------------------------------
# FlashError — user-facing error shown as a banner redirect
# ---------------------------------------------------------------------------

class FlashError(Exception):
    """User-facing error rendered as a banner on the dashboard."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

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
            LOG.warning(
                "Rejecting request from %s for %s",
                client_host,
                request.url.path,
            )
            return PlainTextResponse(
                "Forbidden: frp-mgr is only reachable via Home Assistant "
                "ingress.",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        # Collapse runs of leading slashes (//foo -> /foo, // -> /)
        path = request.scope.get("path", "")
        if path.startswith("//"):
            new_path = "/" + path.lstrip("/")
            request.scope["path"] = new_path
            request.scope["raw_path"] = new_path.encode("ascii")
        return await call_next(request)


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = FastAPI(title="FRP Tunnel - Pairing Panel", docs_url=None, redoc_url=None)
app.add_middleware(IngressOnlyMiddleware)

if (HERE / "static").is_dir():
    app.mount(
        "/static",
        StaticFiles(directory=str(HERE / "static")),
        name="static",
    )


@app.exception_handler(FlashError)
async def _flash_error_handler(
    request: Request, exc: FlashError
) -> RedirectResponse:
    """Convert a FlashError into a 303 redirect with a banner."""
    return _redirect_home(request, error=exc.message)


def _redirect_home(
    request: Request,
    *,
    error: str | None = None,
    ok: str | None = None,
) -> RedirectResponse:
    """Redirect back to the dashboard, staying inside the ingress iframe."""
    ingress_prefix = request.headers.get("X-Ingress-Path", "").rstrip("/")
    params: dict[str, str] = {}
    if error:
        params["error"] = error
    if ok:
        params["ok"] = ok
    qs = "?" + urlencode(params) if params else ""
    return RedirectResponse(
        url=f"{ingress_prefix}/{qs}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


# ---------------------------------------------------------------------------
# Routes — read-only
# ---------------------------------------------------------------------------

@app.get("/_health", response_class=PlainTextResponse)
async def health() -> str:
    return "ok"


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> Any:
    paired = _is_paired()
    state = _read_state()
    pairing = _read_pairing()
    frpc_stat = _frpc_status() if paired else "stopped"

    subdomain = state.get("subdomain", "")
    public_url = f"https://{subdomain}.{SERVER_ADDR}" if subdomain else ""

    flash_error = request.query_params.get("error") or None
    flash_ok = request.query_params.get("ok") or None

    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "paired": paired,
            "subdomain": subdomain,
            "public_url": public_url,
            "frpc_status": frpc_stat,
            "local_host": LOCAL_HOST,
            "local_port": LOCAL_PORT,
            "pairing_active": bool(pairing.get("device_code")),
            "user_code": pairing.get("user_code", ""),
            "verification_uri_complete": pairing.get(
                "verification_uri_complete", ""
            ),
            "interval": pairing.get("interval", 5),
            "flash_error": flash_error,
            "flash_ok": flash_ok,
        },
    )


# ---------------------------------------------------------------------------
# Routes — pairing flow
# ---------------------------------------------------------------------------

@app.post("/pair/start")
async def pair_start(request: Request):
    """Initiate device authorization: call /api/device/code, show user_code."""
    if _is_paired():
        raise FlashError("Already paired. Unpair first to re-pair.")

    status_code, body = _http_json("POST", f"{APP_BASE}/api/device/code", {})

    if status_code != 200:
        msg = body.get("error", str(body)) if isinstance(body, dict) else str(body)
        LOG.error("Device code request failed: %s", msg)
        raise FlashError(f"Failed to start pairing: {msg}")

    device_code = body.get("device_code")
    user_code = body.get("user_code")
    verification_uri_complete = body.get("verification_uri_complete")
    interval = body.get("interval", 5)

    if not device_code or not user_code:
        raise FlashError("Backend returned an incomplete pairing response.")

    _write_pairing(
        {
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri_complete": verification_uri_complete,
            "interval": interval,
            "expires_at": body.get("expires_in", 600),
        }
    )

    # Redirect to the index which will now show the pairing UI
    return _redirect_home(
        request, ok=f"Pairing code ready: {user_code}"
    )


@app.post("/pair/poll")
async def pair_poll(request: Request) -> dict[str, Any]:
    """Poll the token endpoint. Called via fetch() from the pairing page.

    Returns JSON so the client-side JS can decide next steps.
    """
    pairing = _read_pairing()
    device_code = pairing.get("device_code")
    if not device_code:
        return {"status": "error", "error": "No pairing in progress."}

    # 1. Exchange device_code for device_token
    status_code, body = _http_json(
        "POST",
        f"{APP_BASE}/api/device/token",
        {"device_code": device_code},
    )

    if status_code == 200:
        device_token = body.get("device_token")
        if not device_token:
            return {"status": "error", "error": "No device_token in response."}

        # 2. Fetch tunnel details
        t_status, t_body = _http_json(
            "GET",
            f"{APP_BASE}/api/device/tunnel",
            bearer=device_token,
        )

        if t_status == 200:
            subdomain = t_body.get("subdomain", "")
            token = t_body.get("token", "")
            s_addr = t_body.get("server_addr", SERVER_ADDR)
            s_port = t_body.get("server_port", SERVER_PORT)

            if not subdomain or not token:
                return {
                    "status": "error",
                    "error": "Backend returned incomplete tunnel info.",
                }

            # Persist state
            _write_state(
                {
                    "device_token": device_token,
                    "subdomain": subdomain,
                    "server_addr": s_addr,
                    "server_port": s_port,
                }
            )

            # Write frpc.toml
            _write_frpc_toml(subdomain, token)

            # Clear pairing state
            _clear_pairing()

            # Restart frpc
            _restart_frpc()

            LOG.info(
                "Pairing complete: subdomain=%s device_token=<redacted>",
                subdomain,
            )
            return {"status": "paired", "subdomain": subdomain}

        elif t_status == 404:
            # Device has a token but no tunnel yet — create one
            # (shouldn't normally happen, but handle gracefully)
            LOG.info(
                "Device token obtained but no tunnel found; creating default."
            )
            # Use a generated default subdomain — but we need the user
            # to pick one. For now, return status so frontend redirects
            # to the change-subdomain flow.
            _write_state({"device_token": device_token})
            _clear_pairing()
            return {
                "status": "no_tunnel",
                "error": "Device approved but no tunnel found. Set a subdomain.",
            }

        else:
            msg = (
                t_body.get("error", str(t_body))
                if isinstance(t_body, dict)
                else str(t_body)
            )
            LOG.warning("Tunnel fetch failed: %s", msg)
            return {
                "status": "error",
                "error": f"Tunnel fetch failed: {msg}",
            }

    elif status_code == 400:
        err = body.get("error", "") if isinstance(body, dict) else str(body)
        if err == "authorization_pending":
            return {"status": "pending"}
        elif err == "slow_down":
            return {"status": "slow_down"}
        elif err in ("expired_token", "invalid_grant"):
            _clear_pairing()
            return {
                "status": "expired",
                "error": "Pairing session expired. Please start again.",
            }
        else:
            _clear_pairing()
            return {"status": "error", "error": err or "Unknown error."}

    elif status_code == 429:
        return {"status": "slow_down"}

    else:
        err = body.get("error", str(body)) if isinstance(body, dict) else str(body)
        LOG.error("Token exchange unexpected status %d: %s", status_code, err)
        return {"status": "error", "error": f"Backend error: {err}"}


# ---------------------------------------------------------------------------
# Routes — subdomain management
# ---------------------------------------------------------------------------

@app.post("/subdomain/change")
async def subdomain_change(
    request: Request, subdomain: str = Form(...)
):
    """Change the tunnel subdomain."""
    state = _read_state()
    device_token = state.get("device_token")
    if not device_token:
        raise FlashError("Not paired. Start pairing first.")

    subdomain = _validate_subdomain(subdomain)

    status_code, body = _http_json(
        "POST",
        f"{APP_BASE}/api/device/tunnel",
        {"subdomain": subdomain},
        bearer=device_token,
    )

    if status_code == 200:
        new_subdomain = body.get("subdomain", subdomain)
        new_token = body.get("token", "")
        s_addr = body.get("server_addr", SERVER_ADDR)
        s_port = body.get("server_port", SERVER_PORT)

        if not new_token:
            raise FlashError("Backend did not return a new tunnel token.")

        state["subdomain"] = new_subdomain
        state["server_addr"] = s_addr
        state["server_port"] = s_port
        _write_state(state)
        _write_frpc_toml(new_subdomain, new_token)
        _restart_frpc()

        LOG.info("Subdomain changed to %s", new_subdomain)
        return _redirect_home(
            request,
            ok=f"Subdomain changed to {new_subdomain}.{SERVER_ADDR}",
        )

    elif status_code == 409:
        raise FlashError(
            f"Subdomain '{subdomain}' is already taken. Please choose another."
        )
    elif status_code == 400:
        msg = body.get("error", "Invalid subdomain") if isinstance(body, dict) else str(body)
        raise FlashError(f"Backend rejected subdomain: {msg}")
    else:
        msg = body.get("error", str(body)) if isinstance(body, dict) else str(body)
        LOG.error("Subdomain change failed (%d): %s", status_code, msg)
        raise FlashError(f"Failed to change subdomain: {msg}")


# ---------------------------------------------------------------------------
# Routes — unpair
# ---------------------------------------------------------------------------

@app.post("/unpair")
async def unpair(request: Request):
    """Revoke device token and remove all pairing state."""
    state = _read_state()
    device_token = state.get("device_token")

    if device_token:
        # Best-effort: tell the backend to revoke the device.
        try:
            _http_json(
                "DELETE",
                f"{APP_BASE}/api/device/tunnel",
                bearer=device_token,
            )
        except Exception as exc:
            LOG.warning("Backend unpair call failed (non-fatal): %s", exc)

    # Remove local state
    for f in (STATE_FILE, CONFIG_FILE, PAIRING_FILE):
        try:
            f.unlink(missing_ok=True)
        except OSError as exc:
            LOG.warning("Failed to remove %s: %s", f, exc)

    # Restart frpc — without toml it will go back to wait-loop.
    _restart_frpc()

    LOG.info("Device unpaired.")
    return _redirect_home(request, ok="Device unpaired. Tunnel stopped.")
