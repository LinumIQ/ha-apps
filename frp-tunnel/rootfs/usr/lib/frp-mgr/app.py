"""
FRP Tunnel - device pairing management web UI.

Runs on the Home Assistant ingress port (8099), only reachable via the
Supervisor's ingress proxy at 172.30.32.2. Provides a browser-based
device-authorization pairing flow so users never touch tokens or
subdomains in the add-on configuration.

Pairing flow:
  1. User clicks "Start pairing" -> POST /api/device/code at app_base. Every
     value of the response is validated (config.parse_pairing_response)
     before it is stored or rendered: a malformed or foreign link, user code,
     device code or interval rejects the pairing.
  2. Panel shows the user_code + a link to verification_uri_complete.
  3. User opens the link in a browser, signs in, approves the device.
  4. Panel polls /api/device/token until approved and stores the device
     token immediately (it is minted exactly once).
  5. Panel fetches GET /api/device/tunnel ({subdomain, token, server_addr,
     server_port[, domain_base]}), persists it in /data/frp-state.json,
     renders /data/frpc.toml and restarts frpc.

frpc.toml is also re-rendered from the persisted state on every frpc
(re)start (see config.py and the frpc s6 service), so "Refresh tunnel
config" or re-pairing picks up changed server values. Precedence of the
frpc settings: explicitly set add-on option > server-provided value >
built-in default (details in config.py).

Tokens (device token, frp tunnel token) are NEVER logged or returned by
any endpoint of this panel; backend text is sanitised (config.sanitize_text)
before it reaches a log line or a banner, and the panel never follows HTTP
redirects (the device token must only ever go to app_base).
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import os
import subprocess
import threading
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, build_opener
from urllib.request import Request as URLRequest

from fastapi import FastAPI, Form, Request, status
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

import config as cfg

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LOG = logging.getLogger("frp-mgr")
logging.basicConfig(
    level=os.environ.get("FRP_MGR_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

PATHS = cfg.default_paths()

# Options cannot change while the add-on runs (Supervisor restarts the
# add-on on every option change), so they are read once at start-up. Invalid
# options never crash the panel: they are ignored (next precedence layer),
# logged by config.py and shown as a banner until fixed (OPTION_ERRORS).
OPTIONS, OPTION_ERRORS = cfg.load_options_report(PATHS)
_BASE = cfg.effective_settings(OPTIONS, {})
APP_BASE = _BASE.app_base
API_BASE = _BASE.api_base

# Options whose invalid value blocks every backend call: falling back to the
# production app_base would silently pair a dev/test install with production
# (and send its device token there).
BLOCKING_OPTIONS = ("app_base", "options.json")

FRPC_SERVICE = "/run/service/frpc"
USER_AGENT = "linumiq-frp-tunnel-addon"


def _parse_allowed_clients(raw: str) -> list:
    """IPs and/or CIDR networks allowed to reach the panel."""
    nets = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            LOG.error("Ignoring invalid ALLOWED_INGRESS_IPS entry %.60r", item)
    return nets


# Home Assistant Supervisor's ingress proxy IP (+ loopback for the s6
# health check and local tooling). Refuse anything else. The container
# environment is not user-configurable under Supervisor; the variable only
# exists for running the image outside Supervisor (E2E tests).
ALLOWED_CLIENT_NETS = _parse_allowed_clients(
    os.environ.get("ALLOWED_INGRESS_IPS", "172.30.32.2,127.0.0.1")
)

# Early-feedback copy of the server's built-in reserved names (UX only).
# The server is authoritative: it also checks an admin-managed list and
# answers 400 "'<name>' is reserved", which the panel shows verbatim.
RESERVED_SUBDOMAINS = frozenset(
    {
        "app", "api", "www", "admin", "auth", "mail", "static", "studio",
        "dev", "app-dev", "api-dev", "studio-dev", "mail-dev", "diun",
        "ns", "smtp", "imap", "ftp", "localhost",
    }
)

# Templates / static. Autoescaping is forced on (Starlette enables it too):
# every value rendered by the templates is HTML-escaped, and values embedded
# in JavaScript go through |tojson.
HERE = Path(__file__).parent
templates = Jinja2Templates(directory=str(HERE / "templates"))
templates.env.autoescape = True

# Serialises every state-changing operation (pair, poll, refresh, change,
# unpair) inside the panel; _locked() adds the cross-process state lock that
# the frpc service's renderer takes as well.
_STATE_LOCK = threading.Lock()


@contextmanager
def _locked() -> Iterator[None]:
    with _STATE_LOCK, cfg.state_lock(PATHS):
        yield


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class FlashError(Exception):
    """User-facing error rendered as a banner on the dashboard."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class BackendUnavailable(Exception):
    """The LinumIQ backend could not be reached (network/TLS/timeout)."""


# ---------------------------------------------------------------------------
# Helpers - HTTP (stdlib urllib, no extra deps)
# ---------------------------------------------------------------------------

class _RefuseRedirects(HTTPRedirectHandler):
    """Never follow a redirect. urllib would replay the Authorization header
    (device token) to whatever host the Location names; the device API never
    redirects, so a 3xx is reported as an error instead."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        raise HTTPError(req.full_url, code, "redirect refused", headers, fp)


_OPENER = build_opener(_RefuseRedirects())

# Keys of a backend error body that are shown to the user (sanitised).
_ERROR_KEYS = ("error", "message")


def _http_json(
    method: str,
    url: str,
    body: Optional[Dict[str, Any]] = None,
    bearer: Optional[str] = None,
    timeout: int = 15,
) -> Tuple[int, Any]:
    """JSON request. Returns (status, parsed body or text).

    Raises BackendUnavailable on network errors and on redirects. Never logs
    request bodies or headers (they carry device codes / tokens); error texts
    are sanitised with the bearer token redacted.
    """
    secrets = (bearer,) if bearer else ()
    host = urlsplit(url).netloc
    data = None
    headers = {
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    if bearer:
        # A token with spaces/controls would end up in an exception message
        # (urllib echoes invalid header values) - refuse it without echoing.
        if cfg.normalize_token(bearer) is None:
            LOG.error("Refusing to send a malformed device token (stored state corrupt?).")
            raise BackendUnavailable("The stored device token is malformed. Unpair and pair again.")
        headers["Authorization"] = f"Bearer {bearer}"
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = URLRequest(url, data=data, headers=headers, method=method)
    try:
        with _OPENER.open(req, timeout=timeout) as resp:  # noqa: S310 (https/http only)
            raw = resp.read().decode("utf-8", errors="replace")
            code = resp.status
    except HTTPError as exc:
        code = exc.code
        if 300 <= code < 400:
            LOG.error("HTTP %s %s answered %d (redirect) - not followed.", method,
                      cfg.sanitize_text(url, 200), code)
            raise BackendUnavailable(
                f"{host} answered with a redirect (HTTP {code}); redirects are not followed. "
                "Check the app_base option."
            ) from None
        try:
            raw = exc.read().decode("utf-8", errors="replace")
        except Exception:  # pragma: no cover - defensive
            raw = ""
    except (URLError, OSError, http.client.HTTPException) as exc:
        reason = cfg.sanitize_text(getattr(exc, "reason", exc), 160, secrets) or type(exc).__name__
        LOG.error("HTTP %s %s failed: %s", method, cfg.sanitize_text(url, 200), reason)
        raise BackendUnavailable(f"Cannot reach {host}: {reason}") from None
    except ValueError:
        # e.g. an invalid URL or header value; the message may echo it.
        LOG.error("HTTP %s %s failed: invalid request.", method, cfg.sanitize_text(url, 200))
        raise BackendUnavailable(f"Cannot reach {host}: invalid request.") from None
    try:
        return code, json.loads(raw)
    except ValueError:
        return code, raw


def _error_text(body: Any, default: str = "unknown error") -> str:
    """Short, single-line, printable description of a backend error body."""
    if isinstance(body, dict):
        raw = next((body[k] for k in _ERROR_KEYS if body.get(k)), default)
    else:
        raw = body or default
    return cfg.sanitize_text(raw, 200) or default


def _backend_url(path: str) -> str:
    """URL of a device API endpoint; refuses while app_base is invalid."""
    blocking = [OPTION_ERRORS[k] for k in BLOCKING_OPTIONS if k in OPTION_ERRORS]
    if blocking:
        raise FlashError(
            "Fix the add-on configuration first (Configuration tab, then restart "
            "the add-on): " + " ".join(blocking)
        )
    return f"{APP_BASE}{path}"


# ---------------------------------------------------------------------------
# Helpers - state / frpc
# ---------------------------------------------------------------------------

def _state() -> Dict[str, Any]:
    return cfg.load_state(PATHS)


def _settings(state: Optional[Dict[str, Any]] = None) -> cfg.Settings:
    return cfg.effective_settings(OPTIONS, _state() if state is None else state)


def _pairing() -> Dict[str, Any]:
    """The pairing in progress (validated again: the file may predate this
    version or have been tampered with); {} when there is none / it is bad."""
    stored = cfg.read_json(PATHS.pairing)
    if not stored:
        return {}
    try:
        return cfg.parse_pairing_response(stored, APP_BASE)
    except cfg.PairingResponseError as exc:
        # Ignored (not deleted here: callers may not hold the lock); the next
        # "Start Pairing" overwrites it.
        LOG.warning("Ignoring the stored pairing session: %s.", exc)
        return {}


def _clear_pairing() -> None:
    try:
        cfg.remove_file(PATHS.pairing)
    except OSError as exc:
        LOG.warning("Failed to remove pairing file: %s", cfg.sanitize_text(exc))


def _render_and_restart(force_restart: bool = False) -> str:
    """Render frpc.toml from the state; restart frpc when it changed."""
    result, settings = cfg.render_from_disk(PATHS, OPTIONS)
    if settings is not None:
        LOG.info("frpc.toml %s: %s", result, settings.describe())
    if result == cfg.RenderResult.RENDERED or force_restart:
        _restart_frpc()
    return result


def _s6_svc(*args: str, timeout: int = 10) -> bool:
    try:
        proc = subprocess.run(
            ["s6-svc", *args, FRPC_SERVICE],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except Exception as exc:  # pragma: no cover - only outside the image
        LOG.warning("s6-svc %s frpc failed: %s", " ".join(args), cfg.sanitize_text(exc))
        return False
    if proc.returncode != 0:
        LOG.warning("s6-svc %s frpc exited %d.", " ".join(args), proc.returncode)
        return False
    return True


def _restart_frpc() -> None:
    """Tell s6 to (re)start frpc; its run script re-renders frpc.toml and
    starts frpc only from a valid pairing. ``-u`` also brings the service
    back if an earlier unpair left it down."""
    if _s6_svc("-r", "-u"):
        LOG.info("frpc restart triggered via s6-svc -r -u")


def _stop_frpc() -> bool:
    """Take the frpc service down and wait (max 10 s) until it is down."""
    return _s6_svc("-wd", "-T", "10000", "-d", timeout=15)


def _start_frpc_service() -> None:
    """Bring the frpc service back up (its run script then waits for a
    pairing when there is none)."""
    _s6_svc("-u")


def _frpc_status() -> str:
    """'running' only when the s6 service is up AND its process is frpc
    (the run script is a wait loop while unpaired). Reported regardless of
    the pairing state, so a stray frpc would be visible."""
    try:
        proc = subprocess.run(
            ["s6-svstat", "-o", "up,pid", FRPC_SERVICE],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        fields = proc.stdout.split()
        if proc.returncode != 0 or len(fields) < 2:
            return "unknown"
        if fields[0] != "true":
            return "stopped"
        comm = Path(f"/proc/{int(fields[1])}/comm").read_text().strip()
        return "running" if comm == "frpc" else "waiting"
    except Exception:
        return "unknown"


def _apply_tunnel(state: Dict[str, Any], body: Any) -> Dict[str, Any]:
    """Merge + persist a tunnel response. Raises cfg.TunnelResponseError."""
    new_state, warnings = cfg.apply_tunnel_response(state, body)
    for warning in warnings:
        LOG.warning("%s", cfg.sanitize_text(warning))
    cfg.write_json(PATHS.state, new_state)
    return new_state


def _fetch_tunnel(device_token: str) -> Tuple[str, str]:
    """GET /api/device/tunnel and apply it.

    Returns (outcome, message) with outcome one of: "updated", "unchanged",
    "no_tunnel", "unauthorized", "error". Caller must hold _locked().
    """
    code, body = _http_json("GET", _backend_url("/api/device/tunnel"), bearer=device_token)
    if code == 200:
        try:
            _apply_tunnel(_state(), body)
        except cfg.TunnelResponseError as exc:
            LOG.error("Tunnel response rejected: %s", exc)
            return "error", str(exc)
        result = _render_and_restart()
        return ("updated" if result == cfg.RenderResult.RENDERED else "unchanged"), ""
    if code == 404:
        return "no_tunnel", "Device approved but no tunnel exists yet. Choose a subdomain."
    if code == 401:
        return "unauthorized", (
            "The backend no longer accepts this device (revoked?). "
            "Unpair and pair again."
        )
    msg = _error_text(body)
    LOG.warning("Tunnel fetch failed (%d): %s", code, msg)
    return "error", f"Tunnel fetch failed: {msg}"


def _startup_refresh() -> None:
    """Best effort: pick up server-side changes (e.g. a new frps port or
    domain_base, or a token rotated from the dashboard) on add-on start."""
    try:
        with _locked():
            state = _state()
            device_token = state.get("device_token")
            if not device_token or not cfg.is_paired(state):
                return
            outcome, message = _fetch_tunnel(device_token)
    except (BackendUnavailable, FlashError) as exc:
        LOG.warning("Start-up tunnel refresh skipped: %s", cfg.sanitize_text(exc))
        return
    except Exception as exc:  # pragma: no cover - never crash the panel
        LOG.warning("Start-up tunnel refresh failed: %s", cfg.sanitize_text(exc))
        return
    if outcome in ("updated", "unchanged"):
        LOG.info("Start-up tunnel refresh: %s", outcome)
    else:
        LOG.warning("Start-up tunnel refresh: %s - %s", outcome, message)


# ---------------------------------------------------------------------------
# Helpers - validation
# ---------------------------------------------------------------------------

def _validate_subdomain(subdomain: str) -> str:
    """Normalise and validate a user-entered subdomain (UX pre-check; the
    backend is authoritative). Raises FlashError."""
    subdomain = (subdomain or "").strip().lower()
    if not subdomain:
        raise FlashError("Subdomain is required.")
    if not cfg.normalize_subdomain(subdomain) or not 3 <= len(subdomain) <= 32:
        raise FlashError(
            "Subdomain must be 3-32 characters: lowercase a-z, 0-9 "
            "and '-', not starting or ending with '-'."
        )
    if subdomain in RESERVED_SUBDOMAINS:
        raise FlashError(f"'{subdomain}' is reserved and cannot be used.")
    return subdomain


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

def _client_allowed(host: str) -> bool:
    if "%" in host:  # scoped IPv6 (zone ID) - never an ingress client
        return False
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(addr in net for net in ALLOWED_CLIENT_NETS)


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
        if not _client_allowed(client_host):
            LOG.warning("Rejecting request from %s for %s", cfg.sanitize_text(client_host, 64),
                        cfg.sanitize_text(request.url.path, 120))
            return PlainTextResponse(
                "Forbidden: frp-mgr is only reachable via Home Assistant ingress.",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        path = request.scope.get("path", "")
        if path.startswith("//"):
            new_path = "/" + path.lstrip("/")
            request.scope["path"] = new_path
            request.scope["raw_path"] = new_path.encode("ascii")
        return await call_next(request)


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

@asynccontextmanager
async def _lifespan(_app: FastAPI):
    LOG.info(
        "frp-mgr starting: app_base=%s (from %s), %s",
        APP_BASE,
        _BASE.sources.get("app_base"),
        _settings().describe(),
    )
    threading.Thread(target=_startup_refresh, name="startup-refresh", daemon=True).start()
    yield


app = FastAPI(
    title="FRP Tunnel - Pairing Panel",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=_lifespan,
)
app.add_middleware(IngressOnlyMiddleware)

if (HERE / "static").is_dir():
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")


@app.exception_handler(FlashError)
async def _flash_error_handler(request: Request, exc: FlashError) -> RedirectResponse:
    """Convert a FlashError into a 303 redirect with a banner."""
    return _redirect_home(request, error=exc.message)


@app.exception_handler(BackendUnavailable)
async def _backend_error_handler(request: Request, exc: BackendUnavailable) -> RedirectResponse:
    return _redirect_home(request, error=cfg.sanitize_text(exc, 300))


def _redirect_home(
    request: Request,
    *,
    error: Optional[str] = None,
    ok: Optional[str] = None,
) -> RedirectResponse:
    """Redirect back to the dashboard, staying inside the ingress iframe."""
    ingress_prefix = request.headers.get("X-Ingress-Path", "").rstrip("/")
    params: Dict[str, str] = {}
    if error:
        params["error"] = cfg.sanitize_text(error, 300)
    if ok:
        params["ok"] = cfg.sanitize_text(ok, 300)
    qs = "?" + urlencode(params) if params else ""
    return RedirectResponse(url=f"{ingress_prefix}/{qs}", status_code=status.HTTP_303_SEE_OTHER)


def _view_model() -> Dict[str, Any]:
    """Everything the UI / status endpoint shows. Contains NO secrets; every
    pairing value was validated by cfg.parse_pairing_response."""
    state = _state()
    paired = cfg.is_paired(state)
    pairing = _pairing() if not paired else {}
    settings = _settings(state)
    subdomain = state.get("subdomain", "") if paired else ""
    public_host = cfg.public_hostname(settings, subdomain) if subdomain else ""
    return {
        "paired": paired,
        "approved_no_tunnel": bool(state.get("device_token")) and not paired,
        "pairing_active": bool(pairing),
        "user_code": pairing.get("user_code") or "",
        "verification_uri_complete": (
            pairing.get("verification_uri_complete") or pairing.get("verification_uri") or ""
        ),
        "interval": int(pairing.get("interval") or cfg.DEFAULT_POLL_INTERVAL),
        "subdomain": subdomain,
        "public_url": f"https://{public_host}" if public_host else "",
        "frpc_status": _frpc_status(),
        "option_errors": list(OPTION_ERRORS.values()),
        "server_addr": settings.server_addr,
        "server_port": settings.server_port,
        "domain_base": settings.domain_base,
        "sources": dict(settings.sources),
        "tls": True,
        "local_host": settings.local_host,
        "local_port": settings.local_port,
        "app_base": settings.app_base,
        "app_host": urlsplit(settings.app_base).netloc,
        "updated_at": state.get("updated_at", ""),
    }


# ---------------------------------------------------------------------------
# Routes - read-only
# ---------------------------------------------------------------------------

@app.get("/_health", response_class=PlainTextResponse)
async def health() -> str:
    return "ok"


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> Any:
    ctx = _view_model()
    # Query parameters are attacker-controllable text: sanitised + escaped.
    ctx["flash_error"] = cfg.sanitize_text(request.query_params.get("error") or "", 300) or None
    ctx["flash_ok"] = cfg.sanitize_text(request.query_params.get("ok") or "", 300) or None
    return templates.TemplateResponse(request, "index.html", ctx)


@app.get("/api/status")
def api_status() -> Dict[str, Any]:
    """Machine-readable panel state (used by the E2E harness). No secrets."""
    return _view_model()


# ---------------------------------------------------------------------------
# Routes - pairing flow
# ---------------------------------------------------------------------------

@app.post("/pair/start")
def pair_start(request: Request):
    """Initiate device authorization: call /api/device/code, show user_code.

    The response is untrusted input that ends up in the ingress page: it is
    validated completely (cfg.parse_pairing_response) or the pairing is
    rejected.
    """
    with _locked():
        if cfg.is_paired(_state()):
            raise FlashError("Already paired. Unpair first to re-pair.")

        code, body = _http_json("POST", _backend_url("/api/device/code"), {})
        if code != 200 or not isinstance(body, dict):
            msg = _error_text(body)
            LOG.error("Device code request failed (%d): %s", code, msg)
            raise FlashError(f"Failed to start pairing: {msg}")

        try:
            pairing = cfg.parse_pairing_response(body, APP_BASE)
        except cfg.PairingResponseError as exc:
            LOG.error("Pairing response rejected: %s.", exc)
            _clear_pairing()
            raise FlashError(
                f"Pairing rejected: the server sent an invalid pairing response ({exc}). "
                "Check the app_base option or try again later."
            ) from None

        cfg.write_json(PATHS.pairing, dict(pairing, created_at=cfg.utc_now()))
    LOG.info("Pairing started (user_code %s).", pairing["user_code"])
    return _redirect_home(request, ok=f"Pairing code ready: {pairing['user_code']}")


@app.post("/pair/poll")
def pair_poll() -> Dict[str, Any]:
    """Poll the token endpoint. Called via fetch() from the pairing page.

    Returns JSON {status: pending|slow_down|retry|paired|no_tunnel|expired|error}.
    """
    with _locked():
        pairing = _pairing()
        device_code = pairing.get("device_code")
        if not device_code:
            state = _state()
            if cfg.is_paired(state):
                return {"status": "paired", "subdomain": state.get("subdomain")}
            if state.get("device_token"):
                return {"status": "no_tunnel", "error": "Device approved. Choose a subdomain."}
            return {"status": "error", "error": "No pairing in progress."}

        try:
            code, body = _http_json(
                "POST", _backend_url("/api/device/token"), {"device_code": device_code}
            )
        except BackendUnavailable as exc:
            return {"status": "retry", "error": cfg.sanitize_text(exc)}
        except FlashError as exc:
            return {"status": "error", "error": exc.message}

        if code == 200:
            device_token = body.get("device_token") if isinstance(body, dict) else None
            if not device_token:
                return {"status": "error", "error": "No device_token in response."}
            if cfg.normalize_token(device_token) is None:
                # Never stored or sent as a header: it could inject headers.
                _clear_pairing()
                LOG.error("Backend returned a malformed device token (rejected).")
                return {"status": "error", "error": "The server returned an invalid device token."}
            # The device token is minted exactly once: persist it before
            # anything else can fail, so "Refresh" can recover later.
            cfg.write_json(
                PATHS.state,
                {"device_token": device_token, "version": cfg.STATE_VERSION, "paired_at": cfg.utc_now()},
            )
            _clear_pairing()
            LOG.info("Device approved; device token stored (redacted).")
            try:
                outcome, message = _fetch_tunnel(device_token)
            except BackendUnavailable as exc:
                return {"status": "no_tunnel",
                        "error": f"{cfg.sanitize_text(exc)}. Use 'Refresh' to retry."}
            if outcome in ("updated", "unchanged"):
                state = _state()
                LOG.info("Pairing complete: subdomain=%s", state.get("subdomain"))
                return {"status": "paired", "subdomain": state.get("subdomain")}
            if outcome == "no_tunnel":
                return {"status": "no_tunnel", "error": message}
            return {"status": "error", "error": message}

        err = _error_text(body, "") if code in (400, 429) else ""
        if code == 429 or err == "slow_down":
            return {"status": "slow_down"}
        if code == 400 and err == "authorization_pending":
            return {"status": "pending"}
        if code == 400 and err in ("expired_token", "invalid_grant", "access_denied"):
            _clear_pairing()
            return {"status": "expired", "error": "Pairing session expired. Please start again."}
        if code == 400:
            _clear_pairing()
            return {"status": "error", "error": err or "Unknown error."}
        msg = _error_text(body)
        LOG.error("Token exchange unexpected status %d: %s", code, msg)
        return {"status": "retry", "error": f"Backend error ({code}): {msg}"}


# ---------------------------------------------------------------------------
# Routes - tunnel management
# ---------------------------------------------------------------------------

@app.post("/tunnel/refresh")
def tunnel_refresh(request: Request):
    """Re-fetch the tunnel config (subdomain, token, server values) from the
    backend, re-render frpc.toml and restart frpc if anything changed."""
    with _locked():
        device_token = _state().get("device_token")
        if not device_token:
            raise FlashError("Not paired. Start pairing first.")
        outcome, message = _fetch_tunnel(device_token)
    if outcome == "updated":
        return _redirect_home(request, ok="Tunnel configuration updated; frpc restarted.")
    if outcome == "unchanged":
        return _redirect_home(request, ok="Tunnel configuration is up to date.")
    raise FlashError(message)


@app.post("/subdomain/change")
def subdomain_change(request: Request, subdomain: str = Form(...)):
    """Claim or change the tunnel subdomain (the backend rotates the token)."""
    subdomain = _validate_subdomain(subdomain)
    with _locked():
        state = _state()
        device_token = state.get("device_token")
        if not device_token:
            raise FlashError("Not paired. Start pairing first.")

        code, body = _http_json(
            "POST",
            _backend_url("/api/device/tunnel"),
            {"subdomain": subdomain},
            bearer=device_token,
        )
        if code == 200:
            try:
                new_state = _apply_tunnel(state, body)
            except cfg.TunnelResponseError as exc:
                raise FlashError(str(exc)) from None
            _render_and_restart(force_restart=True)
            host = cfg.public_hostname(_settings(new_state), new_state["subdomain"])
            LOG.info("Subdomain changed to %s", new_state["subdomain"])
            return _redirect_home(request, ok=f"Subdomain changed to {host}")

    if code == 409:
        raise FlashError(f"Subdomain '{subdomain}' is already taken. Please choose another.")
    if code == 400:
        # Surface the server's reason verbatim (e.g. "'foo' is reserved").
        raise FlashError(f"The server rejected the subdomain: {_error_text(body, 'invalid subdomain')}")
    if code == 401:
        raise FlashError("The backend no longer accepts this device. Unpair and pair again.")
    msg = _error_text(body)
    LOG.error("Subdomain change failed (%d): %s", code, msg)
    raise FlashError(f"Failed to change subdomain: {msg}")


# ---------------------------------------------------------------------------
# Routes - unpair
# ---------------------------------------------------------------------------

@app.post("/unpair")
def unpair(request: Request):
    """Stop the tunnel, remove all pairing state, revoke the device token.

    Order matters (all under the state lock, which the frpc service's
    renderer also takes): 1. the state file goes first, so any render from
    now on answers "not paired"; 2. frpc is taken down and awaited; 3. only
    then frpc.toml (the old token) is removed and the service brought back up
    into its wait loop; 4. the device token (kept in memory) is revoked
    server-side. A failed revocation is reported - local data is gone either
    way.
    """
    with _locked():
        device_token = _state().get("device_token")

        try:
            cfg.remove_file(PATHS.state)
        except OSError as exc:
            LOG.error("Unpair: cannot remove the state file: %s", cfg.sanitize_text(exc))
            raise FlashError("Unpair failed: the pairing state could not be removed.") from None
        _clear_pairing()

        stopped = _stop_frpc()
        try:
            cfg.remove_file(PATHS.frpc_toml)
        except OSError as exc:
            LOG.error("Unpair: cannot remove frpc.toml: %s", cfg.sanitize_text(exc))
        _start_frpc_service()
        if not stopped:
            LOG.warning("Unpair: frpc did not confirm it stopped; it restarts without a pairing.")

        revoke_error = _revoke_device_token(device_token) if device_token else None

    if revoke_error:
        LOG.warning("Device unpaired locally; server-side revocation failed: %s", revoke_error)
        return _redirect_home(
            request,
            error=(
                "Device unpaired locally and the tunnel is stopped, but the server did not "
                f"confirm that the device token was revoked ({revoke_error}). Local pairing data "
                "is deleted; if the problem persists, remove the device in your LinumIQ account."
            ),
        )
    LOG.info("Device unpaired.")
    return _redirect_home(request, ok="Device unpaired. Tunnel stopped.")


def _revoke_device_token(device_token: str) -> Optional[str]:
    """DELETE /api/device/tunnel. Returns None on success (also when the
    server no longer accepts the token: 401), else a short reason."""
    try:
        code, body = _http_json("DELETE", _backend_url("/api/device/tunnel"), bearer=device_token)
    except BackendUnavailable as exc:
        return cfg.sanitize_text(exc)
    except FlashError as exc:
        return exc.message
    if 200 <= code < 300:
        return None
    if code == 401:
        LOG.info("Backend no longer accepts this device token (already revoked).")
        return None
    return f"HTTP {code}: {_error_text(body)}"
