#!/usr/bin/env python3
"""Approve an FRP Tunnel device pairing as a real LinumIQ user (E2E helper).

Usage:  approve.py <user_code>

Stdlib only (no pip). Signs in through GoTrue (Supabase Auth) at API_BASE,
steps up to AAL2 with TOTP (RFC 6238, implemented below) and calls
``POST {APP_BASE}/api/device/approve`` exactly like the /activate page does.

Environment:
  APP_BASE, API_BASE        dashboard / Supabase API base URLs (required)
  E2E_ANON_KEY              Supabase anon key (required)
  E2E_EMAIL, E2E_PASSWORD   credentials of an existing, confirmed user (required)
  E2E_TOTP_SECRET           base32 secret of the user's verified TOTP factor.
                            Required when the user already has one; when the
                            user has none, a factor is enrolled and verified.
  E2E_TOTP_SECRET_FILE      optional file to read the secret from, and to which
                            the secret of a freshly enrolled factor is written
                            (mode 600) so later runs can reuse it.
  E2E_SUBDOMAIN             subdomain to claim; default: keep the account's
                            current tunnel, or claim "e2e-addon" if it has none.
  E2E_AUTH_COOKIE_NAME      cookie name for the legacy fallback, default
                            sb-<first label of API_BASE host>-auth-token (what
                            @supabase/ssr derives from NEXT_PUBLIC_SUPABASE_URL)

Contract v2.1: the approve route accepts ``Authorization: Bearer
<access_token>`` and requires the token's ``aal`` claim to be ``aal2`` (else
403 aal2_required). Dashboards older than that only read the @supabase/ssr
session cookie, so on a 401 the helper retries once with the session also
sent as that cookie.

Exit status: 0 approved, 1 failure, 2 usage error. Secrets are never printed.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

DEFAULT_SUBDOMAIN = "e2e-addon"
COOKIE_CHUNK_SIZE = 3180  # @supabase/ssr MAX_CHUNK_SIZE


class Failure(Exception):
    pass


def log(msg: str) -> None:
    print(f"[approve] {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# RFC 6238 TOTP (RFC 4226 HOTP with a time-based counter)
# ---------------------------------------------------------------------------

def b32decode(secret: str) -> bytes:
    cleaned = "".join(secret.split()).replace("-", "").upper()
    cleaned += "=" * (-len(cleaned) % 8)
    return base64.b32decode(cleaned)


def totp(secret: str, at: Optional[float] = None, step: int = 30, digits: int = 6,
         digest: Any = hashlib.sha1) -> str:
    key = b32decode(secret)
    counter = int((time.time() if at is None else at) // step)
    mac = hmac.new(key, struct.pack(">Q", counter), digest).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def http(method: str, url: str, body: Optional[Dict[str, Any]] = None,
         headers: Optional[Dict[str, str]] = None, timeout: int = 20) -> Tuple[int, Any]:
    hdrs = {"Accept": "application/json", "User-Agent": "frp-tunnel-addon-e2e"}
    hdrs.update(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    req = Request(url, data=data, headers=hdrs, method=method)
    try:
        with urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw, code = resp.read().decode("utf-8", "replace"), resp.status
    except HTTPError as exc:
        raw, code = exc.read().decode("utf-8", "replace"), exc.code
    except (URLError, OSError) as exc:
        raise Failure(f"{method} {urlsplit(url).netloc}{urlsplit(url).path}: {getattr(exc, 'reason', exc)}")
    try:
        return code, json.loads(raw)
    except ValueError:
        return code, raw


def err(body: Any) -> str:
    """Short, secret-free description of an error body."""
    if isinstance(body, dict):
        parts = [str(body.get(k)) for k in ("error_code", "error", "msg", "message") if body.get(k)]
        return " / ".join(parts)[:200] or "no details"
    return str(body)[:200]


# ---------------------------------------------------------------------------
# GoTrue: password login + TOTP step-up to AAL2
# ---------------------------------------------------------------------------

def read_secret() -> Optional[str]:
    secret = os.environ.get("E2E_TOTP_SECRET", "").strip()
    path = os.environ.get("E2E_TOTP_SECRET_FILE", "").strip()
    if not secret and path and os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            secret = fh.read().strip()
    return secret or None


def save_secret(secret: str) -> None:
    path = os.environ.get("E2E_TOTP_SECRET_FILE", "").strip()
    if not path:
        log("NOTE: enrolled a new TOTP factor; set E2E_TOTP_SECRET_FILE to keep its secret for later runs.")
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(secret + "\n")
    log(f"enrolled a new TOTP factor; secret written to {path} (mode 600)")


def verify_factor(api: str, headers: Dict[str, str], factor_id: str, secret: str) -> Optional[Dict[str, Any]]:
    for attempt in range(2):
        code, ch = http("POST", f"{api}/auth/v1/factors/{factor_id}/challenge", {}, headers)
        if code != 200 or not isinstance(ch, dict) or not ch.get("id"):
            raise Failure(f"MFA challenge failed: HTTP {code} {err(ch)}")
        code, session = http(
            "POST", f"{api}/auth/v1/factors/{factor_id}/verify",
            {"challenge_id": ch["id"], "code": totp(secret)}, headers,
        )
        if code == 200 and isinstance(session, dict) and session.get("access_token"):
            return session
        log(f"MFA verify attempt {attempt + 1} failed: HTTP {code} {err(session)}")
        # Wait for the next 30 s window before the second attempt.
        time.sleep(31 - (time.time() % 30))
    return None


def login_aal2(api: str, anon: str, email: str, password: str) -> Dict[str, Any]:
    base = {"apikey": anon, "Authorization": f"Bearer {anon}"}
    code, session = http("POST", f"{api}/auth/v1/token?grant_type=password",
                         {"email": email, "password": password}, base)
    if code != 200 or not isinstance(session, dict) or not session.get("access_token"):
        raise Failure(f"password login failed: HTTP {code} {err(session)}")
    log("password login ok (aal1)")
    auth = {"apikey": anon, "Authorization": f"Bearer {session['access_token']}"}

    code, user = http("GET", f"{api}/auth/v1/user", headers=auth)
    if code != 200 or not isinstance(user, dict):
        raise Failure(f"fetching the user failed: HTTP {code} {err(user)}")
    verified = [f for f in user.get("factors") or []
                if f.get("factor_type") == "totp" and f.get("status") == "verified"]
    secret = read_secret()

    if verified:
        if not secret:
            raise Failure("the user has a verified TOTP factor: set E2E_TOTP_SECRET (or E2E_TOTP_SECRET_FILE)")
        for factor in verified:
            aal2 = verify_factor(api, auth, factor["id"], secret)
            if aal2:
                log("TOTP verified (aal2)")
                return aal2
        raise Failure("no verified TOTP factor accepted the code from E2E_TOTP_SECRET")

    code, enrolled = http("POST", f"{api}/auth/v1/factors",
                          {"factor_type": "totp", "friendly_name": f"addon-e2e-{int(time.time())}"}, auth)
    if code != 200 or not isinstance(enrolled, dict) or not (enrolled.get("totp") or {}).get("secret"):
        raise Failure(f"TOTP enrollment failed: HTTP {code} {err(enrolled)}")
    secret = enrolled["totp"]["secret"]
    aal2 = verify_factor(api, auth, enrolled["id"], secret)
    if not aal2:
        raise Failure("verifying the freshly enrolled TOTP factor failed")
    save_secret(secret)
    log("TOTP factor enrolled and verified (aal2)")
    return aal2


# ---------------------------------------------------------------------------
# Approve
# ---------------------------------------------------------------------------

def session_cookies(name: str, session: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Serialise the session exactly like @supabase/ssr (base64url, chunked)."""
    raw = json.dumps(session, separators=(",", ":")).encode()
    value = "base64-" + base64.urlsafe_b64encode(raw).decode().rstrip("=")
    if len(value) <= COOKIE_CHUNK_SIZE:
        return [(name, value)]
    return [(f"{name}.{i}", value[pos:pos + COOKIE_CHUNK_SIZE])
            for i, pos in enumerate(range(0, len(value), COOKIE_CHUNK_SIZE))]


def approve(app: str, api: str, session: Dict[str, Any], user_code: str) -> str:
    host = urlsplit(api).hostname or ""
    name = os.environ.get("E2E_AUTH_COOKIE_NAME") or f"sb-{host.split('.')[0]}-auth-token"
    headers = {
        "Authorization": f"Bearer {session['access_token']}",
        "Origin": app,
        "Referer": f"{app}/activate",
    }
    wanted = os.environ.get("E2E_SUBDOMAIN", "").strip()
    body: Dict[str, Any] = {"user_code": user_code}
    if wanted:
        body["subdomain"] = wanted

    def post() -> Tuple[int, Any]:
        return http("POST", f"{app}/api/device/approve", body, headers)

    code, resp = post()
    if code == 401:
        log("bearer token not accepted - retrying with the @supabase/ssr session cookie (pre-2.1 dashboard)")
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in session_cookies(name, session))
        code, resp = post()
    if code == 400 and isinstance(resp, dict) and resp.get("error") == "subdomain_required" and not wanted:
        log(f"account has no tunnel yet - claiming '{DEFAULT_SUBDOMAIN}'")
        body["subdomain"] = DEFAULT_SUBDOMAIN
        code, resp = post()
    if code == 401:
        raise Failure(f"approve: 401 - neither the bearer token nor the session cookie '{name}' was accepted "
                      "(set E2E_AUTH_COOKIE_NAME if NEXT_PUBLIC_SUPABASE_URL differs from API_BASE)")
    if code == 403:
        raise Failure(f"approve: 403 {err(resp)} - the access token is not aal2")
    if code != 200 or not isinstance(resp, dict) or not resp.get("ok"):
        raise Failure(f"approve failed: HTTP {code} {err(resp)}")
    return str(resp.get("subdomain", ""))


def main(argv: List[str]) -> int:
    if len(argv) != 2 or not argv[1].strip():
        print(__doc__, file=sys.stderr)
        return 2
    missing = [k for k in ("APP_BASE", "API_BASE", "E2E_ANON_KEY", "E2E_EMAIL", "E2E_PASSWORD")
               if not os.environ.get(k)]
    if missing:
        log(f"missing environment: {', '.join(missing)}")
        return 2
    app = os.environ["APP_BASE"].rstrip("/")
    api = os.environ["API_BASE"].rstrip("/")
    try:
        session = login_aal2(api, os.environ["E2E_ANON_KEY"], os.environ["E2E_EMAIL"], os.environ["E2E_PASSWORD"])
        subdomain = approve(app, api, session, argv[1].strip())
    except Failure as exc:
        log(f"FAILED: {exc}")
        return 1
    log(f"device approved (subdomain {subdomain})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
