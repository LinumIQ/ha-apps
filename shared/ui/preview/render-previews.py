#!/usr/bin/env python3
"""Render every state of both panels to static HTML (maintainer tool, offline).

Renders the templates the add-ons ship (frp-tunnel/.../frp-mgr/templates and
caddy-mtls/.../cert-mgr/templates, i.e. the synced copies: run
scripts/sync-shared.sh first) with fixture contexts - no backend, no
Supervisor, no Caddy - and writes

    shared/ui/preview/out/<app>/<state>.html   one page per state
    shared/ui/preview/out/<app>/static/        a copy of the add-on's static/
    shared/ui/preview/out/manifest.json        the pages, for screenshot.mjs

screenshot.mjs serves out/ like the ingress proxy would (each page at
/<app>/<state>/ with its static files below it) and captures them.

Needs Jinja2 (the panels' own dependency), e.g.:

    python3 -m venv /tmp/ui-venv
    /tmp/ui-venv/bin/pip install --require-hashes -r frp-tunnel/requirements.txt
    /tmp/ui-venv/bin/python shared/ui/preview/render-previews.py

The caddy-mtls fixtures use the real public_cert.py (standard library) for
the card's data classes, checklist and retry hint. Times are rendered in
Europe/Vienna.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jinja2

REPO = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent / "out"
FRP_MGR = REPO / "frp-tunnel" / "rootfs" / "usr" / "lib" / "frp-mgr"
CERT_MGR = REPO / "caddy-mtls" / "rootfs" / "usr" / "lib" / "cert-mgr"

os.environ["TZ"] = "Europe/Vienna"
time.tzset()
sys.dont_write_bytecode = True  # no __pycache__ in the add-on's rootfs
sys.path.insert(0, str(CERT_MGR))
import public_cert  # noqa: E402

#: 2026-10-28 12:00 UTC - the "now" of every fixture.
NOW = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc).timestamp()


# ---------------------------------------------------------------------------
# frp-tunnel (keys as frp-mgr's app._view_model() returns them, plus what
# app.index() adds: the flash texts and the CSRF token)
# ---------------------------------------------------------------------------

def frp_base(**overrides):
    ctx = {
        "paired": False,
        "approved_no_tunnel": False,
        "pairing_active": False,
        "user_code": "",
        "verification_uri_complete": "",
        "interval": 1,
        "subdomain": "",
        "public_url": "",
        "frpc_status": "waiting",
        "option_errors": [],
        "server_addr": "linumiq.net",
        "server_port": 7001,
        "domain_base": "linumiq.net",
        "sources": {"local_port": "supervisor"},
        "tls": True,
        "tls_mode": "verified",
        "tls_verified": False,
        "tls_login": "unknown",
        "frpc_logged_in_at": "",
        "server_name": "",
        "server_ca": [],
        "tls_errors": [],
        "tls_warnings": [],
        "auto_refresh": {},
        "account_email_masked": "",
        "local_host": "homeassistant",
        "local_port": 8123,
        "app_base": "https://app.linumiq.net",
        "app_host": "app.linumiq.net",
        "updated_at": "",
        "flash_error": None,
        "flash_ok": None,
        "csrf_token": "preview-csrf-token",
    }
    ctx.update(overrides)
    return ctx


FRP_PAIRING = dict(pairing_active=True, user_code="ABCD-EF23",
                   verification_uri_complete="https://app.linumiq.net/activate?code=ABCD-EF23")
FRP_PAIRED = dict(
    paired=True, frpc_status="running", subdomain="my-home", public_url="https://my-home.linumiq.net",
    account_email_masked="g***@example.com", tls_verified=True, tls_login="ok",
    server_name="frps.linumiq.net",
    server_ca=[{"subject": "LinumIQ Tunnel CA", "not_after": "2036-09-30"}],
    frpc_logged_in_at="2026-10-28 09:12 UTC",
    auto_refresh={"at": "2026-10-28T09:12:03Z", "outcome": "unchanged"},
)
UNVERIFIED = (
    "The LinumIQ server did not provide the certificate authority of the tunnel server, so frpc "
    "cannot verify the server it connects to: the connection is encrypted but not protected against "
    "an active man in the middle. Click 'Refresh tunnel config' after the server has been updated."
)
LOGIN_FAILED = (
    "frpc could not log in to the tunnel server with the pinned certificate authority (tls: failed "
    "to verify certificate: x509: certificate signed by unknown authority). If the LinumIQ server "
    "rotated it, 'Refresh tunnel config' fetches the new one (the add-on also does this "
    "automatically after repeated failures)."
)

FRP_STATES = [
    ("unpaired", frp_base(), {}),
    ("option-errors", frp_base(
        frpc_status="running",
        option_errors=[
            "app_base='htps://app.example' is invalid (expected an https:// URL); it is ignored.",
            "local_port='99999' is invalid (expected a port 1-65535); it is ignored.",
        ],
        flash_error="Fix the add-on configuration first (Configuration tab, then restart the add-on): "
                    "app_base='htps://app.example' is invalid (expected an https:// URL).",
    ), {}),
    ("pairing", frp_base(**FRP_PAIRING), {"poll": {"status": "pending"}}),
    ("pairing-expired", frp_base(**FRP_PAIRING), {
        "poll": {"status": "expired"}, "wait_for_text": "Session expired"}),
    ("approved-no-tunnel", frp_base(approved_no_tunnel=True, account_email_masked="g***@example.com"), {}),
    ("paired", frp_base(**FRP_PAIRED, flash_ok="Tunnel configuration is up to date."), {}),
    ("paired-change-dialog", frp_base(**FRP_PAIRED), {"click": "text=Change Subdomain"}),
    ("paired-tls-warning", frp_base(**dict(
        FRP_PAIRED, frpc_status="waiting", account_email_masked="", tls_mode="unverified", tls_verified=False,
        server_name="", server_ca=[], frpc_logged_in_at="", tls_warnings=[UNVERIFIED], auto_refresh={},
        sources={})), {}),
    ("paired-tls-error", frp_base(**dict(
        FRP_PAIRED, frpc_status="running", tls_verified=False, tls_login="failed", frpc_logged_in_at="",
        tls_errors=[LOGIN_FAILED],
        flash_error="Cannot reach app.linumiq.net: [Errno -3] Temporary failure in name resolution")), {}),
]


# ---------------------------------------------------------------------------
# caddy-mtls (as cert-mgr's index() and _public_cert_context() build them)
# ---------------------------------------------------------------------------

DOMAIN = "home.example.org"


def runtime(**overrides):
    values = dict(domain=DOMAIN, started_at=NOW - 900, host_ports_known=True,
                  http_host_port=8080, https_host_port=8443)
    values.update(overrides)
    return public_cert.Runtime(**values)


CERT = public_cert.Certificate(
    path=f"/data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/{DOMAIN}/{DOMAIN}.crt",
    subject_cn=DOMAIN, issuer_cn="R12", issuer_org="Let's Encrypt",
    not_after=datetime.fromtimestamp(NOW, timezone.utc) + timedelta(days=61, hours=3),
    fingerprint_sha256="3f" * 32, mtime=NOW - 29 * 86400,
)
OBTAIN_ERROR = public_cert.AcmeEvent(
    ts=NOW - 300, logger="tls.obtain", level="error", msg="could not get certificate from issuer",
    identifier=DOMAIN, problem_type="connection",
    error="86.62.32.88: Timeout during connect (likely firewall problem)")
CHALLENGES = [
    public_cert.AcmeEvent(ts=NOW - 305, logger="http.acme_client", level="error", msg="challenge failed",
                          identifier=DOMAIN, challenge_type="http-01", problem_type="connection",
                          error=f"86.62.32.88: Fetching http://{DOMAIN}/.well-known/acme-challenge/y0_Ss4VQ: "
                                "Timeout during connect (likely firewall problem)"),
    public_cert.AcmeEvent(ts=NOW - 302, logger="http.acme_client", level="error", msg="challenge failed",
                          identifier=DOMAIN, challenge_type="tls-alpn-01", problem_type="connection",
                          error="86.62.32.88: Error getting validation data"),
]
RETRY = public_cert.AcmeEvent(ts=NOW - 299, logger="tls.obtain", level="error", msg="will retry",
                              identifier=DOMAIN, attempt=3, retrying_in=600)
RENEW_ERROR = public_cert.AcmeEvent(
    ts=NOW - 3600, logger="tls.renew", level="error", msg="could not get certificate from issuer",
    identifier=DOMAIN, problem_type="dns", error=f"DNS problem: NXDOMAIN looking up A for {DOMAIN}")


def caddy_state(clients=True, ca=True, crl=True):
    return {
        "version": 2,
        "ca": {
            "subject_cn": "Caddy mTLS CA",
            "serial": "4C6F8A21D3E0B7F5",
            "fingerprint_sha256": "9A:3C:51:0E:77:B2:4D:C8:1F:6A:E9:03:5B:D4:88:2E:"
                                  "C1:7F:90:3A:6B:E2:14:5D:A8:0C:F3:97:2B:6E:D1:40",
            "not_before": "2026-10-14T08:00:00Z",
            "not_after": "2036-10-11T08:00:00Z",
        } if ca else None,
        "clients": [
            {"name": "alice-phone", "status": "active", "serial": "1A2B3C4D", "not_after": "2027-10-14T08:00:00Z"},
            {"name": "bob-laptop", "status": "revoked", "serial": "5E6F7081", "not_after": "2027-10-14T08:00:00Z",
             "revocation_reason": "keyCompromise"},
            {"name": "carol-tablet-in-the-kitchen", "status": "active", "serial": "92A3B4C5",
             "not_after": "2027-10-28T11:58:00Z"},
        ] if clients else [],
        "crl_number": 7 if crl else None,
        "crl_generated_at": "2026-10-28T11:58:10Z" if crl else None,
    }


def caddy_ctx(status, state=None, flash_error=None, flash_ok=None):
    return {
        "state": state if state is not None else caddy_state(),
        "ca_crt_exists": bool((state or caddy_state())["ca"]),
        "crl_exists": bool((state or caddy_state())["crl_number"]),
        "flash_error": flash_error,
        "flash_ok": flash_ok,
        "pc": status,
        "pc_checklist": public_cert.checklist(status),
        "pc_retry_hint": public_cert.retry_hint(status),
        "pc_time": public_cert.local_time,
    }


OK = public_cert.Status(state="ok", runtime=runtime(), certificate=CERT, served=True, now=NOW)
CADDY_STATES = [
    ("ok", caddy_ctx(OK, flash_ok="Client 'carol-tablet-in-the-kitchen' created."), {}),
    ("ok-danger-zone-open", caddy_ctx(OK), {"click": "summary"}),
    ("missing", caddy_ctx(
        public_cert.Status(state="missing", runtime=runtime(), last_error=OBTAIN_ERROR, challenges=CHALLENGES,
                           retry=RETRY, now=NOW),
        flash_error="Invalid client name 'bad name!' (1-64 characters: letters, digits, dot, dash and "
                    "underscore; not starting with a dot)."), {}),
    ("renewal-failing", caddy_ctx(
        public_cert.Status(state="renewal_failing", runtime=runtime(acme_dns_provider="cloudflare"),
                           certificate=CERT, last_error=RENEW_ERROR, now=NOW)), {}),
    ("pending-empty", caddy_ctx(
        public_cert.Status(state="pending", runtime=runtime(started_at=NOW - 20,
                                                            acme_ca="https://acme-staging-v02.api.letsencrypt.org/directory"),
                           now=NOW),
        state=caddy_state(clients=False, ca=False, crl=False)), {}),
]


# ---------------------------------------------------------------------------

def render(app: str, panel: Path, states) -> list[dict]:
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(panel / "templates")), autoescape=True)
    template = env.get_template("index.html")
    target = OUT / app
    shutil.copytree(panel / "static", target / "static")
    pages = []
    for name, ctx, extra in states:
        (target / f"{name}.html").write_text(template.render(ctx))
        pages.append(dict({"app": app, "state": name, "file": f"{app}/{name}.html",
                           "path": f"/{app}/{name}/"}, **extra))
    return pages


def main() -> int:
    sync = subprocess.run(["bash", str(REPO / "scripts" / "sync-shared.sh"), "--check"],
                          capture_output=True, text=True, check=False)
    if sync.returncode != 0:
        print(sync.stdout + sync.stderr, file=sys.stderr)
        print("The add-ons' shared UI copies are stale: run scripts/sync-shared.sh first.", file=sys.stderr)
        return 1
    shutil.rmtree(OUT, ignore_errors=True)
    OUT.mkdir(parents=True)
    pages = render("frp-tunnel", FRP_MGR, FRP_STATES) + render("caddy-mtls", CERT_MGR, CADDY_STATES)
    (OUT / "manifest.json").write_text(json.dumps({"pages": pages}, indent=2) + "\n")
    print(f"rendered {len(pages)} pages to {OUT.relative_to(REPO)}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
