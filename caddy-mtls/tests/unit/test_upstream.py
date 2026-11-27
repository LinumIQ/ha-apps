"""Unit tests for cert-mgr/upstream.py (forwarded_headers: the probe, the
decision, the snippet, the state) and the monitor's upstream watch
(monitor.UpstreamWatch: cadence, the noise rules, the notification).

Standard library only. The network tests run a fake Home Assistant on
127.0.0.1 (refuses X-Forwarded-For unless told to trust the proxy, HTTP/1.1
keep-alive like aiohttp). Runs against the repository's code or the
installed one with CERT_MGR_DIR (see test_monitor.py).
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

CERT_MGR = Path(
    os.environ.get("CERT_MGR_DIR")
    or Path(__file__).resolve().parents[2] / "rootfs" / "usr" / "lib" / "cert-mgr"
)
sys.path.insert(0, str(CERT_MGR))

import monitor  # noqa: E402
import upstream  # noqa: E402

A, R, U = upstream.ACCEPTED, upstream.REFUSED, upstream.UNREACHABLE


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakeHomeAssistant:
    """A minimal Home Assistant towards a proxy: 400 for X-Forwarded-For
    unless ``trust``; 200 otherwise. ``restart()`` closes every connection
    and listens again on the same port; ``stop()`` leaves it down."""

    def __init__(self, port: int | None = None, keep_alive: bool = True) -> None:
        self.port = port or free_port()
        self.trust = False
        self.status = 200
        self.keep_alive = keep_alive
        #: Seconds to wait before answering (a slow / paused Home Assistant).
        self.delay = 0.0
        #: The same for requests with X-Forwarded-For only (a test request
        #: that is always too slow, B2-3).
        self.forwarded_delay = 0.0
        #: Close a kept connection this many seconds after an answer (an
        #: upstream that closes idle connections itself).
        self.idle_close: float | None = None
        #: A Keep-Alive header to send ("timeout=1").
        self.keep_alive_header: str | None = None
        self.requests: list[dict] = []
        self.conns: list[socket.socket] = []
        self.server: ThreadingHTTPServer | None = None
        self.start()

    def start(self) -> None:
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1" if fake.keep_alive else "HTTP/1.0"
            # One write per response (headers and body), as aiohttp does: two
            # small writes would wait for the client's delayed ACK (Nagle).
            wbufsize = 64 * 1024

            def setup(self) -> None:
                super().setup()
                fake.conns.append(self.connection)

            def do_GET(self) -> None:  # noqa: N802
                if fake.delay:
                    time.sleep(fake.delay)
                forwarded = "X-Forwarded-For" in self.headers
                refused = forwarded and not fake.trust
                fake.requests.append({"forwarded": forwarded, "refused": refused,
                                      "peer": self.client_address[0],
                                      "host": self.headers.get("Host"),
                                      "xff": self.headers.get("X-Forwarded-For")})
                if forwarded and fake.forwarded_delay:
                    time.sleep(fake.forwarded_delay)
                status, body = (400, b"400: Bad Request") if refused else (fake.status, b"{}")
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                if fake.keep_alive_header:
                    self.send_header("Keep-Alive", fake.keep_alive_header)
                self.end_headers()
                self.wfile.write(body)
                if fake.idle_close is not None:
                    self.wfile.flush()
                    timer = threading.Timer(fake.idle_close, self._shut)
                    timer.daemon = True
                    timer.start()

            def _shut(self) -> None:
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            def log_message(self, *args: object) -> None:
                pass

        class Server(ThreadingHTTPServer):
            allow_reuse_address = True
            daemon_threads = True

            def handle_error(self, request, client_address) -> None:  # quiet: clients time out
                pass

        self.server = Server(("127.0.0.1", self.port), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        for conn in self.conns:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()
        self.conns.clear()

    def restart(self) -> None:
        self.stop()
        self.start()

    @property
    def tests(self) -> int:
        return sum(1 for r in self.requests if r["forwarded"])

    @property
    def refusals(self) -> int:
        return sum(1 for r in self.requests if r["refused"])


@contextlib.contextmanager
def captured_logs(name: str = "cert-monitor"):
    """The log records of a logger (an empty list is fine, unlike
    assertLogs)."""
    records: list[logging.LogRecord] = []

    class Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    logger = logging.getLogger(name)
    handler = Collect(level=logging.DEBUG)
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)


class TempFiles(unittest.TestCase):
    """STATE_FILE, SNIPPET_FILE and LOCK_FILE in a temporary directory."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        for name, value in (
            ("STATE_FILE", self.dir / "upstream.json"),
            ("SNIPPET_FILE", self.dir / "forwarded-headers.caddy"),
            ("LOCK_FILE", self.dir / "upstream.lock"),
        ):
            patcher = mock.patch.object(upstream, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.reloads: list[str] = []
        self.reload_ok = True

    def reload(self) -> tuple[bool, str]:
        self.reloads.append(upstream.snippet_mode() or "?")
        return (True, "reloaded") if self.reload_ok else (False, "admin API down")

    def settings(self, port: int, option: str = "auto", mtls: bool = True,
                 host: str = "127.0.0.1") -> upstream.Settings:
        return upstream.Settings(domain="home.example.com", host=host, port=port,
                                 mtls=mtls, option=option)


class ClassifyTest(unittest.TestCase):
    def test_table(self) -> None:
        cases = [
            ((None, None), U),     # control failed
            ((502, None), U),      # control 5xx
            ((503, 400), U),
            ((200, None), upstream.REACHABLE),
            ((200, 400), R),       # Home Assistant without trusted proxy
            ((200, 200), A),       # trusted
            ((404, 400), R),
            ((404, 404), A),       # answers the same: accepted
            ((400, 400), A),       # same 400 both times: not a differential refusal
            ((301, 301), A),
            ((200, 403), A),       # only a 400 counts as refused
        ]
        for (control, test), expected in cases:
            with self.subTest(control=control, test=test):
                self.assertEqual(upstream.classify(control, test), expected)


class DecideTest(unittest.TestCase):
    def test_every_combination(self) -> None:
        """option x mTLS x last decisive result (None: first start or
        unreachable without any result; while unreachable the persisted
        decisive result counts - the last known mode)."""
        expected = {
            ("always", True, A): "pass", ("always", True, R): "pass", ("always", True, None): "pass",
            ("always", False, A): "pass", ("always", False, R): "pass", ("always", False, None): "pass",
            ("never", True, A): "strip", ("never", True, R): "strip", ("never", True, None): "strip",
            # never needs mTLS (init-caddy refuses the start; decide() is the
            # second line): without it, addresses are always passed on.
            ("never", False, A): "pass", ("never", False, R): "pass", ("never", False, None): "pass",
            ("auto", True, A): "pass", ("auto", True, R): "strip", ("auto", True, None): "pass",
            # Without mTLS, auto never strips: unauthenticated internet
            # visitors must not look local to Home Assistant.
            ("auto", False, A): "pass", ("auto", False, R): "pass", ("auto", False, None): "pass",
        }
        for option in upstream.OPTIONS:
            for mtls in (True, False):
                for decisive in (A, R, None):
                    with self.subTest(option=option, mtls=mtls, decisive=decisive):
                        self.assertEqual(upstream.decide(option, mtls, decisive),
                                         expected[(option, mtls, decisive)])


class NoStripWithoutMtlsTest(unittest.TestCase):
    def test_whole_table(self) -> None:
        """B-1: without mTLS the add-on never hides visitor addresses -
        whatever the option (also unknown ones) and the last result."""
        for option in upstream.OPTIONS + ("", "bogus"):
            for decisive in (A, R, None, U, "x"):
                with self.subTest(option=option, decisive=decisive):
                    self.assertEqual(upstream.decide(option, False, decisive), "pass")


class CardStateTest(unittest.TestCase):
    def state(self, **kw) -> upstream.State:
        return upstream.State(upstream="homeassistant:8123", **kw)

    def test_states(self) -> None:
        auto = upstream.Settings("home.example.com", "homeassistant", 8123, True, "auto")
        always = upstream.Settings("home.example.com", "homeassistant", 8123, True, "always")
        never = upstream.Settings("home.example.com", "homeassistant", 8123, True, "never")
        cases = [
            (auto, None, "unknown"),
            (auto, self.state(), "unknown"),
            (auto, self.state(result=A, decisive=A, mode="pass", reachable=True), "accepted"),
            (auto, self.state(result=R, decisive=R, mode="strip", reachable=True), "strip"),
            (auto, self.state(result=R, decisive=R, mode="pass", reachable=True), "broken"),
            (always, self.state(result=R, decisive=R, mode="pass", reachable=True), "broken"),
            (always, self.state(result=A, decisive=A, mode="pass", reachable=True), "accepted"),
            (never, self.state(result=A, decisive=A, mode="strip", reachable=True), "never"),
            (never, self.state(result=R, decisive=R, mode="strip", reachable=True), "never"),
            (auto, self.state(result=U, decisive=R, mode="strip", reachable=False), "unreachable"),
            (never, self.state(result=U, mode="strip", reachable=False), "unreachable"),
            # B-2: what Caddy runs counts; a failed reload is red.
            (auto, self.state(result=R, decisive=R, mode="strip", running="pass", applied=False,
                              reachable=True, reload_error="x"), "reload_failed"),
            (auto, self.state(result=R, decisive=R, mode="strip", running="pass", reachable=True), "broken"),
            # B2-3: nothing known and the add-on stopped retrying slow tests.
            (auto, self.state(reachable=True, slow_tests=2), "unknown"),
            (auto, self.state(reachable=True, slow_tests=3), "too_slow"),
            (auto, self.state(slow_tests=3), "too_slow"),
            (auto, self.state(result=U, reachable=False, slow_tests=3), "unreachable"),
            (auto, self.state(result=R, decisive=R, mode="strip", reachable=True, slow_tests=3), "strip"),
            (never, self.state(reachable=True, mode="strip", slow_tests=3), "never"),
        ]
        for settings, state, expected in cases:
            with self.subTest(option=settings.option, state=state):
                self.assertEqual(upstream.card_state(settings, state), expected)

    def test_broken_and_hidden_follow_what_caddy_runs(self) -> None:
        auto = upstream.Settings("home.example.com", "homeassistant", 8123, True, "auto")
        failed_to_strip = self.state(result=R, decisive=R, mode="strip", running="pass",
                                     applied=False, reachable=True)
        self.assertTrue(upstream.is_broken(auto, failed_to_strip))
        failed_to_pass = self.state(result=A, decisive=A, mode="pass", running="strip",
                                    applied=False, reachable=True, hidden_at_runtime=True)
        self.assertFalse(upstream.is_broken(auto, failed_to_pass))
        self.assertTrue(upstream.is_hidden(failed_to_pass))
        self.assertFalse(upstream.is_hidden(self.state(mode="strip", hidden_at_runtime=False)))

    def test_texts_mid_sentence_and_card_title(self) -> None:
        """B-7: no capital "The upstream" inside a sentence; the card title
        per upstream."""
        other = upstream.Settings("d", "192.0.2.10", 8080, True)
        ha = upstream.Settings("d", "homeassistant", 8123, True)
        self.assertEqual(upstream.upstream_name(other), "the upstream 192.0.2.10:8080")
        self.assertEqual(upstream.upstream_name(other, start=True), "The upstream 192.0.2.10:8080")
        self.assertEqual(upstream.card_title(other), "Upstream connection")
        self.assertEqual(upstream.card_title(ha), "Home Assistant connection")
        self.assertEqual(upstream.unreachable_effect("connect"), "visitors get 502 Bad Gateway")
        self.assertNotIn("502", upstream.unreachable_effect("timeout"))

    def test_an_error_answer_is_an_answer(self) -> None:
        """A 5xx: "answers with an error (HTTP 503)", not "does not answer"."""
        answered = self.state(reachable=False, error="answered HTTP 503", error_kind="http", control_status=503)
        self.assertEqual(upstream.unreachable_reason(answered), ("answers with an error", "HTTP 503"))
        refused = self.state(reachable=False, error="[Errno 111] Connection refused", error_kind="connect")
        self.assertEqual(upstream.unreachable_reason(refused),
                         ("does not answer", "[Errno 111] Connection refused"))
        self.assertEqual(upstream.unreachable_reason(self.state()), ("does not answer", "no answer"))


class SuggestionTest(unittest.TestCase):
    def test_suggestion(self) -> None:
        cases = {
            "172.30.33.3": "172.30.33.0/24",
            "172.30.33.250": "172.30.33.0/24",
            "172.30.32.5": "172.30.32.5",  # not in Home Assistant's documented network
            "10.233.44.2": "10.233.44.2",
            "fd0c:ac1e:2100::5": "fd0c:ac1e:2100::5",
            "fe80::1%eth0": "fe80::1",
            "": "172.30.33.0/24",
            "nonsense": "172.30.33.0/24",
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertEqual(upstream.trusted_proxy_suggestion(source), expected)

    def test_yaml_block(self) -> None:
        self.assertEqual(
            upstream.yaml_block("172.30.33.0/24"),
            "http:\n  use_x_forwarded_for: true\n  trusted_proxies:\n    - 172.30.33.0/24\n",
        )

    def test_texts_name_the_upstream(self) -> None:
        ha = upstream.Settings("home.example.com", "homeassistant", 8123, True)
        other = upstream.Settings("home.example.com", "192.0.2.10", 8080, True)
        self.assertEqual(upstream.upstream_name(ha), "Home Assistant")
        self.assertEqual(upstream.upstream_name(other), "the upstream 192.0.2.10:8080")
        steps = " ".join(upstream.fix_steps(ha, "172.30.33.0/24"))
        for text in ("Settings > System > Network", '"HTTP server"', '"Reverse proxy"',
                     '"Trust X-Forwarded-For"', "add 172.30.33.0/24 to \"Trusted proxies\"",
                     '"Save and restart"', '"Confirm"', "5 minutes"):
            self.assertIn(text, steps)
        consequences = " ".join(upstream.strip_consequences(ha, "172.30.33.3"))
        for text in ("Can only log in from the local network", "Only accessible from the local network",
                     "ip_bans.yaml", "trusted networks", "172.30.33.3"):
            self.assertIn(text, consequences)
        # A different upstream: no Home Assistant steps or claims.
        for text in upstream.fix_steps(other, "172.30.33.0/24") + upstream.strip_consequences(other, "x"):
            self.assertNotIn("Home Assistant", text)


class SnippetTest(TempFiles):
    def test_render(self) -> None:
        passing = upstream.render_snippet("pass")
        self.assertIn("header_up X-Real-IP {remote_host}\n", passing)
        self.assertIn("header_up -Forwarded\n", passing)
        self.assertNotIn("-X-Forwarded-For", passing)
        strip = upstream.render_snippet("strip")
        for header in ("X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Real-IP", "Forwarded"):
            self.assertIn(f"header_up -{header}\n", strip)
        self.assertNotIn("{remote_host}", strip)
        # Only comments and header_up lines (it is imported into reverse_proxy).
        for text in (passing, strip):
            for line in text.splitlines():
                self.assertTrue(line.startswith(("#", "header_up ")), line)

    def test_write_is_atomic_and_readable(self) -> None:
        self.assertIsNone(upstream.snippet_mode())
        upstream.write_snippet("strip", mtls=True)
        self.assertEqual(upstream.snippet_mode(), "strip")
        self.assertEqual(os.stat(upstream.SNIPPET_FILE).st_mode & 0o777, 0o644)
        upstream.write_snippet("pass", mtls=True)
        self.assertEqual(upstream.snippet_mode(), "pass")
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["forwarded-headers.caddy"])

    def test_no_strip_lines_without_mtls(self) -> None:
        """B2-2: whatever a caller asks, without mTLS the pass lines."""
        upstream.write_snippet("strip", mtls=False)
        self.assertEqual(upstream.snippet_mode(), "pass")

    def test_no_snippet_command(self) -> None:
        """B2-2: the command that wrote a mode without asking mTLS is gone
        (init-caddy only runs ``start``)."""
        with contextlib.redirect_stderr(open(os.devnull, "w")) as err, self.assertRaises(SystemExit):
            upstream._main(["snippet", "--mode", "strip"])
        err.close()
        self.assertIsNone(upstream.snippet_mode())


class StateTest(TempFiles):
    def test_round_trip_and_mode(self) -> None:
        self.assertIsNone(upstream.load_state())
        state = upstream.State(upstream="homeassistant:8123", result=R, decisive=R, mode="strip",
                               reachable=True, source_address="172.30.33.3")
        upstream.save_state(state)
        self.assertEqual(os.stat(upstream.STATE_FILE).st_mode & 0o777, 0o600)
        settings = upstream.Settings("home.example.com", "homeassistant", 8123, True)
        loaded = upstream.load_state(settings)
        self.assertEqual(loaded, state)

    def test_another_upstream_forgets_the_result(self) -> None:
        upstream.save_state(upstream.State(upstream="homeassistant:8123", result=R, decisive=R,
                                           mode="strip", reachable=True))
        other = upstream.Settings("home.example.com", "homeassistant", 80, True)
        loaded = upstream.load_state(other)
        self.assertIsNone(loaded.decisive)
        self.assertEqual(loaded.upstream, "homeassistant:80")
        self.assertEqual(loaded.mode, "strip")  # what the snippet holds until decided

    def test_garbage(self) -> None:
        upstream.STATE_FILE.write_text("{not json")
        self.assertIsNone(upstream.load_state())
        upstream.STATE_FILE.write_text(json.dumps({"result": "x", "decisive": "y", "mode": "z", "foo": 1}))
        state = upstream.load_state()
        self.assertEqual((state.result, state.decisive, state.mode), ("unknown", None, "pass"))

    def test_settings_from_runtime(self) -> None:
        self.assertIsNone(upstream.Settings.from_runtime({"domain": "x"}))  # before 2.2.0
        s = upstream.Settings.from_runtime({"domain": "home.example.com", "upstream_host": "homeassistant",
                                            "upstream_port": 8123, "mtls_enabled": True,
                                            "forwarded_headers": "never"})
        self.assertEqual(s, upstream.Settings("home.example.com", "homeassistant", 8123, True, "never"))
        s = upstream.Settings.from_runtime({"upstream_host": "h", "upstream_port": 1, "forwarded_headers": "x"})
        self.assertEqual((s.option, s.mtls), ("auto", False))
        self.assertEqual(upstream.Settings("d", "::1", 8123, True).target, "[::1]:8123")


class ProbeTest(TempFiles):
    def setUp(self) -> None:
        super().setUp()
        self.ha = FakeHomeAssistant()
        self.addCleanup(self.ha.stop)

    def test_refused_then_accepted(self) -> None:
        settings = self.settings(self.ha.port)
        result = upstream.probe(settings)
        self.assertEqual((result.result, result.control_status, result.test_status), (R, 200, 400))
        self.assertEqual(result.source_address, "127.0.0.1")
        self.assertTrue(result.test_sent)
        self.assertEqual(self.ha.refusals, 1)
        control, test = self.ha.requests
        self.assertEqual((control["forwarded"], control["host"]), (False, "home.example.com"))
        self.assertEqual(test["xff"], upstream.TEST_CLIENT)
        self.ha.trust = True
        result = upstream.probe(settings)
        self.assertEqual((result.result, result.test_status), (A, 200))
        self.assertEqual(self.ha.refusals, 1)

    def test_control_only(self) -> None:
        result = upstream.probe(self.settings(self.ha.port), test=False)
        self.assertEqual(result.result, upstream.REACHABLE)
        self.assertEqual(self.ha.tests, 0)

    def test_unreachable(self) -> None:
        self.ha.stop()
        result = upstream.probe(self.settings(self.ha.port))
        self.assertEqual((result.result, result.kind), (U, "connect"))
        self.assertFalse(result.test_sent)
        self.assertTrue(result.error)
        self.ha.start()
        self.ha.status = 502
        result = upstream.probe(self.settings(self.ha.port))
        self.assertEqual((result.result, result.control_status), (U, 502))
        self.assertEqual(self.ha.tests, 0)

    def test_unknown_host_fails_fast(self) -> None:
        result = upstream.probe(self.settings(8123, host="nonexistent.invalid"), deadline=5)
        self.assertEqual(result.result, U)

    def test_silent_host_respects_the_deadline(self) -> None:
        # A listening socket that never answers (accept backlog only).
        with socket.socket() as silent:
            silent.bind(("127.0.0.1", 0))
            silent.listen(8)
            port = silent.getsockname()[1]
            import time
            start = time.monotonic()
            result = upstream.probe(self.settings(port), timeout=1.0, deadline=2.0)
            self.assertLess(time.monotonic() - start, 3.0)
        # Connected, no answer: slow (no decision), not unreachable (B-6).
        self.assertEqual((result.result, result.kind), (upstream.SLOW, "timeout"))

    def test_slow_upstream(self) -> None:
        self.ha.delay = 1.0
        result = upstream.probe(self.settings(self.ha.port), timeout=0.3)
        self.assertEqual((result.result, result.kind, result.test_sent), (upstream.SLOW, "timeout", False))


class ControlChannelTest(TempFiles):
    def test_keep_alive_and_restart(self) -> None:
        ha = FakeHomeAssistant()
        self.addCleanup(ha.stop)
        channel = upstream.ControlChannel(self.settings(ha.port))
        self.addCleanup(channel.close)
        self.assertEqual(channel.check()[0].result, upstream.REACHABLE)
        self.assertEqual(channel.check(), (mock.ANY, False))  # reused
        self.assertEqual(len(ha.conns), 1)  # one connection for both
        ha.restart()
        result, interrupted = channel.check()
        self.assertEqual((result.result, interrupted), (upstream.REACHABLE, True))
        self.assertEqual(channel.check()[1], False)
        self.assertEqual(ha.tests, 0)  # control requests only
        ha.stop()
        result, interrupted = channel.check()
        self.assertEqual(result.result, U)

    def test_restart_before_the_first_reuse(self) -> None:
        """B-4: the connection is lost before it was ever reused."""
        ha = FakeHomeAssistant()
        self.addCleanup(ha.stop)
        channel = upstream.ControlChannel(self.settings(ha.port))
        self.addCleanup(channel.close)
        self.assertEqual(channel.check()[1], False)  # new connection
        ha.restart()  # right after the connect
        result, came_back = channel.check()
        self.assertEqual((result.result, came_back), (upstream.REACHABLE, True))
        self.assertEqual(channel.check()[1], False)

    def test_restart_while_down_is_reported_when_back(self) -> None:
        ha = FakeHomeAssistant()
        self.addCleanup(ha.stop)
        channel = upstream.ControlChannel(self.settings(ha.port))
        self.addCleanup(channel.close)
        channel.check()
        ha.stop()
        self.assertEqual(channel.check()[0].result, U)  # lost, then the connect is refused
        ha.start()
        self.assertEqual(channel.check(), (mock.ANY, True))

    def test_upstream_closing_idle_connections_is_no_restart(self) -> None:
        """An upstream that closes idle connections itself after a short
        time: at most one false "restart" (B-4's guard)."""
        ha = FakeHomeAssistant()
        ha.idle_close = 0.05
        self.addCleanup(ha.stop)
        channel = upstream.ControlChannel(self.settings(ha.port))
        self.addCleanup(channel.close)
        came_back = []
        for _ in range(8):
            result, back = channel.check()
            self.assertEqual(result.result, upstream.REACHABLE)
            came_back.append(back)
            time.sleep(0.15)
        self.assertLessEqual(sum(came_back), 1)

    def test_two_quick_restarts_of_home_assistant(self) -> None:
        """Two restarts before a reuse (seen on a real Core: "Save and
        restart" right after another restart): both noticed for Home
        Assistant; a third loss in a row counts as an idle-closing server."""
        ha = FakeHomeAssistant()
        self.addCleanup(ha.stop)
        real = socket.getaddrinfo
        patcher = mock.patch.object(socket, "getaddrinfo", side_effect=lambda h, *a, **k: real(
            "127.0.0.1" if h == "homeassistant" else h, *a, **k))
        patcher.start()
        self.addCleanup(patcher.stop)
        channel = upstream.ControlChannel(self.settings(ha.port, host="homeassistant"))
        self.addCleanup(channel.close)
        channel.check()
        backs = []
        for _ in range(3):
            ha.restart()
            backs.append(channel.check()[1])
        self.assertEqual(backs, [True, True, False])
        channel.check()  # a successful reuse
        ha.restart()
        self.assertEqual(channel.check()[1], True)

    def test_announced_short_keep_alive_is_no_restart(self) -> None:
        ha = FakeHomeAssistant()
        ha.idle_close = 0.05
        ha.keep_alive_header = "timeout=1, max=100"
        self.addCleanup(ha.stop)
        channel = upstream.ControlChannel(self.settings(ha.port), interval=12)
        self.addCleanup(channel.close)
        for _ in range(5):
            self.assertEqual(channel.check(), (mock.ANY, False))
            time.sleep(0.1)

    def test_slow_is_not_down(self) -> None:
        """B-6: one timeout = slow; two failures in a row = unreachable; a
        refused connect = unreachable at once; a slow kept connection is no
        restart; one 5xx is a failure too."""
        ha = FakeHomeAssistant()
        self.addCleanup(ha.stop)
        channel = upstream.ControlChannel(self.settings(ha.port), timeout=0.3)
        self.addCleanup(channel.close)
        channel.check()
        ha.delay = 1.0
        first, back = channel.check()
        self.assertEqual((first.result, first.kind, back), (upstream.SLOW, "timeout", False))
        ha.delay = 0.0
        result, back = channel.check()
        self.assertEqual((result.result, back), (upstream.REACHABLE, False))  # dropped by us: no restart
        ha.delay = 1.0
        self.assertEqual(channel.check()[0].result, upstream.SLOW)
        second = channel.check()[0]
        self.assertEqual((second.result, second.kind), (U, "timeout"))
        ha.delay = 0.0
        self.assertEqual(channel.check()[0].result, upstream.REACHABLE)
        ha.stop()
        refused = channel.check()[0]
        self.assertEqual((refused.result, refused.kind), (U, "connect"))
        ha.start()
        ha.status = 503
        self.assertEqual(channel.check()[0].result, U)  # still: the refused connect was failure 1
        ha.status = 200
        self.assertEqual(channel.check()[0].result, upstream.REACHABLE)
        ha.status = 503
        self.assertEqual(channel.check()[0].result, upstream.SLOW)  # one 5xx: a failure
        self.assertEqual(channel.check()[0].result, U)

    def test_no_keep_alive_is_no_restart(self) -> None:
        ha = FakeHomeAssistant(keep_alive=False)
        self.addCleanup(ha.stop)
        channel = upstream.ControlChannel(self.settings(ha.port))
        for _ in range(4):
            result, interrupted = channel.check()
            self.assertEqual((result.result, interrupted), (upstream.REACHABLE, False))


class ApplyTest(TempFiles):
    """check / watch_once / retry_apply with a fake Home Assistant and a
    recorded reload."""

    def setUp(self) -> None:
        super().setUp()
        self.ha = FakeHomeAssistant()
        self.addCleanup(self.ha.stop)

    def test_auto_switches_both_ways(self) -> None:
        s = self.settings(self.ha.port)
        out = upstream.check(s, reload=self.reload, now=100.0)
        self.assertEqual((out.card, out.state.mode, out.switched), ("strip", "strip", True))
        self.assertEqual(self.reloads, ["strip"])
        self.assertEqual(upstream.snippet_mode(), "strip")
        out = upstream.check(s, reload=self.reload, now=110.0)  # unchanged: no reload
        self.assertEqual((out.card, out.switched), ("strip", False))
        self.assertEqual(self.reloads, ["strip"])
        self.ha.trust = True
        out = upstream.check(s, reload=self.reload, now=120.0)
        self.assertEqual((out.card, out.state.mode, out.previous_mode, out.switched),
                         ("accepted", "pass", "strip", True))
        self.assertEqual(self.reloads, ["strip", "pass"])
        self.assertEqual(upstream.load_state(s).changed_at, 120.0)

    def test_without_mtls_or_always_it_stays_broken(self) -> None:
        for settings in (self.settings(self.ha.port, mtls=False), self.settings(self.ha.port, "always")):
            with self.subTest(settings=settings):
                upstream.STATE_FILE.unlink(missing_ok=True)
                out = upstream.check(settings, reload=self.reload)
                self.assertEqual((out.card, out.state.mode), ("broken", "pass"))

    def test_never(self) -> None:
        out = upstream.check(self.settings(self.ha.port, "never"), reload=self.reload)
        self.assertEqual((out.card, out.state.mode, out.state.decisive), ("never", "strip", R))

    def test_unreachable_keeps_the_last_known_mode(self) -> None:
        s = self.settings(self.ha.port)
        upstream.check(s, reload=self.reload)
        self.ha.stop()
        out = upstream.check(s, reload=self.reload)
        self.assertEqual((out.card, out.state.mode, out.state.decisive, out.state.reachable),
                         ("unreachable", "strip", R, False))
        self.assertEqual(self.reloads, ["strip"])

    def test_first_start_unreachable_is_pass(self) -> None:
        self.ha.stop()
        out = upstream.check(self.settings(self.ha.port), reload=None)
        self.assertEqual((out.card, out.state.mode), ("unreachable", "pass"))
        self.assertEqual(upstream.snippet_mode(), "pass")  # written for Caddy's start

    def test_reload_failure_is_retried(self) -> None:
        s = self.settings(self.ha.port)
        self.reload_ok = False
        out = upstream.check(s, reload=self.reload)
        self.assertEqual((out.state.mode, out.state.applied), ("strip", False))
        self.assertTrue(out.reload_error)
        self.reload_ok = True
        out = upstream.retry_apply(s, reload=self.reload)
        self.assertTrue(out.state.applied)
        self.assertEqual(self.reloads, ["strip", "strip"])
        self.assertEqual(self.ha.tests, 1)  # the retry asked nobody

    def test_missing_snippet_is_rewritten(self) -> None:
        s = self.settings(self.ha.port)
        upstream.check(s, reload=self.reload)
        upstream.SNIPPET_FILE.unlink()
        upstream.check(s, reload=self.reload)
        self.assertEqual(upstream.snippet_mode(), "strip")

    def test_watch_once_tests_only_when_it_came_back(self) -> None:
        s = self.settings(self.ha.port)
        upstream.check(s, reload=self.reload)  # start: refused -> strip
        channel = upstream.ControlChannel(s)
        self.addCleanup(channel.close)
        for _ in range(5):
            out = upstream.watch_once(s, channel, reload=self.reload)
        self.assertEqual((out.card, self.ha.tests), ("strip", 1))
        # Home Assistant goes down and comes back trusting the add-on.
        self.ha.stop()
        out = upstream.watch_once(s, channel, reload=self.reload)
        self.assertEqual((out.card, out.state.mode), ("unreachable", "strip"))
        self.ha.trust = True
        self.ha.start()
        out = upstream.watch_once(s, channel, reload=self.reload)
        self.assertEqual((out.card, out.state.mode, self.ha.tests), ("accepted", "pass", 2))
        # A restart that is quicker than the watch (the kept-alive
        # connection broke): tested again.
        channel2 = upstream.ControlChannel(s)
        self.addCleanup(channel2.close)
        upstream.watch_once(s, channel2, reload=self.reload)
        upstream.watch_once(s, channel2, reload=self.reload)
        self.assertEqual(self.ha.tests, 2)
        self.ha.trust = False
        self.ha.restart()
        out = upstream.watch_once(s, channel2, reload=self.reload)
        self.assertEqual((out.card, out.state.mode, self.ha.tests), ("strip", "strip", 3))

    def test_failed_reload_shows_what_caddy_runs(self) -> None:
        """B-2: the snippet goes back to the running mode, the card is red,
        is_broken follows the running mode; a retry applies it."""
        s = self.settings(self.ha.port)
        self.ha.trust = True
        upstream.check(s, reload=self.reload)  # accepted: pass
        self.ha.trust = False
        self.reload_ok = False
        out = upstream.check(s, reload=self.reload)
        st = out.state
        self.assertEqual((st.mode, st.running, st.applied, out.card), ("strip", "pass", False, "reload_failed"))
        self.assertEqual(st.reload_error, "admin API down")
        self.assertEqual(upstream.snippet_mode(), "pass")  # what Caddy runs
        self.assertTrue(upstream.is_broken(s, st))
        self.assertFalse(out.switched)
        self.assertFalse(upstream.is_hidden(st))  # Caddy still passes them on
        self.reload_ok = True
        out = upstream.retry_apply(s, reload=self.reload)
        self.assertEqual((out.state.running, out.state.applied, out.card, out.switched),
                         ("strip", True, "strip", True))
        self.assertEqual(upstream.snippet_mode(), "strip")
        # A run-time loss of trust (B-12), also across the failed reload.
        self.assertTrue(upstream.is_hidden(out.state))

    def test_no_strip_without_mtls_after_a_failed_reload(self) -> None:
        """B2-2: option x stored state x failing reload, mTLS off: the
        write-back and ``running`` are pass, never strip."""
        self.reload_ok = False
        combos = 0
        for option in upstream.OPTIONS:
            s = self.settings(self.ha.port, option, mtls=False)
            for mode in ("pass", "strip"):
                for running in ("pass", "strip", None):
                    for applied in (True, False):
                        for decisive in (A, R, None):
                            for call in ("retry_apply", "check"):
                                with self.subTest(option=option, mode=mode, running=running, applied=applied,
                                                  decisive=decisive, call=call):
                                    combos += 1
                                    upstream.save_state(upstream.State(
                                        upstream=s.target, decisive=decisive, mode=mode, running=running,
                                        applied=applied, reachable=True))
                                    upstream.SNIPPET_FILE.write_text(upstream.render_snippet("strip"))
                                    if call == "check":
                                        out = upstream.check(s, reload=self.reload)
                                    else:
                                        out = upstream.retry_apply(s, reload=self.reload)
                                    self.assertEqual(upstream.snippet_mode(), "pass")
                                    self.assertIn(out.state.running, ("pass", None))
                                    self.assertEqual(out.state.running_mode, "pass")
                                    self.assertEqual(upstream.load_state(s).running_mode, "pass")
                                    self.assertFalse(upstream.is_hidden(out.state))
        self.assertEqual(combos, 3 * 2 * 3 * 2 * 3 * 2)
        self.assertNotIn("strip", self.reloads)  # Caddy was never asked to load strip

    def test_reload_error_is_capped(self) -> None:
        """A very long Caddy error: about 500 characters are kept (state,
        log, card)."""
        s = self.settings(self.ha.port)
        out = upstream.check(s, reload=lambda: (False, "x" * 5000))
        self.assertEqual(len(out.state.reload_error), upstream.RELOAD_ERROR_MAX)
        self.assertTrue(out.state.reload_error.endswith("..."))
        self.assertEqual(out.reload_error, out.state.reload_error)
        self.assertEqual(upstream.load_state(s).reload_error, out.state.reload_error)

    def test_hidden_only_at_run_time(self) -> None:
        """B-12: starting in strip is no "hidden at run time"; a run-time
        switch is; passing addresses on again clears it; a start clears it."""
        s = self.settings(self.ha.port)
        upstream.start(s)
        self.assertFalse(upstream.load_state(s).hidden_at_runtime)
        self.ha.trust = True
        upstream.check(s, reload=self.reload)
        self.assertFalse(upstream.load_state(s).hidden_at_runtime)
        self.ha.trust = False
        out = upstream.check(s, reload=self.reload)
        self.assertTrue(out.state.hidden_at_runtime)
        upstream.start(s)
        self.assertFalse(upstream.load_state(s).hidden_at_runtime)

    def test_hidden_only_after_trust(self) -> None:
        """B2-1: a first decision at run time (start with the upstream down
        or slow) is no loss of trust; a refusal after an acceptance is."""
        s = self.settings(self.ha.port)
        for how in ("down", "slow"):
            with self.subTest(start=how):
                upstream.STATE_FILE.unlink(missing_ok=True)
                self.ha.trust = False
                if how == "down":
                    self.ha.stop()
                    upstream.start(s)
                    self.ha.start()
                else:
                    self.ha.delay = 1.0
                    with mock.patch.object(upstream, "REQUEST_TIMEOUT", 0.3):
                        upstream.start(s)
                    self.ha.delay = 0.0
                self.assertIsNone(upstream.load_state(s).decisive)
                out = upstream.check(s, reload=self.reload)  # decided at run time: refused
                self.assertEqual((out.state.running_mode, out.switched), ("strip", True))
                self.assertFalse(out.state.hidden_at_runtime)
                self.assertFalse(upstream.is_hidden(out.state))
                # Trusted, then not: that is a loss of trust.
                self.ha.trust = True
                upstream.check(s, reload=self.reload)
                self.ha.trust = False
                out = upstream.check(s, reload=self.reload)
                self.assertTrue(upstream.is_hidden(out.state))

    def test_slow_check_changes_nothing(self) -> None:
        s = self.settings(self.ha.port)
        upstream.check(s, reload=self.reload)
        before = upstream.load_state(s)
        self.ha.delay = 1.0
        with mock.patch.object(upstream, "WATCH_TIMEOUT", 0.3):
            out = upstream.check(s, reload=self.reload)
        self.assertEqual(out.probe.result, upstream.SLOW)
        before.slow_tests = 1  # only counted (B2-3)
        self.assertEqual(upstream.load_state(s), before)

    def test_start_while_slow(self) -> None:
        s = self.settings(self.ha.port)
        self.ha.delay = 1.0
        with mock.patch.object(upstream, "REQUEST_TIMEOUT", 0.3):
            facts = upstream.start(s)
        self.assertEqual((facts["card"], facts["error_kind"], facts["mode"]), ("unknown", "timeout", "pass"))
        self.assertNotIn("502", facts["effect"])

    def test_reload_error_keeps_only_caddys_error_line(self) -> None:
        """The CLI's timestamped log lines differ at every retry; the error
        logged once is Caddy's "Error:" line."""
        stderr = ("2026/11/27 14:20:40.123\tINFO\tusing config from file\n"
                  "Error: adapting config using caddyfile: /etc/caddy/Caddyfile:42 - unexpected EOF\n")
        done = mock.Mock(returncode=1, stderr=stderr, stdout="")
        with mock.patch.object(upstream.subprocess, "run", return_value=done), \
                mock.patch.object(upstream.caddyctl, "write_fingerprints") as regenerate, \
                mock.patch.object(upstream, "CADDYFILE", upstream.STATE_FILE):
            upstream.STATE_FILE.write_text("{}")
            ok, message = upstream.caddy_reload()
        self.assertFalse(ok)
        # 2.3.0: the fingerprint list was regenerated before the reload.
        regenerate.assert_called_once_with()
        self.assertEqual(message, "Error: adapting config using caddyfile: /etc/caddy/Caddyfile:42 - unexpected EOF")
        # Caddy 2.11.9 prints the error as a JSON log line with a timestamp.
        caddy_2_11 = ('{"level":"info","ts":1795789792.1,"msg":"using config from file"}\n'
                      '{"level":"error","ts":1795789792.92,"msg":"adapting config using caddyfile: syntax '
                      'error: unexpected token \'{\', expecting \'}\', at /etc/caddy/Caddyfile:80"}\n')
        self.assertEqual(upstream._cli_error(caddy_2_11),
                         "adapting config using caddyfile: syntax error: unexpected token '{', "
                         "expecting '}', at /etc/caddy/Caddyfile:80")

    def test_start_reports_the_facts(self) -> None:
        facts = upstream.start(self.settings(self.ha.port))
        self.assertEqual((facts["card"], facts["mode"], facts["source_address"], facts["suggestion"]),
                         ("strip", "strip", "127.0.0.1", "127.0.0.1"))
        self.assertFalse(facts["is_home_assistant"])

    def test_lock_serialises(self) -> None:
        with upstream.locked():
            with self.assertRaises(TimeoutError):
                # A second holder (another process: flock is per open file).
                with upstream.locked(timeout=0.3):
                    pass


class UpstreamWatchTest(TempFiles):
    """monitor.UpstreamWatch with a mocked clock: which requests reach Home
    Assistant (the noise rules) and the notification."""

    def setUp(self) -> None:
        super().setUp()
        self.ha = FakeHomeAssistant()
        self.addCleanup(self.ha.stop)
        self.runtime = self.dir / "runtime.json"
        self.calls: list[tuple[str, str, dict]] = []

        def fake_request(method: str, path: str, payload: dict | None = None) -> bool:
            self.calls.append((method, path, payload or {}))
            return True

        for target, name, value in (
            (monitor, "_supervisor_request", mock.Mock(side_effect=fake_request)),
            (monitor, "UPSTREAM_CONTROL_INTERVAL", 12.0),
            (monitor, "UPSTREAM_TEST_INTERVAL", 60.0),
            (monitor, "UPSTREAM_FAST_INTERVAL", 2.5),
        ):
            patcher = mock.patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.dict(os.environ, {"CADDY_MTLS_RUNTIME_FILE": str(self.runtime)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def write_runtime(self, option: str = "auto", mtls: bool = True) -> upstream.Settings:
        self.runtime.write_text(json.dumps({
            "domain": "home.example.com", "upstream_host": "homeassistant", "upstream_port": self.ha.port,
            "mtls_enabled": mtls, "forwarded_headers": option,
        }))
        return upstream.Settings.load(self.runtime)

    def creates(self, nid: str = "caddy_mtls_upstream_refuses") -> list[dict]:
        return [p for _, path, p in self.calls
                if path.endswith("/persistent_notification/create") and p["notification_id"] == nid]

    def dismisses(self, nid: str = "caddy_mtls_upstream_refuses") -> list[dict]:
        return [p for _, path, p in self.calls
                if path.endswith("/persistent_notification/dismiss") and p["notification_id"] == nid]

    def make_watch(self) -> monitor.UpstreamWatch:
        watch = monitor.UpstreamWatch(started=0.0, reload=self.reload)
        self.addCleanup(lambda: watch.channel is not None and watch.channel.close())
        return watch

    def run_watch(self, watch: monitor.UpstreamWatch, start: float, seconds: float) -> float:
        """Tick like main() does for ``seconds`` of mocked time; returns the
        end time."""
        now = start
        end = start + seconds
        while now < end:
            interval = watch.tick(now)
            self.assertGreater(interval, 0)
            now += interval
        return now

    def resolve_homeassistant(self):
        """'homeassistant' -> 127.0.0.1 (the fake's address)."""
        real = socket.getaddrinfo

        def fake(host, *args, **kwargs):
            return real("127.0.0.1" if host == "homeassistant" else host, *args, **kwargs)

        patcher = mock.patch.object(socket, "getaddrinfo", side_effect=fake)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_strip_sends_no_test_until_a_restart(self) -> None:
        self.resolve_homeassistant()
        s = self.write_runtime()
        upstream.start(s)  # init-caddy: one test, refused -> strip
        self.assertEqual(self.ha.refusals, 1)
        watch = self.make_watch()
        with captured_logs() as logs:
            t = self.run_watch(watch, 0.0, 24 * 3600)  # a day
            self.assertEqual(self.ha.refusals, 1)  # strip: no test request at all
            self.assertGreater(len(self.ha.requests), 24 * 3600 / 12 - 5)  # control every 12 s
            # The user trusts the add-on and restarts Home Assistant.
            self.ha.trust = True
            self.ha.restart()
            t = self.run_watch(watch, t, 30)
        self.assertEqual(upstream.load_state(s).mode, "pass")
        self.assertEqual(self.reloads, ["pass"])
        self.assertIn("mode strip -> pass", "\n".join(r.getMessage() for r in logs))
        self.assertEqual(self.creates(), [])  # strip and accepted: no notification
        self.assertEqual(len(self.dismisses()), 1)  # once after the start (a previous run's)
        # Accepted: a test every 60 s, Home Assistant logs nothing.
        tests_before = self.ha.tests
        t = self.run_watch(watch, t, 3600)
        self.assertAlmostEqual(self.ha.tests - tests_before, 60, delta=2)
        self.assertEqual(self.ha.refusals, 1)
        # Trust lost (another restart): noticed by the next test, one line.
        self.ha.trust = False
        self.ha.restart()
        t = self.run_watch(watch, t, 120)
        self.assertEqual(upstream.load_state(s).mode, "strip")
        self.assertEqual(self.ha.refusals, 2)
        self.run_watch(watch, t, 3600)
        self.assertEqual(self.ha.refusals, 2)

    def test_unreachable_at_boot_then_up(self) -> None:
        self.resolve_homeassistant()
        s = self.write_runtime()
        self.ha.stop()
        upstream.start(s)
        self.assertEqual(upstream.load_state(s).reachable, False)
        watch = self.make_watch()
        with captured_logs():
            t = self.run_watch(watch, 0.0, 120)
            self.assertEqual(self.ha.requests, [])
            self.ha.start()
            self.run_watch(watch, t, 13)
        self.assertEqual(self.ha.refusals, 1)  # tested once when it came up
        self.assertEqual(upstream.load_state(s).mode, "strip")

    def test_broken_raises_once_and_dismisses(self) -> None:
        self.resolve_homeassistant()
        s = self.write_runtime(option="always")
        upstream.start(s)
        watch = self.make_watch()
        with captured_logs() as logs:
            t = self.run_watch(watch, 0.0, 3600)
        self.assertEqual(self.ha.refusals, 1)  # always: same noise rules as strip
        creates = self.creates()
        self.assertEqual(len(creates), 1)
        note = creates[0]
        self.assertEqual(note["notification_id"], "caddy_mtls_upstream_refuses")
        self.assertEqual(note["title"], "Caddy mTLS: Home Assistant refuses the proxied requests")
        for text in ("400: Bad Request", "**home.example.com**", "127.0.0.1", "forwarded_headers is `always`",
                     "Trust X-Forwarded-For", "```yaml", "use_x_forwarded_for: true",
                     "`forwarded_headers` to `auto`"):
            self.assertIn(text, note["message"])
        self.assertEqual(self.dismisses(), [])
        warnings = [r for r in logs if r.levelname == "WARNING"]
        self.assertLessEqual(len(warnings), 1)
        self.ha.trust = True
        self.ha.restart()
        self.run_watch(watch, t, 30)
        self.assertEqual(len(self.dismisses()), 1)
        self.assertEqual(len(self.creates()), 1)

    def test_no_mtls_auto_is_broken(self) -> None:
        self.resolve_homeassistant()
        s = self.write_runtime(option="auto", mtls=False)
        upstream.start(s)
        watch = self.make_watch()
        with captured_logs():
            self.run_watch(watch, 0.0, 60)
        self.assertEqual(upstream.load_state(s).mode, "pass")
        note = self.creates()[0]
        self.assertIn("mtls_enabled: false", note["message"])
        self.assertNotIn("`forwarded_headers` to `auto`", note["message"])
        self.assertNotIn("`never`", note["message"])
        self.assertNotIn("forwarded_headers: never", note["message"])

    def run_until(self, watch: monitor.UpstreamWatch, start: float, done, limit: float) -> float:
        """Tick until ``done()``; returns the simulated seconds it took."""
        now = start
        while now - start <= limit:
            now += watch.tick(now)
            if done():
                return now - start
        self.fail(f"not done within {limit} s")

    def mode(self, s: upstream.Settings) -> str:
        return upstream.load_state(s).running_mode

    def test_lost_trust_is_noticed_at_the_next_control_request(self) -> None:
        """B-3: while passing addresses on, a restart without trust is
        noticed by the kept-alive control channel, not by the minute test."""
        self.resolve_homeassistant()
        s = self.write_runtime()
        self.ha.trust = True
        upstream.start(s)
        watch = self.make_watch()
        with captured_logs():
            t = self.run_watch(watch, 0.0, 30)
            self.assertEqual(self.mode(s), "pass")
            self.ha.trust = False
            self.ha.restart()
            took = self.run_until(watch, t, lambda: self.mode(s) == "strip", 70)
        self.assertLessEqual(took, 12.0)
        self.assertEqual(self.ha.refusals, 1)

    def test_restart_right_after_the_start(self) -> None:
        """B-4: Home Assistant restarts (now trusting) before the watch has
        reused its first connection."""
        self.resolve_homeassistant()
        s = self.write_runtime()
        upstream.start(s)  # refused: strip
        watch = self.make_watch()
        with captured_logs():
            watch.tick(0.0)  # opens the kept-alive connection
            self.ha.trust = True
            self.ha.restart()
            self.run_until(watch, 0.0, lambda: self.mode(s) == "pass", 13)
        self.assertEqual(self.ha.refusals, 1)

    def test_first_start_with_the_upstream_down_polls_fast(self) -> None:
        """B-5: nothing decided and no answer: every 2.5 s, then 12 s."""
        self.resolve_homeassistant()
        s = self.write_runtime()
        self.ha.stop()
        upstream.start(s)
        watch = self.make_watch()
        with captured_logs():
            self.assertEqual(watch.tick(0.0), 2.5)
            self.assertEqual(watch.tick(2.5), 2.5)
            self.ha.start()
            self.assertEqual(watch.tick(5.0), 12.0)
        self.assertEqual(self.mode(s), "strip")
        # B2-1: the first decision is no loss of trust - no "addresses hidden".
        self.assertEqual(self.creates("caddy_mtls_upstream_addresses_hidden"), [])
        self.assertEqual(watch.tick(17.0), 12.0)
        # Down (or restarting) later: fast again, until it is back.
        self.ha.stop()
        with captured_logs():
            self.assertEqual(watch.tick(29.0), 2.5)
            self.ha.start()
            self.assertEqual(watch.tick(31.5), 12.0)

    def test_fast_polling_backs_off_after_ten_minutes(self) -> None:
        """2.5 s for the first 10 minutes without an answer (from the start
        too: B-5 keeps its short window), then 12 s until it answers; the
        next period starts anew."""
        self.resolve_homeassistant()
        s = self.write_runtime()
        self.ha.stop()
        upstream.start(s)
        watch = self.make_watch()

        def intervals(start: float, until: float) -> list[tuple[float, float]]:
            now, seen = start, []
            while now < until:
                step = watch.tick(now)
                seen.append((now, step))
                now += step
            return seen

        with captured_logs():
            seen = intervals(0.0, 700.0)
            self.assertTrue(all(step == 2.5 for now, step in seen if now < 600), seen[:3])
            self.assertTrue(all(step == 12.0 for now, step in seen if now >= 600), seen[-3:])
            self.assertEqual(len([1 for now, _ in seen if now < 600]), 240)
            t = seen[-1][0] + seen[-1][1]
            self.ha.start()
            self.assertEqual(watch.tick(t), 12.0)  # answered: decided (strip)
            self.assertEqual(self.mode(s), "strip")
            self.ha.stop()
            seen = intervals(t + 12, t + 12 + 700)
        self.assertTrue(all(step == 2.5 for now, step in seen if now < t + 12 + 600))
        self.assertTrue(all(step == 12.0 for now, step in seen if now >= t + 12 + 600))
        self.assertEqual(self.ha.refusals, 1)

    def test_a_test_that_is_always_slow_is_given_up(self) -> None:
        """B2-3: the control request answers, the test request never in
        time: the next test at the normal interval, none after three until
        an event (restart, Check again, start); the card says so."""
        self.resolve_homeassistant()
        s = self.write_runtime()
        for name, value in (("WATCH_TIMEOUT", 0.3), ("REQUEST_TIMEOUT", 0.3)):
            patcher = mock.patch.object(upstream, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.ha.forwarded_delay = 1.0
        upstream.start(s)  # its test is slow too: nothing decided
        self.assertEqual(self.ha.tests, 1)
        watch = self.make_watch()
        with captured_logs() as logs:
            steps = [watch.tick(t) for t in (0.0, 12.0, 24.0)]
            self.assertEqual(steps, [12.0, 12.0, 12.0])  # not 2.5
            self.assertEqual(self.ha.tests, 4)
            st = upstream.load_state(s)
            self.assertEqual((st.slow_tests, upstream.card_state(s, st)), (3, "too_slow"))
            t = self.run_watch(watch, 36.0, 3600)
            self.assertEqual(self.ha.tests, 4)  # given up: none in an hour
            st = upstream.load_state(s)
            self.assertEqual((st.reachable, st.decisive, upstream.card_state(s, st)), (True, None, "too_slow"))
            warnings = [r.getMessage() for r in logs if r.levelno >= logging.WARNING]
            self.assertEqual(len(warnings), 1, warnings)
            self.assertIn("answers the test request too slowly to decide", warnings[0])
            # An event: Home Assistant restarts - three more tries.
            self.ha.restart()
            t = self.run_watch(watch, t, 600)
            self.assertEqual(self.ha.tests, 7)
            # "Check again": one more, and the add-on retries again.
            upstream.check(s, reload=self.reload)
            self.assertEqual((self.ha.tests, upstream.load_state(s).slow_tests), (8, 1))
            self.ha.forwarded_delay = 0.0
            self.run_watch(watch, t, 13)
        st = upstream.load_state(s)
        self.assertEqual((st.decisive, st.running_mode, st.slow_tests, upstream.card_state(s, st)),
                         (R, "strip", 0, "strip"))
        self.assertEqual(self.ha.tests, 9)
        # The add-on's start counts anew.
        st.slow_tests = 3
        upstream.save_state(st)
        upstream.start(s)
        self.assertEqual(upstream.load_state(s).slow_tests, 0)

    def test_an_error_answer_is_logged_as_an_answer(self) -> None:
        """A 5xx: "answers with an error (HTTP 503)", not "does not answer"."""
        self.resolve_homeassistant()
        s = self.write_runtime()
        upstream.start(s)
        watch = self.make_watch()
        with captured_logs() as logs:
            watch.tick(0.0)
            self.ha.status = 503
            watch.tick(12.0)
            watch.tick(14.5)
        self.assertEqual(upstream.card_state(s, upstream.load_state(s)), "unreachable")
        text = "\n".join(r.getMessage() for r in logs if r.levelno >= logging.WARNING)
        self.assertIn("Home Assistant answers with an error (HTTP 503): visitors get its error answers.", text)
        self.assertNotIn("does not answer", text)

    def test_restart_pending_and_slow_intervals(self) -> None:
        """Fast while the upstream restarts (it closed the kept connection
        and does not answer yet); not fast while it is merely slow."""
        self.resolve_homeassistant()
        s = self.write_runtime()
        patcher = mock.patch.object(upstream, "WATCH_TIMEOUT", 0.3)
        patcher.start()
        self.addCleanup(patcher.stop)
        upstream.start(s)
        watch = self.make_watch()
        with captured_logs():
            self.assertEqual(watch.tick(0.0), 12.0)
            self.ha.delay = 1.0
            self.assertEqual(watch.tick(12.0), 12.0)  # slow: no hurry
            self.ha.delay = 0.0
            self.assertEqual(watch.tick(24.0), 12.0)
            self.ha.restart()
            self.ha.delay = 1.0  # back, but busy starting
            self.assertEqual(watch.tick(36.0), 2.5)  # restart pending
            self.ha.delay = 0.0
            self.assertEqual(watch.tick(38.5), 12.0)
        self.assertEqual(self.ha.refusals, 2)  # the start, the test after the restart

    def test_a_pause_is_slow_not_down(self) -> None:
        """B-6: one control request without an answer changes nothing; two in
        a row make it unreachable (no claim of a 502), then one test."""
        self.resolve_homeassistant()
        s = self.write_runtime()
        patcher = mock.patch.object(upstream, "WATCH_TIMEOUT", 0.3)
        patcher.start()
        self.addCleanup(patcher.stop)
        upstream.start(s)
        watch = self.make_watch()
        with captured_logs() as logs:
            watch.tick(0.0)
            before = upstream.load_state(s)
            self.ha.delay = 1.0
            watch.tick(12.0)
            self.assertEqual(upstream.load_state(s), before)
            self.ha.delay = 0.0
            watch.tick(24.0)
            self.assertEqual(self.ha.refusals, 1)
            self.assertEqual([r for r in logs if r.levelno >= logging.WARNING], [])
            self.ha.delay = 1.0
            watch.tick(36.0)
            watch.tick(48.0)
            st = upstream.load_state(s)
            self.assertEqual((st.reachable, st.error_kind, st.running_mode), (False, "timeout", "strip"))
            warning = "\n".join(r.getMessage() for r in logs if r.levelno >= logging.WARNING)
            self.assertIn("does not answer", warning)
            self.assertNotIn("502", warning)
            self.ha.delay = 0.0
            watch.tick(60.0)
        self.assertEqual(self.ha.refusals, 2)  # the test after it came back
        self.assertTrue(upstream.load_state(s).reachable)

    def test_failed_reload_is_red_logged_once_and_notified_from_what_caddy_runs(self) -> None:
        """B-2."""
        self.resolve_homeassistant()
        s = self.write_runtime()
        self.ha.trust = True
        upstream.start(s)
        watch = self.make_watch()
        with captured_logs() as logs:
            t = self.run_watch(watch, 0.0, 30)
            self.reload_ok = False
            self.ha.trust = False
            self.ha.restart()
            t = self.run_watch(watch, t, 120)
            st = upstream.load_state(s)
            self.assertEqual((st.mode, st.running, st.applied), ("strip", "pass", False))
            self.assertEqual(upstream.card_state(s, st), "reload_failed")
            errors = [r for r in logs if r.levelno >= logging.ERROR]
            self.assertEqual(len(errors), 1, [r.getMessage() for r in errors])
            self.assertIn("Caddy keeps mode pass - every request is answered 400", errors[0].getMessage())
            self.assertEqual(len(self.creates()), 1)  # what Caddy runs: every request 400
            self.assertEqual(self.ha.refusals, 1)  # retries ask nobody
            self.reload_ok = True
            self.run_watch(watch, t, 13)
        self.assertEqual(self.mode(s), "strip")
        self.assertIn("Caddy reloaded: the forwarding mode strip applies now.",
                      "\n".join(r.getMessage() for r in logs))
        self.assertEqual(len(self.dismisses()), 2)  # at the start, and when it was over
        self.assertEqual(len(self.creates("caddy_mtls_upstream_addresses_hidden")), 1)

    def test_addresses_hidden_at_run_time_notification(self) -> None:
        """B-12: not when the add-on starts in strip; once when it switches
        at run time; dismissed when addresses are passed on again."""
        self.resolve_homeassistant()
        s = self.write_runtime()
        upstream.start(s)  # strip at the start
        watch = self.make_watch()
        hidden = "caddy_mtls_upstream_addresses_hidden"
        with captured_logs():
            t = self.run_watch(watch, 0.0, 30)
            self.assertEqual(self.creates(hidden), [])
            self.assertEqual(len(self.dismisses(hidden)), 1)  # a previous run's, once
            self.ha.trust = True
            self.ha.restart()
            t = self.run_watch(watch, t, 30)
            self.assertEqual(self.mode(s), "pass")
            self.ha.trust = False
            self.ha.restart()
            t = self.run_watch(watch, t, 120)
            self.assertEqual(self.mode(s), "strip")
            notes = self.creates(hidden)
            self.assertEqual(len(notes), 1)
            self.assertEqual(notes[0]["title"],
                             "Caddy mTLS: Home Assistant no longer trusts the app - visitor addresses are hidden")
            for text in ("Can only log in from the local network", "Trust X-Forwarded-For",
                         "**home.example.com**", "127.0.0.1", "within 5 minutes"):
                self.assertIn(text, notes[0]["message"])
            self.ha.trust = True
            self.ha.restart()
            self.run_watch(watch, t, 30)
        self.assertEqual(self.mode(s), "pass")
        self.assertEqual(len(self.dismisses(hidden)), 2)
        self.assertEqual(len(self.creates(hidden)), 1)


if __name__ == "__main__":
    unittest.main()
