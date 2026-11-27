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
                forwarded = "X-Forwarded-For" in self.headers
                refused = forwarded and not fake.trust
                fake.requests.append({"forwarded": forwarded, "refused": refused,
                                      "peer": self.client_address[0],
                                      "host": self.headers.get("Host"),
                                      "xff": self.headers.get("X-Forwarded-For")})
                status, body = (400, b"400: Bad Request") if refused else (fake.status, b"{}")
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                pass

        class Server(ThreadingHTTPServer):
            allow_reuse_address = True
            daemon_threads = True

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
            ("never", False, A): "strip", ("never", False, R): "strip", ("never", False, None): "strip",
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
        ]
        for settings, state, expected in cases:
            with self.subTest(option=settings.option, state=state):
                self.assertEqual(upstream.card_state(settings, state), expected)


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
        upstream.write_snippet("strip")
        self.assertEqual(upstream.snippet_mode(), "strip")
        self.assertEqual(os.stat(upstream.SNIPPET_FILE).st_mode & 0o777, 0o644)
        upstream.write_snippet("pass")
        self.assertEqual(upstream.snippet_mode(), "pass")
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["forwarded-headers.caddy"])


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
        self.assertEqual(result.result, U)
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
        self.assertEqual(result.result, U)


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

    def creates(self) -> list[dict]:
        return [p for _, path, p in self.calls if path.endswith("/persistent_notification/create")]

    def dismisses(self) -> list[dict]:
        return [p for _, path, p in self.calls if path.endswith("/persistent_notification/dismiss")]

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


if __name__ == "__main__":
    unittest.main()
