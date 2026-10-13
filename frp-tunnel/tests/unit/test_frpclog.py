"""Unit tests for frp-mgr/frpclog.py (frpc log watcher; stdlib only)."""
from __future__ import annotations

import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

FRP_MGR = Path(
    os.environ.get("FRP_MGR_DIR")
    or Path(__file__).resolve().parents[2] / "rootfs" / "usr" / "lib" / "frp-mgr"
)
sys.path.insert(0, str(FRP_MGR))

import frpclog  # noqa: E402

# Lines as frpc 0.65 prints them (incl. its ANSI colours).
CONNECTING = "2026-10-13 10:00:00.000 [I] [client/service.go:295] try to connect to server..."
SUCCESS = ("\x1b[1;34m2026-10-13 10:00:00.100 [I] [client/service.go:287] [0123abcd] "
           "login to server success, get run id [0123abcd]\x1b[0m")
TLS_FAIL = ("2026-10-13 10:00:01.000 [W] [client/service.go:298] connect to server error: "
            "tls: failed to verify certificate: x509: certificate is valid for frps, not wrong-name.invalid")
MUX_FAIL = "2026-10-13 10:00:02.000 [W] [client/service.go:298] connect to server error: session shutdown"
REFUSED = ("2026-10-13 10:00:03.000 [W] [client/service.go:298] connect to server error: "
           "dial tcp 127.0.0.1:7000: connect: connection refused")
PROXY = "2026-10-13 10:00:00.200 [I] [proxy/proxy_manager.go:177] [home] start proxy success"


class Clock:
    def __init__(self, now: float = 1000.0):
        self.now = now

    def __call__(self) -> float:
        self.now += 1
        return self.now


class ClassifyTests(unittest.TestCase):
    def test_lines(self):
        self.assertEqual(frpclog.classify(CONNECTING), ("connecting", ""))
        self.assertEqual(frpclog.classify(SUCCESS), ("success", ""))
        kind, reason = frpclog.classify(TLS_FAIL)
        self.assertEqual(kind, "login")
        self.assertTrue(reason.startswith("tls: failed to verify certificate"))
        self.assertEqual(frpclog.classify(MUX_FAIL), ("login", "session shutdown"))
        self.assertEqual(frpclog.classify(REFUSED)[0], "network")
        for line in ("connect to server error: dial tcp: lookup frps: no such host",
                     "connect to server error: dial tcp 1.2.3.4:7000: i/o timeout",
                     "login to the server failed: dial tcp: connect: network is unreachable"):
            self.assertEqual(frpclog.classify(line)[0], "network", line)
        self.assertEqual(frpclog.classify("login to the server failed: authorization failed")[0], "login")
        for line in (PROXY, "", "random text", "frpc.toml rendered"):
            self.assertIsNone(frpclog.classify(line), line)


class WatcherTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "run" / "frpc-status.json"

    def status(self):
        return frpclog.read_status(self.path)

    def test_lifecycle(self):
        clock = Clock()
        watcher = frpclog.Watcher(self.path, "fp1", clock)
        self.assertEqual(self.status()["state"], "starting")
        self.assertEqual(self.status()["fingerprint"], "fp1")
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        self.assertFalse(watcher.feed(PROXY))
        self.assertTrue(watcher.feed(CONNECTING))
        self.assertEqual(self.status()["state"], "connecting")
        watcher.feed(TLS_FAIL)
        watcher.feed(MUX_FAIL)
        watcher.feed(REFUSED)
        status = self.status()
        self.assertEqual((status["state"], status["login_failures"], status["network_failures"]),
                         ("failed", 2, 1))
        self.assertIn("connection refused", status["last_error"])
        self.assertEqual(status["last_error_kind"], "network")
        self.assertIsNone(status["logged_in_at"])
        watcher.feed(SUCCESS)
        status = self.status()
        self.assertEqual((status["state"], status["login_failures"], status["network_failures"]),
                         ("connected", 0, 0))
        self.assertIsInstance(status["logged_in_at"], float)

    def test_counters_survive_restarts_with_the_same_config_only(self):
        first = frpclog.Watcher(self.path, "fp1", Clock(1000))
        for _ in range(3):
            first.feed(TLS_FAIL)
        frpclog.Watcher(self.path, "fp1", Clock(2000))  # frpc restarted, same config
        self.assertEqual((self.status()["state"], self.status()["login_failures"]), ("starting", 3))
        frpclog.Watcher(self.path, "fp2", Clock(3000))  # new config (e.g. refreshed CA)
        self.assertEqual((self.status()["login_failures"], self.status()["last_error"]), (0, ""))
        frpclog.Watcher(self.path, None, Clock(4000))  # no frpc.toml: never carried over
        self.assertEqual(self.status()["login_failures"], 0)

    def test_an_older_watcher_never_overwrites_a_newer_one(self):
        old = frpclog.Watcher(self.path, "fp1", Clock(1000))
        new = frpclog.Watcher(self.path, "fp2", Clock(2000))
        new.status["pid"] = old.status["pid"] + 1  # two processes in reality
        new.write()
        old.feed(SUCCESS)  # late line of the frpc that is shutting down
        self.assertEqual((self.status()["fingerprint"], self.status()["state"]), ("fp2", "starting"))

    def test_error_text_is_sanitised(self):
        watcher = frpclog.Watcher(self.path, "fp1", Clock())
        watcher.feed("connect to server error: bad\r\nINFO: forged ‮" + "x" * 500)
        error = self.status()["last_error"]
        self.assertTrue(error.isprintable())
        self.assertLessEqual(len(error), 200)

    def test_write_problems_never_raise(self):
        blocker = Path(self._tmp.name) / "file"
        blocker.write_text("x")
        watcher = frpclog.Watcher(blocker / "status.json", "fp", Clock())  # parent is a file
        watcher.feed(SUCCESS)

    def test_read_status_tolerates_garbage(self):
        self.assertEqual(frpclog.read_status(self.path), {})
        self.path.parent.mkdir(parents=True)
        for text in ("{not json", "[]", '{"version": 99}'):
            self.path.write_text(text)
            self.assertEqual(frpclog.read_status(self.path), {})


class PassThroughTests(unittest.TestCase):
    def test_every_byte_is_passed_on(self):
        with tempfile.TemporaryDirectory() as tmp:
            watcher = frpclog.Watcher(Path(tmp) / "s.json", "fp", Clock())
            data = (CONNECTING + "\n" + SUCCESS + "\n").encode() + b"\xff\xfe not utf-8\nno newline at the end"
            sink = io.BytesIO()
            frpclog.run(io.BytesIO(data), sink, watcher)
            self.assertEqual(sink.getvalue(), data)
            self.assertEqual(frpclog.read_status(Path(tmp) / "s.json")["state"], "connected")

    def test_a_broken_sink_does_not_stop_the_watcher(self):
        class Broken(io.BytesIO):
            def write(self, _data):
                raise BrokenPipeError

        with tempfile.TemporaryDirectory() as tmp:
            watcher = frpclog.Watcher(Path(tmp) / "s.json", "fp", Clock())
            frpclog.run(io.BytesIO((SUCCESS + "\n").encode()), Broken(), watcher)
            self.assertEqual(frpclog.read_status(Path(tmp) / "s.json")["state"], "connected")

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "frpc.toml").write_text('serverAddr = "x"\n')
            status = Path(tmp, "run", "frpc-status.json")
            env = dict(os.environ, FRP_DATA_DIR=tmp, FRP_STATUS_FILE=str(status))
            data = (CONNECTING + "\n" + TLS_FAIL + "\n").encode()
            proc = subprocess.run([sys.executable, str(FRP_MGR / "frpclog.py")], input=data,  # noqa: S603
                                  env=env, capture_output=True, check=False, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, data)
            written = json.loads(status.read_text())
            self.assertEqual((written["state"], written["login_failures"]), ("failed", 1))
            sys.path.insert(0, str(FRP_MGR))
            import config as cfg  # noqa: PLC0415

            self.assertEqual(written["fingerprint"], cfg.config_fingerprint(cfg.Paths(Path(tmp))))


if __name__ == "__main__":
    unittest.main()
