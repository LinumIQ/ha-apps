"""Unit tests for cert-mgr/caddyctl.py (2.3.0): the list of active client
certificate fingerprints for the header authentication gate, derived from
the leaf verifier's folder - only real certificate fingerprints, never the
hash of an empty certificate - and the reload that regenerates it first.

Standard library only; the certificate tests need the openssl CLI and are
skipped without it. Runs against the repository's module, or the installed
one with CERT_MGR_DIR - see test_monitor.py.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

CERT_MGR = Path(
    os.environ.get("CERT_MGR_DIR")
    or Path(__file__).resolve().parents[2] / "rootfs" / "usr" / "lib" / "cert-mgr"
)
sys.path.insert(0, str(CERT_MGR))

import caddyctl  # noqa: E402

OPENSSL = shutil.which("openssl")
EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def make_cert(directory: Path, name: str) -> Path:
    """A self-signed EC certificate (PEM) - what the fingerprint is taken
    of does not depend on who signed it."""
    crt = directory / f"{name}.crt"
    subprocess.run(
        [OPENSSL, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
         "-subj", f"/CN={name}", "-days", "2", "-keyout", str(directory / f"{name}.key"), "-out", str(crt)],
        check=True, capture_output=True,
    )
    return crt


def der_sha256(pem: Path) -> str:
    der = subprocess.run([OPENSSL, "x509", "-in", str(pem), "-outform", "DER"], check=True,
                         capture_output=True).stdout
    return hashlib.sha256(der).hexdigest()


class RenderTest(unittest.TestCase):
    def test_sentinel_without_clients(self) -> None:
        text = caddyctl.render_fingerprints([])
        self.assertIn("not vars {http.request.tls.client.fingerprint} no-active-client\n", text)
        self.assertNotRegex(caddyctl.NO_CLIENT, r"^[0-9a-f]{64}$")

    def test_never_the_empty_hash_nor_anything_but_hex(self) -> None:
        self.assertEqual(caddyctl.EMPTY_SHA256, EMPTY)
        good = "ab" * 32
        text = caddyctl.render_fingerprints([EMPTY, good, "AB" * 32, "x" * 64, "ab" * 31, "{host}"])
        last = text.strip().splitlines()[-1]
        self.assertEqual(last, f"not vars {{http.request.tls.client.fingerprint}} {good}")
        self.assertEqual(caddyctl.render_fingerprints([EMPTY]).strip().splitlines()[-1],
                         "not vars {http.request.tls.client.fingerprint} no-active-client")


@unittest.skipIf(OPENSSL is None, "openssl CLI not installed")
class FingerprintTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pki = Path(tempfile.mkdtemp())
        cls.alice = make_cert(cls.pki, "alice")
        cls.bob = make_cert(cls.pki, "bob")
        cls.carol = make_cert(cls.pki, "carol")

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.pki)

    def setUp(self) -> None:
        self.active = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.active)

    def put(self, name: str, data: bytes | str) -> Path:
        path = self.active / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode() if isinstance(data, str) else data)
        return path

    def test_the_fingerprint_caddy_reports(self) -> None:
        """Lower-case hex SHA-256 of the DER certificate, as Caddy's
        {http.request.tls.client.fingerprint} (replacer.go: %x of
        sha256.Sum256(cert.Raw))."""
        shutil.copy(self.alice, self.active / "mTLS-client-alice.pem")
        shutil.copy(self.bob, self.active / "mTLS-client-bob.pem")
        fps, warnings = caddyctl.active_fingerprints(self.active)
        # In the order of the file names.
        self.assertEqual(fps, [der_sha256(self.alice), der_sha256(self.bob)])
        self.assertEqual(warnings, [])
        for fp in fps:
            self.assertRegex(fp, r"^[0-9a-f]{64}$")

    def test_bad_files_give_no_entry_and_never_the_empty_hash(self) -> None:
        """An empty file, a truncated one, a key instead of a certificate,
        garbage, an empty PEM block, two certificates in one file - none
        gives an entry (Caddy's own loader refuses each of them)."""
        shutil.copy(self.alice, self.active / "mTLS-client-alice.pem")
        pem = self.bob.read_text()
        self.put("empty.pem", b"")
        self.put("truncated.pem", pem[: len(pem) // 2])
        self.put("truncated-end.pem", pem.replace("-----END CERTIFICATE-----", ""))
        self.put("key.pem", (self.pki / "bob.key").read_text())
        self.put("garbage.pem", "hello\n")
        self.put("empty-block.pem", "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")
        self.put("not-base64.pem", "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n")
        self.put("two.pem", pem + self.carol.read_text())
        self.put("cert-and-key.pem", pem + (self.pki / "bob.key").read_text())
        self.put("bad-der.pem", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
        fps, warnings = caddyctl.active_fingerprints(self.active)
        self.assertEqual(fps, [der_sha256(self.alice)])
        self.assertNotIn(EMPTY, fps)
        self.assertEqual(len(warnings), 10, warnings)
        self.assertTrue(all("left out" in w for w in warnings))

    def test_the_empty_hash_is_refused_explicitly(self) -> None:
        """Even if a file produced it, the value Caddy reports for "no
        certificate" never gets into the list."""
        self.put("x.pem", "irrelevant")
        with mock.patch.object(caddyctl, "_der_of", return_value=b""), \
                mock.patch.object(caddyctl, "_openssl_fingerprint", return_value=EMPTY):
            fps, warnings = caddyctl.active_fingerprints(self.active)
        self.assertEqual(fps, [])
        self.assertIn("not a certificate fingerprint", warnings[0])

    def test_the_files_caddys_loader_reads(self) -> None:
        """Caddy 2.11.9 leaffolderloader.go: every *.pem below the folder
        (case-insensitive suffix, sub-folders, symlinks followed); nothing
        else (.crt is ignored)."""
        shutil.copy(self.alice, self.active / "A.PEM")
        self.put("sub/bob.pem", self.bob.read_bytes())
        (self.active / "link.pem").symlink_to(self.carol)
        shutil.copy(self.carol, self.active / "carol.crt")
        fps, warnings = caddyctl.active_fingerprints(self.active)
        self.assertEqual(sorted(fps), sorted([der_sha256(self.alice), der_sha256(self.bob), der_sha256(self.carol)]))
        self.assertEqual(warnings, [])

    def test_crlf_and_a_missing_folder(self) -> None:
        self.put("crlf.pem", self.alice.read_text().replace("\n", "\r\n"))
        self.assertEqual(caddyctl.active_fingerprints(self.active)[0], [der_sha256(self.alice)])
        self.assertEqual(caddyctl.active_fingerprints(self.active / "missing"), ([], []))

    def test_write_is_atomic_and_derived_from_the_folder(self) -> None:
        out = Path(tempfile.mkdtemp()) / "client-fingerprints.caddy"
        self.addCleanup(shutil.rmtree, out.parent)
        fps, _ = caddyctl.write_fingerprints(self.active, out)
        self.assertEqual(fps, [])
        self.assertTrue(out.read_text().endswith("no-active-client\n"))
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o644)
        shutil.copy(self.alice, self.active / "mTLS-client-alice.pem")
        caddyctl.write_fingerprints(self.active, out)
        self.assertTrue(out.read_text().endswith(f" {der_sha256(self.alice)}\n"))
        (self.active / "mTLS-client-alice.pem").unlink()  # revoked
        caddyctl.write_fingerprints(self.active, out)
        self.assertNotIn(der_sha256(self.alice), out.read_text())
        self.assertEqual([p.name for p in out.parent.iterdir()], [out.name])  # no temp file left

    def test_write_fails_loudly(self) -> None:
        blocker = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, blocker)
        (blocker / "file").write_text("")
        with self.assertRaises(caddyctl.FingerprintError):
            caddyctl.write_fingerprints(self.active, blocker / "file" / "list.caddy")
        with self.assertRaises(caddyctl.FingerprintError):
            caddyctl.active_fingerprints(blocker / "file")  # not a folder

    def test_cli(self) -> None:
        shutil.copy(self.alice, self.active / "a.pem")
        self.put("empty.pem", b"")
        out = self.active.parent / f"{self.active.name}.caddy"
        self.addCleanup(lambda: out.unlink(missing_ok=True))
        proc = subprocess.run([sys.executable, str(CERT_MGR / "caddyctl.py"), "fingerprints",
                               "--folder", str(self.active), "--output", str(out)],
                              capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "1")
        self.assertIn("WARNING", proc.stderr)
        self.assertIn("empty.pem: left out", proc.stderr)


class ReloadTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.caddyfile = self.tmp / "Caddyfile"
        self.caddyfile.write_text("x")
        self.calls: list[str] = []
        self.lock = self.tmp / "run" / "reload.lock"
        self.fallback = self.tmp / "Caddyfile.own"
        for name, value in (("RELOAD_LOCK", self.lock), ("FALLBACK_FILE", self.fallback),
                            ("COPY_DIR", self.tmp / "custom"), ("STATE_FILE", self.tmp / "custom.json")):
            patcher = mock.patch.object(caddyctl.customconf, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def regenerate(self) -> None:
        self.calls.append("regenerate")

    def run_ok(self, args, **kwargs):
        self.calls.append("reload")
        self.assertEqual(args[1:4], ["reload", "--force", "--config"])
        return subprocess.CompletedProcess(args, 0, "", "")

    def test_regenerates_immediately_before_every_reload(self) -> None:
        ok, message = caddyctl.reload(caddyfile=self.caddyfile, run=self.run_ok, regenerate=self.regenerate)
        self.assertEqual((ok, message), (True, "reloaded"))
        self.assertEqual(self.calls, ["regenerate", "reload"])

    @staticmethod
    def fail_list() -> None:
        raise caddyctl.FingerprintError("cannot write /etc/caddy/client-fingerprints.caddy: read-only")

    def test_a_list_failure_still_reloads(self) -> None:
        """C-2: revocation must not depend on the list - Caddy reloads with
        the previous one (it can only refuse too much), and the result says
        so and is not ok."""
        with self.assertLogs("caddyctl", level="ERROR") as logs:
            ok, message = caddyctl.reload(caddyfile=self.caddyfile, run=self.run_ok, regenerate=self.fail_list)
        self.assertFalse(ok)
        self.assertEqual(self.calls, ["reload"])  # the reload command still ran
        self.assertIn("the list of active client certificates could not be written", message)
        self.assertIn("read-only", message)
        self.assertIn("Caddy was reloaded with the previous list: revoked certificates are refused", message)
        self.assertIn("gets 403", message)
        self.assertEqual(logs.output, [f"ERROR:caddyctl:{message}"])
        result = caddyctl.reload_detailed(caddyfile=self.caddyfile, run=self.run_ok, regenerate=self.fail_list)
        self.assertTrue(result.reloaded)
        self.assertFalse(result.ok)

    def test_a_list_failure_and_a_failed_reload_name_both(self) -> None:
        def run_fail(args, **kwargs):
            return subprocess.CompletedProcess(args, 1, "", "Error: loading config: boom\n")
        with self.assertLogs("caddyctl", level="ERROR"):
            ok, message = caddyctl.reload(caddyfile=self.caddyfile, run=run_fail, regenerate=self.fail_list)
        self.assertFalse(ok)
        self.assertIn("could not be written (cannot write", message)
        self.assertIn("and Caddy could not be reloaded: Error: loading config: boom", message)

    def test_failed_reload_output_is_scrubbed_of_the_key(self) -> None:
        key = "fakekey.NOT-A-SECRET.0123456789abcdef0123"
        key_file = self.tmp / "header-auth.key"
        key_file.write_text(key)

        def run_fail(args, **kwargs):
            return subprocess.CompletedProcess(args, 1, "", f"Error: something about {key}\n")
        with mock.patch.object(caddyctl.headerauth, "KEY_FILE", key_file):
            ok, message = caddyctl.reload(caddyfile=self.caddyfile, run=run_fail, regenerate=self.regenerate)
        self.assertFalse(ok)
        self.assertEqual(message, "Error: something about <redacted>\n")

    def test_missing_caddyfile(self) -> None:
        ok, message = caddyctl.reload(caddyfile=self.tmp / "nope", run=self.run_ok, regenerate=self.regenerate)
        self.assertFalse(ok)
        self.assertIn("Caddyfile not found", message)

    # --- B-2: the fallback while custom files are in use ----------------------

    def custom_files_in_use(self) -> None:
        copies = self.tmp / "custom"
        copies.mkdir()
        (copies / "sites.caddy").write_text("other.example.com {\n\ttls /config/caddy/o.crt /config/caddy/o.key\n}\n")
        self.caddyfile.write_text("the Caddyfile with: import /etc/caddy/custom/sites.caddy\n")
        self.fallback.write_text("the add-on's own configuration\n")
        caddyctl.customconf.write_state({"state": "loaded", "files": [{"name": "sites.caddy", "bytes": 60}],
                                         "ignored": [], "error": "", "error_file": None,
                                         "folder": "app_configs/local_caddy_mtls/caddy"})

    def run_custom_fails(self, fallback_ok: bool = True):
        key_error = ('Error: sending configuration to instance: caddy responded with error: HTTP 400: '
                     '{"error":"loading config: loading new config: loading tls app module: provision tls: '
                     'loading certificates: open /config/caddy/o.key: no such file or directory"}\n')

        def run(args, **kwargs):
            config = Path(args[args.index("--config") + 1])
            self.calls.append(config.name)
            if config == self.caddyfile and "import" in config.read_text():
                return subprocess.CompletedProcess(args, 1, "", "2026/11/28 INFO using config\n" + key_error)
            if config == self.fallback and not fallback_ok:
                return subprocess.CompletedProcess(args, 1, "", "Error: the admin endpoint is down\n")
            return subprocess.CompletedProcess(args, 0, "", "")
        return run

    def test_a_failed_reload_falls_back_and_drops_the_custom_files(self) -> None:
        self.custom_files_in_use()
        with self.assertLogs("caddyctl", level="WARNING") as logs:
            result = caddyctl.reload_detailed(caddyfile=self.caddyfile, run=self.run_custom_fails(),
                                              regenerate=self.regenerate)
        # The reload counts as done: the change (a revocation) took effect.
        self.assertTrue(result.ok)
        self.assertTrue(result.reloaded)
        self.assertEqual(self.calls, ["regenerate", "Caddyfile", "Caddyfile.own"])
        expected = ("Caddy could not reload with your custom files while applying a change (loading config: "
                    "loading new config: loading tls app module: provision tls: loading certificates: open "
                    "/config/caddy/o.key: no such file or directory). To apply the change the add-on dropped "
                    "them; they are read again at the next start.")
        self.assertEqual(result.dropped, expected)
        self.assertEqual(result.message, expected)
        self.assertEqual(logs.output, [f"WARNING:caddyctl:{expected}"])
        # Permanent for the run: the Caddyfile is the fallback, which is gone,
        # and so are the copies; the state says so, with the run-time marker.
        self.assertEqual(self.caddyfile.read_text(), "the add-on's own configuration\n")
        self.assertFalse(self.fallback.exists())
        self.assertFalse((self.tmp / "custom").exists())
        state = caddyctl.customconf.read_state()
        self.assertEqual(state["state"], "rejected")
        self.assertEqual(state["error"], expected)
        self.assertIsNone(state["error_file"])
        self.assertEqual(state["dropped"], "reload")
        self.assertIsInstance(state["dropped_at"], float)
        self.assertEqual(state["files"], [{"name": "sites.caddy", "bytes": 60}])
        # The next reload needs no fallback.
        self.calls.clear()
        ok, message = caddyctl.reload(caddyfile=self.caddyfile, run=self.run_custom_fails(), regenerate=self.regenerate)
        self.assertEqual((ok, message, self.calls), (True, "reloaded", ["regenerate", "Caddyfile"]))

    # --- B2-1: fall back only when Caddy judged the configuration -------------

    NOT_REACHED = ('{"level":"info","ts":1795829509.09,"msg":"using config from file","file":"/etc/caddy/Caddyfile"}\n'
                   '{"level":"error","ts":1795829509.10,"msg":"sending configuration to instance: performing request: '
                   'Post \\"http://127.0.0.1:2019/load\\": dial tcp 127.0.0.1:2019: connect: connection refused"}\n')

    def run_first_fails(self, failure):
        """The first reload fails as ``failure`` says (an exception to raise
        or a CLI output with exit status 1); any further call works."""
        def run(args, **kwargs):
            config = Path(args[args.index("--config") + 1])
            self.calls.append(config.name)
            if config == self.caddyfile and "import" in config.read_text():
                if isinstance(failure, BaseException):
                    raise failure
                return subprocess.CompletedProcess(args, 1, "", failure)
            return subprocess.CompletedProcess(args, 0, "", "")
        return run

    def assert_nothing_dropped(self, failure) -> None:
        self.custom_files_in_use()
        result = caddyctl.reload_detailed(caddyfile=self.caddyfile, run=self.run_first_fails(failure),
                                          regenerate=self.regenerate)
        self.assertFalse(result.ok)
        self.assertFalse(result.reloaded)
        self.assertEqual(result.dropped, "")
        self.assertEqual(self.calls, ["regenerate", "Caddyfile"])  # no second call
        self.assertTrue(self.fallback.exists())
        self.assertTrue((self.tmp / "custom" / "sites.caddy").exists())
        self.assertEqual(caddyctl.customconf.read_state()["state"], "loaded")

    def test_a_timeout_drops_nothing(self) -> None:
        """B2-1: the reviewer's stalled Caddy (SIGSTOP): the CLI did not
        finish - reported as before, the snippets stay."""
        self.assert_nothing_dropped(subprocess.TimeoutExpired(["caddy", "reload"], 60))

    def test_a_cli_that_cannot_start_drops_nothing(self) -> None:
        self.assert_nothing_dropped(FileNotFoundError(2, "No such file or directory"))

    def test_an_unreachable_admin_endpoint_drops_nothing(self) -> None:
        self.assert_nothing_dropped(self.NOT_REACHED)
        self.assertFalse(caddyctl.caddy_judged(self.NOT_REACHED))
        self.assertFalse(caddyctl.caddy_judged(
            "Error: sending configuration to instance: performing request: Post \"http://127.0.0.1:2019/load\": EOF"))

    def test_refusals_and_unknown_failures_fall_back(self) -> None:
        """An adapter error, Caddy's answer HTTP 400 and an output this code
        does not know: the configuration was the problem (or may be) - fall
        back, a revocation matters more than a snippet."""
        for output in ('{"level":"error","ts":1.5,"msg":"adapting config using caddyfile: File to import not found: '
                       '/etc/caddy/custom/sites.caddy, at /etc/caddy/Caddyfile:90"}\n',
                       "Error: sending configuration to instance: caddy responded with error: HTTP 400: "
                       '{"error":"loading config: loading new config: x"}\n',
                       "something nobody has seen before\n"):
            with self.subTest(output=output[:40]):
                self.assertTrue(caddyctl.caddy_judged(output))
                shutil.rmtree(self.tmp / "custom", ignore_errors=True)
                self.calls.clear()
                self.custom_files_in_use()
                with self.assertLogs("caddyctl", level="WARNING"):
                    result = caddyctl.reload_detailed(caddyfile=self.caddyfile, run=self.run_first_fails(output),
                                                      regenerate=self.regenerate)
                self.assertTrue(result.ok)
                self.assertTrue(result.dropped)
                self.assertEqual(self.calls, ["regenerate", "Caddyfile", "Caddyfile.own"])

    def test_only_the_start_of_the_final_error_counts(self) -> None:
        """B3-2: the decision reads the CLI's final error message and
        requires it to START with the "not reached" sign - Caddy's answer
        quotes file paths a snippet chooses."""
        phrase = "sending configuration to instance: performing request:"
        named = (f'{{"level":"error","ts":1.5,"msg":"sending configuration to instance: caddy responded with error: '
                 f'HTTP 400: {{\\"error\\":\\"loading config: loading new config: loading tls app module: '
                 f'provision tls: loading certificates: open /config/caddy/{phrase} o.key: no such file or '
                 f'directory\\"}}"}}\n')
        self.assertIn(phrase, named)
        self.assertTrue(caddyctl.caddy_judged(named))  # the reviewer's named file: a refusal
        self.assertFalse(caddyctl.caddy_judged(self.NOT_REACHED))  # the real JSON error line
        self.assertFalse(caddyctl.caddy_judged(
            'Error: sending configuration to instance: performing request: Post "http://127.0.0.1:2019/load": '
            "dial tcp 127.0.0.1:2019: connect: connection refused\n"))
        # The LAST error line decides: an earlier line with the phrase does not.
        self.assertTrue(caddyctl.caddy_judged(self.NOT_REACHED + "Error: sending configuration to instance: caddy "
                                              'responded with error: HTTP 400: {"error":"x"}\n'))
        # No recognisable error line at all: judged (falls back), as before.
        self.assertTrue(caddyctl.caddy_judged(f"{phrase} Post: connection refused\n"))
        self.assertTrue(caddyctl.caddy_judged(""))

    def test_a_refusal_quoting_the_phrase_falls_back(self) -> None:
        """B3-2 end to end: the revocation takes effect."""
        phrase = "sending configuration to instance: performing request:"
        output = ("Error: sending configuration to instance: caddy responded with error: HTTP 400: "
                  f'{{"error":"loading certificates: open /config/caddy/{phrase} o.key: no such file or directory"}}\n')
        self.custom_files_in_use()
        with self.assertLogs("caddyctl", level="WARNING"):
            result = caddyctl.reload_detailed(caddyfile=self.caddyfile, run=self.run_first_fails(output),
                                              regenerate=self.regenerate)
        self.assertTrue(result.ok)
        self.assertTrue(result.dropped)
        self.assertEqual(self.calls, ["regenerate", "Caddyfile", "Caddyfile.own"])

    def test_the_banner_shows_only_the_cause(self) -> None:
        """B2-6: the panel's banner after "list not written and reload
        failed" names Caddy's cause, not its raw log lines (the log keeps
        them: message)."""
        result = caddyctl.ReloadResult(False, "cannot write x: read-only", self.NOT_REACHED)
        self.assertIn('"level":"info"', result.message)
        self.assertEqual(result.banner,
                         "the list of active client certificates could not be written (cannot write x: read-only), "
                         "and Caddy could not be reloaded: sending configuration to instance: performing request: "
                         'Post "http://127.0.0.1:2019/load": dial tcp 127.0.0.1:2019: connect: connection refused')
        self.assertEqual(caddyctl.ReloadResult(True).banner, "reloaded")

    def test_both_failing_drops_nothing(self) -> None:
        self.custom_files_in_use()
        with self.assertLogs("caddyctl", level="ERROR") as logs:
            ok, message = caddyctl.reload(caddyfile=self.caddyfile, run=self.run_custom_fails(fallback_ok=False),
                                          regenerate=self.regenerate)
        self.assertFalse(ok)
        self.assertIn("o.key: no such file or directory", message)
        self.assertEqual(len(logs.output), 1)
        self.assertIn("nor with the add-on's own configuration without them (the admin endpoint is down): nothing "
                      "was dropped", logs.output[0])
        self.assertIn("o.key: no such file or directory", logs.output[0])
        self.assertTrue(self.fallback.exists())
        self.assertTrue((self.tmp / "custom" / "sites.caddy").exists())
        self.assertIn("import", self.caddyfile.read_text())
        self.assertEqual(caddyctl.customconf.read_state()["state"], "loaded")

    def test_without_a_fallback_file_a_failure_is_reported_as_before(self) -> None:
        def run_fail(args, **kwargs):
            self.calls.append("reload")
            return subprocess.CompletedProcess(args, 1, "", "Error: loading config: boom\n")
        ok, message = caddyctl.reload(caddyfile=self.caddyfile, run=run_fail, regenerate=self.regenerate)
        self.assertEqual((ok, message), (False, "Error: loading config: boom\n"))
        self.assertEqual(self.calls, ["regenerate", "reload"])

    def test_the_whole_sequence_holds_the_reload_lock(self) -> None:
        import fcntl
        seen: list[str] = []

        def probe() -> None:
            fd = os.open(self.lock, os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                seen.append("free")
            except BlockingIOError:
                seen.append("held")
            finally:
                os.close(fd)

        def run(args, **kwargs):
            probe()
            return subprocess.CompletedProcess(args, 0, "", "")
        caddyctl.reload(caddyfile=self.caddyfile, run=run, regenerate=probe)
        self.assertEqual(seen, ["held", "held"])
        probe()
        self.assertEqual(seen[-1], "free")

    # --- B-8: one environment for every caddy call ------------------------------

    def test_every_caddy_call_gets_the_small_environment(self) -> None:
        self.custom_files_in_use()
        envs: list[dict] = []
        inner = self.run_custom_fails()

        def run(args, **kwargs):
            envs.append(kwargs["env"])
            return inner(args, **kwargs)
        options = self.tmp / "options.json"
        options.write_text(json.dumps({"acme_dns_provider": "route53", "dns_api_token": "AKIDEXAMPLE:se:cret"}))
        environ = {"PATH": "/usr/bin", "HOME": "/root", "TZ": "Europe/Vienna", "SUPERVISOR_TOKEN": "marker",
                   "HASSIO_TOKEN": "marker", "CADDY_ADMIN": "127.0.0.1:2019", "CADDY_MTLS_X": "1",
                   "DNS_API_TOKEN": "stray"}
        with mock.patch.dict(os.environ, environ, clear=True), \
                mock.patch.object(caddyctl, "OPTIONS_FILE", options), self.assertLogs("caddyctl", level="WARNING"):
            caddyctl.reload(caddyfile=self.caddyfile, run=run, regenerate=self.regenerate)
        want = {"PATH": "/usr/bin", "HOME": "/root", "TZ": "Europe/Vienna",
                "DNS_AWS_ACCESS_KEY_ID": "AKIDEXAMPLE", "DNS_AWS_SECRET_ACCESS_KEY": "se:cret"}
        self.assertEqual(envs, [want, want])  # the reload and the fallback

    def test_dns_env_follows_dns_provider_export(self) -> None:
        self.assertEqual(caddyctl.dns_env("cloudflare", "tok"), {"DNS_API_TOKEN": "tok"})
        self.assertEqual(caddyctl.dns_env("hetzner", "tok"), {"DNS_API_TOKEN": "tok"})
        self.assertEqual(caddyctl.dns_env("route53", "id:se:cret"),
                         {"DNS_AWS_ACCESS_KEY_ID": "id", "DNS_AWS_SECRET_ACCESS_KEY": "se:cret"})
        for provider, token in (("none", "tok"), ("cloudflare", ""), ("route53", "nocolon"), ("route53", ":x"),
                                ("route53", "x:"), ("other", "tok")):
            self.assertEqual(caddyctl.dns_env(provider, token), {}, (provider, token))


DNS_SH = CERT_MGR.parents[2] / "etc" / "s6-overlay" / "scripts" / "lib" / "dns-provider.sh"


@unittest.skipUnless(shutil.which("bash") and DNS_SH.exists(), "bash and lib/dns-provider.sh")
class CaddyEnvShellTest(unittest.TestCase):
    """B-8: the shell's list (CADDY_ENV_NAMES, caddy_env_only) and the
    Python one give the same environment."""

    #: caddy_cmd (a subshell; init-caddy, the caddy service's check) and the
    #: caddy service's exec (the run script itself).
    FORMS = {
        "caddy_cmd": 'source "$0"; dns_provider_export "$1" "$2" || exit 3; ( caddy_env_only; exec env -0 )',
        "caddy/run": 'source "$0"; dns_provider_export "$1" "$2" || exit 3; caddy_env_only; exec env -u SHLVL -0',
    }

    def shell_env(self, form: str, provider: str, token: str, environ: dict[str, str]) -> dict[str, str]:
        proc = subprocess.run(["bash", "--norc", "-c", self.FORMS[form], str(DNS_SH), provider, token],
                              env=environ, capture_output=True, check=True)
        pairs = [item.split("=", 1) for item in proc.stdout.decode().split("\0") if item]
        return dict(pairs)

    def test_the_lists_are_the_same(self) -> None:
        proc = subprocess.run(["bash", "-c", 'source "$0"; printf "%s\\n" "${CADDY_ENV_NAMES[@]}"', str(DNS_SH)],
                              capture_output=True, text=True, check=True)
        self.assertEqual(tuple(proc.stdout.split()), caddyctl.CADDY_ENV_NAMES)

    def test_same_environment_as_python(self) -> None:
        environ = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/root", "TZ": "Europe/Vienna",
                   "XDG_CONFIG_HOME": "/root/.config", "SUPERVISOR_TOKEN": "marker", "HASSIO_TOKEN": "marker",
                   "CADDY_ADMIN": "127.0.0.1:2019", "CADDY_MTLS_CUSTOM_RETRY_SECONDS": "2", "LANG": "C.UTF-8"}
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        for form in self.FORMS:
            for provider, token in (("none", ""), ("cloudflare", "cf-token"), ("route53", "AKIDEXAMPLE:se:cret")):
                with self.subTest(form=form, provider=provider):
                    options = tmp / "options.json"
                    options.write_text(json.dumps({"acme_dns_provider": provider, "dns_api_token": token}))
                    shell = self.shell_env(form, provider, token, environ)
                    self.assertEqual(shell, caddyctl.caddy_env(environ, options))
                    self.assertNotIn("SUPERVISOR_TOKEN", shell)


if __name__ == "__main__":
    unittest.main()
