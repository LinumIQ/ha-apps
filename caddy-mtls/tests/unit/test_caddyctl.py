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

    def test_no_reload_with_a_stale_list(self) -> None:
        def fail() -> None:
            raise caddyctl.FingerprintError("cannot write /etc/caddy/client-fingerprints.caddy: read-only")
        ok, message = caddyctl.reload(caddyfile=self.caddyfile, run=self.run_ok, regenerate=fail)
        self.assertFalse(ok)
        self.assertIn("could not be written", message)
        self.assertIn("Caddy was not reloaded", message)
        self.assertEqual(self.calls, [])

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


if __name__ == "__main__":
    unittest.main()
