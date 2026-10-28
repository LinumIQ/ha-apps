"""Unit tests for cert-mgr/public_cert.py (state of the public certificate).

Standard library only (the certificate tests need the openssl CLI and are
skipped without it). Runs against the repository's public_cert.py, or the
installed one with CERT_MGR_DIR - see test_monitor.py.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

CERT_MGR = Path(
    os.environ.get("CERT_MGR_DIR")
    or Path(__file__).resolve().parents[2] / "rootfs" / "usr" / "lib" / "cert-mgr"
)
sys.path.insert(0, str(CERT_MGR))

import public_cert  # noqa: E402

DOMAIN = "ladyfit.duckdns.org"


def owner_log(t0: float) -> list[str]:
    """The ACME events of the owner's first start (2026-10-28 13:28, router
    not forwarding yet), as Caddy writes them to acme.log."""
    problem_http = {
        "type": "urn:ietf:params:acme:error:connection",
        "title": "",
        "detail": f"86.62.32.88: Fetching http://{DOMAIN}/.well-known/acme-challenge/y0_Ss4VQ: Error getting validation data",
        "instance": "",
        "subproblems": None,
    }
    problem_alpn = dict(problem_http, detail="86.62.32.88: Error getting validation data")
    lines = [
        {"level": "info", "ts": t0 + 0.5, "logger": "tls.obtain", "msg": "obtaining certificate", "identifier": DOMAIN},
        {"level": "info", "ts": t0 + 2.0, "logger": "http.acme_client", "msg": "trying to solve challenge",
         "identifier": DOMAIN, "challenge_type": "http-01", "ca": "https://acme-v02.api.letsencrypt.org/directory"},
        {"level": "error", "ts": t0 + 5.7, "logger": "http.acme_client", "msg": "challenge failed",
         "identifier": DOMAIN, "challenge_type": "http-01", "problem": problem_http},
        {"level": "error", "ts": t0 + 5.7, "logger": "http.acme_client", "msg": "validating authorization",
         "identifier": DOMAIN, "problem": problem_http, "order": "https://acme-v02.api.letsencrypt.org/acme/order/1/2",
         "attempt": 1, "max_attempts": 3},
        {"level": "error", "ts": t0 + 8.7, "logger": "http.acme_client", "msg": "challenge failed",
         "identifier": DOMAIN, "challenge_type": "tls-alpn-01", "problem": problem_alpn},
        {"level": "error", "ts": t0 + 8.7, "logger": "tls.obtain", "msg": "could not get certificate from issuer",
         "identifier": DOMAIN, "issuer": "acme-v02.api.letsencrypt.org-directory",
         "error": "HTTP 400 urn:ietf:params:acme:error:connection - 86.62.32.88: Error getting validation data"},
        {"level": "error", "ts": t0 + 9.0, "logger": "tls.obtain", "msg": "will retry",
         "error": f"[{DOMAIN}] Obtain: HTTP 400 urn:ietf:params:acme:error:connection - 86.62.32.88: Error getting validation data",
         "attempt": 1, "retrying_in": 60, "elapsed": 9.1, "max_duration": 2592000},
    ]
    return [json.dumps(line) for line in lines]


def events(lines: list[str]) -> list[public_cert.AcmeEvent]:
    return [e for e in (public_cert.parse_event(line) for line in lines) if e]


def runtime(started_at: float, **kwargs) -> public_cert.Runtime:
    data = {
        "domain": DOMAIN, "started_at": started_at, "host_ports_known": True,
        "http_host_port": 8080, "https_host_port": 8443, "acme_dns_provider": "none",
    }
    data.update(kwargs)
    return public_cert.Runtime.from_dict(data)


def fake_cert(days: float, mtime: float) -> public_cert.Certificate:
    return public_cert.Certificate(
        path="/x.crt", subject_cn=DOMAIN, issuer_cn="E7", issuer_org="Let's Encrypt",
        not_after=datetime.now(timezone.utc) + timedelta(days=days),
        fingerprint_sha256="ab" * 32, mtime=mtime,
    )


class ParseEventTest(unittest.TestCase):
    def test_owner_log(self) -> None:
        evs = events(owner_log(1000.0))
        self.assertEqual(len(evs), 7)
        challenge = evs[2]
        self.assertEqual(challenge.challenge_type, "http-01")
        self.assertEqual(challenge.problem_type, "connection")
        self.assertTrue(challenge.is_error)
        self.assertIn("Fetching http://", challenge.error)
        verdict = evs[5]
        # The ACME problem inside the error string is split into type + detail.
        self.assertEqual(verdict.problem_type, "connection")
        self.assertEqual(verdict.error, "86.62.32.88: Error getting validation data")
        self.assertEqual(verdict.text, "connection: 86.62.32.88: Error getting validation data")
        retry = evs[6]
        self.assertEqual(retry.retrying_in, 60.0)
        self.assertEqual(retry.attempt, 1)
        self.assertEqual(retry.identifier, "")

    def test_go_duration_and_iso_time(self) -> None:
        line = json.dumps({"level": "error", "ts": "2026-10-28T13:28:19.71Z", "logger": "tls.renew",
                           "msg": "will retry", "error": "boom", "retrying_in": "2m30s"})
        event = public_cert.parse_event(line)
        assert event is not None
        self.assertEqual(event.retrying_in, 150.0)
        self.assertAlmostEqual(
            event.ts, datetime(2026, 10, 28, 13, 28, 19, 710000, tzinfo=timezone.utc).timestamp()
        )

    def test_garbage(self) -> None:
        for line in ("", "not json", "[1, 2]", json.dumps({"msg": "no ts"})):
            with self.subTest(line=line):
                self.assertIsNone(public_cert.parse_event(line))

    def test_read_events_since_and_cut_first_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "acme.log"
            old = owner_log(100.0)
            new = owner_log(5000.0)
            path.write_text("\n".join(old + ["garbage"] + new) + "\n")
            self.assertEqual(len(public_cert.read_events(path, since=4000.0)), 7)
            self.assertEqual(len(public_cert.read_events(path)), 14)
            # Reading only the tail drops the (probably cut) first line.
            tail = len("\n".join(new[1:])) + 2
            self.assertEqual(len(public_cert.read_events(path, tail_bytes=tail)), 6)
            self.assertEqual(public_cert.read_events(Path(tmp) / "missing.log"), [])


class EvaluateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.now = time.time()

    def test_pending_then_missing_without_errors(self) -> None:
        status = public_cert.evaluate(runtime(self.now - 10), None, [], self.now)
        self.assertEqual(status.state, "pending")
        self.assertFalse(status.has_valid_certificate)
        status = public_cert.evaluate(runtime(self.now - 121), None, [], self.now)
        self.assertEqual(status.state, "missing")
        self.assertIsNone(status.last_error)

    def test_missing_with_the_owner_errors(self) -> None:
        started = self.now - 30
        status = public_cert.evaluate(runtime(started), None, events(owner_log(started)), self.now)
        self.assertEqual(status.state, "missing")
        assert status.last_error is not None
        self.assertEqual(status.last_error.msg, "could not get certificate from issuer")
        self.assertEqual(status.last_error.text, "connection: 86.62.32.88: Error getting validation data")
        self.assertEqual([c.challenge_type for c in status.challenges], ["http-01", "tls-alpn-01"])
        self.assertIn(f"Fetching http://{DOMAIN}/", status.challenges[0].text)
        self.assertEqual(status.next_attempt, started + 9.0 + 60)

    def test_events_before_the_start_or_for_other_domains_do_not_count(self) -> None:
        started = self.now - 30
        old = events(owner_log(started - 3600))
        status = public_cert.evaluate(runtime(started), None, old, self.now)
        self.assertEqual(status.state, "pending")
        other = events([line.replace(DOMAIN, "other.example.com") for line in owner_log(started)])
        # "will retry" has no identifier: it counts, nothing else does.
        status = public_cert.evaluate(runtime(started), None, [e for e in other if e.identifier], self.now)
        self.assertEqual(status.state, "pending")

    def test_ok_ignores_obtain_errors(self) -> None:
        started = self.now - 600
        cert = fake_cert(89, mtime=self.now - 60)
        status = public_cert.evaluate(runtime(started), cert, events(owner_log(started)), self.now)
        self.assertEqual(status.state, "ok")
        self.assertTrue(status.has_valid_certificate)
        self.assertIsNone(status.last_error)
        self.assertIsNone(status.retry)

    def test_renewal_failing(self) -> None:
        started = self.now - 600
        cert = fake_cert(20, mtime=started - 86400 * 60)
        renew = [line.replace('"tls.obtain"', '"tls.renew"') for line in owner_log(started)]
        status = public_cert.evaluate(runtime(started), cert, events(renew), self.now)
        self.assertEqual(status.state, "renewal_failing")
        self.assertTrue(status.has_valid_certificate)
        assert status.last_error is not None
        self.assertEqual(status.last_error.logger, "tls.renew")
        # A renewal error older than the stored certificate does not count.
        cert_newer = fake_cert(89, mtime=self.now - 1)
        status = public_cert.evaluate(runtime(started), cert_newer, events(renew), self.now)
        self.assertEqual(status.state, "ok")

    def test_success_clears_earlier_errors(self) -> None:
        started = self.now - 600
        lines = owner_log(started) + [json.dumps({
            "level": "info", "ts": started + 100, "logger": "tls.renew",
            "msg": "certificate renewed successfully", "identifier": DOMAIN,
        })]
        renew = [line.replace('"tls.obtain"', '"tls.renew"') for line in lines]
        cert = fake_cert(89, mtime=started - 10)
        status = public_cert.evaluate(runtime(started), cert, events(renew), self.now)
        self.assertEqual(status.state, "ok")

    def test_expired_certificate_is_missing(self) -> None:
        started = self.now - 30
        cert = fake_cert(-1, mtime=started - 86400 * 91)
        status = public_cert.evaluate(runtime(started), cert, events(owner_log(started)), self.now)
        self.assertEqual(status.state, "missing")
        self.assertIs(status.certificate, cert)

    def test_unknown_without_runtime(self) -> None:
        self.assertEqual(public_cert.evaluate(None, None, [], self.now).state, "unknown")


class ChecklistTest(unittest.TestCase):
    def status(self, **kwargs) -> public_cert.Status:
        return public_cert.Status(state="missing", runtime=runtime(time.time(), **kwargs), now=time.time())

    def test_host_ports_in_the_checklist(self) -> None:
        text = "\n".join(public_cert.checklist(self.status()))
        self.assertIn("external TCP port 80 to this Home Assistant host, port 8080", text)
        self.assertIn("external TCP port 443 to this Home Assistant host, port 8443", text)
        self.assertIn(f"{DOMAIN} resolves to your public IP address", text)
        self.assertNotIn("Home Assistant itself does not use", text)

    def test_ports_80_443_and_unpublished_port(self) -> None:
        text = "\n".join(public_cert.checklist(self.status(http_host_port=80, https_host_port=443)))
        self.assertIn("Home Assistant itself does not use host port 80 / 443", text)
        text = "\n".join(public_cert.checklist(self.status(http_host_port=None)))
        self.assertIn("Container port 80/tcp is not published", text)
        text = "\n".join(public_cert.checklist(self.status(host_ports_known=False, http_host_port=None, https_host_port=None)))
        self.assertIn("port 8080 or whatever the app's Network settings show for 80/tcp", text)

    def test_dns_provider(self) -> None:
        text = "\n".join(public_cert.checklist(self.status(acme_dns_provider="cloudflare")))
        self.assertIn("The DNS provider 'cloudflare' manages the zone", text)
        self.assertNotIn("TCP port 80", text)

    def test_retry_hint(self) -> None:
        now = time.time()
        status = public_cert.evaluate(runtime(now - 30), None, events(owner_log(now - 30)), now)
        self.assertIn("next attempt around", public_cert.retry_hint(status))
        self.assertIn("restart the app to retry immediately", public_cert.retry_hint(status))


class StorageTest(unittest.TestCase):
    def test_storage_key(self) -> None:
        cases = {
            "home.example.com": "home.example.com",
            "Home.Example.COM": "home.example.com",
            "*.example.com": "wildcard_.example.com",
            " a+b.example.com ": "a_plus_b.example.com",
        }
        for domain, key in cases.items():
            with self.subTest(domain=domain):
                self.assertEqual(public_cert.storage_key(domain), key)

    @unittest.skipUnless(shutil.which("openssl"), "needs the openssl CLI")
    def test_find_certificate_picks_the_one_that_expires_last(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            def make(issuer_dir: str, days: int, issuer: str) -> Path:
                d = Path(tmp, "certificates", issuer_dir, DOMAIN)
                d.mkdir(parents=True)
                crt = d / f"{DOMAIN}.crt"
                subprocess.run(
                    ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                     "-nodes", "-subj", issuer, "-days", str(days), "-keyout", str(d / "key.pem"),
                     "-out", str(crt)],
                    check=True, capture_output=True,
                )
                return crt

            make("acme.zerossl.com-v2-dv90", 10, "/O=ZeroSSL/CN=ZeroSSL ECC Domain Secure Site CA")
            le = make("acme-v02.api.letsencrypt.org-directory", 90, "/C=US/O=Let's Encrypt, Inc./CN=E7")
            cert = public_cert.find_certificate(DOMAIN, tmp)
            assert cert is not None
            self.assertEqual(cert.path, str(le))
            self.assertEqual(cert.issuer, "Let's Encrypt, Inc. (E7)")
            self.assertIn(cert.days_left(time.time()), (89, 90))
            self.assertRegex(cert.fingerprint_sha256, r"^[0-9a-f]{64}$")
            self.assertIsNone(public_cert.find_certificate("other.example.com", tmp))

            # The whole status from the files, as the panel reads it.
            log = Path(tmp, "log", "acme.log")
            log.parent.mkdir()
            started = time.time() - 30
            log.write_text("\n".join(owner_log(started)) + "\n")
            rt = Path(tmp, "runtime.json")
            rt.write_text(json.dumps({
                "domain": DOMAIN, "started_at": started, "http_host_port": 8080,
                "https_host_port": 8443, "host_ports_known": True,
                "acme_log": str(log), "caddy_storage": tmp,
            }))
            original = public_cert.RUNTIME_FILE
            public_cert.RUNTIME_FILE = rt
            try:
                status = public_cert.current_status()
            finally:
                public_cert.RUNTIME_FILE = original
            self.assertEqual(status.state, "ok")
            self.assertEqual(status.certificate.issuer if status.certificate else None, "Let's Encrypt, Inc. (E7)")


if __name__ == "__main__":
    unittest.main()
