"""Unit tests for cert-mgr/headerauth.py (header authentication, 2.3.0):
the option rules, the key file, scrubbing, the card's facts - and that no
message, fact or file but the key file ever holds the key.

Standard library only. Runs against the repository's module, or the
installed one with CERT_MGR_DIR - see test_monitor.py.
"""
from __future__ import annotations

import io
import json
import os
import secrets
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

CERT_MGR = Path(
    os.environ.get("CERT_MGR_DIR")
    or Path(__file__).resolve().parents[2] / "rootfs" / "usr" / "lib" / "cert-mgr"
)
sys.path.insert(0, str(CERT_MGR))

import headerauth  # noqa: E402


def fake_key(length: int = 53) -> str:
    """An obviously fake key of the allowed character set, new per call."""
    key = "fakekey.NOT-A-SECRET." + secrets.token_hex(160)
    assert len(key) >= length
    return key[:length]


class NameTest(unittest.TestCase):
    def test_good_names(self) -> None:
        for name in ("X-Custom-PSK", "x-custom-psk", "Garmin-Key", "A", "X" + "a" * 63, "My-Header-2"):
            with self.subTest(name=name):
                self.assertIsNone(headerauth.name_error(name))

    def test_malformed_names(self) -> None:
        for name in ("", "1abc", "-abc", "X_Custom", "X Custom", "X:Custom", "X" + "a" * 64, "Ä-Key",
                     "X-Custom\n", "{host}", "X.Key"):
            with self.subTest(name=name):
                error = headerauth.name_error(name)
                self.assertIsNotNone(error)
                self.assertIn("1-64", error)
                self.assertIn("X-Custom-PSK", error)  # what a good name looks like

    def test_reserved_names(self) -> None:
        """The brief's list, case-insensitively, and every name with a
        reserved prefix."""
        for name in ("Authorization", "authorization", "COOKIE", "Set-Cookie", "Host", "Connection",
                     "Upgrade", "Content-Length", "Content-Type", "Transfer-Encoding", "TE", "te",
                     "Trailer", "Keep-Alive", "Origin", "Referer", "User-Agent", "Forwarded",
                     "X-Real-IP", "x-real-ip", "Via", "Range", "Expect", "Date",
                     "Accept", "Accept-Language", "Sec-WebSocket-Key", "Sec-Fetch-Mode", "Proxy-Authorization",
                     "If-None-Match", "Cache-Control", "Content-Encoding", "X-Forwarded-For",
                     "x-forwarded-host", "X-Hass-Source", "X-Hassio-Key", "X-Ingress-Path",
                     "X-Supervisor-Token", "X-HA-Access", "x-ha-key", "CF-Connecting-IP", "cf-ray"):
            with self.subTest(name=name):
                error = headerauth.name_error(name)
                self.assertIsNotNone(error)
                self.assertIn("browsers, Home Assistant or the proxy", error)

    def test_the_value_is_never_quoted(self) -> None:
        """B-9: a key pasted into header_auth_name by mistake is in no
        message; the length may be."""
        marker = fake_key(43)  # not a valid name: it contains '.'
        error = headerauth.name_error(marker)
        self.assertIn("(43 characters)", error)
        self.assertNotIn(marker, error)
        self.assertNotIn(marker[:12], error)
        reserved = "X-Forwarded-" + "abcdefghij" * 3
        self.assertNotIn(reserved, headerauth.name_error(reserved))

    def test_names_that_only_look_reserved(self) -> None:
        for name in ("X-Hosted", "Hostname-Key", "My-Authorization", "X-Real-IPv6x", "Datex", "X-Hae"):
            with self.subTest(name=name):
                # "X-Hae" does not start with "X-HA-"; "Datex" is not "Date".
                self.assertIsNone(headerauth.name_error(name))


class KeyTest(unittest.TestCase):
    def test_good_keys(self) -> None:
        for key in (fake_key(32), fake_key(256), "A" * 32, "abc~_.+/=-" * 4, fake_key(43)):
            with self.subTest(length=len(key)):
                self.assertIsNone(headerauth.key_error(key))

    def test_length(self) -> None:
        for length in (1, 31, 257, 1000):
            key = (fake_key(256) * 4)[:length]
            with self.subTest(length=length):
                error = headerauth.key_error(key)
                self.assertIn(f"has {length} characters; it needs 32 to 256", error)
                self.assertIn("openssl rand -base64 32", error)
                if length >= 8:  # a single letter is in any sentence
                    self.assertNotIn(key, error)
                    self.assertNotIn(key[-8:], error)

    def test_characters_that_change_the_matcher(self) -> None:
        """REPORT-I I-4: a wildcard, a placeholder, a comment, a heredoc,
        two tokens, quoting characters - and nothing is trimmed."""
        base = fake_key(40)
        for bad in ("*", "{", "}", "{host}", "{$X}", "#", "<<", " ", "\t", "\n", "\r", '"', "'", "`", "\\",
                    ",", ";", ":", "?", "%", "@", "&", "!", "ä", "\x00"):
            for key in (bad + base, base + bad, base[:20] + bad + base[20:]):
                with self.subTest(bad=repr(bad), at=key.index(bad)):
                    error = headerauth.key_error(key)
                    self.assertIsNotNone(error)
                    self.assertIn("not allowed", error)
                    # Never the key or a part of it (the offending character
                    # is named only as an example from a fixed list).
                    self.assertNotIn(base[:10], error)
                    self.assertNotIn(base[-10:], error)

    def test_not_text(self) -> None:
        for value in (12345678901234567890123456789012345, ["x" * 40], {"k": "x" * 40}, True):
            with self.subTest(value=type(value).__name__):
                self.assertEqual(headerauth.key_error(value), "header_auth_key must be text.")


class SetupTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.options = self.tmp / "options.json"
        self.key_file = self.tmp / "etc" / "header-auth.key"

    def tearDown(self) -> None:
        for path in sorted(self.tmp.rglob("*"), reverse=True):
            path.rmdir() if path.is_dir() else path.unlink()
        self.tmp.rmdir()

    def write(self, **options: object) -> None:
        self.options.write_text(json.dumps({"domain": "home.example.com", **options}))

    def test_off_by_default_and_for_options_saved_before_2_3_0(self) -> None:
        for options in ({}, {"header_auth_key": ""}, {"header_auth_key": None, "header_auth_name": None},
                        {"header_auth_name": "", "header_auth_key": ""}):
            with self.subTest(options=options):
                self.write(**options)
                self.key_file.parent.mkdir(exist_ok=True)
                self.key_file.write_text("left over from a previous start")
                facts = headerauth.setup(self.options, self.key_file)
                self.assertEqual(facts, {"enabled": False, "name": "X-Custom-PSK", "key_length": 0})
                self.assertFalse(self.key_file.exists(), "the key file of a previous start is removed")

    def test_on_writes_the_key_file_0600_without_line_break(self) -> None:
        key = fake_key(43)
        self.write(header_auth_name="Garmin-Key", header_auth_key=key)
        facts = headerauth.setup(self.options, self.key_file)
        self.assertEqual(facts, {"enabled": True, "name": "Garmin-Key", "key_length": 43})
        self.assertNotIn(key, json.dumps(facts))
        self.assertEqual(self.key_file.read_text(), key)
        self.assertEqual(stat.S_IMODE(self.key_file.stat().st_mode), 0o600)
        self.assertEqual([p.name for p in self.key_file.parent.iterdir()], ["header-auth.key"])  # no temp file left
        # The default name for an empty or missing name.
        self.write(header_auth_key=key)
        self.assertEqual(headerauth.setup(self.options, self.key_file)["name"], "X-Custom-PSK")

    def test_refusals_never_contain_the_key(self) -> None:
        key = fake_key(60)
        cases = {
            "short": dict(header_auth_key=key[:31]),
            "blank": dict(header_auth_key=key[:30] + " " + key[30:]),
            "trailing line break": dict(header_auth_key=key + "\n"),
            "star": dict(header_auth_key=key + "*"),
            "placeholder": dict(header_auth_key="{env.HOME}" + key),
            "bad name": dict(header_auth_name="X_Key", header_auth_key=key),
            "key pasted into the name": dict(header_auth_name=key, header_auth_key=key),
            "reserved name": dict(header_auth_name="Authorization", header_auth_key=key),
        }
        for case, options in cases.items():
            with self.subTest(case=case):
                self.write(**options)
                with self.assertRaises(headerauth.OptionError) as ctx:
                    headerauth.setup(self.options, self.key_file)
                self.assertNotIn(key[:31], str(ctx.exception))
                self.assertNotIn(key[-20:], str(ctx.exception))
                self.assertFalse(self.key_file.exists())

    def test_a_bad_name_does_not_matter_while_off(self) -> None:
        self.write(header_auth_name="Authorization", header_auth_key="")
        self.assertEqual(headerauth.setup(self.options, self.key_file)["enabled"], False)

    def test_cli(self) -> None:
        key = fake_key(44)
        self.write(header_auth_key=key)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = headerauth._main(["setup", "--options", str(self.options), "--key-file", str(self.key_file)])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out.getvalue()), {"enabled": True, "name": "X-Custom-PSK", "key_length": 44})
        self.assertNotIn(key, out.getvalue() + err.getvalue())
        self.write(header_auth_key=key + "*")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = headerauth._main(["setup", "--options", str(self.options), "--key-file", str(self.key_file)])
        self.assertEqual(rc, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("not allowed", err.getvalue())
        self.assertNotIn(key, err.getvalue())

    def test_unreadable_options(self) -> None:
        self.options.write_text("{not json")
        with self.assertRaises(headerauth.OptionError) as ctx:
            headerauth.setup(self.options, self.key_file)
        self.assertIn("Could not read the add-on's options", str(ctx.exception))

    def test_scrub(self) -> None:
        key = fake_key(50)
        self.write(header_auth_key=key)
        headerauth.setup(self.options, self.key_file)
        text = f"Error: something {key} and {key}x\n"
        self.assertEqual(headerauth.scrub(text, self.key_file), "Error: something <redacted> and <redacted>x\n")
        self.assertEqual(headerauth.scrub("no key here", self.key_file), "no key here")
        self.assertEqual(headerauth.scrub(text, self.tmp / "missing"), text)
        self.key_file.write_text("")
        self.assertEqual(headerauth.scrub(text, self.key_file), text)


class CardTest(unittest.TestCase):
    def test_facts_and_card_context(self) -> None:
        runtime = {"domain": "home.example.com", "mtls_enabled": True, "access_log": True,
                   "header_auth": {"enabled": True, "name": "Garmin-Key", "key_length": 43}}
        ctx = headerauth.card_context(runtime)
        self.assertEqual((ctx["state"], ctx["name"], ctx["key_length"], ctx["mtls"], ctx["access_log"]),
                         ("on", "Garmin-Key", 43, True, True))
        off = headerauth.card_context({"domain": "home.example.com", "mtls_enabled": False})
        self.assertEqual((off["state"], off["name"], off["mtls"], off["known"]), ("off", "X-Custom-PSK", False, True))
        self.assertEqual(headerauth.card_context(None)["known"], False)
        # Garbage in runtime.json: off, the default name.
        for bad in ({"header_auth": "yes"}, {"header_auth": {"enabled": "true", "name": "a b", "key_length": -1}}):
            with self.subTest(bad=bad):
                facts = headerauth.facts(bad)
                self.assertEqual(facts, {"enabled": False, "name": "X-Custom-PSK", "key_length": 0})


if __name__ == "__main__":
    unittest.main()
