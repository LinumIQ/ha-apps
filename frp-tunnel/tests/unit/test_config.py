"""Unit tests for frp-mgr/config.py (pure logic, stdlib only).

Run from the repository root:

    python3 -m unittest discover -s frp-tunnel/tests/unit -v

``FRP_MGR_DIR`` points the tests at another copy of the panel code (CI runs
them inside the built image against /usr/lib/frp-mgr).
"""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest import mock

FRP_MGR = Path(
    os.environ.get("FRP_MGR_DIR")
    or Path(__file__).resolve().parents[2] / "rootfs" / "usr" / "lib" / "frp-mgr"
)
sys.path.insert(0, str(FRP_MGR))

import config as cfg  # noqa: E402
from tls_fixtures import CA1, CA2, EXPIRED_CA, LEAF  # noqa: E402

TOKEN = "a" * 64
OTHER_TOKEN = "b" * 64


class ValidationTests(unittest.TestCase):
    def test_hosts(self):
        self.assertEqual(cfg.normalize_host("LinumIQ.net"), "linumiq.net")
        self.assertEqual(cfg.normalize_host("frps-dev"), "frps-dev")
        self.assertEqual(cfg.normalize_host("10.0.0.5"), "10.0.0.5")
        self.assertEqual(cfg.normalize_host("::1"), "::1")
        # Surrounding whitespace is stripped; embedded junk is rejected.
        self.assertEqual(cfg.normalize_host(" linumiq.net\n"), "linumiq.net")
        for bad in ("", " ", "-bad.net", "bad-.net", "a..b", "a b", 'x"y', "a\nb.net",
                    "a" * 64 + ".net", "x/y", None, 7000, "é.net",
                    # IPv6 zone IDs: Python accepts any text after '%'.
                    "fe80::1%eth0", 'fe80::1%"x', "fe80::1%\nevil", "fe80::1%a]b c", "::1%é"):
            self.assertIsNone(cfg.normalize_host(bad), repr(bad))

    def test_ports(self):
        self.assertEqual(cfg.normalize_port(7000), 7000)
        self.assertEqual(cfg.normalize_port("7001"), 7001)
        self.assertEqual(cfg.normalize_port(1), 1)
        self.assertEqual(cfg.normalize_port(65535), 65535)
        for bad in (0, 65536, -1, "0", "70000", "7000a", "", " ", True, False, 7000.0, None, "²"):
            self.assertIsNone(cfg.normalize_port(bad), repr(bad))

    def test_domain_base(self):
        self.assertEqual(cfg.normalize_domain_base("dev.linumiq.net"), "dev.linumiq.net")
        self.assertEqual(cfg.normalize_domain_base("LinumIQ.net."), "linumiq.net")
        self.assertEqual(cfg.normalize_domain_base("dev.linumiq.net\n"), "dev.linumiq.net")
        for bad in ("linumiq", "10.0.0.5", "1.2.3.4", "*.linumiq.net", ".linumiq.net",
                    "linumiq.123", "a_b.net", "dev.linumiq\n.net", "", None, 3):
            self.assertIsNone(cfg.normalize_domain_base(bad), repr(bad))

    def test_subdomain_and_token(self):
        self.assertEqual(cfg.normalize_subdomain("My-Home"), "my-home")
        for bad in ("-x", "x-", "a.b", "a_b", "", "a" * 64, None):
            self.assertIsNone(cfg.normalize_subdomain(bad), repr(bad))
        self.assertEqual(cfg.normalize_token(TOKEN), TOKEN)
        for bad in ("short", 'abc"defghij', "abcdefgh\\ij", "abcd efghij", "abcdefghij\n", None, 12345678):
            self.assertIsNone(cfg.normalize_token(bad), repr(bad))

    def test_base_url(self):
        self.assertEqual(cfg.normalize_base_url("https://app-dev.linumiq.net/"), "https://app-dev.linumiq.net")
        self.assertEqual(cfg.normalize_base_url("http://web-dev:3000"), "http://web-dev:3000")
        self.assertEqual(cfg.normalize_base_url("https://[::1]:8443"), "https://[::1]:8443")
        for bad in ("ftp://x.net", "https://", "https://x.net/?a=1", "https://x.net/#f",
                    "https://x .net", "javascript:alert(1)", "https://x.net:99999", None,
                    "https://user:pw@app.example.net", "https://evil@app.example.net",
                    "https://[fe80::1%25eth0]", "https://[fe80::1%eth0]:443",
                    "https://app.example.net/\x00", "https://app.example.net/a\\b",
                    'https://app.example.net/"x'):
            self.assertIsNone(cfg.normalize_base_url(bad), repr(bad))


class CaPemTests(unittest.TestCase):
    """normalize_ca_pem: only parseable X.509 CA certificates are pinned."""

    def test_accepts_ca_certificates_and_normalises(self):
        self.assertEqual(cfg.normalize_ca_pem(CA1), CA1)
        self.assertEqual(cfg.normalize_ca_pem(CA1 + CA2), CA1 + CA2)  # order kept
        # CRLF, indentation, blank lines and a missing final newline are fine;
        # the result is canonical PEM.
        messy = "\n\n" + CA1.replace("\n", "\r\n").replace("MII", "  MII") + "\n" + CA2.rstrip("\n")
        self.assertEqual(cfg.normalize_ca_pem(messy), CA1 + CA2)
        self.assertEqual(cfg.normalize_ca_pem(CA1 + CA1), CA1)  # duplicates dropped
        self.assertEqual(cfg.normalize_ca_pem(EXPIRED_CA), EXPIRED_CA)  # validity is not judged here

    def test_rejects_everything_else(self):
        body = "".join(CA1.splitlines()[1:-1])
        bad_der = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        for bad in (
            LEAF,                                   # not a CA
            CA1 + LEAF,                             # one non-CA spoils the bundle
            CA1.replace("CERTIFICATE", "PRIVATE KEY"),
            CA1 + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            CA1.replace("END CERTIFICATE", "END X509 CRL"),
            "junk\n" + CA1,
            CA1 + "trailing junk",
            CA1 + "\nx\n" + CA2,
            CA1.replace(body[10:14], "!!!!"),       # not base64
            CA1.replace(body[:8], "AAAAAAAA"),      # base64, but broken DER
            bad_der,
            "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
            body, "", "   ", None, 42, [CA1], b"x",
            CA1 + " " * cfg.CA_PEM_MAX_CHARS,       # too large
        ):
            self.assertIsNone(cfg.normalize_ca_pem(bad), repr(bad)[:80])

    def test_bundle_size_limit(self):
        with mock.patch.object(cfg, "CA_MAX_CERTS", 1):
            self.assertIsNone(cfg.normalize_ca_pem(CA1 + CA2))
            self.assertEqual(cfg.normalize_ca_pem(CA1), CA1)

    def test_describe_ca(self):
        info = cfg.describe_ca(CA1 + EXPIRED_CA)
        self.assertEqual(sorted(i["subject"] for i in info), ["Expired test CA", "Test frps CA 1"])
        by_subject = {i["subject"]: i for i in info}
        self.assertEqual(by_subject["Test frps CA 1"]["not_after"], "2125-12-31")
        self.assertFalse(by_subject["Test frps CA 1"]["expired"])
        self.assertTrue(by_subject["Expired test CA"]["expired"])
        self.assertEqual(cfg.describe_ca(LEAF), [])
        self.assertEqual(cfg.describe_ca(None), [])


class MaskedEmailTests(unittest.TestCase):
    def test_masked_email(self):
        for ok in ("g***@linumiq.com", "j***.d***@e***.co.uk", "a@b.c", "x+tag***@sub-domain.example"):
            self.assertEqual(cfg.normalize_masked_email(ok), ok)
        self.assertEqual(cfg.normalize_masked_email(" g***@linumiq.com\n"), "g***@linumiq.com")
        for bad in ("", "no-at-sign", "a@@b.c", "<b>x</b>@e.com", "a b@c.d", "a@b.c\r\nX: y",
                    "g***@linumiq.com‮", "a@" + "b" * 254, None, 3):
            self.assertIsNone(cfg.normalize_masked_email(bad), repr(bad))


class LogLevelTests(unittest.TestCase):
    def test_addon_levels_map_to_frpc_levels(self):
        expected = {"trace": "trace", "debug": "debug", "info": "info", "notice": "info",
                    "warning": "warn", "warn": "warn", "error": "error", "fatal": "error"}
        for level, frp in expected.items():
            self.assertEqual(cfg.normalize_log_level(level), frp, level)
        self.assertIsNone(cfg.normalize_log_level("verbose"))


class OptionsTests(unittest.TestCase):
    def test_only_explicit_and_valid_options_count(self):
        raw = {
            "log_level": "debug",
            "app_base": "https://app-dev.linumiq.net",
            "api_base": "",            # empty  -> not set
            "server_addr": None,       # null   -> not set
            "server_port": 7001,
            "domain_base": "   ",      # blank  -> not set
            "local_host": "bad host",  # invalid -> ignored
            "local_port": "8124",
            "unknown": "x",
        }
        with self.assertLogs("frp-mgr.config", "ERROR"):
            opts = cfg.parse_options(raw)
        self.assertEqual(
            opts,
            {
                "log_level": "debug",
                "app_base": "https://app-dev.linumiq.net",
                "server_port": 7001,
                "local_port": 8124,
            },
        )

    def test_non_mapping(self):
        self.assertEqual(cfg.parse_options([]), {})

    def test_verify_server_option(self):
        self.assertEqual(cfg.parse_options({"verify_server": False}), {"verify_server": False})
        self.assertEqual(cfg.parse_options({"verify_server": True}), {"verify_server": True})
        self.assertEqual(cfg.parse_options({"verify_server": "false"}), {"verify_server": False})
        self.assertEqual(cfg.parse_options({"verify_server": None}), {})  # unset -> default (on)
        with self.assertLogs("frp-mgr.config", "ERROR"):
            opts, errors = cfg.parse_options_report({"verify_server": "nope"})
        self.assertEqual(opts, {})  # invalid -> ignored -> verification stays on
        self.assertIn("true or false", errors["verify_server"])

    def test_report_lists_invalid_options_with_hints(self):
        raw = {"log_level": "warn", "server_addr": "my_ha\nhost", "domain_base": "x",
               "app_base": "https://u:p@app.example.net", "local_port": 8123}
        with self.assertLogs("frp-mgr.config", "ERROR"):
            opts, errors = cfg.parse_options_report(raw)
        self.assertEqual(opts, {"log_level": "warn", "local_port": 8123})
        self.assertEqual(set(errors), {"server_addr", "domain_base", "app_base"})
        for key, message in errors.items():
            self.assertTrue(message.startswith(f"{key}="), message)
            self.assertIn("is invalid (expected", message)
            self.assertNotIn("\n", message)  # sanitised (no raw newline)
        self.assertIn("dev.linumiq.net", errors["domain_base"])
        # URL credentials are never echoed.
        self.assertNotIn("u:p", errors["app_base"])
        self.assertIn("https://***@app.example.net", errors["app_base"])

    def test_load_options_report_file_problems(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = cfg.Paths(Path(tmp))
            self.assertEqual(cfg.load_options_report(paths), ({}, {}))  # missing: defaults
            paths.options.write_text("{not json")
            with self.assertLogs("frp-mgr.config", "ERROR"):
                opts, errors = cfg.load_options_report(paths)
            self.assertEqual(opts, {})
            self.assertIn("options.json", errors)
            paths.options.write_text("[1, 2]")
            with self.assertLogs("frp-mgr.config", "ERROR"):
                self.assertIn("options.json", cfg.load_options_report(paths)[1])
            paths.options.write_text(json.dumps({"server_port": 7001}))
            self.assertEqual(cfg.load_options_report(paths), ({"server_port": 7001}, {}))


class PairingResponseTests(unittest.TestCase):
    """Validation of POST /api/device/code responses (rendered in the panel)."""

    APP = "https://app.linumiq.net"
    DEVICE_CODE = "0123456789abcdef" * 4

    def body(self, **extra):
        body = {
            "device_code": self.DEVICE_CODE,
            "user_code": "ABCD-EF23",
            "verification_uri": "https://app.linumiq.net/activate",
            "verification_uri_complete": "https://app.linumiq.net/activate?code=ABCD-EF23",
            "interval": 5,
            "expires_in": 600,
        }
        body.update(extra)
        return {k: v for k, v in body.items() if v is not ...}

    def assertRejected(self, app_base=APP, **extra):
        with self.assertRaises(cfg.PairingResponseError, msg=repr(extra)) as ctx:
            cfg.parse_pairing_response(self.body(**extra), app_base)
        # The message never echoes the offending value.
        for value in extra.values():
            if isinstance(value, str) and len(value) > 3:
                self.assertNotIn(value, str(ctx.exception))
        return ctx.exception

    def test_dashboard_response_is_accepted(self):
        parsed = cfg.parse_pairing_response(self.body(), self.APP)
        self.assertEqual(parsed, {
            "device_code": self.DEVICE_CODE,
            "user_code": "ABCD-EF23",
            "verification_uri": "https://app.linumiq.net/activate",
            "verification_uri_complete": "https://app.linumiq.net/activate?code=ABCD-EF23",
            "interval": 5,
            "expires_in": 600,
        })
        self.assertEqual(set(parsed), set(cfg.PAIRING_KEYS))
        # Unknown keys are dropped; the host comparison ignores case.
        parsed = cfg.parse_pairing_response(
            self.body(extra="x", verification_uri_complete="https://APP.linumiq.net:443/activate"),
            self.APP)
        self.assertNotIn("extra", parsed)
        self.assertEqual(parsed["verification_uri_complete"], "https://APP.linumiq.net:443/activate")

    def test_optional_values_default(self):
        parsed = cfg.parse_pairing_response(
            self.body(interval=..., expires_in=None, verification_uri=..., verification_uri_complete=""),
            self.APP)
        self.assertEqual(parsed["interval"], cfg.DEFAULT_POLL_INTERVAL)
        self.assertEqual(parsed["expires_in"], cfg.DEFAULT_EXPIRES_IN)
        self.assertIsNone(parsed["verification_uri"])
        self.assertIsNone(parsed["verification_uri_complete"])

    def test_interval_and_expires_in(self):
        for ok in (1, 60):
            self.assertEqual(cfg.parse_pairing_response(self.body(interval=ok), self.APP)["interval"], ok)
        for bad in (0, 61, -5, "5", 5.0, 5.5, True, [], {}, "1;fetch('//evil')//"):
            self.assertRejected(interval=bad)
        for ok in (1, 3600):
            self.assertEqual(cfg.parse_pairing_response(self.body(expires_in=ok), self.APP)["expires_in"], ok)
        for bad in (0, -1, 3601, "600", 600.0, False):
            self.assertRejected(expires_in=bad)

    def test_user_code(self):
        for bad in ("abcd-ef23", "ABCD-EF2", "ABCDEF23", "ABCD_EF23", "ABCD-EF23\n", " ABCD-EF23",
                    "<b>X</b>", "AB<i>CD", "ÄBCD-EF23", "", None, 12345678):
            self.assertRejected(user_code=bad)

    def test_device_code(self):
        for ok in ("a" * 16, "A-b_c.d~" * 8, "x" * 512):
            self.assertEqual(cfg.parse_pairing_response(self.body(device_code=ok), self.APP)["device_code"], ok)
        for bad in ("a" * 15, "x" * 513, 'abc"defghijklmnopq', "abcdefghijklmnop q", "abcdefghijklmnop\n",
                    "abcdefghijklmnop/", "abcdefghijklmnop=", "", None, 1234567890123456):
            self.assertRejected(device_code=bad)

    def test_verification_links(self):
        for key in ("verification_uri", "verification_uri_complete"):
            for bad in (
                "javascript:fetch('//evil/'+localStorage.hassTokens)",
                "JavaScript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
                "vbscript:x",
                "http://app.linumiq.net/activate",           # http with an https app_base
                "https://evil.example.com/activate",
                "https://evil.app.linumiq.net/activate",     # sub-domain of app host
                "https://app.linumiq.net.evil.com/activate",
                "https://app.linumiq.net@evil.com/activate",  # user info
                "https://user:pw@app.linumiq.net/activate",
                "https://evil.com\\@app.linumiq.net/",     # backslash (browsers: '/')
                "//app.linumiq.net/activate",                # scheme-relative
                "https:app.linumiq.net/activate",
                "/activate",
                'https://app.linumiq.net/a"onmouseover="x',
                "https://app.linumiq.net/a b",
                "https://app.linumiq.net/a\tb",
                "https://app.linumiq.net/\n",
                "https://app.linumiq.net/<script>",
                "https://app.linumiq.net:99999/activate",
                "https://app.linumiq.net/" + "a" * 2048,
                42, ["https://app.linumiq.net/activate"],
            ):
                self.assertRejected(**{key: bad})

    def test_http_links_only_for_an_http_app_base(self):
        dev = "http://web-dev:3000"
        parsed = cfg.parse_pairing_response(self.body(
            verification_uri="http://web-dev:3000/activate",
            verification_uri_complete="https://WEB-DEV/activate?code=ABCD-EF23"), dev)
        self.assertEqual(parsed["verification_uri"], "http://web-dev:3000/activate")
        self.assertRejected(app_base=dev, verification_uri="http://app.linumiq.net/activate")
        self.assertRejected(app_base=dev, verification_uri="javascript:alert(1)")
        # An unusable app_base accepts no link at all.
        self.assertRejected(app_base="not a url", verification_uri="https://app.linumiq.net/activate")

    def test_non_object(self):
        for body in (None, [], "x", 1):
            with self.assertRaises(cfg.PairingResponseError):
                cfg.parse_pairing_response(body, self.APP)


class SanitizeTests(unittest.TestCase):
    def test_control_and_format_characters_removed(self):
        text = "line1\r\nINFO: forged\tx\x00y\u202eevil\u2028z\x1b[31m"
        out = cfg.sanitize_text(text)
        self.assertEqual(out, "line1 INFO: forged x y evil z [31m")
        self.assertTrue(out.isprintable())

    def test_truncation(self):
        self.assertEqual(cfg.sanitize_text("x" * 50, limit=10), "xxxxxxx...")
        self.assertEqual(cfg.sanitize_text("  a   b  "), "a b")
        self.assertEqual(cfg.sanitize_text(ValueError("boom\n")), "boom")

    def test_secrets_redacted_in_raw_and_escaped_form(self):
        secret = "SECRETDEVICETOKEN\n"
        # What urllib raises for an invalid header value:
        message = "Invalid header value b'Bearer SECRETDEVICETOKEN\\n'"
        out = cfg.sanitize_text(message, secrets=(secret,))
        self.assertNotIn("SECRETDEVICETOKEN", out)
        self.assertIn("<redacted>", out)
        out = cfg.sanitize_text(f"token {TOKEN} leaked", secrets=(TOKEN, None, ""))
        self.assertEqual(out, "token <redacted> leaked")


class TunnelResponseTests(unittest.TestCase):
    def test_full_v21_response(self):
        state, warnings = cfg.apply_tunnel_response(
            {"device_token": "dt"},
            {"subdomain": "home", "token": TOKEN, "server_addr": "linumiq.net",
             "server_port": 7001, "domain_base": "dev.linumiq.net"},
        )
        self.assertEqual(warnings, [])
        self.assertEqual(state["device_token"], "dt")
        self.assertEqual(state["subdomain"], "home")
        self.assertEqual(state["token"], TOKEN)
        self.assertEqual(state["server_addr"], "linumiq.net")
        self.assertEqual(state["server_port"], 7001)
        self.assertEqual(state["domain_base"], "dev.linumiq.net")
        self.assertTrue(cfg.is_paired(state))

    def test_old_server_without_domain_base_drops_stale_value(self):
        old = {"device_token": "dt", "domain_base": "dev.linumiq.net", "server_port": 7001}
        state, _ = cfg.apply_tunnel_response(
            old, {"subdomain": "home", "token": TOKEN, "server_addr": "linumiq.net", "server_port": 7000}
        )
        self.assertNotIn("domain_base", state)
        self.assertEqual(state["server_port"], 7000)

    def test_invalid_server_values_are_dropped_with_warning(self):
        state, warnings = cfg.apply_tunnel_response(
            {"device_token": "dt"},
            {"subdomain": "home", "token": TOKEN, "server_addr": "evil\nhost",
             "server_port": 70000, "domain_base": "10.0.0.1"},
        )
        self.assertEqual(len(warnings), 3)
        for key in cfg.SERVER_KEYS:
            self.assertNotIn(key, state)

    def test_v22_tls_and_account_fields(self):
        body = {"subdomain": "home", "token": TOKEN, "server_addr": "linumiq.net",
                "server_name": "FRPS.linumiq.net", "server_ca_pem": CA1.replace("\n", "\r\n"),
                "account_email_masked": "g***@linumiq.com"}
        state, warnings = cfg.apply_tunnel_response({"device_token": "dt"}, body)
        self.assertEqual(warnings, [])
        self.assertEqual(state["server_ca_pem"], CA1)  # normalised
        self.assertEqual(state["server_name"], "frps.linumiq.net")
        self.assertEqual(state["account_email_masked"], "g***@linumiq.com")
        self.assertNotIn("server_ca_note", state)

    def test_ca_is_kept_when_the_server_stops_sending_it(self):
        pinned = {"device_token": "dt", "server_ca_pem": CA1, "server_name": "frps.linumiq.net",
                  "account_email_masked": "g***@linumiq.com"}
        for missing in ({}, {"server_ca_pem": None}, {"server_ca_pem": ""}, {"server_ca_pem": "  "}):
            body = dict({"subdomain": "home", "token": TOKEN}, **missing)
            with self.subTest(missing=missing):
                state, warnings = cfg.apply_tunnel_response(pinned, body)
                self.assertEqual(state["server_ca_pem"], CA1)
                self.assertEqual(state["server_name"], "frps.linumiq.net")  # sticky as well
                self.assertEqual(state["server_ca_note"], "missing")
                self.assertTrue(any("stays pinned" in w for w in warnings), warnings)
                self.assertNotIn("account_email_masked", state)  # authoritative, not sticky

    def test_invalid_ca_never_replaces_or_downgrades(self):
        pinned = {"device_token": "dt", "server_ca_pem": CA1}
        body = {"subdomain": "home", "token": TOKEN, "server_ca_pem": LEAF, "server_name": "bad name"}
        state, warnings = cfg.apply_tunnel_response(pinned, body)
        self.assertEqual(state["server_ca_pem"], CA1)
        self.assertEqual(state["server_ca_note"], "invalid")
        self.assertEqual(len(warnings), 2)  # CA + server_name
        self.assertNotIn("server_name", state)
        # Without a previous CA there is nothing to keep: unverified, flagged.
        state, _ = cfg.apply_tunnel_response({"device_token": "dt"}, body)
        self.assertNotIn("server_ca_pem", state)
        self.assertEqual(state["server_ca_note"], "invalid")

    def test_ca_rotation_and_recovery_clear_the_note(self):
        state = {"device_token": "dt", "server_ca_pem": CA1, "server_ca_note": "missing"}
        state, warnings = cfg.apply_tunnel_response(
            state, {"subdomain": "home", "token": TOKEN, "server_ca_pem": CA2 + CA1})
        self.assertEqual(warnings, [])
        self.assertEqual(state["server_ca_pem"], CA2 + CA1)
        self.assertNotIn("server_ca_note", state)

    def test_invalid_account_email_is_dropped(self):
        state, warnings = cfg.apply_tunnel_response(
            {"device_token": "dt", "account_email_masked": "old***@x.y"},
            {"subdomain": "home", "token": TOKEN, "account_email_masked": "<script>@x"})
        self.assertNotIn("account_email_masked", state)
        self.assertEqual(len(warnings), 1)

    def test_missing_or_invalid_mandatory_fields(self):
        for body in (None, [], {}, {"subdomain": "home"}, {"token": TOKEN},
                     {"subdomain": "bad.sub", "token": TOKEN},
                     {"subdomain": "home", "token": 'x"injected"'}):
            with self.assertRaises(cfg.TunnelResponseError, msg=repr(body)):
                cfg.apply_tunnel_response({}, body)


class PrecedenceTests(unittest.TestCase):
    SERVER_STATE = {
        "device_token": "dt", "subdomain": "home", "token": TOKEN,
        "server_addr": "srv.example.net", "server_port": 7001, "domain_base": "dev.linumiq.net",
    }

    def test_defaults(self):
        s = cfg.effective_settings({}, {})
        self.assertEqual((s.server_addr, s.server_port, s.domain_base), ("linumiq.net", 7000, "linumiq.net"))
        self.assertEqual((s.local_host, s.local_port, s.log_level), ("homeassistant", 8123, "info"))
        self.assertEqual(s.app_base, "https://app.linumiq.net")
        self.assertEqual(s.sources["server_addr"], "default")
        self.assertEqual(s.sources["domain_base"], "server_addr")

    def test_server_values_beat_defaults(self):
        s = cfg.effective_settings({}, self.SERVER_STATE)
        self.assertEqual((s.server_addr, s.server_port, s.domain_base),
                         ("srv.example.net", 7001, "dev.linumiq.net"))
        self.assertEqual({s.sources[k] for k in cfg.SERVER_KEYS}, {"server"})

    def test_explicit_options_beat_server_values(self):
        opts = cfg.parse_options({"server_addr": "frps-dev", "server_port": 7100, "domain_base": "x.example.org"})
        s = cfg.effective_settings(opts, self.SERVER_STATE)
        self.assertEqual((s.server_addr, s.server_port, s.domain_base), ("frps-dev", 7100, "x.example.org"))
        self.assertEqual({s.sources[k] for k in cfg.SERVER_KEYS}, {"option"})

    def test_partial_override(self):
        opts = cfg.parse_options({"server_port": 7002, "domain_base": ""})
        s = cfg.effective_settings(opts, self.SERVER_STATE)
        self.assertEqual((s.server_addr, s.server_port, s.domain_base),
                         ("srv.example.net", 7002, "dev.linumiq.net"))

    def test_old_server_domain_base_falls_back_to_server_addr(self):
        state = {"server_addr": "linumiq.net", "server_port": 7000}
        s = cfg.effective_settings({}, state)
        self.assertEqual(s.domain_base, "linumiq.net")
        self.assertEqual(s.sources["domain_base"], "server_addr")
        # An IP / single-label server_addr is no DNS suffix -> built-in default.
        s = cfg.effective_settings(cfg.parse_options({"server_addr": "10.1.2.3"}), {})
        self.assertEqual((s.domain_base, s.sources["domain_base"]), ("linumiq.net", "default"))

    def test_tampered_state_values_are_ignored(self):
        state = dict(self.SERVER_STATE, server_addr='x"y', server_port="0", domain_base="nodot")
        s = cfg.effective_settings({}, state)
        self.assertEqual((s.server_addr, s.server_port, s.domain_base), ("linumiq.net", 7000, "linumiq.net"))

    def test_tls_modes(self):
        s = cfg.effective_settings({}, self.SERVER_STATE)
        self.assertEqual(s.tls_mode, cfg.TLS_UNVERIFIED)  # no CA known (pre-2.2 server)
        self.assertEqual(s.server_name, "srv.example.net")  # falls back to server_addr
        self.assertIn("NOT verified (the server provided no CA)", s.describe())
        pinned = dict(self.SERVER_STATE, server_ca_pem=CA1, server_name="frps.example.net")
        s = cfg.effective_settings({}, pinned)
        self.assertEqual((s.tls_mode, s.server_name, s.ca_pem), (cfg.TLS_VERIFIED, "frps.example.net", CA1))
        self.assertIn("tls=verified (CA from server, serverName=frps.example.net)", s.describe())
        self.assertNotIn("BEGIN", s.describe() + repr(s))  # the PEM is not logged
        # An explicit server_addr override does not change the certificate name.
        s = cfg.effective_settings(cfg.parse_options({"server_addr": "10.0.0.7"}), pinned)
        self.assertEqual((s.server_addr, s.server_name), ("10.0.0.7", "frps.example.net"))
        # Only an explicit verify_server: false disables verification.
        s = cfg.effective_settings(cfg.parse_options({"verify_server": False}), pinned)
        self.assertEqual(s.tls_mode, cfg.TLS_DISABLED)
        self.assertIn("verify_server=false", s.describe())
        s = cfg.effective_settings(cfg.parse_options({"verify_server": True}), pinned)
        self.assertEqual(s.tls_mode, cfg.TLS_VERIFIED)
        # A tampered CA / name in the state is never pinned.
        s = cfg.effective_settings({}, dict(pinned, server_ca_pem=LEAF, server_name="bad name"))
        self.assertEqual((s.tls_mode, s.server_name), (cfg.TLS_UNVERIFIED, "srv.example.net"))


class RenderTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.paths = cfg.Paths(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, path: Path, data):
        path.write_text(json.dumps(data) if not isinstance(data, str) else data)

    def test_render_contents(self):
        settings = cfg.effective_settings(
            cfg.parse_options({"log_level": "warn", "local_host": "whoami", "local_port": 80}),
            {"server_addr": "linumiq.net", "server_port": 7001, "domain_base": "dev.linumiq.net"},
        )
        text = cfg.render_frpc_toml(settings, "home", TOKEN)
        lines = text.splitlines()
        self.assertIn('serverAddr = "linumiq.net"', lines)
        self.assertIn("serverPort = 7001", lines)
        self.assertIn("loginFailExit = false", lines)
        self.assertIn("transport.tls.enable = true", lines)
        self.assertIn('customDomains = ["home.dev.linumiq.net"]', lines)
        self.assertIn('localIP = "whoami"', lines)
        self.assertIn("localPort = 80", lines)
        self.assertIn('level = "warn"', lines)
        self.assertIn(f'token = "{TOKEN}"', lines)
        # Root keys (incl. the dotted TLS key) must precede the first table.
        first_table = next(i for i, l in enumerate(lines) if l.startswith("["))
        self.assertLess(lines.index("transport.tls.enable = true"), first_table)
        self.assertEqual(lines[lines.index("[metadatas]") + 1], f'token = "{TOKEN}"')
        if sys.version_info >= (3, 11):
            import tomllib
            doc = tomllib.loads(text)
            self.assertEqual(doc["transport"]["tls"]["enable"], True)
            self.assertEqual(doc["metadatas"]["token"], TOKEN)
            self.assertEqual(doc["proxies"][0]["customDomains"], ["home.dev.linumiq.net"])

    PINNED = {"device_token": "dt", "subdomain": "home", "token": TOKEN, "server_addr": "linumiq.net",
              "server_port": 7000, "domain_base": "linumiq.net", "server_name": "frps.linumiq.net",
              "server_ca_pem": CA1}

    def test_render_verified_pins_ca_and_server_name(self):
        self._write(self.paths.state, self.PINNED)
        result, settings = cfg.render_from_disk(self.paths)
        self.assertEqual(result, cfg.RenderResult.RENDERED)
        self.assertEqual(settings.tls_mode, cfg.TLS_VERIFIED)
        self.assertEqual(self.paths.frps_ca.read_text(), CA1)
        text = self.paths.frpc_toml.read_text()
        lines = text.splitlines()
        self.assertIn(f'transport.tls.trustedCaFile = "{self.paths.frps_ca}"', lines)
        self.assertIn('transport.tls.serverName = "frps.linumiq.net"', lines)
        self.assertIn("transport.tls.enable = true", lines)
        first_table = next(i for i, l in enumerate(lines) if l.startswith("["))
        self.assertLess(lines.index('transport.tls.serverName = "frps.linumiq.net"'), first_table)
        if sys.version_info >= (3, 11):
            import tomllib
            tls = tomllib.loads(text)["transport"]["tls"]
            self.assertEqual(tls, {"enable": True, "trustedCaFile": str(self.paths.frps_ca),
                                   "serverName": "frps.linumiq.net"})
        for path in (self.paths.frps_ca, self.paths.frpc_toml):
            # 0600 here, 0640 root:frpc in the image (frpc runs as that user)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), cfg.frpc_file_access()[0])
        self.assertEqual(cfg.render_from_disk(self.paths)[0], cfg.RenderResult.UNCHANGED)

    def test_ca_rotation_rerenders_even_if_frpc_toml_is_unchanged(self):
        self._write(self.paths.state, self.PINNED)
        cfg.render_from_disk(self.paths)
        toml_before = self.paths.frpc_toml.read_text()
        self._write(self.paths.state, dict(self.PINNED, server_ca_pem=CA2 + CA1))
        self.assertEqual(cfg.render_from_disk(self.paths)[0], cfg.RenderResult.RENDERED)
        self.assertEqual(self.paths.frpc_toml.read_text(), toml_before)
        self.assertEqual(self.paths.frps_ca.read_text(), CA2 + CA1)

    def test_render_unverified_and_disabled(self):
        unpinned = {k: v for k, v in self.PINNED.items() if k != "server_ca_pem"}
        self._write(self.paths.state, unpinned)
        result, settings = cfg.render_from_disk(self.paths)
        self.assertEqual(settings.tls_mode, cfg.TLS_UNVERIFIED)
        text = self.paths.frpc_toml.read_text()
        self.assertNotIn("trustedCaFile", text)
        self.assertIn("NOT verified (the server provided no CA)", text)
        self.assertFalse(self.paths.frps_ca.exists())
        # Pinned, then verification switched off explicitly: the CA file goes.
        self._write(self.paths.state, self.PINNED)
        cfg.render_from_disk(self.paths)
        self.assertTrue(self.paths.frps_ca.exists())
        self._write(self.paths.options, {"verify_server": False})
        result, settings = cfg.render_from_disk(self.paths)
        self.assertEqual((result, settings.tls_mode), (cfg.RenderResult.RENDERED, cfg.TLS_DISABLED))
        self.assertFalse(self.paths.frps_ca.exists())
        self.assertIn("verify_server: false", self.paths.frpc_toml.read_text())
        self.assertNotIn("trustedCaFile", self.paths.frpc_toml.read_text())

    def test_render_requires_ca_file_and_name_when_verified(self):
        settings = cfg.effective_settings({}, self.PINNED)
        with self.assertRaises(ValueError):
            cfg.render_frpc_toml(settings, "home", TOKEN)  # no ca_file

    def test_unpaired_render_removes_pinned_ca(self):
        self._write(self.paths.state, self.PINNED)
        cfg.render_from_disk(self.paths)
        self.paths.state.unlink()
        self.assertEqual(cfg.render_from_disk(self.paths)[0], cfg.RenderResult.NOT_PAIRED)
        self.assertFalse(self.paths.frps_ca.exists())
        self.assertFalse(self.paths.frpc_toml.exists())

    def test_files_frpc_reads_are_group_readable_for_the_frpc_group(self):
        gid = os.getgid()  # stand-in for the image's frpc group
        self._write(self.paths.state, self.PINNED)
        self._write(self.paths.frpc_toml, "old 2.1 file")
        os.chmod(self.paths.frpc_toml, 0o600)
        with mock.patch.object(cfg, "frpc_file_access", return_value=(0o640, gid)):
            cfg.render_from_disk(self.paths)
            for path in (self.paths.frps_ca, self.paths.frpc_toml):
                st = os.stat(path)
                self.assertEqual((stat.S_IMODE(st.st_mode), st.st_gid), (0o640, gid), path)
            # Unchanged content with wrong permissions (written 0600 by 2.1.x)
            # is fixed without a rewrite.
            os.chmod(self.paths.frpc_toml, 0o600)
            self.assertEqual(cfg.render_from_disk(self.paths)[0], cfg.RenderResult.UNCHANGED)
            self.assertEqual(stat.S_IMODE(os.stat(self.paths.frpc_toml).st_mode), 0o640)
        # The state file (device token) stays private.
        cfg.write_json(self.paths.state, self.PINNED)
        self.assertEqual(stat.S_IMODE(os.stat(self.paths.state).st_mode), 0o600)

    def test_data_dir_is_made_searchable_for_frpc(self):
        gid = os.getgid()
        self._write(self.paths.state, self.PINNED)
        os.chmod(self.paths.data_dir, 0o700)
        try:
            with mock.patch.object(cfg, "frpc_file_access", return_value=(0o640, gid)), \
                    self.assertLogs("frp-mgr.config", "WARNING"):
                cfg.render_from_disk(self.paths)
            self.assertEqual(stat.S_IMODE(os.stat(self.paths.data_dir).st_mode), 0o701)
            # Already searchable (other x, or group x for the frpc group): untouched.
            for mode in (0o755, 0o751, 0o710):
                os.chmod(self.paths.data_dir, mode)
                self.assertFalse(cfg.ensure_searchable(self.paths.data_dir, os.stat(self.paths.data_dir).st_gid))
                self.assertEqual(stat.S_IMODE(os.stat(self.paths.data_dir).st_mode), mode)
            self.assertFalse(cfg.ensure_searchable(self.paths.data_dir, None))  # no frpc group
        finally:
            os.chmod(self.paths.data_dir, 0o700)

    def test_frpc_file_access_without_the_group(self):
        with mock.patch("grp.getgrnam", side_effect=KeyError("frpc")):
            self.assertEqual(cfg.frpc_file_access(), (0o600, None))

    def test_toml_str_escapes(self):
        self.assertEqual(cfg.toml_str('a"b\\c\n'), '"a\\"b\\\\c\\u000a"')

    def test_render_from_disk_not_paired(self):
        result, settings = cfg.render_from_disk(self.paths)
        self.assertEqual(result, cfg.RenderResult.NOT_PAIRED)
        self.assertFalse(self.paths.frpc_toml.exists())
        self._write(self.paths.state, {"device_token": "dt"})  # approved, no tunnel
        self.assertEqual(cfg.render_from_disk(self.paths)[0], cfg.RenderResult.NOT_PAIRED)

    def test_render_from_disk_and_rerender_on_change(self):
        state = {"device_token": "dt", "subdomain": "home", "token": TOKEN,
                 "server_addr": "linumiq.net", "server_port": 7001, "domain_base": "dev.linumiq.net"}
        self._write(self.paths.state, state)
        self._write(self.paths.options, {"log_level": "info"})
        self.assertEqual(cfg.render_from_disk(self.paths)[0], cfg.RenderResult.RENDERED)
        mode = stat.S_IMODE(os.stat(self.paths.frpc_toml).st_mode)
        self.assertEqual(mode, cfg.frpc_file_access()[0])  # 0600, or 0640 root:frpc in the image
        self.assertEqual(cfg.render_from_disk(self.paths)[0], cfg.RenderResult.UNCHANGED)
        # Server value changes (e.g. after "Refresh") -> re-rendered.
        new_state, _ = cfg.apply_tunnel_response(
            state, {"subdomain": "home", "token": OTHER_TOKEN, "server_addr": "linumiq.net",
                    "server_port": 7000, "domain_base": "linumiq.net"})
        cfg.write_json(self.paths.state, new_state)
        self.assertEqual(cfg.render_from_disk(self.paths)[0], cfg.RenderResult.RENDERED)
        text = self.paths.frpc_toml.read_text()
        self.assertIn("serverPort = 7000", text)
        self.assertIn('customDomains = ["home.linumiq.net"]', text)
        self.assertIn(OTHER_TOKEN, text)
        # An explicit option override wins on the next render.
        self._write(self.paths.options, {"server_port": 7100})
        cfg.render_from_disk(self.paths)
        self.assertIn("serverPort = 7100", self.paths.frpc_toml.read_text())
        self.assertEqual(stat.S_IMODE(os.stat(self.paths.state).st_mode), 0o600)

    def test_legacy_v20_state_migration(self):
        legacy_toml = (
            "# Auto-generated by frp-mgr pairing panel. Do not edit by hand.\n"
            'serverAddr = "linumiq.net"\nserverPort = 7000\nloginFailExit = false\n\n'
            f'[metadatas]\ntoken = "{TOKEN}"\n\n[log]\nto = "console"\nlevel = "info"\n\n'
            '[[proxies]]\nname = "home"\ntype = "http"\ncustomDomains = ["home.linumiq.net"]\n'
            'localIP = "homeassistant"\nlocalPort = 8123\n'
        )
        self._write(self.paths.frpc_toml, legacy_toml)
        self._write(self.paths.state, {"device_token": "dt", "subdomain": "home",
                                       "server_addr": "linumiq.net", "server_port": 7000})
        result, settings = cfg.render_from_disk(self.paths)
        self.assertEqual(result, cfg.RenderResult.RENDERED)
        self.assertEqual(json.loads(self.paths.state.read_text())["token"], TOKEN)
        text = self.paths.frpc_toml.read_text()
        self.assertIn("transport.tls.enable = true", text)
        self.assertIn('customDomains = ["home.linumiq.net"]', text)

    def test_extract_legacy_token_only_from_metadatas(self):
        self.assertIsNone(cfg.extract_legacy_token(f'token = "{TOKEN}"\n'))
        self.assertIsNone(cfg.extract_legacy_token(f'[auth]\ntoken = "{TOKEN}"\n'))
        self.assertEqual(cfg.extract_legacy_token(f'[metadatas]\ntoken = "{TOKEN}"\n'), TOKEN)

    def test_corrupt_state_is_not_paired(self):
        self._write(self.paths.state, "{not json")
        with self.assertLogs("frp-mgr.config", "ERROR"):
            self.assertEqual(cfg.render_from_disk(self.paths)[0], cfg.RenderResult.NOT_PAIRED)

    def test_leftover_toml_is_deleted_without_a_valid_pairing(self):
        leftover = f'[metadatas]\ntoken = "{TOKEN}"\n'
        for state in (None, "{not json", {"device_token": "dt"},
                      {"device_token": "dt", "subdomain": "-bad-", "token": TOKEN}):
            self._write(self.paths.frpc_toml, leftover)
            if state is None:
                self.paths.state.unlink(missing_ok=True)
            else:
                self._write(self.paths.state, state)
            with self.subTest(state=state), self._quiet_logs():
                self.assertEqual(cfg.render_from_disk(self.paths)[0], cfg.RenderResult.NOT_PAIRED)
                self.assertFalse(self.paths.frpc_toml.exists())

    @staticmethod
    def _quiet_logs():
        """Corrupt JSON logs an ERROR - expected here, so mute the logger."""
        import contextlib
        import logging

        @contextlib.contextmanager
        def ctx():
            logger = logging.getLogger("frp-mgr.config")
            old, logger.disabled = logger.disabled, True
            try:
                yield
            finally:
                logger.disabled = old
        return ctx()


class StateLockTests(unittest.TestCase):
    def test_lock_is_exclusive_and_released(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = cfg.Paths(Path(tmp))
            with cfg.state_lock(paths):
                self.assertEqual(stat.S_IMODE(os.stat(paths.lock).st_mode) & 0o077, 0)
                with self.assertRaises(TimeoutError):
                    with cfg.state_lock(paths, timeout=0.3):
                        pass
            with cfg.state_lock(paths, timeout=0.3):
                pass  # released

    def test_cli_waits_for_the_lock_and_never_runs_a_leftover_config(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            paths = cfg.Paths(Path(tmp))
            paths.frpc_toml.write_text(f'[metadatas]\ntoken = "{TOKEN}"\n')
            env = dict(os.environ, FRP_DATA_DIR=tmp)
            with cfg.state_lock(paths):
                proc = subprocess.Popen(  # noqa: S603
                    [sys.executable, str(FRP_MGR / "config.py"), "render"],
                    env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                with self.assertRaises(subprocess.TimeoutExpired):
                    proc.wait(timeout=0.5)  # blocked on the lock
                self.assertTrue(paths.frpc_toml.exists())
            _, err = proc.communicate(timeout=30)
            self.assertEqual(proc.returncode, cfg.EXIT_NOT_PAIRED, err)
            self.assertFalse(paths.frpc_toml.exists())


class CliTests(unittest.TestCase):
    def test_cli_exit_codes(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, FRP_DATA_DIR=tmp)
            run = lambda: subprocess.run(  # noqa: E731
                [sys.executable, str(FRP_MGR / "config.py"), "render"],
                env=env, capture_output=True, text=True, check=False)
            self.assertEqual(run().returncode, cfg.EXIT_NOT_PAIRED)
            device_token = "DEVICE-TOKEN-SECRET-0123456789"
            Path(tmp, "frp-state.json").write_text(json.dumps(
                {"device_token": device_token, "subdomain": "home", "token": TOKEN,
                 "domain_base": "dev.linumiq.net"}))
            proc = run()
            self.assertEqual(proc.returncode, cfg.EXIT_OK, proc.stderr)
            # Secrets are never logged.
            self.assertNotIn(TOKEN, proc.stderr)
            self.assertNotIn(device_token, proc.stderr)
            self.assertIn("domain_base=dev.linumiq.net (from server)", proc.stderr)
            self.assertEqual(run().returncode, cfg.EXIT_OK)  # unchanged
            self.assertIn("frps server certificate is not verified", proc.stderr)  # pre-2.2 server
            Path(tmp, "frp-state.json").write_text(json.dumps(
                {"device_token": device_token, "subdomain": "home", "token": TOKEN,
                 "server_name": "frps.linumiq.net", "server_ca_pem": CA1}))
            proc = run()
            self.assertEqual(proc.returncode, cfg.EXIT_OK, proc.stderr)
            self.assertIn("tls=verified (CA from server, serverName=frps.linumiq.net)", proc.stderr)
            self.assertNotIn("not verified", proc.stderr)
            self.assertNotIn("BEGIN CERTIFICATE", proc.stderr)
            self.assertEqual(Path(tmp, "frps-ca.pem").read_text(), CA1)
            Path(tmp, "frp-state.json").write_text(json.dumps(
                {"device_token": device_token, "subdomain": "-bad-", "token": TOKEN}))
            self.assertEqual(run().returncode, cfg.EXIT_NOT_PAIRED)
            self.assertFalse(Path(tmp, "frps-ca.pem").exists())


class BackupExcludeTests(unittest.TestCase):
    """config.yaml's backup_exclude must cover every pairing secret, using
    Supervisor's matching (PurePath(<data dir>/<file>).match(pattern))."""

    def test_pairing_files_are_excluded_from_ha_backups(self):
        config_yaml = Path(__file__).resolve().parents[2] / "config.yaml"  # frp-tunnel/config.yaml
        if not config_yaml.exists():  # e.g. only tests/ mounted into the image
            self.skipTest("config.yaml not available")
        patterns, inside = [], False
        for line in config_yaml.read_text().splitlines():
            if line.startswith("backup_exclude:"):
                inside = True
                continue
            if inside:
                if not line.startswith("  - "):
                    break
                patterns.append(line[4:].strip().strip('"'))
        self.assertTrue(patterns)
        supervisor_dir = PurePosixPath("/data/addons/data/local_frp_tunnel")
        paths = cfg.Paths(Path("/data"))
        secret_files = [paths.state, paths.pairing, paths.frpc_toml, paths.frps_ca, paths.lock,
                        Path(".frp-state.json.k2j3h4.tmp"), Path(".frpc.toml.abc123.tmp")]
        for file in secret_files:
            full = supervisor_dir / file.name
            self.assertTrue(any(full.match(p) for p in patterns), f"{file.name} not excluded by {patterns}")
        self.assertFalse(any((supervisor_dir / "options.json").match(p) for p in patterns))


if __name__ == "__main__":
    unittest.main()
