"""Unit tests for cert-mgr/customconf.py (Caddyfile snippets for experts,
2.3.0): which files count, the copies, the import rule, Caddy's messages,
the state and the card - and the integrity check against configurations
that Caddy 2.11.9 really built (fixtures/customconf/*.json: `caddy adapt` of
the add-on's own rendering with and without custom files, collected by
`SMOKE_FIXTURES_DIR=<dir> SMOKE_ONLY=custom tests/smoke.sh <image>`; the
cases are smoke.sh's custom_files), also changed on purpose here to prove
each rule.

Standard library only. Runs against the repository's module, or the
installed one with CERT_MGR_DIR - see test_monitor.py.
"""
from __future__ import annotations

import io
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

CERT_MGR = Path(
    os.environ.get("CERT_MGR_DIR")
    or Path(__file__).resolve().parents[2] / "rootfs" / "usr" / "lib" / "cert-mgr"
)
sys.path.insert(0, str(CERT_MGR))

import customconf  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "customconf"


class CollectTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.src = self.tmp / "config" / "caddy"
        self.src.mkdir(parents=True)
        self.dst = self.tmp / "etc" / "custom"

    def put(self, name: str, data: bytes | str) -> Path:
        path = self.src / name
        path.write_bytes(data.encode() if isinstance(data, str) else data)
        return path

    def test_nothing(self) -> None:
        result = customconf.collect(self.src, self.dst)
        self.assertEqual(result, {"files": [], "ignored": [], "error": "", "error_file": None})
        self.assertEqual(list(self.dst.iterdir()), [])
        self.assertEqual(stat.S_IMODE(self.dst.stat().st_mode), 0o700)

    def test_counting_files_are_copied_byte_for_byte(self) -> None:
        site = 'header X-Site "yes"\r\nrespond /hello "hello" 200\r\n'  # CRLF
        self.put("site.caddy", site)
        self.put("sites.caddy", b"\xef\xbb\xbfother.example.com {\n\timport mtls\n}\n")  # a BOM
        self.put("global.caddy", "servers {\n\tprotocols h1 h2\n}\n")
        self.put("notes.txt", "ignored silently")
        self.put("README.txt", "ours")
        result = customconf.collect(self.src, self.dst)
        self.assertEqual(result["error"], "")
        self.assertEqual([f["name"] for f in result["files"]], ["global.caddy", "site.caddy", "sites.caddy"])
        self.assertEqual(result["files"][1]["bytes"], len(site.encode()))
        self.assertEqual(result["ignored"], [])
        self.assertEqual((self.dst / "site.caddy").read_bytes(), site.encode())
        self.assertEqual((self.dst / "sites.caddy").read_bytes()[:3], b"\xef\xbb\xbf")
        for path in self.dst.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(sorted(p.name for p in self.dst.iterdir()), ["global.caddy", "site.caddy", "sites.caddy"])

    def test_ignored_entries(self) -> None:
        target = self.put("elsewhere.txt", "respond x\n")
        (self.src / "site.caddy").symlink_to(target)
        self.put("lan.caddy", "x" * (customconf.MAX_BYTES + 1))
        self.put("global.caddy", "  \n\t\n")
        (self.src / "sites.caddy").mkdir()
        result = customconf.collect(self.src, self.dst)
        reasons = {i["name"]: i["reason"] for i in result["ignored"]}
        self.assertIn("symbolic link", reasons["site.caddy"])
        self.assertIn("larger than 256 KiB", reasons["lan.caddy"])
        self.assertEqual(reasons["global.caddy"], "empty")
        self.assertEqual(reasons["sites.caddy"], "not a regular file")
        self.assertEqual(result["files"], [])
        self.assertEqual(list(self.dst.iterdir()), [])

    def test_a_fifo_is_never_opened(self) -> None:
        os.mkfifo(self.src / "site.caddy")  # opening it would block the start
        self.put("lan.caddy", "respond /x 200\n")
        result = customconf.collect(self.src, self.dst)
        self.assertEqual(result["ignored"], [{"name": "site.caddy", "reason": "not a regular file"}])
        self.assertEqual([f["name"] for f in result["files"]], ["lan.caddy"])

    def test_exactly_256_kib_counts(self) -> None:
        self.put("site.caddy", "#" * (customconf.MAX_BYTES - 1) + "\n")
        self.assertEqual(len(customconf.collect(self.src, self.dst)["files"]), 1)

    def test_imports_of_files_reject_everything(self) -> None:
        self.put("site.caddy", "respond /ok 200\n")
        for line in ("import /etc/caddy/Caddyfile", "  import ../certs/x", 'import "other.caddy"',
                     "`import` /x", '"import" /x', "@m {\n\timport /tmp/m\n}", "import *.caddy",
                     "import", "respond x { import /y }"):
            with self.subTest(line=line):
                self.put("sites.caddy", f"other.example.com {{\n{line}\n}}\n")
                result = customconf.collect(self.src, self.dst)
                self.assertEqual(result["error_file"], "sites.caddy")
                self.assertIn("caddy/sites.caddy:", result["error"])
                self.assertIn("may only import a snippet by its name", result["error"])
                self.assertEqual(list(self.dst.iterdir()), [], "nothing is copied")

    def test_snippet_imports_and_comments_are_fine(self) -> None:
        self.put("sites.caddy", "other.example.com {\n\timport mtls\n\timport my_snippet arg1\n"
                                "\t# import /etc/passwd\n\trespond \"x\" # import /y\n}\n")
        result = customconf.collect(self.src, self.dst)
        self.assertEqual(result["error"], "")
        self.assertEqual([f["name"] for f in result["files"]], ["sites.caddy"])

    def test_not_utf8(self) -> None:
        self.put("site.caddy", b"respond /x \xff\xfe 200\n")
        result = customconf.collect(self.src, self.dst)
        self.assertEqual(result["error"], "caddy/site.caddy is not UTF-8 text")

    def test_previous_copies_are_removed(self) -> None:
        self.put("site.caddy", "respond /x 200\n")
        customconf.collect(self.src, self.dst)
        (self.src / "site.caddy").unlink()
        customconf.collect(self.src, self.dst)
        self.assertEqual(list(self.dst.iterdir()), [])

    def test_cli_collect_readme_and_state(self) -> None:
        self.put("site.caddy", "respond /x 200\n")
        state_file = self.tmp / "run" / "custom.json"
        out = io.StringIO()
        with redirect_stdout(out):
            rc = customconf._main(["collect", "--config-dir", str(self.src), "--copy-dir", str(self.dst),
                                   "--state", str(state_file), "--slug", "local_caddy_mtls"])
        self.assertEqual(rc, 0)
        state = json.loads(state_file.read_text())
        self.assertEqual((state["state"], state["folder"]), ("loaded", "app_configs/local_caddy_mtls/caddy"))
        readme = (self.src / "README.txt").read_text()
        for needle in ("global.caddy", "site.caddy", "lan.caddy", "sites.caddy", "import mtls",
                       "applied when the add-on STARTS", "NONE of", customconf.DOCS_URL):
            self.assertIn(needle, readme)
        # rejected: the copies go, the state says why.
        with redirect_stdout(io.StringIO()):
            customconf._main(["reject", "--copy-dir", str(self.dst), "--state", str(state_file),
                              "--message", "rule 2 (sites.caddy): x", "--file", "sites.caddy"])
        state = json.loads(state_file.read_text())
        self.assertEqual((state["state"], state["error"], state["error_file"]),
                         ("rejected", "rule 2 (sites.caddy): x", "sites.caddy"))
        self.assertFalse(self.dst.exists())

    def test_cli_without_a_config_folder(self) -> None:
        """Outside Supervisor (no /config): nothing is written there."""
        state_file = self.tmp / "custom.json"
        missing = self.tmp / "nope" / "caddy"
        with redirect_stdout(io.StringIO()):
            customconf._main(["collect", "--config-dir", str(missing), "--copy-dir", str(self.dst),
                              "--state", str(state_file)])
        self.assertFalse(missing.parent.exists())
        self.assertEqual(json.loads(state_file.read_text())["state"], "none")


class MessageTest(unittest.TestCase):
    def test_named_file(self) -> None:
        out = ('{"level":"info","msg":"using config from file"}\n'
               '{"level":"error","ts":1.5,"msg":"adapting config using caddyfile: File to import not found: foo, '
               "at /etc/caddy/custom/site.caddy:1 import chain ['/etc/caddy/Caddyfile:96 (import)']\"}\n")
        text, file = customconf.describe_error(out)
        self.assertEqual(file, "site.caddy")
        self.assertEqual(text, "adapting config using caddyfile: File to import not found: foo, at caddy/site.caddy:1")
        self.assertNotIn("/etc/caddy", text)

    def test_only_the_generated_file(self) -> None:
        out = ('{"level":"error","msg":"adapting config using caddyfile: parsing caddyfile tokens for '
               "'route': tls directive returned something other than an HTTP route or subroute: "
               '&caddytls.InternalIssuer{} (only handler directives can be used in routes), at /etc/caddy/Caddyfile:96"}\n')
        text, file = customconf.describe_error(out)
        self.assertIsNone(file)
        self.assertIn("one of your files", text)
        self.assertIn("unbalanced braces", text)
        self.assertNotIn("Caddyfile:96", text)
        self.assertIn("tls directive returned something other", text)

    def test_cli_error_line_and_cap(self) -> None:
        text, _ = customconf.describe_error("noise\nError: " + "x" * 5000 + "\n")
        self.assertLessEqual(len(text), customconf.ERROR_MAX)
        self.assertTrue(text.endswith("..."))


class CardTest(unittest.TestCase):
    def test_context(self) -> None:
        self.assertFalse(customconf.card_context(customconf.read_state(Path("/nonexistent")))["show"])
        ctx = customconf.card_context({"state": "none", "files": [], "folder": "app_configs/x/caddy",
                                       "ignored": [{"name": "site.caddy", "reason": "a symbolic link"}]})
        self.assertTrue(ctx["show"])
        ctx = customconf.card_context({"state": "rejected", "files": [{"name": "site.caddy", "bytes": 3}],
                                       "error": "e" * 9000, "error_file": "../x", "folder": None})
        self.assertEqual((ctx["state"], ctx["error_file"], len(ctx["error"])), ("rejected", None, customconf.ERROR_MAX))


class HostTest(unittest.TestCase):
    def test_overlap(self) -> None:
        for pattern, domain, expected in (
            ("home.example.com", "home.example.com", True),
            ("HOME.example.com.", "home.example.com", True),
            ("*.example.com", "home.example.com", True),
            ("other.example.com", "home.example.com", False),
            ("*.home.example.com", "home.example.com", False),
            ("printer.example.com", "*.example.com", True),
            ("{env.HOST}", "home.example.com", True),
            ("*", "home.example.com", False),
        ):
            with self.subTest(pattern=pattern, domain=domain):
                self.assertEqual(customconf._labels_overlap(pattern, domain), expected)

    def test_route_may_match(self) -> None:
        d = "home.example.com"
        self.assertTrue(customconf.route_may_match({"handle": []}, d))
        self.assertTrue(customconf.route_may_match({"match": [{"path": ["/x"]}]}, d))
        self.assertTrue(customconf.route_may_match({"match": [{"host": ["other.example.com"]}, {"path": ["/x"]}]}, d))
        self.assertFalse(customconf.route_may_match({"match": [{"host": ["other.example.com"], "path": ["/x"]}]}, d))
        self.assertTrue(customconf.route_may_match({"match": [{"host": [d], "path": ["/bypass/*"]}]}, d))


@unittest.skipUnless((FIXTURES / "meta.json").is_file(), "fixtures not generated")
class IntegrityTest(unittest.TestCase):
    """The integrity check on configurations Caddy 2.11.9 built from the
    add-on's own rendering (see make.sh)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.meta = json.loads((FIXTURES / "meta.json").read_text())

    def load(self, name: str) -> dict:
        return json.loads((FIXTURES / f"{name}.json").read_text())

    def run_check(self, case: str) -> list[str]:
        info = self.meta[case]
        return customconf.check(self.load(case), self.load(f"{case}.reference"), domain=self.meta["domain"],
                                upstream=info["upstream"], files=info["files"],
                                header_auth=info["header_auth"])

    def test_cases(self) -> None:
        for case, info in sorted(self.meta.items()):
            if not isinstance(info, dict):
                continue
            with self.subTest(case=case):
                if info["expect"] == "ok":
                    rules = self.run_check(case)
                    self.assertEqual(len(rules), 4, rules)
                else:
                    with self.assertRaises(customconf.Violation) as ctx:
                        self.run_check(case)
                    self.assertEqual(ctx.exception.rule, info["expect"], ctx.exception.message)

    def mutated(self, case: str, change) -> list[str]:
        """The check of <case> after ``change(adapted)`` (a deliberate edit of
        what Caddy built, for a rule the smoke test cannot reach easily)."""
        info = self.meta[case]
        adapted = self.load(case)
        change(adapted)
        return customconf.check(adapted, self.load(f"{case}.reference"), domain=self.meta["domain"],
                                upstream=info["upstream"], files=info["files"], header_auth=info["header_auth"])

    def server(self, config: dict, listen: str) -> dict:
        return next(s for s in config["apps"]["http"]["servers"].values() if s["listen"] == [listen])

    def assert_rule(self, rule: int, case: str, change) -> None:
        with self.assertRaises(customconf.Violation) as ctx:
            self.mutated(case, change)
        self.assertEqual(ctx.exception.rule, rule, ctx.exception.message)

    def test_rule_4_server_fields(self) -> None:
        self.assert_rule(4, "ok", lambda c: self.server(c, ":443").update(
            listener_wrappers=[{"wrapper": "proxy_protocol"}, {"wrapper": "tls"}]))
        self.assert_rule(4, "ok", lambda c: self.server(c, ":4443").update(trusted_proxies={"source": "static",
                                                                                          "ranges": ["0.0.0.0/0"]}))
        self.assert_rule(4, "ok", lambda c: c.update(admin={"disabled": True}))
        self.assert_rule(4, "ok", lambda c: c["apps"]["http"].update(grace_period=1000000000))
        # A performance option is free.
        self.assertEqual(len(self.mutated("ok", lambda c: self.server(c, ":443").update(idle_timeout=60000000000))), 4)

    def test_rule_4_logs(self) -> None:
        def unfiltered(c):
            c["logging"]["logs"]["mine"] = {"writer": {"output": "stdout"}, "encoder": {"format": "console"}}
        self.assert_rule(4, "ok", unfiltered)  # while a key is set
        self.assertEqual(len(self.mutated("ok-strict", unfiltered)), 4)  # without a key: allowed

        def filtered(c):
            c["logging"]["logs"]["mine"] = {"writer": {"output": "stdout"}, "encoder": {
                "format": "filter", "wrap": {"format": "console"},
                "fields": {"request>headers": {"filter": "delete"}}}}
        self.assertEqual(len(self.mutated("ok", filtered)), 4)

        def default_changed(c):
            c["logging"]["logs"]["default"]["level"] = "ERROR"
        self.assert_rule(4, "ok", default_changed)

    def test_rule_2_more_ways_to_answer_the_domain(self) -> None:
        catch_all = {"handle": [{"handler": "static_response", "body": "x"}]}
        self.assert_rule(2, "ok", lambda c: self.server(c, ":443")["routes"].append(catch_all))
        self.assert_rule(2, "ok", lambda c: self.server(c, ":443").setdefault("errors", {}).update(routes=[catch_all]))
        self.assert_rule(2, "ok", lambda c: c["apps"]["http"]["servers"].update(
            extra={"listen": [":8444"], "routes": [{"match": [{"host": ["caddy-mtls-smoke.localhost"]}],
                                                    "handle": [{"handler": "reverse_proxy"}]}]}))
        # Another host name on the same listener is fine.
        self.assertEqual(len(self.mutated("ok", lambda c: self.server(c, ":443")["routes"].append(
            {"match": [{"host": ["printer.example.com"]}], "handle": [{"handler": "static_response"}]}))), 4)

    def test_rule_3_tls(self) -> None:
        self.assert_rule(3, "ok", lambda c: self.server(c, ":443").update(automatic_https={
            "skip_certificates": ["caddy-mtls-smoke.localhost"]}))
        self.assert_rule(3, "ok", lambda c: self.server(c, ":443")["tls_connection_policies"].insert(0, {}))
        self.assert_rule(3, "ok-strict", lambda c: self.server(c, ":443").update(strict_sni_host=False))

    def test_rule_1_groups_are_compared_up_to_renaming(self) -> None:
        def rename(c, old, new):
            text = json.dumps(c).replace(f'"{old}"', f'"{new}"')
            c.clear()
            c.update(json.loads(text))
        groups = sorted({g for g in _values(self.load("ok"), "group")})
        self.assertTrue(groups)
        self.assertEqual(len(self.mutated("ok", lambda c: rename(c, groups[0], "group99"))), 4)

        def split(c):
            routes = [r for r in _objects(self.server(c, ":80")) if r.get("group")]
            routes[-1]["group"] = "group98"  # two routes that excluded each other no longer do
        self.assert_rule(1, "ok", split)

    def test_rule_1_the_gate(self) -> None:
        def weaker_gate(c):
            for obj in _objects(self.server(c, ":443")):
                if isinstance(obj.get("handle"), list) and obj["handle"] and \
                        obj["handle"][0].get("handler") == "static_response" and obj["handle"][0].get("status_code") == 403:
                    obj["match"] = [{"path": ["/nothing"]}]
                    return
            raise AssertionError("no gate found")
        self.assert_rule(1, "ok", weaker_gate)

    def test_a_reference_passes_against_itself(self) -> None:
        for case in ("ok", "ok-strict"):
            with self.subTest(case=case):
                info = self.meta[case]
                config = self.load(f"{case}.reference")
                # (Both name the reference's own file: no renaming.)
                self.assertEqual(len(customconf.check(config, config, domain=self.meta["domain"],
                                                      upstream=info["upstream"], files=[],
                                                      header_auth=info["header_auth"],
                                                      config_path="/etc/caddy/Caddyfile.reference")), 4)


def _objects(value):
    """Every dict inside ``value`` (depth first)."""
    if isinstance(value, dict):
        yield value
        for v in value.values():
            yield from _objects(v)
    elif isinstance(value, list):
        for v in value:
            yield from _objects(v)


def _values(value, key):
    for obj in _objects(value):
        if key in obj:
            yield obj[key]


if __name__ == "__main__":
    unittest.main()
