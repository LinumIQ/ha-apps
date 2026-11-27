"""Unit tests for cert-mgr/lan.py (the local-network HTTPS port: private
ranges, the container's default gateways) and the panel's "Local network"
card. Standard library only (the card test needs Jinja2: inside the image).
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

CERT_MGR = Path(
    os.environ.get("CERT_MGR_DIR")
    or Path(__file__).resolve().parents[2] / "rootfs" / "usr" / "lib" / "cert-mgr"
)
sys.path.insert(0, str(CERT_MGR))

import lan  # noqa: E402
import public_cert  # noqa: E402

try:
    import jinja2
except ImportError:  # pragma: no cover - CI's plain Python job
    jinja2 = None

# /proc/net/route of a Home Assistant OS add-on (hassio network, gateway
# 172.30.32.1) and /proc/net/ipv6_route with Supervisor's IPv6 network.
ROUTE = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t01201EAC\t0003\t0\t0\t0\t00000000\t0\t0\t0
eth0\t00201EAC\t00000000\t0001\t0\t0\t0\t00FEFFFF\t0\t0\t0
"""
IPV6_ROUTE = (
    "fd0cac1e210000000000000000000000 30 00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n"
    "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
    "fd0cac1e210000000000000000000001 00000400 00000002 00000000 00000003     eth0\n"
    "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n"
)


class GatewayTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def files(self, route: str, ipv6: str) -> tuple[Path, Path]:
        (self.dir / "route").write_text(route)
        (self.dir / "ipv6_route").write_text(ipv6)
        return self.dir / "route", self.dir / "ipv6_route"

    def test_home_assistant_os(self) -> None:
        self.assertEqual(lan.default_gateways(*self.files(ROUTE, IPV6_ROUTE)),
                         ["172.30.32.1", "fd0c:ac1e:2100::1"])

    def test_ipv4_only(self) -> None:
        self.assertEqual(lan.default_gateways(*self.files(ROUTE, "")), ["172.30.32.1"])

    def test_no_default_route(self) -> None:
        # --network none / an --internal Docker network: no default route.
        route = ROUTE.splitlines()[0] + "\neth0\t00281AAC\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
        self.assertEqual(lan.default_gateways(*self.files(route, IPV6_ROUTE.splitlines()[-1] + "\n")), [])

    def test_missing_files(self) -> None:
        self.assertEqual(lan.default_gateways(self.dir / "nope", self.dir / "nope6"), [])

    def test_garbage(self) -> None:
        self.assertEqual(lan.default_gateways(*self.files("x\nshort\n", "zz\n")), [])


class PrivateTest(unittest.TestCase):
    def test_private(self) -> None:
        for address in ("10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.1.181", "127.0.0.1",
                        "169.254.10.10", "fd0c:ac1e:2100::5", "fc00::1", "fe80::1%eth0", "::1",
                        "::ffff:192.168.1.20"):
            with self.subTest(address=address):
                self.assertTrue(lan.is_private(address))

    def test_public(self) -> None:
        for address in ("203.0.113.7", "198.51.100.7", "172.32.0.1", "8.8.8.8", "2001:db8::7",
                        "2a0a:4cc0:c1:cf22::1", "::ffff:203.0.113.7", "", "nonsense"):
            with self.subTest(address=address):
                self.assertFalse(lan.is_private(address))

    def test_ranges_as_the_brief_lists_them(self) -> None:
        self.assertEqual(set(lan.PRIVATE_RANGES), {
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
            "fc00::/7", "fe80::/10", "::1/128",
        })


class RuntimeTest(unittest.TestCase):
    def test_lan_fields(self) -> None:
        rt = public_cert.Runtime.from_dict({"domain": "home.example.com", "started_at": 1,
                                            "lan_host_port": 9443, "lan_state": "on",
                                            "lan_refused": ["172.30.32.1"]})
        self.assertEqual((rt.lan_host_port, rt.lan_state, rt.lan_refused), (9443, "on", ("172.30.32.1",)))
        rt = public_cert.Runtime.from_dict({"domain": "home.example.com", "started_at": 1})
        self.assertEqual((rt.lan_host_port, rt.lan_state, rt.lan_refused), (None, "off", ()))


@unittest.skipIf(jinja2 is None, "Jinja2 not installed (run inside the add-on image)")
class LanCardTest(unittest.TestCase):
    TEMPLATES = CERT_MGR / "templates"

    def render(self, **runtime) -> str:
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(self.TEMPLATES)), autoescape=True)
        rt = public_cert.Runtime.from_dict({"domain": "home.example.com", "started_at": 1,
                                            "host_ports_known": True, **runtime})
        return env.get_template("_lan.html").render(lan_rt=rt)

    def test_off(self) -> None:
        html = self.render(lan_state="off")
        self.assertIn('data-state="off"', html)
        self.assertIn("Show disabled ports", html)
        self.assertIn("4443/tcp", html)
        self.assertNotIn("https://home.example.com:", html)

    def test_on(self) -> None:
        html = self.render(lan_state="on", lan_host_port=9443, lan_refused=["172.30.32.1"])
        self.assertIn('data-state="on"', html)
        self.assertIn("https://home.example.com:9443/", html)
        self.assertIn("Never forward", html)
        self.assertIn("172.30.32.1", html)
        self.assertIn("IPv4", html)

    def test_port_443_is_the_plain_url(self) -> None:
        html = self.render(lan_state="on", lan_host_port=443, https_host_port=8444)
        self.assertIn("https://home.example.com/", html)
        self.assertNotIn("https://home.example.com:443/", html)
        # B-10: the router must forward 443 to the client-certificate port.
        self.assertIn("Check your router's port forwarding now", html)
        self.assertIn("<strong>8444</strong>", html)
        self.assertNotIn("lan__warn", self.render(lan_state="on", lan_host_port=9443))

    def test_unknown(self) -> None:
        html = self.render(lan_state="unknown", host_ports_known=False)
        self.assertIn('data-state="unknown"', html)
        self.assertIn("could not be read", html)


if __name__ == "__main__":
    unittest.main()
