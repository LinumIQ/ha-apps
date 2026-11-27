"""
Caddy mTLS Proxy - the local-network HTTPS port (container port 4443, since
2.2.0): HTTPS for the same domain, without client certificates, for private
source addresses only.

The site is rendered by init-caddy; this module provides what it needs from
the container's network:

  * PRIVATE_RANGES - the source addresses the site answers;
  * ``default_gateways()`` - the container's default gateways. Docker's
    userland proxy (docker-proxy) forwards connections it cannot route
    itself - IPv6 to a container without IPv6, connections from the host
    itself - from the host's address on the container's bridge, i.e. the
    gateway (Docker 29: daemon/libnetwork/drivers/bridge/
    port_mapping_linux.go, cmd/docker-proxy/tcp_proxy_linux.go). That
    address hides the real source, which may be a public IPv6 client, so
    the site refuses it although it is private.

``python3 lan.py gateways`` prints the gateways, one per line. Standard
library only.
"""
from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

#: Private, loopback and link-local ranges (RFC 1918, 127/8, 169.254/16,
#: unique local fc00::/7, link-local fe80::/10, ::1).
PRIVATE_RANGES = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
    "::1/128",
)


def default_gateways(route: Path = Path("/proc/net/route"),
                     ipv6_route: Path = Path("/proc/net/ipv6_route")) -> list[str]:
    """The next hops of the default routes (IPv4 first), without duplicates."""
    found: list[str] = []
    try:
        lines = route.read_text().splitlines()[1:]
    except OSError:
        lines = []
    for line in lines:
        fields = line.split()
        # Iface Destination Gateway Flags RefCnt Use Metric Mask ...
        if len(fields) < 8 or fields[1] != "00000000" or fields[7] != "00000000":
            continue
        try:
            gateway = ipaddress.IPv4Address(bytes.fromhex(fields[2])[::-1])
        except ValueError:
            continue
        if int(gateway):
            found.append(str(gateway))
    try:
        lines = ipv6_route.read_text().splitlines()
    except OSError:
        lines = []
    for line in lines:
        fields = line.split()
        # dst dst_len src src_len next_hop metric refcnt use flags iface
        if len(fields) < 10 or fields[0] != "0" * 32 or fields[1] != "00":
            continue
        try:
            gateway6 = ipaddress.IPv6Address(bytes.fromhex(fields[4]))
        except ValueError:
            continue
        if int(gateway6):
            found.append(str(gateway6))
    return list(dict.fromkeys(found))


def is_private(address: str) -> bool:
    """Whether the LAN site answers this source address (before the gateway
    exclusion)."""
    try:
        addr = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return any(addr in ipaddress.ip_network(net) for net in PRIVATE_RANGES)


if __name__ == "__main__":
    if sys.argv[1:] == ["gateways"]:
        print("\n".join(default_gateways()))
        sys.exit(0)
    if sys.argv[1:] == ["ranges"]:
        print(" ".join(PRIVATE_RANGES))
        sys.exit(0)
    print("usage: lan.py gateways|ranges", file=sys.stderr)
    sys.exit(2)
