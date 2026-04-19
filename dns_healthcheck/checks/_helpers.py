"""Shared helpers for check implementations."""

from __future__ import annotations

import ipaddress
import re

DOMAIN_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def valid_label(label: str) -> bool:
    return bool(DOMAIN_LABEL_RE.match(label))


def valid_hostname(hostname: str) -> bool:
    h = hostname.rstrip(".").lower()
    if not h or len(h) > 253:
        return False
    return all(valid_label(p) for p in h.split("."))


def is_global_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_global


def autonomous_system_diversity(asns: list[int | None]) -> int:
    return len({a for a in asns if a is not None})


def prefix_diversity(addresses: list[str], v4_prefix: int = 24, v6_prefix: int = 48) -> int:
    nets: set[str] = set()
    for a in addresses:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        if isinstance(ip, ipaddress.IPv4Address):
            nets.add(str(ipaddress.ip_network(f"{a}/{v4_prefix}", strict=False)))
        else:
            nets.add(str(ipaddress.ip_network(f"{a}/{v6_prefix}", strict=False)))
    return len(nets)
