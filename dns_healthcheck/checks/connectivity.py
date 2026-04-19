"""Connectivity-TP: UDP/TCP reachability and topological diversity."""

from __future__ import annotations

import asyncio

from dns_healthcheck.checks._helpers import prefix_diversity
from dns_healthcheck.context import CheckContext
from dns_healthcheck.registry import register
from dns_healthcheck.result import Finding, Severity

CATEGORY = "connectivity"
SPEC_BASE = "https://doc.zonemaster.net/latest/specifications/tests/Connectivity-TP"


@register(
    id="CONNECTIVITY01",
    category=CATEGORY,
    name="Each name server answers SOA over UDP",
    spec_url=f"{SPEC_BASE}/connectivity01.html",
    default_severity=Severity.ERROR,
)
async def connectivity01(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []

    async def probe(ns_name: str, addr: str) -> Finding | None:
        r = await ctx.resolver.query_at(ctx.domain, "SOA", addr, use_tcp=False)
        if r.error or r.rcode != 0:
            return Finding(
                check_id="CONNECTIVITY01",
                severity=Severity.ERROR,
                message=f"UDP query to {ns_name}/{addr} failed: {r.error or f'rcode={r.rcode}'}",
                args={"ns": ns_name, "address": addr, "rcode": r.rcode, "error": r.error},
                ns=ns_name,
            )
        return None

    tasks = []
    for ns in ctx.zone.parent_ns + ctx.zone.child_ns:
        for addr in ns.all_addresses():
            tasks.append(probe(ns.name, addr))
    for f in await asyncio.gather(*tasks):
        if f:
            findings.append(f)
    return findings


@register(
    id="CONNECTIVITY02",
    category=CATEGORY,
    name="Each name server answers SOA over TCP",
    description="Authoritative servers must accept TCP queries (RFC 7766).",
    spec_url=f"{SPEC_BASE}/connectivity02.html",
    default_severity=Severity.ERROR,
)
async def connectivity02(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []

    async def probe(ns_name: str, addr: str) -> Finding | None:
        r = await ctx.resolver.query_at(ctx.domain, "SOA", addr, use_tcp=True)
        if r.error or r.rcode != 0:
            return Finding(
                check_id="CONNECTIVITY02",
                severity=Severity.ERROR,
                message=f"TCP query to {ns_name}/{addr} failed: {r.error or f'rcode={r.rcode}'}",
                args={"ns": ns_name, "address": addr, "rcode": r.rcode, "error": r.error},
                ns=ns_name,
            )
        return None

    tasks = []
    for ns in ctx.zone.parent_ns + ctx.zone.child_ns:
        for addr in ns.all_addresses():
            tasks.append(probe(ns.name, addr))
    for f in await asyncio.gather(*tasks):
        if f:
            findings.append(f)
    return findings


@register(
    id="CONNECTIVITY03",
    category=CATEGORY,
    name="Authoritative servers in distinct AS-paths",
    description=(
        "Best practice: name server addresses should not all live in one Autonomous System "
        "(no cheap whois lookup is performed; we approximate via /16 (v4) and /32 (v6) prefix diversity)."
    ),
    spec_url=f"{SPEC_BASE}/connectivity03.html",
    default_severity=Severity.NOTICE,
)
async def connectivity03(ctx: CheckContext) -> list[Finding]:
    addrs: list[str] = []
    for ns in ctx.zone.parent_ns + ctx.zone.child_ns:
        addrs.extend(ns.all_addresses())
    if not addrs:
        return []
    diversity = prefix_diversity(addrs, v4_prefix=16, v6_prefix=32)
    if diversity < 2 and len(addrs) > 1:
        return [
            Finding(
                check_id="CONNECTIVITY03",
                severity=Severity.NOTICE,
                message=f"All {len(addrs)} authoritative addresses share one /16 (v4) or /32 (v6) — likely the same AS",
                args={"addresses": addrs, "diverse_blocks": diversity},
            )
        ]
    return []


@register(
    id="CONNECTIVITY04",
    category=CATEGORY,
    name="Authoritative server addresses span multiple IP prefixes",
    spec_url=f"{SPEC_BASE}/connectivity04.html",
    default_severity=Severity.NOTICE,
)
async def connectivity04(ctx: CheckContext) -> list[Finding]:
    addrs: list[str] = []
    for ns in ctx.zone.parent_ns + ctx.zone.child_ns:
        addrs.extend(ns.all_addresses())
    if len(addrs) < 2:
        return []
    diversity = prefix_diversity(addrs, v4_prefix=24, v6_prefix=48)
    if diversity < 2:
        return [
            Finding(
                check_id="CONNECTIVITY04",
                severity=Severity.NOTICE,
                message="Authoritative addresses share a single /24 (v4) or /48 (v6) prefix",
                args={"addresses": addrs, "diverse_prefixes": diversity},
            )
        ]
    return []
