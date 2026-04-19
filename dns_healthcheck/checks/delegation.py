"""Delegation-TP: parent/child delegation correctness."""

from __future__ import annotations

import dns.rdatatype

from dns_healthcheck.context import CheckContext
from dns_healthcheck.registry import register
from dns_healthcheck.result import Finding, Severity

CATEGORY = "delegation"
SPEC_BASE = "https://doc.zonemaster.net/latest/specifications/tests/Delegation-TP"


@register(
    id="DELEGATION01",
    category=CATEGORY,
    name="At least two name servers in the delegation",
    description="RFC 1035 §4.1 strongly recommends >= 2 name servers per zone.",
    spec_url=f"{SPEC_BASE}/delegation01.html",
    default_severity=Severity.WARNING,
)
async def delegation01(ctx: CheckContext) -> list[Finding]:
    n = len(ctx.zone.parent_ns)
    if n < 2:
        return [
            Finding(
                check_id="DELEGATION01",
                severity=Severity.WARNING,
                message=f"Only {n} name server(s) delegated; RFC 1035 recommends >= 2",
                args={"count": n},
            )
        ]
    return []


@register(
    id="DELEGATION02",
    category=CATEGORY,
    name="Distinct IP addresses across delegated name servers",
    spec_url=f"{SPEC_BASE}/delegation02.html",
    default_severity=Severity.WARNING,
)
async def delegation02(ctx: CheckContext) -> list[Finding]:
    addrs: list[str] = []
    for ns in ctx.zone.parent_ns:
        addrs.extend(ns.all_addresses())
    if len(addrs) > 1 and len(set(addrs)) < 2:
        return [
            Finding(
                check_id="DELEGATION02",
                severity=Severity.WARNING,
                message="Delegated name servers all resolve to the same IP address",
                args={"addresses": addrs},
            )
        ]
    return []


@register(
    id="DELEGATION03",
    category=CATEGORY,
    name="Referral packet from parent fits in 512 bytes (UDP)",
    description="A delegation that exceeds 512 bytes risks fragmentation on legacy resolvers.",
    spec_url=f"{SPEC_BASE}/delegation03.html",
    default_severity=Severity.NOTICE,
)
async def delegation03(ctx: CheckContext) -> list[Finding]:
    parent = ctx.zone.parent
    if not parent:
        return []
    servers = ctx.resolver.root_servers()[:3]
    for srv in servers:
        r = await ctx.resolver.query_at(ctx.domain, "NS", srv)
        if r.error or r.response is None:
            continue
        wire = r.response.to_wire()
        if len(wire) > 512:
            return [
                Finding(
                    check_id="DELEGATION03",
                    severity=Severity.NOTICE,
                    message=f"Referral packet is {len(wire)} bytes (>512 UDP limit)",
                    args={"size": len(wire)},
                )
            ]
        return []
    return []


@register(
    id="DELEGATION04",
    category=CATEGORY,
    name="Authoritative servers respond with AA bit set",
    spec_url=f"{SPEC_BASE}/delegation04.html",
    default_severity=Severity.ERROR,
)
async def delegation04(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    import dns.flags as _flags

    for ns in ctx.zone.parent_ns + ctx.zone.child_ns:
        for addr in ns.all_addresses():
            r = await ctx.resolver.query_at(ctx.domain, "SOA", addr)
            if r.error or r.response is None:
                continue
            if not (r.response.flags & _flags.AA):
                findings.append(
                    Finding(
                        check_id="DELEGATION04",
                        severity=Severity.ERROR,
                        message=f"{ns.name}/{addr} did not set AA bit on SOA response",
                        args={"ns": ns.name, "address": addr},
                        ns=ns.name,
                    )
                )
    return findings


@register(
    id="DELEGATION05",
    category=CATEGORY,
    name="Domain apex must not be a CNAME",
    description="RFC 2181 §10.3: a CNAME cannot coexist with NS/SOA at a zone apex.",
    spec_url=f"{SPEC_BASE}/delegation05.html",
    default_severity=Severity.ERROR,
)
async def delegation05(ctx: CheckContext) -> list[Finding]:
    for addr in ctx.authoritative_servers()[:3]:
        r = await ctx.resolver.query_at(ctx.domain, "CNAME", addr)
        if r.error or r.response is None:
            continue
        if any(rrset.rdtype == dns.rdatatype.CNAME for rrset in r.response.answer):
            return [
                Finding(
                    check_id="DELEGATION05",
                    severity=Severity.ERROR,
                    message=f"Zone apex {ctx.domain} has a CNAME record",
                    args={},
                )
            ]
    return []


@register(
    id="DELEGATION06",
    category=CATEGORY,
    name="Each authoritative server returns a SOA",
    spec_url=f"{SPEC_BASE}/delegation06.html",
    default_severity=Severity.ERROR,
)
async def delegation06(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for ns in ctx.zone.parent_ns + ctx.zone.child_ns:
        for addr in ns.all_addresses():
            r = await ctx.resolver.query_at(ctx.domain, "SOA", addr)
            if r.error or r.response is None:
                findings.append(
                    Finding(
                        check_id="DELEGATION06",
                        severity=Severity.ERROR,
                        message=f"{ns.name}/{addr} did not return SOA: {r.error or 'no response'}",
                        args={"ns": ns.name, "address": addr},
                        ns=ns.name,
                    )
                )
                continue
            if not any(rrset.rdtype == dns.rdatatype.SOA for rrset in r.response.answer):
                findings.append(
                    Finding(
                        check_id="DELEGATION06",
                        severity=Severity.ERROR,
                        message=f"{ns.name}/{addr} returned no SOA in answer section",
                        args={"ns": ns.name, "address": addr},
                        ns=ns.name,
                    )
                )
    return findings


@register(
    id="DELEGATION07",
    category=CATEGORY,
    name="Glue is provided for in-bailiwick name servers",
    description="If a name server is in-bailiwick, the parent must include glue (A/AAAA) records.",
    spec_url=f"{SPEC_BASE}/delegation07.html",
    default_severity=Severity.WARNING,
)
async def delegation07(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for ns in ctx.zone.parent_ns:
        if ns.in_bailiwick and not ns.glue_addresses:
            findings.append(
                Finding(
                    check_id="DELEGATION07",
                    severity=Severity.WARNING,
                    message=f"In-bailiwick NS {ns.name} has no glue at parent",
                    args={"ns": ns.name},
                    ns=ns.name,
                )
            )
    return findings
