"""Delegation checks: parent/child delegation correctness."""

from __future__ import annotations

import dns.rdatatype

from dns_healthcheck.context import CheckContext
from dns_healthcheck.registry import register
from dns_healthcheck.result import Finding, Severity

CATEGORY = "delegation"


@register(
    id="DELEGATION01",
    category=CATEGORY,
    name="At least two name servers in the delegation",
    description="RFC 1035 §4.1 strongly recommends >= 2 name servers per zone.",
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


@register(
    id="DELEGATION08",
    category=CATEGORY,
    name="No NS target is a CNAME",
    description=(
        "RFC 2181 §10.3: an NS RDATA value MUST point to a hostname that owns "
        "an A/AAAA record, never a CNAME. Resolvers reject CNAME-targeted NS."
    ),
    default_severity=Severity.ERROR,
)
async def delegation08(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for ns in ctx.zone.parent_ns + ctx.zone.child_ns:
        r = await ctx.resolver.query_stub(ns.name, "CNAME")
        if r.answer:
            findings.append(
                Finding(
                    check_id="DELEGATION08",
                    severity=Severity.ERROR,
                    message=f"NS {ns.name} resolves through a CNAME (RFC 2181 §10.3 forbids)",
                    args={"ns": ns.name},
                    ns=ns.name,
                )
            )
    return findings


@register(
    id="DELEGATION09",
    category=CATEGORY,
    name="Every NS hostname resolves to at least one address",
    description=(
        "An NS hostname that returns NXDOMAIN or no A/AAAA records is a "
        "lame delegation at the name level: the parent advertises it but no "
        "resolver can ever reach it."
    ),
    default_severity=Severity.ERROR,
)
async def delegation09(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for ns in ctx.zone.parent_ns + ctx.zone.child_ns:
        if ns.all_addresses():
            continue
        addrs = await ctx.resolver.resolve_addresses(ns.name)
        if not addrs:
            findings.append(
                Finding(
                    check_id="DELEGATION09",
                    severity=Severity.ERROR,
                    message=f"NS hostname {ns.name} resolves to no A/AAAA address",
                    args={"ns": ns.name},
                    ns=ns.name,
                )
            )
    return findings


@register(
    id="DELEGATION10",
    category=CATEGORY,
    name="NS set has both IPv4 and IPv6 coverage (BCP 91)",
    description=(
        "RFC 3901 / BCP 91: a zone SHOULD be reachable over both address families. "
        "An IPv4-only or IPv6-only NS set degrades reachability for half the internet."
    ),
    default_severity=Severity.NOTICE,
)
async def delegation10(ctx: CheckContext) -> list[Finding]:
    import ipaddress

    has_v4 = False
    has_v6 = False
    for ns in ctx.zone.parent_ns + ctx.zone.child_ns:
        for addr in ns.all_addresses():
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if isinstance(ip, ipaddress.IPv4Address):
                has_v4 = True
            else:
                has_v6 = True
    findings: list[Finding] = []
    if not has_v4:
        findings.append(
            Finding(
                check_id="DELEGATION10",
                severity=Severity.NOTICE,
                message="No IPv4 address among NS set (zone unreachable from v4-only resolvers)",
                args={},
            )
        )
    if not has_v6:
        findings.append(
            Finding(
                check_id="DELEGATION10",
                severity=Severity.NOTICE,
                message="No IPv6 address among NS set (zone unreachable from v6-only resolvers)",
                args={},
            )
        )
    return findings
