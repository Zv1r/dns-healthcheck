"""Consistency-TP: ensure every authoritative NS gives the same answer."""

from __future__ import annotations

import dns.rdatatype

from dns_healthcheck.context import CheckContext
from dns_healthcheck.registry import register
from dns_healthcheck.result import Finding, Severity

CATEGORY = "consistency"
SPEC_BASE = "https://doc.zonemaster.net/latest/specifications/tests/Consistency-TP"


async def _gather_soas(ctx: CheckContext) -> dict[str, dict | None]:
    out: dict[str, dict | None] = {}
    for addr in ctx.authoritative_servers():
        r = await ctx.resolver.query_at(ctx.domain, "SOA", addr)
        if r.error or not r.response:
            out[addr] = None
            continue
        for rrset in r.response.answer:
            if rrset.rdtype == dns.rdatatype.SOA:
                rd = next(iter(rrset))
                out[addr] = {
                    "mname": rd.mname.to_text().rstrip(".").lower(),
                    "rname": rd.rname.to_text().rstrip(".").lower(),
                    "serial": rd.serial,
                    "refresh": rd.refresh,
                    "retry": rd.retry,
                    "expire": rd.expire,
                    "minimum": rd.minimum,
                }
                break
        else:
            out[addr] = None
    return out


@register(
    id="CONSISTENCY01",
    category=CATEGORY,
    name="SOA serial is identical across all authoritative servers",
    spec_url=f"{SPEC_BASE}/consistency01.html",
    default_severity=Severity.WARNING,
)
async def consistency01(ctx: CheckContext) -> list[Finding]:
    soas = await _gather_soas(ctx)
    serials = {addr: s["serial"] for addr, s in soas.items() if s}
    if len(set(serials.values())) > 1:
        return [
            Finding(
                check_id="CONSISTENCY01",
                severity=Severity.WARNING,
                message=f"SOA serials differ: {serials}",
                args={"serials": serials},
            )
        ]
    return []


@register(
    id="CONSISTENCY02",
    category=CATEGORY,
    name="SOA RNAME consistent across servers",
    spec_url=f"{SPEC_BASE}/consistency02.html",
    default_severity=Severity.NOTICE,
)
async def consistency02(ctx: CheckContext) -> list[Finding]:
    soas = await _gather_soas(ctx)
    rnames = {addr: s["rname"] for addr, s in soas.items() if s}
    if len(set(rnames.values())) > 1:
        return [
            Finding(
                check_id="CONSISTENCY02",
                severity=Severity.NOTICE,
                message=f"SOA RNAME differs across servers: {rnames}",
                args={"rnames": rnames},
            )
        ]
    return []


@register(
    id="CONSISTENCY03",
    category=CATEGORY,
    name="SOA timer values consistent across servers",
    spec_url=f"{SPEC_BASE}/consistency03.html",
    default_severity=Severity.NOTICE,
)
async def consistency03(ctx: CheckContext) -> list[Finding]:
    soas = await _gather_soas(ctx)
    timers = {addr: (s["refresh"], s["retry"], s["expire"], s["minimum"]) for addr, s in soas.items() if s}
    if len(set(timers.values())) > 1:
        return [
            Finding(
                check_id="CONSISTENCY03",
                severity=Severity.NOTICE,
                message=f"SOA timer tuples (refresh,retry,expire,minimum) differ: {timers}",
                args={"timers": {a: list(t) for a, t in timers.items()}},
            )
        ]
    return []


@register(
    id="CONSISTENCY04",
    category=CATEGORY,
    name="NS RRset is identical at every authoritative server",
    spec_url=f"{SPEC_BASE}/consistency04.html",
    default_severity=Severity.WARNING,
)
async def consistency04(ctx: CheckContext) -> list[Finding]:
    nsets: dict[str, frozenset[str]] = {}
    for addr in ctx.authoritative_servers():
        r = await ctx.resolver.query_at(ctx.domain, "NS", addr)
        if r.error or not r.response:
            continue
        names: set[str] = set()
        for rrset in r.response.answer:
            if rrset.rdtype == dns.rdatatype.NS:
                for rd in rrset:
                    names.add(rd.to_text().rstrip(".").lower())
        nsets[addr] = frozenset(names)
    distinct = set(nsets.values())
    if len(distinct) > 1:
        return [
            Finding(
                check_id="CONSISTENCY04",
                severity=Severity.WARNING,
                message="NS RRset differs across authoritative servers",
                args={"per_server": {a: sorted(s) for a, s in nsets.items()}},
            )
        ]
    return []


@register(
    id="CONSISTENCY05",
    category=CATEGORY,
    name="Glue at parent matches authoritative addresses",
    spec_url=f"{SPEC_BASE}/consistency05.html",
    default_severity=Severity.WARNING,
)
async def consistency05(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for ns in ctx.zone.parent_ns:
        if not ns.glue_addresses:
            continue
        if not ns.in_bailiwick:
            continue
        auth_addrs = await ctx.resolver.resolve_addresses(ns.name)
        if not auth_addrs:
            continue
        if set(ns.glue_addresses) != set(auth_addrs):
            findings.append(
                Finding(
                    check_id="CONSISTENCY05",
                    severity=Severity.WARNING,
                    message=(
                        f"Glue for {ns.name} ({sorted(ns.glue_addresses)}) "
                        f"differs from authoritative ({sorted(auth_addrs)})"
                    ),
                    args={
                        "ns": ns.name,
                        "glue": sorted(ns.glue_addresses),
                        "authoritative": sorted(auth_addrs),
                    },
                    ns=ns.name,
                )
            )
    return findings


@register(
    id="CONSISTENCY06",
    category=CATEGORY,
    name="SOA MNAME consistent across authoritative servers",
    spec_url=f"{SPEC_BASE}/consistency06.html",
    default_severity=Severity.NOTICE,
)
async def consistency06(ctx: CheckContext) -> list[Finding]:
    soas = await _gather_soas(ctx)
    mnames = {addr: s["mname"] for addr, s in soas.items() if s}
    if len(set(mnames.values())) > 1:
        return [
            Finding(
                check_id="CONSISTENCY06",
                severity=Severity.NOTICE,
                message=f"SOA MNAME differs across servers: {mnames}",
                args={"mnames": mnames},
            )
        ]
    return []
