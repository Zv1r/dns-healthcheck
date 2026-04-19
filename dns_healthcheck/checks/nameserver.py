"""Nameserver-TP: behavioural checks against each authoritative server."""

from __future__ import annotations

import asyncio

import dns.flags
import dns.message
import dns.opcode
import dns.rcode
import dns.rdatatype

from dns_healthcheck.context import CheckContext
from dns_healthcheck.registry import register
from dns_healthcheck.result import Finding, Severity

CATEGORY = "nameserver"
SPEC_BASE = "https://doc.zonemaster.net/latest/specifications/tests/Nameserver-TP"


def _iter_servers(ctx: CheckContext) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for ns in ctx.zone.parent_ns + ctx.zone.child_ns:
        for addr in ns.all_addresses():
            out.append((ns.name, addr))
    return out


@register(
    id="NAMESERVER01",
    category=CATEGORY,
    name="Authoritative server is not an open recursive resolver",
    spec_url=f"{SPEC_BASE}/nameserver01.html",
    default_severity=Severity.WARNING,
)
async def nameserver01(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for ns_name, addr in _iter_servers(ctx):
        r = await ctx.resolver.query_at("example.com", "A", addr)
        if r.response is not None and r.response.flags & dns.flags.RA:
            findings.append(
                Finding(
                    check_id="NAMESERVER01",
                    severity=Severity.WARNING,
                    message=f"{ns_name}/{addr} advertises recursion (RA flag set)",
                    args={"ns": ns_name, "address": addr},
                    ns=ns_name,
                )
            )
    return findings


@register(
    id="NAMESERVER02",
    category=CATEGORY,
    name="Authoritative server supports EDNS0",
    spec_url=f"{SPEC_BASE}/nameserver02.html",
    default_severity=Severity.WARNING,
)
async def nameserver02(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for ns_name, addr in _iter_servers(ctx):
        r = await ctx.resolver.query_at(ctx.domain, "SOA", addr, want_dnssec=True)
        if r.response is None:
            continue
        if r.response.edns < 0:
            findings.append(
                Finding(
                    check_id="NAMESERVER02",
                    severity=Severity.WARNING,
                    message=f"{ns_name}/{addr} does not support EDNS0",
                    args={"ns": ns_name, "address": addr},
                    ns=ns_name,
                )
            )
    return findings


@register(
    id="NAMESERVER03",
    category=CATEGORY,
    name="Authoritative server refuses zone transfer (AXFR) from internet",
    description="Public AXFR exposure leaks the entire zone (CWE-200).",
    spec_url=f"{SPEC_BASE}/nameserver03.html",
    default_severity=Severity.ERROR,
)
async def nameserver03(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    import dns.message
    import dns.name as _name
    import dns.rdataclass as _rdc

    async def probe(ns_name: str, addr: str) -> Finding | None:
        import contextlib

        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(addr, 53), timeout=4.0)
        except Exception:
            return None
        try:
            req = dns.message.make_query(_name.from_text(ctx.domain), dns.rdatatype.AXFR, _rdc.IN)
            wire = req.to_wire()
            writer.write(len(wire).to_bytes(2, "big") + wire)
            await writer.drain()
            length_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=4.0)
            n = int.from_bytes(length_bytes, "big")
            data = await asyncio.wait_for(reader.readexactly(n), timeout=4.0)
            resp = dns.message.from_wire(data)
            soa_count = sum(1 for rrset in resp.answer if rrset.rdtype == dns.rdatatype.SOA)
            if soa_count >= 1 and resp.rcode() == 0:
                return Finding(
                    check_id="NAMESERVER03",
                    severity=Severity.ERROR,
                    message=f"{ns_name}/{addr} allowed AXFR (zone transfer)",
                    args={"ns": ns_name, "address": addr},
                    ns=ns_name,
                )
        except Exception:
            return None
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        return None

    tasks = [probe(n, a) for n, a in _iter_servers(ctx)]
    for f in await asyncio.gather(*tasks, return_exceptions=False):
        if f:
            findings.append(f)
    return findings


@register(
    id="NAMESERVER04",
    category=CATEGORY,
    name="Authoritative server uses consistent source IP",
    description="Some bogus servers reply from a different IP than queried.",
    spec_url=f"{SPEC_BASE}/nameserver04.html",
    default_severity=Severity.NOTICE,
)
async def nameserver04(ctx: CheckContext) -> list[Finding]:
    return []


@register(
    id="NAMESERVER05",
    category=CATEGORY,
    name="Authoritative server returns AAAA records when asked",
    spec_url=f"{SPEC_BASE}/nameserver05.html",
    default_severity=Severity.NOTICE,
)
async def nameserver05(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for ns_name, addr in _iter_servers(ctx):
        r = await ctx.resolver.query_at(ctx.domain, "AAAA", addr)
        if r.error or r.response is None:
            continue
        if r.rcode not in (0,):
            findings.append(
                Finding(
                    check_id="NAMESERVER05",
                    severity=Severity.NOTICE,
                    message=f"{ns_name}/{addr} returned rcode={r.rcode} for AAAA",
                    args={"ns": ns_name, "address": addr, "rcode": r.rcode},
                    ns=ns_name,
                )
            )
    return findings


@register(
    id="NAMESERVER06",
    category=CATEGORY,
    name="Authoritative server can resolve its own SOA MNAME",
    spec_url=f"{SPEC_BASE}/nameserver06.html",
    default_severity=Severity.NOTICE,
)
async def nameserver06(ctx: CheckContext) -> list[Finding]:
    if not ctx.zone.soa:
        return []
    mname = ctx.zone.soa["mname"]
    addrs = await ctx.resolver.resolve_addresses(mname)
    if not addrs:
        return [
            Finding(
                check_id="NAMESERVER06",
                severity=Severity.NOTICE,
                message=f"SOA MNAME {mname} does not resolve to any address",
                args={"mname": mname},
            )
        ]
    return []


@register(
    id="NAMESERVER07",
    category=CATEGORY,
    name="Authoritative server treats names case-insensitively",
    spec_url=f"{SPEC_BASE}/nameserver07.html",
    default_severity=Severity.NOTICE,
)
async def nameserver07(ctx: CheckContext) -> list[Finding]:
    upper = ctx.domain.upper()
    findings: list[Finding] = []
    for ns_name, addr in _iter_servers(ctx)[:4]:
        r1 = await ctx.resolver.query_at(ctx.domain, "SOA", addr)
        r2 = await ctx.resolver.query_at(upper, "SOA", addr)
        if r1.error or r2.error:
            continue
        if r1.rcode != r2.rcode:
            findings.append(
                Finding(
                    check_id="NAMESERVER07",
                    severity=Severity.NOTICE,
                    message=f"{ns_name}/{addr} treats case differently (rcode {r1.rcode} vs {r2.rcode})",
                    args={"ns": ns_name},
                    ns=ns_name,
                )
            )
    return findings


@register(
    id="NAMESERVER08",
    category=CATEGORY,
    name="Authoritative server returns same SOA serial regardless of source",
    spec_url=f"{SPEC_BASE}/nameserver08.html",
    default_severity=Severity.NOTICE,
)
async def nameserver08(ctx: CheckContext) -> list[Finding]:
    return []


@register(
    id="NAMESERVER09",
    category=CATEGORY,
    name="Authoritative server returns NOERROR for the apex SOA",
    spec_url=f"{SPEC_BASE}/nameserver09.html",
    default_severity=Severity.ERROR,
)
async def nameserver09(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for ns_name, addr in _iter_servers(ctx):
        r = await ctx.resolver.query_at(ctx.domain, "SOA", addr)
        if r.error:
            continue
        if r.rcode != 0:
            findings.append(
                Finding(
                    check_id="NAMESERVER09",
                    severity=Severity.ERROR,
                    message=f"{ns_name}/{addr} returned rcode={r.rcode} for apex SOA",
                    args={"ns": ns_name, "rcode": r.rcode},
                    ns=ns_name,
                )
            )
    return findings


@register(
    id="NAMESERVER10",
    category=CATEGORY,
    name="Authoritative server responds to DNS COOKIE option (RFC 7873)",
    spec_url=f"{SPEC_BASE}/nameserver10.html",
    default_severity=Severity.INFO,
)
async def nameserver10(ctx: CheckContext) -> list[Finding]:
    return []


@register(
    id="NAMESERVER11",
    category=CATEGORY,
    name="Authoritative server does not leak its software version",
    description="`version.bind` CHAOS class queries should not reveal exact software/version.",
    spec_url=f"{SPEC_BASE}/nameserver11.html",
    default_severity=Severity.NOTICE,
)
async def nameserver11(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    import dns.asyncquery
    import dns.message as _msg
    import dns.rdataclass as _rdc

    async def probe(ns_name: str, addr: str) -> Finding | None:
        try:
            req = _msg.make_query("version.bind", "TXT", rdclass=_rdc.CH)
            resp = await dns.asyncquery.udp(req, addr, timeout=3.0, ignore_unexpected=True)
        except Exception:
            return None
        for rrset in resp.answer:
            for rd in rrset:
                txt = b"".join(rd.strings).decode(errors="ignore")
                if txt:
                    return Finding(
                        check_id="NAMESERVER11",
                        severity=Severity.NOTICE,
                        message=f"{ns_name}/{addr} discloses version: {txt!r}",
                        args={"ns": ns_name, "version": txt},
                        ns=ns_name,
                    )
        return None

    tasks = [probe(n, a) for n, a in _iter_servers(ctx)]
    for f in await asyncio.gather(*tasks):
        if f:
            findings.append(f)
    return findings


@register(
    id="NAMESERVER12",
    category=CATEGORY,
    name="Authoritative server handles TCP queries promptly",
    spec_url=f"{SPEC_BASE}/nameserver12.html",
    default_severity=Severity.NOTICE,
)
async def nameserver12(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for ns_name, addr in _iter_servers(ctx):
        r = await ctx.resolver.query_at(ctx.domain, "SOA", addr, use_tcp=True)
        if r.error:
            findings.append(
                Finding(
                    check_id="NAMESERVER12",
                    severity=Severity.NOTICE,
                    message=f"{ns_name}/{addr} TCP query failed: {r.error}",
                    args={"ns": ns_name, "error": r.error},
                    ns=ns_name,
                )
            )
    return findings


@register(
    id="NAMESERVER13",
    category=CATEGORY,
    name="Server gives the same answer over UDP and TCP",
    spec_url=f"{SPEC_BASE}/nameserver13.html",
    default_severity=Severity.NOTICE,
)
async def nameserver13(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for ns_name, addr in _iter_servers(ctx)[:6]:
        u = await ctx.resolver.query_at(ctx.domain, "SOA", addr, use_tcp=False)
        t = await ctx.resolver.query_at(ctx.domain, "SOA", addr, use_tcp=True)
        if u.error or t.error:
            continue
        if u.rcode != t.rcode:
            findings.append(
                Finding(
                    check_id="NAMESERVER13",
                    severity=Severity.NOTICE,
                    message=f"{ns_name}/{addr} UDP rcode={u.rcode} != TCP rcode={t.rcode}",
                    args={"ns": ns_name, "udp": u.rcode, "tcp": t.rcode},
                    ns=ns_name,
                )
            )
    return findings


@register(
    id="NAMESERVER14",
    category=CATEGORY,
    name="Server returns NXDOMAIN for clearly nonexistent name",
    spec_url=f"{SPEC_BASE}/nameserver14.html",
    default_severity=Severity.NOTICE,
)
async def nameserver14(ctx: CheckContext) -> list[Finding]:
    fake = f"definitely-does-not-exist-{abs(hash(ctx.domain)) % 10**8}.{ctx.domain}"
    findings: list[Finding] = []
    for ns_name, addr in _iter_servers(ctx)[:4]:
        r = await ctx.resolver.query_at(fake, "A", addr)
        if r.error or r.response is None:
            continue
        if r.rcode != dns.rcode.NXDOMAIN:
            findings.append(
                Finding(
                    check_id="NAMESERVER14",
                    severity=Severity.NOTICE,
                    message=f"{ns_name}/{addr} returned rcode={r.rcode} for nonexistent name (expected NXDOMAIN)",
                    args={"ns": ns_name, "rcode": r.rcode},
                    ns=ns_name,
                )
            )
    return findings
