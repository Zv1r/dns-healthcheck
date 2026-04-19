"""Nameserver behavioural checks against each authoritative server."""

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
    name="Server preserves QNAME case in response (0x20)",
    description=(
        "draft-vixie-dnsext-dns0x20: a name server SHOULD reflect the exact case "
        "of the query name in its response. Lowercasing breaks 0x20 spoofing defence."
    ),
    default_severity=Severity.NOTICE,
)
async def nameserver04(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    mixed = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(ctx.domain))
    for ns_name, addr in _iter_servers(ctx)[:4]:
        r = await ctx.resolver.query_at(mixed, "SOA", addr)
        if r.error or r.response is None or not r.response.answer:
            continue
        echoed = r.response.answer[0].name.to_text().rstrip(".")
        if echoed != mixed:
            findings.append(
                Finding(
                    check_id="NAMESERVER04",
                    severity=Severity.NOTICE,
                    message=f"{ns_name}/{addr} did not preserve QNAME case ({mixed!r} -> {echoed!r})",
                    args={"ns": ns_name, "queried": mixed, "returned": echoed},
                    ns=ns_name,
                )
            )
    return findings


@register(
    id="NAMESERVER05",
    category=CATEGORY,
    name="Authoritative server returns AAAA records when asked",
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
    name="SOA serial is stable across rapid identical queries",
    description=(
        "Three SOA queries within ~1s should return the same serial. A flapping "
        "serial usually means an inconsistent backend or load-balancer fan-out."
    ),
    default_severity=Severity.WARNING,
)
async def nameserver08(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for ns_name, addr in _iter_servers(ctx):
        serials: set[int] = set()
        for _ in range(3):
            r = await ctx.resolver.query_at(ctx.domain, "SOA", addr)
            if r.error or r.response is None:
                break
            for rrset in r.response.answer:
                if rrset.rdtype == dns.rdatatype.SOA:
                    serials.add(next(iter(rrset)).serial)
        if len(serials) > 1:
            findings.append(
                Finding(
                    check_id="NAMESERVER08",
                    severity=Severity.WARNING,
                    message=f"{ns_name}/{addr} returned multiple SOA serials in rapid succession: {sorted(serials)}",
                    args={"ns": ns_name, "address": addr, "serials": sorted(serials)},
                    ns=ns_name,
                )
            )
    return findings


@register(
    id="NAMESERVER09",
    category=CATEGORY,
    name="Authoritative server returns NOERROR for the apex SOA",
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
    name="Server supports DNS COOKIE (RFC 7873)",
    description=(
        "RFC 7873 defines the EDNS0 COOKIE option as a lightweight defence "
        "against off-path spoofing. Public authoritative servers SHOULD support it."
    ),
    default_severity=Severity.NOTICE,
)
async def nameserver10(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    import os

    import dns.asyncquery
    import dns.edns
    import dns.message as _msg

    client_cookie = os.urandom(8)

    async def probe(ns_name: str, addr: str) -> Finding | None:
        try:
            req = _msg.make_query(ctx.domain, "SOA")
            req.use_edns(0, options=[dns.edns.GenericOption(dns.edns.OptionType.COOKIE, client_cookie)])
            resp = await dns.asyncquery.udp(req, addr, timeout=4.0, ignore_unexpected=True)
        except Exception:
            return None
        for opt in resp.options or []:
            # COOKIE option. dnspython parses incoming cookies as
            # CookieOption with `.server` set; a non-empty server cookie
            # means the server actually supports COOKIE (and isn't just
            # echoing our client cookie). Also tolerate older dnspython
            # that may return GenericOption with raw bytes.
            if opt.otype != dns.edns.OptionType.COOKIE:
                continue
            if isinstance(opt, dns.edns.CookieOption) and len(opt.server) > 0:
                return None
            if isinstance(opt, dns.edns.GenericOption) and len(opt.data) > 8:
                return None
        return Finding(
            check_id="NAMESERVER10",
            severity=Severity.NOTICE,
            message=f"{ns_name}/{addr} did not return a server DNS COOKIE",
            args={"ns": ns_name, "address": addr},
            ns=ns_name,
        )

    tasks = [probe(n, a) for n, a in _iter_servers(ctx)]
    for f in await asyncio.gather(*tasks):
        if f:
            findings.append(f)
    return findings


@register(
    id="NAMESERVER11",
    category=CATEGORY,
    name="Authoritative server does not leak its software version",
    description="`version.bind` CHAOS class queries should not reveal exact software/version.",
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


@register(
    id="NAMESERVER15",
    category=CATEGORY,
    name="Server refuses IXFR (RFC 1995) from arbitrary clients",
    description=(
        "Like AXFR, public IXFR exposure leaks zone history. RFC 1995 servers "
        "should answer with NOTIMP, REFUSED, or fall back to AXFR (which we test "
        "separately) — never deliver an incremental zone transfer to a stranger."
    ),
    default_severity=Severity.ERROR,
)
async def nameserver15(ctx: CheckContext) -> list[Finding]:
    if not ctx.zone.soa:
        return []
    serial = max(int(ctx.zone.soa["serial"]) - 1, 0)
    findings: list[Finding] = []
    import dns.message as _msg
    import dns.name as _name
    import dns.rdata as _rdata
    import dns.rdataclass as _rdc

    soa_rdata = _rdata.from_text(
        _rdc.IN,
        dns.rdatatype.SOA,
        f"{ctx.zone.soa['mname']}. {ctx.zone.soa['rname']}. {serial} 7200 3600 1209600 3600",
    )

    async def probe(ns_name: str, addr: str) -> Finding | None:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(addr, 53), timeout=4.0)
        except Exception:
            return None
        try:
            req = _msg.make_query(_name.from_text(ctx.domain), dns.rdatatype.IXFR, _rdc.IN)
            req.authority.append(dns.rrset.from_rdata_list(_name.from_text(ctx.domain), 0, [soa_rdata]))
            wire = req.to_wire()
            writer.write(len(wire).to_bytes(2, "big") + wire)
            await writer.drain()
            length_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=4.0)
            n = int.from_bytes(length_bytes, "big")
            data = await asyncio.wait_for(reader.readexactly(n), timeout=4.0)
            resp = _msg.from_wire(data)
            soa_count = sum(1 for rrset in resp.answer if rrset.rdtype == dns.rdatatype.SOA)
            non_soa = any(rrset.rdtype not in (dns.rdatatype.SOA,) for rrset in resp.answer)
            # A successful IXFR delivers either a full zone (multiple answers) or
            # condensed difference records. Either way: more than just NOERROR+empty.
            if resp.rcode() == 0 and (soa_count > 1 or non_soa):
                return Finding(
                    check_id="NAMESERVER15",
                    severity=Severity.ERROR,
                    message=f"{ns_name}/{addr} delivered IXFR to an unauthenticated client",
                    args={"ns": ns_name, "address": addr},
                    ns=ns_name,
                )
        except Exception:
            return None
        finally:
            writer.close()
            import contextlib

            with contextlib.suppress(Exception):
                await writer.wait_closed()
        return None

    tasks = [probe(n, a) for n, a in _iter_servers(ctx)]
    for f in await asyncio.gather(*tasks):
        if f:
            findings.append(f)
    return findings


@register(
    id="NAMESERVER16",
    category=CATEGORY,
    name="Server is authoritative for unrelated zones (informational)",
    description=(
        "Reports when an authoritative server also answers (AA bit + answer data) "
        "for an unrelated probe domain. This usually means shared multi-tenant "
        "authoritative infrastructure — perfectly legitimate, but worth noting "
        "for blast-radius / supply-chain reasoning. RFC 1035 §4.3.1 / RFC 8499."
    ),
    default_severity=Severity.NOTICE,
)
async def nameserver16(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    foreign = "iana.org" if not ctx.domain.endswith("iana.org") else "icann.org"
    import dns.flags as _flags

    for ns_name, addr in _iter_servers(ctx)[:4]:
        r = await ctx.resolver.query_at(foreign, "A", addr)
        if r.error or r.response is None:
            continue
        has_answer = any(rrset.rdtype == dns.rdatatype.A for rrset in r.response.answer)
        if r.rcode == 0 and (r.response.flags & _flags.AA) and has_answer:
            findings.append(
                Finding(
                    check_id="NAMESERVER16",
                    severity=Severity.NOTICE,
                    message=(
                        f"{ns_name}/{addr} also serves {foreign} authoritatively (shared multi-tenant infrastructure)"
                    ),
                    args={"ns": ns_name, "address": addr, "probe": foreign},
                    ns=ns_name,
                )
            )
    return findings


@register(
    id="NAMESERVER17",
    category=CATEGORY,
    name="Negative responses include SOA in authority section (RFC 2308)",
    description=(
        "RFC 2308 §5: NXDOMAIN and NoData responses MUST include the zone's SOA "
        "in the authority section so resolvers can negative-cache correctly."
    ),
    default_severity=Severity.WARNING,
)
async def nameserver17(ctx: CheckContext) -> list[Finding]:
    fake = f"rfc2308-probe-{abs(hash(ctx.domain)) % 10**6}.{ctx.domain}"
    findings: list[Finding] = []
    for ns_name, addr in _iter_servers(ctx)[:4]:
        r = await ctx.resolver.query_at(fake, "A", addr)
        if r.error or r.response is None:
            continue
        if r.rcode != dns.rcode.NXDOMAIN:
            continue
        has_soa = any(rrset.rdtype == dns.rdatatype.SOA for rrset in r.response.authority)
        if not has_soa:
            findings.append(
                Finding(
                    check_id="NAMESERVER17",
                    severity=Severity.WARNING,
                    message=f"{ns_name}/{addr} NXDOMAIN response omits SOA in authority section (RFC 2308)",
                    args={"ns": ns_name, "address": addr},
                    ns=ns_name,
                )
            )
    return findings


@register(
    id="NAMESERVER18",
    category=CATEGORY,
    name="ANY queries are minimised per RFC 8482",
    description=(
        'RFC 8482: a server MAY synthesize a single HINFO record ("RFC8482") in '
        "response to qtype=ANY. Returning an entire RRset list is a known DDoS "
        "amplification vector and is discouraged."
    ),
    default_severity=Severity.NOTICE,
)
async def nameserver18(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for ns_name, addr in _iter_servers(ctx)[:4]:
        r = await ctx.resolver.query_at(ctx.domain, "ANY", addr)
        if r.error or r.response is None:
            continue
        rrtypes = {rrset.rdtype for rrset in r.response.answer}
        rrtypes.discard(dns.rdatatype.RRSIG)
        if len(rrtypes) > 3:
            findings.append(
                Finding(
                    check_id="NAMESERVER18",
                    severity=Severity.NOTICE,
                    message=(
                        f"{ns_name}/{addr} returned {len(rrtypes)} distinct rrtypes "
                        f"on qtype=ANY (RFC 8482 recommends minimised response)"
                    ),
                    args={
                        "ns": ns_name,
                        "address": addr,
                        "rrtypes": sorted(dns.rdatatype.to_text(t) for t in rrtypes),
                    },
                    ns=ns_name,
                )
            )
    return findings


@register(
    id="NAMESERVER19",
    category=CATEGORY,
    name="EDNS version negotiation is correct (RFC 6891)",
    description=(
        "RFC 6891 §6.1.3: when a server receives an EDNS version it doesn't support, "
        "it MUST respond with BADVERS (rcode 16) and echo an OPT RR. FORMERR or a "
        "silent timeout indicates broken EDNS handling that breaks DNSSEC and large "
        "responses for downstream resolvers."
    ),
    default_severity=Severity.WARNING,
)
async def nameserver19(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    import dns.asyncquery
    import dns.message as _msg

    async def probe(ns_name: str, addr: str) -> Finding | None:
        try:
            req = _msg.make_query(ctx.domain, "SOA")
            req.use_edns(edns=1, payload=1232)  # version 1 — server should answer BADVERS
            resp = await dns.asyncquery.udp(req, addr, timeout=4.0, ignore_unexpected=True)
        except dns.exception.Timeout:
            return Finding(
                check_id="NAMESERVER19",
                severity=Severity.WARNING,
                message=f"{ns_name}/{addr} timed out on EDNS version=1 query (broken EDNS)",
                args={"ns": ns_name, "address": addr},
                ns=ns_name,
            )
        except Exception:
            return None
        # Acceptable: BADVERS (16) with OPT echoed, or NOERROR (server ignored
        # the version and answered normally — RFC 6891 §6.1.3 allows this when
        # the requested version is back-compatible).
        if resp.rcode() in (0, 16) and resp.edns >= 0:
            return None
        return Finding(
            check_id="NAMESERVER19",
            severity=Severity.WARNING,
            message=(
                f"{ns_name}/{addr} mishandled EDNS version=1: rcode={dns.rcode.to_text(resp.rcode())}, edns={resp.edns}"
            ),
            args={"ns": ns_name, "address": addr, "rcode": resp.rcode(), "edns": resp.edns},
            ns=ns_name,
        )

    tasks = [probe(n, a) for n, a in _iter_servers(ctx)]
    for f in await asyncio.gather(*tasks):
        if f:
            findings.append(f)
    return findings


@register(
    id="NAMESERVER20",
    category=CATEGORY,
    name="Authoritative server responds within reasonable RTT",
    description=(
        "Per-NS UDP query latency. >150 ms is a NOTICE, >500 ms is a WARNING. "
        "Slow authoritative answers compound through the resolver hierarchy and "
        "noticeably degrade web/mail user experience."
    ),
    default_severity=Severity.NOTICE,
)
async def nameserver20(ctx: CheckContext) -> list[Finding]:
    import time

    import dns.asyncquery
    import dns.message as _msg

    findings: list[Finding] = []

    async def probe(ns_name: str, addr: str) -> Finding | None:
        req = _msg.make_query(ctx.domain, "SOA")
        # Fresh query (skip cache) to actually measure RTT.
        try:
            t0 = time.monotonic()
            await dns.asyncquery.udp(req, addr, timeout=4.0, ignore_unexpected=True)
            elapsed_ms = (time.monotonic() - t0) * 1000
        except Exception:
            return None
        if elapsed_ms > 500:
            return Finding(
                check_id="NAMESERVER20",
                severity=Severity.WARNING,
                message=f"{ns_name}/{addr} answered SOA in {elapsed_ms:.0f} ms (>500 ms)",
                args={"ns": ns_name, "address": addr, "rtt_ms": int(elapsed_ms)},
                ns=ns_name,
            )
        if elapsed_ms > 150:
            return Finding(
                check_id="NAMESERVER20",
                severity=Severity.NOTICE,
                message=f"{ns_name}/{addr} answered SOA in {elapsed_ms:.0f} ms (>150 ms)",
                args={"ns": ns_name, "address": addr, "rtt_ms": int(elapsed_ms)},
                ns=ns_name,
            )
        return None

    tasks = [probe(n, a) for n, a in _iter_servers(ctx)]
    for f in await asyncio.gather(*tasks):
        if f:
            findings.append(f)
    return findings


@register(
    id="NAMESERVER21",
    category=CATEGORY,
    name="Server sets TC bit and TCP fallback works for large responses",
    description=(
        "RFC 1035 §4.2.1 + RFC 7766: when a UDP response exceeds the buffer the "
        "client advertised, the server MUST set the TC (truncation) bit and the "
        "client MUST be able to retry over TCP with a complete answer. We probe "
        "DNSKEY (typically large, especially with RRSIG) at EDNS bufsize=512."
    ),
    default_severity=Severity.WARNING,
)
async def nameserver21(ctx: CheckContext) -> list[Finding]:
    import dns.asyncquery
    import dns.message as _msg

    findings: list[Finding] = []

    async def probe(ns_name: str, addr: str) -> Finding | None:
        # Force a tiny EDNS buffer so almost any DNSKEY+RRSIG will overflow.
        try:
            req = _msg.make_query(ctx.domain, "DNSKEY", want_dnssec=True)
            req.use_edns(0, payload=512)
            udp_resp = await dns.asyncquery.udp(req, addr, timeout=4.0, ignore_unexpected=True)
        except Exception:
            return None
        if not (udp_resp.flags & dns.flags.TC):
            # Either response fits in 512B (small zone — fine) or server ignores
            # the bufsize (worth reporting at INFO but skip to avoid noise).
            return None
        # TC was set — verify TCP retry returns a full, untruncated response.
        try:
            tcp_req = _msg.make_query(ctx.domain, "DNSKEY", want_dnssec=True)
            tcp_resp = await dns.asyncquery.tcp(tcp_req, addr, timeout=4.0)
        except Exception as e:
            return Finding(
                check_id="NAMESERVER21",
                severity=Severity.WARNING,
                message=f"{ns_name}/{addr} set TC over UDP but TCP retry failed: {e}",
                args={"ns": ns_name, "address": addr, "error": str(e)},
                ns=ns_name,
            )
        if tcp_resp.flags & dns.flags.TC:
            return Finding(
                check_id="NAMESERVER21",
                severity=Severity.WARNING,
                message=f"{ns_name}/{addr} returned a still-truncated response over TCP",
                args={"ns": ns_name, "address": addr},
                ns=ns_name,
            )
        return None

    tasks = [probe(n, a) for n, a in _iter_servers(ctx)[:4]]
    for f in await asyncio.gather(*tasks):
        if f:
            findings.append(f)
    return findings


@register(
    id="NAMESERVER22",
    category=CATEGORY,
    name="Server advertises a sane EDNS UDP buffer size (RFC 9715)",
    description=(
        "RFC 9715 §4: authoritative servers SHOULD advertise an EDNS UDP buffer "
        "size of 1232 (the safe MTU floor). Larger advertised payloads invite "
        "IPv6 fragmentation attacks; missing OPT (no EDNS) breaks DNSSEC."
    ),
    default_severity=Severity.NOTICE,
)
async def nameserver22(ctx: CheckContext) -> list[Finding]:
    import dns.asyncquery
    import dns.message as _msg

    findings: list[Finding] = []

    async def probe(ns_name: str, addr: str) -> Finding | None:
        try:
            req = _msg.make_query(ctx.domain, "SOA")
            req.use_edns(0, payload=1232)
            resp = await dns.asyncquery.udp(req, addr, timeout=4.0, ignore_unexpected=True)
        except Exception:
            return None
        if resp.edns < 0:
            return Finding(
                check_id="NAMESERVER22",
                severity=Severity.WARNING,
                message=f"{ns_name}/{addr} stripped EDNS — DNSSEC and large RRsets will break",
                args={"ns": ns_name, "address": addr},
                ns=ns_name,
            )
        if resp.payload > 4096:
            return Finding(
                check_id="NAMESERVER22",
                severity=Severity.NOTICE,
                message=(f"{ns_name}/{addr} advertises EDNS UDP payload {resp.payload}B (RFC 9715 recommends 1232)"),
                args={"ns": ns_name, "address": addr, "payload": resp.payload},
                ns=ns_name,
            )
        return None

    tasks = [probe(n, a) for n, a in _iter_servers(ctx)]
    for f in await asyncio.gather(*tasks):
        if f:
            findings.append(f)
    return findings
