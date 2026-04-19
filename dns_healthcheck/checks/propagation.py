"""Multi-resolver propagation checks: query the same name through several public
resolvers and surface answer drift caused by stale caches or split-horizon DNS."""

from __future__ import annotations

import asyncio

import dns.rdatatype

from dns_healthcheck.context import CheckContext
from dns_healthcheck.data.root_hints import PUBLIC_RESOLVERS
from dns_healthcheck.registry import register
from dns_healthcheck.resolver import AsyncResolver
from dns_healthcheck.result import Finding, Severity

CATEGORY = "propagation"


def _resolvers(ctx: CheckContext) -> dict[str, list[str]]:
    return ctx.public_resolvers or PUBLIC_RESOLVERS


async def _resolve_via(resolver_addr: str, qname: str, qtype: str) -> set[str]:
    r = AsyncResolver(nameservers=[resolver_addr], timeout=5.0)
    res = await r.query_stub(qname, qtype)
    out: set[str] = set()
    if res.response is None:
        return out
    rdtype = dns.rdatatype.from_text(qtype)
    for rrset in res.response.answer:
        if rrset.rdtype != rdtype:
            continue
        for rd in rrset:
            out.add(rd.to_text().lower())
    return out


async def _per_resolver(qname: str, qtype: str, mapping: dict[str, list[str]]) -> dict[str, set[str]]:
    items: list[tuple[str, str]] = []
    for vendor, addrs in mapping.items():
        if addrs:
            items.append((vendor, addrs[0]))

    async def one(vendor: str, addr: str) -> tuple[str, set[str]]:
        return vendor, await _resolve_via(addr, qname, qtype)

    pairs = await asyncio.gather(*(one(v, a) for v, a in items))
    return dict(pairs)


@register(
    id="PROPAGATION01",
    category=CATEGORY,
    name="A/AAAA records consistent across major public resolvers",
    description="Compares answers from Cloudflare, Google, Quad9, OpenDNS, ControlD.",
    default_severity=Severity.NOTICE,
)
async def propagation01(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for qtype in ("A", "AAAA"):
        per = await _per_resolver(ctx.domain, qtype, _resolvers(ctx))
        per = {v: s for v, s in per.items() if s}
        distinct = {frozenset(s) for s in per.values()}
        if len(distinct) > 1:
            findings.append(
                Finding(
                    "PROPAGATION01",
                    Severity.NOTICE,
                    f"{qtype} answers differ across resolvers",
                    {"per_resolver": {v: sorted(s) for v, s in per.items()}},
                )
            )
    return findings


@register(
    id="PROPAGATION02",
    category=CATEGORY,
    name="MX records consistent across major public resolvers",
    default_severity=Severity.NOTICE,
    requires_mx=True,
)
async def propagation02(ctx: CheckContext) -> list[Finding]:
    per = await _per_resolver(ctx.domain, "MX", _resolvers(ctx))
    per = {v: s for v, s in per.items() if s}
    distinct = {frozenset(s) for s in per.values()}
    if len(distinct) > 1:
        return [
            Finding(
                "PROPAGATION02",
                Severity.NOTICE,
                "MX answers differ across resolvers",
                {"per_resolver": {v: sorted(s) for v, s in per.items()}},
            )
        ]
    return []


@register(
    id="PROPAGATION03",
    category=CATEGORY,
    name="NS records as seen by public resolvers match authoritative set",
    default_severity=Severity.NOTICE,
)
async def propagation03(ctx: CheckContext) -> list[Finding]:
    expected = {n.lower().rstrip(".") for n in ctx.authoritative_ns_names()}
    if not expected:
        return []
    per = await _per_resolver(ctx.domain, "NS", _resolvers(ctx))
    findings: list[Finding] = []
    for vendor, names in per.items():
        seen = {n.rstrip(".").lower() for n in names}
        if seen and seen != expected:
            findings.append(
                Finding(
                    "PROPAGATION03",
                    Severity.NOTICE,
                    f"{vendor} reports NS set {sorted(seen)} differing from authoritative {sorted(expected)}",
                    {"vendor": vendor, "seen": sorted(seen), "expected": sorted(expected)},
                )
            )
    return findings


@register(
    id="PROPAGATION04",
    category=CATEGORY,
    name="A-record TTLs are coherent across major public resolvers",
    description=(
        "When the same A RRset is served at wildly different TTLs across "
        "resolvers, it usually means the resolvers' caches are out of sync — "
        "either due to a recent change still propagating or to inconsistent "
        "authoritative TTLs. Skew greater than 5x the smallest TTL is flagged."
    ),
    default_severity=Severity.NOTICE,
)
async def propagation04(ctx: CheckContext) -> list[Finding]:
    items: list[tuple[str, str]] = []
    for vendor, addrs in _resolvers(ctx).items():
        if addrs:
            items.append((vendor, addrs[0]))

    async def one(vendor: str, addr: str) -> tuple[str, int | None]:
        r = AsyncResolver(nameservers=[addr], timeout=5.0)
        res = await r.query_stub(ctx.domain, "A")
        if res.response is None:
            return vendor, None
        for rrset in res.response.answer:
            if rrset.rdtype == dns.rdatatype.A:
                return vendor, int(rrset.ttl)
        return vendor, None

    pairs = await asyncio.gather(*(one(v, a) for v, a in items))
    ttls = {v: t for v, t in pairs if t is not None and t > 0}
    if len(ttls) < 2:
        return []
    lo = min(ttls.values())
    hi = max(ttls.values())
    if hi >= 5 * lo and (hi - lo) > 60:
        return [
            Finding(
                "PROPAGATION04",
                Severity.NOTICE,
                f"A-record TTL skew across resolvers: {ttls} (range {lo}..{hi}s)",
                {"per_resolver": ttls},
            )
        ]
    return []
