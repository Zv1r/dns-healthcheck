"""Zone checks: SOA timer values, MX presence, mail/SPF policy."""

from __future__ import annotations

from dns_healthcheck.checks._helpers import valid_hostname
from dns_healthcheck.context import CheckContext
from dns_healthcheck.registry import register
from dns_healthcheck.result import Finding, Severity

CATEGORY = "zone"


def _soa_or_skip(ctx: CheckContext) -> dict | None:
    return ctx.zone.soa


@register(
    id="ZONE01",
    category=CATEGORY,
    name="SOA MNAME is a fully-qualified, valid hostname",
    default_severity=Severity.WARNING,
)
async def zone01(ctx: CheckContext) -> list[Finding]:
    soa = _soa_or_skip(ctx)
    if not soa:
        return []
    if not valid_hostname(soa["mname"]):
        return [
            Finding(
                check_id="ZONE01",
                severity=Severity.WARNING,
                message=f"SOA MNAME '{soa['mname']}' is not a valid hostname",
                args={"mname": soa["mname"]},
            )
        ]
    return []


@register(
    id="ZONE02",
    category=CATEGORY,
    name="SOA refresh value within recommended range",
    description="RFC 1912 §2.2 recommends 1200..43200 seconds.",
    default_severity=Severity.NOTICE,
)
async def zone02(ctx: CheckContext) -> list[Finding]:
    soa = _soa_or_skip(ctx)
    if not soa:
        return []
    refresh = soa["refresh"]
    if refresh < 1200:
        return [Finding("ZONE02", Severity.NOTICE, f"SOA refresh {refresh}s is below 1200s", {"refresh": refresh})]
    if refresh > 86400:
        return [Finding("ZONE02", Severity.NOTICE, f"SOA refresh {refresh}s is above 86400s", {"refresh": refresh})]
    return []


@register(
    id="ZONE03",
    category=CATEGORY,
    name="SOA retry within recommended range",
    description="RFC 1912 §2.2 recommends 180..7200 seconds.",
    default_severity=Severity.NOTICE,
)
async def zone03(ctx: CheckContext) -> list[Finding]:
    soa = _soa_or_skip(ctx)
    if not soa:
        return []
    retry = soa["retry"]
    if retry < 180 or retry > 7200:
        return [
            Finding(
                "ZONE03",
                Severity.NOTICE,
                f"SOA retry {retry}s outside 180..7200",
                {"retry": retry},
            )
        ]
    if retry > soa["refresh"]:
        return [
            Finding(
                "ZONE03",
                Severity.WARNING,
                f"SOA retry ({retry}s) is greater than refresh ({soa['refresh']}s)",
                {"retry": retry, "refresh": soa["refresh"]},
            )
        ]
    return []


@register(
    id="ZONE04",
    category=CATEGORY,
    name="SOA expire within recommended range",
    description="RFC 1912 §2.2 recommends 1209600..2419200 seconds (2..4 weeks).",
    default_severity=Severity.NOTICE,
)
async def zone04(ctx: CheckContext) -> list[Finding]:
    soa = _soa_or_skip(ctx)
    if not soa:
        return []
    expire = soa["expire"]
    if expire < 1209600:
        return [Finding("ZONE04", Severity.WARNING, f"SOA expire {expire}s is < 14 days", {"expire": expire})]
    if expire > 4 * 1209600:
        return [Finding("ZONE04", Severity.NOTICE, f"SOA expire {expire}s is > 8 weeks", {"expire": expire})]
    return []


@register(
    id="ZONE05",
    category=CATEGORY,
    name="SOA minimum TTL within recommended range",
    description="RFC 2308 §3 recommends 1..86400 seconds; many ops use 300..3600.",
    default_severity=Severity.NOTICE,
)
async def zone05(ctx: CheckContext) -> list[Finding]:
    soa = _soa_or_skip(ctx)
    if not soa:
        return []
    minimum = soa["minimum"]
    if minimum < 1 or minimum > 86400:
        return [
            Finding(
                "ZONE05",
                Severity.NOTICE,
                f"SOA minimum {minimum}s outside 1..86400",
                {"minimum": minimum},
            )
        ]
    return []


@register(
    id="ZONE06",
    category=CATEGORY,
    name="SOA MNAME resolves to an authoritative server",
    default_severity=Severity.WARNING,
)
async def zone06(ctx: CheckContext) -> list[Finding]:
    soa = _soa_or_skip(ctx)
    if not soa:
        return []
    auth_addrs = set(ctx.authoritative_servers())
    mname_addrs = await ctx.resolver.resolve_addresses(soa["mname"])
    if not mname_addrs:
        return []
    if not any(a in auth_addrs for a in mname_addrs):
        return [
            Finding(
                "ZONE06",
                Severity.NOTICE,
                f"SOA MNAME {soa['mname']} ({mname_addrs}) is not among the authoritative server set",
                {"mname": soa["mname"], "addresses": mname_addrs},
            )
        ]
    return []


@register(
    id="ZONE07",
    category=CATEGORY,
    name="MX hostnames are not CNAMEs",
    description="RFC 2181 §10.3 forbids MX target being a CNAME.",
    default_severity=Severity.WARNING,
)
async def zone07(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for _, host in await ctx.get_mx():
        r = await ctx.resolver.query_stub(host, "CNAME")
        if r.answer:
            findings.append(
                Finding(
                    "ZONE07",
                    Severity.WARNING,
                    f"MX target {host} is a CNAME (RFC 2181 forbids)",
                    {"mx": host},
                )
            )
    return findings


@register(
    id="ZONE08",
    category=CATEGORY,
    name="At least one MX record exists (when mail is expected)",
    default_severity=Severity.INFO,
)
async def zone08(ctx: CheckContext) -> list[Finding]:
    if not await ctx.has_mx():
        return [
            Finding(
                "ZONE08",
                Severity.INFO,
                f"No MX record present for {ctx.domain} (mail will fall back to A)",
                {},
            )
        ]
    return []


@register(
    id="ZONE09",
    category=CATEGORY,
    name="Domain has SPF record (TXT v=spf1) when MX present",
    default_severity=Severity.WARNING,
    requires_mx=True,
)
async def zone09(ctx: CheckContext) -> list[Finding]:
    r = await ctx.resolver.query_stub(ctx.domain, "TXT")
    spf_count = 0
    if r.response is not None:
        for rrset in r.response.answer:
            for rd in rrset:
                txt = b"".join(rd.strings).decode(errors="ignore")
                if txt.lower().startswith("v=spf1"):
                    spf_count += 1
    if spf_count == 0:
        return [
            Finding(
                "ZONE09",
                Severity.WARNING,
                f"No SPF (v=spf1) TXT record at {ctx.domain}",
                {},
            )
        ]
    if spf_count > 1:
        return [
            Finding(
                "ZONE09",
                Severity.ERROR,
                f"Multiple ({spf_count}) SPF records found — RFC 7208 §3.2 disallows",
                {"count": spf_count},
            )
        ]
    return []


@register(
    id="ZONE10",
    category=CATEGORY,
    name="Only one SOA record is returned",
    default_severity=Severity.ERROR,
)
async def zone10(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    import dns.rdatatype as _t

    for addr in ctx.authoritative_servers()[:4]:
        r = await ctx.resolver.query_at(ctx.domain, "SOA", addr)
        if r.error or r.response is None:
            continue
        soa_rrsets = [rrset for rrset in r.response.answer if rrset.rdtype == _t.SOA]
        soa_count = sum(len(rs) for rs in soa_rrsets)
        if soa_count > 1:
            findings.append(
                Finding(
                    "ZONE10",
                    Severity.ERROR,
                    f"{addr} returned {soa_count} SOA records (must be exactly 1)",
                    {"address": addr, "count": soa_count},
                )
            )
    return findings


@register(
    id="ZONE11",
    category=CATEGORY,
    name="No wildcard MX record at apex",
    description="A wildcard MX may capture nonexistent subdomains and surprise mail flow.",
    default_severity=Severity.NOTICE,
)
async def zone11(ctx: CheckContext) -> list[Finding]:
    fake = f"wildcard-probe-{abs(hash(ctx.domain)) % 10**6}.{ctx.domain}"
    r = await ctx.resolver.query_stub(fake, "MX")
    if r.answer:
        return [
            Finding(
                "ZONE11",
                Severity.NOTICE,
                f"Wildcard MX detected (random {fake} returned MX)",
                {"probe": fake},
            )
        ]
    return []


@register(
    id="ZONE12",
    category=CATEGORY,
    name="SOA TTL is consistent with SOA MINIMUM (RFC 2308 §4)",
    description=(
        "RFC 2308 §4: a SOA record's own TTL SHOULD be less than or equal to its "
        "MINIMUM field, since MINIMUM is the negative-cache TTL ceiling. A SOA TTL "
        "much larger than MINIMUM produces inconsistent caching behaviour."
    ),
    default_severity=Severity.NOTICE,
)
async def zone12(ctx: CheckContext) -> list[Finding]:
    if not ctx.zone.soa:
        return []
    import dns.rdatatype as _t

    minimum = ctx.zone.soa["minimum"]
    for addr in ctx.authoritative_servers()[:2]:
        r = await ctx.resolver.query_at(ctx.domain, "SOA", addr)
        if r.error or r.response is None:
            continue
        for rrset in r.response.answer:
            if rrset.rdtype == _t.SOA and rrset.ttl > minimum:
                return [
                    Finding(
                        "ZONE12",
                        Severity.NOTICE,
                        f"SOA TTL {rrset.ttl}s exceeds SOA MINIMUM {minimum}s (RFC 2308 §4)",
                        {"soa_ttl": rrset.ttl, "minimum": minimum},
                    )
                ]
        return []
    return []
