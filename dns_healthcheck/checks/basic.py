"""Basic checks: fundamental zone reachability."""

from __future__ import annotations

from dns_healthcheck.context import CheckContext
from dns_healthcheck.registry import register
from dns_healthcheck.result import Finding, Severity

CATEGORY = "basic"


@register(
    id="BASIC01",
    category=CATEGORY,
    name="Parent zone delegates the domain",
    description="The parent zone must contain a delegation (NS records) for the tested domain.",
    default_severity=Severity.CRITICAL,
)
async def basic01(ctx: CheckContext) -> list[Finding]:
    if not ctx.zone.parent_ns:
        return [
            Finding(
                check_id="BASIC01",
                severity=Severity.CRITICAL,
                message=f"No delegation found for {ctx.domain} from parent {ctx.zone.parent or '(root)'}",
                args={"parent": ctx.zone.parent},
            )
        ]
    return []


@register(
    id="BASIC02",
    category=CATEGORY,
    name="Domain has at least one working name server",
    description="At least one of the delegated name servers must answer authoritatively for the SOA.",
    default_severity=Severity.CRITICAL,
)
async def basic02(ctx: CheckContext) -> list[Finding]:
    if not ctx.authoritative_servers():
        return [
            Finding(
                check_id="BASIC02",
                severity=Severity.CRITICAL,
                message="No reachable authoritative name servers",
                args={},
            )
        ]
    if ctx.zone.soa is None:
        return [
            Finding(
                check_id="BASIC02",
                severity=Severity.ERROR,
                message="No name server returned a SOA record",
                args={"servers": ctx.authoritative_servers()},
            )
        ]
    return []


@register(
    id="BASIC03",
    category=CATEGORY,
    name="Zone resolves a representative A query",
    description="A query for the zone apex should be answerable (NOERROR) by an authoritative server.",
    default_severity=Severity.WARNING,
)
async def basic03(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for ns_addr in ctx.authoritative_servers()[:4]:
        r = await ctx.resolver.query_at(ctx.domain, "A", ns_addr)
        if not r.error and r.rcode == 0:
            return []
    findings.append(
        Finding(
            check_id="BASIC03",
            severity=Severity.WARNING,
            message=f"No authoritative server returned NOERROR for A {ctx.domain}",
            args={},
        )
    )
    return findings
