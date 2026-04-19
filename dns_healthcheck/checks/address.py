"""Address checks: nameserver IP reachability and reverse DNS."""

from __future__ import annotations

import asyncio

import dns.rdatatype
import dns.reversename

from dns_healthcheck.checks._helpers import is_global_ip
from dns_healthcheck.context import CheckContext
from dns_healthcheck.registry import register
from dns_healthcheck.result import Finding, Severity

CATEGORY = "address"


@register(
    id="ADDRESS01",
    category=CATEGORY,
    name="Name server address must be globally reachable",
    description="Authoritative name server addresses must not be in private/reserved ranges (RFC 1918, RFC 6890).",
    default_severity=Severity.ERROR,
)
async def address01(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for ns in ctx.zone.parent_ns + ctx.zone.child_ns:
        for addr in ns.all_addresses():
            if not is_global_ip(addr):
                findings.append(
                    Finding(
                        check_id="ADDRESS01",
                        severity=Severity.ERROR,
                        message=f"Name server {ns.name} uses non-globally-routable address {addr}",
                        args={"ns": ns.name, "address": addr},
                        ns=ns.name,
                    )
                )
    return findings


@register(
    id="ADDRESS02",
    category=CATEGORY,
    name="Reverse DNS entry exists for name server IP",
    description="Every authoritative name server IP should have a PTR record.",
    default_severity=Severity.WARNING,
)
async def address02(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []

    async def check_one(ns_name: str, addr: str) -> Finding | None:
        try:
            arpa = dns.reversename.from_address(addr).to_text()
            r = await ctx.resolver.query_stub(arpa, "PTR")
            if not r.answer:
                return Finding(
                    check_id="ADDRESS02",
                    severity=Severity.WARNING,
                    message=f"No PTR record for {addr} (NS {ns_name})",
                    args={"ns": ns_name, "address": addr},
                    ns=ns_name,
                )
        except Exception as e:
            return Finding(
                check_id="ADDRESS02",
                severity=Severity.NOTICE,
                message=f"Could not look up PTR for {addr}: {e}",
                args={"ns": ns_name, "address": addr},
                ns=ns_name,
            )
        return None

    tasks = []
    for ns in ctx.zone.parent_ns + ctx.zone.child_ns:
        for addr in ns.all_addresses():
            tasks.append(check_one(ns.name, addr))
    for f in await asyncio.gather(*tasks):
        if f:
            findings.append(f)
    return findings


@register(
    id="ADDRESS03",
    category=CATEGORY,
    name="Reverse DNS matches name server name",
    description="The PTR record should resolve back to the name server's hostname.",
    default_severity=Severity.NOTICE,
)
async def address03(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for ns in ctx.zone.parent_ns + ctx.zone.child_ns:
        for addr in ns.all_addresses():
            try:
                arpa = dns.reversename.from_address(addr).to_text()
                r = await ctx.resolver.query_stub(arpa, "PTR")
                if not r.response:
                    continue
                ptr_names = [
                    rd.to_text().rstrip(".").lower()
                    for rrset in r.response.answer
                    if rrset.rdtype == dns.rdatatype.PTR
                    for rd in rrset
                ]
                if ptr_names and ns.name not in ptr_names:
                    findings.append(
                        Finding(
                            check_id="ADDRESS03",
                            severity=Severity.NOTICE,
                            message=f"PTR for {addr} ({', '.join(ptr_names)}) does not match NS {ns.name}",
                            args={"ns": ns.name, "address": addr, "ptr": ptr_names},
                            ns=ns.name,
                        )
                    )
            except Exception:
                continue
    return findings
