"""Syntax checks for domain names and SOA fields (RFC 1035, 5891)."""

from __future__ import annotations

import idna

from dns_healthcheck.checks._helpers import valid_hostname, valid_label
from dns_healthcheck.context import CheckContext
from dns_healthcheck.registry import register
from dns_healthcheck.result import Finding, Severity

CATEGORY = "syntax"


@register(
    id="SYNTAX01",
    category=CATEGORY,
    name="Domain only contains allowed characters",
    description="Each label of the domain must use letters, digits, or hyphens (RFC 1035).",
    default_severity=Severity.ERROR,
)
async def syntax01(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for label in ctx.domain.split("."):
        if not valid_label(label):
            findings.append(
                Finding(
                    check_id="SYNTAX01",
                    severity=Severity.ERROR,
                    message=f"Label '{label}' contains characters outside [A-Za-z0-9-]",
                    args={"label": label},
                )
            )
    return findings


@register(
    id="SYNTAX02",
    category=CATEGORY,
    name="No leading or trailing hyphen",
    description="DNS labels must not begin or end with a hyphen.",
    default_severity=Severity.ERROR,
)
async def syntax02(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for label in ctx.domain.split("."):
        if label.startswith("-") or label.endswith("-"):
            findings.append(
                Finding(
                    check_id="SYNTAX02",
                    severity=Severity.ERROR,
                    message=f"Label '{label}' has leading or trailing hyphen",
                    args={"label": label},
                )
            )
    return findings


@register(
    id="SYNTAX03",
    category=CATEGORY,
    name="No double-hyphen unless it's a valid IDN A-label",
    description="Labels with '--' in positions 3-4 must be a valid IDNA A-label (xn--...).",
    default_severity=Severity.WARNING,
)
async def syntax03(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for label in ctx.domain.split("."):
        if len(label) >= 4 and label[2:4] == "--":
            if not label.lower().startswith("xn--"):
                findings.append(
                    Finding(
                        check_id="SYNTAX03",
                        severity=Severity.WARNING,
                        message=f"Label '{label}' has '--' at positions 3-4 but is not an IDN A-label",
                        args={"label": label},
                    )
                )
            else:
                try:
                    idna.decode(label)
                except idna.IDNAError as e:
                    findings.append(
                        Finding(
                            check_id="SYNTAX03",
                            severity=Severity.ERROR,
                            message=f"Invalid IDN A-label '{label}': {e}",
                            args={"label": label},
                        )
                    )
    return findings


@register(
    id="SYNTAX04",
    category=CATEGORY,
    name="SOA MNAME is a valid hostname",
    default_severity=Severity.WARNING,
)
async def syntax04(ctx: CheckContext) -> list[Finding]:
    if not ctx.zone.soa:
        return []
    mname = ctx.zone.soa["mname"]
    if not valid_hostname(mname):
        return [
            Finding(
                check_id="SYNTAX04",
                severity=Severity.WARNING,
                message=f"SOA MNAME '{mname}' is not a valid hostname",
                args={"mname": mname},
            )
        ]
    return []


@register(
    id="SYNTAX05",
    category=CATEGORY,
    name="SOA RNAME has valid mailbox syntax",
    description=(
        "The SOA RNAME field encodes an email address; "
        "the local part may not start with a digit-only label or unescaped '@'."
    ),
    default_severity=Severity.WARNING,
)
async def syntax05(ctx: CheckContext) -> list[Finding]:
    if not ctx.zone.soa:
        return []
    rname = ctx.zone.soa["rname"]
    if "@" in rname:
        return [
            Finding(
                check_id="SYNTAX05",
                severity=Severity.WARNING,
                message=f"SOA RNAME '{rname}' contains '@' (must be DNS-encoded with dot)",
                args={"rname": rname},
            )
        ]
    if not valid_hostname(rname):
        return [
            Finding(
                check_id="SYNTAX05",
                severity=Severity.WARNING,
                message=f"SOA RNAME '{rname}' is not a valid DNS-encoded mailbox",
                args={"rname": rname},
            )
        ]
    return []


@register(
    id="SYNTAX06",
    category=CATEGORY,
    name="Each NS hostname is syntactically valid",
    default_severity=Severity.WARNING,
)
async def syntax06(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for ns in ctx.zone.parent_ns + ctx.zone.child_ns:
        if not valid_hostname(ns.name):
            findings.append(
                Finding(
                    check_id="SYNTAX06",
                    severity=Severity.WARNING,
                    message=f"NS hostname '{ns.name}' is not syntactically valid",
                    args={"ns": ns.name},
                    ns=ns.name,
                )
            )
    return findings


@register(
    id="SYNTAX07",
    category=CATEGORY,
    name="Each MX hostname is syntactically valid",
    default_severity=Severity.WARNING,
)
async def syntax07(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for _, host in await ctx.get_mx():
        if not valid_hostname(host):
            findings.append(
                Finding(
                    check_id="SYNTAX07",
                    severity=Severity.WARNING,
                    message=f"MX hostname '{host}' is not syntactically valid",
                    args={"mx": host},
                )
            )
    return findings


@register(
    id="SYNTAX08",
    category=CATEGORY,
    name="Domain length is within DNS limits",
    description="Total domain length must be <= 253 octets and each label <= 63 octets.",
    default_severity=Severity.ERROR,
)
async def syntax08(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    if len(ctx.domain) > 253:
        findings.append(
            Finding(
                check_id="SYNTAX08",
                severity=Severity.ERROR,
                message=f"Domain length {len(ctx.domain)} exceeds 253 octets",
                args={"length": len(ctx.domain)},
            )
        )
    for label in ctx.domain.split("."):
        if len(label) > 63:
            findings.append(
                Finding(
                    check_id="SYNTAX08",
                    severity=Severity.ERROR,
                    message=f"Label '{label[:20]}...' exceeds 63 octets ({len(label)})",
                    args={"label": label},
                )
            )
    return findings
