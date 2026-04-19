"""Email security checks: SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, DANE."""

from __future__ import annotations

import asyncio
import re

import dns.rdatatype
import httpx

from dns_healthcheck.context import CheckContext
from dns_healthcheck.data.root_hints import COMMON_DKIM_SELECTORS
from dns_healthcheck.registry import register
from dns_healthcheck.result import Finding, Severity

CATEGORY = "email"


async def _txt_records(ctx: CheckContext, name: str) -> list[str]:
    r = await ctx.resolver.query_stub(name, "TXT")
    out: list[str] = []
    if r.response is not None:
        for rrset in r.response.answer:
            if rrset.rdtype == dns.rdatatype.TXT:
                for rd in rrset:
                    out.append(b"".join(rd.strings).decode(errors="ignore"))
    return out


@register(
    id="EMAIL01",
    category=CATEGORY,
    name="SPF (v=spf1) record present and parseable",
    description="RFC 7208. Domain accepting mail must publish SPF policy.",
    default_severity=Severity.WARNING,
)
async def email01(ctx: CheckContext) -> list[Finding]:
    txts = await _txt_records(ctx, ctx.domain)
    spfs = [t for t in txts if t.lower().startswith("v=spf1")]
    if not spfs:
        if await ctx.has_mx():
            return [Finding("EMAIL01", Severity.WARNING, "No SPF (v=spf1) record published", {})]
        return [Finding("EMAIL01", Severity.NOTICE, "No SPF record (no MX present either)", {})]
    if len(spfs) > 1:
        return [
            Finding(
                "EMAIL01",
                Severity.ERROR,
                f"Multiple ({len(spfs)}) SPF records — RFC 7208 §3.2 requires exactly one",
                {"records": spfs},
            )
        ]
    return []


@register(
    id="EMAIL02",
    category=CATEGORY,
    name="SPF policy uses safe terminator and stays under DNS lookup limit",
    description="RFC 7208 §4.6.4: policy may not require more than 10 mechanism DNS lookups; +all is unsafe.",
    default_severity=Severity.WARNING,
)
async def email02(ctx: CheckContext) -> list[Finding]:
    txts = await _txt_records(ctx, ctx.domain)
    spfs = [t for t in txts if t.lower().startswith("v=spf1")]
    if not spfs:
        return []
    spf = spfs[0]
    findings: list[Finding] = []

    if "+all" in spf.lower() or spf.lower().rstrip().endswith(" all"):
        findings.append(
            Finding(
                "EMAIL02",
                Severity.ERROR,
                "SPF terminator is '+all' (or implicit pass) — accepts mail from anywhere",
                {"spf": spf},
            )
        )
    elif "?all" in spf.lower():
        findings.append(
            Finding(
                "EMAIL02",
                Severity.NOTICE,
                "SPF terminator is '?all' (neutral) — provides no policy guidance",
                {"spf": spf},
            )
        )

    lookups = await _spf_lookup_count(ctx, ctx.domain, spf, depth=0)
    if lookups > 10:
        findings.append(
            Finding(
                "EMAIL02",
                Severity.ERROR,
                f"SPF policy exceeds 10-DNS-lookup limit ({lookups} required)",
                {"lookups": lookups},
            )
        )
    elif lookups > 8:
        findings.append(
            Finding(
                "EMAIL02",
                Severity.WARNING,
                f"SPF policy uses {lookups} DNS lookups (limit is 10)",
                {"lookups": lookups},
            )
        )
    return findings


_SPF_TOKEN = re.compile(r"^[?+\-~]?(include|exists|redirect|a|mx|ptr)(?:[:=](.+))?$")


async def _spf_lookup_count(ctx: CheckContext, current: str, spf: str, depth: int) -> int:
    if depth > 5:
        return 0
    count = 0
    for raw in spf.split():
        token = raw.lower()
        if token in {"v=spf1", "+all", "-all", "~all", "?all", "all"}:
            continue
        m = _SPF_TOKEN.match(token)
        if not m:
            continue
        kind, val = m.group(1), m.group(2)
        if kind in {"a", "mx", "ptr", "exists"}:
            count += 1
        elif (kind == "include" and val) or (kind == "redirect" and val):
            count += 1
            for t in await _txt_records(ctx, val):
                if t.lower().startswith("v=spf1"):
                    count += await _spf_lookup_count(ctx, val, t, depth + 1)
                    break
    return count


@register(
    id="EMAIL03",
    category=CATEGORY,
    name="DMARC policy is published with strict-enough enforcement",
    description="RFC 7489 — _dmarc.{domain} TXT must exist; p=none provides no protection.",
    default_severity=Severity.WARNING,
)
async def email03(ctx: CheckContext) -> list[Finding]:
    txts = await _txt_records(ctx, f"_dmarc.{ctx.domain}")
    dmarcs = [t for t in txts if t.lower().startswith("v=dmarc1")]
    if not dmarcs:
        return [Finding("EMAIL03", Severity.WARNING, f"No DMARC record at _dmarc.{ctx.domain}", {})]
    rec = dmarcs[0]
    tags = {k.strip().lower(): v.strip() for k, _, v in (s.partition("=") for s in rec.split(";")) if k}
    findings: list[Finding] = []
    policy = tags.get("p", "").lower()
    if not policy:
        findings.append(Finding("EMAIL03", Severity.ERROR, "DMARC record missing required p= tag", {"record": rec}))
    elif policy == "none":
        findings.append(
            Finding(
                "EMAIL03",
                Severity.WARNING,
                "DMARC policy is p=none (monitoring only) — provides no enforcement",
                {"record": rec},
            )
        )
    if "rua" not in tags:
        findings.append(
            Finding(
                "EMAIL03",
                Severity.NOTICE,
                "DMARC record has no rua= aggregate-report destination",
                {"record": rec},
            )
        )
    return findings


@register(
    id="EMAIL04",
    category=CATEGORY,
    name="DKIM key found at common selectors",
    description="Probes ~25 common DKIM selectors; absence is informational since selectors are arbitrary.",
    default_severity=Severity.INFO,
    requires_mx=True,
)
async def email04(ctx: CheckContext) -> list[Finding]:
    found: list[str] = []

    async def probe(selector: str) -> str | None:
        txts = await _txt_records(ctx, f"{selector}._domainkey.{ctx.domain}")
        if any("v=dkim1" in t.lower() or "p=" in t.lower() for t in txts):
            return selector
        return None

    sem = asyncio.Semaphore(8)

    async def bounded(s: str) -> str | None:
        async with sem:
            return await probe(s)

    results = await asyncio.gather(*(bounded(s) for s in COMMON_DKIM_SELECTORS))
    found = [r for r in results if r]
    if not found:
        return [
            Finding(
                "EMAIL04",
                Severity.INFO,
                f"No DKIM key found at {len(COMMON_DKIM_SELECTORS)} common selectors; selectors are operator-defined",
                {"probed": COMMON_DKIM_SELECTORS},
            )
        ]
    return [
        Finding(
            "EMAIL04",
            Severity.INFO,
            f"DKIM keys present at selectors: {', '.join(sorted(found))}",
            {"selectors": found},
        )
    ]


@register(
    id="EMAIL05",
    category=CATEGORY,
    name="MTA-STS published and policy retrievable over HTTPS",
    description="RFC 8461. Requires _mta-sts TXT and a policy at https://mta-sts.{domain}/.well-known/mta-sts.txt.",
    default_severity=Severity.NOTICE,
    requires_mx=True,
)
async def email05(ctx: CheckContext) -> list[Finding]:
    txts = await _txt_records(ctx, f"_mta-sts.{ctx.domain}")
    if not any("v=stsv1" in t.lower() for t in txts):
        return [
            Finding(
                "EMAIL05",
                Severity.NOTICE,
                f"No MTA-STS record at _mta-sts.{ctx.domain}",
                {},
            )
        ]
    url = f"https://mta-sts.{ctx.domain}/.well-known/mta-sts.txt"
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
            resp = await client.get(url)
        if resp.status_code != 200:
            return [
                Finding(
                    "EMAIL05",
                    Severity.WARNING,
                    f"MTA-STS TXT present but policy URL {url} returned HTTP {resp.status_code}",
                    {"url": url, "status": resp.status_code},
                )
            ]
        if "version: STSv1" not in resp.text:
            return [
                Finding(
                    "EMAIL05",
                    Severity.WARNING,
                    "MTA-STS policy is missing 'version: STSv1' header",
                    {"url": url},
                )
            ]
    except Exception as e:
        return [
            Finding(
                "EMAIL05",
                Severity.WARNING,
                f"Could not fetch MTA-STS policy: {e}",
                {"url": url, "error": str(e)},
            )
        ]
    return []


@register(
    id="EMAIL06",
    category=CATEGORY,
    name="TLS-RPT (SMTP TLS Reporting) published",
    description="RFC 8460. _smtp._tls.{domain} TXT enables TLS failure reports.",
    default_severity=Severity.INFO,
    requires_mx=True,
)
async def email06(ctx: CheckContext) -> list[Finding]:
    txts = await _txt_records(ctx, f"_smtp._tls.{ctx.domain}")
    if not any("v=tlsrptv1" in t.lower() for t in txts):
        return [
            Finding(
                "EMAIL06",
                Severity.INFO,
                f"No TLS-RPT record at _smtp._tls.{ctx.domain}",
                {},
            )
        ]
    return []


@register(
    id="EMAIL07",
    category=CATEGORY,
    name="BIMI record present and references VMC",
    description="BIMI: default._bimi.{domain} TXT publishes a logo URL and (ideally) a Verified Mark Certificate.",
    default_severity=Severity.INFO,
    requires_mx=True,
)
async def email07(ctx: CheckContext) -> list[Finding]:
    txts = await _txt_records(ctx, f"default._bimi.{ctx.domain}")
    bimis = [t for t in txts if t.lower().startswith("v=bimi1")]
    if not bimis:
        return [Finding("EMAIL07", Severity.INFO, "No BIMI record at default._bimi", {})]
    rec = bimis[0]
    findings: list[Finding] = []
    tags = {k.strip().lower(): v.strip() for k, _, v in (s.partition("=") for s in rec.split(";")) if k}
    if not tags.get("l"):
        findings.append(Finding("EMAIL07", Severity.WARNING, "BIMI record missing l= (logo URL)", {"record": rec}))
    if not tags.get("a"):
        findings.append(
            Finding(
                "EMAIL07",
                Severity.NOTICE,
                "BIMI record missing a= (VMC URL); Gmail/Yahoo require VMC for blue checkmark",
                {"record": rec},
            )
        )
    return findings


@register(
    id="EMAIL08",
    category=CATEGORY,
    name="DANE TLSA records present for SMTP (port 25) when DNSSEC enabled",
    description="RFC 7672 — DANE for SMTP requires DNSSEC + TLSA records on each MX target.",
    default_severity=Severity.INFO,
    requires_mx=True,
)
async def email08(ctx: CheckContext) -> list[Finding]:
    if not ctx.zone.has_dnssec:
        return []
    findings: list[Finding] = []
    for _, mx in await ctx.get_mx():
        r = await ctx.resolver.query_stub(f"_25._tcp.{mx}", "TLSA")
        if not r.answer:
            findings.append(
                Finding(
                    "EMAIL08",
                    Severity.NOTICE,
                    f"No TLSA record for _25._tcp.{mx}",
                    {"mx": mx},
                )
            )
    return findings
