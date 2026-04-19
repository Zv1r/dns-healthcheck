"""Run orchestration: discover checks, execute concurrently, aggregate results."""

from __future__ import annotations

import asyncio
import time

from dns_healthcheck.context import CheckContext
from dns_healthcheck.profiles import Profile
from dns_healthcheck.registry import REGISTRY, CheckSpec
from dns_healthcheck.resolver import AsyncResolver
from dns_healthcheck.result import CheckResult, RunReport


async def _run_one(spec: CheckSpec, ctx: CheckContext) -> CheckResult:
    res = CheckResult(check_id=spec.id, category=spec.category, name=spec.name)
    if spec.requires_dnssec and not ctx.zone.has_dnssec:
        res.skipped = True
        res.skip_reason = "Zone is not DNSSEC-signed"
        return res
    if spec.requires_mx and not await ctx.has_mx():
        res.skipped = True
        res.skip_reason = "Zone has no MX records"
        return res
    if spec.requires_non_tld and "." not in ctx.domain:
        res.skipped = True
        res.skip_reason = "Check is not meaningful for a TLD"
        return res
    t0 = time.monotonic()
    try:
        findings = await spec.fn(ctx)
        res.findings = findings
    except Exception as e:
        res.error = f"{type(e).__name__}: {e}"
    res.duration_ms = int((time.monotonic() - t0) * 1000)
    return res


async def run(
    domain: str,
    profile: Profile,
    only: list[str] | None = None,
    skip: list[str] | None = None,
    resolvers: list[str] | None = None,
    public_resolvers: dict[str, list[str]] | None = None,
    concurrency: int = 8,
    timeout: float = 5.0,
    use_ipv6: bool = True,
) -> RunReport:
    res = AsyncResolver(nameservers=resolvers, timeout=timeout, use_ipv6=use_ipv6)
    ctx = CheckContext(domain, res, profile=profile.name, public_resolvers=public_resolvers or {})
    await ctx.initialize()

    selected = REGISTRY.filter(
        only=only,
        skip=(skip or []) + profile.skip_ids,
        categories=profile.categories or None,
    )

    report = RunReport.begin(domain, profile.name, [str(s) for s in (resolvers or res._stub.nameservers)])
    sem = asyncio.Semaphore(concurrency)

    async def bounded(spec: CheckSpec) -> CheckResult:
        async with sem:
            return await _run_one(spec, ctx)

    results = await asyncio.gather(*(bounded(s) for s in selected))
    report.results = list(results)
    report.end()
    return report
