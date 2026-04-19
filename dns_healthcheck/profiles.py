"""Predefined run profiles."""

from __future__ import annotations

from dataclasses import dataclass, field

from dns_healthcheck.result import Severity


@dataclass
class Profile:
    name: str
    description: str
    categories: list[str] = field(default_factory=list)
    skip_ids: list[str] = field(default_factory=list)
    promote_to_error: list[str] = field(default_factory=list)
    fail_on: Severity = Severity.ERROR


PROFILES: dict[str, Profile] = {
    "default": Profile(
        name="default",
        description="Run all categories with stock severities.",
        fail_on=Severity.ERROR,
    ),
    "strict": Profile(
        name="strict",
        description="Promote WARNINGs to ERRORs; fail on WARNING.",
        fail_on=Severity.WARNING,
    ),
    "minimal": Profile(
        name="minimal",
        description="Only delegation, basic, and DNSSEC categories.",
        categories=["basic", "delegation", "dnssec"],
        fail_on=Severity.ERROR,
    ),
    "email": Profile(
        name="email",
        description="Focus on mail-related checks (MX, SPF, DKIM, DMARC, MTA-STS, DANE).",
        categories=["basic", "email", "zone"],
        fail_on=Severity.WARNING,
    ),
    "web": Profile(
        name="web",
        description="Focus on web-facing posture (CAA, HTTPS, HSTS, certs).",
        categories=["basic", "web"],
        fail_on=Severity.WARNING,
    ),
    "ci": Profile(
        name="ci",
        description="All categories; designed for pipelines (machine output).",
        fail_on=Severity.ERROR,
    ),
}


def get_profile(name: str) -> Profile:
    if name not in PROFILES:
        raise KeyError(f"Unknown profile '{name}'. Available: {', '.join(sorted(PROFILES))}")
    return PROFILES[name]
