"""Result data model: severity, findings, per-check results, run report."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Severity levels, modelled on Zonemaster: INFO < NOTICE < WARNING < ERROR < CRITICAL."""

    INFO = 0
    NOTICE = 1
    WARNING = 2
    ERROR = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int) -> Severity:
        if isinstance(value, int):
            return cls(value)
        return cls[value.upper()]

    @property
    def label(self) -> str:
        return self.name


@dataclass(slots=True)
class Finding:
    """A single observation produced by a check."""

    check_id: str
    severity: Severity
    message: str
    args: dict[str, Any] = field(default_factory=dict)
    ns: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "severity": self.severity.label,
            "message": self.message,
            "args": self.args,
            "ns": self.ns,
        }


@dataclass(slots=True)
class CheckResult:
    """Outcome of running a single check."""

    check_id: str
    category: str
    name: str
    findings: list[Finding] = field(default_factory=list)
    duration_ms: int = 0
    skipped: bool = False
    skip_reason: str | None = None
    error: str | None = None

    @property
    def severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)

    @property
    def passed(self) -> bool:
        return self.severity < Severity.WARNING and not self.error

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "category": self.category,
            "name": self.name,
            "severity": self.severity.label,
            "findings": [f.to_dict() for f in self.findings],
            "duration_ms": self.duration_ms,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
            "error": self.error,
        }


@dataclass(slots=True)
class RunReport:
    """Report aggregating all check results for one domain run."""

    domain: str
    profile: str
    started_at: datetime
    ended_at: datetime
    results: list[CheckResult]
    resolvers: list[str] = field(default_factory=list)
    schema: str = "dns-healthcheck/1"

    @classmethod
    def begin(cls, domain: str, profile: str, resolvers: list[str]) -> RunReport:
        now = datetime.now(timezone.utc)
        return cls(
            domain=domain,
            profile=profile,
            started_at=now,
            ended_at=now,
            results=[],
            resolvers=resolvers,
        )

    def end(self) -> None:
        self.ended_at = datetime.now(timezone.utc)

    @property
    def duration_ms(self) -> int:
        return int((self.ended_at - self.started_at).total_seconds() * 1000)

    @property
    def severity(self) -> Severity:
        if not self.results:
            return Severity.INFO
        return max((r.severity for r in self.results), default=Severity.INFO)

    @property
    def summary(self) -> dict[str, int]:
        counts: Counter[str] = Counter()
        for r in self.results:
            for f in r.findings:
                counts[f.severity.label] += 1
        for level in Severity:
            counts.setdefault(level.label, 0)
        counts["total_checks"] = len(self.results)
        counts["skipped"] = sum(1 for r in self.results if r.skipped)
        counts["errored"] = sum(1 for r in self.results if r.error)
        return dict(counts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "domain": self.domain,
            "profile": self.profile,
            "resolvers": self.resolvers,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat(),
            "duration_ms": self.duration_ms,
            "severity": self.severity.label,
            "summary": self.summary,
            "results": [r.to_dict() for r in self.results],
        }
