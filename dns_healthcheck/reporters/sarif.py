"""SARIF 2.1.0 reporter so findings can be ingested by GitHub Code Scanning."""

from __future__ import annotations

import json
from typing import Any

from dns_healthcheck import __version__
from dns_healthcheck.registry import REGISTRY
from dns_healthcheck.result import RunReport, Severity

_SEVERITY_TO_LEVEL = {
    Severity.INFO: "note",
    Severity.NOTICE: "note",
    Severity.WARNING: "warning",
    Severity.ERROR: "error",
    Severity.CRITICAL: "error",
}


def _rules() -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for spec in REGISTRY.all():
        rule: dict[str, Any] = {
            "id": spec.id,
            "name": spec.name,
            "shortDescription": {"text": spec.name},
            "fullDescription": {"text": spec.description.strip()},
            "defaultConfiguration": {"level": _SEVERITY_TO_LEVEL[spec.default_severity]},
            "properties": {"category": spec.category},
        }
        if spec.spec_url:
            rule["helpUri"] = spec.spec_url
        rules.append(rule)
    return rules


def render_sarif(report: RunReport) -> str:
    results: list[dict[str, Any]] = []
    for r in report.results:
        if r.skipped:
            continue
        if r.error:
            results.append(
                {
                    "ruleId": r.check_id,
                    "level": "error",
                    "message": {"text": f"Check execution error: {r.error}"},
                    "properties": {"category": r.category, "execution_error": True},
                }
            )
            continue
        for f in r.findings:
            results.append(
                {
                    "ruleId": r.check_id,
                    "level": _SEVERITY_TO_LEVEL[f.severity],
                    "message": {"text": f.message},
                    "properties": {
                        "category": r.category,
                        "severity": f.severity.label,
                        "ns": f.ns,
                        "args": f.args,
                    },
                }
            )

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dns-healthcheck",
                        "version": __version__,
                        "informationUri": "https://github.com/Zv1r/dns-healthcheck",
                        "rules": _rules(),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": report.started_at.isoformat(),
                        "endTimeUtc": report.ended_at.isoformat(),
                        "commandLine": f"dnshc check {report.domain}",
                    }
                ],
                "properties": {
                    "domain": report.domain,
                    "profile": report.profile,
                    "summary": report.summary,
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, default=str)
