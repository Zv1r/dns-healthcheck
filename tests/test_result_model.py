"""Tests for Severity / Finding / CheckResult / RunReport."""

from __future__ import annotations

from datetime import datetime, timezone

from dns_healthcheck.result import CheckResult, Finding, RunReport, Severity


def test_severity_ordering() -> None:
    assert Severity.INFO < Severity.NOTICE < Severity.WARNING < Severity.ERROR < Severity.CRITICAL
    assert Severity.parse("warning") == Severity.WARNING
    assert Severity.parse(3) == Severity.ERROR


def test_check_result_severity_is_max_of_findings() -> None:
    r = CheckResult(check_id="X", category="basic", name="x")
    assert r.severity == Severity.INFO
    r.findings.append(Finding("X", Severity.NOTICE, "n"))
    r.findings.append(Finding("X", Severity.ERROR, "e"))
    assert r.severity == Severity.ERROR
    assert not r.passed


def test_run_report_summary_counts_per_severity() -> None:
    rep = RunReport.begin("example.com", "default", ["1.1.1.1"])
    r1 = CheckResult(check_id="A", category="basic", name="a")
    r1.findings.append(Finding("A", Severity.WARNING, "w"))
    r1.findings.append(Finding("A", Severity.WARNING, "w2"))
    r2 = CheckResult(check_id="B", category="basic", name="b")
    r2.findings.append(Finding("B", Severity.ERROR, "e"))
    r3 = CheckResult(check_id="C", category="basic", name="c", skipped=True)
    rep.results = [r1, r2, r3]
    rep.end()
    sm = rep.summary
    assert sm["WARNING"] == 2
    assert sm["ERROR"] == 1
    assert sm["total_checks"] == 3
    assert sm["skipped"] == 1
    assert rep.severity == Severity.ERROR


def test_run_report_serializes_to_dict() -> None:
    rep = RunReport(
        domain="x",
        profile="default",
        started_at=datetime.now(timezone.utc),
        ended_at=datetime.now(timezone.utc),
        results=[],
    )
    d = rep.to_dict()
    assert d["schema"].startswith("dns-healthcheck/")
    assert d["domain"] == "x"
    assert "summary" in d
