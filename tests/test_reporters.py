"""Reporter output sanity tests."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from dns_healthcheck.reporters import (
    render_json,
    render_junit,
    render_markdown,
    render_sarif,
    render_text,
)
from dns_healthcheck.result import CheckResult, Finding, RunReport, Severity


def _sample() -> RunReport:
    rep = RunReport(
        domain="example.com",
        profile="default",
        started_at=datetime.now(timezone.utc),
        ended_at=datetime.now(timezone.utc),
        results=[
            CheckResult(
                check_id="BASIC01",
                category="basic",
                name="Parent zone delegates the domain",
                findings=[],
            ),
            CheckResult(
                check_id="DELEGATION01",
                category="delegation",
                name="Min NS",
                findings=[
                    Finding("DELEGATION01", Severity.WARNING, "Only 1 NS"),
                ],
            ),
        ],
        resolvers=["1.1.1.1"],
    )
    return rep


def test_json_reporter_is_valid_json() -> None:
    out = render_json(_sample())
    parsed = json.loads(out)
    assert parsed["domain"] == "example.com"
    assert parsed["summary"]["WARNING"] == 1


def test_sarif_reporter_minimum_schema() -> None:
    out = render_sarif(_sample())
    parsed = json.loads(out)
    assert parsed["version"] == "2.1.0"
    runs = parsed["runs"]
    assert len(runs) == 1
    assert runs[0]["tool"]["driver"]["name"] == "dns-healthcheck"
    assert any(r["ruleId"] == "DELEGATION01" for r in runs[0]["results"])


def test_junit_reporter_is_valid_xml() -> None:
    out = render_junit(_sample())
    root = ET.fromstring(out)
    assert root.tag == "testsuites"
    suites = root.findall("testsuite")
    assert len(suites) >= 1


def test_markdown_reporter_contains_domain() -> None:
    out = render_markdown(_sample())
    assert "example.com" in out
    assert "DELEGATION01" in out


def test_text_reporter_renders() -> None:
    out = render_text(_sample(), no_color=True)
    assert "example.com" in out
    assert "Summary" in out
