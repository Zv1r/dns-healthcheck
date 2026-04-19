"""JUnit-XML reporter for CI consumption."""

from __future__ import annotations

from xml.etree import ElementTree as ET

from dns_healthcheck.result import RunReport, Severity


def render_junit(report: RunReport) -> str:
    suites = ET.Element(
        "testsuites",
        {
            "name": f"dns-healthcheck:{report.domain}",
            "tests": str(len(report.results)),
            "time": f"{report.duration_ms / 1000:.3f}",
        },
    )

    by_cat: dict[str, list] = {}
    for r in report.results:
        by_cat.setdefault(r.category, []).append(r)

    for category, items in sorted(by_cat.items()):
        failures = sum(1 for r in items if r.severity >= Severity.WARNING and not r.skipped)
        errors = sum(1 for r in items if r.error)
        skipped = sum(1 for r in items if r.skipped)
        suite = ET.SubElement(
            suites,
            "testsuite",
            {
                "name": category,
                "tests": str(len(items)),
                "failures": str(failures),
                "errors": str(errors),
                "skipped": str(skipped),
                "time": f"{sum(r.duration_ms for r in items) / 1000:.3f}",
            },
        )
        for r in items:
            tc = ET.SubElement(
                suite,
                "testcase",
                {
                    "classname": f"{category}.{r.check_id}",
                    "name": r.name,
                    "time": f"{r.duration_ms / 1000:.3f}",
                },
            )
            if r.skipped:
                ET.SubElement(tc, "skipped", {"message": r.skip_reason or ""})
            elif r.error:
                err = ET.SubElement(tc, "error", {"message": r.error, "type": "execution"})
                err.text = r.error
            else:
                worst = max((f.severity for f in r.findings), default=Severity.INFO)
                if worst >= Severity.WARNING:
                    msg = "; ".join(f.message for f in r.findings if f.severity >= Severity.WARNING)
                    fail = ET.SubElement(
                        tc,
                        "failure",
                        {"message": msg, "type": worst.label},
                    )
                    fail.text = "\n".join(f"[{f.severity.label}] {f.message}" for f in r.findings)

    ET.indent(suites, space="  ")
    return '<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(suites, encoding="unicode")
