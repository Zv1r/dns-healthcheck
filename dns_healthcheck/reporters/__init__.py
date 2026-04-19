"""Output reporters: text, json, sarif, junit, markdown."""

from __future__ import annotations

from collections.abc import Callable

from dns_healthcheck.reporters.json_reporter import render_json
from dns_healthcheck.reporters.junit import render_junit
from dns_healthcheck.reporters.markdown import render_markdown
from dns_healthcheck.reporters.sarif import render_sarif
from dns_healthcheck.reporters.text import render_text
from dns_healthcheck.result import RunReport

# Single-arg reporters (text takes a kwarg, so it's not in this dict).
REPORTERS: dict[str, Callable[[RunReport], str]] = {
    "text": render_text,
    "json": render_json,
    "sarif": render_sarif,
    "junit": render_junit,
    "markdown": render_markdown,
}

__all__ = [
    "REPORTERS",
    "render_json",
    "render_junit",
    "render_markdown",
    "render_sarif",
    "render_text",
]
