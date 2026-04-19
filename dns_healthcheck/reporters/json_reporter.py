"""JSON reporter."""

from __future__ import annotations

import json

from dns_healthcheck.result import RunReport


def render_json(report: RunReport, *, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, sort_keys=False, default=str)
