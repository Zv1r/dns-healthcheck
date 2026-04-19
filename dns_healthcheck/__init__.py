"""dns-healthcheck — comprehensive DNS auditor."""

from dns_healthcheck.context import CheckContext
from dns_healthcheck.registry import REGISTRY, register
from dns_healthcheck.result import (
    CheckResult,
    Finding,
    RunReport,
    Severity,
)

__version__ = "0.5.0"

__all__ = [
    "REGISTRY",
    "CheckContext",
    "CheckResult",
    "Finding",
    "RunReport",
    "Severity",
    "__version__",
    "register",
]
