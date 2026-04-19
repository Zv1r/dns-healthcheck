"""Decorator-based registry of all checks.

Each check is an async function ``(ctx: CheckContext) -> list[Finding]`` annotated with
:func:`register`. Modules under :mod:`dns_healthcheck.checks` self-register on import.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from dns_healthcheck.result import Severity

if TYPE_CHECKING:
    from dns_healthcheck.context import CheckContext
    from dns_healthcheck.result import Finding

CheckFn = Callable[["CheckContext"], Awaitable[list["Finding"]]]


@dataclass(frozen=True)
class CheckSpec:
    """Static metadata for a registered check."""

    id: str
    category: str
    name: str
    description: str
    spec_url: str | None
    fn: CheckFn
    requires_dnssec: bool = False
    requires_mx: bool = False
    requires_https: bool = False
    requires_non_tld: bool = False
    default_severity: Severity = Severity.NOTICE


class _Registry:
    def __init__(self) -> None:
        self._items: dict[str, CheckSpec] = {}
        self._loaded = False

    def add(self, spec: CheckSpec) -> None:
        if spec.id in self._items:
            raise ValueError(f"Duplicate check id: {spec.id}")
        self._items[spec.id] = spec

    def all(self) -> list[CheckSpec]:
        self._ensure_loaded()
        return sorted(self._items.values(), key=lambda c: (c.category, c.id))

    def by_id(self, check_id: str) -> CheckSpec | None:
        self._ensure_loaded()
        return self._items.get(check_id.upper())

    def by_category(self, category: str) -> list[CheckSpec]:
        self._ensure_loaded()
        return [c for c in self.all() if c.category == category]

    def categories(self) -> list[str]:
        self._ensure_loaded()
        return sorted({c.category for c in self._items.values()})

    def filter(
        self,
        only: list[str] | None = None,
        skip: list[str] | None = None,
        categories: list[str] | None = None,
    ) -> list[CheckSpec]:
        self._ensure_loaded()
        items = self.all()
        if categories:
            cat_set = {c.lower() for c in categories}
            items = [c for c in items if c.category.lower() in cat_set]
        if only:
            only_set = {o.upper() for o in only}
            items = [c for c in items if c.id.upper() in only_set or c.category.lower() in {o.lower() for o in only}]
        if skip:
            skip_set = {o.upper() for o in skip}
            items = [
                c for c in items if c.id.upper() not in skip_set and c.category.lower() not in {o.lower() for o in skip}
            ]
        return items

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        package = importlib.import_module("dns_healthcheck.checks")
        for mod in pkgutil.iter_modules(package.__path__):
            if mod.name.startswith("_"):
                continue
            importlib.import_module(f"dns_healthcheck.checks.{mod.name}")


REGISTRY = _Registry()


def register(
    *,
    id: str,
    category: str,
    name: str,
    description: str = "",
    spec_url: str | None = None,
    requires_dnssec: bool = False,
    requires_mx: bool = False,
    requires_https: bool = False,
    requires_non_tld: bool = False,
    default_severity: Severity = Severity.NOTICE,
) -> Callable[[CheckFn], CheckFn]:
    """Decorator that registers an async check function under ``id``."""

    def deco(fn: CheckFn) -> CheckFn:
        REGISTRY.add(
            CheckSpec(
                id=id.upper(),
                category=category.lower(),
                name=name,
                description=description or fn.__doc__ or "",
                spec_url=spec_url,
                fn=fn,
                requires_dnssec=requires_dnssec,
                requires_mx=requires_mx,
                requires_https=requires_https,
                requires_non_tld=requires_non_tld,
                default_severity=default_severity,
            )
        )
        return fn

    return deco
