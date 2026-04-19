"""Smoke tests for the check registry."""

from __future__ import annotations

from dns_healthcheck.registry import REGISTRY


def test_registry_has_all_core_dns_categories() -> None:
    cats = set(REGISTRY.categories())
    expected = {
        "address",
        "basic",
        "connectivity",
        "consistency",
        "delegation",
        "dnssec",
        "nameserver",
        "syntax",
        "zone",
    }
    assert expected.issubset(cats), f"Missing: {expected - cats}"


def test_registry_has_extended_categories() -> None:
    cats = set(REGISTRY.categories())
    assert {"email", "web", "propagation"}.issubset(cats)


def test_registry_minimum_check_count() -> None:
    # 9 core DNS categories (87) + 3 extended categories (25) = 112
    assert len(REGISTRY.all()) >= 112


def test_check_ids_are_unique_and_uppercase() -> None:
    ids = [c.id for c in REGISTRY.all()]
    assert len(ids) == len(set(ids))
    for cid in ids:
        assert cid == cid.upper()


def test_filter_by_category() -> None:
    dnssec = REGISTRY.by_category("dnssec")
    assert len(dnssec) >= 18
    assert all(c.category == "dnssec" for c in dnssec)


def test_filter_only_and_skip() -> None:
    items = REGISTRY.filter(only=["BASIC01", "BASIC02"])
    assert {c.id for c in items} == {"BASIC01", "BASIC02"}
    items = REGISTRY.filter(only=["dnssec"], skip=["DNSSEC01"])
    ids = {c.id for c in items}
    assert "DNSSEC01" not in ids
    assert "DNSSEC02" in ids


def test_explain_lookup() -> None:
    spec = REGISTRY.by_id("delegation01")
    assert spec is not None
    assert spec.category == "delegation"
    assert "name server" in spec.name.lower()
