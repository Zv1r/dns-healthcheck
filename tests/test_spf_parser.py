"""Unit tests for the SPF lookup-counter used by EMAIL02."""

from __future__ import annotations

import pytest

import dns_healthcheck.checks.email as email_mod


@pytest.fixture
def fake_txt(monkeypatch):
    """Patch _txt_records so we don't hit the real DNS."""
    table: dict[str, list[str]] = {}

    async def fake(_ctx, name: str) -> list[str]:
        return table.get(name.lower(), [])

    monkeypatch.setattr(email_mod, "_txt_records", fake)
    return table


@pytest.mark.asyncio
async def test_simple_spf_no_lookups(fake_txt) -> None:
    spf = "v=spf1 ip4:1.2.3.4 -all"
    assert await email_mod._spf_lookup_count(None, "x.com", spf, depth=0) == 0


@pytest.mark.asyncio
async def test_spf_a_mx_count_one_each(fake_txt) -> None:
    spf = "v=spf1 a mx -all"
    assert await email_mod._spf_lookup_count(None, "x.com", spf, depth=0) == 2


@pytest.mark.asyncio
async def test_spf_include_recurses(fake_txt) -> None:
    fake_txt["partner.example"] = ["v=spf1 ip4:1.1.1.1 a mx -all"]
    spf = "v=spf1 include:partner.example -all"
    # 1 for include, +2 (a, mx) inside partner.example = 3
    assert await email_mod._spf_lookup_count(None, "x.com", spf, depth=0) == 3


@pytest.mark.asyncio
async def test_spf_redirect_counts(fake_txt) -> None:
    fake_txt["other.example"] = ["v=spf1 a -all"]
    spf = "v=spf1 redirect=other.example"
    assert await email_mod._spf_lookup_count(None, "x.com", spf, depth=0) == 2
