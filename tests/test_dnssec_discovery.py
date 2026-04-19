"""Regression tests for DS discovery (the rv.ua bug).

DS records live in the parent zone, not in the child zone. The discovery
code MUST query DS at the parent zone's nameservers (the IPs captured during
the iterative walk), not at the child zone's authoritative nameservers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock

import dns.rdatatype
import pytest

from dns_healthcheck.context import CheckContext, NameServer
from dns_healthcheck.resolver import QueryResult


@dataclass
class _Rdata:
    text: str

    def to_text(self) -> str:
        return self.text


@dataclass
class _RRset:
    rdtype: int
    rdatas: list[_Rdata] = field(default_factory=list)

    def __iter__(self):
        return iter(self.rdatas)


@dataclass
class _Response:
    answer: list[Any] = field(default_factory=list)


def _ds_response(*ds_texts: str) -> _Response:
    return _Response(answer=[_RRset(rdtype=dns.rdatatype.DS, rdatas=[_Rdata(t) for t in ds_texts])])


@pytest.mark.asyncio
async def test_collect_ds_uses_parent_zone_servers_not_child_servers() -> None:
    """When the parent zone holds a DS, _collect_ds_records must find it
    by querying the parent's NS IPs (NOT the child zone's NS IPs)."""
    parent_addr = "192.0.2.10"  # pretend .ua TLD server
    child_addr = "203.0.113.20"  # pretend rv.ua's own NS

    async def fake_query_at(qname, qtype, server, want_dnssec=False, use_tcp=None):
        if qtype == "DS" and server == parent_addr:
            return QueryResult(
                qname=qname,
                qtype=qtype,
                server=server,
                rcode=0,
                response=_ds_response("17154 13 2 abc123"),
            )
        return QueryResult(
            qname=qname,
            qtype=qtype,
            server=server,
            rcode=0,
            response=_Response(),
        )

    resolver = AsyncMock()
    resolver.query_at.side_effect = fake_query_at
    resolver.query_stub = AsyncMock(return_value=QueryResult(qname="", qtype="DS", server=None, rcode=0, response=None))

    ctx = CheckContext("rv.ua", resolver)
    ctx.zone.parent_zone_ns_addresses = [parent_addr]
    ctx.zone.parent_ns = [NameServer(name="ns1.rv.ua", addresses=[child_addr])]

    await ctx._collect_ds_records()

    assert ctx.zone.has_dnssec is True, "DS should be detected at parent zone NS"
    assert ctx.zone.ds_records == ["17154 13 2 abc123"]
    # Confirm the child NS was never queried for DS:
    asked_servers = {call.args[2] for call in resolver.query_at.call_args_list if call.args[1] == "DS"}
    assert child_addr not in asked_servers


@pytest.mark.asyncio
async def test_collect_ds_falls_back_to_stub_when_parent_unknown() -> None:
    """If parent zone NS were never captured (e.g. TLD audit), fall back
    to the stub resolver so we don't silently report 'not signed'."""
    resolver = AsyncMock()
    resolver.query_at = AsyncMock()
    resolver.query_stub = AsyncMock(
        return_value=QueryResult(
            qname="x",
            qtype="DS",
            server=None,
            rcode=0,
            response=_ds_response("1 8 2 deadbeef"),
        )
    )

    ctx = CheckContext("ua", resolver)
    # parent_zone_ns_addresses left empty on purpose
    await ctx._collect_ds_records()

    assert ctx.zone.has_dnssec is True
    assert ctx.zone.ds_records == ["1 8 2 deadbeef"]
    resolver.query_stub.assert_awaited_once()


@pytest.mark.asyncio
async def test_collect_ds_reports_unsigned_when_parent_returns_no_ds() -> None:
    """Genuinely unsigned zone: parent returns NOERROR with empty answer,
    stub fallback also empty, so has_dnssec stays False."""
    empty = _Response()
    resolver = AsyncMock()
    resolver.query_at = AsyncMock(
        return_value=QueryResult(qname="x", qtype="DS", server="1.2.3.4", rcode=0, response=empty)
    )
    resolver.query_stub = AsyncMock(
        return_value=QueryResult(qname="x", qtype="DS", server=None, rcode=0, response=empty)
    )

    ctx = CheckContext("unsigned.example", resolver)
    ctx.zone.parent_zone_ns_addresses = ["1.2.3.4"]
    await ctx._collect_ds_records()

    assert ctx.zone.has_dnssec is False
    assert ctx.zone.ds_records == []


def test_zone_dataclass_has_parent_zone_ns_addresses_field() -> None:
    """Public surface guarantee: the field name we capture in
    _discover_parent_ns must exist so check authors can rely on it."""
    from dns_healthcheck.context import Zone

    z = Zone(name="example.com", parent="com")
    assert hasattr(z, "parent_zone_ns_addresses")
    assert z.parent_zone_ns_addresses == []
