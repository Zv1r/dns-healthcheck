"""CheckContext: shared state passed to every check during a run.

Holds the target zone, the resolver, and a lazily-populated set of facts about the
zone (parent NS, child NS, glue, SOA, DS, DNSKEY) so that individual checks don't
re-do upstream resolution work.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import dns.name
import dns.rdatatype

from dns_healthcheck.resolver import AsyncResolver


@dataclass
class NameServer:
    """Resolved name server, with one or more IP addresses."""

    name: str
    addresses: list[str] = field(default_factory=list)
    glue_addresses: list[str] = field(default_factory=list)
    in_bailiwick: bool = False

    def all_addresses(self) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for a in self.glue_addresses + self.addresses:
            if a not in seen:
                seen.add(a)
                out.append(a)
        return out


@dataclass
class Zone:
    """Snapshot of a zone's delegation and authoritative data."""

    name: str
    parent: str
    parent_ns: list[NameServer] = field(default_factory=list)  # delegation NS for the zone
    child_ns: list[NameServer] = field(default_factory=list)  # NS at zone apex
    # IPs of the *parent zone's* own authoritative servers (e.g. the .ua TLD servers
    # for rv.ua). DS records live in the parent zone and MUST be queried here, not
    # at parent_ns (which holds the child zone's authoritative servers).
    parent_zone_ns_addresses: list[str] = field(default_factory=list)
    soa: dict[str, Any] | None = None
    ds_records: list[str] = field(default_factory=list)
    dnskey_records: list[str] = field(default_factory=list)
    has_dnssec: bool = False


class CheckContext:
    """Per-run context. Methods below memoize their results."""

    def __init__(
        self,
        domain: str,
        resolver: AsyncResolver,
        profile: str = "default",
        public_resolvers: dict[str, list[str]] | None = None,
    ) -> None:
        self.domain = domain.rstrip(".").lower()
        self.resolver = resolver
        self.profile = profile
        self.public_resolvers = public_resolvers or {}
        self.zone = Zone(name=self.domain, parent=self._parent_of(self.domain))
        self._lock = asyncio.Lock()
        self._initialized = False
        self._cache: dict[str, Any] = {}

    @staticmethod
    def _parent_of(domain: str) -> str:
        if "." not in domain:
            return ""
        return domain.split(".", 1)[1]

    async def initialize(self) -> None:
        """Resolve delegation, parent NS, child NS, glue, SOA, DS, DNSKEY."""
        async with self._lock:
            if self._initialized:
                return
            await self._discover_parent_ns()
            await self._discover_child_ns()
            await self._discover_soa()
            await self._discover_dnssec()
            self._initialized = True

    async def _discover_parent_ns(self) -> None:
        """Walk from root to find the delegation NS records and any glue.

        For TLDs (single-label domains like "ua") the iterative walk has just one
        step — query NS for "ua." at the root servers. The previous early-return
        on `parent == ""` skipped this and left the whole zone state empty,
        which silently broke every NS-iterating check.
        """
        if not self.domain:
            return

        servers = list(self.resolver.root_servers())
        labels: list[str] = []
        for label in reversed(self.domain.split(".")):
            labels.insert(0, label)
            qname = ".".join(labels) + "."
            ns_set: set[str] = set()
            glue: dict[str, list[str]] = {}
            new_servers: set[str] = set()
            for srv in servers[:6]:
                r = await self.resolver.query_at(qname, "NS", srv)
                if r.error:
                    continue
                if r.response is None:
                    continue
                for rrset in r.response.authority:
                    if rrset.rdtype == dns.rdatatype.NS:
                        for rd in rrset:
                            ns_name = rd.to_text().rstrip(".").lower()
                            ns_set.add(ns_name)
                for rrset in r.response.additional:
                    if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                        ns_name = rrset.name.to_text().rstrip(".").lower()
                        glue.setdefault(ns_name, []).extend(rd.to_text() for rd in rrset)
                for rrset in r.response.answer:
                    if rrset.rdtype == dns.rdatatype.NS:
                        for rd in rrset:
                            ns_name = rd.to_text().rstrip(".").lower()
                            ns_set.add(ns_name)
                for ns in ns_set:
                    new_servers.update(glue.get(ns, []))
                if ns_set:
                    break
            if not ns_set:
                break
            if qname.rstrip(".") == self.domain:
                # `servers` here holds the IPs of the parent zone's nameservers — the
                # ones that just gave us the referral. Capture them so DNSSEC discovery
                # can ask them for DS records (which only the parent zone serves).
                self.zone.parent_zone_ns_addresses = list(servers)
                ns_objs: list[NameServer] = []
                for n in sorted(ns_set):
                    addrs = glue.get(n, [])
                    if not addrs:
                        addrs = await self.resolver.resolve_addresses(n)
                    ns_objs.append(
                        NameServer(
                            name=n,
                            addresses=[a for a in addrs if not glue.get(n)],
                            glue_addresses=glue.get(n, []),
                            in_bailiwick=n.endswith("." + self.domain) or n == self.domain,
                        )
                    )
                self.zone.parent_ns = ns_objs
                break
            if not new_servers:
                resolved: list[str] = []
                for n in ns_set:
                    resolved.extend(await self.resolver.resolve_addresses(n))
                new_servers.update(resolved)
            if not new_servers:
                break
            servers = list(new_servers)

    async def _discover_child_ns(self) -> None:
        """Ask each delegation NS for the apex NS RRset (the 'child' view)."""
        if not self.zone.parent_ns:
            return
        seen: dict[str, NameServer] = {}
        for ns in self.zone.parent_ns:
            for addr in ns.all_addresses():
                r = await self.resolver.query_at(self.domain, "NS", addr)
                if r.error or r.response is None:
                    continue
                for rrset in r.response.answer:
                    if rrset.rdtype == dns.rdatatype.NS:
                        for rd in rrset:
                            name = rd.to_text().rstrip(".").lower()
                            if name not in seen:
                                addrs = await self.resolver.resolve_addresses(name)
                                seen[name] = NameServer(
                                    name=name,
                                    addresses=addrs,
                                    in_bailiwick=name.endswith("." + self.domain) or name == self.domain,
                                )
                if seen:
                    break
            if seen:
                break
        self.zone.child_ns = list(seen.values())

    async def _discover_soa(self) -> None:
        for ns in self.authoritative_servers():
            r = await self.resolver.query_at(self.domain, "SOA", ns)
            if r.error or r.response is None:
                continue
            for rrset in r.response.answer:
                if rrset.rdtype == dns.rdatatype.SOA:
                    rd = next(iter(rrset))
                    self.zone.soa = {
                        "mname": rd.mname.to_text().rstrip(".").lower(),
                        "rname": rd.rname.to_text().rstrip(".").lower(),
                        "serial": rd.serial,
                        "refresh": rd.refresh,
                        "retry": rd.retry,
                        "expire": rd.expire,
                        "minimum": rd.minimum,
                        "source_ns": ns,
                    }
                    return

    async def _discover_dnssec(self) -> None:
        # DS lives only in the parent zone — query the parent zone's nameservers
        # (captured during the iterative walk), not the child zone's.
        await self._collect_ds_records()

        if self.zone.has_dnssec:
            # DNSKEY lives at the child apex — query authoritative child servers.
            for srv in self.authoritative_servers():
                r = await self.resolver.query_at(self.domain, "DNSKEY", srv, want_dnssec=True)
                if r.error or r.response is None:
                    continue
                for rrset in r.response.answer:
                    if rrset.rdtype == dns.rdatatype.DNSKEY:
                        for rd in rrset:
                            self.zone.dnskey_records.append(rd.to_text())
                if self.zone.dnskey_records:
                    break

    async def _collect_ds_records(self) -> None:
        """Populate zone.ds_records / zone.has_dnssec by asking the parent zone."""
        for addr in self.zone.parent_zone_ns_addresses:
            r = await self.resolver.query_at(self.domain, "DS", addr, want_dnssec=True)
            if r.error or r.response is None:
                continue
            for rrset in r.response.answer:
                if rrset.rdtype == dns.rdatatype.DS:
                    for rd in rrset:
                        self.zone.ds_records.append(rd.to_text())
            if self.zone.ds_records:
                self.zone.has_dnssec = True
                return

        # Fallback: parent NS were unreachable (or zone is a TLD with parent==root).
        # Ask the configured stub resolver, which walks the chain itself.
        r = await self.resolver.query_stub(self.domain, "DS", want_dnssec=True)
        if r.response is not None:
            for rrset in r.response.answer:
                if rrset.rdtype == dns.rdatatype.DS:
                    for rd in rrset:
                        self.zone.ds_records.append(rd.to_text())
            if self.zone.ds_records:
                self.zone.has_dnssec = True

    def authoritative_servers(self) -> list[str]:
        """All authoritative server IPs we know about (parent glue + child resolution)."""
        seen: set[str] = set()
        out: list[str] = []
        for ns in self.zone.parent_ns + self.zone.child_ns:
            for addr in ns.all_addresses():
                if addr not in seen:
                    seen.add(addr)
                    out.append(addr)
        return out

    def authoritative_ns_names(self) -> list[str]:
        names: set[str] = set()
        for ns in self.zone.parent_ns + self.zone.child_ns:
            names.add(ns.name)
        return sorted(names)

    async def has_mx(self) -> bool:
        if "has_mx" not in self._cache:
            r = await self.resolver.query_stub(self.domain, "MX")
            self._cache["has_mx"] = bool(r.answer) and r.ok
        return bool(self._cache["has_mx"])

    async def get_mx(self) -> list[tuple[int, str]]:
        if "mx" in self._cache:
            return self._cache["mx"]
        r = await self.resolver.query_stub(self.domain, "MX")
        out: list[tuple[int, str]] = []
        if r.response is not None:
            for rrset in r.response.answer:
                if rrset.rdtype == dns.rdatatype.MX:
                    for rd in rrset:
                        out.append((rd.preference, rd.exchange.to_text().rstrip(".").lower()))
        self._cache["mx"] = out
        return out
