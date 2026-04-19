"""Async DNS resolver wrapper around dnspython with per-run caching."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import dns.asyncquery
import dns.asyncresolver
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver

from dns_healthcheck.data import root_hints

DEFAULT_TIMEOUT = 5.0
DEFAULT_LIFETIME = 10.0


@dataclass
class QueryResult:
    """Outcome of a DNS query against a specific server (or stub resolver)."""

    qname: str
    qtype: str
    server: str | None
    rcode: int
    answer: list[str] = field(default_factory=list)
    authority: list[str] = field(default_factory=list)
    additional: list[str] = field(default_factory=list)
    flags: int = 0
    rrsigs: bool = False
    error: str | None = None
    response: dns.message.Message | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.rcode == 0


class AsyncResolver:
    """Async DNS resolver supporting both stub and direct (server-targeted) queries.

    Maintains a per-instance cache so the same (qname, qtype, server) tuple is only
    asked once during a single audit run.
    """

    def __init__(
        self,
        nameservers: list[str] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        lifetime: float = DEFAULT_LIFETIME,
        use_ipv6: bool = True,
        use_tcp: bool = False,
    ) -> None:
        self.timeout = timeout
        self.lifetime = lifetime
        self.use_ipv6 = use_ipv6
        self.use_tcp = use_tcp
        self._cache: dict[tuple[str, str, str | None, bool], QueryResult] = {}
        self._lock = asyncio.Lock()

        self._stub = dns.asyncresolver.Resolver(configure=False)
        self._stub.timeout = timeout
        self._stub.lifetime = lifetime
        self._stub.nameservers = nameservers or ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    async def query_stub(self, qname: str, qtype: str = "A", want_dnssec: bool = False) -> QueryResult:
        """Query via the configured stub resolver."""
        key = (qname.lower().rstrip("."), qtype.upper(), None, want_dnssec)
        if key in self._cache:
            return self._cache[key]

        result = QueryResult(qname=qname, qtype=qtype, server=None, rcode=-1)
        try:
            answer = await self._stub.resolve(
                qname,
                qtype,
                raise_on_no_answer=False,
            )
            response = answer.response
            result.response = response
            result.rcode = response.rcode()
            result.flags = response.flags
            result.answer = [r.to_text() for r in response.answer for r in r]
            result.authority = [r.to_text() for r in response.authority for r in r]
            result.additional = [r.to_text() for r in response.additional for r in r]
            result.rrsigs = any(rrset.rdtype == dns.rdatatype.RRSIG for rrset in response.answer)
        except dns.resolver.NXDOMAIN:
            result.rcode = dns.rcode.NXDOMAIN
        except dns.resolver.NoAnswer:
            result.rcode = 0
        except (dns.resolver.NoNameservers, dns.exception.Timeout, OSError) as e:
            result.error = f"{type(e).__name__}: {e}"
        except Exception as e:
            result.error = f"{type(e).__name__}: {e}"

        self._cache[key] = result
        return result

    async def query_at(
        self,
        qname: str,
        qtype: str,
        server: str,
        want_dnssec: bool = False,
        use_tcp: bool | None = None,
    ) -> QueryResult:
        """Send a single query directly to ``server``."""
        key = (qname.lower().rstrip("."), qtype.upper(), server, want_dnssec)
        if key in self._cache:
            return self._cache[key]

        result = QueryResult(qname=qname, qtype=qtype, server=server, rcode=-1)
        try:
            qname_obj = dns.name.from_text(qname)
            rdtype = dns.rdatatype.from_text(qtype)
            request = dns.message.make_query(
                qname_obj,
                rdtype,
                want_dnssec=want_dnssec,
                use_edns=0 if want_dnssec else None,
            )
            tcp = use_tcp if use_tcp is not None else self.use_tcp
            if tcp:
                response = await dns.asyncquery.tcp(request, server, timeout=self.timeout)
            else:
                response = await dns.asyncquery.udp(request, server, timeout=self.timeout, ignore_unexpected=True)
                if response.flags & dns.flags.TC:
                    response = await dns.asyncquery.tcp(request, server, timeout=self.timeout)
            result.response = response
            result.rcode = response.rcode()
            result.flags = response.flags
            result.answer = [str(r) for rrset in response.answer for r in rrset]
            result.authority = [str(r) for rrset in response.authority for r in rrset]
            result.additional = [str(r) for rrset in response.additional for r in rrset]
            result.rrsigs = any(rrset.rdtype == dns.rdatatype.RRSIG for rrset in response.answer)
        except (dns.exception.Timeout, OSError) as e:
            result.error = f"{type(e).__name__}: {e}"
        except Exception as e:
            result.error = f"{type(e).__name__}: {e}"

        self._cache[key] = result
        return result

    async def query_many(
        self,
        qname: str,
        qtype: str,
        servers: list[str],
        want_dnssec: bool = False,
        concurrency: int = 16,
    ) -> dict[str, QueryResult]:
        """Query the same (qname, qtype) at many servers concurrently."""
        sem = asyncio.Semaphore(concurrency)

        async def one(s: str) -> tuple[str, QueryResult]:
            async with sem:
                return s, await self.query_at(qname, qtype, s, want_dnssec=want_dnssec)

        results = await asyncio.gather(*(one(s) for s in servers))
        return dict(results)

    async def resolve_addresses(self, hostname: str) -> list[str]:
        """Resolve A and AAAA addresses for a hostname via the stub resolver."""
        addrs: list[str] = []
        for qtype in ("A", "AAAA") if self.use_ipv6 else ("A",):
            try:
                ans = await self._stub.resolve(hostname, qtype, raise_on_no_answer=False)
                for rrset in ans.response.answer:
                    if rrset.rdtype == dns.rdatatype.from_text(qtype):
                        for r in rrset:
                            addrs.append(r.to_text())
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except (dns.resolver.NoNameservers, dns.exception.Timeout, OSError):
                continue
        return addrs

    def root_servers(self) -> list[str]:
        return root_hints.ROOT_IPV4 + (root_hints.ROOT_IPV6 if self.use_ipv6 else [])


def parse_rdata(text: str) -> dict[str, Any]:
    """Best-effort parse of a single rdata text representation."""
    parts = text.split()
    return {"raw": text, "fields": parts}
