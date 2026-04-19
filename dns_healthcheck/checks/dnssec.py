"""DNSSEC checks: chain-of-trust, key strength, signature freshness, NSEC/NSEC3."""

from __future__ import annotations

import time

import dns.dnssec
import dns.flags
import dns.name
import dns.rdataclass
import dns.rdatatype

from dns_healthcheck.context import CheckContext
from dns_healthcheck.registry import register
from dns_healthcheck.result import Finding, Severity

CATEGORY = "dnssec"

ALG_NAMES = {
    1: "RSAMD5",
    3: "DSA",
    5: "RSASHA1",
    6: "DSA-NSEC3-SHA1",
    7: "RSASHA1-NSEC3-SHA1",
    8: "RSASHA256",
    10: "RSASHA512",
    13: "ECDSAP256SHA256",
    14: "ECDSAP384SHA384",
    15: "ED25519",
    16: "ED448",
}

WEAK_ALGS = {1, 3, 5, 6, 7}
DEPRECATED_DS_DIGESTS = {1}  # SHA-1


def _parse_ds_records(ctx: CheckContext) -> list[tuple[int, int, int, str]]:
    out: list[tuple[int, int, int, str]] = []
    for ds in ctx.zone.ds_records:
        parts = ds.split(maxsplit=3)
        if len(parts) >= 4:
            try:
                key_tag = int(parts[0])
                alg = int(parts[1])
                digest_type = int(parts[2])
                digest = parts[3]
                out.append((key_tag, alg, digest_type, digest))
            except ValueError:
                continue
    return out


def _parse_dnskey_records(ctx: CheckContext) -> list[tuple[int, int, int, str]]:
    out: list[tuple[int, int, int, str]] = []
    for k in ctx.zone.dnskey_records:
        parts = k.split(maxsplit=3)
        if len(parts) >= 4:
            try:
                flags = int(parts[0])
                proto = int(parts[1])
                alg = int(parts[2])
                key = parts[3]
                out.append((flags, proto, alg, key))
            except ValueError:
                continue
    return out


@register(
    id="DNSSEC01",
    category=CATEGORY,
    name="Zone is DNSSEC-signed (DS at parent + DNSKEY at apex)",
    default_severity=Severity.NOTICE,
)
async def dnssec01(ctx: CheckContext) -> list[Finding]:
    if not ctx.zone.has_dnssec:
        return [
            Finding(
                "DNSSEC01",
                Severity.NOTICE,
                f"Zone {ctx.domain} is not DNSSEC-signed (no DS at parent)",
                {},
            )
        ]
    if not ctx.zone.dnskey_records:
        return [
            Finding(
                "DNSSEC01",
                Severity.ERROR,
                f"Parent has DS for {ctx.domain} but apex returns no DNSKEY",
                {},
            )
        ]
    return []


@register(
    id="DNSSEC02",
    category=CATEGORY,
    name="DS digest type is not SHA-1",
    default_severity=Severity.WARNING,
    requires_dnssec=True,
)
async def dnssec02(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for tag, _alg, digest_type, _ in _parse_ds_records(ctx):
        if digest_type in DEPRECATED_DS_DIGESTS:
            findings.append(
                Finding(
                    "DNSSEC02",
                    Severity.WARNING,
                    f"DS for key tag {tag} uses deprecated digest type {digest_type} (SHA-1)",
                    {"key_tag": tag, "digest_type": digest_type},
                )
            )
    return findings


@register(
    id="DNSSEC03",
    category=CATEGORY,
    name="DNSKEY algorithm is not weak",
    default_severity=Severity.WARNING,
    requires_dnssec=True,
)
async def dnssec03(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for flags, _, alg, _ in _parse_dnskey_records(ctx):
        if alg in WEAK_ALGS:
            findings.append(
                Finding(
                    "DNSSEC03",
                    Severity.WARNING,
                    f"DNSKEY uses weak algorithm {alg} ({ALG_NAMES.get(alg, '?')})",
                    {"alg": alg, "alg_name": ALG_NAMES.get(alg, str(alg)), "flags": flags},
                )
            )
    return findings


@register(
    id="DNSSEC04",
    category=CATEGORY,
    name="DNSKEY RRset has at least one KSK (flags 257) and one ZSK (flags 256)",
    default_severity=Severity.NOTICE,
    requires_dnssec=True,
)
async def dnssec04(ctx: CheckContext) -> list[Finding]:
    keys = _parse_dnskey_records(ctx)
    has_ksk = any(f == 257 for f, _, _, _ in keys)
    has_zsk = any(f == 256 for f, _, _, _ in keys)
    findings: list[Finding] = []
    if not has_ksk:
        findings.append(Finding("DNSSEC04", Severity.NOTICE, "No KSK (flags=257) in DNSKEY RRset", {}))
    if not has_zsk:
        findings.append(Finding("DNSSEC04", Severity.NOTICE, "No separate ZSK (flags=256) in DNSKEY RRset", {}))
    return findings


@register(
    id="DNSSEC05",
    category=CATEGORY,
    name="RSA DNSKEYs use a key size >= 2048 bits",
    description="RSA keys < 2048 bits are no longer considered safe.",
    default_severity=Severity.WARNING,
    requires_dnssec=True,
)
async def dnssec05(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for addr in ctx.authoritative_servers()[:1]:
        r = await ctx.resolver.query_at(ctx.domain, "DNSKEY", addr, want_dnssec=True)
        if r.response is None:
            continue
        for rrset in r.response.answer:
            if rrset.rdtype != dns.rdatatype.DNSKEY:
                continue
            for rd in rrset:
                if rd.algorithm not in (5, 7, 8, 10):
                    continue
                key_size = _rsa_key_size(rd.key)
                if key_size and key_size < 2048:
                    findings.append(
                        Finding(
                            "DNSSEC05",
                            Severity.WARNING,
                            f"RSA DNSKEY (alg={rd.algorithm}) key size {key_size} bits < 2048",
                            {"alg": rd.algorithm, "size_bits": key_size},
                        )
                    )
        break
    return findings


def _rsa_key_size(key: bytes) -> int | None:
    try:
        if not key:
            return None
        if key[0] == 0:
            elen = int.from_bytes(key[1:3], "big")
            offset = 3
        else:
            elen = key[0]
            offset = 1
        modulus = key[offset + elen :]
        return len(modulus) * 8
    except Exception:
        return None


@register(
    id="DNSSEC06",
    category=CATEGORY,
    name="DNSKEY RRset is signed",
    default_severity=Severity.ERROR,
    requires_dnssec=True,
)
async def dnssec06(ctx: CheckContext) -> list[Finding]:
    for addr in ctx.authoritative_servers()[:2]:
        r = await ctx.resolver.query_at(ctx.domain, "DNSKEY", addr, want_dnssec=True)
        if r.response is None:
            continue
        if any(rrset.rdtype == dns.rdatatype.RRSIG for rrset in r.response.answer):
            return []
    return [
        Finding(
            "DNSSEC06",
            Severity.ERROR,
            "DNSKEY RRset returns no RRSIG",
            {},
        )
    ]


@register(
    id="DNSSEC07",
    category=CATEGORY,
    name="SOA RRset is signed",
    default_severity=Severity.ERROR,
    requires_dnssec=True,
)
async def dnssec07(ctx: CheckContext) -> list[Finding]:
    for addr in ctx.authoritative_servers()[:2]:
        r = await ctx.resolver.query_at(ctx.domain, "SOA", addr, want_dnssec=True)
        if r.response is None:
            continue
        if any(rrset.rdtype == dns.rdatatype.RRSIG for rrset in r.response.answer):
            return []
    return [
        Finding(
            "DNSSEC07",
            Severity.ERROR,
            "SOA RRset returns no RRSIG",
            {},
        )
    ]


@register(
    id="DNSSEC08",
    category=CATEGORY,
    name="RRSIG inception is in the past and not too old",
    default_severity=Severity.WARNING,
    requires_dnssec=True,
)
async def dnssec08(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    now = time.time()
    for addr in ctx.authoritative_servers()[:1]:
        r = await ctx.resolver.query_at(ctx.domain, "SOA", addr, want_dnssec=True)
        if r.response is None:
            continue
        for rrset in r.response.answer:
            if rrset.rdtype != dns.rdatatype.RRSIG:
                continue
            for rd in rrset:
                if rd.inception > now:
                    findings.append(
                        Finding(
                            "DNSSEC08",
                            Severity.ERROR,
                            f"RRSIG (key tag {rd.key_tag}) inception {rd.inception} is in the future",
                            {"key_tag": rd.key_tag, "inception": rd.inception},
                        )
                    )
        break
    return findings


@register(
    id="DNSSEC09",
    category=CATEGORY,
    name="RRSIG expiration is in the future and not too close",
    description="Warn if RRSIG expires in less than 7 days.",
    default_severity=Severity.WARNING,
    requires_dnssec=True,
)
async def dnssec09(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    now = time.time()
    for addr in ctx.authoritative_servers()[:1]:
        r = await ctx.resolver.query_at(ctx.domain, "SOA", addr, want_dnssec=True)
        if r.response is None:
            continue
        for rrset in r.response.answer:
            if rrset.rdtype != dns.rdatatype.RRSIG:
                continue
            for rd in rrset:
                remaining = rd.expiration - now
                if remaining < 0:
                    findings.append(
                        Finding(
                            "DNSSEC09",
                            Severity.CRITICAL,
                            f"RRSIG (key tag {rd.key_tag}) is expired",
                            {"key_tag": rd.key_tag, "expiration": rd.expiration},
                        )
                    )
                elif remaining < 7 * 86400:
                    findings.append(
                        Finding(
                            "DNSSEC09",
                            Severity.WARNING,
                            f"RRSIG (key tag {rd.key_tag}) expires in {remaining / 86400:.1f} days",
                            {"key_tag": rd.key_tag, "remaining_seconds": remaining},
                        )
                    )
        break
    return findings


@register(
    id="DNSSEC10",
    category=CATEGORY,
    name="Authenticated denial of existence (NSEC or NSEC3) works",
    default_severity=Severity.WARNING,
    requires_dnssec=True,
)
async def dnssec10(ctx: CheckContext) -> list[Finding]:
    fake = f"nsec-probe-{abs(hash(ctx.domain)) % 10**6}.{ctx.domain}"
    for addr in ctx.authoritative_servers()[:2]:
        r = await ctx.resolver.query_at(fake, "A", addr, want_dnssec=True)
        if r.response is None:
            continue
        has_nsec = any(rrset.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3) for rrset in r.response.authority)
        if has_nsec:
            return []
    return [
        Finding(
            "DNSSEC10",
            Severity.WARNING,
            "Negative response carries no NSEC/NSEC3 — denial of existence is unsigned",
            {},
        )
    ]


@register(
    id="DNSSEC11",
    category=CATEGORY,
    name="DNSKEY published for every algorithm referenced by DS",
    default_severity=Severity.ERROR,
    requires_dnssec=True,
)
async def dnssec11(ctx: CheckContext) -> list[Finding]:
    ds_algs = {a for _, a, _, _ in _parse_ds_records(ctx)}
    key_algs = {a for _, _, a, _ in _parse_dnskey_records(ctx)}
    missing = ds_algs - key_algs
    if missing:
        return [
            Finding(
                "DNSSEC11",
                Severity.ERROR,
                f"DS references algorithms {sorted(missing)} not present in DNSKEY",
                {"ds_algs": sorted(ds_algs), "dnskey_algs": sorted(key_algs)},
            )
        ]
    return []


@register(
    id="DNSSEC12",
    category=CATEGORY,
    name="Each DS record's key tag matches a published DNSKEY",
    default_severity=Severity.ERROR,
    requires_dnssec=True,
)
async def dnssec12(ctx: CheckContext) -> list[Finding]:
    ds_tags = {t for t, _, _, _ in _parse_ds_records(ctx)}
    dnskey_tags: set[int] = set()
    for addr in ctx.authoritative_servers()[:1]:
        r = await ctx.resolver.query_at(ctx.domain, "DNSKEY", addr, want_dnssec=True)
        if r.response is None:
            continue
        for rrset in r.response.answer:
            if rrset.rdtype != dns.rdatatype.DNSKEY:
                continue
            for rd in rrset:
                dnskey_tags.add(dns.dnssec.key_id(rd))
        break
    missing = ds_tags - dnskey_tags
    if missing:
        return [
            Finding(
                "DNSSEC12",
                Severity.ERROR,
                f"DS key tags {sorted(missing)} are not present in DNSKEY",
                {"ds_tags": sorted(ds_tags), "dnskey_tags": sorted(dnskey_tags)},
            )
        ]
    return []


@register(
    id="DNSSEC13",
    category=CATEGORY,
    name="Every DNSKEY algorithm has at least one signing RRSIG",
    default_severity=Severity.ERROR,
    requires_dnssec=True,
)
async def dnssec13(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for addr in ctx.authoritative_servers()[:1]:
        r = await ctx.resolver.query_at(ctx.domain, "SOA", addr, want_dnssec=True)
        if r.response is None:
            continue
        rrsig_algs = {
            rd.algorithm for rrset in r.response.answer if rrset.rdtype == dns.rdatatype.RRSIG for rd in rrset
        }
        dnskey_algs = {a for _, _, a, _ in _parse_dnskey_records(ctx)}
        missing = dnskey_algs - rrsig_algs
        if missing:
            findings.append(
                Finding(
                    "DNSSEC13",
                    Severity.ERROR,
                    f"DNSKEY algorithms {sorted(missing)} have no RRSIG on SOA",
                    {"missing": sorted(missing)},
                )
            )
        break
    return findings


@register(
    id="DNSSEC14",
    category=CATEGORY,
    name="NSEC3 iteration count is reasonable",
    description="RFC 9276 recommends iterations = 0; iterations > 50 are a denial-of-service risk.",
    default_severity=Severity.WARNING,
    requires_dnssec=True,
)
async def dnssec14(ctx: CheckContext) -> list[Finding]:
    for addr in ctx.authoritative_servers()[:1]:
        fake = f"nsec3-probe-{abs(hash(ctx.domain)) % 10**6}.{ctx.domain}"
        r = await ctx.resolver.query_at(fake, "A", addr, want_dnssec=True)
        if r.response is None:
            continue
        for rrset in r.response.authority:
            if rrset.rdtype == dns.rdatatype.NSEC3:
                for rd in rrset:
                    if rd.iterations > 50:
                        return [
                            Finding(
                                "DNSSEC14",
                                Severity.WARNING,
                                f"NSEC3 iterations={rd.iterations} > 50 (RFC 9276)",
                                {"iterations": rd.iterations},
                            )
                        ]
                    if rd.iterations > 0:
                        return [
                            Finding(
                                "DNSSEC14",
                                Severity.NOTICE,
                                f"NSEC3 iterations={rd.iterations}; RFC 9276 recommends 0",
                                {"iterations": rd.iterations},
                            )
                        ]
        break
    return []


@register(
    id="DNSSEC15",
    category=CATEGORY,
    name="Zone publishes CDS or CDNSKEY for automated DS rollover (RFC 7344)",
    default_severity=Severity.INFO,
    requires_dnssec=True,
)
async def dnssec15(ctx: CheckContext) -> list[Finding]:
    has_cds = False
    has_cdnskey = False
    for addr in ctx.authoritative_servers()[:1]:
        r1 = await ctx.resolver.query_at(ctx.domain, "CDS", addr)
        r2 = await ctx.resolver.query_at(ctx.domain, "CDNSKEY", addr)
        has_cds = bool(r1.answer)
        has_cdnskey = bool(r2.answer)
        break
    if not has_cds and not has_cdnskey:
        return [
            Finding(
                "DNSSEC15",
                Severity.INFO,
                "No CDS/CDNSKEY published — automated DS rollover unavailable",
                {},
            )
        ]
    return []


@register(
    id="DNSSEC16",
    category=CATEGORY,
    name="CDS digest type is not SHA-1",
    default_severity=Severity.WARNING,
    requires_dnssec=True,
)
async def dnssec16(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for addr in ctx.authoritative_servers()[:1]:
        r = await ctx.resolver.query_at(ctx.domain, "CDS", addr)
        if r.response is None:
            continue
        for rrset in r.response.answer:
            if rrset.rdtype != dns.rdatatype.CDS:
                continue
            for rd in rrset:
                if rd.digest_type == 1:
                    findings.append(
                        Finding(
                            "DNSSEC16",
                            Severity.WARNING,
                            f"CDS for key tag {rd.key_tag} uses SHA-1 digest type",
                            {"key_tag": rd.key_tag},
                        )
                    )
        break
    return findings


@register(
    id="DNSSEC17",
    category=CATEGORY,
    name="DNSKEY TTL is consistent across the RRset",
    default_severity=Severity.NOTICE,
    requires_dnssec=True,
)
async def dnssec17(ctx: CheckContext) -> list[Finding]:
    ttls: set[int] = set()
    for addr in ctx.authoritative_servers()[:1]:
        r = await ctx.resolver.query_at(ctx.domain, "DNSKEY", addr)
        if r.response is None:
            continue
        for rrset in r.response.answer:
            if rrset.rdtype == dns.rdatatype.DNSKEY:
                ttls.add(rrset.ttl)
        break
    if len(ttls) > 1:
        return [
            Finding(
                "DNSSEC17",
                Severity.NOTICE,
                f"Multiple TTL values seen on DNSKEY RRset: {sorted(ttls)}",
                {"ttls": sorted(ttls)},
            )
        ]
    return []


@register(
    id="DNSSEC18",
    category=CATEGORY,
    name="DNSKEY signature validates against published key",
    default_severity=Severity.ERROR,
    requires_dnssec=True,
)
async def dnssec18(ctx: CheckContext) -> list[Finding]:
    for addr in ctx.authoritative_servers()[:1]:
        r = await ctx.resolver.query_at(ctx.domain, "DNSKEY", addr, want_dnssec=True)
        if r.response is None:
            continue
        dnskey_rrset = None
        rrsig_rrset = None
        for rrset in r.response.answer:
            if rrset.rdtype == dns.rdatatype.DNSKEY:
                dnskey_rrset = rrset
            elif rrset.rdtype == dns.rdatatype.RRSIG:
                rrsig_rrset = rrset
        if not dnskey_rrset or not rrsig_rrset:
            return []
        try:
            dns.dnssec.validate(dnskey_rrset, rrsig_rrset, {dns.name.from_text(ctx.domain): dnskey_rrset})
            return []
        except dns.dnssec.ValidationFailure as e:
            return [
                Finding(
                    "DNSSEC18",
                    Severity.ERROR,
                    f"DNSKEY self-signature invalid: {e}",
                    {"error": str(e)},
                )
            ]
        except Exception as e:
            return [
                Finding(
                    "DNSSEC18",
                    Severity.NOTICE,
                    f"Could not validate DNSKEY signature: {e}",
                    {"error": str(e)},
                )
            ]
    return []


@register(
    id="DNSSEC19",
    category=CATEGORY,
    name="NSEC3 salt is empty (RFC 9276 §3.1)",
    description=(
        "RFC 9276 §3.1: NSEC3 records SHOULD use an empty salt field. Salts add "
        "no real security and increase signing cost; modern resolvers expect '-'."
    ),
    default_severity=Severity.NOTICE,
    requires_dnssec=True,
)
async def dnssec19(ctx: CheckContext) -> list[Finding]:
    fake = f"nsec3-salt-probe-{abs(hash(ctx.domain)) % 10**6}.{ctx.domain}"
    for addr in ctx.authoritative_servers()[:1]:
        r = await ctx.resolver.query_at(fake, "A", addr, want_dnssec=True)
        if r.response is None:
            continue
        for rrset in r.response.authority:
            if rrset.rdtype == dns.rdatatype.NSEC3:
                for rd in rrset:
                    if rd.salt:
                        return [
                            Finding(
                                "DNSSEC19",
                                Severity.NOTICE,
                                f"NSEC3 uses non-empty salt ({rd.salt.hex()}); RFC 9276 recommends empty",
                                {"salt_hex": rd.salt.hex()},
                            )
                        ]
                return []
        return []
    return []
