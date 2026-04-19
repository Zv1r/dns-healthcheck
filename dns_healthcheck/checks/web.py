"""Web/CDN posture: CAA, HTTPS redirect, HSTS, TLS certificate, OCSP."""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone

import dns.rdatatype
import httpx
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from dns_healthcheck.context import CheckContext
from dns_healthcheck.registry import register
from dns_healthcheck.result import Finding, Severity

CATEGORY = "web"


@register(
    id="WEB01",
    category=CATEGORY,
    name="CAA record present at apex with at least one issue clause",
    description="RFC 8659. CAA constrains which CAs may issue certs for the domain.",
    default_severity=Severity.NOTICE,
)
async def web01(ctx: CheckContext) -> list[Finding]:
    r = await ctx.resolver.query_stub(ctx.domain, "CAA")
    if r.response is None:
        return []
    issues: list[str] = []
    issuewild: list[str] = []
    for rrset in r.response.answer:
        if rrset.rdtype == dns.rdatatype.CAA:
            for rd in rrset:
                tag = rd.tag.decode()
                value = rd.value.decode()
                if tag == "issue":
                    issues.append(value)
                elif tag == "issuewild":
                    issuewild.append(value)
    if not issues:
        return [
            Finding(
                "WEB01",
                Severity.NOTICE,
                "No CAA record with 'issue' tag — any CA may issue certs for this domain",
                {},
            )
        ]
    return []


@register(
    id="WEB02",
    category=CATEGORY,
    name="HTTP redirects to HTTPS for apex and www",
    default_severity=Severity.WARNING,
)
async def web02(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for host in (ctx.domain, f"www.{ctx.domain}"):
        url = f"http://{host}/"
        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
                resp = await client.get(url)
        except Exception as e:
            findings.append(
                Finding(
                    "WEB02",
                    Severity.NOTICE,
                    f"HTTP probe to {url} failed: {e}",
                    {"host": host, "error": str(e)},
                )
            )
            continue
        if 300 <= resp.status_code < 400:
            loc = resp.headers.get("location", "")
            if not loc.lower().startswith("https://"):
                findings.append(
                    Finding(
                        "WEB02",
                        Severity.WARNING,
                        f"{url} redirects to non-HTTPS target {loc!r}",
                        {"host": host, "location": loc},
                    )
                )
        else:
            findings.append(
                Finding(
                    "WEB02",
                    Severity.WARNING,
                    f"{url} returned HTTP {resp.status_code}, expected 30x → HTTPS",
                    {"host": host, "status": resp.status_code},
                )
            )
    return findings


@register(
    id="WEB03",
    category=CATEGORY,
    name="HTTPS endpoint sets HSTS header with sufficient max-age",
    description="HSTS max-age >= 31536000 (1y) is required for preload.",
    default_severity=Severity.NOTICE,
)
async def web03(ctx: CheckContext) -> list[Finding]:
    url = f"https://{ctx.domain}/"
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, verify=True) as client:
            resp = await client.get(url)
    except Exception as e:
        return [
            Finding(
                "WEB03",
                Severity.NOTICE,
                f"HTTPS probe to {url} failed: {e}",
                {"error": str(e)},
            )
        ]
    sts = resp.headers.get("strict-transport-security", "").lower()
    if not sts:
        return [Finding("WEB03", Severity.NOTICE, "HTTPS response has no Strict-Transport-Security header", {})]
    import contextlib

    max_age = 0
    for token in (t.strip() for t in sts.split(";")):
        if token.startswith("max-age="):
            with contextlib.suppress(ValueError):
                max_age = int(token.split("=", 1)[1])
    if max_age < 31536000:
        return [
            Finding(
                "WEB03",
                Severity.NOTICE,
                f"HSTS max-age={max_age} is less than 1 year (31536000)",
                {"max_age": max_age, "header": sts},
            )
        ]
    return []


@register(
    id="WEB04",
    category=CATEGORY,
    name="HSTS preload eligibility (includeSubDomains + preload directives)",
    default_severity=Severity.INFO,
)
async def web04(ctx: CheckContext) -> list[Finding]:
    url = f"https://{ctx.domain}/"
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, verify=True) as client:
            resp = await client.get(url)
    except Exception:
        return []
    sts = resp.headers.get("strict-transport-security", "").lower()
    if not sts:
        return []
    findings: list[Finding] = []
    if "preload" not in sts:
        findings.append(Finding("WEB04", Severity.INFO, "HSTS header has no 'preload' directive", {"header": sts}))
    if "includesubdomains" not in sts:
        findings.append(
            Finding("WEB04", Severity.INFO, "HSTS header has no 'includeSubDomains' directive", {"header": sts})
        )
    return findings


@register(
    id="WEB05",
    category=CATEGORY,
    name="TLS certificate is valid, matches SAN, and >=14 days from expiry",
    default_severity=Severity.WARNING,
)
async def web05(ctx: CheckContext) -> list[Finding]:
    addrs = await ctx.resolver.resolve_addresses(ctx.domain)
    if not addrs:
        return []
    addr = addrs[0]
    findings: list[Finding] = []
    try:
        sock_context = ssl.create_default_context()
        sock_context.check_hostname = True
        with socket.create_connection((addr, 443), timeout=8.0) as sock:
            with sock_context.wrap_socket(sock, server_hostname=ctx.domain) as ssock:
                der = ssock.getpeercert(binary_form=True)
        if not der:
            return []
        cert = x509.load_der_x509_certificate(der, default_backend())
        not_after = cert.not_valid_after_utc
        days_left = (not_after - datetime.now(timezone.utc)).days
        if days_left < 0:
            findings.append(
                Finding(
                    "WEB05",
                    Severity.CRITICAL,
                    f"Certificate expired {abs(days_left)} days ago",
                    {"days": days_left},
                )
            )
        elif days_left < 14:
            findings.append(
                Finding("WEB05", Severity.WARNING, f"Certificate expires in {days_left} days", {"days": days_left})
            )
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            names = san.get_values_for_type(x509.DNSName)
            if not _name_matches(ctx.domain, names):
                findings.append(
                    Finding(
                        "WEB05",
                        Severity.ERROR,
                        f"Certificate SANs {names} do not match {ctx.domain}",
                        {"sans": names},
                    )
                )
        except x509.ExtensionNotFound:
            findings.append(Finding("WEB05", Severity.WARNING, "Certificate has no SAN extension", {}))
    except ssl.SSLCertVerificationError as e:
        findings.append(Finding("WEB05", Severity.ERROR, f"TLS verification failed: {e}", {"error": str(e)}))
    except Exception as e:
        findings.append(Finding("WEB05", Severity.NOTICE, f"Could not establish TLS to :443: {e}", {"error": str(e)}))
    return findings


def _name_matches(host: str, names: list[str]) -> bool:
    host = host.lower()
    for raw in names:
        n = raw.lower()
        if n == host:
            return True
        if n.startswith("*.") and host.endswith(n[1:]) and host.count(".") == n.count("."):
            return True
    return False


@register(
    id="WEB06",
    category=CATEGORY,
    name="HTTPS server replies (TLS handshake succeeds)",
    default_severity=Severity.WARNING,
)
async def web06(ctx: CheckContext) -> list[Finding]:
    addrs = await ctx.resolver.resolve_addresses(ctx.domain)
    if not addrs:
        return [Finding("WEB06", Severity.NOTICE, "Apex has no A/AAAA records — no web endpoint", {})]
    try:
        sock_context = ssl.create_default_context()
        with socket.create_connection((addrs[0], 443), timeout=8.0) as sock:
            with sock_context.wrap_socket(sock, server_hostname=ctx.domain) as _ssock:
                pass
    except Exception as e:
        return [
            Finding("WEB06", Severity.WARNING, f"TLS handshake failed against {addrs[0]}:443: {e}", {"error": str(e)})
        ]
    return []


@register(
    id="WEB07",
    category=CATEGORY,
    name="HTTPS endpoint refuses TLS 1.0 / 1.1",
    description=(
        "RFC 8996 (BCP 195): TLS 1.0 and 1.1 MUST NOT be supported. PCI-DSS 3.2.1 "
        "and the major browsers all dropped them. Try a 1.0/1.1 handshake; success "
        "means the server still accepts an obsolete protocol version."
    ),
    default_severity=Severity.ERROR,
)
async def web07(ctx: CheckContext) -> list[Finding]:
    addrs = await ctx.resolver.resolve_addresses(ctx.domain)
    if not addrs:
        return []
    addr = addrs[0]
    findings: list[Finding] = []

    def try_old_tls(proto: ssl.TLSVersion, label: str) -> str | None:
        try:
            ctx_old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_old.check_hostname = False
            ctx_old.verify_mode = ssl.CERT_NONE
            ctx_old.minimum_version = proto
            ctx_old.maximum_version = proto
            with socket.create_connection((addr, 443), timeout=6.0) as sock:
                with ctx_old.wrap_socket(sock, server_hostname=ctx.domain) as ssock:
                    return ssock.version()
        except (ssl.SSLError, OSError):
            return None
        except Exception:
            return None

    for proto, label in (
        (ssl.TLSVersion.TLSv1, "TLS 1.0"),
        (ssl.TLSVersion.TLSv1_1, "TLS 1.1"),
    ):
        negotiated = await asyncio.get_running_loop().run_in_executor(None, try_old_tls, proto, label)
        if negotiated:
            findings.append(
                Finding(
                    "WEB07",
                    Severity.ERROR,
                    f"HTTPS server accepts obsolete {label} (negotiated {negotiated})",
                    {"protocol": label, "negotiated": negotiated},
                )
            )
    return findings


@register(
    id="WEB08",
    category=CATEGORY,
    name="TLS certificate uses a modern signature algorithm",
    description=(
        "RFC 6194 / NIST SP 800-131A: SHA-1 (and earlier) are deprecated for "
        "digital signatures. A SHA-1-signed leaf certificate is rejected by "
        "every modern browser and MTA."
    ),
    default_severity=Severity.ERROR,
)
async def web08(ctx: CheckContext) -> list[Finding]:
    addrs = await ctx.resolver.resolve_addresses(ctx.domain)
    if not addrs:
        return []
    addr = addrs[0]
    try:
        sock_context = ssl.create_default_context()
        with socket.create_connection((addr, 443), timeout=8.0) as sock:
            with sock_context.wrap_socket(sock, server_hostname=ctx.domain) as ssock:
                der = ssock.getpeercert(binary_form=True)
        if not der:
            return []
        cert = x509.load_der_x509_certificate(der, default_backend())
    except Exception:
        return []
    sig_alg = cert.signature_hash_algorithm
    if sig_alg is None:
        return []
    name = sig_alg.name.lower()
    if name in {"md5", "sha1"}:
        return [
            Finding(
                "WEB08",
                Severity.ERROR,
                f"TLS certificate signed with deprecated {sig_alg.name} — modern clients will reject",
                {"algorithm": sig_alg.name},
            )
        ]
    return []


@register(
    id="WEB09",
    category=CATEGORY,
    name="HTTPS endpoint negotiates HTTP/2 via ALPN",
    description=(
        "RFC 7540 + RFC 7301: a modern HTTPS endpoint SHOULD advertise the "
        "h2 ALPN identifier so clients can use HTTP/2 multiplexing. Pure "
        "HTTP/1.1-only endpoints add latency and head-of-line blocking."
    ),
    default_severity=Severity.NOTICE,
)
async def web09(ctx: CheckContext) -> list[Finding]:
    addrs = await ctx.resolver.resolve_addresses(ctx.domain)
    if not addrs:
        return []
    addr = addrs[0]

    def negotiate() -> str | None:
        try:
            ctx_alpn = ssl.create_default_context()
            ctx_alpn.set_alpn_protocols(["h2", "http/1.1"])
            with socket.create_connection((addr, 443), timeout=6.0) as sock:
                with ctx_alpn.wrap_socket(sock, server_hostname=ctx.domain) as ssock:
                    return ssock.selected_alpn_protocol()
        except Exception:
            return None

    selected = await asyncio.get_running_loop().run_in_executor(None, negotiate)
    if selected and selected != "h2":
        return [
            Finding(
                "WEB09",
                Severity.NOTICE,
                f"HTTPS server negotiated {selected!r} via ALPN (no HTTP/2 offered)",
                {"alpn": selected},
            )
        ]
    if selected is None:
        return [
            Finding(
                "WEB09",
                Severity.NOTICE,
                "HTTPS server did not negotiate any ALPN protocol",
                {},
            )
        ]
    return []
