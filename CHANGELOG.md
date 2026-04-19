# Changelog

All notable changes to `dns-healthcheck` are recorded here. The version
number is the source of truth in `pyproject.toml` and `dns_healthcheck/__init__.py`;
keep them in sync (use `scripts/bump-version.py` to bump both).

## 0.5.1 — 2026-04-19

### Fixed — TLD audit bugs surfaced by `dnshc check ua`

- `_discover_parent_ns` returned early when the target's parent was empty
  (true for any single-label domain like a TLD). That left
  `parent_ns` / `child_ns` / `authoritative_servers()` empty, so:
  - DNSKEY discovery had no servers to ask → false
    `DNSSEC01: Parent has DS but apex returns no DNSKEY` and cascading
    DNSSEC06/07/11/12 errors.
  - Every NS-iterating check (`NAMESERVER*`, `CONNECTIVITY*`,
    `DELEGATION04+06`) silently passed with zero iterations — no signal
    at all.
  Fix: only bail out when `self.domain` itself is empty; let the
  iterative walk produce the parent-zone NS IPs (root for a TLD) and
  populate `parent_ns` from the root's referral.
- `NAMESERVER10` (DNS COOKIE) crashed with `AttributeError: 'CookieOption'
  has no attribute 'data'`. dnspython 2.6+ parses incoming cookies into
  a typed `CookieOption` (with `.client` / `.server`) instead of the
  generic option byte buffer. Now handles both shapes.

### Added

- `requires_non_tld` flag on the check spec — gates checks that aren't
  meaningful for a TLD (e.g. SPF, DMARC, DBL listing). The runner skips
  them with reason `"Check is not meaningful for a TLD"` instead of
  reporting WARNINGs that no operator would act on.
- Applied to: `EMAIL01-12`, `ZONE09`. (Web checks already gracefully
  degrade when the apex has no A/AAAA — no change needed there.)

### Verified

`dnshc check ua` went from 5 errors / 7 warnings to 0 errors / 0
warnings, with 13 sensible TLD-skips. Non-TLD runs unchanged
(iana.org 2 warnings, rift.org.ua 1 warning).

## 0.5.0 — 2026-04-19

### Added — 11 enterprise-tool-parity checks (101 -> 112)

Sourced from a survey of MXToolbox, DNSViz, intoDNS, Hardenize, and SSL Labs.

**nameserver (3)**
- `NAMESERVER20` — per-NS UDP query RTT (NOTICE >150ms, WARNING >500ms).
- `NAMESERVER21` — TC bit set on truncated UDP responses + TCP retry returns
  full answer (RFC 1035 §4.2.1, RFC 7766). Probes DNSKEY at EDNS bufsize=512.
- `NAMESERVER22` — server advertises a sane EDNS UDP buffer size per
  RFC 9715 (warns on very large advertisements; warns hard on missing EDNS).

**email (4)**
- `EMAIL09` — every MX target has a PTR matching its forward A/AAAA
  (forward-confirmed reverse DNS).
- `EMAIL10` — MX accepts SMTP-25 with a 220 banner (RFC 5321 §3.1). Connection
  failures degrade to NOTICE since many networks block egress port 25.
- `EMAIL11` — MX advertises STARTTLS in EHLO response (RFC 3207).
- `EMAIL12` — domain not listed on Spamhaus DBL (DNS-queryable; no API key).

**web (3)**
- `WEB07` — HTTPS endpoint refuses TLS 1.0 / 1.1 per RFC 8996 (BCP 195).
  Probes both protocols; success = ERROR.
- `WEB08` — TLS certificate uses a modern signature algorithm (no SHA-1, MD5).
- `WEB09` — HTTPS endpoint negotiates HTTP/2 via ALPN (RFC 7540 + RFC 7301).

**propagation (1)**
- `PROPAGATION04` — A-record TTL coherence across 5 public resolvers
  (NOTICE if max-TTL ≥ 5× min-TTL with >60s spread — usually a recent change
  still propagating, or inconsistent authoritative TTLs).

## 0.4.0 — 2026-04-19

### Fixed
- Mypy errors that were failing CI on `lint`: `runner.py` casts the
  resolver nameservers to `list[str]`; `cli.py` uses `render_text`
  directly (instead of going through the reporter dict whose entries
  have heterogeneous signatures); `nameserver10` uses
  `dns.edns.OptionType.COOKIE` instead of a magic int.

## 0.3.0 — 2026-04-19

### Added
- Three previously-stub nameserver checks now do real work:
  `NAMESERVER04` (0x20 case preservation), `NAMESERVER08` (SOA serial
  stability), `NAMESERVER10` (DNS COOKIE per RFC 7873).
- New checks (10 total): `NAMESERVER15` (IXFR refusal RFC 1995),
  `NAMESERVER16` (multi-tenant infra detection),
  `NAMESERVER17` (RFC 2308 negative-cache SOA in authority),
  `NAMESERVER18` (RFC 8482 ANY minimisation),
  `NAMESERVER19` (RFC 6891 EDNS version negotiation),
  `DELEGATION08` (NS not CNAME, RFC 2181 §10.3),
  `DELEGATION09` (every NS hostname resolves),
  `DELEGATION10` (BCP 91 IPv4+IPv6 coverage),
  `ZONE12` (RFC 2308 §4 SOA TTL ≤ MINIMUM),
  `DNSSEC19` (RFC 9276 §3.1 NSEC3 salt empty).
- Total checks: 91 → 101.

### Fixed
- Text reporter no longer prints the report twice. `Console(record=True)`
  was writing to stdout AND recording, then the CLI re-printed the
  recorded copy. Switched to `Console.capture()` so the reporter
  exclusively returns text.

## 0.2.0 — 2026-04-19

### Fixed
- DNSSEC discovery: query DS records at the parent zone's nameservers
  (captured during the iterative walk), not at the child zone's NS.
  rv.ua, iana.org, and any zone whose parent operator is distinct from
  the child operator were previously misreported as unsigned.

## 0.1.0 — 2026-04-19

Initial release.
- 91 RFC-grounded checks across 12 categories.
- Five output formats: text, JSON, SARIF 2.1.0, JUnit XML, Markdown.
- Six profiles: default, strict, minimal, email, web, ci.
- Typer CLI with `check`, `list-checks`, `list-profiles`, `explain`.
