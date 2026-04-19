# Changelog

All notable changes to `dns-healthcheck` are recorded here. The version
number is the source of truth in `pyproject.toml` and `dns_healthcheck/__init__.py`;
keep them in sync (use `scripts/bump-version.py` to bump both).

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
