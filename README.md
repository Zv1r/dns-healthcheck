# dns-healthcheck

A comprehensive DNS auditor for the modern internet, packaged as a single Python CLI.

`dns-healthcheck` runs **101 checks** against any domain you point it at, covering the full
RFC-defined DNS surface (delegation, name servers, DNSSEC, SOA, syntax, connectivity,
consistency) **plus** four areas most auditors skip:

- **Email security**: SPF, DKIM (selector probing), DMARC, MTA-STS, TLS-RPT, BIMI, DANE.
- **Web/CDN posture**: CAA, HTTPS redirect, HSTS, HSTS preload eligibility, TLS cert chain.
- **Multi-resolver propagation**: query Cloudflare, Google, Quad9, OpenDNS, ControlD in parallel and surface answer drift.
- **CI-native output**: text, JSON, **SARIF 2.1.0**, JUnit XML, and Markdown — with a `--fail-on` exit code so domain regressions can fail your pipeline.

MIT-licensed. No daemon, no database, no UI — install in a virtual environment and run.

---

## Install

`dns-healthcheck` is not on PyPI yet — install directly from this GitHub repository
into a virtual environment:

```bash
# 1. Create and activate a virtualenv
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 2. Install from GitHub (latest main)
pip install --upgrade pip
pip install "git+https://github.com/Zv1r/dns-healthcheck.git@main"

# 3. Verify
dnshc --version
```

Or, if you want the source tree alongside the install (for hacking / running from a clone):

```bash
git clone https://github.com/Zv1r/dns-healthcheck.git
cd dns-healthcheck
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
pip install -e .
```

Prefer an isolated, never-activate workflow? `pipx` manages its own venv per tool:

```bash
pipx install "git+https://github.com/Zv1r/dns-healthcheck.git@main"
```

Python 3.10+ required. A PyPI release will be tagged once the test matrix has run a
few releases against the wild.

## Quick start

All commands below assume your virtualenv is activated (`source .venv/bin/activate`).

```bash
# Audit a domain (rich terminal output)
dnshc check example.com

# Strict mode — promote warnings to errors
dnshc check example.com --profile strict

# Only run DNSSEC checks
dnshc check example.com --only dnssec

# Skip the slow DKIM selector sweep
dnshc check example.com --skip EMAIL04

# Use specific resolvers for stub queries
dnshc check example.com -r 1.1.1.1 -r 8.8.8.8

# CI: emit SARIF for GitHub Code Scanning, exit non-zero on any warning
dnshc check example.com --output sarif --fail-on warning > report.sarif
```

## Output formats

| `--output` | Use |
|---|---|
| `text` (default) | Coloured terminal tables, one per category |
| `json` | Machine-readable; schema `dns-healthcheck/1` |
| `sarif` | SARIF 2.1.0 — uploadable to GitHub Code Scanning |
| `junit` | JUnit XML for any CI that consumes test reports |
| `markdown` | Drop into a PR comment or GitHub issue |

## Profiles

| Profile | Behaviour |
|---|---|
| `default` | All categories, fail on `error`. |
| `strict` | All categories, fail on `warning`. |
| `minimal` | Only basic + delegation + DNSSEC. Fast smoke check. |
| `email` | Mail-focused: basic, email, zone. Fail on warning. |
| `web` | Web-facing: basic + web (CAA, HSTS, cert). Fail on warning. |
| `ci` | Same as default, designed for non-interactive runs. |

`dnshc list-profiles` to see them in your terminal.

## Use as a library

```python
import asyncio
from dns_healthcheck import runner
from dns_healthcheck.profiles import get_profile
from dns_healthcheck.reporters import render_json

report = asyncio.run(runner.run("example.com", get_profile("default")))
print(render_json(report))
```

## Check categories

| Category | Count | What it covers |
|---|---|---|
| `address` | 3 | NS IP must be globally routable; PTR exists and matches |
| `basic` | 3 | Parent delegates; ≥1 working NS; apex resolves |
| `connectivity` | 4 | UDP, TCP, AS diversity, prefix diversity |
| `consistency` | 6 | SOA serial / RNAME / timers / NS / glue / MNAME |
| `delegation` | 10 | Min NS, distinct IPs, AA bit, CNAME-at-apex, glue, NS-not-CNAME (RFC 2181), NS resolves, IPv4+IPv6 (BCP 91) |
| `dnssec` | 19 | DS, DNSKEY, RRSIG, NSEC/NSEC3 (RFC 9276 incl. salt), key strength, CDS, signature validation |
| `nameserver` | 19 | Recursion, EDNS0/version, AXFR + IXFR refusal (RFC 1995), DNS COOKIE (RFC 7873), 0x20 case preservation, RFC 2308 negative-cache SOA, RFC 8482 ANY minimisation, NXDOMAIN, version disclosure, serial stability |
| `syntax` | 8 | Charset, hyphen rules, IDN, SOA RNAME/MNAME, hostname validity |
| `zone` | 12 | SOA timers, RFC 2308 SOA-TTL-vs-MINIMUM, MX hygiene, SPF presence, wildcard MX |
| `email` | 8 | SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, DANE |
| `web` | 6 | CAA, HTTPS redirect, HSTS, preload, TLS cert |
| `propagation` | 3 | A/AAAA/MX/NS consistency across 5 public resolvers |
| **Total** | **101** | |

`dnshc list-checks` for the full catalog. `dnshc explain <CHECK_ID>` for one check's spec.

## Severity levels

`INFO < NOTICE < WARNING < ERROR < CRITICAL`. Each finding has one. The default profile
fails the run on `ERROR+`; use `--fail-on warning` for stricter pipelines.

## Development

```bash
git clone https://github.com/Zv1r/dns-healthcheck
cd dns-healthcheck

# Always work inside a virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e '.[dev]'

# Quality gates
pytest
ruff check . && ruff format --check .

# Smoke run from the source tree
dnshc check example.com
```

## License

MIT — see [LICENSE](LICENSE).
