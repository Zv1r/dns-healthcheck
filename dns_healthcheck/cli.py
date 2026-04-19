"""dnshc — Typer-based CLI."""

from __future__ import annotations

import asyncio
import json

import typer
from rich.console import Console
from rich.table import Table

from dns_healthcheck import __version__, runner
from dns_healthcheck.profiles import PROFILES, get_profile
from dns_healthcheck.registry import REGISTRY
from dns_healthcheck.reporters import REPORTERS
from dns_healthcheck.result import Severity

app = typer.Typer(
    name="dnshc",
    help="dns-healthcheck — comprehensive DNS auditor.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"dns-healthcheck {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    """dns-healthcheck CLI."""


@app.command()
def check(
    domain: str = typer.Argument(..., help="Domain to audit (e.g. example.com)."),
    profile: str = typer.Option("default", "--profile", "-p", help=f"One of: {', '.join(PROFILES)}"),
    only: str | None = typer.Option(None, "--only", help="Comma-separated check IDs or categories to include."),
    skip: str | None = typer.Option(None, "--skip", help="Comma-separated check IDs or categories to skip."),
    resolver: list[str] = typer.Option(
        [], "--resolver", "-r", help="Public resolver IP for stub queries (repeatable)."
    ),
    fail_on: str = typer.Option(
        "error",
        "--fail-on",
        help="Exit non-zero if any finding has at least this severity (info/notice/warning/error/critical).",
    ),
    output: str = typer.Option("text", "--output", "-o", help="Output format: text, json, sarif, junit, markdown."),
    timeout: float = typer.Option(5.0, "--timeout", help="Per-query timeout in seconds."),
    concurrency: int = typer.Option(8, "--concurrency", help="Concurrent checks."),
    no_ipv6: bool = typer.Option(False, "--no-ipv6", help="Skip IPv6 resolution."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI colour in text output."),
) -> None:
    """Audit a single DOMAIN."""
    try:
        prof = get_profile(profile)
    except KeyError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(code=2) from e

    only_list = [s.strip() for s in only.split(",")] if only else None
    skip_list = [s.strip() for s in skip.split(",")] if skip else None
    fail_severity = Severity.parse(fail_on)

    if output not in REPORTERS:
        typer.echo(f"Unknown output format '{output}'. Choices: {', '.join(REPORTERS)}", err=True)
        raise typer.Exit(code=2)

    report = asyncio.run(
        runner.run(
            domain=domain,
            profile=prof,
            only=only_list,
            skip=skip_list,
            resolvers=resolver or None,
            concurrency=concurrency,
            timeout=timeout,
            use_ipv6=not no_ipv6,
        )
    )

    reporter = REPORTERS[output]
    rendered = reporter(report, no_color=no_color) if output == "text" else reporter(report)
    typer.echo(rendered)

    worst = max((f.severity for r in report.results for f in r.findings), default=Severity.INFO)
    if worst >= fail_severity:
        raise typer.Exit(code=1)


@app.command("list-checks")
def list_checks(
    category: str | None = typer.Option(None, "--category", "-c"),
    fmt: str = typer.Option("table", "--format", "-f", help="table or json"),
) -> None:
    """List all registered checks."""
    items = REGISTRY.all()
    if category:
        items = [c for c in items if c.category == category.lower()]
    if fmt == "json":
        out = [
            {
                "id": c.id,
                "category": c.category,
                "name": c.name,
                "default_severity": c.default_severity.label,
                "spec_url": c.spec_url,
                "requires_dnssec": c.requires_dnssec,
                "requires_mx": c.requires_mx,
            }
            for c in items
        ]
        typer.echo(json.dumps(out, indent=2))
        return
    table = Table(title=f"Registered checks ({len(items)})")
    table.add_column("ID", style="bold")
    table.add_column("Category")
    table.add_column("Name")
    table.add_column("Default", no_wrap=True)
    for c in items:
        table.add_row(c.id, c.category, c.name, c.default_severity.label)
    Console().print(table)


@app.command()
def explain(check_id: str) -> None:
    """Show detail for a single check (description + spec link)."""
    spec = REGISTRY.by_id(check_id)
    if spec is None:
        typer.echo(f"No such check: {check_id}", err=True)
        raise typer.Exit(code=2)
    typer.echo(f"{spec.id}  [{spec.category}]")
    typer.echo(f"  {spec.name}")
    typer.echo(f"  default severity: {spec.default_severity.label}")
    typer.echo("")
    typer.echo("  " + spec.description.strip().replace("\n", "\n  "))
    if spec.spec_url:
        typer.echo("")
        typer.echo(f"  spec: {spec.spec_url}")


@app.command("list-profiles")
def list_profiles() -> None:
    """List built-in run profiles."""
    table = Table(title="Profiles")
    table.add_column("Name", style="bold")
    table.add_column("Fail on")
    table.add_column("Description")
    for p in PROFILES.values():
        table.add_row(p.name, p.fail_on.label, p.description)
    Console().print(table)


if __name__ == "__main__":
    app()
