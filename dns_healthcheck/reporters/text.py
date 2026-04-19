"""Rich-formatted terminal reporter."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from dns_healthcheck.result import RunReport, Severity

SEVERITY_STYLE = {
    Severity.INFO: "dim",
    Severity.NOTICE: "blue",
    Severity.WARNING: "yellow",
    Severity.ERROR: "red",
    Severity.CRITICAL: "bold red",
}


def render_text(report: RunReport, *, no_color: bool = False, quiet: bool = False) -> str:
    # Render via capture() so the reporter only RETURNS text — the CLI is
    # responsible for printing it. Otherwise everything would be printed twice.
    console = Console(no_color=no_color, force_terminal=not no_color, width=120)
    with console.capture() as cap:
        _render(console, report)
    return cap.get()


def _render(console: Console, report: RunReport) -> None:
    header = Text()
    header.append("dns-healthcheck", style="bold")
    header.append(f" — {report.domain}", style="cyan")
    header.append(f"  profile={report.profile}", style="dim")
    console.print(Panel(header, expand=False))

    by_cat: dict[str, list] = {}
    for r in report.results:
        by_cat.setdefault(r.category, []).append(r)

    for category in sorted(by_cat):
        table = Table(title=category.upper(), show_lines=False, expand=True)
        table.add_column("ID", style="bold", no_wrap=True)
        table.add_column("Check", style="cyan")
        table.add_column("Severity", no_wrap=True)
        table.add_column("Findings")
        for r in by_cat[category]:
            sev = r.severity
            style = SEVERITY_STYLE.get(sev, "")
            sev_label = sev.label
            if r.skipped:
                sev_label = "SKIP"
                style = "dim"
            elif r.error:
                sev_label = "ERROR"
                style = "red"
            findings_text: str
            if r.skipped:
                findings_text = f"[dim]{r.skip_reason or 'skipped'}[/dim]"
            elif r.error:
                findings_text = f"[red]{r.error}[/red]"
            elif not r.findings:
                findings_text = "[dim]ok[/dim]"
            else:
                lines = []
                for f in r.findings:
                    s = SEVERITY_STYLE.get(f.severity, "")
                    line = f"[{s}]{f.severity.label}[/{s}] {f.message}"
                    if f.ns:
                        line += f"  [dim]({f.ns})[/dim]"
                    lines.append(line)
                findings_text = "\n".join(lines)
            table.add_row(r.check_id, r.name, Text(sev_label, style=style), findings_text)
        console.print(table)
        console.print()

    sm = report.summary
    summary = (
        f"[bold]Summary[/bold]  checks={sm['total_checks']}  "
        f"errors={sm.get('ERROR', 0)}  warnings={sm.get('WARNING', 0)}  "
        f"notices={sm.get('NOTICE', 0)}  skipped={sm['skipped']}  "
        f"runtime={report.duration_ms}ms"
    )
    console.print(Panel(summary, expand=False))
