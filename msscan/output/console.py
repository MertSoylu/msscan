"""Rich console output — banner, tables, progress."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from msscan import __version__
from msscan.core.result import ScanResult

console = Console()

# Rich markup color names mapped to each severity level
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "blue",
    "INFO":     "dim white",
}

# Emoji indicator shown next to each severity label
SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🔴",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}

# Display order for severity levels — highest impact first
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

BANNER = r"""
  ███╗   ███╗███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
  ████╗ ████║██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██╔████╔██║███████╗███████╗██║     ███████║██╔██╗ ██║
  ██║╚██╔╝██║╚════██║╚════██║██║     ██╔══██║██║╚██╗██║
  ██║ ╚═╝ ██║███████║███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝     ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""


def print_banner() -> None:
    """Print the ASCII banner."""
    text = Text(BANNER, style="bold cyan")
    panel = Panel(
        text,
        subtitle=f"[dim]v{__version__} • Web Application Security Scanner[/dim]",
        border_style="bright_cyan",
        expand=False,
    )
    console.print(panel)


def print_scan_config(url: str, modules: list[str], rate_limit: int, timeout: float) -> None:
    """Print the scan configuration summary."""
    console.print()
    console.print(f"  [bold white]🎯 Target  :[/bold white]  {url}")
    console.print(f"  [bold white]📦 Modules :[/bold white]  {', '.join(m.upper() for m in modules)}")
    rate_str = f"{rate_limit} req/s" if rate_limit > 0 else "unlimited"
    console.print(f"  [bold white]⚡ Rate    :[/bold white]  {rate_str}")
    console.print(f"  [bold white]⏱  Timeout :[/bold white]  {timeout}s")
    console.print()


def print_scan_summary(url: str, results: list[ScanResult], elapsed_secs: float) -> None:
    """Print the post-scan summary panel with severity breakdown."""
    # Count findings per severity level
    counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for r in results:
        if r.severity in counts:
            counts[r.severity] += 1

    # Build badge text only for severity levels that have at least one finding
    badge_parts = []
    for sev in SEVERITY_ORDER:
        if counts[sev]:
            icon = SEVERITY_ICONS[sev]
            color = SEVERITY_COLORS[sev]
            badge_parts.append(f"[{color}]{icon} {sev}: {counts[sev]}[/{color}]")

    summary_text = Text.assemble(
        ("  🎯 Target  : ", "bold white"), (url + "\n", "cyan"),
        ("  📅 Date    : ", "bold white"), (datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n", "white"),
        ("  ⏱  Elapsed : ", "bold white"), (f"{elapsed_secs:.2f}s\n", "white"),
        # Color the total red/yellow if there are findings, green if clean
        ("  📊 Total   : ", "bold white"), (f"{len(results)} finding(s)\n", "bold yellow" if results else "bold green"),
    )

    panel = Panel(
        summary_text,
        title="[bold]📋 Scan Summary[/bold]",
        border_style="bright_cyan",
        expand=False,
    )
    console.print()
    console.print(panel)
    if badge_parts:
        # Print severity badges on a single line below the panel
        console.print(f"  {'  '.join(badge_parts)}")
    console.print()


def print_results(results: list[ScanResult]) -> None:
    """Print findings grouped by module as separate tables."""
    if not results:
        return

    # Group results by scanner name so each module gets its own table
    grouped: dict[str, list[ScanResult]] = defaultdict(list)
    for r in results:
        grouped[r.scanner].append(r)

    for module, findings in grouped.items():
        console.print(Rule(
            title=f"[bold cyan]{module.upper()} Findings ({len(findings)})[/bold cyan]",
            style="bright_cyan",
        ))

        table = Table(
            show_header=True,
            header_style="bold magenta",
            border_style="dim cyan",
            expand=True,
            show_lines=True,
        )
        table.add_column("Severity", width=14)
        table.add_column("URL", style="cyan", ratio=2)
        table.add_column("Detail", ratio=3)
        table.add_column("Evidence", style="dim", ratio=2)

        for r in findings:
            icon = SEVERITY_ICONS.get(r.severity, "")
            color = SEVERITY_COLORS.get(r.severity, "white")
            table.add_row(
                f"[{color}]{icon} {r.severity}[/{color}]",
                r.url,
                r.detail,
                r.evidence[:100] if r.evidence else "",  # truncate long payloads for readability
            )

        console.print(table)
        console.print()
