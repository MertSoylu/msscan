"""Rich console output — banner, tables, progress."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from rich.color import Color
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.style import Style
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


# Gradient color stops for the banner (cyan → blue → purple)
_GRADIENT_COLORS = [
    (0, 212, 255),    # #00d4ff
    (0, 180, 216),    # #00b4d8
    (0, 150, 199),    # #0096c7
    (0, 119, 182),    # #0077b6
    (131, 56, 236),   # #8338ec
    (199, 125, 255),  # #c77dff
]


def _lerp_color(colors: list[tuple[int, int, int]], t: float) -> tuple[int, int, int]:
    """Linearly interpolate between a list of RGB color stops at position t (0..1)."""
    t = max(0.0, min(1.0, t))
    n = len(colors) - 1
    idx = t * n
    i = int(idx)
    if i >= n:
        return colors[-1]
    frac = idx - i
    r = int(colors[i][0] + (colors[i + 1][0] - colors[i][0]) * frac)
    g = int(colors[i][1] + (colors[i + 1][1] - colors[i][1]) * frac)
    b = int(colors[i][2] + (colors[i + 1][2] - colors[i][2]) * frac)
    return (r, g, b)


def print_banner() -> None:
    """Print the ASCII banner with gradient colors."""
    lines = BANNER.strip("\n").splitlines()
    text = Text()
    max_len = max(len(line) for line in lines) or 1
    for i, line in enumerate(lines):
        for j, ch in enumerate(line):
            t = j / max_len
            r, g, b = _lerp_color(_GRADIENT_COLORS, t)
            text.append(ch, style=Style(color=Color.from_rgb(r, g, b), bold=True))
        text.append("\n")
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


def build_results_renderables(
    results: list[ScanResult],
    severity_filter: set[str] | None = None,
) -> list[Table | Rule]:
    """Build Rich renderables for scan findings, optionally filtered by severity.

    Returns a list of Rule + Table pairs for each scanner module.
    """
    filtered = results
    if severity_filter:
        filtered = [r for r in results if r.severity in severity_filter]

    if not filtered:
        return []

    grouped: dict[str, list[ScanResult]] = defaultdict(list)
    for r in filtered:
        grouped[r.scanner].append(r)

    renderables: list[Table | Rule] = []
    for module, findings in grouped.items():
        renderables.append(Rule(
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
        table.add_column("Confidence", width=10)
        table.add_column("URL", style="cyan", ratio=2)
        table.add_column("Detail", ratio=3)
        table.add_column("Evidence", style="dim", ratio=2)

        for r in findings:
            icon = SEVERITY_ICONS.get(r.severity, "")
            color = SEVERITY_COLORS.get(r.severity, "white")
            conf_color = {"HIGH": "green", "MEDIUM": "yellow", "LOW": "dim"}.get(r.confidence, "dim")
            detail_text = f"{r.detail} [{r.cwe_id}]" if r.cwe_id else r.detail
            table.add_row(
                f"[{color}]{icon} {r.severity}[/{color}]",
                f"[{conf_color}]{r.confidence}[/{conf_color}]",
                r.url,
                detail_text,
                r.evidence[:100] if r.evidence else "",
            )

        renderables.append(table)

    return renderables


def print_results(results: list[ScanResult]) -> None:
    """Print findings grouped by module as separate tables."""
    if not results:
        return
    for renderable in build_results_renderables(results):
        console.print(renderable)
    console.print()
