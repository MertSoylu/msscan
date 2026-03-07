"""Interactive scan results viewer with severity filtering."""

from __future__ import annotations

from rich.console import Console, Group
from rich.text import Text

from msscan.core.result import ScanResult
from msscan.output.console import (
    SEVERITY_ORDER,
    SEVERITY_COLORS,
    SEVERITY_ICONS,
    build_results_renderables,
)
from msscan.ui.overlay import alternate_screen, read_key, _clear_screen


def _render_results(
    console: Console,
    results: list[ScanResult],
    active_filters: set[str],
) -> None:
    """Clear and re-render the results viewer."""
    _clear_screen()

    # Build filter bar
    filter_parts = []
    for i, sev in enumerate(SEVERITY_ORDER, 1):
        icon = SEVERITY_ICONS[sev]
        color = SEVERITY_COLORS[sev]
        if sev in active_filters:
            filter_parts.append(f"[{color}][{i}] {icon} {sev}[/{color}]")
        else:
            filter_parts.append(f"[dim strikethrough][{i}] {sev}[/dim strikethrough]")
    filter_bar = "  ".join(filter_parts)

    # Build renderables for filtered results
    renderables = build_results_renderables(results, severity_filter=active_filters)

    # Count
    filtered_count = sum(1 for r in results if r.severity in active_filters)
    count_text = f"{filtered_count} of {len(results)} finding(s)"

    footer = Text.assemble(
        ("  1-5", "bold cyan"), (" toggle severity  ", "dim"),
        ("a", "bold cyan"), (" show all  ", "dim"),
        ("q/ESC", "bold red"), (" close", "dim"),
    )

    with console.capture() as capture:
        console.print()
        console.print(filter_bar, justify="center")
        console.print(f"[dim]  {count_text}[/dim]", justify="center")
        console.print()
        if renderables:
            for r in renderables:
                console.print(r)
        else:
            console.print("[dim]No findings match the current filter.[/dim]", justify="center")
        console.print()
        console.print(footer, justify="center")

    import sys
    sys.stdout.write(capture.get())
    sys.stdout.flush()


def run_results_viewer(console: Console, results: list[ScanResult]) -> None:
    """Show scan results in an interactive overlay with severity filtering."""
    if console.size.height < 20 or not results:
        return

    # Start with all severities active
    active_filters = set(SEVERITY_ORDER)

    # Map key presses to severity levels
    key_to_severity = {str(i): sev for i, sev in enumerate(SEVERITY_ORDER, 1)}

    with alternate_screen():
        _render_results(console, results, active_filters)
        while True:
            key = read_key()
            if key in ("q", "ESC"):
                break
            elif key == "a":
                active_filters = set(SEVERITY_ORDER)
            elif key in key_to_severity:
                sev = key_to_severity[key]
                if sev in active_filters:
                    # Don't allow removing the last filter
                    if len(active_filters) > 1:
                        active_filters.discard(sev)
                else:
                    active_filters.add(sev)
            else:
                continue
            _render_results(console, results, active_filters)
