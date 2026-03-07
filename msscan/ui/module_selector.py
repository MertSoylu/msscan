"""Interactive checkbox-based module selector using alternate screen."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.style import Style
from rich.text import Text

from msscan.ui.overlay import alternate_screen, read_key, _clear_screen

# Short descriptions for each scanner module
MODULE_DESCRIPTIONS: dict[str, str] = {
    "xss":           "Reflected Cross-Site Scripting detection",
    "sqli":          "SQL Injection detection",
    "csrf":          "CSRF token & SameSite cookie checks",
    "open_redirect": "Open redirect vulnerability scanner",
    "ssrf":          "Server-Side Request Forgery scanner",
    "headers":       "HTTP security headers analysis",
    "subdomain":     "DNS brute-force subdomain enumeration",
}

HIGHLIGHT_STYLE = Style(bgcolor="grey23")


def _render_selector(
    console: Console,
    modules: list[str],
    enabled: list[bool],
    cursor: int,
) -> None:
    """Clear and re-render the module selector UI."""
    _clear_screen()

    table = Table(
        title="🔍 Select Scan Modules",
        show_header=True,
        header_style="bold magenta",
        border_style="bright_cyan",
    )
    table.add_column(" ", width=3, justify="center")
    table.add_column("Module", style="bold cyan", min_width=16)
    table.add_column("Description", style="dim")

    for i, mod in enumerate(modules):
        check = "[green]✔[/green]" if enabled[i] else " "
        desc = MODULE_DESCRIPTIONS.get(mod, "")
        style = HIGHLIGHT_STYLE if i == cursor else None
        table.add_row(check, mod, desc, style=style)

    footer = Text.assemble(
        ("  ↑↓", "bold cyan"), (" navigate  ", "dim"),
        ("Space", "bold cyan"), (" toggle  ", "dim"),
        ("a", "bold cyan"), (" toggle all  ", "dim"),
        ("Enter", "bold green"), (" confirm  ", "dim"),
        ("q/ESC", "bold red"), (" cancel", "dim"),
    )

    # Build output in one go to minimize flicker
    with console.capture() as capture:
        console.print()
        console.print(table, justify="center")
        console.print()
        console.print(footer, justify="center")

    import sys
    sys.stdout.write(capture.get())
    sys.stdout.flush()


def run_module_selector(
    console: Console,
    all_modules: list[str],
    current_selection: list[str],
) -> list[str] | None:
    """Run the interactive module selector.

    Returns the list of selected module names, or None if cancelled.
    """
    if console.size.height < 20:
        # Terminal too small — fall back to inline display
        console.print("[yellow]Terminal too small for interactive selector.[/yellow]")
        console.print(f"[dim]Use: set modules xss,sqli,...[/dim]")
        return None

    modules = list(all_modules)
    enabled = [m in current_selection for m in modules]
    cursor = 0

    with alternate_screen():
        _render_selector(console, modules, enabled, cursor)
        while True:
            key = read_key()
            if key == "UP":
                cursor = (cursor - 1) % len(modules)
            elif key == "DOWN":
                cursor = (cursor + 1) % len(modules)
            elif key == "SPACE":
                enabled[cursor] = not enabled[cursor]
            elif key == "a":
                # Toggle all: if all enabled, disable all; otherwise enable all
                if all(enabled):
                    enabled = [False] * len(modules)
                else:
                    enabled = [True] * len(modules)
            elif key == "ENTER":
                selected = [m for m, e in zip(modules, enabled) if e]
                if not selected:
                    # Don't allow empty selection — keep at least one
                    continue
                return selected
            elif key in ("q", "ESC"):
                return None
            else:
                continue
            _render_selector(console, modules, enabled, cursor)
