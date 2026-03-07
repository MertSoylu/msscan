"""Interactive CLI shell entry point for msscan."""

from __future__ import annotations

import asyncio
import cmd
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.table import Table

from msscan import __version__
from msscan.core.engine import ScanEngine
from msscan.core.exceptions import RateLimitedError
from msscan.output.console import print_banner, print_results, print_scan_config, print_scan_summary
from msscan.ui.overlay import show_overlay

console = Console()

# Full list of available scanner modules — used for "all" resolution and validation
ALL_MODULES = ["xss", "sqli", "csrf", "open_redirect", "ssrf", "headers", "subdomain"]

# (command_syntax, description) pairs shown by the `help` command
COMMANDS_HELP = [
    ("help",                  "List available commands"),
    ("set <key> <value>",     "Set a session option (url, modules, rate-limit, timeout, report)"),
    ("modules",               "Interactive module selector"),
    ("config",                "Show current settings"),
    ("scan",                  "Start the security scan"),
    ("exit / quit",           "Exit the shell"),
]

# Safety bounds for rate-limit — enforced both on set and on scan
RATE_LIMIT_MIN = 1
RATE_LIMIT_MAX = 50
RATE_LIMIT_RECOMMENDED = 10  # shown as suggestion when user sets a high or invalid value

# Maps each settable key to (human description, type-cast function)
SET_KEYS = {
    "url":        ("Target URL",                                                str),
    "modules":    ("Modules: all or xss,sqli,...",                              str),
    "rate-limit": (f"Requests/second (min {RATE_LIMIT_MIN}, max {RATE_LIMIT_MAX})", int),
    "timeout":    ("Request timeout in seconds",                                float),
    "report":     ("HTML report output path (optional)",                        str),
}


class MsscanShell(cmd.Cmd):
    prompt = "[bold cyan]msscan>[/bold cyan] "
    use_rawinput = True  # use built-in input() so readline history works on supported platforms

    def __init__(self) -> None:
        super().__init__()
        # Session-scoped config; resets every time the shell is started
        self._config: dict = {
            "url":        None,
            "modules":    "all",
            "rate-limit": RATE_LIMIT_RECOMMENDED,
            "timeout":    10.0,
            "report":     None,
        }

    # ------------------------------------------------------------------ prompt
    def cmdloop(self, intro=None) -> None:  # type: ignore[override]
        """Override to render Rich markup in the prompt string."""
        self.preloop()
        try:
            while True:
                try:
                    # cmd.Cmd normally prints self.prompt via write(); we use Rich instead
                    console.print(f"[bold cyan]msscan>[/bold cyan] ", end="")
                    line = input()
                except EOFError:
                    # Ctrl+D or end of piped input — treat as exit
                    line = "exit"
                line = self.precmd(line)
                stop = self.onecmd(line)
                stop = self.postcmd(stop, line)
                if stop:
                    break
        finally:
            self.postloop()

    # ------------------------------------------------------------------ help
    def do_help(self, _arg: str) -> None:
        """List available commands."""
        table = Table(
            title="📖 msscan Commands",
            show_header=True,
            header_style="bold magenta",
            border_style="bright_cyan",
        )
        table.add_column("Command", style="bold cyan", min_width=30)
        table.add_column("Description")
        for cmd_name, desc in COMMANDS_HELP:
            table.add_row(cmd_name, desc)
        show_overlay(console, table)

    # ------------------------------------------------------------------ set
    def do_set(self, arg: str) -> None:
        """Set a session option.  Usage: set <key> <value>"""
        # Split on first whitespace only so values with spaces are kept intact
        parts = arg.strip().split(None, 1)
        if len(parts) < 2:
            console.print("[red]Usage:[/red] set <key> <value>")
            console.print(f"[dim]Valid keys: {', '.join(SET_KEYS)}[/dim]")
            return

        key, value = parts[0].lower(), parts[1].strip()

        if key not in SET_KEYS:
            console.print(f"[red]Error:[/red] Unknown key '{key}'")
            console.print(f"[dim]Valid keys: {', '.join(SET_KEYS)}[/dim]")
            return

        # Cast the raw string to the expected type (int, float, or str)
        _, cast = SET_KEYS[key]
        try:
            casted_value = cast(value)
        except (ValueError, TypeError):
            console.print(f"[red]Error:[/red] Invalid value for '{key}': {value!r}")
            return

        if key == "url":
            # Auto-prepend https:// when the user omits the scheme
            from msscan.utils.helpers import normalize_url
            casted_value = normalize_url(casted_value)

        if key == "report":
            p = Path(casted_value)
            if p.is_dir():
                # Path points to a directory — append a default filename
                casted_value = str(p / "msscan_report.html")
                console.print(
                    f"[yellow]⚠  report path is a directory.[/yellow] "
                    f"Using: [cyan]{casted_value}[/cyan]"
                )
            elif not p.suffix:
                # No extension given — append .html
                casted_value = casted_value + ".html"
                console.print(f"[dim]  → .html extension added automatically[/dim]")

        if key == "rate-limit":
            # Hard block: values outside 1–50 are refused outright
            if casted_value < RATE_LIMIT_MIN or casted_value > RATE_LIMIT_MAX:
                console.print(
                    f"[bold red]⛔ Security Limit:[/bold red] "
                    f"rate-limit must be between {RATE_LIMIT_MIN} and {RATE_LIMIT_MAX} req/s."
                )
                console.print(f"[dim]  Recommended safe value: {RATE_LIMIT_RECOMMENDED} req/s[/dim]")
                console.print("[dim]  rate-limit was not updated.[/dim]")
                return
            # Soft warning: values above 20 are accepted but flagged as aggressive
            if casted_value > 20:
                console.print(
                    f"[yellow]⚠  Warning:[/yellow] rate-limit = {casted_value} req/s is high. "
                    f"Recommended: ≤ {RATE_LIMIT_RECOMMENDED} req/s"
                )

        self._config[key] = casted_value
        console.print(f"[green]✔[/green]  {key} = [bold]{self._config[key]}[/bold]")

    # ------------------------------------------------------------------ config
    def do_config(self, _arg: str) -> None:
        """Show current session settings."""
        table = Table(
            title="⚙  Current Settings",
            show_header=True,
            header_style="bold magenta",
            border_style="bright_cyan",
        )
        table.add_column("Key", style="bold cyan")
        table.add_column("Value")
        table.add_column("Description", style="dim")
        for k, (desc, _) in SET_KEYS.items():
            val = self._config[k]
            display = str(val) if val is not None else "[dim]—[/dim]"
            table.add_row(k, display, desc)
        show_overlay(console, table)

    # ------------------------------------------------------------------ scan
    def do_scan(self, _arg: str) -> None:
        """Start the scan (set a URL first with 'set url <target>')."""
        url = self._config["url"]
        if not url:
            console.print("[red]Error:[/red] No target URL set.")
            console.print("[dim]  → set url https://target.com[/dim]")
            return

        # Resolve "all" shorthand to the full module list, or validate explicit list
        raw_modules = self._config["modules"]
        if raw_modules == "all":
            selected = ALL_MODULES
        else:
            selected = [m.strip().lower() for m in raw_modules.split(",")]
            invalid = [m for m in selected if m not in ALL_MODULES]
            if invalid:
                console.print(f"[red]Error:[/red] Unknown module(s): {', '.join(invalid)}")
                console.print(f"[dim]Valid modules: {', '.join(ALL_MODULES)}[/dim]")
                return

        rate_limit = self._config["rate-limit"]
        timeout = self._config["timeout"]
        report = self._config["report"]

        # Second guard: catches cases where _config was mutated directly (e.g. in tests)
        if rate_limit < RATE_LIMIT_MIN or rate_limit > RATE_LIMIT_MAX:
            console.print(
                f"[bold red]⛔ Scan blocked:[/bold red] "
                f"rate-limit ({rate_limit}) is outside the safe range "
                f"({RATE_LIMIT_MIN}–{RATE_LIMIT_MAX} req/s)."
            )
            console.print(f"[dim]  → set rate-limit {RATE_LIMIT_RECOMMENDED}  (recommended)[/dim]")
            return

        # Show legal disclaimer and require explicit consent before every scan
        from rich.panel import Panel
        console.print()
        console.print(Panel(
            f"  This tool may only be used on systems you [bold]have explicit written permission[/bold] to test.\n"
            f"  Unauthorized scanning is [bold red]illegal[/bold red] and may result in criminal or civil liability.\n\n"
            f"  [bold]Target:[/bold] [cyan]{url}[/cyan]",
            title="[bold yellow]⚖  Legal Usage Warning[/bold yellow]",
            border_style="yellow",
            expand=False,
        ))
        try:
            answer = input("  Do you have permission to scan this target? [Y/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            # Piped input ended or user pressed Ctrl+C during the prompt
            console.print("\n[dim]Scan cancelled.[/dim]")
            return

        # Only "y", "yes", or blank Enter proceed; anything else cancels
        if answer not in ("", "y", "yes"):
            console.print("[dim]Scan cancelled.[/dim]")
            return

        print_scan_config(url, selected, rate_limit, timeout)

        # Measure wall-clock time for the scan summary and HTML report
        t0 = time.perf_counter()
        engine = ScanEngine(url=url, modules=selected, rate_limit=rate_limit, timeout=timeout)
        try:
            results = asyncio.run(engine.run())
        except RateLimitedError as exc:
            # Target is blocking us — surface the error and suggest a lower rate
            elapsed = time.perf_counter() - t0
            console.print()
            console.print(
                f"[bold red]⛔ Rate Limited![/bold red] "
                f"Target responded with HTTP {exc.status_code}."
            )
            # Suggest half the current rate, but never below the minimum
            suggested = max(RATE_LIMIT_MIN, exc.current_rate // 2)
            console.print(f"  [bold]Current rate-limit:[/bold] [yellow]{exc.current_rate} req/s[/yellow]")
            console.print(f"  [bold]Suggested value  :[/bold] [green]{suggested} req/s[/green]")
            console.print(f"\n  To continue: [cyan]set rate-limit {suggested}[/cyan]  →  [cyan]scan[/cyan]")
            console.print(f"\n[dim]Scan stopped after {elapsed:.2f}s.[/dim]")
            return
        elapsed = time.perf_counter() - t0

        print_results(results)
        print_scan_summary(url, results, elapsed)

        if report:
            from msscan.output.html_report import generate_html_report
            generate_html_report(results, url, report, elapsed_secs=elapsed)
            console.print(f"\n[bold green]✅ HTML report saved:[/bold green] {report}")

        total = len(results)
        if total == 0:
            console.print("\n[bold green]✅ Scan complete. No vulnerabilities found.[/bold green]")
        else:
            console.print(f"\n[bold yellow]⚠  Scan complete. {total} finding(s) detected.[/bold yellow]")
            console.print("[dim]  Press [bold]v[/bold] to view results interactively, or [bold]Enter[/bold] to continue...[/dim]")
            try:
                from msscan.ui.overlay import read_key
                key = read_key()
                if key == "v":
                    from msscan.ui.results_viewer import run_results_viewer
                    run_results_viewer(console, results)
            except (EOFError, KeyboardInterrupt):
                pass

    # ------------------------------------------------------------------ modules
    def do_modules(self, _arg: str) -> None:
        """Interactive module selector."""
        from msscan.ui.module_selector import run_module_selector

        raw = self._config["modules"]
        if raw == "all":
            current = list(ALL_MODULES)
        else:
            current = [m.strip().lower() for m in raw.split(",")]

        result = run_module_selector(console, ALL_MODULES, current)
        if result is not None:
            if set(result) == set(ALL_MODULES):
                self._config["modules"] = "all"
                console.print("[green]✔[/green]  modules = [bold]all[/bold]")
            else:
                self._config["modules"] = ",".join(result)
                console.print(f"[green]✔[/green]  modules = [bold]{self._config['modules']}[/bold]")

    # ------------------------------------------------------------------ tab completion
    def complete_set(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        """Tab-complete for the set command."""
        args = line.split()
        if len(args) <= 2 and not (len(args) == 2 and line.endswith(" ")):
            # Completing the key name
            return [k for k in SET_KEYS if k.startswith(text)]
        # Completing the value — only useful for modules
        if len(args) >= 2 and args[1] == "modules":
            return [m for m in ALL_MODULES if m.startswith(text)]
        return []

    def complete_help(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        """Tab-complete for help topics."""
        commands = [c[0].split()[0] for c in COMMANDS_HELP]
        return [c for c in commands if c.startswith(text)]

    # ------------------------------------------------------------------ exit / quit
    def do_exit(self, _arg: str) -> bool:
        """Exit the shell."""
        console.print("\n[dim]Goodbye! 👋[/dim]\n")
        return True  # returning True signals cmd.Cmd to stop the loop

    def do_quit(self, arg: str) -> bool:
        """Exit the shell."""
        return self.do_exit(arg)

    def default(self, line: str) -> None:
        console.print(f"[red]Unknown command:[/red] {line!r}  (type [dim]help[/dim] to see available commands)")

    def emptyline(self) -> None:
        pass  # suppress cmd.Cmd default of re-running the last command


def app() -> None:
    """msscan interactive shell entry point."""
    print_banner()
    console.print("[dim]  Type 'help' to list commands. Type 'exit' to quit.[/dim]\n")
    try:
        MsscanShell().cmdloop()
    except KeyboardInterrupt:
        console.print("\n[dim]Exiting...[/dim]\n")
        sys.exit(0)
