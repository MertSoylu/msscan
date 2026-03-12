"""Interactive CLI shell — preserved from V1 with V2 engine integration."""

from __future__ import annotations

import asyncio
import cmd
import time
from pathlib import Path

from rich.console import Console
from rich.table import Table

from msscan.core.engine import ScanEngine
from msscan.core.exceptions import RateLimitedError
from msscan.core.plugins import discover_scanners
from msscan.output.console import print_results, print_scan_config, print_scan_summary
from msscan.ui.overlay import show_overlay

console = Console()

# Safety bounds for rate-limit
RATE_LIMIT_MIN = 1
RATE_LIMIT_MAX = 50
RATE_LIMIT_RECOMMENDED = 10

# Maps each settable key to (human description, type-cast function)
SET_KEYS = {
    "url":        ("Target URL",                                                str),
    "modules":    ("Modules: all or xss,sqli,...",                              str),
    "rate-limit": (f"Requests/second (min {RATE_LIMIT_MIN}, max {RATE_LIMIT_MAX})", int),
    "timeout":    ("Request timeout in seconds",                                float),
    "report":     ("HTML report output path (optional)",                        str),
    "profile":    ("Speed profile: stealth, normal, aggressive",                str),
    "output":     ("Output format:path (json:out.json, sarif:out.sarif)",       str),
}

# (command_syntax, description) pairs shown by the `help` command
COMMANDS_HELP = [
    ("help",                  "List available commands"),
    ("set <key> <value>",     "Set a session option"),
    ("modules",               "Interactive module selector"),
    ("config",                "Show current settings"),
    ("scan",                  "Start the security scan"),
    ("plugins",               "List installed scanner plugins"),
    ("exit / quit",           "Exit the shell"),
]


class MsscanShell(cmd.Cmd):
    prompt = "[bold cyan]msscan>[/bold cyan] "
    use_rawinput = True

    def __init__(self) -> None:
        super().__init__()
        self._config: dict = {
            "url":        None,
            "modules":    "all",
            "rate-limit": RATE_LIMIT_RECOMMENDED,
            "timeout":    10.0,
            "report":     None,
            "profile":    "normal",
            "output":     None,
        }

    def cmdloop(self, intro=None) -> None:  # type: ignore[override]
        self.preloop()
        try:
            while True:
                try:
                    console.print("[bold cyan]msscan>[/bold cyan] ", end="")
                    line = input()
                except EOFError:
                    line = "exit"
                line = self.precmd(line)
                stop = self.onecmd(line)
                stop = self.postcmd(stop, line)
                if stop:
                    break
        finally:
            self.postloop()

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

    def do_set(self, arg: str) -> None:
        """Set a session option.  Usage: set <key> <value>"""
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

        _, cast = SET_KEYS[key]
        try:
            casted_value = cast(value)
        except (ValueError, TypeError):
            console.print(f"[red]Error:[/red] Invalid value for '{key}': {value!r}")
            return

        if key == "url":
            from msscan.utils.helpers import normalize_url
            casted_value = normalize_url(casted_value)

        if key == "report":
            p = Path(casted_value)
            if p.is_dir():
                casted_value = str(p / "msscan_report.html")
                console.print(
                    f"[yellow]⚠  report path is a directory.[/yellow] "
                    f"Using: [cyan]{casted_value}[/cyan]"
                )
            elif not p.suffix:
                casted_value = casted_value + ".html"
                console.print("[dim]  → .html extension added automatically[/dim]")

        if key == "rate-limit":
            if casted_value < RATE_LIMIT_MIN or casted_value > RATE_LIMIT_MAX:
                console.print(
                    f"[bold red]⛔ Security Limit:[/bold red] "
                    f"rate-limit must be between {RATE_LIMIT_MIN} and {RATE_LIMIT_MAX} req/s."
                )
                console.print(f"[dim]  Recommended safe value: {RATE_LIMIT_RECOMMENDED} req/s[/dim]")
                console.print("[dim]  rate-limit was not updated.[/dim]")
                return
            if casted_value > 20:
                console.print(
                    f"[yellow]⚠  Warning:[/yellow] rate-limit = {casted_value} req/s is high. "
                    f"Recommended: ≤ {RATE_LIMIT_RECOMMENDED} req/s"
                )

        if key == "profile":
            valid_profiles = ["stealth", "normal", "aggressive"]
            if casted_value not in valid_profiles:
                console.print(f"[red]Error:[/red] Unknown profile '{casted_value}'")
                console.print(f"[dim]Valid profiles: {', '.join(valid_profiles)}[/dim]")
                return

        self._config[key] = casted_value
        console.print(f"[green]✔[/green]  {key} = [bold]{self._config[key]}[/bold]")

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
            val = self._config.get(k)
            display = str(val) if val is not None else "[dim]—[/dim]"
            table.add_row(k, display, desc)
        show_overlay(console, table)

    def do_scan(self, _arg: str) -> None:
        """Start the scan."""
        url = self._config["url"]
        if not url:
            console.print("[red]Error:[/red] No target URL set.")
            console.print("[dim]  → set url https://target.com[/dim]")
            return

        # Discover available scanners dynamically
        available = discover_scanners()
        all_modules = list(available.keys())

        raw_modules = self._config["modules"]
        if raw_modules == "all":
            selected = all_modules
        else:
            selected = [m.strip().lower() for m in raw_modules.split(",")]
            invalid = [m for m in selected if m not in available]
            if invalid:
                console.print(f"[red]Error:[/red] Unknown module(s): {', '.join(invalid)}")
                console.print(f"[dim]Valid modules: {', '.join(all_modules)}[/dim]")
                return

        rate_limit = self._config["rate-limit"]
        timeout = self._config["timeout"]
        report = self._config["report"]

        if rate_limit < RATE_LIMIT_MIN or rate_limit > RATE_LIMIT_MAX:
            console.print(
                f"[bold red]⛔ Scan blocked:[/bold red] "
                f"rate-limit ({rate_limit}) is outside the safe range "
                f"({RATE_LIMIT_MIN}–{RATE_LIMIT_MAX} req/s)."
            )
            console.print(f"[dim]  → set rate-limit {RATE_LIMIT_RECOMMENDED}  (recommended)[/dim]")
            return

        # Legal disclaimer
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
            console.print("\n[dim]Scan cancelled.[/dim]")
            return

        if answer not in ("", "y", "yes"):
            console.print("[dim]Scan cancelled.[/dim]")
            return

        print_scan_config(url, selected, rate_limit, timeout)

        t0 = time.perf_counter()
        engine = ScanEngine(url=url, modules=selected, rate_limit=rate_limit, timeout=timeout)
        try:
            results = asyncio.run(engine.run())
        except RateLimitedError as exc:
            elapsed = time.perf_counter() - t0
            console.print()
            console.print(
                f"[bold red]⛔ Rate Limited![/bold red] "
                f"Target responded with HTTP {exc.status_code}."
            )
            suggested = max(RATE_LIMIT_MIN, exc.current_rate // 2)
            console.print(f"  [bold]Current rate-limit:[/bold] [yellow]{exc.current_rate} req/s[/yellow]")
            console.print(f"  [bold]Suggested value  :[/bold] [green]{suggested} req/s[/green]")
            console.print(f"\n  To continue: [cyan]set rate-limit {suggested}[/cyan]  →  [cyan]scan[/cyan]")
            console.print(f"\n[dim]Scan stopped after {elapsed:.2f}s.[/dim]")
            return
        elapsed = time.perf_counter() - t0

        print_results(results)
        print_scan_summary(url, results, elapsed)

        # Generate reports
        if report:
            from msscan.output.html_report import generate_html_report
            generate_html_report(results, url, report, elapsed_secs=elapsed)
            console.print(f"\n[bold green]✅ HTML report saved:[/bold green] {report}")

        # Handle output format
        output_spec = self._config.get("output")
        if output_spec and ":" in output_spec:
            fmt, path = output_spec.split(":", 1)
            try:
                if fmt == "json":
                    from msscan.output.json_report import generate_json_report
                    generate_json_report(results, path, url=url, elapsed_secs=elapsed)
                    console.print(f"[green]✔[/green] JSON report: {path}")
                elif fmt == "sarif":
                    from msscan.output.sarif_report import generate_sarif_report
                    generate_sarif_report(results, path, url=url, elapsed_secs=elapsed)
                    console.print(f"[green]✔[/green] SARIF report: {path}")
            except Exception as exc:
                console.print(f"[red]✗[/red] Report generation failed: {exc}")

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

    def do_modules(self, _arg: str) -> None:
        """Interactive module selector."""
        from msscan.ui.module_selector import run_module_selector

        available = discover_scanners()
        all_modules = list(available.keys())

        raw = self._config["modules"]
        if raw == "all":
            current = list(all_modules)
        else:
            current = [m.strip().lower() for m in raw.split(",")]

        result = run_module_selector(console, all_modules, current)
        if result is not None:
            if set(result) == set(all_modules):
                self._config["modules"] = "all"
                console.print("[green]✔[/green]  modules = [bold]all[/bold]")
            else:
                self._config["modules"] = ",".join(result)
                console.print(f"[green]✔[/green]  modules = [bold]{self._config['modules']}[/bold]")

    def do_plugins(self, _arg: str) -> None:
        """List installed scanner plugins."""
        from msscan.core.plugins import list_available_scanners
        from rich.table import Table

        scanners = list_available_scanners()
        table = Table(
            title="🔌 Installed Scanners",
            show_header=True,
            header_style="bold magenta",
            border_style="bright_cyan",
        )
        table.add_column("Name", style="bold cyan")
        table.add_column("Source")
        table.add_column("Version")

        for s in scanners:
            table.add_row(s["name"], s["source"], s["version"])
        show_overlay(console, table)

    def complete_set(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        args = line.split()
        if len(args) <= 2 and not (len(args) == 2 and line.endswith(" ")):
            return [k for k in SET_KEYS if k.startswith(text)]
        if len(args) >= 2 and args[1] == "modules":
            available = discover_scanners()
            return [m for m in available if m.startswith(text)]
        if len(args) >= 2 and args[1] == "profile":
            return [p for p in ["stealth", "normal", "aggressive"] if p.startswith(text)]
        return []

    def complete_help(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        commands = [c[0].split()[0] for c in COMMANDS_HELP]
        return [c for c in commands if c.startswith(text)]

    def do_exit(self, _arg: str) -> bool:
        console.print("\n[dim]Goodbye! 👋[/dim]\n")
        return True

    def do_quit(self, arg: str) -> bool:
        return self.do_exit(arg)

    def default(self, line: str) -> None:
        console.print(f"[red]Unknown command:[/red] {line!r}  (type [dim]help[/dim] to see available commands)")

    def emptyline(self) -> None:
        pass
