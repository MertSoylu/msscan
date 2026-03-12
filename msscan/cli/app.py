"""Typer-based CLI app with subcommand routing.

Supports two modes:
- No arguments: launches interactive shell (backward compatible)
- Subcommands: headless scan, config, plugins
"""

from __future__ import annotations

import sys
import keyword
import textwrap
from pathlib import Path
from typing import Optional

import typer

from msscan.cli.interactive import MsscanShell
from msscan.output.console import print_banner

cli = typer.Typer(
    name="msscan",
    help="msscan — Web Application Security Scanner",
    add_completion=False,
    invoke_without_command=True,
    no_args_is_help=False,
)


@cli.callback()
def main(ctx: typer.Context) -> None:
    """msscan — Web Application Security Scanner.

    Run without arguments for interactive shell, or use subcommands.
    """
    if ctx.invoked_subcommand is None:
        # No subcommand = interactive shell (backward compatible)
        _run_interactive()


def _run_interactive() -> None:
    """Launch the interactive shell."""
    from rich.console import Console
    console = Console()
    print_banner()
    console.print("[dim]  Type 'help' to list commands. Type 'exit' to quit.[/dim]\n")
    try:
        MsscanShell().cmdloop()
    except KeyboardInterrupt:
        console.print("\n[dim]Exiting...[/dim]\n")
        sys.exit(0)


@cli.command()
def scan(
    url: str = typer.Option(
        ..., "--url", "-u", help="Target URL to scan"
    ),
    modules: str = typer.Option(
        "all", "--modules", "-m", help="Comma-separated module list or 'all'"
    ),
    profile: str = typer.Option(
        "normal", "--profile", "-p",
        help="Speed profile: stealth, normal, aggressive"
    ),
    output: Optional[list[str]] = typer.Option(
        None, "--output", "-o",
        help="Output format:path (e.g. json:results.json, sarif:results.sarif, html:report.html)"
    ),
    targets_file: Optional[Path] = typer.Option(
        None, "--list", "-l",
        help="File with target URLs (one per line), use '-' for stdin"
    ),
    timeout: float = typer.Option(
        10.0, "--timeout", "-t", help="Request timeout in seconds"
    ),
    rate_limit: int = typer.Option(
        0, "--rate-limit", "-r",
        help="Override rate limit (req/s). 0 = use profile default"
    ),
    fail_on: str = typer.Option(
        "HIGH,CRITICAL", "--fail-on",
        help="Comma-separated severity levels that trigger exit code 1"
    ),
    no_banner: bool = typer.Option(
        False, "--no-banner", help="Suppress banner output"
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip legal consent prompt"
    ),
) -> None:
    """Run a headless security scan."""
    from msscan.cli.headless import run_headless_scan

    # Collect targets
    targets: list[str] = []
    if targets_file:
        if str(targets_file) == "-":
            targets = [line.strip() for line in sys.stdin if line.strip()]
        else:
            targets = [
                line.strip()
                for line in targets_file.read_text().splitlines()
                if line.strip() and not line.startswith("#")
            ]
    else:
        targets = [url]

    # Parse output formats
    output_formats: dict[str, str] = {}
    if output:
        for spec in output:
            if ":" in spec:
                fmt, path = spec.split(":", 1)
                output_formats[fmt] = path
            else:
                output_formats[spec] = f"msscan-results.{spec}"

    # Parse fail_on
    fail_on_levels = [s.strip().upper() for s in fail_on.split(",")]

    # Parse modules
    module_list = (
        ["xss", "sqli", "csrf", "open_redirect", "ssrf", "headers", "subdomain"]
        if modules == "all"
        else [m.strip().lower() for m in modules.split(",")]
    )

    exit_code = run_headless_scan(
        targets=targets,
        modules=module_list,
        profile=profile,
        timeout=timeout,
        rate_limit_override=rate_limit if rate_limit > 0 else None,
        output_formats=output_formats,
        fail_on=fail_on_levels,
        no_banner=no_banner,
        skip_consent=yes,
    )
    raise SystemExit(exit_code)


@cli.command(name="config")
def config_cmd(
    init: bool = typer.Option(
        False, "--init", help="Generate a msscan.toml config template"
    ),
    show: bool = typer.Option(
        False, "--show", help="Show resolved configuration"
    ),
) -> None:
    """Manage msscan configuration."""
    from rich.console import Console
    console = Console()

    if init:
        from msscan.core.config import generate_config_template
        template = generate_config_template()
        Path("msscan.toml").write_text(template, encoding="utf-8")
        console.print("[green]✔[/green] Generated msscan.toml")
        return

    if show:
        from msscan.core.config import load_config
        config = load_config()
        console.print(f"  [bold]Profile:[/bold]   {config.speed_profile.value}")
        console.print(f"  [bold]Rate:[/bold]      {config.rate_limit} req/s")
        console.print(f"  [bold]Timeout:[/bold]   {config.timeout}s")
        console.print(f"  [bold]Modules:[/bold]   {', '.join(config.modules)}")
        console.print(f"  [bold]Cache:[/bold]     {config.cache_enabled}")
        if config.config_file:
            console.print(f"  [bold]File:[/bold]      {config.config_file}")
        return

    console.print("[dim]Use --init to generate config or --show to display current config[/dim]")


@cli.command()
def plugins() -> None:
    """List installed scanner plugins."""
    from rich.console import Console
    from rich.table import Table

    from msscan.core.plugins import list_available_scanners

    console = Console()
    scanners = list_available_scanners()

    table = Table(
        title="🔌 Installed Scanners",
        show_header=True,
        header_style="bold magenta",
        border_style="bright_cyan",
    )
    table.add_column("Name", style="bold cyan")
    table.add_column("Version")
    table.add_column("Source")
    table.add_column("Description", style="dim")

    for s in scanners:
        source_style = {
            "built-in": "[green]built-in[/green]",
            "entry-point": "[yellow]entry-point[/yellow]",
            "local": "[blue]local[/blue]",
        }.get(s["source"], s["source"])
        table.add_row(s["name"], s["version"], source_style, s["description"])

    console.print(table)


@cli.command(name="new-plugin")
def new_plugin(name: str = typer.Argument(..., help="Plugin name (Python identifier)")) -> None:
    """Create a new local plugin scaffold in ~/.msscan/plugins/."""
    from rich.console import Console
    import msscan.core.plugins as plugins

    console = Console()

    if not name.isidentifier() or keyword.iskeyword(name):
        raise typer.BadParameter("Plugin name must be a valid Python identifier.")

    plugin_dir = plugins._PLUGIN_DIR
    plugin_dir.mkdir(parents=True, exist_ok=True)
    plugin_path = plugin_dir / f"{name}.py"

    if plugin_path.exists():
        console.print(f"[red]✗[/red] Plugin already exists: {plugin_path}")
        raise typer.Exit(code=1)

    template = textwrap.dedent(f"""\
    # Generated by: msscan new-plugin {name}
    from msscan.scanners.base import BaseScanner
    from msscan.core.context import ScanContext
    from msscan.core.events import ScanEvent, FindingEvent, ProgressEvent
    from msscan.core.result import ScanResult

    class Scanner(BaseScanner):
        name = "{name}"
        description = "Describe what this scanner checks"
        author = "Your Name"

        @property
        def version(self) -> str:
            return "1.0"

        async def scan(self, ctx: ScanContext):
            # ctx.target    -> target URL
            # ctx.client    -> HttpClient (await ctx.client.get(url))
            # ctx.is_cancelled -> cooperative cancellation flag

            yield ProgressEvent(scanner_name=self.name, current=0, total=1, message="Starting...")

            # To emit a finding:
            # yield FindingEvent(result=ScanResult(
            #     scanner=self.name,
            #     severity="HIGH",   # CRITICAL | HIGH | MEDIUM | LOW | INFO
            #     url=ctx.target,
            #     detail="What was found",
            #     evidence="Proof",
            #     confidence="HIGH",
            #     confidence_score=0.9,
            #     cvss_score=0.0,
            #     cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            #     exploit_scenario="Short exploit description",
            #     cwe_id="CWE-XXX",
            #     remediation="How to fix",
            # ))

            yield ProgressEvent(scanner_name=self.name, current=1, total=1, message="Done")
    """)

    plugin_path.write_text(template, encoding="utf-8")
    console.print(f"[green]✔[/green] Created plugin scaffold: {plugin_path}")


def app() -> None:
    """Main entry point — delegates to typer CLI."""
    cli()
