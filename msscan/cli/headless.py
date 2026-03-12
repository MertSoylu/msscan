"""Headless scan mode — one-shot CLI scan without interactive shell."""

from __future__ import annotations

import asyncio
import time

from rich.console import Console
from rich.panel import Panel

from msscan.core.config import ScanConfig, SpeedProfile, PROFILE_DEFAULTS
from msscan.core.engine import ScanEngine
from msscan.core.exceptions import RateLimitedError
from msscan.core.result import ScanResult
from msscan.output.console import print_banner, print_results, print_scan_config, print_scan_summary
from msscan.utils.helpers import normalize_url

console = Console()


def run_headless_scan(
    targets: list[str],
    modules: list[str],
    profile: str = "normal",
    timeout: float = 10.0,
    rate_limit_override: int | None = None,
    output_formats: dict[str, str] | None = None,
    fail_on: list[str] | None = None,
    no_banner: bool = False,
    skip_consent: bool = False,
) -> int:
    """Execute a headless scan and return exit code.

    Returns:
        0 = clean (no findings matching fail_on)
        1 = findings detected (matching fail_on severities)
        2 = scan error
        3 = configuration error
    """
    if not targets:
        console.print("[red]Error:[/red] No targets specified.")
        return 3

    if not modules:
        console.print("[red]Error:[/red] No modules specified.")
        return 3

    output_formats = output_formats or {}
    fail_on = fail_on or ["HIGH", "CRITICAL"]

    # Resolve speed profile
    try:
        speed_profile = SpeedProfile(profile)
    except ValueError:
        console.print(f"[red]Error:[/red] Unknown profile '{profile}'. Use: stealth, normal, aggressive")
        return 3

    # Determine rate limit
    profile_defaults = PROFILE_DEFAULTS.get(speed_profile.value, {})
    rate_limit = rate_limit_override or profile_defaults.get("rate_limit", 10)

    config = ScanConfig(
        targets=targets,
        modules=modules,
        speed_profile=speed_profile,
        rate_limit=rate_limit,
        timeout=timeout,
        output_formats=list(output_formats.keys()) or ["console"],
        output_paths=output_formats,
        fail_on=fail_on,
    )

    if not no_banner:
        print_banner()

    # Legal consent (skip with --yes flag)
    if not skip_consent:
        console.print()
        console.print(Panel(
            "  This tool may only be used on systems you [bold]have explicit written permission[/bold] to test.\n"
            "  Unauthorized scanning is [bold red]illegal[/bold red] and may result in criminal or civil liability.",
            title="[bold yellow]⚖  Legal Usage Warning[/bold yellow]",
            border_style="yellow",
            expand=False,
        ))
        try:
            answer = input("  Do you have permission to scan? [Y/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Scan cancelled.[/dim]")
            return 0
        if answer not in ("", "y", "yes"):
            console.print("[dim]Scan cancelled.[/dim]")
            return 0

    all_results: list[ScanResult] = []
    total_elapsed = 0.0

    for target_url in targets:
        target_url = normalize_url(target_url)

        if len(targets) > 1:
            console.print(f"\n[bold cyan]━━━ Target: {target_url} ━━━[/bold cyan]")

        print_scan_config(target_url, modules, rate_limit, timeout)

        t0 = time.perf_counter()
        engine = ScanEngine(
            url=target_url,
            modules=modules,
            rate_limit=rate_limit,
            timeout=timeout,
            config=config,
        )

        try:
            results = asyncio.run(engine.run())
        except RateLimitedError as exc:
            elapsed = time.perf_counter() - t0
            console.print(
                f"\n[bold red]⛔ Rate Limited![/bold red] HTTP {exc.status_code} "
                f"on {target_url}"
            )
            console.print(f"[dim]Scan stopped after {elapsed:.2f}s.[/dim]")
            return 2
        except Exception as exc:
            console.print(f"\n[bold red]✗ Scan error:[/bold red] {exc}")
            return 2

        elapsed = time.perf_counter() - t0
        total_elapsed += elapsed
        all_results.extend(results)

        print_results(results)
        print_scan_summary(target_url, results, elapsed)

    # Generate output files
    _write_outputs(all_results, targets, output_formats, total_elapsed)

    # Summary for multi-target
    if len(targets) > 1:
        console.print(
            f"\n[bold]Total: {len(all_results)} finding(s) across "
            f"{len(targets)} target(s) in {total_elapsed:.2f}s[/bold]"
        )

    # Determine exit code based on fail_on severities
    has_failures = any(r.severity in fail_on for r in all_results)
    if has_failures:
        console.print(
            f"\n[bold yellow]⚠  Findings match fail-on severities: "
            f"{', '.join(fail_on)}[/bold yellow]"
        )
        return 1

    if all_results:
        console.print(
            "\n[bold green]✅ Scan complete. Findings detected but below fail-on threshold.[/bold green]"
        )
    else:
        console.print(
            "\n[bold green]✅ Scan complete. No vulnerabilities found.[/bold green]"
        )
    return 0


def _write_outputs(
    results: list[ScanResult],
    targets: list[str],
    output_formats: dict[str, str],
    elapsed: float,
) -> None:
    """Write results to configured output formats."""
    url = targets[0] if len(targets) == 1 else f"{len(targets)} targets"

    for fmt, path in output_formats.items():
        try:
            if fmt == "json":
                from msscan.output.json_report import generate_json_report
                generate_json_report(results, path, url=url, elapsed_secs=elapsed)
                console.print(f"[green]✔[/green] JSON report: {path}")

            elif fmt == "sarif":
                from msscan.output.sarif_report import generate_sarif_report
                generate_sarif_report(results, path, url=url, elapsed_secs=elapsed)
                console.print(f"[green]✔[/green] SARIF report: {path}")

            elif fmt == "html":
                from msscan.output.html_report import generate_html_report
                generate_html_report(results, url, path, elapsed_secs=elapsed)
                console.print(f"[green]✔[/green] HTML report: {path}")

        except Exception as exc:
            console.print(f"[red]✗[/red] Failed to write {fmt} report: {exc}")
