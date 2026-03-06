"""Scan engine — asyncio orchestrator for all scanner modules."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from msscan.core.http_client import HttpClient
from msscan.core.result import ScanResult

if TYPE_CHECKING:
    from msscan.scanners.base import BaseScanner

console = Console()

# Maps the short CLI name to the full importlib module path
SCANNER_MAP: dict[str, str] = {
    "xss":           "msscan.scanners.xss",
    "sqli":          "msscan.scanners.sqli",
    "csrf":          "msscan.scanners.csrf",
    "open_redirect": "msscan.scanners.open_redirect",
    "ssrf":          "msscan.scanners.ssrf",
    "headers":       "msscan.scanners.headers",
    "subdomain":     "msscan.scanners.subdomain",
}


def _load_scanner(name: str) -> "BaseScanner":
    """Dynamically load a scanner module by name."""
    import importlib

    # Lazy import avoids loading all scanners when only a subset is requested
    module = importlib.import_module(SCANNER_MAP[name])
    # Convention: every scanner module exposes exactly one class called Scanner
    return module.Scanner()


class ScanEngine:
    """Main engine that orchestrates all scanner modules."""

    def __init__(
        self,
        url: str,
        modules: list[str],
        rate_limit: int = 0,
        timeout: float = 10.0,
    ):
        self.url = url
        self.modules = modules
        self.rate_limit = rate_limit
        self.timeout = timeout

    async def run(self) -> list[ScanResult]:
        """Run all selected scanners asynchronously."""
        all_results: list[ScanResult] = []

        # A single HttpClient is shared across all scanners so rate-limit is global
        async with HttpClient(timeout=self.timeout, rate_limit=self.rate_limit) as client:
            # Skip any module name not in SCANNER_MAP (unknown modules)
            scanners = [
                (name, _load_scanner(name))
                for name in self.modules
                if name in SCANNER_MAP
            ]

            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
            ) as progress:
                main_task = progress.add_task("Scanning", total=len(scanners))

                for name, scanner in scanners:
                    progress.update(main_task, description=f"[{name.upper()}] scanning...")
                    try:
                        results = await scanner.scan(self.url, client)
                        all_results.extend(results)
                    except Exception as exc:
                        # Scanner errors are non-fatal; log and continue with remaining modules
                        console.print(f"  [bold red]✗ {name}:[/bold red] {exc}")
                    progress.advance(main_task)

        return all_results
