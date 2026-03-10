"""Scan engine — parallel asyncio orchestrator for all scanner modules."""

from __future__ import annotations

import asyncio
from typing import AsyncIterator

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from msscan.core.config import ScanConfig, SpeedProfile
from msscan.core.context import ScanContext
from msscan.core.events import ScanEvent, FindingEvent, ProgressEvent, ErrorEvent
from msscan.core.http_client import HttpClient
from msscan.core.plugins import discover_scanners
from msscan.core.result import ScanResult

console = Console()


class ScanEngine:
    """Main engine that orchestrates all scanner modules in parallel.

    V2 improvements:
    - All scanners run concurrently via asyncio.gather()
    - Event-driven: scanners yield ScanEvent instances in real-time
    - Shared HttpClient with caching and adaptive rate limiting
    - Cooperative cancellation via cancel_token
    """

    def __init__(
        self,
        url: str,
        modules: list[str],
        rate_limit: int = 10,
        timeout: float = 10.0,
        config: ScanConfig | None = None,
    ):
        self.url = url
        self.modules = modules
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.config = config or ScanConfig(
            targets=[url],
            modules=modules,
            rate_limit=rate_limit,
            timeout=timeout,
        )

    async def run(self) -> list[ScanResult]:
        """Run all selected scanners in parallel and return collected results.

        This is the simple convenience method that collects all findings.
        For real-time event streaming, use run_stream().
        """
        all_results: list[ScanResult] = []
        all_errors: list[str] = []

        async with HttpClient(
            timeout=self.timeout,
            rate_limit=self.rate_limit,
            max_response_size=self.config.max_response_size,
            retry_count=self.config.retry_count,
            jitter=self.config.jitter,
            cache_enabled=self.config.cache_enabled,
        ) as client:
            ctx = ScanContext(
                target=self.url,
                client=client,
                config=self.config,
            )

            # Discover and instantiate scanners
            available = discover_scanners()
            scanners = []
            for name in self.modules:
                if name in available:
                    scanners.append((name, available[name]()))

            if not scanners:
                return all_results

            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
            ) as progress:
                main_task = progress.add_task(
                    "Scanning", total=len(scanners)
                )

                # Create per-scanner tasks
                scanner_tasks = []
                for name, scanner in scanners:
                    scanner_tasks.append(
                        self._run_scanner_task(
                            name, scanner, ctx, progress, main_task
                        )
                    )

                # Run all scanners in parallel
                task_results = await asyncio.gather(
                    *scanner_tasks, return_exceptions=True
                )

                for i, result in enumerate(task_results):
                    name = scanners[i][0]
                    if isinstance(result, Exception):
                        console.print(
                            f"  [bold red]✗ {name}:[/bold red] {result}"
                        )
                        all_errors.append(f"{name}: {result}")
                    elif isinstance(result, list):
                        all_results.extend(result)

        return all_results

    async def _run_scanner_task(
        self,
        name: str,
        scanner,
        ctx: ScanContext,
        progress: Progress,
        main_task,
    ) -> list[ScanResult]:
        """Run a single scanner, collecting its results."""
        results: list[ScanResult] = []
        try:
            progress.update(
                main_task,
                description=f"[{name.upper()}] scanning...",
            )
            async for event in scanner.scan(ctx):
                if isinstance(event, FindingEvent):
                    results.append(event.result)
                elif isinstance(event, ProgressEvent):
                    pass  # Could update per-scanner progress in future TUI
                elif isinstance(event, ErrorEvent):
                    console.print(
                        f"  [dim red]⚠ {name}: {event.error}[/dim red]"
                    )
        except Exception as exc:
            console.print(f"  [bold red]✗ {name}:[/bold red] {exc}")
        finally:
            progress.advance(main_task)
        return results

    async def run_stream(self) -> AsyncIterator[ScanEvent]:
        """Run all scanners and yield events as they occur.

        This is the streaming API for real-time output (TUI dashboard, etc).
        """
        async with HttpClient(
            timeout=self.timeout,
            rate_limit=self.rate_limit,
            max_response_size=self.config.max_response_size,
            retry_count=self.config.retry_count,
            jitter=self.config.jitter,
            cache_enabled=self.config.cache_enabled,
        ) as client:
            ctx = ScanContext(
                target=self.url,
                client=client,
                config=self.config,
            )

            available = discover_scanners()
            scanners = []
            for name in self.modules:
                if name in available:
                    scanners.append((name, available[name]()))

            if not scanners:
                return

            # Use an asyncio.Queue to merge events from all scanners
            queue: asyncio.Queue[ScanEvent | None] = asyncio.Queue()
            active_count = len(scanners)

            async def _scanner_worker(name: str, scanner) -> None:
                """Run a scanner and put its events into the shared queue."""
                try:
                    async for event in scanner.scan(ctx):
                        await queue.put(event)
                except Exception as exc:
                    await queue.put(ErrorEvent(
                        scanner_name=name,
                        error=str(exc),
                        exception=exc,
                    ))
                finally:
                    await queue.put(None)  # Signal completion

            # Start all scanner tasks
            tasks = [
                asyncio.create_task(_scanner_worker(name, scanner))
                for name, scanner in scanners
            ]

            # Yield events as they arrive
            completed = 0
            while completed < active_count:
                event = await queue.get()
                if event is None:
                    completed += 1
                    continue
                yield event

            # Ensure all tasks are done
            await asyncio.gather(*tasks, return_exceptions=True)
