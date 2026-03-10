"""Shared fixtures and helpers for msscan test suite."""

from __future__ import annotations

from msscan.core.config import ScanConfig
from msscan.core.context import ScanContext
from msscan.core.events import FindingEvent
from msscan.core.http_client import HttpClient
from msscan.core.result import ScanResult


async def collect_results(scanner, url: str, client: HttpClient) -> list[ScanResult]:
    """Run a scanner with the V2 ScanContext protocol and collect results.

    Replaces the old ``await scanner.scan(url, client)`` pattern used in V1 tests.
    """
    ctx = ScanContext(
        target=url,
        client=client,
        config=ScanConfig(targets=[url], modules=[scanner.name]),
    )
    results: list[ScanResult] = []
    async for event in scanner.scan(ctx):
        if isinstance(event, FindingEvent):
            results.append(event.result)
    return results
