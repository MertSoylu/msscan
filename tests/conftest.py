"""Shared fixtures and helpers for msscan test suite."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from msscan.core.config import ScanConfig
from msscan.core.context import ScanContext
from msscan.core.events import FindingEvent
from msscan.core.http_client import HttpClient
from msscan.core.result import ScanResult


@pytest.fixture
def make_mock_context():
    """Create a ready-to-use ScanContext for unit tests."""
    def _make(
        url: str,
        *,
        client: HttpClient | None = None,
        modules: list[str] | None = None,
        config: ScanConfig | None = None,
    ) -> ScanContext:
        if client is None:
            client = MagicMock(spec=HttpClient)
            client.get = AsyncMock()
        if config is None:
            config = ScanConfig(targets=[url], modules=modules or ["xss"])
        return ScanContext(target=url, client=client, config=config)

    return _make


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
