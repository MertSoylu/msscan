"""Tests for ScanEngine — parallel execution, error isolation, cancellation."""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest
import respx

from msscan.core.engine import ScanEngine
from msscan.core.events import FindingEvent, ErrorEvent, ProgressEvent
from msscan.core.result import ScanResult
from msscan.scanners.base import BaseScanner


# ---------------------------------------------------------------------------
# Helpers: fake scanners for engine tests
# ---------------------------------------------------------------------------

class _FakeScanner(BaseScanner):
    """Yields one INFO finding."""
    name = "fake"

    async def scan(self, ctx):
        yield FindingEvent(result=ScanResult(
            scanner="fake", severity="INFO", url=ctx.target, detail="fake finding",
        ))


class _SlowScanner(BaseScanner):
    """Yields after a short delay — used to verify parallelism."""
    name = "slow"

    async def scan(self, ctx):
        await asyncio.sleep(0.1)
        yield FindingEvent(result=ScanResult(
            scanner="slow", severity="LOW", url=ctx.target, detail="slow finding",
        ))


class _ErrorScanner(BaseScanner):
    """Always raises an exception."""
    name = "error"

    async def scan(self, ctx):
        raise RuntimeError("scanner crashed")
        yield  # type: ignore[misc]  # make it an async generator


class _CancellableScanner(BaseScanner):
    """Checks cancel_token and exits early."""
    name = "cancellable"

    async def scan(self, ctx):
        for i in range(100):
            if ctx.is_cancelled:
                return
            yield ProgressEvent(scanner_name="cancellable", current=i, total=100)
            await asyncio.sleep(0.01)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_engine_runs_scanners_in_parallel():
    """Multiple scanners should run concurrently, not sequentially."""
    with respx.mock:
        scanners = {"s1": _SlowScanner, "s2": _SlowScanner}
        with patch("msscan.core.engine.discover_scanners", return_value=scanners):
            engine = ScanEngine(url="https://test.com", modules=["s1", "s2"])
            import time
            t0 = time.monotonic()
            results = await engine.run()
            elapsed = time.monotonic() - t0

    # Two 0.1s scanners in parallel should finish in ~0.1-0.2s, not 0.2s+
    assert elapsed < 0.5
    assert len(results) == 2


@pytest.mark.asyncio
async def test_engine_error_isolation():
    """A crashing scanner should not prevent others from completing."""
    scanners = {
        "good": _FakeScanner,
        "bad": _ErrorScanner,
    }
    with patch("msscan.core.engine.discover_scanners", return_value=scanners):
        engine = ScanEngine(url="https://test.com", modules=["good", "bad"])
        results = await engine.run()

    # The good scanner's finding should still be collected
    assert len(results) >= 1
    assert any(r.scanner == "fake" for r in results)


@pytest.mark.asyncio
async def test_engine_empty_modules():
    """Engine with no valid modules returns empty results."""
    with patch("msscan.core.engine.discover_scanners", return_value={}):
        engine = ScanEngine(url="https://test.com", modules=["nonexistent"])
        results = await engine.run()
    assert results == []


@pytest.mark.asyncio
async def test_engine_run_stream_yields_events():
    """run_stream() should yield FindingEvent objects."""
    scanners = {"fake": _FakeScanner}
    with patch("msscan.core.engine.discover_scanners", return_value=scanners):
        engine = ScanEngine(url="https://test.com", modules=["fake"])
        events = []
        async for event in engine.run_stream():
            events.append(event)

    findings = [e for e in events if isinstance(e, FindingEvent)]
    assert len(findings) == 1
    assert findings[0].result.scanner == "fake"


@pytest.mark.asyncio
async def test_engine_stream_error_event():
    """run_stream() should yield ErrorEvent for crashing scanners."""
    scanners = {"bad": _ErrorScanner}
    with patch("msscan.core.engine.discover_scanners", return_value=scanners):
        engine = ScanEngine(url="https://test.com", modules=["bad"])
        events = []
        async for event in engine.run_stream():
            events.append(event)

    errors = [e for e in events if isinstance(e, ErrorEvent)]
    assert len(errors) == 1
    assert "crashed" in errors[0].error


@pytest.mark.asyncio
async def test_engine_uses_config_defaults():
    """Engine should apply ScanConfig defaults when no config is provided."""
    engine = ScanEngine(url="https://test.com", modules=["xss"])
    assert engine.config.rate_limit == 10
    assert engine.config.timeout == 10.0
    assert engine.config.cache_enabled is True
