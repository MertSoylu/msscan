"""Tests for headless CLI mode."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from msscan.core.result import ScanResult
from msscan.cli.headless import run_headless_scan


def _mock_engine_run(results):
    """Return a mock ScanEngine whose run() returns the given results."""
    async def fake_run(self):
        return results

    return fake_run


# ---------------------------------------------------------------------------
# Exit code tests
# ---------------------------------------------------------------------------

def test_headless_no_targets_returns_3():
    """No targets → exit code 3 (configuration error)."""
    code = run_headless_scan(
        targets=[], modules=["xss"], skip_consent=True
    )
    assert code == 3


def test_headless_no_modules_returns_3():
    """No modules → exit code 3."""
    code = run_headless_scan(
        targets=["https://test.com"], modules=[], skip_consent=True
    )
    assert code == 3


def test_headless_invalid_profile_returns_3():
    """Invalid profile → exit code 3."""
    code = run_headless_scan(
        targets=["https://test.com"], modules=["xss"],
        profile="invalid_profile", skip_consent=True,
    )
    assert code == 3


def test_headless_clean_scan_returns_0():
    """No findings → exit code 0."""
    with patch("msscan.cli.headless.ScanEngine") as MockEngine:
        instance = MagicMock()
        instance.run = MagicMock(return_value=[])
        # Make asyncio.run call the mock
        with patch("msscan.cli.headless.asyncio.run", return_value=[]):
            code = run_headless_scan(
                targets=["https://test.com"], modules=["xss"],
                skip_consent=True, no_banner=True,
            )
    assert code == 0


def test_headless_findings_matching_fail_on_returns_1():
    """Findings matching fail_on severities → exit code 1."""
    results = [ScanResult(
        scanner="xss", severity="HIGH", url="https://test.com",
        detail="XSS found",
    )]
    with patch("msscan.cli.headless.asyncio.run", return_value=results):
        code = run_headless_scan(
            targets=["https://test.com"], modules=["xss"],
            fail_on=["HIGH", "CRITICAL"],
            skip_consent=True, no_banner=True,
        )
    assert code == 1


def test_headless_findings_below_fail_on_returns_0():
    """Findings below fail_on threshold → exit code 0."""
    results = [ScanResult(
        scanner="headers", severity="LOW", url="https://test.com",
        detail="Missing header",
    )]
    with patch("msscan.cli.headless.asyncio.run", return_value=results):
        code = run_headless_scan(
            targets=["https://test.com"], modules=["headers"],
            fail_on=["HIGH", "CRITICAL"],
            skip_consent=True, no_banner=True,
        )
    assert code == 0
