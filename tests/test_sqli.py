"""Tests for SQL Injection scanner."""

from __future__ import annotations

import pytest
import httpx
import respx

from msscan.core.http_client import HttpClient
from msscan.scanners.sqli import Scanner
from tests.conftest import collect_results


@pytest.fixture
def scanner():
    return Scanner()


@pytest.mark.asyncio
async def test_error_based_sqli_detected(scanner):
    """Error-based SQLi tespit edilmeli."""
    with respx.mock:
        def handler(request):
            param_id = request.url.params.get("id", "")
            if "'" in param_id:
                return httpx.Response(
                    500,
                    text="You have an error in your SQL syntax; check the manual"
                )
            return httpx.Response(200, text="<html>Normal</html>")

        respx.get("https://vuln.com/item").mock(side_effect=handler)

        async with HttpClient() as client:
            results = await collect_results(scanner, "https://vuln.com/item?id=1", client)

    assert len(results) > 0
    assert results[0].severity == "CRITICAL"
    assert results[0].scanner == "sqli"


@pytest.mark.asyncio
async def test_no_sqli_on_safe_site(scanner):
    """Güvenli sitede SQLi bulgusu olmamalı."""
    with respx.mock:
        respx.get("https://safe.com/item").mock(
            return_value=httpx.Response(200, text="<html>Item details</html>")
        )

        async with HttpClient() as client:
            results = await collect_results(scanner, "https://safe.com/item?id=1", client)

    sqli_results = [r for r in results if r.severity in ("CRITICAL", "HIGH")]
    assert len(sqli_results) == 0
