"""Tests for XSS scanner."""

from __future__ import annotations

import pytest
import httpx
import respx

from msscan.core.http_client import HttpClient
from msscan.scanners.xss import Scanner


@pytest.fixture
def scanner():
    return Scanner()


@pytest.mark.asyncio
async def test_reflected_xss_detected(scanner):
    """Reflected XSS tespit edilmeli."""
    with respx.mock:
        # Payload'ı yansıtan bir sayfa simüle et
        def handler(request):
            q = request.url.params.get("q", "")
            return httpx.Response(200, text=f"<html>Sonuçlar: {q}</html>")

        respx.get("https://vuln.com/search").mock(side_effect=handler)

        async with HttpClient() as client:
            results = await scanner.scan("https://vuln.com/search?q=test", client)

    assert len(results) > 0
    assert results[0].severity == "HIGH"
    assert results[0].scanner == "xss"


@pytest.mark.asyncio
async def test_no_xss_when_encoded(scanner):
    """Payload yansıtılmadığında XSS bulgu üretmemeli."""
    with respx.mock:
        # Güvenli site: parametreyi hiç gövdeye yansıtmaz
        respx.get("https://safe.com/search").mock(
            return_value=httpx.Response(200, text="<html>Arama sonucu bulunamadı.</html>")
        )

        async with HttpClient() as client:
            results = await scanner.scan("https://safe.com/search?q=test", client)

    assert len(results) == 0
