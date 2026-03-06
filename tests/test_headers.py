"""Tests for HTTP Security Headers scanner."""

from __future__ import annotations

import pytest
import httpx
import respx

from msscan.core.http_client import HttpClient
from msscan.scanners.headers import Scanner


@pytest.fixture
def scanner():
    return Scanner()


@pytest.mark.asyncio
async def test_missing_security_headers(scanner):
    """Güvenlik header'ları eksik olduğunda bulgu üretmeli."""
    with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text="<html></html>")
        )
        async with HttpClient() as client:
            results = await scanner.scan("https://example.com/", client)

    # En az HSTS ve CSP eksikliği rapor edilmeli
    scanner_names = [r.detail for r in results]
    assert any("HSTS" in d for d in scanner_names)
    assert any("CSP" in d for d in scanner_names)


@pytest.mark.asyncio
async def test_all_headers_present(scanner):
    """Tüm güvenlik header'ları varsa eksiklik bulgusu olmamalı."""
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
        "X-XSS-Protection": "1; mode=block",
    }
    with respx.mock:
        respx.get("https://secure.com/").mock(
            return_value=httpx.Response(200, headers=headers, text="<html></html>")
        )
        async with HttpClient() as client:
            results = await scanner.scan("https://secure.com/", client)

    # Eksik header bulgusu olmamalı (sadece INFO seviyesinde olabilir)
    non_info = [r for r in results if r.severity != "INFO"]
    assert len(non_info) == 0


@pytest.mark.asyncio
async def test_cors_wildcard_detected(scanner):
    """CORS wildcard tespiti."""
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
        "X-XSS-Protection": "1; mode=block",
    }
    with respx.mock:
        respx.get("https://cors.com/").mock(
            return_value=httpx.Response(200, headers=headers, text="<html></html>")
        )
        async with HttpClient() as client:
            results = await scanner.scan("https://cors.com/", client)

    cors_results = [r for r in results if "CORS" in r.detail]
    assert len(cors_results) == 1
    assert cors_results[0].severity == "MEDIUM"
