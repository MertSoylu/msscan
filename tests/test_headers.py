"""Tests for HTTP Security Headers scanner."""

from __future__ import annotations

import pytest
import httpx
import respx

from msscan.core.http_client import HttpClient
from msscan.scanners.headers import Scanner
from tests.conftest import collect_results


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
            results = await collect_results(scanner, "https://example.com/", client)

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
            results = await collect_results(scanner, "https://secure.com/", client)

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
            results = await collect_results(scanner, "https://cors.com/", client)

    cors_results = [r for r in results if "CORS" in r.detail]
    assert len(cors_results) == 1
    assert cors_results[0].severity == "MEDIUM"


@pytest.mark.asyncio
async def test_csp_unsafe_inline_detected(scanner):
    """CSP with unsafe-inline should be flagged."""
    headers = {
        "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
    }
    with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, headers=headers, text="<html></html>")
        )
        async with HttpClient() as client:
            results = await collect_results(scanner, "https://example.com/", client)

    unsafe_inline = [r for r in results if "unsafe-inline" in r.detail]
    assert len(unsafe_inline) > 0
    assert unsafe_inline[0].severity == "MEDIUM"


@pytest.mark.asyncio
async def test_csp_unsafe_eval_detected(scanner):
    """CSP with unsafe-eval should be flagged."""
    headers = {
        "Content-Security-Policy": "script-src 'unsafe-eval'",
        "Strict-Transport-Security": "max-age=31536000",
    }
    with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, headers=headers, text="<html></html>")
        )
        async with HttpClient() as client:
            results = await collect_results(scanner, "https://example.com/", client)

    unsafe_eval = [r for r in results if "unsafe-eval" in r.detail]
    assert len(unsafe_eval) > 0
    assert unsafe_eval[0].severity == "MEDIUM"


@pytest.mark.asyncio
async def test_csp_data_uri_detected(scanner):
    """CSP allowing data: URIs should be flagged."""
    headers = {
        "Content-Security-Policy": "script-src data:",
        "Strict-Transport-Security": "max-age=31536000",
    }
    with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, headers=headers, text="<html></html>")
        )
        async with HttpClient() as client:
            results = await collect_results(scanner, "https://example.com/", client)

    data_uri = [r for r in results if "data:" in r.detail]
    assert len(data_uri) > 0
    assert data_uri[0].severity == "LOW"


@pytest.mark.asyncio
async def test_hsts_short_max_age_detected(scanner):
    """HSTS with short max-age should be flagged."""
    headers = {
        "Strict-Transport-Security": "max-age=3600; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
    }
    with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, headers=headers, text="<html></html>")
        )
        async with HttpClient() as client:
            results = await collect_results(scanner, "https://example.com/", client)

    hsts_short = [r for r in results if "max-age too short" in r.detail]
    assert len(hsts_short) > 0
    assert hsts_short[0].severity == "LOW"


@pytest.mark.asyncio
async def test_hsts_missing_includesubdomains_detected(scanner):
    """HSTS without includeSubDomains should be flagged."""
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
    }
    with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, headers=headers, text="<html></html>")
        )
        async with HttpClient() as client:
            results = await collect_results(scanner, "https://example.com/", client)

    hsts_subdomains = [r for r in results if "includeSubDomains" in r.detail]
    assert len(hsts_subdomains) > 0
    assert hsts_subdomains[0].severity == "INFO"
