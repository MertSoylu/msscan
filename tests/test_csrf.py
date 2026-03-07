"""Tests for CSRF scanner."""

from __future__ import annotations

import pytest
import httpx
import respx

from msscan.core.http_client import HttpClient
from msscan.scanners.csrf import Scanner, _shannon_entropy


@pytest.fixture
def scanner():
    return Scanner()


# ---------------------------------------------------------------------------
# Unit test for Shannon entropy helper
# ---------------------------------------------------------------------------

def test_shannon_entropy_uniform():
    """All same character → entropy 0."""
    assert _shannon_entropy("aaaa") == 0.0


def test_shannon_entropy_high():
    """Random hex string → entropy > 3.5."""
    token = "a3f8b2c91e4d7056"  # 16 distinct hex chars
    assert _shannon_entropy(token) > 3.0


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_csrf_no_token_no_samesite_high(scanner):
    """POST form without CSRF token and no SameSite cookie → HIGH finding."""
    body = '<html><form method="POST" action="/submit"><input name="email"></form></html>'
    with respx.mock:
        respx.get("https://vuln.com/form").mock(
            return_value=httpx.Response(200, text=body)
        )
        async with HttpClient() as client:
            results = await scanner.scan("https://vuln.com/form", client)

    high = [r for r in results if r.severity == "HIGH"]
    assert len(high) > 0
    assert high[0].cwe_id == "CWE-352"
    assert high[0].remediation != ""


@pytest.mark.asyncio
async def test_csrf_get_state_changing_flagged(scanner):
    """GET form with state-changing action URL → MEDIUM finding."""
    body = '<html><form method="GET" action="/admin/delete"><input name="id"></form></html>'
    with respx.mock:
        respx.get("https://vuln.com/page").mock(
            return_value=httpx.Response(200, text=body)
        )
        async with HttpClient() as client:
            results = await scanner.scan("https://vuln.com/page", client)

    medium = [r for r in results if r.severity == "MEDIUM"]
    assert len(medium) > 0


@pytest.mark.asyncio
async def test_csrf_get_benign_not_flagged(scanner):
    """GET form with non-state-changing action → no finding."""
    body = '<html><form method="GET" action="/search"><input name="q"></form></html>'
    with respx.mock:
        respx.get("https://example.com/page").mock(
            return_value=httpx.Response(200, text=body)
        )
        async with HttpClient() as client:
            results = await scanner.scan("https://example.com/page", client)

    assert len(results) == 0


@pytest.mark.asyncio
async def test_csrf_meta_token_accepted(scanner):
    """Meta csrf-token present → form is considered protected (no HIGH)."""
    body = (
        '<html>'
        '<meta name="csrf-token" content="abc123xyz456abc123xyz456abc123xy">'
        '<form method="POST" action="/submit"><input name="email"></form>'
        '</html>'
    )
    with respx.mock:
        respx.get("https://protected.com/form").mock(
            return_value=httpx.Response(200, text=body)
        )
        async with HttpClient() as client:
            results = await scanner.scan("https://protected.com/form", client)

    high = [r for r in results if r.severity == "HIGH"]
    assert len(high) == 0


@pytest.mark.asyncio
async def test_csrf_response_header_token_accepted(scanner):
    """X-CSRF-Token response header present → form is considered protected."""
    body = '<html><form method="POST" action="/submit"><input name="data"></form></html>'
    with respx.mock:
        respx.get("https://protected.com/form").mock(
            return_value=httpx.Response(
                200,
                text=body,
                headers={"X-CSRF-Token": "token-value-here"},
            )
        )
        async with HttpClient() as client:
            results = await scanner.scan("https://protected.com/form", client)

    high = [r for r in results if r.severity == "HIGH"]
    assert len(high) == 0


@pytest.mark.asyncio
async def test_csrf_weak_token_entropy_flagged(scanner):
    """CSRF token with low entropy → LOW 'weak token' finding."""
    body = (
        '<html>'
        '<form method="POST" action="/submit">'
        '<input name="csrf" value="aaaa">'
        '<input name="email">'
        '</form>'
        '</html>'
    )
    with respx.mock:
        respx.get("https://weaktoken.com/form").mock(
            return_value=httpx.Response(200, text=body)
        )
        async with HttpClient() as client:
            results = await scanner.scan("https://weaktoken.com/form", client)

    low = [r for r in results if r.severity == "LOW" and "entropy" in r.detail.lower()]
    assert len(low) > 0


@pytest.mark.asyncio
async def test_csrf_samesite_cookie_downgrades_to_low(scanner):
    """POST form without token but with SameSite cookie → LOW, not HIGH."""
    body = '<html><form method="POST" action="/submit"><input name="email"></form></html>'
    with respx.mock:
        respx.get("https://samesite.com/form").mock(
            return_value=httpx.Response(
                200,
                text=body,
                headers={"Set-Cookie": "session=abc; SameSite=Strict; Secure"},
            )
        )
        async with HttpClient() as client:
            results = await scanner.scan("https://samesite.com/form", client)

    high = [r for r in results if r.severity == "HIGH"]
    low = [r for r in results if r.severity == "LOW"]
    assert len(high) == 0
    assert len(low) > 0
