"""Tests for Open Redirect scanner."""

from __future__ import annotations

import pytest
import httpx
import respx

from msscan.core.http_client import HttpClient
from msscan.scanners.open_redirect import Scanner, _is_external


@pytest.fixture
def scanner():
    return Scanner()


# ---------------------------------------------------------------------------
# Unit tests for _is_external helper
# ---------------------------------------------------------------------------

def test_is_external_different_domain():
    assert _is_external("https://evil.com/path", "https://target.com/") is True


def test_is_external_same_domain():
    assert _is_external("https://target.com/callback", "https://target.com/login") is False


def test_is_external_relative_url():
    assert _is_external("/callback", "https://target.com/login") is False


def test_is_external_no_scheme():
    assert _is_external("//evil.com", "https://target.com/") is True


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_http_redirect_flagged_high(scanner):
    """HTTP 3xx redirect to external domain → HIGH finding."""
    with respx.mock:
        respx.get("https://target.com/redirect").mock(
            return_value=httpx.Response(
                302,
                headers={"Location": "https://evil.com/phish"},
                text="",
            )
        )
        async with HttpClient() as client:
            results = await scanner.scan("https://target.com/redirect?url=test", client)

    high = [r for r in results if r.severity == "HIGH"]
    assert len(high) > 0
    assert high[0].cwe_id == "CWE-601"
    assert high[0].confidence == "HIGH"


@pytest.mark.asyncio
async def test_js_redirect_flagged_medium(scanner):
    """window.location assignment to external URL in response body → MEDIUM finding."""
    body = "window.location = 'https://evil.com';"
    with respx.mock:
        respx.get("https://target.com/redirect").mock(
            return_value=httpx.Response(200, text=body)
        )
        async with HttpClient() as client:
            results = await scanner.scan("https://target.com/redirect?url=test", client)

    medium = [r for r in results if r.severity == "MEDIUM" and "JavaScript" in r.detail]
    assert len(medium) > 0
    assert medium[0].confidence == "MEDIUM"


@pytest.mark.asyncio
async def test_meta_refresh_flagged_medium(scanner):
    """Meta-refresh to external domain → MEDIUM finding with HIGH confidence."""
    body = '<html><meta http-equiv="refresh" content="0; url=https://evil.com"></html>'
    with respx.mock:
        respx.get("https://target.com/redirect").mock(
            return_value=httpx.Response(200, text=body)
        )
        async with HttpClient() as client:
            results = await scanner.scan("https://target.com/redirect?url=test", client)

    medium = [r for r in results if r.severity == "MEDIUM" and "meta-refresh" in r.detail]
    assert len(medium) > 0
    assert medium[0].confidence == "HIGH"


@pytest.mark.asyncio
async def test_same_domain_redirect_not_flagged(scanner):
    """HTTP redirect to same domain → no finding."""
    with respx.mock:
        respx.get("https://target.com/redirect").mock(
            return_value=httpx.Response(
                302,
                headers={"Location": "https://target.com/home"},
                text="",
            )
        )
        async with HttpClient() as client:
            results = await scanner.scan("https://target.com/redirect?url=test", client)

    assert len(results) == 0


@pytest.mark.asyncio
async def test_no_redirect_no_finding(scanner):
    """Normal 200 response with no redirect indicators → no finding."""
    with respx.mock:
        respx.get("https://safe.com/page").mock(
            return_value=httpx.Response(200, text="<html>Welcome</html>")
        )
        async with HttpClient() as client:
            results = await scanner.scan("https://safe.com/page?url=test", client)

    assert len(results) == 0
