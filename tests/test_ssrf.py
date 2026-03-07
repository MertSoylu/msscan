"""Tests for SSRF scanner."""

from __future__ import annotations

import pytest
import httpx
import respx

from msscan.core.http_client import HttpClient
from msscan.scanners.ssrf import Scanner


@pytest.fixture
def scanner():
    return Scanner()


@pytest.mark.asyncio
async def test_etc_passwd_indicator_critical(scanner):
    """/etc/passwd content in response → CRITICAL finding."""
    with respx.mock:
        def handler(request):
            url_param = request.url.params.get("url", "")
            if "127.0.0.1" in url_param or "localhost" in url_param or "file://" in url_param:
                return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")
            return httpx.Response(200, text="<html>ok</html>")

        respx.get("https://vuln.com/fetch").mock(side_effect=handler)

        async with HttpClient() as client:
            results = await scanner.scan("https://vuln.com/fetch?url=test", client)

    critical = [r for r in results if r.severity == "CRITICAL"]
    assert len(critical) > 0
    assert critical[0].cwe_id == "CWE-918"
    assert critical[0].confidence == "HIGH"
    assert critical[0].remediation != ""


@pytest.mark.asyncio
async def test_aws_metadata_indicator_critical(scanner):
    """AWS EC2 metadata field in response → CRITICAL finding."""
    with respx.mock:
        def handler(request):
            url_param = request.url.params.get("url", "")
            if "169.254" in url_param or "metadata" in url_param:
                return httpx.Response(200, text="ami-id\ninstance-id\niam/security-credentials")
            return httpx.Response(200, text="<html>ok</html>")

        respx.get("https://vuln.com/fetch").mock(side_effect=handler)

        async with HttpClient() as client:
            results = await scanner.scan("https://vuln.com/fetch?url=https://example.com", client)

    critical = [r for r in results if r.severity == "CRITICAL"]
    assert len(critical) > 0


@pytest.mark.asyncio
async def test_generic_body_without_indicator_not_flagged(scanner):
    """Response body that mentions localhost but contains no high-specificity indicator → no finding."""
    with respx.mock:
        # Every request returns the same generic page mentioning localhost in a benign way
        respx.get("https://safe.com/page").mock(
            return_value=httpx.Response(
                200,
                text="<html>Contact us at localhost support team</html>",
            )
        )
        async with HttpClient() as client:
            results = await scanner.scan("https://safe.com/page?url=test", client)

    # "localhost" alone is no longer a trigger — expect no findings
    critical_high = [r for r in results if r.severity in ("CRITICAL", "HIGH")]
    assert len(critical_high) == 0


@pytest.mark.asyncio
async def test_no_ssrf_on_safe_site(scanner):
    """Clean response with no indicators → no findings."""
    with respx.mock:
        respx.get("https://safe.com/page").mock(
            return_value=httpx.Response(200, text="<html>Welcome!</html>")
        )
        async with HttpClient() as client:
            results = await scanner.scan("https://safe.com/page?url=test", client)

    assert len(results) == 0


@pytest.mark.asyncio
async def test_differential_medium_indicator_filtered(scanner):
    """Medium-specificity indicator already present in baseline → not flagged."""
    with respx.mock:
        # Both baseline and payload responses return the same body containing a medium indicator
        respx.get("https://stable.com/page").mock(
            return_value=httpx.Response(
                200,
                text="<html>Internal server error occurred during processing</html>",
            )
        )
        async with HttpClient() as client:
            results = await scanner.scan("https://stable.com/page?url=test", client)

    # "internal server error" is a MEDIUM indicator; if it's in baseline too, it should be filtered
    assert len(results) == 0
