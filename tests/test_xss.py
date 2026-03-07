"""Tests for XSS scanner — covers context-aware detection."""

from __future__ import annotations

import pytest
import httpx
import respx

from msscan.core.http_client import HttpClient
from msscan.scanners.xss import Scanner, _detect_reflection_context


@pytest.fixture
def scanner():
    return Scanner()


# ---------------------------------------------------------------------------
# Unit tests for _detect_reflection_context
# ---------------------------------------------------------------------------

def test_context_none_when_not_reflected():
    assert _detect_reflection_context("<html>hello</html>", "<script>alert(1)</script>") == "none"


def test_context_encoded_when_lt_gt_escaped():
    body = "<html>&lt;script&gt;alert(1)&lt;/script&gt;</html>"
    assert _detect_reflection_context(body, "<script>alert(1)</script>") == "encoded"


def test_context_javascript_inside_script_block():
    body = '<html><script>var x = "<script>alert(1)</script>";</script></html>'
    # The payload is inside a <script> block
    ctx = _detect_reflection_context(body, "<script>alert(1)</script>")
    # Can be javascript or html_body depending on nesting — just verify it's NOT "none"
    assert ctx != "none"


def test_context_javascript_unambiguous():
    payload = "alert(1)"
    body = f"<script>var q = '{payload}';</script>"
    assert _detect_reflection_context(body, payload) == "javascript"


def test_context_html_attribute():
    payload = "test"
    body = f'<input value="{payload}" type="text">'
    assert _detect_reflection_context(body, payload) == "html_attribute"


def test_context_html_body_unescaped():
    payload = '<img src=x onerror=alert(1)>'
    body = f"<html><body>Result: {payload}</body></html>"
    assert _detect_reflection_context(body, payload) == "html_body"


# ---------------------------------------------------------------------------
# Integration tests — scanner produces correct findings
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reflected_xss_detected(scanner):
    """Payload reflected unescaped → at least one finding with appropriate severity."""
    with respx.mock:
        def handler(request):
            q = request.url.params.get("q", "")
            return httpx.Response(200, text=f"<html>Results: {q}</html>")

        respx.get("https://vuln.com/search").mock(side_effect=handler)

        async with HttpClient() as client:
            results = await scanner.scan("https://vuln.com/search?q=test", client)

    assert len(results) > 0
    assert results[0].severity in ("CRITICAL", "HIGH")
    assert results[0].scanner == "xss"
    assert results[0].cwe_id == "CWE-79"
    assert results[0].remediation != ""


@pytest.mark.asyncio
async def test_xss_javascript_context_critical(scanner):
    """Payload reflected inside <script> block → CRITICAL."""
    with respx.mock:
        def handler(request):
            q = request.url.params.get("q", "")
            return httpx.Response(200, text=f"<script>var q = '{q}';</script>")

        respx.get("https://vuln.com/js").mock(side_effect=handler)

        async with HttpClient() as client:
            results = await scanner.scan("https://vuln.com/js?q=test", client)

    assert len(results) > 0
    severities = {r.severity for r in results}
    assert "CRITICAL" in severities


@pytest.mark.asyncio
async def test_xss_encoded_response_downgraded(scanner):
    """Payload with HTML-encoded angle brackets → INFO (not HIGH)."""
    with respx.mock:
        def handler(request):
            q = request.url.params.get("q", "")
            # Server HTML-encodes the payload
            safe = q.replace("<", "&lt;").replace(">", "&gt;")
            return httpx.Response(200, text=f"<html>Results: {safe}</html>")

        respx.get("https://safe.com/search").mock(side_effect=handler)

        async with HttpClient() as client:
            results = await scanner.scan("https://safe.com/search?q=test", client)

    # All findings should be INFO (encoded context) or nothing — never HIGH/CRITICAL
    high_findings = [r for r in results if r.severity in ("HIGH", "CRITICAL")]
    assert len(high_findings) == 0


@pytest.mark.asyncio
async def test_no_xss_when_not_reflected(scanner):
    """Payload never reflected → no findings."""
    with respx.mock:
        respx.get("https://safe.com/search").mock(
            return_value=httpx.Response(200, text="<html>No results found.</html>")
        )

        async with HttpClient() as client:
            results = await scanner.scan("https://safe.com/search?q=test", client)

    assert len(results) == 0
