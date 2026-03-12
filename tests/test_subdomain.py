"""Tests for Subdomain scanner — uses unittest.mock to patch DNS resolution."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from msscan.core.http_client import HttpClient
from msscan.scanners.subdomain import Scanner
from tests.conftest import collect_results


@pytest.fixture
def scanner():
    return Scanner()


def _make_a_answer(ip: str):
    """Create a minimal mock DNS A-record answer."""
    rdata = MagicMock()
    rdata.address = ip
    answer = MagicMock()
    answer.__iter__ = MagicMock(return_value=iter([rdata]))
    return answer


def _make_cname_answer(target: str):
    """Create a minimal mock DNS CNAME-record answer."""
    rdata = MagicMock()
    rdata.target = MagicMock()
    rdata.target.to_text = MagicMock(return_value=f"{target}.")
    answer = MagicMock()
    answer.__iter__ = MagicMock(return_value=iter([rdata]))
    return answer


# ---------------------------------------------------------------------------
# Unit tests for _check_takeover
# ---------------------------------------------------------------------------

def test_check_takeover_returns_none_no_cname(scanner):
    result = Scanner._check_takeover("https://sub.example.com", ["1.2.3.4"], [])
    assert result is None


def test_check_takeover_high_no_a_record(scanner):
    """CNAME → vulnerable service, no A record → HIGH."""
    result = Scanner._check_takeover(
        "https://sub.example.com", [], ["customer.amazonaws.com"]
    )
    assert result is not None
    assert result.severity == "HIGH"
    assert result.cwe_id == "CWE-345"


def test_check_takeover_medium_with_a_record(scanner):
    """CNAME → vulnerable service, A record exists → MEDIUM."""
    result = Scanner._check_takeover(
        "https://sub.example.com", ["1.2.3.4"], ["myapp.herokuapp.com"]
    )
    assert result is not None
    assert result.severity == "MEDIUM"


def test_check_takeover_safe_cname(scanner):
    """CNAME pointing to a non-vulnerable service → None."""
    result = Scanner._check_takeover(
        "https://sub.example.com", ["1.2.3.4"], ["cdn.cloudflare.net"]
    )
    assert result is None


# ---------------------------------------------------------------------------
# Integration tests (DNS resolution patched)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_wildcard_filters_false_positives(scanner):
    """Subdomain IPs that match wildcard IPs should not produce INFO findings."""
    wildcard_ip = "10.0.0.1"

    async def mock_resolve(fqdn, record_type):
        # Both random wildcard probe and real subdomains return the same IP.
        if record_type == "A":
            return _make_a_answer(wildcard_ip)
        raise Exception("No CNAME")

    with patch("msscan.scanners.subdomain.dns.asyncresolver.Resolver") as MockResolver:
        instance = MagicMock()
        instance.resolve = AsyncMock(side_effect=mock_resolve)
        MockResolver.return_value = instance

        import respx
        with respx.mock:
            async with HttpClient() as client:
                results = await collect_results(scanner, "https://example.com", client)

    # All subdomains resolve to wildcard IP → no INFO findings from A records
    info_findings = [r for r in results if r.severity == "INFO"]
    assert len(info_findings) == 0


@pytest.mark.asyncio
async def test_cname_takeover_high_no_a_record(scanner):
    """CNAME → amazonaws.com, no A record → HIGH takeover finding."""
    call_count = {"n": 0}

    async def mock_resolve(fqdn, record_type):
        if record_type == "A":
            # Wildcard probe resolves; real subdomain A records fail.
            if call_count["n"] == 0:
                call_count["n"] += 1
                raise Exception("NXDOMAIN")
            raise Exception("NXDOMAIN")
        if record_type == "CNAME":
            return _make_cname_answer("app.s3.amazonaws.com")
        raise Exception("unsupported")

    with patch("msscan.scanners.subdomain.dns.asyncresolver.Resolver") as MockResolver:
        instance = MagicMock()
        instance.resolve = AsyncMock(side_effect=mock_resolve)
        MockResolver.return_value = instance

        import respx
        with respx.mock:
            async with HttpClient() as client:
                results = await collect_results(scanner, "https://example.com", client)

    high = [r for r in results if r.severity == "HIGH" and "takeover" in r.detail.lower()]
    assert len(high) > 0


@pytest.mark.asyncio
async def test_clean_subdomain_produces_info(scanner):
    """Subdomain with a unique A record (no wildcard) → INFO finding."""
    call_count = {"wildcard_done": False}

    async def mock_resolve(fqdn, record_type):
        if record_type == "A":
            # Wildcard probe: fail (no wildcard DNS).
            if not call_count["wildcard_done"]:
                call_count["wildcard_done"] = True
                raise Exception("NXDOMAIN")
            # Real subdomain resolves.
            return _make_a_answer("93.184.216.34")
        raise Exception("No CNAME")

    with patch("msscan.scanners.subdomain.dns.asyncresolver.Resolver") as MockResolver:
        instance = MagicMock()
        instance.resolve = AsyncMock(side_effect=mock_resolve)
        MockResolver.return_value = instance

        import respx
        with respx.mock:
            async with HttpClient() as client:
                results = await collect_results(scanner, "https://example.com", client)

    info = [r for r in results if r.severity == "INFO"]
    assert len(info) > 0
