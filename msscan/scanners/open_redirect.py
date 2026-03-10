"""Open Redirect scanner — detects HTTP, JavaScript, and meta-refresh redirects."""

from __future__ import annotations

import re

from typing import AsyncIterator
from urllib.parse import urlparse

from msscan.core.context import ScanContext
from msscan.core.events import ScanEvent, FindingEvent, ProgressEvent
from msscan.core.result import ScanResult
from msscan.scanners.base import BaseScanner
from msscan.utils.helpers import inject_param, extract_params
from msscan.utils.payloads import load_payloads

REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "next",
    "return", "returnto", "return_url", "goto", "rurl",
    "dest", "destination", "continue", "target", "link", "out",
]

_REMEDIATION = (
    "Validate redirect URLs against an explicit allowlist of trusted domains. "
    "Reject or sanitize any URL that does not match an allowed destination."
)

# JS redirect patterns: capture the URL string from common redirect assignments.
_JS_REDIRECT_RE = re.compile(
    r"""(?:window\.location|document\.location|window\.location\.href|window\.location\.replace)\s*[=(]\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)

# Meta refresh: <meta http-equiv="refresh" content="0; url=https://...">
_META_REFRESH_RE = re.compile(
    r"""<meta[^>]+http-equiv=['"]\s*refresh\s*['"][^>]+content=['"]\s*\d+\s*;\s*url=([^'">\s]+)""",
    re.IGNORECASE,
)


def _is_external(target_url: str, base_url: str) -> bool:
    """Return True if *target_url* resolves to a different host than *base_url*."""
    parsed_target = urlparse(target_url)
    parsed_base = urlparse(base_url)
    if not parsed_target.netloc:
        return False
    return parsed_target.netloc.lower() != parsed_base.netloc.lower()


class Scanner(BaseScanner):
    name = "open_redirect"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[ScanEvent]:
        url = ctx.target
        client = ctx.client

        payloads = load_payloads("redirects.txt")
        if not payloads:
            payloads = self._default_payloads()

        # Merge existing URL params with common redirect parameter names.
        params = list(extract_params(url).keys())
        for rp in REDIRECT_PARAMS:
            if rp not in params:
                params.append(rp)

        for param_idx, param_name in enumerate(params):
            if ctx.is_cancelled:
                return

            for payload in payloads:
                if ctx.is_cancelled:
                    return

                test_url = inject_param(url, param_name, payload)
                try:
                    resp = await client.get(test_url)
                    found = False

                    # 1. HTTP 3xx redirect via Location header.
                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("location", "")
                        if _is_external(location, url):
                            yield FindingEvent(result=ScanResult(
                                scanner=self.name,
                                severity="HIGH",
                                url=test_url,
                                detail=(
                                    f"Open Redirect (HTTP {resp.status_code}) — "
                                    f"'{param_name}' redirects to external URL"
                                ),
                                evidence=f"Location: {location}",
                                confidence="HIGH",
                                confidence_score=0.9,
                                cwe_id="CWE-601",
                                remediation=_REMEDIATION,
                            ))
                            found = True

                    if not found:
                        body = resp.text

                        # 2. JavaScript redirect in response body.
                        for js_match in _JS_REDIRECT_RE.finditer(body):
                            js_url = js_match.group(1)
                            if _is_external(js_url, url):
                                yield FindingEvent(result=ScanResult(
                                    scanner=self.name,
                                    severity="MEDIUM",
                                    url=test_url,
                                    detail=(
                                        f"Open Redirect (JavaScript) — "
                                        f"'{param_name}' triggers JS redirect to external URL"
                                    ),
                                    evidence=f"JS redirect: {js_match.group(0)[:120]}",
                                    confidence="MEDIUM",
                                    confidence_score=0.6,
                                    cwe_id="CWE-601",
                                    remediation=_REMEDIATION,
                                ))
                                found = True
                                break

                    if not found:
                        body = resp.text

                        # 3. Meta-refresh redirect in HTML.
                        for meta_match in _META_REFRESH_RE.finditer(body):
                            meta_url = meta_match.group(1).strip().rstrip('"\'>')
                            if _is_external(meta_url, url):
                                yield FindingEvent(result=ScanResult(
                                    scanner=self.name,
                                    severity="MEDIUM",
                                    url=test_url,
                                    detail=(
                                        f"Open Redirect (meta-refresh) — "
                                        f"'{param_name}' causes meta redirect to external URL"
                                    ),
                                    evidence=f"Meta refresh URL: {meta_url}",
                                    confidence="HIGH",
                                    confidence_score=0.7,
                                    cwe_id="CWE-601",
                                    remediation=_REMEDIATION,
                                ))
                                found = True
                                break

                    if found:
                        break  # Parameter is vulnerable; move to next param.

                except Exception:
                    continue

            yield ProgressEvent(
                scanner_name=self.name,
                current=param_idx + 1,
                total=len(params),
                message=f"Tested parameter '{param_name}'",
            )

    @staticmethod
    def _default_payloads() -> list[str]:
        return [
            "https://evil.com",
            "//evil.com",
            "https://evil.com/%2f..",
            "////evil.com",
            "https:///evil.com",
            "/\\evil.com",
            "https://evil.com@target.com",
        ]
