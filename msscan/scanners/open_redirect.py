"""Open Redirect scanner."""

from __future__ import annotations

from urllib.parse import urlparse

from msscan.core.http_client import HttpClient
from msscan.core.result import ScanResult
from msscan.scanners.base import BaseScanner
from msscan.utils.helpers import inject_param, extract_params
from msscan.utils.payloads import load_payloads

REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "next",
    "return", "returnto", "return_url", "goto", "rurl",
    "dest", "destination", "continue", "target", "link", "out",
]


class Scanner(BaseScanner):
    name = "open_redirect"

    async def scan(self, url: str, client: HttpClient) -> list[ScanResult]:
        results: list[ScanResult] = []
        payloads = load_payloads("redirects.txt")
        if not payloads:
            payloads = self._default_payloads()

        # Merge existing URL params with common redirect parameter names
        params = list(extract_params(url).keys())
        for rp in REDIRECT_PARAMS:
            if rp not in params:
                params.append(rp)

        for param_name in params:
            for payload in payloads:
                test_url = inject_param(url, param_name, payload)
                try:
                    resp = await client.get(test_url)
                    location = resp.headers.get("location", "")

                    if resp.status_code in (301, 302, 303, 307, 308):
                        parsed_loc = urlparse(location)
                        if parsed_loc.netloc and parsed_loc.netloc != urlparse(url).netloc:
                            results.append(ScanResult(
                                scanner=self.name,
                                severity="MEDIUM",
                                url=test_url,
                                detail=f"Open Redirect — '{param_name}' redirects to an external URL",
                                evidence=f"Location: {location}",
                            ))
                            break  # Parameter is vulnerable, move to next
                except Exception:
                    continue

        return results

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
