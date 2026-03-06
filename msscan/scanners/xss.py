"""Reflected XSS scanner."""

from __future__ import annotations

from urllib.parse import urlparse, parse_qs

from msscan.core.http_client import HttpClient
from msscan.core.result import ScanResult
from msscan.scanners.base import BaseScanner
from msscan.utils.helpers import inject_param, extract_params
from msscan.utils.payloads import load_payloads


class Scanner(BaseScanner):
    name = "xss"

    async def scan(self, url: str, client: HttpClient) -> list[ScanResult]:
        results: list[ScanResult] = []
        payloads = load_payloads("xss.txt")
        if not payloads:
            payloads = self._default_payloads()

        params = extract_params(url)
        if not params:
            # No params found — try common parameter names
            params = {p: ["test"] for p in ["q", "search", "query", "s", "id", "page", "name"]}

        for param_name in params:
            for payload in payloads:
                test_url = inject_param(url, param_name, payload)
                try:
                    resp = await client.get(test_url)
                    body = resp.text

                    if payload in body:
                        results.append(ScanResult(
                            scanner=self.name,
                            severity="HIGH",
                            url=test_url,
                            detail=f"Reflected XSS — payload reflected in '{param_name}' parameter",
                            evidence=payload,
                        ))
                        break  # Parameter already vulnerable, skip remaining payloads
                except Exception:
                    continue

        return results

    @staticmethod
    def _default_payloads() -> list[str]:
        return [
            '<script>alert("msscan")</script>',
            '"><script>alert(1)</script>',
            "'-alert(1)-'",
            '<img src=x onerror=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            "javascript:alert(1)",
        ]
