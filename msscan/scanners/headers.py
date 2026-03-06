"""HTTP Security Headers scanner."""

from __future__ import annotations

from msscan.core.http_client import HttpClient
from msscan.core.result import ScanResult
from msscan.scanners.base import BaseScanner

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "detail": "HSTS header missing — vulnerable to MITM attacks",
    },
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "detail": "CSP header missing — no XSS protection",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "detail": "X-Frame-Options missing — clickjacking risk",
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "detail": "X-Content-Type-Options missing — MIME sniffing risk",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "detail": "Referrer-Policy missing — information leakage risk",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "detail": "Permissions-Policy missing — no browser API access control",
    },
    "X-XSS-Protection": {
        "severity": "INFO",
        "detail": "X-XSS-Protection missing (legacy browsers)",
    },
}

CORS_HEADERS = ["Access-Control-Allow-Origin"]


class Scanner(BaseScanner):
    name = "headers"

    async def scan(self, url: str, client: HttpClient) -> list[ScanResult]:
        results: list[ScanResult] = []

        resp = await client.get(url)
        headers = resp.headers

        # Security header checks
        for header_name, info in SECURITY_HEADERS.items():
            if header_name.lower() not in {k.lower() for k in headers.keys()}:
                results.append(ScanResult(
                    scanner=self.name,
                    severity=info["severity"],
                    url=url,
                    detail=info["detail"],
                    evidence=f"'{header_name}' not found in response headers",
                ))

        # CORS analysis
        acao = headers.get("access-control-allow-origin")
        if acao and acao == "*":
            results.append(ScanResult(
                scanner=self.name,
                severity="MEDIUM",
                url=url,
                detail="CORS wildcard (*) — all origins are allowed",
                evidence=f"Access-Control-Allow-Origin: {acao}",
            ))

        # Server header information leakage
        server = headers.get("server")
        if server:
            results.append(ScanResult(
                scanner=self.name,
                severity="INFO",
                url=url,
                detail=f"Server header exposes version info: {server}",
                evidence=f"Server: {server}",
            ))

        # X-Powered-By information leakage
        powered_by = headers.get("x-powered-by")
        if powered_by:
            results.append(ScanResult(
                scanner=self.name,
                severity="INFO",
                url=url,
                detail=f"X-Powered-By exposes technology info: {powered_by}",
                evidence=f"X-Powered-By: {powered_by}",
            ))

        return results
