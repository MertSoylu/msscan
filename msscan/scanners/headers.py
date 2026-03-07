"""HTTP Security Headers scanner."""

from __future__ import annotations

import re

from msscan.core.http_client import HttpClient
from msscan.core.result import ScanResult
from msscan.scanners.base import BaseScanner

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "detail": "HSTS header missing — vulnerable to MITM attacks",
        "remediation": "Add Strict-Transport-Security header with max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "detail": "CSP header missing — no XSS protection",
        "remediation": "Add a Content-Security-Policy header with a strict policy that avoids unsafe-inline and unsafe-eval",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "detail": "X-Frame-Options missing — clickjacking risk",
        "remediation": "Add X-Frame-Options header with value DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "detail": "X-Content-Type-Options missing — MIME sniffing risk",
        "remediation": "Add X-Content-Type-Options header with value nosniff",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "detail": "Referrer-Policy missing — information leakage risk",
        "remediation": "Add Referrer-Policy header with value strict-origin-when-cross-origin or no-referrer",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "detail": "Permissions-Policy missing — no browser API access control",
        "remediation": "Add Permissions-Policy header to restrict browser feature access",
    },
    "X-XSS-Protection": {
        "severity": "INFO",
        "detail": "X-XSS-Protection missing (legacy browsers)",
        "remediation": "Add X-XSS-Protection header with value 1; mode=block for legacy browser support",
    },
}

INFO_LEAKAGE_HEADERS = ["X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]

CORS_HEADERS = ["Access-Control-Allow-Origin"]


class Scanner(BaseScanner):
    name = "headers"

    async def scan(self, url: str, client: HttpClient) -> list[ScanResult]:
        results: list[ScanResult] = []

        resp = await client.get(url)
        headers = resp.headers
        lower_headers = {k.lower(): v for k, v in headers.items()}

        # Security header checks
        for header_name, info in SECURITY_HEADERS.items():
            if header_name.lower() not in lower_headers:
                results.append(ScanResult(
                    scanner=self.name,
                    severity=info["severity"],
                    url=url,
                    detail=info["detail"],
                    evidence=f"'{header_name}' not found in response headers",
                    confidence="HIGH",
                    cwe_id="CWE-693",
                    remediation=info["remediation"],
                ))

        # CSP analysis — when header IS present
        csp_value = lower_headers.get("content-security-policy")
        if csp_value:
            self._analyze_csp(url, csp_value, results)

        # HSTS validation — when header IS present
        hsts_value = lower_headers.get("strict-transport-security")
        if hsts_value:
            self._analyze_hsts(url, hsts_value, results)

        # CORS analysis
        acao = lower_headers.get("access-control-allow-origin")
        if acao and acao == "*":
            results.append(ScanResult(
                scanner=self.name,
                severity="MEDIUM",
                url=url,
                detail="CORS wildcard (*) — all origins are allowed",
                evidence=f"Access-Control-Allow-Origin: {acao}",
                confidence="HIGH",
                cwe_id="CWE-942",
            ))

        # Server header information leakage
        server = lower_headers.get("server")
        if server:
            results.append(ScanResult(
                scanner=self.name,
                severity="INFO",
                url=url,
                detail=f"Server header exposes version info: {server}",
                evidence=f"Server: {server}",
                confidence="HIGH",
                cwe_id="CWE-200",
            ))

        # Information leakage headers (X-Powered-By, X-AspNet-Version, X-AspNetMvc-Version)
        for header_name in INFO_LEAKAGE_HEADERS:
            value = lower_headers.get(header_name.lower())
            if value:
                results.append(ScanResult(
                    scanner=self.name,
                    severity="INFO",
                    url=url,
                    detail=f"{header_name} exposes technology info: {value}",
                    evidence=f"{header_name}: {value}",
                    confidence="HIGH",
                    cwe_id="CWE-200",
                ))

        return results

    def _analyze_csp(self, url: str, csp_value: str, results: list[ScanResult]) -> None:
        """Parse CSP directives and flag insecure patterns."""
        directives = [d.strip() for d in csp_value.split(";") if d.strip()]

        has_unsafe_inline = False
        has_unsafe_eval = False
        has_wildcard = False

        for directive in directives:
            parts = directive.split()
            if len(parts) < 2:
                continue
            sources = parts[1:]

            for source in sources:
                if source == "'unsafe-inline'":
                    has_unsafe_inline = True
                if source == "'unsafe-eval'":
                    has_unsafe_eval = True
                if source == "*":
                    has_wildcard = True

        if has_unsafe_inline:
            results.append(ScanResult(
                scanner=self.name,
                severity="MEDIUM",
                url=url,
                detail="CSP allows unsafe-inline scripts",
                evidence=f"Content-Security-Policy: {csp_value}",
                confidence="HIGH",
                cwe_id="CWE-693",
            ))

        if has_unsafe_eval:
            results.append(ScanResult(
                scanner=self.name,
                severity="MEDIUM",
                url=url,
                detail="CSP allows unsafe-eval",
                evidence=f"Content-Security-Policy: {csp_value}",
                confidence="HIGH",
                cwe_id="CWE-693",
            ))

        if has_wildcard:
            results.append(ScanResult(
                scanner=self.name,
                severity="MEDIUM",
                url=url,
                detail="CSP allows wildcard sources",
                evidence=f"Content-Security-Policy: {csp_value}",
                confidence="HIGH",
                cwe_id="CWE-693",
            ))

    def _analyze_hsts(self, url: str, hsts_value: str, results: list[ScanResult]) -> None:
        """Validate HSTS header configuration."""
        hsts_lower = hsts_value.lower()

        # Check max-age value
        max_age_match = re.search(r"max-age=(\d+)", hsts_lower)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:
                results.append(ScanResult(
                    scanner=self.name,
                    severity="LOW",
                    url=url,
                    detail=f"HSTS max-age too short ({max_age}s, recommended >= 31536000)",
                    evidence=f"Strict-Transport-Security: {hsts_value}",
                    confidence="HIGH",
                    cwe_id="CWE-693",
                ))

        # Check for includeSubDomains
        if "includesubdomains" not in hsts_lower:
            results.append(ScanResult(
                scanner=self.name,
                severity="INFO",
                url=url,
                detail="HSTS header missing includeSubDomains directive",
                evidence=f"Strict-Transport-Security: {hsts_value}",
                confidence="HIGH",
                cwe_id="CWE-693",
            ))

        # Check for preload
        if "preload" not in hsts_lower:
            results.append(ScanResult(
                scanner=self.name,
                severity="INFO",
                url=url,
                detail="HSTS header missing preload directive",
                evidence=f"Strict-Transport-Security: {hsts_value}",
                confidence="HIGH",
                cwe_id="CWE-693",
            ))
