"""HTTP Security Headers scanner."""

from __future__ import annotations

import re
from typing import AsyncIterator

from msscan.core.context import ScanContext
from msscan.core.events import FindingEvent, ProgressEvent, ScanEvent
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
}

INFO_LEAKAGE_HEADERS = ["X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]

CORS_HEADERS = ["Access-Control-Allow-Origin"]

_CVSS_BY_SEVERITY: dict[str, tuple[float, str]] = {
    "HIGH": (
        5.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    ),
    "MEDIUM": (
        4.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    ),
    "LOW": (
        3.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    ),
    "INFO": (
        0.0,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N",
    ),
}


def _cvss_for_severity(severity: str) -> tuple[float, str]:
    return _CVSS_BY_SEVERITY.get(severity, _CVSS_BY_SEVERITY["LOW"])


class Scanner(BaseScanner):
    name = "headers"
    description = "HTTP security headers and misconfiguration checks."
    author = "msscan"

    @property
    def version(self) -> str:
        return "1.1"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[ScanEvent]:
        url = ctx.target
        client = ctx.client

        yield ProgressEvent(
            scanner_name=self.name,
            current=0,
            total=100,
            message="Starting headers scan",
        )

        if ctx.is_cancelled:
            return

        resp = await client.get(url)
        headers = resp.headers
        lower_headers = {k.lower(): v for k, v in headers.items()}

        yield ProgressEvent(
            scanner_name=self.name,
            current=20,
            total=100,
            message="Response received, analyzing security headers",
        )

        if ctx.is_cancelled:
            return

        # Security header checks
        for header_name, info in SECURITY_HEADERS.items():
            if header_name.lower() not in lower_headers:
                cvss_score, cvss_vector = _cvss_for_severity(info["severity"])
                yield FindingEvent(result=ScanResult(
                    scanner=self.name,
                    severity=info["severity"],
                    url=url,
                    detail=info["detail"],
                    evidence=f"'{header_name}' not found in response headers",
                    confidence="HIGH",
                    confidence_score=0.9,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    exploit_scenario=(
                        f"Missing {header_name} weakens browser protections and increases attack surface."
                    ),
                    cwe_id="CWE-693",
                    remediation=info["remediation"],
                ))

        yield ProgressEvent(
            scanner_name=self.name,
            current=40,
            total=100,
            message="Security header presence checks complete",
        )

        if ctx.is_cancelled:
            return

        # CSP analysis — when header IS present
        csp_value = lower_headers.get("content-security-policy")
        if csp_value:
            for finding in self._analyze_csp(url, csp_value):
                yield finding

        # HSTS validation — when header IS present
        hsts_value = lower_headers.get("strict-transport-security")
        if hsts_value:
            for finding in self._analyze_hsts(url, hsts_value):
                yield finding

        yield ProgressEvent(
            scanner_name=self.name,
            current=70,
            total=100,
            message="CSP and HSTS analysis complete",
        )

        if ctx.is_cancelled:
            return

        # CORS analysis
        acao = lower_headers.get("access-control-allow-origin")
        if acao and acao == "*":
            cvss_score, cvss_vector = _cvss_for_severity("MEDIUM")
            yield FindingEvent(result=ScanResult(
                scanner=self.name,
                severity="MEDIUM",
                url=url,
                detail="CORS wildcard (*) — all origins are allowed",
                evidence=f"Access-Control-Allow-Origin: {acao}",
                confidence="HIGH",
                confidence_score=0.9,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                exploit_scenario=(
                    "Any origin can read responses, enabling data exposure via malicious sites."
                ),
                cwe_id="CWE-942",
            ))

        # Server header information leakage
        server = lower_headers.get("server")
        if server:
            cvss_score, cvss_vector = _cvss_for_severity("INFO")
            yield FindingEvent(result=ScanResult(
                scanner=self.name,
                severity="INFO",
                url=url,
                detail=f"Server header exposes version info: {server}",
                evidence=f"Server: {server}",
                confidence="HIGH",
                confidence_score=0.8,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                exploit_scenario="Exposed version info can help attackers target known vulnerabilities.",
                cwe_id="CWE-200",
            ))

        # X-XSS-Protection: if PRESENT and enabled, flag as deprecated (modern CSP is preferred)
        # Don't flag its absence — it's deprecated and shouldn't be added.
        xss_protection = lower_headers.get("x-xss-protection")
        if xss_protection:
            if "1" in xss_protection:  # If it's enabled (1; mode=block or similar)
                cvss_score, cvss_vector = _cvss_for_severity("INFO")
                yield FindingEvent(result=ScanResult(
                    scanner=self.name,
                    severity="INFO",
                    url=url,
                    detail="X-XSS-Protection header is deprecated — use Content-Security-Policy instead",
                    evidence=f"X-XSS-Protection: {xss_protection}",
                    confidence="HIGH",
                    confidence_score=0.8,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    exploit_scenario=(
                        "Deprecated header can create a false sense of protection without modern defenses."
                    ),
                    cwe_id="CWE-693",
                    remediation="Remove X-XSS-Protection and rely on Content-Security-Policy for XSS protection.",
                ))

        # Information leakage headers (X-Powered-By, X-AspNet-Version, X-AspNetMvc-Version)
        for header_name in INFO_LEAKAGE_HEADERS:
            value = lower_headers.get(header_name.lower())
            if value:
                cvss_score, cvss_vector = _cvss_for_severity("INFO")
                yield FindingEvent(result=ScanResult(
                    scanner=self.name,
                    severity="INFO",
                    url=url,
                    detail=f"{header_name} exposes technology info: {value}",
                    evidence=f"{header_name}: {value}",
                    confidence="HIGH",
                    confidence_score=0.8,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    exploit_scenario="Technology fingerprinting can aid targeted attacks.",
                    cwe_id="CWE-200",
                ))

        yield ProgressEvent(
            scanner_name=self.name,
            current=100,
            total=100,
            message="Headers scan complete",
        )

    def _analyze_csp(self, url: str, csp_value: str) -> list[FindingEvent]:
        """Parse CSP directives and flag insecure patterns."""
        findings: list[FindingEvent] = []
        directives = [d.strip() for d in csp_value.split(";") if d.strip()]

        has_unsafe_inline = False
        has_unsafe_eval = False
        has_wildcard = False
        has_data_uri = False
        has_http_source = False
        has_default_src = False
        has_upgrade_insecure = False

        for directive in directives:
            parts = directive.split()
            if len(parts) < 1:
                continue
            directive_name = parts[0].lower()

            if directive_name == "default-src":
                has_default_src = True
            if directive_name == "upgrade-insecure-requests":
                has_upgrade_insecure = True

            sources = parts[1:] if len(parts) > 1 else []

            for source in sources:
                if source == "'unsafe-inline'":
                    has_unsafe_inline = True
                if source == "'unsafe-eval'":
                    has_unsafe_eval = True
                if source == "*":
                    has_wildcard = True
                if source == "data:":
                    has_data_uri = True
                if source.startswith("http:"):
                    has_http_source = True

        if has_unsafe_inline:
            cvss_score, cvss_vector = _cvss_for_severity("MEDIUM")
            findings.append(FindingEvent(result=ScanResult(
                scanner=self.name,
                severity="MEDIUM",
                url=url,
                detail="CSP allows unsafe-inline scripts",
                evidence=f"Content-Security-Policy: {csp_value}",
                confidence="HIGH",
                confidence_score=0.9,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                exploit_scenario="Unsafe inline scripts can allow XSS payload execution.",
                cwe_id="CWE-693",
            )))

        if has_unsafe_eval:
            cvss_score, cvss_vector = _cvss_for_severity("MEDIUM")
            findings.append(FindingEvent(result=ScanResult(
                scanner=self.name,
                severity="MEDIUM",
                url=url,
                detail="CSP allows unsafe-eval",
                evidence=f"Content-Security-Policy: {csp_value}",
                confidence="HIGH",
                confidence_score=0.9,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                exploit_scenario="Allowing unsafe-eval increases the risk of script injection.",
                cwe_id="CWE-693",
            )))

        if has_wildcard:
            cvss_score, cvss_vector = _cvss_for_severity("MEDIUM")
            findings.append(FindingEvent(result=ScanResult(
                scanner=self.name,
                severity="MEDIUM",
                url=url,
                detail="CSP allows wildcard sources",
                evidence=f"Content-Security-Policy: {csp_value}",
                confidence="HIGH",
                confidence_score=0.9,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                exploit_scenario="Wildcard sources make it easier for attackers to load untrusted scripts.",
                cwe_id="CWE-693",
            )))

        if has_data_uri:
            cvss_score, cvss_vector = _cvss_for_severity("LOW")
            findings.append(FindingEvent(result=ScanResult(
                scanner=self.name,
                severity="LOW",
                url=url,
                detail="CSP allows data: URIs (potential XSS vector)",
                evidence=f"Content-Security-Policy: {csp_value}",
                confidence="HIGH",
                confidence_score=0.8,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                exploit_scenario="data: URIs can be abused to inject script content.",
                cwe_id="CWE-693",
            )))

        if has_http_source:
            cvss_score, cvss_vector = _cvss_for_severity("LOW")
            findings.append(FindingEvent(result=ScanResult(
                scanner=self.name,
                severity="LOW",
                url=url,
                detail="CSP allows http: sources (should be https: only)",
                evidence=f"Content-Security-Policy: {csp_value}",
                confidence="HIGH",
                confidence_score=0.8,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                exploit_scenario="Allowing http: sources can enable mixed-content script injection.",
                cwe_id="CWE-693",
            )))

        if not has_default_src:
            cvss_score, cvss_vector = _cvss_for_severity("LOW")
            findings.append(FindingEvent(result=ScanResult(
                scanner=self.name,
                severity="LOW",
                url=url,
                detail="CSP missing default-src directive (acts as fallback)",
                evidence=f"Content-Security-Policy: {csp_value}",
                confidence="MEDIUM",
                confidence_score=0.7,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                exploit_scenario="Missing fallback directives weakens CSP protections.",
                cwe_id="CWE-693",
            )))

        return findings

    def _analyze_hsts(self, url: str, hsts_value: str) -> list[FindingEvent]:
        """Validate HSTS header configuration."""
        findings: list[FindingEvent] = []
        hsts_lower = hsts_value.lower()

        # Check max-age value
        max_age_match = re.search(r"max-age=(\d+)", hsts_lower)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:
                cvss_score, cvss_vector = _cvss_for_severity("LOW")
                findings.append(FindingEvent(result=ScanResult(
                    scanner=self.name,
                    severity="LOW",
                    url=url,
                    detail=f"HSTS max-age too short ({max_age}s, recommended >= 31536000)",
                    evidence=f"Strict-Transport-Security: {hsts_value}",
                    confidence="HIGH",
                    confidence_score=0.9,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    exploit_scenario="Short HSTS duration weakens HTTPS enforcement against downgrades.",
                    cwe_id="CWE-693",
                )))

        # Check for includeSubDomains
        if "includesubdomains" not in hsts_lower:
            cvss_score, cvss_vector = _cvss_for_severity("INFO")
            findings.append(FindingEvent(result=ScanResult(
                scanner=self.name,
                severity="INFO",
                url=url,
                detail="HSTS header missing includeSubDomains directive",
                evidence=f"Strict-Transport-Security: {hsts_value}",
                confidence="HIGH",
                confidence_score=0.8,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                exploit_scenario="Subdomains may remain vulnerable to downgrade attacks.",
                cwe_id="CWE-693",
            )))

        # Check for preload
        if "preload" not in hsts_lower:
            cvss_score, cvss_vector = _cvss_for_severity("INFO")
            findings.append(FindingEvent(result=ScanResult(
                scanner=self.name,
                severity="INFO",
                url=url,
                detail="HSTS header missing preload directive",
                evidence=f"Strict-Transport-Security: {hsts_value}",
                confidence="HIGH",
                confidence_score=0.8,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                exploit_scenario="Domain is not eligible for browser preload protections.",
                cwe_id="CWE-693",
            )))

        return findings
