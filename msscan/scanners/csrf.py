"""CSRF (Cross-Site Request Forgery) scanner."""

from __future__ import annotations

import math
import re
from typing import AsyncIterator

from msscan.core.context import ScanContext
from msscan.core.events import FindingEvent, ProgressEvent, ScanEvent
from msscan.core.result import ScanResult
from msscan.scanners.base import BaseScanner


CSRF_TOKEN_NAMES = [
    "csrf", "csrftoken", "csrf_token", "_csrf", "xsrf",
    "xsrf-token", "_token", "authenticity_token", "__requestverificationtoken",
    "anti-csrf-token", "antiforgery",
]

# GET form actions that imply state-changing behaviour — flag even for GET method.
_STATE_CHANGING_KEYWORDS = re.compile(
    r"(delete|remove|update|logout|signout|edit|modify|reset|disable|enable|promote|revoke)",
    re.IGNORECASE,
)

FORM_PATTERN = re.compile(r"<form[^>]*>.*?</form>", re.DOTALL | re.IGNORECASE)
INPUT_PATTERN = re.compile(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*/?\s*>', re.IGNORECASE)
INPUT_VALUE_PATTERN = re.compile(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*value=["\']([^"\']*)["\']', re.IGNORECASE)
ACTION_PATTERN = re.compile(r'<form[^>]*action=["\']([^"\']*)["\']', re.IGNORECASE)
METHOD_PATTERN = re.compile(r'<form[^>]*method=["\']([^"\']*)["\']', re.IGNORECASE)
META_TOKEN_PATTERN = re.compile(
    r'<meta[^>]+name=["\']csrf[-_]token["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

_REMEDIATION = (
    "Implement the Synchronizer Token Pattern: generate a cryptographically random "
    "per-session token, embed it in every state-changing form as a hidden field, "
    "and validate it server-side. Alternatively use SameSite=Strict cookies."
)

_CVSS_CSRF_HIGH = (
    6.5,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
)
_CVSS_CSRF_MEDIUM = (
    5.3,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
)
_CVSS_CSRF_LOW = (
    3.1,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
)

_HEADER_TOKEN_NAMES = {"x-csrf-token", "x-xsrf-token", "x-csrftoken", "x-anti-forgery"}


def _shannon_entropy(value: str) -> float:
    """Calculate Shannon entropy (bits per character) of *value*."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


class Scanner(BaseScanner):
    name = "csrf"
    description = "CSRF protection analysis for forms and tokens."
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
            message="Starting CSRF scan",
        )

        if ctx.is_cancelled:
            return

        resp = await client.get(url)
        body = resp.text
        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        yield ProgressEvent(
            scanner_name=self.name,
            current=20,
            total=100,
            message="Page fetched, scanning for forms",
        )

        forms = FORM_PATTERN.findall(body)
        if not forms:
            yield ProgressEvent(
                scanner_name=self.name,
                current=100,
                total=100,
                message="No forms found, CSRF scan complete",
            )
            return

        cookies_safe = self._check_samesite_cookies(resp)

        # Check for global protection signals visible in the response.
        meta_token_match = META_TOKEN_PATTERN.search(body)
        meta_token_value = meta_token_match.group(1) if meta_token_match else None

        header_token_present = any(
            name in resp_headers_lower for name in _HEADER_TOKEN_NAMES
        )

        total_forms = len(forms)
        for i, form_html in enumerate(forms):
            if ctx.is_cancelled:
                return

            method_match = METHOD_PATTERN.search(form_html)
            method = method_match.group(1).upper() if method_match else "GET"

            action_match = ACTION_PATTERN.search(form_html)
            action = action_match.group(1) if action_match else url

            # Skip GET forms unless the action suggests a state-changing operation.
            if method == "GET":
                if not _STATE_CHANGING_KEYWORDS.search(action):
                    continue
                yield FindingEvent(result=ScanResult(
                    scanner=self.name,
                    severity="MEDIUM",
                    url=url,
                    detail=f"CSRF risk — GET form with state-changing action: {action}",
                    evidence=f"Method: GET | Action: {action}",
                    confidence="MEDIUM",
                    confidence_score=0.6,
                    cvss_score=_CVSS_CSRF_MEDIUM[0],
                    cvss_vector=_CVSS_CSRF_MEDIUM[1],
                    exploit_scenario=(
                        "A crafted link can trigger a state-changing GET request for a logged-in user."
                    ),
                    cwe_id="CWE-352",
                    remediation=_REMEDIATION,
                ))
                continue

            # Collect input field names and values.
            input_names = INPUT_PATTERN.findall(form_html)
            input_names_lower = [n.lower() for n in input_names]
            input_values = {
                m[0].lower(): m[1]
                for m in INPUT_VALUE_PATTERN.findall(form_html)
            }

            # Determine whether any CSRF token is present.
            form_token_name: str | None = next(
                (
                    name
                    for name in input_names_lower
                    for token_name in CSRF_TOKEN_NAMES
                    if token_name in name
                ),
                None,
            )
            has_csrf_token = (
                form_token_name is not None
                or meta_token_value is not None
                or header_token_present
            )

            token_value: str | None = (
                input_values.get(form_token_name) if form_token_name else meta_token_value
            )

            if not has_csrf_token and not cookies_safe:
                yield FindingEvent(result=ScanResult(
                    scanner=self.name,
                    severity="HIGH",
                    url=url,
                    detail=f"No CSRF protection — Form #{i + 1} ({method} {action})",
                    evidence=f"No CSRF token found. Input fields: {', '.join(input_names[:5])}",
                    confidence="HIGH",
                    confidence_score=0.9,
                    cvss_score=_CVSS_CSRF_HIGH[0],
                    cvss_vector=_CVSS_CSRF_HIGH[1],
                    exploit_scenario=(
                        "An attacker can trick a logged-in user into submitting a forged request."
                    ),
                    cwe_id="CWE-352",
                    remediation=_REMEDIATION,
                ))
            elif not has_csrf_token and cookies_safe:
                yield FindingEvent(result=ScanResult(
                    scanner=self.name,
                    severity="LOW",
                    url=url,
                    detail=f"No CSRF token but SameSite cookie present — Form #{i + 1}",
                    evidence="SameSite cookie protection found, but token-based protection is recommended",
                    confidence="MEDIUM",
                    confidence_score=0.5,
                    cvss_score=_CVSS_CSRF_LOW[0],
                    cvss_vector=_CVSS_CSRF_LOW[1],
                    exploit_scenario=(
                        "Protection relies on SameSite cookies; token-based defense is missing."
                    ),
                    cwe_id="CWE-352",
                    remediation=_REMEDIATION,
                ))
            elif has_csrf_token and token_value:
                # Check token quality.
                for event in self._check_token_quality(url, token_value):
                    yield event

                # Double-submit cookie: token value matches a cookie value (weak pattern).
                cookie_values = {
                    v.strip() for pair in resp.headers.get("set-cookie", "").split(";")
                    for v in [pair.split("=", 1)[-1]] if v.strip()
                }
                if token_value in cookie_values:
                    yield FindingEvent(result=ScanResult(
                        scanner=self.name,
                        severity="LOW",
                        url=url,
                        detail=f"Double-submit cookie pattern — CSRF token matches cookie value (Form #{i + 1})",
                        evidence=f"Token value appears in Set-Cookie header",
                        confidence="LOW",
                        confidence_score=0.3,
                        cvss_score=_CVSS_CSRF_LOW[0],
                        cvss_vector=_CVSS_CSRF_LOW[1],
                        exploit_scenario=(
                            "Token matches a cookie value, which may be bypassed if an attacker can set cookies."
                        ),
                        cwe_id="CWE-352",
                        remediation=(
                            "Double-submit cookie is weaker than server-side validation. "
                            "Use a server-stored synchronizer token instead."
                        ),
                    ))

            yield ProgressEvent(
                scanner_name=self.name,
                current=20 + int(80 * (i + 1) / total_forms),
                total=100,
                message=f"Analyzed form {i + 1}/{total_forms}",
            )

        yield ProgressEvent(
            scanner_name=self.name,
            current=100,
            total=100,
            message="CSRF scan complete",
        )

    def _check_token_quality(
        self, url: str, token_value: str
    ) -> list[FindingEvent]:
        """Flag CSRF tokens that appear cryptographically weak."""
        findings: list[FindingEvent] = []
        entropy = _shannon_entropy(token_value)
        if len(token_value) < 8 or entropy < 3.0:
            findings.append(FindingEvent(result=ScanResult(
                scanner=self.name,
                severity="LOW",
                url=url,
                detail=f"Weak CSRF token — low entropy ({entropy:.2f} bits/char, length {len(token_value)})",
                evidence=f"Token: {token_value[:20]}{'...' if len(token_value) > 20 else ''}",
                confidence="MEDIUM",
                confidence_score=0.5,
                cvss_score=_CVSS_CSRF_LOW[0],
                cvss_vector=_CVSS_CSRF_LOW[1],
                exploit_scenario="Low-entropy CSRF tokens may be guessed or predicted.",
                cwe_id="CWE-352",
                remediation=(
                    "Use a cryptographically secure random generator (e.g. secrets.token_hex(32)) "
                    "to produce CSRF tokens with sufficient entropy."
                ),
            )))
        return findings

    @staticmethod
    def _check_samesite_cookies(resp) -> bool:
        """Check if SameSite flag is present in Set-Cookie headers.

        Properly handles multiple Set-Cookie headers by iterating through
        resp.headers.multi_items() to get all cookies (httpx doesn't have get_list).
        """
        # httpx.Headers.multi_items() returns all header pairs including duplicates
        cookies = [v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"]

        for cookie in cookies:
            if "samesite=strict" in cookie.lower() or "samesite=lax" in cookie.lower():
                return True
        return False
