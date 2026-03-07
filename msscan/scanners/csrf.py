"""CSRF (Cross-Site Request Forgery) scanner."""

from __future__ import annotations

import math
import re

from msscan.core.http_client import HttpClient
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

    async def scan(self, url: str, client: HttpClient) -> list[ScanResult]:
        results: list[ScanResult] = []

        resp = await client.get(url)
        body = resp.text
        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        forms = FORM_PATTERN.findall(body)
        if not forms:
            return results

        cookies_safe = self._check_samesite_cookies(resp)

        # Check for global protection signals visible in the response.
        meta_token_match = META_TOKEN_PATTERN.search(body)
        meta_token_value = meta_token_match.group(1) if meta_token_match else None

        header_token_present = any(
            name in resp_headers_lower for name in _HEADER_TOKEN_NAMES
        )

        for i, form_html in enumerate(forms):
            method_match = METHOD_PATTERN.search(form_html)
            method = method_match.group(1).upper() if method_match else "GET"

            action_match = ACTION_PATTERN.search(form_html)
            action = action_match.group(1) if action_match else url

            # Skip GET forms unless the action suggests a state-changing operation.
            if method == "GET":
                if not _STATE_CHANGING_KEYWORDS.search(action):
                    continue
                results.append(ScanResult(
                    scanner=self.name,
                    severity="MEDIUM",
                    url=url,
                    detail=f"CSRF risk — GET form with state-changing action: {action}",
                    evidence=f"Method: GET | Action: {action}",
                    confidence="MEDIUM",
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
                results.append(ScanResult(
                    scanner=self.name,
                    severity="HIGH",
                    url=url,
                    detail=f"No CSRF protection — Form #{i + 1} ({method} {action})",
                    evidence=f"No CSRF token found. Input fields: {', '.join(input_names[:5])}",
                    confidence="HIGH",
                    cwe_id="CWE-352",
                    remediation=_REMEDIATION,
                ))
            elif not has_csrf_token and cookies_safe:
                results.append(ScanResult(
                    scanner=self.name,
                    severity="LOW",
                    url=url,
                    detail=f"No CSRF token but SameSite cookie present — Form #{i + 1}",
                    evidence="SameSite cookie protection found, but token-based protection is recommended",
                    confidence="MEDIUM",
                    cwe_id="CWE-352",
                    remediation=_REMEDIATION,
                ))
            elif has_csrf_token and token_value:
                # Check token quality.
                self._check_token_quality(url, token_value, results)

                # Double-submit cookie: token value matches a cookie value (weak pattern).
                cookie_values = {
                    v.strip() for pair in resp.headers.get("set-cookie", "").split(";")
                    for v in [pair.split("=", 1)[-1]] if v.strip()
                }
                if token_value in cookie_values:
                    results.append(ScanResult(
                        scanner=self.name,
                        severity="LOW",
                        url=url,
                        detail=f"Double-submit cookie pattern — CSRF token matches cookie value (Form #{i + 1})",
                        evidence=f"Token value appears in Set-Cookie header",
                        confidence="LOW",
                        cwe_id="CWE-352",
                        remediation=(
                            "Double-submit cookie is weaker than server-side validation. "
                            "Use a server-stored synchronizer token instead."
                        ),
                    ))

        return results

    def _check_token_quality(
        self, url: str, token_value: str, results: list[ScanResult]
    ) -> None:
        """Flag CSRF tokens that appear cryptographically weak."""
        entropy = _shannon_entropy(token_value)
        if len(token_value) < 8 or entropy < 3.0:
            results.append(ScanResult(
                scanner=self.name,
                severity="LOW",
                url=url,
                detail=f"Weak CSRF token — low entropy ({entropy:.2f} bits/char, length {len(token_value)})",
                evidence=f"Token: {token_value[:20]}{'...' if len(token_value) > 20 else ''}",
                confidence="MEDIUM",
                cwe_id="CWE-352",
                remediation=(
                    "Use a cryptographically secure random generator (e.g. secrets.token_hex(32)) "
                    "to produce CSRF tokens with sufficient entropy."
                ),
            ))

    @staticmethod
    def _check_samesite_cookies(resp) -> bool:
        """Check if SameSite flag is present in Set-Cookie headers."""
        cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        if not cookies:
            raw = resp.headers.get("set-cookie", "")
            cookies = [raw] if raw else []

        for cookie in cookies:
            if "samesite=strict" in cookie.lower() or "samesite=lax" in cookie.lower():
                return True
        return False
