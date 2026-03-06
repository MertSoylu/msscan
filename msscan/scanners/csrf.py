"""CSRF (Cross-Site Request Forgery) scanner."""

from __future__ import annotations

import re

from msscan.core.http_client import HttpClient
from msscan.core.result import ScanResult
from msscan.scanners.base import BaseScanner


CSRF_TOKEN_NAMES = [
    "csrf", "csrftoken", "csrf_token", "_csrf", "xsrf",
    "xsrf-token", "_token", "authenticity_token", "__requestverificationtoken",
    "anti-csrf-token", "antiforgery",
]

FORM_PATTERN = re.compile(r"<form[^>]*>.*?</form>", re.DOTALL | re.IGNORECASE)
INPUT_PATTERN = re.compile(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*/?\s*>', re.IGNORECASE)
ACTION_PATTERN = re.compile(r'<form[^>]*action=["\']([^"\']*)["\']', re.IGNORECASE)
METHOD_PATTERN = re.compile(r'<form[^>]*method=["\']([^"\']*)["\']', re.IGNORECASE)


class Scanner(BaseScanner):
    name = "csrf"

    async def scan(self, url: str, client: HttpClient) -> list[ScanResult]:
        results: list[ScanResult] = []

        resp = await client.get(url)
        body = resp.text

        forms = FORM_PATTERN.findall(body)
        if not forms:
            return results

        # SameSite cookie check
        cookies_safe = self._check_samesite_cookies(resp)

        for i, form_html in enumerate(forms):
            method_match = METHOD_PATTERN.search(form_html)
            method = method_match.group(1).upper() if method_match else "GET"

            if method == "GET":
                continue  # GET forms are generally not critical for CSRF

            action_match = ACTION_PATTERN.search(form_html)
            action = action_match.group(1) if action_match else url

            input_names = INPUT_PATTERN.findall(form_html)
            input_names_lower = [n.lower() for n in input_names]

            has_csrf_token = any(
                token_name in name
                for name in input_names_lower
                for token_name in CSRF_TOKEN_NAMES
            )

            if not has_csrf_token and not cookies_safe:
                results.append(ScanResult(
                    scanner=self.name,
                    severity="HIGH",
                    url=url,
                    detail=f"No CSRF protection — Form #{i+1} ({method} {action})",
                    evidence=f"No CSRF token found. Input fields: {', '.join(input_names[:5])}",
                ))
            elif not has_csrf_token and cookies_safe:
                results.append(ScanResult(
                    scanner=self.name,
                    severity="LOW",
                    url=url,
                    detail=f"No CSRF token but SameSite cookie present — Form #{i+1}",
                    evidence="SameSite cookie protection found, but token-based protection is recommended",
                ))

        return results

    @staticmethod
    def _check_samesite_cookies(resp) -> bool:
        """Check if SameSite flag is present in Set-Cookie headers."""
        cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, 'get_list') else []
        if not cookies:
            raw = resp.headers.get("set-cookie", "")
            cookies = [raw] if raw else []

        for cookie in cookies:
            if "samesite=strict" in cookie.lower() or "samesite=lax" in cookie.lower():
                return True
        return False
