"""Reflected XSS scanner with context-aware severity classification."""

from __future__ import annotations

import re

from msscan.core.http_client import HttpClient
from msscan.core.result import ScanResult
from msscan.scanners.base import BaseScanner
from msscan.utils.helpers import inject_param, extract_params
from msscan.utils.payloads import load_payloads

_REMEDIATION = (
    "Apply context-sensitive output encoding: HTML-encode in HTML body/attributes, "
    "JS-encode inside script blocks. Use a templating engine with auto-escaping."
)

# Compiled patterns used by _detect_reflection_context
_RE_SCRIPT_OPEN = re.compile(r"<script[\s>]", re.IGNORECASE)
_RE_SCRIPT_CLOSE = re.compile(r"</script>", re.IGNORECASE)
_RE_ATTR = re.compile(r'=\s*["\'][^"\']*$', re.IGNORECASE)
_RE_COMMENT = re.compile(r"<!--", re.IGNORECASE)


def _detect_reflection_context(body: str, payload: str) -> str:
    """Return the reflection context of *payload* inside *body*.

    Possible return values (in priority order):
    - ``"encoded"``        – angle brackets are HTML-entity-encoded
    - ``"javascript"``     – payload sits inside a <script> block
    - ``"html_attribute"`` – payload sits inside an HTML attribute value
    - ``"html_comment"``   – payload sits inside an HTML comment
    - ``"html_body"``      – payload reflected in HTML body (unescaped)
    - ``"none"``           – payload not found in body
    """
    idx = body.find(payload)
    if idx == -1:
        # Also check for partial reflection (just the tag markers)
        if "&lt;" in body or "&amp;lt;" in body:
            return "encoded"
        return "none"

    # Check HTML-entity encoding of the payload's angle brackets.
    # If < became &lt; or > became &gt; the browser won't execute it.
    if "<" in payload and "&lt;" in body[max(0, idx - 10): idx + len(payload) + 10]:
        return "encoded"
    if ">" in payload and "&gt;" in body[max(0, idx - 10): idx + len(payload) + 10]:
        return "encoded"

    # Extract a window of ~300 chars around the reflection point.
    window_start = max(0, idx - 200)
    window_end = min(len(body), idx + len(payload) + 200)
    window = body[window_start:window_end]

    # Check if we're inside a <script>...</script> block.
    prefix = body[:idx]
    script_opens = len(_RE_SCRIPT_OPEN.findall(prefix))
    script_closes = len(_RE_SCRIPT_CLOSE.findall(prefix))
    if script_opens > script_closes:
        return "javascript"

    # Check if inside an HTML attribute (heuristic: ="...payload or '...payload).
    if _RE_ATTR.search(body[max(0, idx - 100): idx]):
        return "html_attribute"

    # Check if inside an HTML comment.
    if "<!--" in window and "-->" not in window[window.find("<!--") + 4:]:
        return "html_comment"

    return "html_body"


# Severity / confidence mapping per context
_CONTEXT_MAP: dict[str, tuple[str, str]] = {
    "javascript":     ("CRITICAL", "HIGH"),
    "html_body":      ("HIGH",     "HIGH"),
    "html_attribute": ("HIGH",     "MEDIUM"),
    "html_comment":   ("LOW",      "LOW"),
    "encoded":        ("INFO",     "LOW"),
}


class Scanner(BaseScanner):
    name = "xss"

    async def scan(self, url: str, client: HttpClient) -> list[ScanResult]:
        results: list[ScanResult] = []
        payloads = load_payloads("xss.txt")
        if not payloads:
            payloads = self._default_payloads()

        params = extract_params(url)
        if not params:
            params = {p: ["test"] for p in ["q", "search", "query", "s", "id", "page", "name"]}

        for param_name in params:
            for payload in payloads:
                test_url = inject_param(url, param_name, payload)
                try:
                    resp = await client.get(test_url)
                    body = resp.text

                    context = _detect_reflection_context(body, payload)
                    if context == "none":
                        continue

                    severity, confidence = _CONTEXT_MAP[context]
                    results.append(ScanResult(
                        scanner=self.name,
                        severity=severity,
                        url=test_url,
                        detail=(
                            f"Reflected XSS ({context}) — payload reflected in "
                            f"'{param_name}' parameter"
                        ),
                        evidence=payload,
                        confidence=confidence,
                        cwe_id="CWE-79",
                        remediation=_REMEDIATION,
                    ))
                    break  # Parameter already classified, skip remaining payloads
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
