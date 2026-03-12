"""SSRF (Server-Side Request Forgery) scanner with differential analysis."""

from __future__ import annotations

from typing import AsyncIterator

from msscan.core.context import ScanContext
from msscan.core.events import ScanEvent, FindingEvent, ProgressEvent
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

# Structured indicators: (pattern, specificity, description)
# HIGH specificity → CRITICAL finding; MEDIUM specificity → HIGH finding.
SSRF_INDICATORS: list[tuple[str, str, str]] = [
    # File content — unambiguous proof of internal access
    ("root:x:0:0",          "HIGH",   "/etc/passwd content"),
    ("daemon:x:",            "HIGH",   "/etc/passwd content"),
    ("[boot loader]",        "HIGH",   "Windows win.ini content"),
    ("for 16-bit app support", "HIGH", "Windows win.ini content"),
    # Cloud metadata responses
    ("ami-id",               "HIGH",   "AWS EC2 metadata field"),
    ("instance-id",          "HIGH",   "Cloud instance metadata field"),
    ("iam/security-credentials", "HIGH", "AWS IAM credentials endpoint"),
    ("computemetadata",      "HIGH",   "GCP metadata API response"),
    ("metadata/instance",    "HIGH",   "Azure IMDS response"),
    ("droplet_id",           "HIGH",   "DigitalOcean metadata field"),
    # Service banners / error responses that indicate internal server access
    ("ssh-2.0",              "HIGH",   "SSH server banner"),
    ("mysql_native_password","HIGH",   "MySQL server banner"),
    ("redis_version",        "HIGH",   "Redis server response"),
    ("elasticsearch",        "HIGH",   "Elasticsearch response"),
    # Medium-specificity — strong hints but could occasionally appear elsewhere
    ("internal server error","MEDIUM", "Internal error message"),
    ("connection refused",   "MEDIUM", "Internal connection error"),
]

_REMEDIATION = (
    "Implement an allowlist of permitted URL schemes and destinations. "
    "Block requests to private IP ranges (RFC 1918) and link-local addresses. "
    "Use a dedicated egress proxy to enforce network-level restrictions."
)

_CVSS_SSRF = (
    9.1,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
)

# Benign value used to establish a baseline response for differential analysis.
_BENIGN_VALUE = "https://example.com"


class Scanner(BaseScanner):
    name = "ssrf"
    description = "SSRF detection with differential response analysis."
    author = "msscan"

    @property
    def version(self) -> str:
        return "1.1"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[ScanEvent]:
        url = ctx.target
        client = ctx.client

        payloads = load_payloads("ssrf.txt")
        if not payloads:
            payloads = self._default_payloads()

        params = list(extract_params(url).keys())
        for sp in SSRF_PARAMS:
            if sp not in params:
                params.append(sp)

        for param_idx, param_name in enumerate(params):
            if ctx.is_cancelled:
                return

            # Fetch baseline response with a safe, benign URL value.
            baseline_body: str | None = None
            baseline_len: int = 0
            try:
                baseline_url = inject_param(url, param_name, _BENIGN_VALUE)
                baseline_resp = await client.get(baseline_url)
                baseline_body = baseline_resp.text.lower()
                baseline_len = len(baseline_body)
            except Exception:
                pass

            for payload in payloads:
                if ctx.is_cancelled:
                    return

                test_url = inject_param(url, param_name, payload)
                try:
                    resp = await client.get(test_url)
                    body = resp.text.lower()

                    for pattern, specificity, description in SSRF_INDICATORS:
                        if pattern.lower() not in body:
                            continue

                        # For MEDIUM-specificity indicators apply differential check:
                        # only flag if the payload response is meaningfully different
                        # from the baseline (avoids flagging pre-existing content).
                        if specificity == "MEDIUM" and baseline_body is not None:
                            body_len = len(body)
                            max_len = max(body_len, baseline_len, 1)
                            diff_pct = abs(body_len - baseline_len) / max_len
                            if diff_pct < 0.10 and pattern.lower() in baseline_body:
                                continue  # Indicator was already in baseline

                        severity = "CRITICAL" if specificity == "HIGH" else "HIGH"
                        confidence = "HIGH" if specificity == "HIGH" else "MEDIUM"
                        confidence_score = 0.95 if specificity == "HIGH" else 0.7
                        yield FindingEvent(result=ScanResult(
                            scanner=self.name,
                            severity=severity,
                            url=test_url,
                            detail=(
                                f"SSRF — '{param_name}' parameter triggers internal request "
                                f"({description})"
                            ),
                            evidence=f"Indicator: {pattern!r} | Payload: {payload}",
                            confidence=confidence,
                            confidence_score=confidence_score,
                            cvss_score=_CVSS_SSRF[0],
                            cvss_vector=_CVSS_SSRF[1],
                            exploit_scenario=(
                                f"Server can be coerced to access internal resources ({description})."
                            ),
                            cwe_id="CWE-918",
                            remediation=_REMEDIATION,
                        ))
                        break  # One indicator is enough; skip remaining for this payload.
                    else:
                        continue
                    break  # Parameter is vulnerable; skip remaining payloads.

                except Exception:
                    continue

            yield ProgressEvent(
                scanner_name=self.name,
                current=param_idx + 1,
                total=len(params),
                message=f"Tested parameter '{param_name}'",
            )

    @staticmethod
    def _default_payloads() -> list[str]:
        return [
            # Standard localhost variants
            "http://127.0.0.1",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://localhost",
            "http://0.0.0.0",
            "http://[::1]",
            # Bypass variants for localhost (IP format obfuscation)
            "http://127.1",                                  # Short-form IPv4
            "http://2130706433",                             # 127.0.0.1 in decimal
            "http://0x7f000001",                             # 127.0.0.1 in hex
            "http://0x7f.0x0.0x0.0x1",                       # 127.0.0.1 octal bypasses
            # AWS metadata
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254",
            # GCP metadata
            "http://metadata.google.internal/",
            "http://169.254.169.254/metadata/v1/instance/",
            # File access
            "file:///etc/passwd",
            "file:///c:/windows/win.ini",
        ]
