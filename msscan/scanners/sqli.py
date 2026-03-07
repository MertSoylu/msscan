"""SQL Injection scanner — error-based, boolean-based blind, and time-based blind."""

from __future__ import annotations

import re
import time

from msscan.core.http_client import HttpClient
from msscan.core.result import ScanResult
from msscan.scanners.base import BaseScanner
from msscan.utils.helpers import inject_param, extract_params
from msscan.utils.payloads import load_payloads

_REMEDIATION = "Use parameterized queries / prepared statements instead of string concatenation"

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

    async def scan(self, url: str, client: HttpClient) -> list[ScanResult]:
        results: list[ScanResult] = []
        payloads = load_payloads("sqli.txt")
        if not payloads:
            payloads = self._default_payloads()

        params = extract_params(url)
        if not params:
            params = {p: ["1"] for p in ["id", "page", "cat", "item", "user", "product"]}

        for param_name in params:
            # 1. Error-based SQLi
            found = await self._test_error_based(url, param_name, payloads, client, results)

            # 2. Boolean-based blind SQLi (only if error-based was not found)
            if not found:
                found = await self._test_boolean_based(url, param_name, client, results)

            # 3. Time-based blind SQLi (only if neither was found)
            if not found:
                await self._test_time_based(url, param_name, client, results)

        return results

    async def _test_error_based(
        self, url: str, param: str, payloads: list[str],
        client: HttpClient, results: list[ScanResult],
    ) -> bool:
        for payload in payloads:
            test_url = inject_param(url, param, payload)
            try:
                resp = await client.get(test_url)
                body = resp.text.lower()

                for raw_pattern, compiled in _COMPILED_PATTERNS:
                    if compiled.search(body):
                        results.append(ScanResult(
                            scanner=self.name,
                            severity="CRITICAL",
                            url=test_url,
                            detail=f"Error-based SQLi — SQL error in '{param}' parameter",
                            evidence=f"Pattern: {raw_pattern} | Payload: {payload}",
                            confidence="HIGH",
                            remediation=_REMEDIATION,
                            cwe_id="CWE-89",
                        ))
                        return True
            except Exception:
                continue
        return False

    async def _test_boolean_based(
        self, url: str, param: str,
        client: HttpClient, results: list[ScanResult],
    ) -> bool:
        true_payload = "1' AND '1'='1"
        false_payload = "1' AND '1'='2"

        true_url = inject_param(url, param, true_payload)
        false_url = inject_param(url, param, false_payload)

        try:
            true_resp = await client.get(true_url)
            false_resp = await client.get(false_url)

            true_len = len(true_resp.text)
            false_len = len(false_resp.text)
            diff = abs(true_len - false_len)

            max_len = max(true_len, false_len, 1)
            pct_diff = diff / max_len

            if diff > 200 or pct_diff > 0.10:
                results.append(ScanResult(
                    scanner=self.name,
                    severity="HIGH",
                    url=true_url,
                    detail=f"Boolean-based Blind SQLi — response length difference in '{param}' parameter",
                    evidence=(
                        f"True condition length: {true_len} | "
                        f"False condition length: {false_len} | "
                        f"Difference: {diff} ({pct_diff:.1%})"
                    ),
                    confidence="MEDIUM",
                    remediation=_REMEDIATION,
                    cwe_id="CWE-89",
                ))
                return True
        except Exception:
            pass

        return False

    async def _test_time_based(
        self, url: str, param: str,
        client: HttpClient, results: list[ScanResult],
    ) -> None:
        # Measure baseline response time from 3 benign requests
        baselines: list[float] = []
        for _ in range(3):
            try:
                t0 = time.monotonic()
                await client.get(url)
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
            test_url = inject_param(url, param, payload)
            try:
                t0 = time.monotonic()
                await client.get(test_url)
                elapsed = time.monotonic() - t0

                if elapsed >= threshold:
                    results.append(ScanResult(
                        scanner=self.name,
                        severity="HIGH",
                        url=test_url,
                        detail=f"Time-based Blind SQLi — {elapsed:.1f}s delay in '{param}' parameter",
                        evidence=(
                            f"Payload: {payload} | Duration: {elapsed:.1f}s | "
                            f"Baseline: {avg_baseline:.2f}s | Threshold: {threshold:.2f}s"
                        ),
                        confidence="MEDIUM",
                        remediation=_REMEDIATION,
                        cwe_id="CWE-89",
                    ))
                    return
            except Exception:
                continue

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
