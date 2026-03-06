"""SQL Injection scanner — error-based and time-based blind."""

from __future__ import annotations

import time

from msscan.core.http_client import HttpClient
from msscan.core.result import ScanResult
from msscan.scanners.base import BaseScanner
from msscan.utils.helpers import inject_param, extract_params
from msscan.utils.payloads import load_payloads

# SQL error message patterns
SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "microsoft ole db provider for sql server",
    "microsoft ole db provider for odbc drivers",
    "syntax error in string in query expression",
    "pg_query():",
    "pg_exec():",
    "psqlexception",
    "ora-01756",
    "ora-00933",
    "sqlite3.operationalerror",
    "sqliteexception",
    "jdbc.sqltransientconnectionexception",
    "sql syntax.*mysql",
    "valid mysql result",
    "postgresql.*error",
    "warning.*pg_",
    "driver.* sql",
]

TIME_BASED_THRESHOLD = 5.0  # seconds


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
            # Error-based SQLi
            found_error = await self._test_error_based(url, param_name, payloads, client, results)

            # Time-based blind SQLi (only if error-based was not found)
            if not found_error:
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

                for pattern in SQL_ERROR_PATTERNS:
                    if pattern in body:
                        results.append(ScanResult(
                            scanner=self.name,
                            severity="CRITICAL",
                            url=test_url,
                            detail=f"Error-based SQLi — SQL error in '{param}' parameter",
                            evidence=f"Pattern: {pattern} | Payload: {payload}",
                        ))
                        return True
            except Exception:
                continue
        return False

    async def _test_time_based(
        self, url: str, param: str,
        client: HttpClient, results: list[ScanResult],
    ) -> None:
        time_payloads = [
            "1' AND SLEEP(5)--",
            "1' AND SLEEP(5)#",
            "1; WAITFOR DELAY '0:0:5'--",
            "1' OR SLEEP(5)--",
            "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        ]
        for payload in time_payloads:
            test_url = inject_param(url, param, payload)
            try:
                t0 = time.monotonic()
                await client.get(test_url)
                elapsed = time.monotonic() - t0

                if elapsed >= TIME_BASED_THRESHOLD:
                    results.append(ScanResult(
                        scanner=self.name,
                        severity="HIGH",
                        url=test_url,
                        detail=f"Time-based Blind SQLi — {elapsed:.1f}s delay in '{param}' parameter",
                        evidence=f"Payload: {payload} | Duration: {elapsed:.1f}s",
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
