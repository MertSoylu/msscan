"""Subdomain enumeration scanner via DNS brute-force."""

from __future__ import annotations

import asyncio

import dns.resolver
import dns.asyncresolver

from msscan.core.http_client import HttpClient
from msscan.core.result import ScanResult
from msscan.scanners.base import BaseScanner
from msscan.utils.helpers import get_base_url
from msscan.utils.payloads import load_payloads

from urllib.parse import urlparse


class Scanner(BaseScanner):
    name = "subdomain"

    async def scan(self, url: str, client: HttpClient) -> list[ScanResult]:
        results: list[ScanResult] = []
        wordlist = load_payloads("subdomains.txt")
        if not wordlist:
            wordlist = self._default_wordlist()

        parsed = urlparse(url)
        domain = parsed.netloc.split(":")[0]

        # Parallel DNS queries via semaphore (prevents flooding)
        sem = asyncio.Semaphore(20)
        tasks = [self._resolve(sub, domain, sem) for sub in wordlist]
        resolved = await asyncio.gather(*tasks)

        for subdomain, ips in resolved:
            if ips:
                full = f"{subdomain}.{domain}"
                results.append(ScanResult(
                    scanner=self.name,
                    severity="INFO",
                    url=f"https://{full}",
                    detail=f"Subdomain found: {full}",
                    evidence=f"IP: {', '.join(ips)}",
                ))

        return results

    @staticmethod
    async def _resolve(sub: str, domain: str, sem: asyncio.Semaphore) -> tuple[str, list[str]]:
        fqdn = f"{sub}.{domain}"
        async with sem:
            try:
                resolver = dns.asyncresolver.Resolver()
                resolver.lifetime = 3.0
                answers = await resolver.resolve(fqdn, "A")
                return sub, [rdata.address for rdata in answers]
            except Exception:
                return sub, []

    @staticmethod
    def _default_wordlist() -> list[str]:
        return [
            "www", "mail", "ftp", "admin", "api", "dev", "staging",
            "test", "beta", "app", "portal", "webmail", "ns1", "ns2",
            "mx", "vpn", "cdn", "static", "assets", "img", "docs",
            "blog", "shop", "store", "m", "mobile", "login", "auth",
            "dashboard", "panel", "db", "database", "jenkins", "git",
            "gitlab", "ci", "jira", "confluence", "grafana", "monitor",
            "status", "help", "support", "forum", "wiki", "intranet",
        ]
