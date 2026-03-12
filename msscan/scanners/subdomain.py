"""Subdomain enumeration scanner via DNS brute-force.

Includes wildcard DNS detection and CNAME subdomain-takeover checks.
"""

from __future__ import annotations

import asyncio
import random
import string

from typing import AsyncIterator

import dns.asyncresolver
import dns.resolver

from msscan.core.context import ScanContext
from msscan.core.events import ScanEvent, FindingEvent, ProgressEvent
from msscan.core.result import ScanResult
from msscan.scanners.base import BaseScanner
from msscan.utils.payloads import load_payloads

from urllib.parse import urlparse

# Known services vulnerable to subdomain takeover via dangling CNAME.
VULNERABLE_CNAME_TARGETS: list[str] = [
    "amazonaws.com",
    "s3.amazonaws.com",
    "azurewebsites.net",
    "cloudapp.azure.com",
    "azure-api.net",
    "azurefd.net",
    "github.io",
    "herokuapp.com",
    "shopify.com",
    "fastly.net",
    "pantheon.io",
    "ghost.io",
    "surge.sh",
    "bitbucket.io",
    "wordpress.com",
    "zendesk.com",
    "readme.io",
    "statuspage.io",
    "helpjuice.com",
]

_CVSS_TAKEOVER_HIGH = (
    8.6,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
)
_CVSS_TAKEOVER_MEDIUM = (
    5.3,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
)
_CVSS_SUBDOMAIN_INFO = (
    0.0,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
)


class Scanner(BaseScanner):
    name = "subdomain"
    description = "Subdomain enumeration with wildcard detection and takeover checks."
    author = "msscan"

    @property
    def version(self) -> str:
        return "1.1"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[ScanEvent]:
        url = ctx.target

        wordlist = load_payloads("subdomains.txt")
        if not wordlist:
            wordlist = self._default_wordlist()

        parsed = urlparse(url)
        domain = parsed.netloc.split(":")[0]

        # --- Create a reusable DNS resolver (once for all queries) ---
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 3.0

        # --- Wildcard DNS detection ---
        wildcard_ips: set[str] = set()
        random_sub = "".join(random.choices(string.ascii_lowercase, k=12))
        try:
            answers = await resolver.resolve(f"{random_sub}.{domain}", "A")
            wildcard_ips = {rdata.address for rdata in answers}
        except Exception:
            pass  # No wildcard — this is the common/expected case.

        if ctx.is_cancelled:
            return

        yield ProgressEvent(
            scanner_name=self.name,
            current=0,
            total=len(wordlist),
            message="Wildcard detection complete, starting DNS brute-force",
        )

        # --- Parallel DNS queries via semaphore (prevents flooding) ---
        sem = asyncio.Semaphore(20)
        tasks = [self._resolve(sub, domain, sem, resolver) for sub in wordlist]
        resolved = await asyncio.gather(*tasks)

        for idx, (subdomain, ips, cnames) in enumerate(resolved):
            if ctx.is_cancelled:
                return

            full = f"{subdomain}.{domain}"
            full_url = f"https://{full}"

            # Check for CNAME takeover opportunities regardless of wildcard.
            takeover_result = self._check_takeover(full_url, ips, cnames)
            if takeover_result is not None:
                yield FindingEvent(result=takeover_result)

            if not ips:
                continue

            # Filter out wildcard-only results.
            if wildcard_ips and set(ips).issubset(wildcard_ips):
                continue

            yield FindingEvent(result=ScanResult(
                scanner=self.name,
                severity="INFO",
                url=full_url,
                detail=f"Subdomain found: {full}",
                evidence=f"IP: {', '.join(ips)}",
                cwe_id="",
                confidence="HIGH",
                confidence_score=0.9,
                cvss_score=_CVSS_SUBDOMAIN_INFO[0],
                cvss_vector=_CVSS_SUBDOMAIN_INFO[1],
                exploit_scenario="Discovered subdomain increases the externally reachable attack surface.",
            ))

            if (idx + 1) % 10 == 0 or idx + 1 == len(resolved):
                yield ProgressEvent(
                    scanner_name=self.name,
                    current=idx + 1,
                    total=len(resolved),
                    message=f"Processed {idx + 1}/{len(resolved)} subdomains",
                )

    @staticmethod
    async def _resolve(
        sub: str, domain: str, sem: asyncio.Semaphore,
        resolver: dns.asyncresolver.Resolver,
    ) -> tuple[str, list[str], list[str]]:
        """Resolve A and CNAME records for *sub.domain*.

        Uses a shared DNS resolver instance to avoid re-initialization overhead.
        Returns ``(subdomain, ips, cnames)`` where *cnames* is a list of
        CNAME target strings (may be empty).
        """
        fqdn = f"{sub}.{domain}"
        ips: list[str] = []
        cnames: list[str] = []

        async with sem:
            # Query CNAME records.
            try:
                cname_answers = await resolver.resolve(fqdn, "CNAME")
                cnames = [rdata.target.to_text().rstrip(".") for rdata in cname_answers]
            except Exception:
                pass

            # Query A records.
            try:
                a_answers = await resolver.resolve(fqdn, "A")
                ips = [rdata.address for rdata in a_answers]
            except Exception:
                pass

        return sub, ips, cnames

    # ------------------------------------------------------------------
    # CNAME takeover helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _matches_vulnerable_service(cname: str) -> bool:
        """Return True if *cname* ends with a known vulnerable service."""
        cname_lower = cname.lower()
        return any(
            cname_lower == target or cname_lower.endswith(f".{target}")
            for target in VULNERABLE_CNAME_TARGETS
        )

    @classmethod
    def _check_takeover(
        cls, url: str, ips: list[str], cnames: list[str]
    ) -> ScanResult | None:
        """Evaluate CNAME records for potential subdomain takeover.

        Returns a ``ScanResult`` when a noteworthy CNAME is found, or
        ``None`` otherwise.
        """
        vulnerable_cnames = [c for c in cnames if cls._matches_vulnerable_service(c)]
        if not vulnerable_cnames:
            return None

        cname_evidence = f"CNAME: {', '.join(vulnerable_cnames)}"

        if not ips:
            # CNAME points to a vulnerable service AND no A record resolves.
            return ScanResult(
                scanner="subdomain",
                severity="HIGH",
                url=url,
                detail="Potential subdomain takeover",
                evidence=cname_evidence,
                confidence="HIGH",
                confidence_score=0.85,
                cvss_score=_CVSS_TAKEOVER_HIGH[0],
                cvss_vector=_CVSS_TAKEOVER_HIGH[1],
                exploit_scenario=(
                    "Dangling CNAME may allow an attacker to claim the service and host content."
                ),
                cwe_id="CWE-345",
                remediation="Remove dangling DNS record or reclaim the service",
            )

        # CNAME points to a vulnerable service but A record does resolve.
        return ScanResult(
            scanner="subdomain",
            severity="MEDIUM",
            url=url,
            detail="CNAME points to third-party service",
            evidence=cname_evidence,
            confidence="MEDIUM",
            confidence_score=0.6,
            cvss_score=_CVSS_TAKEOVER_MEDIUM[0],
            cvss_vector=_CVSS_TAKEOVER_MEDIUM[1],
            exploit_scenario=(
                "Third-party service association may be abused if the account is unclaimed."
            ),
            cwe_id="CWE-345",
            remediation="Remove dangling DNS record or reclaim the service",
        )

    # ------------------------------------------------------------------
    # Fallback wordlist
    # ------------------------------------------------------------------

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
