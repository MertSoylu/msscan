"""BaseScanner — abstract interface for all scanner modules."""

from __future__ import annotations

from abc import ABC, abstractmethod

from msscan.core.http_client import HttpClient
from msscan.core.result import ScanResult


class BaseScanner(ABC):
    """All scanner modules inherit from this class and implement scan().

    Convention: each module in msscan/scanners/ must define exactly one
    subclass of BaseScanner named `Scanner`.
    """

    name: str = "base"

    @abstractmethod
    async def scan(self, url: str, client: HttpClient) -> list[ScanResult]:
        """Run the scanner against url using the shared HTTP client.

        Returns an empty list if no vulnerabilities are found.
        """
        ...
