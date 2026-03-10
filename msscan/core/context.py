"""ScanContext — shared context object passed to all scanners."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from msscan.core.config import ScanConfig
    from msscan.core.http_client import HttpClient


@dataclass
class ScanContext:
    """Shared context passed to every scanner during a scan run.

    Replaces the old (url, client) pair with a richer context that
    supports progress reporting, cooperative cancellation, and
    access to scan configuration.
    """

    target: str
    client: "HttpClient"
    config: "ScanConfig"
    cancel_token: asyncio.Event = field(default_factory=asyncio.Event)

    @property
    def is_cancelled(self) -> bool:
        """Check if the scan has been cancelled."""
        return self.cancel_token.is_set()
