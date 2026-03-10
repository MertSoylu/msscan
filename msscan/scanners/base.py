"""BaseScanner — abstract interface for all scanner modules (V2 protocol)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import AsyncIterator

from msscan.core.context import ScanContext
from msscan.core.events import ScanEvent


class BaseScanner(ABC):
    """All scanner modules inherit from this class and implement scan().

    V2 protocol changes:
    - scan() now accepts a ScanContext instead of (url, client)
    - scan() returns AsyncIterator[ScanEvent] instead of list[ScanResult]
    - Scanners yield FindingEvent/ProgressEvent as they discover results
    - Scanners should check ctx.is_cancelled periodically

    Convention: each module in msscan/scanners/ must define exactly one
    subclass of BaseScanner named `Scanner`.
    """

    name: str = "base"

    @abstractmethod
    async def scan(self, ctx: ScanContext) -> AsyncIterator[ScanEvent]:
        """Run the scanner against the target in ctx.

        Yields ScanEvent instances as findings are discovered.
        """
        ...
        # Make this an async generator for type checking
        yield  # type: ignore[misc]  # pragma: no cover

    @property
    def description(self) -> str:
        """Human-readable description of this scanner."""
        return ""

    @property
    def version(self) -> str:
        """Scanner version string."""
        return "2.0"
