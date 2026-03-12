"""BaseScanner — abstract interface for all scanner modules (V2 protocol)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import AsyncIterator

from msscan.core.context import ScanContext
from msscan.core.events import ScanEvent


class BaseScanner(ABC):
    """All scanner modules inherit from this class and implement scan().

    Required metadata properties:
    - name: short identifier (e.g. "xss")
    - version: semantic string (e.g. "1.0")
    - description: human-readable summary
    - author: plugin author or organization name

    V2 protocol changes:
    - scan() now accepts a ScanContext instead of (url, client)
    - scan() returns AsyncIterator[ScanEvent] instead of list[ScanResult]
    - Scanners yield FindingEvent/ProgressEvent as they discover results
    - Scanners should check ctx.is_cancelled periodically

    Convention: each module in msscan/scanners/ must define exactly one
    subclass of BaseScanner named `Scanner`.

    Example:
        class Scanner(BaseScanner):
            name = "custom_check"
            description = "Detects custom issues"
            author = "Your Name"

            @property
            def version(self) -> str:
                return "1.0"

            async def scan(self, ctx: ScanContext) -> AsyncIterator[ScanEvent]:
                ...
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
    def author(self) -> str:
        """Author or organization of this scanner."""
        return ""

    @property
    def version(self) -> str:
        """Scanner version string."""
        return "1.0"

    def validate(self) -> None:
        """Validate required scanner metadata fields."""
        missing: list[str] = []
        if not getattr(self, "name", ""):
            missing.append("name")
        if not self.version:
            missing.append("version")
        if not self.description:
            missing.append("description")
        if not self.author:
            missing.append("author")
        if missing:
            raise ValueError(f"Scanner metadata missing: {', '.join(missing)}")
