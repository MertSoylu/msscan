"""Output formatter base class — abstract interface for all output formats."""

from __future__ import annotations

from abc import ABC, abstractmethod

from msscan.core.events import ScanEvent


class OutputFormatter(ABC):
    """Abstract base class for output formatters.

    Formatters receive scan events in real-time and produce output
    in their respective format.
    """

    @abstractmethod
    async def on_event(self, event: ScanEvent) -> None:
        """Handle a scan event (finding, progress, error)."""
        ...

    @abstractmethod
    async def finalize(self) -> None:
        """Called after all events have been emitted. Flush output."""
        ...
