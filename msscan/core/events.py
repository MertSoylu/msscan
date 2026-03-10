"""Scan event types — event-driven architecture for real-time output."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from msscan.core.result import ScanResult


@dataclass
class ScanEvent:
    """Base class for all scan events."""

    timestamp: str = field(
        default_factory=lambda: datetime.now().isoformat(timespec="seconds")
    )


@dataclass
class FindingEvent(ScanEvent):
    """Emitted when a scanner discovers a vulnerability."""

    result: ScanResult = field(default_factory=lambda: ScanResult(
        scanner="", severity="INFO", url="", detail=""
    ))


@dataclass
class ProgressEvent(ScanEvent):
    """Emitted to report scanner progress."""

    scanner_name: str = ""
    current: int = 0
    total: int = 0
    message: str = ""


@dataclass
class ErrorEvent(ScanEvent):
    """Emitted when a scanner encounters a non-fatal error."""

    scanner_name: str = ""
    error: str = ""
    exception: Exception | None = field(default=None, repr=False)
