"""ScanResult dataclass — common output format for all scanners."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ScanResult:
    """A single security finding produced by any scanner module."""

    scanner: str        # module name that produced this finding (e.g. "xss")
    severity: str       # CRITICAL | HIGH | MEDIUM | LOW | INFO
    url: str            # exact URL where the finding was detected
    detail: str         # human-readable description of the finding
    evidence: str = ""  # payload or response snippet that proves the finding
    # ISO 8601 timestamp with seconds precision, auto-set at creation time
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
