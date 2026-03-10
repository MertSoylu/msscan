"""ScanResult dataclass — common output format for all scanners."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime


@dataclass
class ScanResult:
    """A single security finding produced by any scanner module."""

    scanner: str        # module name that produced this finding (e.g. "xss")
    severity: str       # CRITICAL | HIGH | MEDIUM | LOW | INFO
    url: str            # exact URL where the finding was detected
    detail: str         # human-readable description of the finding
    evidence: str = ""  # payload or response snippet that proves the finding
    confidence: str = "MEDIUM"  # HIGH | MEDIUM | LOW
    confidence_score: float = 0.5  # 0.0-1.0 numeric confidence for CI/CD thresholding
    remediation: str = ""  # actionable fix guidance
    cwe_id: str = ""  # e.g. "CWE-79"
    references: list[str] = field(default_factory=list)
    # ISO 8601 timestamp with seconds precision, auto-set at creation time
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))

    def to_dict(self) -> dict:
        """Convert to a plain dictionary for serialization."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialize to a JSON string."""
        return json.dumps(self.to_dict(), ensure_ascii=False)
