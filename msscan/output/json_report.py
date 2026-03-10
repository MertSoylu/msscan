"""JSON report generator — JSON Lines and summary JSON output."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from msscan.core.events import FindingEvent, ScanEvent
from msscan.core.result import ScanResult
from msscan.output.base import OutputFormatter


class JsonFormatter(OutputFormatter):
    """Writes findings as JSON Lines and a final summary."""

    def __init__(self, output_path: str) -> None:
        self.output_path = output_path
        self._findings: list[ScanResult] = []

    async def on_event(self, event: ScanEvent) -> None:
        if isinstance(event, FindingEvent):
            self._findings.append(event.result)

    async def finalize(self) -> None:
        generate_json_report(self._findings, self.output_path)


def generate_json_report(
    results: list[ScanResult],
    output_path: str,
    url: str = "",
    elapsed_secs: float = 0.0,
) -> None:
    """Generate a JSON report file from scan results."""
    severity_counts: dict[str, int] = defaultdict(int)
    for r in results:
        severity_counts[r.severity] += 1

    report = {
        "tool": "msscan",
        "version": _get_version(),
        "target": url,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "elapsed_seconds": round(elapsed_secs, 2),
        "summary": {
            "total_findings": len(results),
            "severity_counts": dict(severity_counts),
        },
        "findings": [r.to_dict() for r in results],
    }

    Path(output_path).write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _get_version() -> str:
    try:
        from msscan import __version__
        return __version__
    except ImportError:
        return "unknown"
