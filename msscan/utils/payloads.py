"""Payload loading utilities."""

from __future__ import annotations

from pathlib import Path

# Payload files live two levels above this module (project root / payloads/)
PAYLOADS_DIR = Path(__file__).resolve().parent.parent.parent / "payloads"


def load_payloads(filename: str) -> list[str]:
    """Read a payload file and return non-empty, non-comment lines."""
    filepath = PAYLOADS_DIR / filename
    if not filepath.exists():
        return []
    lines = filepath.read_text(encoding="utf-8").splitlines()
    # Skip blank lines and lines starting with '#' (comments)
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]
