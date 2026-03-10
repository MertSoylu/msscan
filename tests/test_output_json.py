"""Tests for JSON report output."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from msscan.core.result import ScanResult
from msscan.output.json_report import generate_json_report


def _make_result(**kwargs) -> ScanResult:
    defaults = dict(
        scanner="xss", severity="HIGH", url="https://test.com",
        detail="XSS found", cwe_id="CWE-79", confidence="HIGH",
    )
    defaults.update(kwargs)
    return ScanResult(**defaults)


def test_json_report_structure(tmp_path):
    """JSON report should contain required top-level keys."""
    results = [_make_result()]
    path = str(tmp_path / "report.json")
    generate_json_report(results, path, url="https://test.com", elapsed_secs=1.5)

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    assert data["tool"] == "msscan"
    assert "version" in data
    assert data["target"] == "https://test.com"
    assert "timestamp" in data
    assert data["elapsed_seconds"] == 1.5
    assert data["summary"]["total_findings"] == 1
    assert len(data["findings"]) == 1


def test_json_report_finding_fields(tmp_path):
    """Each finding in JSON should have all ScanResult fields."""
    results = [_make_result(evidence="<script>", remediation="encode output")]
    path = str(tmp_path / "report.json")
    generate_json_report(results, path)

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    finding = data["findings"][0]
    assert finding["scanner"] == "xss"
    assert finding["severity"] == "HIGH"
    assert finding["cwe_id"] == "CWE-79"
    assert finding["evidence"] == "<script>"
    assert finding["remediation"] == "encode output"


def test_json_report_empty_results(tmp_path):
    """Empty results should produce valid JSON with zero findings."""
    path = str(tmp_path / "report.json")
    generate_json_report([], path)

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    assert data["summary"]["total_findings"] == 0
    assert data["findings"] == []


def test_json_report_severity_counts(tmp_path):
    """Severity counts should reflect the results."""
    results = [
        _make_result(severity="HIGH"),
        _make_result(severity="HIGH"),
        _make_result(severity="MEDIUM"),
        _make_result(severity="LOW"),
    ]
    path = str(tmp_path / "report.json")
    generate_json_report(results, path)

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    counts = data["summary"]["severity_counts"]
    assert counts["HIGH"] == 2
    assert counts["MEDIUM"] == 1
    assert counts["LOW"] == 1


def test_json_report_valid_json(tmp_path):
    """Output file should be parseable JSON."""
    results = [_make_result()]
    path = str(tmp_path / "report.json")
    generate_json_report(results, path)

    # Should not raise
    content = Path(path).read_text(encoding="utf-8")
    json.loads(content)
