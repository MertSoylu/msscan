"""Tests for SARIF 2.1.0 report output."""

from __future__ import annotations

import json
from pathlib import Path


from msscan.core.result import ScanResult
from msscan.output.sarif_report import generate_sarif_report


def _make_result(**kwargs) -> ScanResult:
    defaults = dict(
        scanner="xss", severity="HIGH", url="https://test.com",
        detail="Reflected XSS", cwe_id="CWE-79", confidence="HIGH",
        confidence_score=0.9,
        cvss_score=6.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    )
    defaults.update(kwargs)
    return ScanResult(**defaults)


def test_sarif_schema_version(tmp_path):
    """SARIF output should declare version 2.1.0."""
    path = str(tmp_path / "results.sarif")
    generate_sarif_report([_make_result()], path, url="https://test.com")

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert "$schema" in data


def test_sarif_tool_driver(tmp_path):
    """Tool driver should identify msscan."""
    path = str(tmp_path / "results.sarif")
    generate_sarif_report([_make_result()], path)

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    driver = data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "msscan"
    assert "version" in driver


def test_sarif_rules_generated(tmp_path):
    """SARIF rules should be generated from unique scanner/CWE pairs."""
    results = [
        _make_result(scanner="xss", cwe_id="CWE-79"),
        _make_result(scanner="sqli", cwe_id="CWE-89"),
        _make_result(scanner="xss", cwe_id="CWE-79"),  # duplicate rule
    ]
    path = str(tmp_path / "results.sarif")
    generate_sarif_report(results, path)

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 2  # xss/CWE-79 and sqli/CWE-89
    assert "cvssV3_1" in rules[0]["properties"]


def test_sarif_results_count(tmp_path):
    """SARIF results should match input findings count."""
    results = [_make_result() for _ in range(3)]
    path = str(tmp_path / "results.sarif")
    generate_sarif_report(results, path)

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    assert len(data["runs"][0]["results"]) == 3


def test_sarif_severity_mapping(tmp_path):
    """SARIF level should map from msscan severity."""
    results = [
        _make_result(severity="CRITICAL"),
        _make_result(severity="MEDIUM"),
        _make_result(severity="LOW"),
        _make_result(severity="INFO"),
    ]
    path = str(tmp_path / "results.sarif")
    generate_sarif_report(results, path)

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    levels = [r["level"] for r in data["runs"][0]["results"]]
    assert levels[0] == "error"    # CRITICAL
    assert levels[1] == "warning"  # MEDIUM
    assert levels[2] == "note"     # LOW
    assert levels[3] == "note"     # INFO


def test_sarif_result_properties(tmp_path):
    """Each SARIF result should carry msscan-specific properties."""
    path = str(tmp_path / "results.sarif")
    generate_sarif_report([_make_result()], path)

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    props = data["runs"][0]["results"][0]["properties"]
    assert props["severity"] == "HIGH"
    assert props["confidence"] == "HIGH"
    assert props["confidence_score"] == 0.9
    assert props["scanner"] == "xss"
    assert props["cvssScore"] == 6.1
    assert props["cvssVector"].startswith("CVSS:3.1/")


def test_sarif_cwe_taxonomy(tmp_path):
    """SARIF should include CWE taxonomy when CWE IDs are present."""
    path = str(tmp_path / "results.sarif")
    generate_sarif_report([_make_result(cwe_id="CWE-79")], path)

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    taxonomies = data["runs"][0]["taxonomies"]
    assert len(taxonomies) == 1
    assert taxonomies[0]["name"] == "CWE"
    taxa = taxonomies[0]["taxa"]
    assert len(taxa) == 1
    assert taxa[0]["id"] == "CWE-79"


def test_sarif_empty_results(tmp_path):
    """Empty results should produce valid SARIF."""
    path = str(tmp_path / "results.sarif")
    generate_sarif_report([], path)

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    assert data["runs"][0]["results"] == []
    assert data["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_valid_json(tmp_path):
    """Output should be valid JSON."""
    path = str(tmp_path / "results.sarif")
    generate_sarif_report([_make_result()], path)
    json.loads(Path(path).read_text(encoding="utf-8"))
