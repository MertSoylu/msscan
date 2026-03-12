"""SARIF 2.1.0 report generator — for GitHub Code Scanning and SIEM integration."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from msscan.core.events import FindingEvent, ScanEvent
from msscan.core.result import ScanResult
from msscan.output.base import OutputFormatter

# SARIF severity mapping
_SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

# SARIF confidence mapping
_CONFIDENCE_TO_RANK = {
    "HIGH": 90.0,
    "MEDIUM": 60.0,
    "LOW": 30.0,
}


class SarifFormatter(OutputFormatter):
    """Writes findings in SARIF 2.1.0 format."""

    def __init__(self, output_path: str, url: str = "") -> None:
        self.output_path = output_path
        self.url = url
        self._findings: list[ScanResult] = []

    async def on_event(self, event: ScanEvent) -> None:
        if isinstance(event, FindingEvent):
            self._findings.append(event.result)

    async def finalize(self) -> None:
        generate_sarif_report(self._findings, self.output_path, url=self.url)


def generate_sarif_report(
    results: list[ScanResult],
    output_path: str,
    url: str = "",
    elapsed_secs: float = 0.0,
) -> None:
    """Generate a SARIF 2.1.0 report from scan results."""
    version = _get_version()

    rule_cvss: dict[str, tuple[float, str]] = {}
    for r in results:
        rule_id = f"{r.scanner}/{r.cwe_id}" if r.cwe_id else r.scanner
        existing = rule_cvss.get(rule_id)
        if existing is None or r.cvss_score > existing[0]:
            rule_cvss[rule_id] = (r.cvss_score, r.cvss_vector)

    # Build rules from unique (scanner, cwe_id) pairs
    rules: list[dict] = []
    rule_index: dict[str, int] = {}

    for r in results:
        rule_id = f"{r.scanner}/{r.cwe_id}" if r.cwe_id else r.scanner
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            cvss_score, cvss_vector = rule_cvss.get(rule_id, (0.0, ""))
            rule: dict = {
                "id": rule_id,
                "name": r.scanner.upper(),
                "shortDescription": {"text": r.detail[:200]},
                "defaultConfiguration": {
                    "level": _SEVERITY_TO_LEVEL.get(r.severity, "note"),
                },
                "properties": {
                    "cvssV3_1": {
                        "score": cvss_score,
                        "vector": cvss_vector,
                    },
                },
            }
            if r.cwe_id:
                cwe_num = r.cwe_id.replace("CWE-", "")
                rule["relationships"] = [{
                    "target": {
                        "id": r.cwe_id,
                        "guid": f"CWE-{cwe_num}",
                        "toolComponent": {"name": "CWE"},
                    },
                    "kinds": ["superset"],
                }]
            if r.remediation:
                rule["help"] = {"text": r.remediation}
            rules.append(rule)

    # Build results
    sarif_results: list[dict] = []
    for r in results:
        rule_id = f"{r.scanner}/{r.cwe_id}" if r.cwe_id else r.scanner
        sarif_result: dict = {
            "ruleId": rule_id,
            "ruleIndex": rule_index[rule_id],
            "level": _SEVERITY_TO_LEVEL.get(r.severity, "note"),
            "message": {"text": r.detail},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": r.url},
                },
            }],
            "properties": {
                "severity": r.severity,
                "confidence": r.confidence,
                "confidence_score": r.confidence_score,
                "scanner": r.scanner,
                "cvssScore": r.cvss_score,
                "cvssVector": r.cvss_vector,
            },
        }
        if r.evidence:
            sarif_result["fingerprints"] = {
                "evidence/v1": r.evidence[:200],
            }
        sarif_results.append(sarif_result)

    # Build taxa for CWE references
    taxa: list[dict] = []
    seen_cwes: set[str] = set()
    for r in results:
        if r.cwe_id and r.cwe_id not in seen_cwes:
            seen_cwes.add(r.cwe_id)
            cwe_num = r.cwe_id.replace("CWE-", "")
            taxa.append({
                "id": r.cwe_id,
                "guid": f"CWE-{cwe_num}",
                "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
            })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "msscan",
                    "version": version,
                    "informationUri": "https://github.com/MertSoylu/msscan",
                    "rules": rules,
                },
            },
            "results": sarif_results,
            "taxonomies": [{
                "name": "CWE",
                "version": "4.14",
                "informationUri": "https://cwe.mitre.org/data/published/cwe_latest.pdf",
                "taxa": taxa,
            }] if taxa else [],
            "invocations": [{
                "executionSuccessful": True,
                "commandLine": f"msscan scan -u {url}" if url else "msscan",
                "startTimeUtc": datetime.now().astimezone().isoformat(),
            }],
        }],
    }

    Path(output_path).write_text(
        json.dumps(sarif, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _get_version() -> str:
    try:
        from msscan import __version__
        return __version__
    except ImportError:
        return "unknown"
