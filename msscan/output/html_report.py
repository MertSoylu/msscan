"""HTML report generator using Jinja2."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from pathlib import Path

from jinja2 import Template

from msscan.core.result import ScanResult

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>msscan Report — {{ url }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; }
        .container { max-width: 1100px; margin: 0 auto; padding: 2rem; }

        /* Header */
        .header { text-align: center; margin-bottom: 2rem; }
        .header h1 { color: #58a6ff; font-size: 2rem; }
        .header p { color: #8b949e; margin-top: 0.5rem; }

        /* Meta bar */
        .meta { display: flex; gap: 1rem; justify-content: center; margin: 1rem 0 1.5rem; flex-wrap: wrap; }
        .meta span { background: #161b22; padding: 0.4rem 1rem; border-radius: 6px; border: 1px solid #30363d; font-size: 0.9rem; }

        /* Severity badges */
        .summary { display: flex; gap: 1rem; justify-content: center; margin: 1rem 0 2rem; flex-wrap: wrap; }
        .badge { padding: 0.4rem 1.2rem; border-radius: 20px; font-weight: bold; font-size: 0.9rem; }
        .badge-critical,.badge-high { background: #f8514922; color: #f85149; border: 1px solid #f85149; }
        .badge-medium { background: #d2992222; color: #d29922; border: 1px solid #d29922; }
        .badge-low { background: #58a6ff22; color: #58a6ff; border: 1px solid #58a6ff; }
        .badge-info { background: #8b949e22; color: #8b949e; border: 1px solid #8b949e; }

        /* Module section */
        .module-section { margin-bottom: 2.5rem; }
        .module-title {
            color: #58a6ff; font-size: 1.1rem; font-weight: bold;
            padding: 0.6rem 1rem; background: #161b22;
            border-left: 4px solid #58a6ff; border-radius: 4px;
            margin-bottom: 0.75rem;
        }

        /* Expandable finding cards */
        details { margin-bottom: 0.5rem; border: 1px solid #30363d; border-radius: 6px; overflow: hidden; }
        details[open] { border-color: #58a6ff55; }
        summary {
            display: flex; align-items: center; gap: 1rem;
            padding: 0.75rem 1rem; cursor: pointer;
            background: #161b22; user-select: none;
            list-style: none;
        }
        summary::-webkit-details-marker { display: none; }
        summary:hover { background: #1c2128; }
        .arrow { font-size: 0.75rem; color: #8b949e; transition: transform 0.2s; min-width: 16px; }
        details[open] .arrow { transform: rotate(90deg); }
        .sev-badge {
            padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.8rem;
            font-weight: bold; min-width: 80px; text-align: center;
        }
        .sev-CRITICAL,.sev-HIGH { background: #f8514922; color: #f85149; border: 1px solid #f85149; }
        .sev-MEDIUM { background: #d2992222; color: #d29922; border: 1px solid #d29922; }
        .sev-LOW { background: #58a6ff22; color: #58a6ff; border: 1px solid #58a6ff; }
        .sev-INFO { background: #8b949e22; color: #8b949e; border: 1px solid #8b949e; }
        .summary-detail { color: #c9d1d9; font-size: 0.95rem; flex: 1; }
        .summary-url { color: #8b949e; font-size: 0.8rem; }

        /* Expanded detail panel */
        .detail-panel { padding: 1rem 1.2rem; background: #0d1117; border-top: 1px solid #21262d; }
        .detail-grid { display: grid; grid-template-columns: 140px 1fr; gap: 0.4rem 1rem; font-size: 0.9rem; }
        .detail-label { color: #8b949e; font-weight: bold; }
        .detail-value { color: #c9d1d9; word-break: break-all; }
        .evidence-box {
            margin-top: 0.75rem; padding: 0.75rem 1rem;
            background: #161b22; border: 1px solid #30363d; border-radius: 4px;
            font-family: 'Consolas', monospace; font-size: 0.85rem;
            color: #f0883e; word-break: break-all; white-space: pre-wrap;
        }
        .remediation-box {
            margin-top: 0.75rem; padding: 0.75rem 1rem;
            background: #0d2b1a; border: 1px solid #238636; border-radius: 4px;
            font-size: 0.875rem; color: #3fb950;
        }
        .remediation-box strong { color: #56d364; }
        .references-list {
            margin-top: 0.5rem; padding-left: 1.2rem;
            font-size: 0.85rem;
        }
        .references-list li { margin-bottom: 0.25rem; }
        .references-list a { color: #58a6ff; text-decoration: none; }
        .references-list a:hover { text-decoration: underline; }
        .conf-badge {
            display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
            font-size: 0.8rem; font-weight: bold;
        }
        .conf-HIGH   { background: #23373b; color: #3fb950; border: 1px solid #238636; }
        .conf-MEDIUM { background: #2d2a1a; color: #d29922; border: 1px solid #d29922; }
        .conf-LOW    { background: #21262d; color: #8b949e; border: 1px solid #484f58; }

        /* Empty state */
        .empty { text-align: center; margin: 3rem; color: #3fb950; font-size: 1.1rem; }

        /* Footer */
        .footer { text-align: center; margin-top: 3rem; color: #484f58; font-size: 0.8rem; padding-top: 1rem; border-top: 1px solid #21262d; }
    </style>
</head>
<body>
<div class="container">

    <div class="header">
        <h1>🛡️ msscan Security Report</h1>
        <p>Automated web application security scan results</p>
    </div>

    <div class="meta">
        <span>🎯 <strong>{{ url }}</strong></span>
        <span>📅 {{ timestamp }}</span>
        <span>⏱ {{ elapsed }}</span>
        <span>📊 {{ results|length }} finding(s)</span>
    </div>

    <div class="summary">
        {% for sev, count in severity_counts.items() %}{% if count > 0 %}
        <span class="badge badge-{{ sev|lower }}">{{ sev }}: {{ count }}</span>
        {% endif %}{% endfor %}
    </div>

    {% if results %}
    {% for module, findings in grouped.items() %}
    <div class="module-section">
        <div class="module-title">🔍 {{ module|upper }} — {{ findings|length }} finding(s)</div>
        {% for r in findings %}
        <details>
            <summary>
                <span class="arrow">▶</span>
                <span class="sev-badge sev-{{ r.severity }}">{{ r.severity }}</span>
                <span>
                    <div class="summary-detail">{{ r.detail }}</div>
                    <div class="summary-url">{{ r.url }}</div>
                </span>
            </summary>
            <div class="detail-panel">
                <div class="detail-grid">
                    <span class="detail-label">Module</span>
                    <span class="detail-value">{{ r.scanner|upper }}</span>
                    <span class="detail-label">Severity</span>
                    <span class="detail-value">{{ r.severity }}</span>
                    <span class="detail-label">Confidence</span>
                    <span class="detail-value"><span class="conf-badge conf-{{ r.confidence }}">{{ r.confidence }}</span></span>
                    {% if r.cwe_id %}
                    <span class="detail-label">CWE</span>
                    <span class="detail-value"><a href="https://cwe.mitre.org/data/definitions/{{ r.cwe_id[4:] }}.html" style="color:#58a6ff" target="_blank">{{ r.cwe_id }}</a></span>
                    {% endif %}
                    <span class="detail-label">URL</span>
                    <span class="detail-value">{{ r.url }}</span>
                    <span class="detail-label">Detail</span>
                    <span class="detail-value">{{ r.detail }}</span>
                    <span class="detail-label">Timestamp</span>
                    <span class="detail-value">{{ r.timestamp }}</span>
                </div>
                {% if r.evidence %}
                <div class="evidence-box">{{ r.evidence }}</div>
                {% endif %}
                {% if r.remediation %}
                <div class="remediation-box"><strong>🔧 Remediation:</strong> {{ r.remediation }}</div>
                {% endif %}
                {% if r.references %}
                <ul class="references-list">
                    <strong>📚 References:</strong>
                    {% for ref in r.references %}
                    <li><a href="{{ ref }}" target="_blank" rel="noopener">{{ ref }}</a></li>
                    {% endfor %}
                </ul>
                {% endif %}
            </div>
        </details>
        {% endfor %}
    </div>
    {% endfor %}
    {% else %}
    <p class="empty">✅ No vulnerabilities found.</p>
    {% endif %}

    <div class="footer">
        <p>Generated by msscan v{{ version }} &mdash; For authorized security testing only.</p>
    </div>

</div>
</body>
</html>
"""


def generate_html_report(
    results: list[ScanResult],
    url: str,
    output_path: str,
    elapsed_secs: float = 0.0,
) -> None:
    """Generate an HTML report from scan results."""
    from msscan import __version__

    # Tally findings per severity for the badge row at the top of the report
    severity_counts: dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
    }
    for r in results:
        if r.severity in severity_counts:
            severity_counts[r.severity] += 1

    # Group findings by scanner module — used to render separate module sections
    grouped: dict[str, list[ScanResult]] = defaultdict(list)
    for r in results:
        grouped[r.scanner].append(r)

    # Show a dash when elapsed time was not provided (e.g. called outside do_scan)
    elapsed_str = f"{elapsed_secs:.2f}s" if elapsed_secs else "—"

    template = Template(HTML_TEMPLATE)
    html = template.render(
        url=url,
        results=results,
        grouped=grouped,           # dict[scanner_name -> list[ScanResult]]
        severity_counts=severity_counts,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        elapsed=elapsed_str,
        version=__version__,
    )
    Path(output_path).write_text(html, encoding="utf-8")
