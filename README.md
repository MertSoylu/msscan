# msscan — Web Application Security Scanner

A fast, async Python CLI tool for scanning web applications for common security vulnerabilities. Performs automated testing for XSS, SQL injection, CSRF, open redirects, SSRF, security header misconfigurations, and subdomain enumeration.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests Passing](https://img.shields.io/badge/tests-45%2F45-brightgreen)]()

---

## 📋 Table of Contents

1. [Features](#features)
2. [Tech Stack](#tech-stack)
3. [Prerequisites](#prerequisites)
4. [Getting Started](#getting-started)
5. [Architecture](#architecture)
6. [Available Scanners](#available-scanners)
7. [Usage Guide](#usage-guide)
8. [Output & Reports](#output--reports)
9. [Testing](#testing)
10. [Troubleshooting](#troubleshooting)
11. [Legal Notice](#legal-notice)
12. [License](#license)

---

## ✨ Features

- **7 Security Scanners** — XSS, SQL Injection, CSRF, Open Redirect, SSRF, HTTP Headers, Subdomain Enumeration
- **Async HTTP Client** — Concurrent requests with semaphore-based rate limiting
- **Context-Aware Detection** — XSS severity mapped to reflection context (JavaScript, HTML attribute, encoded, etc.)
- **Differential Analysis** — SSRF uses baseline comparison to reduce false positives
- **Rich Console Output** — Color-coded findings with severity, confidence, and CWE ID
- **HTML Reports** — Generate detailed reports with expandable finding cards
- **Interactive CLI** — Session-based configuration with live validation
- **Comprehensive Payloads** — 150+ XSS, 40+ SSRF, 30+ Open Redirect, 155+ Subdomain wordlist entries
- **Well-Tested** — 45 unit and integration tests covering all scanners

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| **Language** | Python 3.10+ |
| **CLI Framework** | Typer (with Click under the hood) |
| **HTTP Client** | httpx (async/await) |
| **DNS Resolution** | dnspython (async DNS queries) |
| **Console Output** | Rich (tables, panels, colors) |
| **HTML Reporting** | Jinja2 template engine |
| **Testing** | pytest, pytest-asyncio, respx (HTTP mocking), unittest.mock (DNS mocking) |
| **Package Management** | pip / setuptools |

---

## 📦 Prerequisites

### System Requirements

- **Python 3.10 or higher** (3.11+ recommended)
- **pip** (included with Python 3.9+)
- **git** (for cloning the repository)

### Optional (for development)

- **venv** (built-in with Python 3.4+) or **Poetry** for virtual environments
- **Docker** (if running msscan in a container)

### Verify Your Setup

```bash
python --version     # Should be 3.10 or higher
pip --version
```

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/MertSoylu/msscan.git
cd msscan
```

### 2. Create a Virtual Environment (Recommended)

Using venv:

```bash
python -m venv venv

# Activate the virtual environment
# On macOS/Linux:
source venv/bin/activate

# On Windows (PowerShell):
venv\Scripts\Activate.ps1

# On Windows (Command Prompt):
venv\Scripts\activate.bat
```

Or using Poetry:

```bash
poetry install
poetry shell
```

### 3. Install msscan in Development Mode

```bash
pip install -e ".[dev]"
```

This installs:
- **Core dependencies**: httpx, dnspython, typer, rich, jinja2
- **Dev dependencies**: pytest, pytest-asyncio, respx (for testing)

The `-e` flag installs in "editable" mode, so code changes are reflected immediately.

### 4. Verify Installation

```bash
msscan --help
```

You should see the msscan help menu. If the command is not found:

```bash
python -m msscan.cli
```

### 5. Run Your First Scan

```bash
msscan
```

You'll enter the interactive `msscan>` prompt:

```
msscan> set url https://example.com
msscan> set modules xss,headers
msscan> scan
```

Press `Enter` when prompted for the legal consent acknowledgment.

---

## 🏗️ Architecture

### Directory Structure

```
msscan/
├── msscan/
│   ├── cli.py                 # Interactive shell (Cmd-based), entry point
│   ├── core/
│   │   ├── engine.py          # ScanEngine orchestrator (async, lazy-loads scanners)
│   │   ├── http_client.py     # HttpClient wrapper with semaphore rate limiting
│   │   ├── result.py          # ScanResult dataclass (all findings)
│   │   └── exceptions.py       # RateLimitedError for HTTP 429/503
│   ├── scanners/
│   │   ├── base.py            # BaseScanner abstract class
│   │   ├── xss.py             # Reflected XSS with context detection
│   │   ├── sqli.py            # Error-based, boolean-blind, time-based SQLi
│   │   ├── csrf.py            # CSRF token & SameSite validation + entropy check
│   │   ├── headers.py         # HTTP security headers (CSP, HSTS, CORS, etc.)
│   │   ├── open_redirect.py   # HTTP 3xx, JS, meta-refresh redirects
│   │   ├── ssrf.py            # SSRF with differential baseline analysis
│   │   └── subdomain.py       # DNS brute-force with wildcard detection + CNAME takeover
│   ├── output/
│   │   ├── console.py         # Rich console formatting (tables, colors)
│   │   └── html_report.py     # Jinja2 HTML report generation
│   ├── utils/
│   │   ├── helpers.py         # URL normalization, param injection/extraction
│   │   └── payloads.py        # Dynamic payload loader from files
│   └── __init__.py            # Package metadata (__version__)
├── payloads/                  # External payload text files (loaded dynamically)
│   ├── xss.txt                # ~55 XSS payloads (scripts, SVG, encoding bypasses)
│   ├── sqli.txt               # ~28 SQL injection patterns
│   ├── ssrf.txt               # ~40 SSRF payloads (cloud metadata, file://, ports)
│   ├── redirects.txt          # ~30 open redirect bypass techniques
│   └── subdomains.txt         # ~155 subdomain wordlist entries
├── tests/
│   ├── __init__.py
│   ├── test_xss.py            # 10 unit + integration tests (context detection)
│   ├── test_csrf.py           # 9 tests (entropy, meta tokens, SameSite)
│   ├── test_open_redirect.py  # 9 tests (HTTP, JS, meta-refresh)
│   ├── test_ssrf.py           # 5 tests (high-spec indicators, differential)
│   ├── test_subdomain.py      # 7 tests (wildcard filtering, CNAME takeover)
│   ├── test_sqli.py           # 2 tests (error-based, boolean-blind)
│   └── test_headers.py        # 3 tests (missing headers, CORS, CSP)
├── pyproject.toml             # Project metadata & dependencies
├── LICENSE                    # MIT License
├── README.md                  # This file
└── .gitignore
```

### Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│ User Input (msscan> set url ... / scan)                     │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ CLI (cli.py) — Interactive Shell                            │
│ ├─ Validates config (URL, rate-limit, modules)             │
│ └─ Calls ScanEngine.run()                                   │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ ScanEngine (engine.py) — Async Orchestrator                │
│ ├─ Lazy-loads enabled scanner modules                      │
│ ├─ Creates HttpClient with rate limiter                    │
│ └─ Runs all scanners concurrently (gather())               │
└────────────────────┬────────────────────────────────────────┘
                     │
      ┌──────────────┼──────────────┬──────────────┐
      │              │              │              │
      ▼              ▼              ▼              ▼
  ┌────────┐    ┌────────┐    ┌────────┐    ┌────────┐
  │  XSS   │    │ SQLi   │    │ CSRF   │    │Headers │  ...
  │Scanner │    │Scanner │    │Scanner │    │Scanner │
  │        │    │        │    │        │    │        │
  │ async  │    │ async  │    │ async  │    │ async  │
  │ scan() │    │ scan() │    │ scan() │    │ scan() │
  └───┬────┘    └───┬────┘    └───┬────┘    └───┬────┘
      │             │             │             │
      │ HTTP Client (httpx) with Rate Limiter   │
      │ ├─ 3-20 concurrent requests             │
      │ ├─ Respects rate-limit (req/s)          │
      │ └─ Catches RateLimitedError (429/503)   │
      │                                          │
      └──────────────┬───────────────────────────┘
                     │
                     ▼
    ┌──────────────────────────────────────┐
    │ List[ScanResult]                     │
    │ ├─ scanner: str (module name)       │
    │ ├─ severity: str (CRITICAL..INFO)   │
    │ ├─ url: str (where finding found)   │
    │ ├─ detail: str (description)        │
    │ ├─ evidence: str (payload/response) │
    │ ├─ confidence: str (HIGH/MED/LOW)   │
    │ ├─ cwe_id: str (e.g., CWE-79)      │
    │ └─ remediation: str (how to fix)    │
    └──────────────┬───────────────────────┘
                   │
         ┌─────────┴──────────┐
         │                    │
         ▼                    ▼
    ┌──────────┐         ┌──────────────┐
    │ Console  │         │ HTML Report  │
    │ Output   │         │ (optional)   │
    │ (Rich)   │         │ (Jinja2)     │
    └──────────┘         └──────────────┘
```

### Scanner Execution Model

1. **ScanEngine.run(url, modules, http_client, ...)** is called
2. For each enabled module:
   - Lazy-load the scanner class from `SCANNER_MAP` (only if enabled)
   - Instantiate it and call `await Scanner.scan(url, client)`
   - Each scanner returns `list[ScanResult]`
3. Results are aggregated from all scanners
4. Results filtered by severity (if requested) and printed to console
5. If `report` path is set, HTML report is generated

### Key Data Structures

**ScanResult** (in `core/result.py`):
```python
@dataclass
class ScanResult:
    scanner: str                              # e.g., "xss"
    severity: str                             # CRITICAL | HIGH | MEDIUM | LOW | INFO
    url: str                                  # exact URL where vulnerability detected
    detail: str                               # human-readable finding description
    evidence: str = ""                        # payload or response snippet
    confidence: str = "MEDIUM"                # HIGH | MEDIUM | LOW
    remediation: str = ""                     # actionable fix guidance
    cwe_id: str = ""                          # e.g., "CWE-79"
    references: list[str] = field(default_factory=list)  # external links
    timestamp: str = (auto-set ISO 8601)      # when finding was detected
```

---

## 🔍 Available Scanners

### 1. XSS (Reflected Cross-Site Scripting)

**Severity Mapping by Context:**
| Context | Severity | Confidence | Description |
|---------|----------|-----------|-------------|
| `javascript` | CRITICAL | HIGH | Payload reflected unescaped inside `<script>` block |
| `html_body` | HIGH | HIGH | Payload in HTML body with visible event handler/script tag |
| `html_attribute` | HIGH | MEDIUM | Payload unescaped inside HTML attribute (e.g., `value="payload"`) |
| `html_comment` | LOW | LOW | Payload inside HTML comment (limited exploitability) |
| `encoded` | INFO | LOW | Payload HTML-entity-encoded (`<` → `&lt;`, etc.) |
| `none` | — | — | Payload not reflected |

**CWE:** CWE-79  
**Tests:** 10 unit + integration tests

### 2. SQL Injection (SQLi)

**Detection Methods:**
- **Error-based:** Matches 50 SQL error patterns (MySQL, PostgreSQL, MSSQL, MariaDB, Oracle, SQLite, CockroachDB, DB2, Firebird)
- **Boolean-based blind:** Injects true/false conditions, compares response length (>200 bytes or >10% diff)
- **Time-based blind:** Measures response time; threshold = baseline + 2.5 seconds (prevents slow-network false positives)

**Supported DBMS:** MySQL, PostgreSQL, Oracle, MSSQL, SQLite, MariaDB, CockroachDB, DB2, Firebird  
**CWE:** CWE-89  
**Tests:** 2 tests

### 3. CSRF (Cross-Site Request Forgery)

**Protections Checked:**
- CSRF token presence (13+ token name patterns: `csrf`, `xsrf`, `_token`, etc.)
- `<meta name="csrf-token">` detection
- `X-CSRF-Token` / `X-XSRF-Token` response headers
- `SameSite` cookie attribute
- **New:** Shannon entropy on token values (weak tokens flagged as LOW)
- **New:** Double-submit cookie pattern detection (flagged as LOW)
- **New:** GET forms with state-changing actions (e.g., `/delete`, `/logout`)

**Severity Mapping:**
| Condition | Severity |
|-----------|----------|
| POST form, no token, no SameSite | HIGH |
| POST form, no token, SameSite present | LOW |
| GET form with state-changing action (delete/update) | MEDIUM |
| Token entropy < 3.0 bits/char or length < 8 | LOW (weak token) |
| Token value matches cookie value | LOW (double-submit pattern) |

**CWE:** CWE-352  
**Tests:** 9 tests (including entropy checks)

### 4. Headers (HTTP Security Headers)

**Headers Checked:**
| Header | Missing Severity | Issues Checked |
|--------|------------------|---|
| `Strict-Transport-Security` | HIGH | `max-age < 31536000` (1 year), missing `includeSubDomains`, missing `preload` |
| `Content-Security-Policy` | MEDIUM | `unsafe-inline`, `unsafe-eval`, wildcard `*` sources |
| `X-Frame-Options` | MEDIUM | Missing (clickjacking risk) |
| `X-Content-Type-Options` | LOW | Missing (MIME sniffing) |
| `Referrer-Policy` | LOW | Missing (information leakage) |
| `Permissions-Policy` | LOW | Missing (browser API control) |
| `X-XSS-Protection` | INFO | Missing (legacy browser support) |
| `Access-Control-Allow-Origin` | MEDIUM | Wildcard `*` (CORS misconfiguration) |
| `Server`, `X-Powered-By`, `X-AspNet-Version` | INFO | Information leakage |

**CWE:** CWE-693 (Headers), CWE-942 (CORS), CWE-200 (Info Leakage)  
**Tests:** 3 tests

### 5. Open Redirect

**Detection Methods:**
| Redirect Type | Severity | Confidence | Method |
|---|---|---|---|
| HTTP 3xx with Location header to external domain | HIGH | HIGH | Check `Location` response header |
| JavaScript redirect (`window.location =`) to external domain | MEDIUM | MEDIUM | Regex pattern matching in response body |
| Meta-refresh (`<meta http-equiv="refresh">`) to external domain | MEDIUM | HIGH | Parse meta tag with regex |

**Bypass Techniques in Payloads:**
- Protocol confusion: `//evil.com`, `///evil.com`
- Null bytes / CRLF: `%00`, `%0d%0a`
- Subdomain confusion: `target.evil.com@target.com`
- Fullwidth characters: `ｅｖｉｌ.ｃｏｍ`
- Data URIs and JavaScript protocols

**CWE:** CWE-601  
**Tests:** 9 tests

### 6. SSRF (Server-Side Request Forgery)

**Detection Strategy:**
- **High-Specificity Indicators** (→ CRITICAL, HIGH confidence):
  - `/etc/passwd` content (`root:x:0:0`, `daemon:x:`)
  - Windows `win.ini` content (`[boot loader]`)
  - Cloud metadata fields (`ami-id`, `instance-id`, `iam/security-credentials`)
  - Service banners (`ssh-2.0`, `mysql_native_password`, `redis_version`, `elasticsearch`)

- **Medium-Specificity Indicators** (→ HIGH, MEDIUM confidence) with **Differential Analysis**:
  - Only flagged if response body differs meaningfully from baseline (>10% length diff)
  - Baseline fetched with benign value (`https://example.com`) to filter pre-existing content

**Payloads Target:**
- Localhost variants: `127.0.0.1`, `127.1`, `[::1]`, `0x7f000001`
- AWS EC2 metadata: `169.254.169.254/latest/meta-data/`
- GCP metadata: `metadata.google.internal/`
- Azure IMDS: `169.254.169.254/metadata/instance`
- DigitalOcean: `169.254.169.254/metadata/v1/`
- Internal ports: 22 (SSH), 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), 27017 (MongoDB), 9200 (Elasticsearch)
- File protocol: `file:///etc/passwd`, `file:///c:/windows/win.ini`
- Alternative protocols: `dict://`, `gopher://`

**CWE:** CWE-918  
**Tests:** 5 tests (including differential analysis validation)

### 7. Subdomain Enumeration

**Detection Features:**
| Feature | What It Does |
|---------|------------|
| **DNS Brute-Force** | Queries 150+ subdomain names against target domain (A records) |
| **Wildcard Detection** | Probes random 12-char subdomain first; if it resolves, filters subdomains matching wildcard IPs |
| **CNAME Takeover** | Checks if CNAME points to vulnerable services (AWS S3, Azure, GitHub Pages, Heroku, etc.) |
| **Concurrent Queries** | Uses asyncio semaphore (20 concurrent) to avoid DNS flooding |

**Severity Mapping:**
| Condition | Severity | CWE |
|-----------|----------|-----|
| Subdomain resolves (no wildcard, no vulnerable CNAME) | INFO | — |
| CNAME → vulnerable service, **no** A record | HIGH | CWE-345 |
| CNAME → vulnerable service, **has** A record | MEDIUM | CWE-345 |

**Vulnerable Services Checked:**
- amazonaws.com, s3.amazonaws.com
- azurewebsites.net, cloudapp.azure.com
- github.io
- herokuapp.com
- shopify.com, fastly.net, surge.sh
- Zendesk, ReadMe, Statuspage, HelpJuice, etc.

**Wordlist Size:** ~155 subdomain patterns (cloud, DevOps, network, environment prefixes)  
**CWE:** CWE-345  
**Tests:** 7 tests (wildcard filtering, CNAME detection)

---

## 📖 Usage Guide

### Interactive Shell

Start msscan:

```bash
msscan
```

### Configure Session

```
msscan> set url https://example.com/
msscan> set modules xss,sqli,headers          # comma-separated, no spaces
msscan> set rate-limit 15                     # requests per second (1-50)
msscan> set timeout 10.0                      # request timeout in seconds
msscan> set report ./reports/scan.html        # optional HTML report path
```

### View Configuration

```
msscan> config
```

### Run Scan

```
msscan> scan
```

A prompt will ask you to acknowledge the legal notice. Type `yes` to proceed.

### Exit

```
msscan> exit
```

### Available Commands

| Command | Description | Example |
|---------|-------------|---------|
| `set <key> <value>` | Set configuration option | `set url https://example.com` |
| `config` | Show current settings | `config` |
| `scan` | Start the security scan | `scan` |
| `help` | Show available commands | `help` |
| `clear` | Clear the screen | `clear` |
| `history` | Show command history | `history` |
| `exit` / `quit` | Exit the shell | `exit` |

### Configuration Options

| Key | Default | Allowed Range | Description |
|-----|---------|---|---|
| `url` | *(required)* | Valid URL | Target website URL (https:// added automatically) |
| `modules` | `all` | Comma-separated or `all` | Scanners to run: `xss,sqli,csrf,headers,open_redirect,ssrf,subdomain` |
| `rate-limit` | `10` | 1–50 | Requests per second (>20 shows warning) |
| `timeout` | `10.0` | 0.5–300 | HTTP request timeout in seconds |
| `report` | *(none)* | Valid file path | Path to save HTML report (optional) |

### Safety Features

- **Rate Limit Validation:** Enforced 1–50 req/s (prevents flooding)
- **HTTP 429/503 Handling:** Scan halts immediately if server rate-limits; user advised to lower rate-limit
- **Legal Consent:** Every scan requires `yes` acknowledgment before starting
- **Timeout Protection:** Default 10s timeout prevents hanging on unresponsive servers

---

## 📊 Output & Reports

### Console Output

#### Scan Configuration Panel
Shows target, modules, rate limit, timeout before scan starts.

#### Scan Summary Panel
```
📋 Scan Summary
  🎯 Target  : https://example.com
  📅 Date    : 2026-03-07 18:30:45
  ⏱  Elapsed : 3.45s
  📊 Total   : 8 finding(s)

  🔴 CRITICAL: 1    🔴 HIGH: 3    🟡 MEDIUM: 2    🔵 LOW: 2    ⚪ INFO: 0
```

#### Results Table (Per Module)
Color-coded findings grouped by scanner:

```
──────────────────────────── XSS Findings (2) ────────────────────────────
 Severity    Confidence    URL                                   Detail
─────────────────────────────────────────────────────────────────────────
 🔴 CRITICAL     HIGH       https://example.com/search?q=<script> Reflected XSS
 🟡 MEDIUM       MEDIUM     https://example.com/login?id=<img>    Reflected XSS
────────────────────────────────────────────────────────────────────────
```

**Columns:**
- **Severity** (with emoji icon)
- **Confidence** (HIGH=green, MEDIUM=yellow, LOW=grey)
- **URL** (cyan text, where vulnerability detected)
- **Detail** (includes `[CWE-ID]` if present)
- **Evidence** (payload/response, truncated to 100 chars)

### HTML Report

Generated when `report` option is set. Features:

- **Header:** Project title and scan metadata (target, date, elapsed time, total findings)
- **Severity Summary:** Badge breakdown (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- **Findings by Module:** Grouped sections with expandable detail cards
- **Expandable Cards:** Click arrow (▶) to expand each finding
- **Finding Details:**
  - Module name
  - Severity (color-coded badge)
  - **Confidence** (green/yellow/grey badge)
  - **CWE ID** (linked to MITRE definition)
  - URL
  - Description
  - Timestamp
  - **Evidence box** (monospace, syntax-highlighted)
  - **Remediation section** (actionable fix guidance)
  - **References list** (clickable external links)
- **Footer:** msscan version and legal notice

**Example HTML Report Output:**
```html
<div class="detail-panel">
  <div class="detail-grid">
    <span class="detail-label">Confidence</span>
    <span class="detail-value">
      <span class="conf-badge conf-HIGH">HIGH</span>
    </span>
    <span class="detail-label">CWE</span>
    <span class="detail-value">
      <a href="https://cwe.mitre.org/data/definitions/79.html" target="_blank">CWE-79</a>
    </span>
    <span class="detail-label">Remediation</span>
    <span class="detail-value">Apply context-sensitive output encoding...</span>
  </div>
  <div class="evidence-box">payload_here</div>
</div>
```

---

## 🧪 Testing

### Run All Tests

```bash
pytest tests/ -v
```

**Output:**
```
collected 45 items

tests/test_xss.py::test_context_none_when_not_reflected PASSED         [  2%]
...
================================================= 45 passed in 2.91s ==================================================
```

### Run Specific Test File

```bash
pytest tests/test_xss.py -v
```

### Run Single Test

```bash
pytest tests/test_csrf.py::test_csrf_no_token_no_samesite_high -v
```

### Run Tests Matching a Pattern

```bash
pytest tests/ -k "entropy" -v
```

### Test Coverage

```bash
pytest tests/ --cov=msscan --cov-report=html
# Open htmlcov/index.html in browser
```

### Test Structure

```
tests/
├── test_xss.py         # 10 tests: context detection, severity mapping
├── test_csrf.py        # 9 tests: tokens, entropy, SameSite, meta tags
├── test_open_redirect.py # 9 tests: HTTP 3xx, JS, meta-refresh, same-domain filters
├── test_ssrf.py        # 5 tests: indicators, differential analysis
├── test_subdomain.py   # 7 tests: wildcard filtering, CNAME takeover
├── test_sqli.py        # 2 tests: error-based, boolean-blind
└── test_headers.py     # 3 tests: missing headers, CORS, CSP parsing
```

### Mock Framework

- **HTTP Mocking:** `respx` (library for mocking httpx)
- **DNS Mocking:** `unittest.mock` (patches dnspython resolver)
- **Async Testing:** `pytest-asyncio` (auto-discovers async tests via `asyncio_mode = "auto"`)

### Example Test

```python
import pytest
import httpx
import respx
from msscan.core.http_client import HttpClient
from msscan.scanners.xss import Scanner

@pytest.mark.asyncio
async def test_xss_javascript_context_critical():
    """Payload inside <script> block → CRITICAL."""
    with respx.mock:
        def handler(request):
            q = request.url.params.get("q", "")
            return httpx.Response(200, text=f"<script>var q = '{q}';</script>")

        respx.get("https://vuln.com/js").mock(side_effect=handler)

        scanner = Scanner()
        async with HttpClient() as client:
            results = await scanner.scan("https://vuln.com/js?q=test", client)

    assert any(r.severity == "CRITICAL" for r in results)
```

---

## 🔧 Troubleshooting

### Installation Issues

#### Error: `pip: command not found` or `pip3: command not found`

**Solution:**  
Ensure Python is installed and in PATH:

```bash
python --version
python -m pip install -e ".[dev]"
```

#### Error: `No module named 'msscan'`

**Solution:**  
Reinstall in editable mode:

```bash
pip uninstall msscan
pip install -e .
```

#### Error: `ImportError: No module named 'httpx'`

**Solution:**  
Install dependencies:

```bash
pip install -e ".[dev]"
```

### Runtime Issues

#### Error: `msscan: command not found` (after installation)

**Solution:**  
The virtual environment may not be activated:

```bash
# Activate venv first
source venv/bin/activate      # macOS/Linux
# or
venv\Scripts\activate.bat      # Windows Command Prompt
# or
venv\Scripts\Activate.ps1      # Windows PowerShell

# Then run:
msscan
```

Or use the module directly:
```bash
python -m msscan.cli
```

#### Error: `URL required` / `Set a target URL before scanning`

**Solution:**  
Configure the URL before scanning:

```
msscan> set url https://example.com
msscan> scan
```

#### Error: `Scan halted — rate-limited by target server (HTTP 429/503)`

**Solution:**  
Lower the rate limit and retry:

```
msscan> set rate-limit 5
msscan> scan
```

#### Error: `Request timed out after 10.0 seconds`

**Solution:**  
Increase the timeout:

```
msscan> set timeout 30.0
msscan> scan
```

### Testing Issues

#### Error: `ModuleNotFoundError: No module named 'pytest'`

**Solution:**  
Install dev dependencies:

```bash
pip install -e ".[dev]"
```

#### Error: `Failed to resolve DNS` in tests

**Solution:**  
DNS mocking may not be set up. Ensure `unittest.mock` patches are applied in test:

```python
from unittest.mock import patch, AsyncMock

with patch("msscan.scanners.subdomain.dns.asyncresolver.Resolver") as MockResolver:
    instance = MagicMock()
    instance.resolve = AsyncMock(...)
    MockResolver.return_value = instance
    # test code
```

#### Error: `Tests pass locally but fail in CI`

**Solution:**  
Ensure CI has Python 3.10+ and runs:

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

---

## 📝 Legal Notice

⚠️ **WARNING**

This tool is designed for authorized security testing only. You **must**:

1. Have **explicit written permission** from the system owner to scan
2. Comply with all applicable laws and regulations
3. Not use this tool on systems you do not own or have permission to test
4. Understand that unauthorized scanning is illegal in most jurisdictions

**The user assumes all responsibility for any misuse of this tool.**

---

## 📄 License

msscan is released under the **MIT License**. See [LICENSE](LICENSE) for details.

```
MIT License

Copyright (c) 2024 msscan Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software...
```

---

## 🤝 Contributing

Contributions are welcome! To add a new scanner or improve existing ones:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-scanner`)
3. Implement your scanner following the `BaseScanner` interface
4. Add comprehensive tests (respx mocking for HTTP, unittest.mock for external APIs)
5. Update payloads and documentation
6. Submit a pull request

---

## 📚 Further Reading

- [OWASP Top 10](https://owasp.org/Top10/) — Web application security risks
- [CWE List](https://cwe.mitre.org/) — Common Weakness Enumeration
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document) — Severity rating system
- [httpx Documentation](https://www.python-httpx.org/) — Async HTTP client
- [Typer Documentation](https://typer.tiangolo.com/) — CLI framework
