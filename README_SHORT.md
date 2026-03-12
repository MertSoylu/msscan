# msscan — Web Application Security Scanner

A fast, async Python CLI tool for automated security testing of web applications. Scans for XSS, SQL injection, CSRF, open redirects, SSRF, HTTP header misconfigurations, and subdomain enumeration.

**Version:** 1.1
**Python:** 3.10+
**License:** MIT

---

## ⚡ Features

- **7 Security Scanners**: XSS, SQLi, CSRF, Headers, Open Redirect, SSRF, Subdomain Enumeration
- **Async Execution**: Concurrent requests with rate limiting (1-50 req/s)
- **Context-Aware Detection**: Severity mapped to reflection context and detection confidence
- **Differential Analysis**: Baseline comparison to reduce false positives (SSRF, SQLi)
- **Rich Output**: Color-coded console results + optional HTML reports
- **150+ Payloads**: XSS, SQLi, SSRF, Open Redirect, and Subdomain wordlists included

---

## 📦 Installation

### Prerequisites
- Python 3.10 or higher
- pip (included with Python)

### Quick Start

```bash
# Clone repository
git clone https://github.com/MertSoylu/msscan.git
cd msscan

# Create virtual environment (recommended)
python -m venv venv

# Activate venv
# Linux/macOS:
source venv/bin/activate
# Windows (PowerShell):
venv\Scripts\Activate.ps1
# Windows (CMD):
venv\Scripts\activate.bat

# Install msscan
pip install -e ".[dev]"

# Verify installation
msscan --help
```

---

## 🚀 Quick Usage

### Interactive Shell

```bash
msscan
```

Configure and run scan:

```
msscan> set url https://example.com
msscan> set modules xss,sqli,headers
msscan> set rate-limit 10
msscan> scan
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `url` | required | Target website URL |
| `modules` | all | Scanners: `xss,sqli,csrf,headers,open_redirect,ssrf,subdomain` |
| `rate-limit` | 10 | Requests per second (1-50) |
| `timeout` | 10.0 | HTTP request timeout (seconds) |
| `report` | none | HTML report output path (optional) |

### Available Commands

- `set <key> <value>` — Configure scan settings
- `config` — Show current configuration
- `scan` — Start security scan
- `help` — Show available commands
- `exit` — Exit shell

---

## 🔍 Scanners

### 1. XSS (Reflected Cross-Site Scripting)
Detects reflected XSS payloads with context-aware severity:
- **JavaScript context** (inside `<script>` tag) → CRITICAL
- **HTML body** (unescaped in body) → HIGH
- **HTML attribute** (inside attribute value) → HIGH
- **Encoded** (HTML entities) → INFO

Tests 57 payloads including SVG, event handlers, encoding bypasses.

### 2. SQL Injection (SQLi)
Three-tier detection cascade:
- **Error-based**: Matches 32+ SQL error patterns (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, etc.)
- **Boolean-blind**: Compares true/false response lengths with baseline
- **Time-based**: Measures response delay with confirmation request

### 3. CSRF (Cross-Site Request Forgery)
Checks for:
- CSRF token presence (13+ token name patterns)
- SameSite cookie attribute
- Token entropy (weak tokens flagged)
- Double-submit cookie pattern
- State-changing GET forms (delete, update, logout)

### 4. HTTP Security Headers
Validates presence and configuration of:
- HSTS (max-age, includeSubDomains, preload)
- CSP (unsafe-inline, unsafe-eval, data: URIs, http: schemes)
- X-Frame-Options, X-Content-Type-Options
- CORS (wildcard detection)
- Server/X-Powered-By (version disclosure)

### 5. Open Redirect
Detects three redirect mechanisms:
- HTTP 3xx redirects via Location header
- JavaScript redirects (`window.location = payload`)
- Meta-refresh redirects

Tests 7+ bypass techniques (protocol confusion, encoding, subdomain tricks).

### 6. SSRF (Server-Side Request Forgery)
Identifies internal resource access:
- **High-specificity**: /etc/passwd, win.ini, cloud metadata (ami-id, instance-id), service banners
- **Medium-specificity**: With differential baseline analysis to avoid false positives

Targets: localhost variants, AWS/GCP/Azure metadata, file protocol, internal ports.

### 7. Subdomain Enumeration
Features:
- DNS brute-force against 155+ subdomain patterns
- Wildcard detection (random probe)
- CNAME takeover detection (20+ vulnerable services: AWS S3, Azure, GitHub Pages, Heroku, etc.)
- Concurrent DNS queries (semaphore: 20 parallel)

---

## 📊 Output Formats

### Console
- Color-coded severity badges
- Confidence levels (HIGH/MEDIUM/LOW)
- CWE IDs and remediation guidance
- Grouped by scanner module

### HTML Report
```bash
msscan> set report ./report.html
msscan> scan
```
Generates interactive HTML with:
- Severity summary
- Expandable finding cards
- CWE links
- Remediation sections
- Timestamps

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific scanner tests
pytest tests/test_xss.py -v

# Coverage report
pytest tests/ --cov=msscan --cov-report=html
```

**Test Status**: 99 tests passing

---

## 🔧 Troubleshooting

### Installation Issues

#### ❌ `pip: command not found`
```bash
python --version  # Verify Python is installed
python -m pip install -e ".[dev]"
```

#### ❌ `No module named 'msscan'`
```bash
pip uninstall msscan
pip install -e .
```

#### ❌ `ImportError: No module named 'httpx'`
```bash
pip install -e ".[dev]"  # Reinstall all dependencies
```

---

### Runtime Issues

#### ❌ `msscan: command not found`
Virtual environment may not be activated:
```bash
# Linux/macOS:
source venv/bin/activate

# Windows (PowerShell):
venv\Scripts\Activate.ps1

# Windows (CMD):
venv\Scripts\activate.bat

# Or use directly:
python -m msscan.cli
```

#### ❌ `URL required` / `Set a target URL before scanning`
```
msscan> set url https://example.com
msscan> scan
```

#### ❌ `Scan halted — rate-limited by target server (HTTP 429/503)`
Server is rate-limiting. Lower the request rate:
```
msscan> set rate-limit 5
msscan> scan
```

#### ❌ `Request timed out after 10.0 seconds`
Target is slow. Increase timeout:
```
msscan> set timeout 30.0
msscan> scan
```

#### ❌ `ModuleNotFoundError: No module named 'pytest'`
Install dev dependencies:
```bash
pip install -e ".[dev]"
```

#### ❌ `Failed to resolve DNS` in tests
DNS mocking issue. Run with verbose output:
```bash
pytest tests/test_subdomain.py -v -s
```

#### ❌ `Tests pass locally but fail in CI`
Ensure CI environment has correct setup:
```bash
python --version  # Must be 3.10+
pip install -e ".[dev]"
pytest tests/ -v
```

---

## ⚠️ Legal Notice

**THIS TOOL IS FOR AUTHORIZED SECURITY TESTING ONLY**

You must have explicit written permission from the system owner before scanning. Unauthorized scanning is illegal in most jurisdictions. The user assumes all responsibility for any misuse.

---

## 📝 Project Info

- **GitHub**: https://github.com/MertSoylu/msscan
- **License**: MIT
- **Author**: msscan Contributors

---

## 🔗 References

- [OWASP Top 10](https://owasp.org/Top10/) — Security risks
- [CWE List](https://cwe.mitre.org/) — Weakness enumeration
- [httpx Docs](https://www.python-httpx.org/) — Async HTTP client
- [Typer Docs](https://typer.tiangolo.com/) — CLI framework
