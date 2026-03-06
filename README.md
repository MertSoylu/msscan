# msscan

A terminal-based web application security scanner written in Python.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Installation

**Requirements:** Python 3.10+

```bash
cd msscan
pip install -e .
```

After installation, open a **new terminal** and run `msscan`.

> If the command is not found: `python -m msscan`

---

## Usage

```bash
msscan
```

The `msscan>` interactive prompt opens. Use the commands below to configure and run scans.

### Commands

| Command | Description |
|---|---|
| `set <key> <value>` | Set a session option |
| `config` | Show current settings |
| `scan` | Start the scan |
| `help` | List all commands |
| `exit` | Quit the shell |

### Options (`set`)

| Key | Default | Description |
|---|---|---|
| `url` | — | Target URL (required) |
| `modules` | `all` | Modules to run (comma-separated) |
| `rate-limit` | `10` | Requests per second (1–50) |
| `timeout` | `10.0` | Request timeout in seconds |
| `report` | — | HTML report output path (optional) |

### Example

```
msscan> set url https://example.com
msscan> set modules xss,sqli,headers
msscan> set report report.html
msscan> scan
```

> The `https://` scheme is added automatically if omitted.
> If `report` is a directory path, `msscan_report.html` is appended automatically.

---

## Scanner Modules

| Module | What it checks |
|---|---|
| `xss` | Reflected XSS — injects payloads into URL parameters and checks for reflection |
| `sqli` | SQL Injection — error-based detection and time-based blind detection |
| `csrf` | CSRF — missing CSRF tokens and SameSite cookie attributes |
| `open_redirect` | Open Redirect — manipulates redirect parameters to detect external redirects |
| `ssrf` | SSRF — injects internal addresses into request parameters |
| `headers` | HTTP Security Headers — CSP, HSTS, X-Frame-Options, and more |
| `subdomain` | Subdomain Enumeration — DNS brute-force with a built-in wordlist |

---

## Safety Limits

| Condition | Behavior |
|---|---|
| `rate-limit` < 1 or > 50 | Blocked — scan does not start |
| `rate-limit` > 20 | Warning shown, value accepted |
| Target returns HTTP 429 / 503 | Scan halts, lower rate suggested |
| Before every scan | Legal consent prompt is shown |

---

## HTML Report

When `report` is set, an HTML file is generated after the scan containing:

- Target URL, scan date, elapsed time, and total finding count
- Per-severity finding counts (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- Findings grouped by module
- Expandable detail cards for each finding (URL, evidence, timestamp)

---

## Tests

```bash
pytest tests/ -v
```

---

## Legal Notice

This tool may only be used on systems you have **explicit written permission** to test. Unauthorized scanning is illegal. The user assumes all responsibility for any misuse.
