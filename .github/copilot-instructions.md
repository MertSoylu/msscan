# msscan – Copilot Instructions

## Build & Test

```bash
# Install (editable, with dev dependencies)
pip install -e ".[dev]"

# Run all tests
pytest

# Run a single test file
pytest tests/test_xss.py

# Run a single test by name
pytest tests/test_xss.py::test_reflected_xss_detected

# Lint / type-check
ruff check msscan/
mypy msscan/
```

`asyncio_mode = "auto"` is set in `pyproject.toml`, so all async tests run automatically — no explicit event loop setup needed.

Tests use **respx** to mock HTTP calls and **unittest.mock** for DNS mocking. The shared helper `collect_results()` in `tests/conftest.py` creates a `ScanContext` and iterates the scanner's async generator to collect `ScanResult` objects from `FindingEvent`s.

---

## Architecture

```
msscan/
  cli/
    __init__.py       ← re-exports app()
    app.py            ← Typer CLI: scan / config / plugins subcommands
    headless.py       ← Headless scan executor (exit codes 0/1/2/3)
    interactive.py    ← Interactive shell (cmd.Cmd) — launched when no subcommand
  core/
    engine.py         ← ScanEngine: parallel asyncio orchestrator (run + run_stream)
    context.py        ← ScanContext dataclass (target, client, config, cancel_token)
    events.py         ← Event hierarchy: FindingEvent, ProgressEvent, ErrorEvent
    config.py         ← ScanConfig, SpeedProfile, TOML loading, env vars
    plugins.py        ← Plugin discovery (builtins, entry points, local ~/.msscan/plugins/)
    http_client.py    ← httpx wrapper: caching, retry, adaptive rate limiting, jitter
    result.py         ← ScanResult dataclass (common output for all scanners)
    exceptions.py     ← RateLimitedError (raised on HTTP 429/503)
  scanners/
    base.py           ← BaseScanner ABC (V2 protocol: async generator yielding ScanEvent)
    xss.py            ← Reflected XSS with context analysis (CWE-79)
    sqli.py           ← Error-based, boolean-blind, time-based SQLi (CWE-89)
    csrf.py           ← Missing/weak CSRF tokens, GET forms (CWE-352)
    open_redirect.py  ← HTTP 3xx, JS, meta-refresh redirects (CWE-601)
    ssrf.py           ← File access, cloud metadata, service banners (CWE-918)
    headers.py        ← 8 security header checks (HSTS, CSP, X-Frame-Options, etc.)
    subdomain.py      ← DNS enumeration, wildcard detection, CNAME takeover (CWE-404)
  output/
    console.py        ← Rich-based terminal output (banner, results, summary)
    json_report.py    ← JSON report generator
    sarif_report.py   ← SARIF 2.1.0 report (GitHub Code Scanning compatible)
    html_report.py    ← Jinja2 HTML report with dark theme
  utils/
    helpers.py        ← URL normalization, query param injection/extraction
    payloads.py       ← Attack payload loading from payloads/ directory
  ui/                 ← Textual TUI components (reserved)
payloads/             ← External payload text files (xss.txt, sqli.txt, ssrf.txt, redirects.txt, subdomains.txt)
tests/                ← 91 tests across 14 files (one per module + engine/config/output/plugins/cli)
```

**Entry point:** `pyproject.toml` → `[project.scripts] msscan = "msscan.cli:app"` → `msscan/cli/__init__.py` → `app.py`

**Data flow:**  
`cli scan` → `headless.run_headless_scan()` → `ScanEngine.run()` → `discover_scanners()` → per-module `Scanner.scan(ctx)` → `AsyncIterator[ScanEvent]` → collect `FindingEvent.result` → `output/*`

**Config resolution order (lowest → highest priority):**  
Built-in defaults → `~/.config/msscan/config.toml` → `./msscan.toml` → env vars (`MSSCAN_*`) → CLI arguments

---

## Key Conventions

### V2 Scanner Protocol

Scanners implement an **async generator** that yields events:

```python
from msscan.scanners.base import BaseScanner
from msscan.core.context import ScanContext
from msscan.core.events import ScanEvent, FindingEvent
from msscan.core.result import ScanResult

class Scanner(BaseScanner):
    name = "my_scanner"

    async def scan(self, ctx: ScanContext) -> AsyncIterator[ScanEvent]:
        # ctx.target — URL string
        # ctx.client — HttpClient (shared, rate-limited)
        # ctx.config — ScanConfig
        # ctx.is_cancelled — cooperative cancellation check

        resp = await ctx.client.get(ctx.target)
        if some_vuln_detected(resp):
            yield FindingEvent(result=ScanResult(
                scanner=self.name,
                severity="HIGH",
                url=ctx.target,
                detail="Description of the finding",
                evidence="proof snippet",
                confidence="HIGH",
                confidence_score=0.9,
                remediation="How to fix",
                cwe_id="CWE-XXX",
            ))
```

### Adding a new scanner module

1. Create `msscan/scanners/<name>.py` with exactly one class named `Scanner` that subclasses `BaseScanner`.
2. Register it in `msscan/core/plugins.py` → `BUILTIN_SCANNERS` dict.
3. Add an entry point in `pyproject.toml` under `[project.entry-points."msscan.scanners"]`.
4. Create `tests/test_<name>.py` using `conftest.collect_results()` for integration tests.

### ScanResult fields

```python
ScanResult(
    scanner="xss",              # short module name
    severity="HIGH",            # CRITICAL | HIGH | MEDIUM | LOW | INFO
    url="https://...",          # exact URL where finding was detected
    detail="...",               # human-readable description — must be in English
    evidence="<script>...",     # payload or response snippet proving the finding
    confidence="HIGH",          # HIGH | MEDIUM | LOW
    confidence_score=0.9,       # 0.0–1.0 for CI/CD thresholding
    remediation="...",          # actionable fix guidance
    cwe_id="CWE-79",           # Common Weakness Enumeration ID
    references=["https://..."], # relevant links
)
```

All `detail`, `evidence`, and `remediation` strings must be in **English** — they appear in reports.

### Event types

| Event | Emitted when | Contains |
|---|---|---|
| `FindingEvent` | Vulnerability found | `result: ScanResult` |
| `ProgressEvent` | Scanner progress update | `scanner_name`, `current`, `total`, `message` |
| `ErrorEvent` | Non-fatal scanner error | `scanner_name`, `error`, `exception` |

### HTTP client usage

Always use `HttpClient` as an async context manager. It is shared across all scanners within a single scan run. Do **not** instantiate `httpx.AsyncClient` directly in scanners.

```python
resp = await ctx.client.get(url)
resp = await ctx.client.post(url, data=payload)
```

Features: response caching (GET only), retry with exponential backoff (1s/2s/4s), adaptive rate limiting (detects target slowdown), jitter for stealth mode, response size limit (5 MB default).

### Speed profiles

| Profile | Rate | Concurrency | Jitter | Use case |
|---|---|---|---|---|
| `stealth` | 2 req/s | 1 | 1–3 s | WAF evasion |
| `normal` | 10 req/s | 5 | none | Default, balanced |
| `aggressive` | 50 req/s | 20 | none | Trusted/internal targets |

### Plugin system

Scanner discovery checks three sources (later overrides earlier):
1. **Built-in** — `msscan/scanners/*.py` (registered in `BUILTIN_SCANNERS`)
2. **Entry points** — `msscan.scanners` group in installed packages
3. **Local plugins** — `~/.msscan/plugins/*.py` (each must export a `Scanner` class)

### URL utilities (`utils/helpers.py`)

| Function | Purpose |
|---|---|
| `normalize_url(url)` | Prepend `https://` when scheme is missing |
| `get_base_url(url)` | Return `scheme://host` only |
| `inject_param(url, param, value)` | Add/overwrite a query parameter |
| `extract_params(url)` | Return all query params as `dict[str, list[str]]` |

### Testing patterns

```python
# Scanner integration test pattern (all scanner tests follow this)
async def test_something_detected():
    with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text="..."))
        async with HttpClient() as client:
            scanner = Scanner()
            results = await collect_results(scanner, "https://example.com/", client)
            assert len(results) >= 1
            assert results[0].severity == "HIGH"
```

### Exit codes (headless mode)

| Code | Meaning |
|---|---|
| `0` | Clean — no findings matching `--fail-on` severities |
| `1` | Findings detected matching `--fail-on` |
| `2` | Scan error (network, runtime) |
| `3` | Configuration error (no targets, invalid profile) |
