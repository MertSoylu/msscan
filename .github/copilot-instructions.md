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
```

`asyncio_mode = "auto"` is set in `pyproject.toml`, so all async tests run automatically — no explicit event loop setup needed.

Tests use **respx** to mock HTTP calls. Wrap mocked requests in `with respx.mock:` and use `async with HttpClient() as client:` inside.

---

## Architecture

```
msscan/
  cli.py              ← Interactive shell (cmd.Cmd). Entry point: app()
  core/
    engine.py         ← ScanEngine: async orchestrator; loads scanners lazily via SCANNER_MAP
    http_client.py    ← httpx AsyncClient wrapper with semaphore-based rate limiting
    result.py         ← ScanResult dataclass (common output for all scanners)
    exceptions.py     ← RateLimitedError (raised on HTTP 429/503)
  scanners/
    base.py           ← BaseScanner ABC; every scanner implements scan(url, client)
    xss.py / sqli.py / csrf.py / headers.py / ...  ← Individual scanner modules
  output/
    console.py        ← Rich-based terminal output helpers
    html_report.py    ← Jinja2 HTML report generator
  utils/
    helpers.py        ← URL normalization, query param injection/extraction
    payloads.py       ← Attack payload lists used by scanners
payloads/             ← External payload text files (loaded by utils/payloads.py)
tests/                ← pytest tests (one file per scanner module)
```

**Data flow:**  
`cli.do_scan()` → `ScanEngine.run()` → per-module `Scanner.scan(url, client)` → `list[ScanResult]` → `output/console.py` + `output/html_report.py`

---

## Key Conventions

### Adding a new scanner module

1. Create `msscan/scanners/<name>.py` with exactly one class named `Scanner` that subclasses `BaseScanner` and implements `async def scan(url, client) -> list[ScanResult]`.
2. Register it in **both** places:
   - `engine.py` → add to `SCANNER_MAP`
   - `cli.py` → add to `ALL_MODULES`

### ScanResult fields

```python
ScanResult(
    scanner="xss",          # short module name
    severity="HIGH",        # CRITICAL | HIGH | MEDIUM | LOW | INFO
    url="https://...",      # exact URL where finding was detected
    detail="...",           # human-readable description — must be in English
    evidence="<script>...", # payload or response snippet proving the finding
)
```

All `detail` and `evidence` strings must be in **English** — they appear directly in the HTML report.

### HTTP client usage

Always use `HttpClient` as an async context manager. It is shared across all scanners within a single scan run (rate limit is global). Do not instantiate `httpx.AsyncClient` directly in scanners.

```python
async with HttpClient(timeout=10.0, rate_limit=10) as client:
    resp = await client.get(url)
```

### Rate limit enforcement

- Hard bounds: 1–50 req/s (constants `RATE_LIMIT_MIN` / `RATE_LIMIT_MAX` in `cli.py`)
- Enforced at `set rate-limit` time **and** again at scan start
- `RateLimitedError` is raised by `HttpClient` on HTTP 429/503 and handled in `cli.do_scan()`

### URL utilities (`utils/helpers.py`)

| Function | Purpose |
|---|---|
| `normalize_url(url)` | Prepend `https://` when scheme is missing |
| `get_base_url(url)` | Return `scheme://host` only |
| `inject_param(url, param, value)` | Add/overwrite a query parameter |
| `extract_params(url)` | Return all query params as `dict[str, list[str]]` |

### Shell config keys

`url`, `modules`, `rate-limit`, `timeout`, `report` — defined in `SET_KEYS` dict in `cli.py`. Setting `report` to a directory auto-appends `msscan_report.html`; paths without a file extension get `.html` appended automatically.
