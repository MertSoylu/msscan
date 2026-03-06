"""Helper utilities — URL normalization, parsing."""

from __future__ import annotations

from urllib.parse import urlparse, urlencode, parse_qs, urlunparse


def normalize_url(url: str) -> str:
    """Ensure URL has a scheme and is well-formed."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url  # default to HTTPS when scheme is missing
    parsed = urlparse(url)
    return urlunparse(parsed)


def get_base_url(url: str) -> str:
    """Return scheme + host (e.g. https://example.com)."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def inject_param(url: str, param: str, value: str) -> str:
    """Add or overwrite a single query parameter in the URL."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]                          # replace existing value if present
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def extract_params(url: str) -> dict[str, list[str]]:
    """Return all query parameters from the URL as a dict."""
    parsed = urlparse(url)
    return parse_qs(parsed.query, keep_blank_values=True)
