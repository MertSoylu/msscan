"""Shared scanner logic — reusable mixins for common patterns."""

from __future__ import annotations

from msscan.core.context import ScanContext
from msscan.utils.helpers import extract_params, inject_param
from msscan.utils.payloads import load_payloads


class ParameterFuzzMixin:
    """Shared logic for parameter extraction and payload iteration.

    Used by XSS, SQLi, Open Redirect, and SSRF scanners.
    """

    @staticmethod
    def get_params_or_defaults(
        url: str, defaults: list[str]
    ) -> dict[str, list[str]]:
        """Extract URL params or fall back to common parameter names."""
        params = extract_params(url)
        if not params:
            params = {p: ["test"] for p in defaults}
        return params

    @staticmethod
    def load_payloads_or_defaults(
        filename: str, default_payloads: list[str]
    ) -> list[str]:
        """Load payloads from file, falling back to built-in defaults."""
        payloads = load_payloads(filename)
        return payloads if payloads else default_payloads


class BaselineMixin:
    """Shared logic for baseline response fetching.

    Used by SQLi (boolean-based) and SSRF (differential analysis).
    """

    @staticmethod
    async def fetch_baseline(
        ctx: ScanContext, url: str, param: str, value: str
    ) -> tuple[str | None, int]:
        """Fetch a baseline response with a benign value.

        Returns (body_lower, body_length) or (None, 0) on failure.
        """
        try:
            baseline_url = inject_param(url, param, value)
            resp = await ctx.client.get(baseline_url)
            body = resp.text.lower()
            return body, len(body)
        except Exception:
            return None, 0
