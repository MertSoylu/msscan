"""HTTP client wrapper — httpx AsyncClient with rate limiting."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from msscan.core.exceptions import RateLimitedError


class HttpClient:
    """httpx AsyncClient wrapper with optional rate limiting."""

    def __init__(self, timeout: float = 10.0, rate_limit: int = 0):
        self.timeout = timeout
        self.rate_limit = rate_limit
        self._semaphore: asyncio.Semaphore | None = None  # None = no throttling
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "HttpClient":
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=False,   # scanners inspect each redirect hop manually
            verify=False,             # allow self-signed / expired certs on test targets
            headers={"User-Agent": "msscan/1.0 (Security Scanner)"},
        )
        if self.rate_limit > 0:
            # Semaphore caps the number of concurrent in-flight requests
            self._semaphore = asyncio.Semaphore(self.rate_limit)
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client:
            await self._client.aclose()

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request("HEAD", url, **kwargs)

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        assert self._client is not None, "HttpClient must be used as async context manager"
        if self._semaphore:
            async with self._semaphore:
                resp = await self._client.request(method, url, **kwargs)
                # Sleep paces throughput to approximately rate_limit requests per second
                await asyncio.sleep(1.0 / self.rate_limit)
                if resp.status_code in (429, 503):
                    # Stop immediately — no point sending more requests to a rate-limited target
                    raise RateLimitedError(
                        status_code=resp.status_code,
                        current_rate=self.rate_limit,
                    )
                return resp
        # Fallback: no semaphore (rate_limit <= 0 is blocked by CLI guards, kept for safety)
        resp = await self._client.request(method, url, **kwargs)
        if resp.status_code in (429, 503):
            raise RateLimitedError(
                status_code=resp.status_code,
                current_rate=self.rate_limit,
            )
        return resp
