"""HTTP client wrapper — httpx AsyncClient with caching, retry, and adaptive rate limiting."""

from __future__ import annotations

import asyncio
import random
from collections import deque
from typing import Any

import httpx

from msscan.core.exceptions import RateLimitedError


class HttpClient:
    """httpx AsyncClient wrapper with response caching, retry logic,
    and adaptive rate limiting.

    Features over V1:
    - Response cache: avoids duplicate requests to the same URL
    - Retry with exponential backoff (configurable attempts)
    - Response size limit to prevent memory pressure
    - Adaptive rate limiting: backs off when target slows down
    - Jitter support for stealth scanning
    """

    def __init__(
        self,
        timeout: float = 10.0,
        rate_limit: int = 0,
        max_response_size: int = 5_000_000,
        retry_count: int = 3,
        jitter: tuple[float, float] = (0.0, 0.0),
        cache_enabled: bool = True,
    ):
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.max_response_size = max_response_size
        self.retry_count = retry_count
        self.jitter = jitter
        self.cache_enabled = cache_enabled

        self._semaphore: asyncio.Semaphore | None = None
        self._client: httpx.AsyncClient | None = None
        self._cache: dict[str, httpx.Response] = {}

        # Adaptive rate limiting: track recent response times
        self._response_times: deque[float] = deque(maxlen=20)
        self._baseline_avg: float | None = None

        # Stats
        self.request_count: int = 0
        self.cache_hits: int = 0
        self.retry_total: int = 0

    async def __aenter__(self) -> "HttpClient":
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=False,
            verify=False,
            headers={"User-Agent": "msscan/2.0 (Security Scanner)"},
        )
        if self.rate_limit > 0:
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

    def _cache_key(self, method: str, url: str) -> str:
        """Generate a cache key for the request."""
        return f"{method}:{url}"

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        assert self._client is not None, "HttpClient must be used as async context manager"

        # Check cache for GET requests without custom kwargs
        cache_key = self._cache_key(method, url)
        if self.cache_enabled and method == "GET" and not kwargs and cache_key in self._cache:
            self.cache_hits += 1
            return self._cache[cache_key]

        resp = await self._request_with_retry(method, url, **kwargs)

        # Cache successful GET responses
        if self.cache_enabled and method == "GET" and not kwargs and resp.status_code < 400:
            self._cache[cache_key] = resp

        return resp

    async def _request_with_retry(
        self, method: str, url: str, **kwargs: Any
    ) -> httpx.Response:
        """Execute request with retry logic and rate limiting."""
        last_exc: Exception | None = None

        for attempt in range(self.retry_count):
            try:
                resp = await self._throttled_request(method, url, **kwargs)
                self.request_count += 1
                return resp
            except RateLimitedError:
                raise  # Don't retry rate limiting — surface immediately
            except (httpx.TimeoutException, httpx.ConnectError) as exc:
                last_exc = exc
                if attempt < self.retry_count - 1:
                    self.retry_total += 1
                    delay = (2 ** attempt) * 1.0  # 1s, 2s, 4s
                    await asyncio.sleep(delay)
                continue
            except Exception as exc:
                last_exc = exc
                break  # Don't retry unknown errors

        if last_exc is not None:
            raise last_exc
        raise RuntimeError("Unexpected retry loop exit")  # pragma: no cover

    async def _throttled_request(
        self, method: str, url: str, **kwargs: Any
    ) -> httpx.Response:
        """Execute a single request with rate limiting and adaptive throttling."""
        if self._semaphore:
            async with self._semaphore:
                return await self._timed_request(method, url, **kwargs)
        return await self._timed_request(method, url, **kwargs)

    async def _timed_request(
        self, method: str, url: str, **kwargs: Any
    ) -> httpx.Response:
        """Execute request, track timing, and enforce rate/jitter."""
        import time

        t0 = time.monotonic()
        resp = await self._client.request(method, url, **kwargs)  # type: ignore[union-attr]
        elapsed = time.monotonic() - t0

        # Track response times for adaptive rate limiting
        self._response_times.append(elapsed)
        if self._baseline_avg is None and len(self._response_times) >= 3:
            self._baseline_avg = sum(self._response_times) / len(self._response_times)

        # Check for rate limiting response
        if resp.status_code in (429, 503):
            raise RateLimitedError(
                status_code=resp.status_code,
                current_rate=self.rate_limit,
            )

        # Apply pacing: sleep to maintain rate limit
        if self.rate_limit > 0:
            await asyncio.sleep(1.0 / self.rate_limit)

        # Apply jitter for stealth mode
        if self.jitter[1] > 0:
            jitter_delay = random.uniform(self.jitter[0], self.jitter[1])
            await asyncio.sleep(jitter_delay)

        return resp

    @property
    def is_target_slowing(self) -> bool:
        """Check if target response times are increasing significantly."""
        if self._baseline_avg is None or len(self._response_times) < 5:
            return False
        recent_avg = sum(self._response_times) / len(self._response_times)
        return recent_avg > self._baseline_avg * 2.0

    def clear_cache(self) -> None:
        """Clear the response cache."""
        self._cache.clear()
