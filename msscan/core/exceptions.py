"""Custom exceptions for msscan core."""

from __future__ import annotations


class RateLimitedError(Exception):
    """Raised by HttpClient when the target returns HTTP 429 or 503.

    Propagates up through the scanner and engine to cli.do_scan(),
    which halts the scan and advises the user to lower the rate limit.
    """

    def __init__(self, status_code: int, current_rate: int) -> None:
        self.status_code = status_code   # 429 or 503
        self.current_rate = current_rate  # req/s at the time of the error
        super().__init__(
            f"Target server is rate-limiting requests (HTTP {status_code}). "
            f"Current rate-limit: {current_rate} req/s"
        )
