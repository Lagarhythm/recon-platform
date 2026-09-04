"""Token-bucket rate limiter shared by every outbound request in a scan run."""

from __future__ import annotations

import asyncio
import time


class RateLimiter:
    def __init__(self, rate_per_second: float) -> None:
        self._rate = max(rate_per_second, 0.01)
        self._tokens = self._rate
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(
                    self._rate, self._tokens + (now - self._updated) * self._rate
                )
                self._updated = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                await asyncio.sleep((1 - self._tokens) / self._rate)

    def update_rate(self, rate_per_second: float) -> None:
        """Phase 3 adaptive backoff adjusts this live."""
        self._rate = max(rate_per_second, 0.01)
