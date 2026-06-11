"""Token bucket rate limiter for outbound requests.

Enforces per-domain and global rate limits to prevent abuse.
"""

import asyncio
import time
from typing import Dict

from redteam_analyzer.core.models import ScopeConfig


class TokenBucket:
    """Async token bucket rate limiter."""

    def __init__(self, rate: int, capacity: int):
        """Initialize token bucket.

        Args:
            rate: Tokens added per second
            capacity: Maximum tokens the bucket can hold
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = float(capacity)
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire a token, waiting if necessary."""
        async with self._lock:
            await self._wait_for_token()
            self.tokens -= 1

    async def _wait_for_token(self) -> None:
        """Wait until at least one full token is available."""
        while self.tokens < 1:
            self._refill()
            if self.tokens < 1:
                # Calculate wait time for next token
                wait_time = 1.0 / self.rate
                await asyncio.sleep(wait_time)
        self._refill()

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_refill = now


class RateLimiter:
    """Global rate limiter with per-domain buckets."""

    def __init__(self, scope: ScopeConfig):
        """Initialize rate limiter.

        Args:
            scope: Scope configuration with rate limits
        """
        self.scope = scope
        self.buckets: Dict[str, TokenBucket] = {}
        self.global_bucket = TokenBucket(
            rate=scope.rate_limit_per_second,
            capacity=scope.rate_limit_per_second,
        )

    async def acquire(self, domain: str) -> None:
        """Acquire token for specific domain and globally.

        Args:
            domain: The domain to acquire a token for
        """
        # Get or create domain bucket
        if domain not in self.buckets:
            self.buckets[domain] = TokenBucket(
                rate=self.scope.rate_limit_per_second,
                capacity=self.scope.rate_limit_per_second,
            )

        # Acquire from both global and domain buckets
        await self.global_bucket.acquire()
        await self.buckets[domain].acquire()

    def get_domain_bucket(self, domain: str) -> TokenBucket:
        """Get or create a token bucket for a domain."""
        if domain not in self.buckets:
            self.buckets[domain] = TokenBucket(
                rate=self.scope.rate_limit_per_second,
                capacity=self.scope.rate_limit_per_second,
            )
        return self.buckets[domain]
