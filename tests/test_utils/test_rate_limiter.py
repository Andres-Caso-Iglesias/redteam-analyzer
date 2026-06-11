"""Tests for rate limiter utilities."""

import asyncio
import pytest
import time

from redteam_analyzer.core.models import ScopeConfig
from redteam_analyzer.utils.rate_limiter import RateLimiter, TokenBucket


class TestTokenBucket:
    """Tests for TokenBucket rate limiter."""

    def test_initial_tokens_at_capacity(self):
        """Bucket starts with full tokens."""
        bucket = TokenBucket(rate=10, capacity=10)
        assert bucket.tokens == 10.0

    def test_tokens_cannot_exceed_capacity(self):
        """Tokens never exceed capacity even with refill."""
        bucket = TokenBucket(rate=10, capacity=5)
        bucket.tokens = 5.0
        bucket._refill()
        assert bucket.tokens <= 5.0

    @pytest.mark.asyncio
    async def test_acquire_decrements_tokens(self):
        """Acquiring a token reduces count."""
        bucket = TokenBucket(rate=100, capacity=10)
        initial = bucket.tokens
        await bucket.acquire()
        assert bucket.tokens < initial

    @pytest.mark.asyncio
    async def test_acquire_waits_when_empty(self):
        """Acquire waits when bucket is empty, then proceeds."""
        bucket = TokenBucket(rate=1, capacity=1)
        await bucket.acquire()

        # Bucket is now empty (rate=1 means 1 token/sec refill)
        # Second acquire should have to wait for refill
        start = time.monotonic()
        await bucket.acquire()
        elapsed = time.monotonic() - start

        # With rate=1, acquiring from empty bucket should take ~1 second
        assert elapsed >= 0.5

    @pytest.mark.asyncio
    async def test_concurrent_acquire(self):
        """Multiple concurrent acquires work correctly."""
        bucket = TokenBucket(rate=100, capacity=5)

        results = await asyncio.gather(*[bucket.acquire() for _ in range(3)])

        assert bucket.tokens <= 5.0


class TestRateLimiter:
    """Tests for RateLimiter with per-domain buckets."""

    def test_creates_domain_bucket(self):
        """RateLimiter creates per-domain buckets."""
        scope = ScopeConfig(rate_limit_per_second=10)
        limiter = RateLimiter(scope)

        bucket = limiter.get_domain_bucket("example.com")
        assert isinstance(bucket, TokenBucket)
        assert bucket.rate == 10

    def test_same_domain_returns_same_bucket(self):
        """Same domain returns the same bucket instance."""
        scope = ScopeConfig(rate_limit_per_second=10)
        limiter = RateLimiter(scope)

        b1 = limiter.get_domain_bucket("example.com")
        b2 = limiter.get_domain_bucket("example.com")
        assert b1 is b2

    def test_different_domains_get_different_buckets(self):
        """Different domains get different buckets."""
        scope = ScopeConfig(rate_limit_per_second=10)
        limiter = RateLimiter(scope)

        b1 = limiter.get_domain_bucket("example.com")
        b2 = limiter.get_domain_bucket("other.com")
        assert b1 is not b2

    @pytest.mark.asyncio
    async def test_acquire_uses_global_bucket(self):
        """Acquire uses both global and domain buckets."""
        scope = ScopeConfig(rate_limit_per_second=100)
        limiter = RateLimiter(scope)

        await limiter.acquire("example.com")

        assert limiter.global_bucket.tokens < 100.0

    @pytest.mark.asyncio
    async def test_acquire_rate_limits(self):
        """Acquire enforces rate limiting — tokens deplete and refill slowly."""
        scope = ScopeConfig(rate_limit_per_second=1)  # 1 per second
        limiter = RateLimiter(scope)

        start = time.monotonic()
        for _ in range(3):
            await limiter.acquire("example.com")
        elapsed = time.monotonic() - start

        # 3 acquires at 1/sec: first instant, next 2 need ~1s each = ~2s total
        assert elapsed >= 1.0
