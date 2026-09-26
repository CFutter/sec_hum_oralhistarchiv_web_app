"""Redis coordination integration tests.

Everything here requires a real Redis:

- reachable Redis -> tests run;
- unreachable without REQUIRE_REDIS=1 -> module skips;
- unreachable with REQUIRE_REDIS=1 -> hard failure.

The tests cover:

- cross-worker invalidation of CatalogueStatsCache;
- subscriber recovery after a dropped Redis connection;
- clean subscriber-thread shutdown;
- shared rate-limit counters across Limiter instances.
"""

import contextlib
import os
import time
from typing import cast

import pytest
import redis as redis_lib
from pydantic import SecretStr
from slowapi import Limiter
from slowapi.util import get_remote_address

import app.services.redis_client as rc
from app.services.cache import (
    _INVALIDATION_CHANNEL,
    CatalogueStatsCache,
    GlobalStats,
)
from config import settings

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


def _redis_reachable() -> bool:
    """Return whether the configured integration-test Redis is reachable."""
    try:
        client = redis_lib.Redis.from_url(
            REDIS_URL,
            socket_connect_timeout=3,
        )
        client.ping()
        client.close()
        return True
    except Exception:
        return False


_REDIS_AVAILABLE = _redis_reachable()


@pytest.fixture(scope="session", autouse=True)
def _require_redis_tier():
    """Skip without Redis unless CI explicitly requires the Redis tier."""
    if not _REDIS_AVAILABLE:
        if os.environ.get("REQUIRE_REDIS") == "1":
            raise RuntimeError(f"REQUIRE_REDIS=1 but Redis unreachable at {REDIS_URL}")
        pytest.skip(f"Redis not reachable at {REDIS_URL}")


@pytest.fixture
def redis_enabled(monkeypatch):
    """Point the application Redis client at the integration-test Redis."""
    monkeypatch.setattr(settings, "redis_enabled", True)
    monkeypatch.setattr(settings, "redis_url", SecretStr(REDIS_URL))

    saved_client = rc._client
    saved_failure = rc._last_failure_time

    rc._client = None
    rc._last_failure_time = None

    try:
        yield
    finally:
        if rc._client is not None:
            with contextlib.suppress(Exception):
                rc._client.close()

        rc._client = saved_client
        rc._last_failure_time = saved_failure


@pytest.fixture
def clean_channel(redis_enabled):  # noqa: ARG001
    """Provide a direct Redis handle for assertions and fault injection."""
    client = redis_lib.Redis.from_url(
        REDIS_URL,
        decode_responses=True,
    )
    try:
        yield client
    finally:
        client.close()


def _wait_until(predicate, timeout: float = 5.0, interval: float = 0.02) -> bool:
    """Poll a predicate until it succeeds or the timeout expires."""
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)

    return predicate()


def _subscriber_count(client: redis_lib.Redis) -> int:
    """Return the number of subscribers on the cache-invalidation channel."""
    result = cast("list[tuple[str, int]]", client.pubsub_numsub(_INVALIDATION_CHANNEL))
    if not result:
        return 0

    return int(result[0][1])


def _prime_global_cache(cache: CatalogueStatsCache) -> None:
    """Install a fresh global-statistics value without querying PostgreSQL."""
    with cache._lock:
        cache._global = (
            GlobalStats(
                total_datasets=1,
                last_full_rebuild=None,
            ),
            time.monotonic(),
        )


def _global_cache_is_empty(cache: CatalogueStatsCache) -> bool:
    """Read the private cache slot under the same lock used by production."""
    with cache._lock:
        return cache._global is None


# ---------------------------------------------------------------------------
# Cross-worker statistics-cache invalidation
# ---------------------------------------------------------------------------


def test_publish_on_one_cache_invalidates_another(clean_channel):
    """An invalidation published by worker A clears worker B's global slot."""
    pool = _DummyPool()
    worker_a = CatalogueStatsCache(pool)
    worker_b = CatalogueStatsCache(pool)

    try:
        # Waiting for Redis' subscriber count avoids relying on an arbitrary
        # sleep: a live thread is not necessarily subscribed yet.
        assert _wait_until(
            lambda: _subscriber_count(clean_channel) >= 2,
        )

        _prime_global_cache(worker_b)
        assert not _global_cache_is_empty(worker_b)

        worker_a.invalidate_cache()

        assert _wait_until(
            lambda: _global_cache_is_empty(worker_b),
        )
    finally:
        worker_a.stop()
        worker_b.stop()


def test_subscriber_survives_dropped_connection(clean_channel):
    """The subscriber reconnects and processes later invalidations."""
    cache = CatalogueStatsCache(_DummyPool())

    try:
        assert _wait_until(
            lambda: _subscriber_count(clean_channel) >= 1,
        )

        # Drop server-side pub/sub connections. skipme=True preserves the
        # direct test connection issuing this command.
        clean_channel.client_kill_filter(
            _type="pubsub",
            skipme=True,
        )

        _prime_global_cache(cache)
        assert not _global_cache_is_empty(cache)

        def _publish_until_received() -> bool:
            clean_channel.publish(_INVALIDATION_CHANNEL, "1")
            return _global_cache_is_empty(cache)

        # The first publication may precede the reconnect, so publish
        # repeatedly until the subscriber has re-established its subscription.
        assert _wait_until(
            _publish_until_received,
            timeout=10.0,
            interval=0.25,
        )
    finally:
        cache.stop()


@pytest.mark.usefixtures("redis_enabled")
def test_stop_joins_subscriber_thread():
    """stop() terminates and joins the subscriber thread."""
    cache = CatalogueStatsCache(_DummyPool())

    assert _wait_until(
        lambda: cache._subscriber_thread is not None and cache._subscriber_thread.is_alive()
    )

    cache.stop()

    assert cache._subscriber_thread is not None
    assert not cache._subscriber_thread.is_alive(), "subscriber thread did not join"


# ---------------------------------------------------------------------------
# Shared rate-limit counters
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("redis_enabled")
def test_two_limiters_share_counters_via_redis():
    """Independent Limiter instances share one Redis-backed counter."""
    limiter_a = Limiter(
        key_func=get_remote_address,
        storage_uri=REDIS_URL,
        enabled=True,
    )
    limiter_b = Limiter(
        key_func=get_remote_address,
        storage_uri=REDIS_URL,
        enabled=True,
    )

    storage_a = limiter_a.limiter.storage
    storage_b = limiter_b.limiter.storage

    key = f"test-shared-counter-{time.time_ns()}"

    try:
        storage_a.incr(key, expiry=60, amount=1)
        assert storage_b.get(key) == 1

        storage_a.incr(key, expiry=60, amount=1)
        assert storage_b.get(key) == 2
    finally:
        storage_a.clear(key)


class _DummyPool:
    """Pool stand-in for tests that never initiate a cache fill."""

    def __repr__(self) -> str:  # pragma: no cover
        return "<DummyPool for Redis coordination tests>"
