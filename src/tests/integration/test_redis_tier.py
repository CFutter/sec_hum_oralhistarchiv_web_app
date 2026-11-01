"""Redis coordination integration tests."""

import contextlib
import os
import subprocess
import time
from collections.abc import Iterator
from typing import cast

import pytest
import redis as redis_lib
from pydantic import SecretStr
from slowapi import Limiter
from slowapi.util import get_remote_address

import app.services.redis_client as rc
from app.middleware.bounded_rate_limit_storage import bounded_redis_uri
from app.middleware.rate_limiting import bounded_storage_options
from app.services.cache import (
    _INVALIDATION_CHANNEL,
    CatalogueStatsCache,
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
    """Require the shared Redis used by the root limiter-reset fixture."""
    if not _REDIS_AVAILABLE:
        if os.environ.get("REQUIRE_REDIS") == "1":
            raise RuntimeError(f"REQUIRE_REDIS=1 but Redis unreachable at {REDIS_URL}")
        pytest.skip(f"Redis not reachable at {REDIS_URL}")


@pytest.fixture
def redis_enabled(
    monkeypatch: pytest.MonkeyPatch,
    private_redis: tuple[int, subprocess.Popen[bytes]],
) -> Iterator[str]:
    """Use one test's private Redis and restore the application's client afterward."""
    port, _proc = private_redis
    redis_url = f"redis://127.0.0.1:{port}/0"
    with monkeypatch.context() as patches:
        patches.setattr(settings, "redis_enabled", True)
        patches.setattr(settings, "redis_url", SecretStr(redis_url))
        patches.setattr(rc, "_client", None)
        patches.setattr(rc, "_last_failure_time", None)
        try:
            yield redis_url
        finally:
            client = rc._client
            if client is not None:
                with contextlib.suppress(Exception):
                    client.close()


@pytest.fixture
def clean_channel(redis_enabled: str) -> Iterator[redis_lib.Redis]:
    """Inspect and inject faults only into this test's private Redis."""
    client = redis_lib.Redis.from_url(
        redis_enabled,
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


def _prime_freshness_cache(cache: CatalogueStatsCache) -> None:
    """Install cached unknown freshness without querying PostgreSQL."""
    with cache._lock:
        cache._freshness = (None, time.monotonic())


def _freshness_cache_is_empty(cache: CatalogueStatsCache) -> bool:
    """Read the private cache slot under the same lock used by production."""
    with cache._lock:
        return cache._freshness is None


# Cross-worker statistics-cache invalidation


def test_publish_on_one_cache_invalidates_another(clean_channel):
    """An invalidation published by worker A clears worker B's freshness slot."""
    pool = _DummyPool()
    worker_a = CatalogueStatsCache(
        pool, source_names=("redis_archive",), policy_fingerprint="a" * 64
    )
    worker_b = CatalogueStatsCache(
        pool, source_names=("redis_archive",), policy_fingerprint="a" * 64
    )

    try:
        # Waiting for Redis' subscriber count avoids relying on an arbitrary
        # sleep: a live thread is not necessarily subscribed yet.
        assert _wait_until(
            lambda: _subscriber_count(clean_channel) >= 2,
        )

        _prime_freshness_cache(worker_b)
        assert not _freshness_cache_is_empty(worker_b)

        worker_a.invalidate_cache()

        assert _wait_until(
            lambda: _freshness_cache_is_empty(worker_b),
        )
    finally:
        worker_a.stop()
        worker_b.stop()


def test_subscriber_survives_dropped_connection(clean_channel):
    """The subscriber reconnects and processes later invalidations."""
    cache = CatalogueStatsCache(
        _DummyPool(), source_names=("redis_archive",), policy_fingerprint="a" * 64
    )

    try:
        assert _wait_until(
            lambda: _subscriber_count(clean_channel) >= 1,
        )

        # This private server has exactly this cache's subscriber. The
        # direct inspection connection is not a pub/sub client.
        killed = clean_channel.client_kill_filter(
            _type="pubsub",
            skipme=True,
        )
        assert killed == 1, "fault injection must disconnect this cache's subscriber"

        _prime_freshness_cache(cache)
        assert not _freshness_cache_is_empty(cache)

        def _publish_until_received() -> bool:
            """Publish an invalidation and report whether the cache became empty."""
            clean_channel.publish(_INVALIDATION_CHANNEL, "1")
            return _freshness_cache_is_empty(cache)

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
    cache = CatalogueStatsCache(
        _DummyPool(), source_names=("redis_archive",), policy_fingerprint="a" * 64
    )

    try:
        assert _wait_until(
            lambda: cache._subscriber_thread is not None and cache._subscriber_thread.is_alive()
        )
    finally:
        cache.stop()

    assert cache._subscriber_thread is not None
    assert not cache._subscriber_thread.is_alive(), "subscriber thread did not join"


# Shared rate-limit counters


def test_two_limiters_share_counters_via_redis(redis_enabled):
    """Independent Limiter instances share one Redis-backed counter."""
    limiter_a = Limiter(
        key_func=get_remote_address,
        storage_uri=bounded_redis_uri(redis_enabled),
        storage_options=bounded_storage_options(),
        enabled=True,
    )
    limiter_b = Limiter(
        key_func=get_remote_address,
        storage_uri=bounded_redis_uri(redis_enabled),
        storage_options=bounded_storage_options(),
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
        """Identify this Redis-test pool double."""
        return "<DummyPool for Redis coordination tests>"
