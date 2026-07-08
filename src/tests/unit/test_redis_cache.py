"""Unit tests for the Redis client singleton and the FacetCache.

Covers TESTING_BACKLOG §4.1 (get_redis control flow, boot-window sentinel,
failure cooldown), §4.2 (subscriber gating on config not liveness), §4.5
(per-reconnect-cycle pubsub close), plus the unit form of §4.3
(get_cached_facets build/serve/invalidate/TTL) and invalidate_cache's
cross-worker publish.

No database, no real Redis: everything is mocked at the module-under-test
namespace ("app.services.redis_client.*" / "app.services.cache.*").
"""

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import redis

import app.services.redis_client as redis_client_module
from app.services.cache import _INVALIDATION_CHANNEL, FacetCache
from config import settings


@pytest.fixture(autouse=True)
def _fresh_redis_client_state():
    """STATE HYGIENE: redis_client caches a singleton in module globals.

    Save both globals, force a fresh-process state (no cached client, no
    recorded failure) for the test, and restore the originals afterwards so
    this file can never leak a mock client or a cooldown timestamp into
    other test files.
    """
    saved_client = redis_client_module._client
    saved_failure = redis_client_module._last_failure_time
    redis_client_module._client = None
    redis_client_module._last_failure_time = None
    try:
        yield
    finally:
        redis_client_module._client = saved_client
        redis_client_module._last_failure_time = saved_failure


# ---------------------------------------------------------------------------
# §4.1 get_redis control flow
# ---------------------------------------------------------------------------

def test_get_redis_initializes_pings_and_caches(monkeypatch):
    """§4.1: fresh process with Redis up -> get_redis returns a client (init
    runs at top level, guarding the over-nesting regression that skipped init
    on a fresh process), pings it, and caches it: the second call returns the
    same object WITHOUT a second from_url connection attempt."""
    monkeypatch.setattr(settings, "redis_enabled", True)
    fake_client = MagicMock(name="redis-client")
    with patch(
        "app.services.redis_client.redis.Redis.from_url", return_value=fake_client
    ) as from_url:
        first = redis_client_module.get_redis()
        assert first is fake_client
        fake_client.ping.assert_called_once()
        assert from_url.call_count == 1

        second = redis_client_module.get_redis()
        assert second is fake_client
        # Cached fast path: no new connection attempt.
        assert from_url.call_count == 1


def test_get_redis_low_uptime_is_not_a_spurious_cooldown(monkeypatch):
    """§4.1 boot-window bug: monotonic() measures seconds since boot, so at
    low uptime (5.0s here) a 0.0 failure sentinel would satisfy
    `monotonic() - 0.0 < 30` and wrongly suppress init forever at boot.
    The fixed code uses None as the no-failure sentinel, so with
    _last_failure_time None a client is returned regardless of uptime."""
    monkeypatch.setattr(settings, "redis_enabled", True)
    monkeypatch.setattr("app.services.redis_client.time.monotonic", lambda: 5.0)
    assert redis_client_module._last_failure_time is None  # fixture guarantee
    fake_client = MagicMock(name="redis-client")
    with patch(
        "app.services.redis_client.redis.Redis.from_url", return_value=fake_client
    ):
        assert redis_client_module.get_redis() is fake_client


def test_get_redis_failure_cooldown_then_recovery_resets_sentinel(monkeypatch):
    """§4.1: a connection failure records the failure time and returns None;
    a second call inside the 30s cooldown returns None WITHOUT another
    from_url attempt (log-spam guard); once the cooldown expires the retry
    runs, succeeds, and _last_failure_time is reset to None (not 0.0 — the
    reset-on-success pin that keeps the boot-window fix honest)."""
    monkeypatch.setattr(settings, "redis_enabled", True)
    now = {"t": 100.0}
    monkeypatch.setattr(
        "app.services.redis_client.time.monotonic", lambda: now["t"]
    )
    fake_client = MagicMock(name="redis-client")
    with patch(
        "app.services.redis_client.redis.Redis.from_url",
        side_effect=[redis.RedisError("connection refused"), fake_client],
    ) as from_url:
        # Failure: None returned, failure timestamp recorded.
        assert redis_client_module.get_redis() is None
        assert redis_client_module._last_failure_time == 100.0
        assert from_url.call_count == 1

        # Within cooldown (10s later): suppressed, no new attempt.
        now["t"] = 110.0
        assert redis_client_module.get_redis() is None
        assert from_url.call_count == 1

        # Cooldown expired (31s after failure): retry runs and succeeds.
        now["t"] = 131.0
        assert redis_client_module.get_redis() is fake_client
        assert from_url.call_count == 2
        fake_client.ping.assert_called_once()
        assert redis_client_module._last_failure_time is None


def test_get_redis_disabled_returns_none_without_connecting(monkeypatch):
    """§4.1: redis_enabled=False short-circuits to None before any connection
    attempt — dev mode must never touch the network."""
    monkeypatch.setattr(settings, "redis_enabled", False)
    with patch("app.services.redis_client.redis.Redis.from_url") as from_url:
        assert redis_client_module.get_redis() is None
        from_url.assert_not_called()


# ---------------------------------------------------------------------------
# §4.2 FacetCache subscriber gating (config, not liveness)
# ---------------------------------------------------------------------------

def test_subscriber_thread_starts_when_redis_configured_but_unreachable(monkeypatch):
    """§4.2: _start_subscriber gates on settings.redis_enabled (config), NOT
    on get_redis() liveness. A Redis blip at process boot must not
    permanently disable cross-worker invalidation: the thread exists and is
    alive (backing off inside _listen_loop), and stop() joins it cleanly."""
    monkeypatch.setattr(settings, "redis_enabled", True)
    with patch("app.services.cache.get_redis", return_value=None):
        cache = FacetCache(MagicMock(name="pool"))
        try:
            assert cache._subscriber_thread is not None
            assert cache._subscriber_thread.is_alive()
        finally:
            cache.stop()
        assert not cache._subscriber_thread.is_alive()


def test_no_subscriber_thread_when_redis_disabled(monkeypatch):
    """§4.2: with redis_enabled=False the cache runs local-only — no
    subscriber thread is ever created."""
    monkeypatch.setattr(settings, "redis_enabled", False)
    cache = FacetCache(MagicMock(name="pool"))
    assert cache._subscriber_thread is None


# ---------------------------------------------------------------------------
# §4.5 _listen_loop closes each cycle's pubsub connection
# ---------------------------------------------------------------------------

def test_listen_loop_closes_each_pubsub_across_reconnect_cycles(monkeypatch):
    """§4.5: the try/finally lives INSIDE the outer reconnect loop, so each
    reconnect cycle closes ITS pubsub connection before the next one is
    created (redis-py pubsub holds a connection outside the pool — a finally
    moved outside the loop reintroduces the flapping-accumulation leak).

    Runs _listen_loop directly on this thread: cycle 1's get_message raises
    ConnectionError; creating cycle 2's pubsub sets the stop event, so the
    loop exits after closing it. Total runtime ~1s (one backoff wait)."""
    monkeypatch.setattr(settings, "redis_enabled", False)
    cache = FacetCache(MagicMock(name="pool"))  # no thread (disabled)

    created: list[MagicMock] = []
    first_closed_before_second_created: list[bool] = []

    def make_pubsub():
        if len(created) == 1:
            # Record whether cycle 1's pubsub was already closed when the
            # reconnect creates cycle 2's — the finally-inside-loop pin.
            first_closed_before_second_created.append(created[0].close.called)
        ps = MagicMock(name=f"pubsub-{len(created)}")
        ps.get_message.side_effect = redis.ConnectionError("wire dropped")
        created.append(ps)
        if len(created) >= 2:
            cache._stop_event.set()  # end the loop after this cycle
        return ps

    fake_redis = MagicMock(name="redis")
    fake_redis.pubsub.side_effect = make_pubsub

    with patch("app.services.cache.get_redis", return_value=fake_redis):
        cache._listen_loop()  # returns once the stop event is honored

    assert len(created) == 2
    created[0].close.assert_called_once()
    created[1].close.assert_called_once()
    # Cycle 1's connection was released BEFORE cycle 2 reconnected.
    assert first_closed_before_second_created == [True]


# ---------------------------------------------------------------------------
# §4.3 (unit form) get_cached_facets build / serve / invalidate / TTL
# ---------------------------------------------------------------------------

async def test_get_cached_facets_builds_once_then_serves_from_cache(monkeypatch):
    """§4.3 unit form: first call builds via get_facets (awaited once);
    the second call for the same tier is served from the in-memory cache
    without another database round-trip."""
    monkeypatch.setattr(settings, "redis_enabled", False)
    cache = FacetCache(MagicMock(name="pool"))
    facets = {"keywords": ["k"]}
    spy = AsyncMock(return_value=facets)
    monkeypatch.setattr("app.services.cache.get_facets", spy)

    first = await cache.get_cached_facets("registered")
    assert first == facets
    assert spy.await_count == 1

    second = await cache.get_cached_facets("registered")
    assert second == facets
    assert spy.await_count == 1  # cache hit, no rebuild


async def test_get_cached_facets_builds_per_tier(monkeypatch):
    """§4.3 unit form: facets are tier-scoped (a public user must not see
    higher-tier keywords), so a different tier triggers its own lazy build
    while the first tier's entry stays cached."""
    monkeypatch.setattr(settings, "redis_enabled", False)
    pool = MagicMock(name="pool")
    cache = FacetCache(pool)
    spy = AsyncMock(return_value={"keywords": ["k"]})
    monkeypatch.setattr("app.services.cache.get_facets", spy)

    await cache.get_cached_facets("public")
    assert spy.await_count == 1

    await cache.get_cached_facets("vetted")
    assert spy.await_count == 2
    # Each build queried for its own tier.
    tiers = [call.args[1] for call in spy.await_args_list]
    assert tiers == ["public", "vetted"]

    # Both tiers now cached: repeat calls do not rebuild.
    await cache.get_cached_facets("public")
    await cache.get_cached_facets("vetted")
    assert spy.await_count == 2


async def test_invalidate_cache_forces_rebuild_on_next_access(monkeypatch):
    """§4.3 unit form: invalidate_cache() clears the local cache, so the next
    get_cached_facets call rebuilds from the database."""
    monkeypatch.setattr(settings, "redis_enabled", False)
    cache = FacetCache(MagicMock(name="pool"))
    spy = AsyncMock(return_value={"keywords": ["k"]})
    monkeypatch.setattr("app.services.cache.get_facets", spy)

    await cache.get_cached_facets("registered")
    assert spy.await_count == 1

    cache.invalidate_cache()  # redis disabled -> local clear only

    await cache.get_cached_facets("registered")
    assert spy.await_count == 2


async def test_cache_ttl_expiry_triggers_rebuild(monkeypatch):
    """§4.3 unit form / TTL safety net: even without an invalidation signal,
    an entry older than _CACHE_TTL_SECONDS (1h) is considered stale and is
    rebuilt on the next access."""
    monkeypatch.setattr(settings, "redis_enabled", False)
    cache = FacetCache(MagicMock(name="pool"))
    spy = AsyncMock(return_value={"keywords": ["k"]})
    monkeypatch.setattr("app.services.cache.get_facets", spy)

    now = {"t": 1_000.0}
    monkeypatch.setattr("app.services.cache.time.time", lambda: now["t"])

    await cache.get_cached_facets("registered")
    assert spy.await_count == 1

    # Still fresh just inside the TTL: served from cache.
    now["t"] = 1_000.0 + 3600.0
    await cache.get_cached_facets("registered")
    assert spy.await_count == 1

    # One second past the TTL: stale -> rebuild.
    now["t"] = 1_000.0 + 3601.0
    await cache.get_cached_facets("registered")
    assert spy.await_count == 2


# ---------------------------------------------------------------------------
# invalidate_cache publishes cross-worker (and never raises on publish errors)
# ---------------------------------------------------------------------------

def test_invalidate_cache_publishes_on_invalidation_channel(monkeypatch):
    """invalidate_cache publishes to the shared channel so other workers'
    subscriber loops drop their local caches too."""
    monkeypatch.setattr(settings, "redis_enabled", False)
    cache = FacetCache(MagicMock(name="pool"))
    fake_redis = MagicMock(name="redis")
    with patch("app.services.cache.get_redis", return_value=fake_redis):
        cache.invalidate_cache()
    fake_redis.publish.assert_called_once_with(_INVALIDATION_CHANNEL, "1")


def test_invalidate_cache_publish_failure_is_logged_not_raised(
    monkeypatch, caplog
):
    """A Redis outage during publish must not break the caller (e.g. the
    post-sync scheduler): the error is swallowed and logged as a warning,
    and the local cache is still cleared."""
    monkeypatch.setattr(settings, "redis_enabled", False)
    cache = FacetCache(MagicMock(name="pool"))
    cache._cache = {"registered": {"keywords": ["k"]}}
    fake_redis = MagicMock(name="redis")
    fake_redis.publish.side_effect = redis.ConnectionError("gone away")
    with patch("app.services.cache.get_redis", return_value=fake_redis):
        with caplog.at_level(logging.WARNING, logger="app.services.cache"):
            cache.invalidate_cache()  # must not raise
    assert cache._cache == {}
    assert any(
        "Failed to publish facet invalidation" in rec.getMessage()
        for rec in caplog.records
    )
