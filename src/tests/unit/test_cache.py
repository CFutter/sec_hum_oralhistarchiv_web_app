"""Unit tests for the catalogue statistics cache surface.

Covers `app.services.redis_client` (the lazy, cooldown-guarded Redis
singleton) and `app.services.cache` (CatalogueStatsCache: subscriber-thread
gating, the pubsub reconnect loop, cross-worker invalidation, shutdown, and
concurrent-fill coalescing of the global-statistics snapshot).

No database, no real Redis: everything is mocked at the module-under-test
namespace ("app.services.redis_client.*" / "app.services.cache.*").
"""

import asyncio
import logging
import threading
from unittest.mock import MagicMock, create_autospec, patch

import pytest
import redis

import app.services.cache as cache_module
import app.services.redis_client as redis_client_module
from app.services.cache import (
    _INVALIDATION_CHANNEL,
    CatalogueStatsCache,
    GlobalStats,
)
from app.services.datasets import get_global_catalogue_stats as _real_get_global_catalogue_stats
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


class TestRedisClientLifecycle:
    """`get_redis()` control flow: lazy init, caching, and failure cooldown."""

    def test_get_redis_initializes_pings_and_caches(self, monkeypatch):
        """Fresh process with Redis up: get_redis returns a client (init runs
        at top level so it is not skipped on a fresh process), pings it, and
        caches it: the second call returns the same object WITHOUT a second
        from_url connection attempt."""
        monkeypatch.setattr(settings, "redis_enabled", True)
        fake_client = create_autospec(redis.Redis, instance=True, spec_set=True)
        with patch(
            "app.services.redis_client.redis.Redis.from_url",
            autospec=True,
            return_value=fake_client,
        ) as from_url:
            first = redis_client_module.get_redis()
            assert first is fake_client
            fake_client.ping.assert_called_once()
            assert from_url.call_count == 1

            second = redis_client_module.get_redis()
            assert second is fake_client
            # Cached fast path: no new connection attempt.
            assert from_url.call_count == 1

    def test_get_redis_low_uptime_is_not_a_spurious_cooldown(self, monkeypatch):
        """monotonic() measures seconds since boot, so at low uptime (5.0s
        here) a 0.0 failure sentinel would satisfy
        `monotonic() - 0.0 < 30` and wrongly suppress init forever at boot.
        The correct sentinel is None, so with _last_failure_time None a
        client is returned regardless of uptime."""
        monkeypatch.setattr(settings, "redis_enabled", True)
        monkeypatch.setattr("app.services.redis_client.time.monotonic", lambda: 5.0)
        assert redis_client_module._last_failure_time is None  # fixture guarantee
        fake_client = create_autospec(redis.Redis, instance=True, spec_set=True)
        with patch(
            "app.services.redis_client.redis.Redis.from_url",
            autospec=True,
            return_value=fake_client,
        ):
            assert redis_client_module.get_redis() is fake_client

    def test_get_redis_failure_cooldown_then_recovery_resets_sentinel(self, monkeypatch):
        """A connection failure records the failure time and returns None; a
        second call inside the 30s cooldown returns None WITHOUT another
        from_url attempt (log-spam guard); once the cooldown expires the
        retry runs, succeeds, and _last_failure_time is reset to None (not
        0.0 — this keeps the boot-window sentinel meaningful)."""
        monkeypatch.setattr(settings, "redis_enabled", True)
        now = {"t": 100.0}
        monkeypatch.setattr("app.services.redis_client.time.monotonic", lambda: now["t"])
        fake_client = create_autospec(redis.Redis, instance=True, spec_set=True)
        with patch(
            "app.services.redis_client.redis.Redis.from_url",
            autospec=True,
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

    def test_get_redis_disabled_returns_none_without_connecting(self, monkeypatch):
        """redis_enabled=False short-circuits to None before any connection
        attempt — dev mode must never touch the network."""
        monkeypatch.setattr(settings, "redis_enabled", False)
        with patch("app.services.redis_client.redis.Redis.from_url", autospec=True) as from_url:
            assert redis_client_module.get_redis() is None
            from_url.assert_not_called()


class TestSubscriberThreadGating:
    """CatalogueStatsCache starts its subscriber thread on config, not on
    Redis liveness, and only when it will actually read the cache."""

    def test_subscriber_thread_starts_when_redis_configured_but_unreachable(self, monkeypatch):
        """_start_subscriber gates on settings.redis_enabled (config), NOT
        on get_redis() liveness. A Redis blip at process boot must not
        permanently disable cross-worker invalidation: the thread exists and
        is alive (backing off inside _listen_loop), and stop() joins it
        cleanly. Positive control for the absence cases below."""
        monkeypatch.setattr(settings, "redis_enabled", True)
        with patch("app.services.cache.get_redis", autospec=True, return_value=None):
            cache = CatalogueStatsCache(MagicMock(name="pool"))
            try:
                assert cache._subscriber_thread is not None
                assert cache._subscriber_thread.is_alive()
            finally:
                cache.stop()
            assert not cache._subscriber_thread.is_alive()

    @pytest.mark.parametrize(
        ("redis_enabled", "subscribe"),
        [
            pytest.param(False, True, id="redis_disabled_runs_local_only"),
            pytest.param(True, False, id="publish_only_mode_suppresses_thread"),
        ],
    )
    def test_no_subscriber_thread_when_gated(self, monkeypatch, redis_enabled, subscribe):
        """With redis_enabled=False the cache runs local-only, and even with
        Redis ON, subscribe=False suppresses the thread — the scheduler
        process publishes invalidations but never reads the cache, so a
        subscriber there would only consume its own messages. These are the
        two halves of the `not redis_enabled or not self._subscribe` gate;
        the positive-control test above pins neither half being true."""
        monkeypatch.setattr(settings, "redis_enabled", redis_enabled)
        cache = CatalogueStatsCache(MagicMock(name="pool"), subscribe=subscribe)
        assert cache._subscriber_thread is None


class TestSubscriberListenLoop:
    """The invalidation subscriber's reconnect loop."""

    def test_listen_loop_closes_each_pubsub_across_reconnect_cycles(self, monkeypatch):
        """The try/finally lives INSIDE the outer reconnect loop, so each
        reconnect cycle closes ITS pubsub connection before the next one is
        created (redis-py pubsub holds a connection outside the pool — a
        finally moved outside the loop would reintroduce a flapping
        connection leak).

        Runs _listen_loop directly on this thread: cycle 1's get_message
        raises ConnectionError; creating cycle 2's pubsub sets the stop
        event, so the loop exits after closing it. Total runtime ~1s (one
        backoff wait)."""
        monkeypatch.setattr(settings, "redis_enabled", False)
        cache = CatalogueStatsCache(MagicMock(name="pool"))  # no thread (disabled)

        created: list[MagicMock] = []
        first_closed_before_second_created: list[bool] = []

        def make_pubsub():
            if len(created) == 1:
                # Record whether cycle 1's pubsub was already closed when the
                # reconnect creates cycle 2's — pins the finally-inside-loop.
                first_closed_before_second_created.append(created[0].close.called)
            ps = create_autospec(redis.client.PubSub, instance=True, spec_set=True)
            ps.get_message.side_effect = redis.ConnectionError("wire dropped")
            created.append(ps)
            if len(created) >= 2:
                cache._stop_event.set()  # end the loop after this cycle
            return ps

        fake_redis = create_autospec(redis.Redis, instance=True, spec_set=True)
        fake_redis.pubsub.side_effect = make_pubsub

        with patch("app.services.cache.get_redis", autospec=True, return_value=fake_redis):
            cache._listen_loop()  # returns once the stop event is honored

        assert len(created) == 2
        created[0].close.assert_called_once()
        created[1].close.assert_called_once()
        # Cycle 1's connection was released BEFORE cycle 2 reconnected.
        assert first_closed_before_second_created == [True]


class TestInvalidationPublishing:
    """invalidate_cache clears local state and publishes cross-worker."""

    def test_invalidate_cache_publishes_on_invalidation_channel(self, monkeypatch):
        """invalidate_cache publishes to the shared channel so other
        workers' subscriber loops drop their local caches too."""
        monkeypatch.setattr(settings, "redis_enabled", False)
        cache = CatalogueStatsCache(MagicMock(name="pool"))
        fake_redis = create_autospec(redis.Redis, instance=True, spec_set=True)
        with patch("app.services.cache.get_redis", autospec=True, return_value=fake_redis):
            cache.invalidate_cache()
        fake_redis.publish.assert_called_once_with(_INVALIDATION_CHANNEL, "1")

    def test_publish_only_mode_still_invalidates_and_publishes(self, monkeypatch):
        """subscribe=False suppresses ONLY the subscriber thread —
        invalidate_cache() must still clear local state, bump the generation
        counter, and publish to other workers. This is the property that
        makes publish-only mode safe for the scheduler (which writes via
        sync but never reads the cache, so it needs the publish side without
        the subscriber thread)."""
        monkeypatch.setattr(settings, "redis_enabled", True)
        cache = CatalogueStatsCache(MagicMock(name="pool"), subscribe=False)
        cache._global = (
            GlobalStats(
                total_datasets=1,
                last_full_rebuild=None,
            ),
            0.0,
        )
        generation_before = cache._generation
        fake_redis = create_autospec(redis.Redis, instance=True, spec_set=True)
        with patch("app.services.cache.get_redis", autospec=True, return_value=fake_redis):
            cache.invalidate_cache()
        fake_redis.publish.assert_called_once_with(_INVALIDATION_CHANNEL, "1")
        assert cache._generation == generation_before + 1
        assert cache._global is None


class TestSubscriberShutdown:
    """stop() must be safe to call regardless of subscriber mode."""

    def test_stop_is_safe_no_op_in_publish_only_mode(self, monkeypatch, caplog):
        """stop() must be callable unconditionally regardless of subscribe
        mode — the scheduler's shutdown `finally` calls facet_cache.stop()
        without checking whether a subscriber thread was ever started. With
        subscribe=False there is no thread to join, so stop() should set the
        stop event and return without raising, and it must NOT emit the
        'did not exit cleanly' warning (that would be a false alarm about a
        thread that never existed). Positive control for the warning test
        below."""
        monkeypatch.setattr(settings, "redis_enabled", True)
        cache = CatalogueStatsCache(MagicMock(name="pool"), subscribe=False)
        assert cache._subscriber_thread is None  # precondition for this mode

        with caplog.at_level(logging.WARNING, logger="app.services.cache"):
            cache.stop()  # must not raise

        assert cache._stop_event.is_set()
        assert not any("did not exit cleanly" in rec.getMessage() for rec in caplog.records)

    def test_stop_warns_when_subscriber_thread_does_not_exit_in_time(self, caplog):
        """The 'did not exit cleanly' warning is not dead code — a thread
        that is still alive after the join timeout DOES trigger it. Without
        this, a stop() that always suppressed the warning would pass the
        publish-only test above for the wrong reason.

        Constructs the cache via __new__ (bypassing __init__/threading
        entirely) and swaps in a mock thread whose is_alive() stays True
        after join(), so the join timeout never has to actually elapse."""
        cache = CatalogueStatsCache.__new__(CatalogueStatsCache)  # bypass __init__, no real thread
        cache._stop_event = MagicMock()
        stuck_thread = MagicMock()
        stuck_thread.is_alive.return_value = True  # never actually exits
        cache._subscriber_thread = stuck_thread

        with caplog.at_level(logging.WARNING, logger="app.services.cache"):
            cache.stop()  # must not raise despite the stuck thread

        stuck_thread.join.assert_called_once_with(timeout=5.0)
        assert any("did not exit cleanly" in rec.getMessage() for rec in caplog.records)


class TestGlobalStatsCache:
    """get_global_catalogue_stats reads are cached until invalidated."""

    async def test_catalogue_statistics_are_cached_until_invalidated(self, monkeypatch):
        """get_global_catalogue_stats supplies the dataset count and the
        last-full-rebuild timestamp together in one snapshot; the cache
        coalesces get_total_datasets/get_last_full_rebuild reads into a
        single fetch and only re-fetches after invalidate_cache."""
        monkeypatch.setattr(settings, "redis_enabled", False)

        pool = MagicMock(name="pool")
        cache = CatalogueStatsCache(pool)

        fetch_stats = create_autospec(_real_get_global_catalogue_stats, return_value=(42, None))
        monkeypatch.setattr("app.services.cache.get_global_catalogue_stats", fetch_stats)

        assert await cache.get_total_datasets() == 42
        assert await cache.get_total_datasets() == 42
        assert await cache.get_last_full_rebuild() is None

        assert fetch_stats.await_count == 1

        cache.invalidate_cache()

        assert await cache.get_total_datasets() == 42
        assert fetch_stats.await_count == 2


class TestConcurrentGlobalStatsFill:
    """Deterministic cache-fill concurrency, cancellation, and invalidation
    checks for CatalogueStatsCache._get_global."""

    @pytest.fixture
    def cache(self):
        return CatalogueStatsCache(object(), subscribe=False)

    async def test_concurrent_cache_misses_share_one_fill(self, cache, monkeypatch):
        started = asyncio.Event()
        release = asyncio.Event()

        async def slow(*_args):
            started.set()
            await release.wait()
            return (9, None)

        fetch_stats = create_autospec(_real_get_global_catalogue_stats, side_effect=slow)
        monkeypatch.setattr(cache_module, "get_global_catalogue_stats", fetch_stats)

        async def read():
            return await cache._get_global()

        tasks = [asyncio.create_task(read()) for _ in range(25)]
        try:
            await asyncio.wait_for(started.wait(), timeout=1)
            await asyncio.sleep(0)
            assert fetch_stats.await_count == 1
            release.set()
            values = await asyncio.wait_for(asyncio.gather(*tasks), timeout=1)
            assert all(value == values[0] for value in values)
            fetch_stats.assert_awaited_once()
            assert await read() == values[0]
            fetch_stats.assert_awaited_once()
        finally:
            release.set()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def test_failed_fill_releases_lock_for_next_reader(self, cache, monkeypatch):
        fetch_stats = create_autospec(
            _real_get_global_catalogue_stats,
            side_effect=[RuntimeError("query failed"), (4, None)],
        )
        monkeypatch.setattr(cache_module, "get_global_catalogue_stats", fetch_stats)

        async def read():
            return await cache._get_global()

        with pytest.raises(RuntimeError, match="query failed"):
            await read()
        result = await asyncio.wait_for(read(), timeout=1)
        assert result is not None
        assert fetch_stats.await_count == 2

    async def test_cancelled_filler_does_not_strand_waiter(self, cache, monkeypatch):
        started = asyncio.Event()
        never = asyncio.Event()
        calls = 0

        async def fetch_stats_impl(*_args):
            nonlocal calls
            calls += 1
            if calls == 1:
                started.set()
                await never.wait()
            return (4, None)

        fetch_stats = create_autospec(
            _real_get_global_catalogue_stats, side_effect=fetch_stats_impl
        )
        monkeypatch.setattr(cache_module, "get_global_catalogue_stats", fetch_stats)

        async def read():
            return await cache._get_global()

        leader = asyncio.create_task(read())
        waiter = None
        try:
            await asyncio.wait_for(started.wait(), timeout=1)
            waiter = asyncio.create_task(read())
            await asyncio.sleep(0)
            leader.cancel()
            with pytest.raises(asyncio.CancelledError):
                await leader
            assert await asyncio.wait_for(waiter, timeout=1) is not None
            assert calls == 2
        finally:
            leader.cancel()
            if waiter is not None:
                waiter.cancel()
            await asyncio.gather(
                leader, *([waiter] if waiter is not None else []), return_exceptions=True
            )

    async def test_cross_thread_invalidation_during_fill_is_not_cached(self, cache, monkeypatch):
        calls = 0

        async def fetch_stats_impl(*_args):
            nonlocal calls
            calls += 1
            if calls == 1:
                invalidator = threading.Thread(
                    target=cache._on_invalidation_message,
                    daemon=True,
                )
                invalidator.start()
                invalidator.join(timeout=1)
                assert not invalidator.is_alive()
            return (calls, None)

        fetch_stats = create_autospec(
            _real_get_global_catalogue_stats, side_effect=fetch_stats_impl
        )
        monkeypatch.setattr(cache_module, "get_global_catalogue_stats", fetch_stats)

        async def read():
            return await cache._get_global()

        old = await read()
        fresh = await read()
        assert old != fresh
        assert await read() == fresh
        assert calls == 2
