"""Mocked Redis initialization, subscriber lifecycle and concurrent catalogue-freshness caching."""

import asyncio
import logging
import threading
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, create_autospec, patch

import pytest
import redis
from psycopg import AsyncConnection, AsyncCursor
from redis.backoff import NoBackoff
from redis.retry import Retry

import app.services.cache as cache_module
import app.services.redis_client as redis_client_module
from app.services import datasets
from app.services.cache import (
    _INVALIDATION_CHANNEL,
    CatalogueStatsCache,
    GlobalStats,
)
from app.services.datasets import get_last_full_rebuild_date as _real_get_last_full_rebuild_date
from app.services.datasets import get_total_dataset_count as _real_get_total_dataset_count
from config import settings
from tests.fixtures import FakeCursorCtx, make_async_cursor

_POLICY_FINGERPRINT = "a" * 64


@pytest.fixture(autouse=True)
def guarded_cache_reads():
    """Patch guarded reads with one signature-checked connection per pool."""
    connections = {}

    def connection_for(pool):
        """Return the same signature-checked connection for each pool identity."""
        key = id(pool)
        if key not in connections:
            connections[key] = create_autospec(AsyncConnection, instance=True, spec_set=True)
        return connections[key]

    def cursor_for(pool, row_factory=None):
        """Wrap a strict cursor sharing the pool connection and requested row factory."""
        cursor = create_autospec(AsyncCursor, instance=True, spec_set=True)
        cursor.connection = connection_for(pool)
        if row_factory is not None:
            cursor.row_factory = row_factory
        return FakeCursorCtx(cursor)

    with (
        patch.object(cache_module, "get_db_cursor", autospec=True, side_effect=cursor_for),
        patch.object(cache_module, "guard_catalogue_policy_cur", autospec=True) as guard,
    ):
        yield SimpleNamespace(connection_for=connection_for, guard=guard)


@pytest.fixture(autouse=True)
def _fresh_redis_client_state():
    """Clear and restore cached Redis-client and cooldown globals around each test."""
    saved_client = redis_client_module._client
    saved_failure = redis_client_module._last_failure_time
    redis_client_module._client = None
    redis_client_module._last_failure_time = None
    try:
        yield
    finally:
        redis_client_module._client = saved_client
        redis_client_module._last_failure_time = saved_failure


def _redis_client_with_pool():
    """Keep real constructor options while mocking network operations."""
    actual = redis.Redis.from_url(
        settings.redis_url.get_secret_value(),
        socket_timeout=2.0,
        socket_connect_timeout=2.0,
        retry=Retry(NoBackoff(), 0),
        retry_on_timeout=False,
    )
    double = create_autospec(actual, spec_set=True)
    double.connection_pool = actual.connection_pool
    return double


class TestRedisClientLifecycle:
    """`get_redis()` control flow: lazy init, caching, and failure cooldown."""

    def test_get_redis_initializes_pings_and_caches(self, monkeypatch):
        """Initialize and ping Redis once, reusing the client on subsequent calls."""
        monkeypatch.setattr(settings, "redis_enabled", True)
        fake_client = _redis_client_with_pool()
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
            assert from_url.call_count == 1

    def test_get_redis_low_uptime_is_not_a_spurious_cooldown(self, monkeypatch):
        """Allow first Redis initialization during low monotonic uptime."""
        monkeypatch.setattr(settings, "redis_enabled", True)
        monkeypatch.setattr("app.services.redis_client.time.monotonic", lambda: 5.0)
        assert redis_client_module._last_failure_time is None
        fake_client = _redis_client_with_pool()
        with patch(
            "app.services.redis_client.redis.Redis.from_url",
            autospec=True,
            return_value=fake_client,
        ):
            assert redis_client_module.get_redis() is fake_client

    def test_get_redis_failure_cooldown_then_recovery_resets_sentinel(self, monkeypatch):
        """Suppress Redis retries for 30 seconds after failure and clear the sentinel on recovery."""
        monkeypatch.setattr(settings, "redis_enabled", True)
        now = {"t": 100.0}
        monkeypatch.setattr("app.services.redis_client.time.monotonic", lambda: now["t"])
        fake_client = _redis_client_with_pool()
        with patch(
            "app.services.redis_client.redis.Redis.from_url",
            autospec=True,
            side_effect=[redis.RedisError("connection refused"), fake_client],
        ) as from_url:
            assert redis_client_module.get_redis() is None
            assert redis_client_module._last_failure_time == 100.0
            assert from_url.call_count == 1

            now["t"] = 110.0
            assert redis_client_module.get_redis() is None
            assert from_url.call_count == 1

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
        """Start a reconnecting subscriber when Redis is enabled but initially unavailable."""
        monkeypatch.setattr(settings, "redis_enabled", True)
        with patch("app.services.cache.get_redis", autospec=True, return_value=None):
            cache = CatalogueStatsCache(
                MagicMock(name="pool"),
                policy_fingerprint=_POLICY_FINGERPRINT,
                source_names=("archive",),
            )
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
        """Skip subscriber creation when Redis or subscriptions are disabled."""
        monkeypatch.setattr(settings, "redis_enabled", redis_enabled)
        cache = CatalogueStatsCache(
            MagicMock(name="pool"),
            policy_fingerprint=_POLICY_FINGERPRINT,
            source_names=("archive",),
            subscribe=subscribe,
        )
        assert cache._subscriber_thread is None


class TestSubscriberListenLoop:
    """The invalidation subscriber's reconnect loop."""

    def test_listen_loop_closes_each_pubsub_across_reconnect_cycles(self, monkeypatch):
        """Close each pubsub before creating its replacement on reconnect."""
        monkeypatch.setattr(settings, "redis_enabled", False)
        cache = CatalogueStatsCache(
            MagicMock(name="pool"),
            policy_fingerprint=_POLICY_FINGERPRINT,
            source_names=("archive",),
        )

        created: list[MagicMock] = []
        first_closed_before_second_created: list[bool] = []

        def make_pubsub():
            """Create failing pubsubs, recording closure order and stopping after the second."""
            if len(created) == 1:
                # Record whether cycle 1's pubsub was already closed when the
                # reconnect creates cycle 2's — pins the finally-inside-loop.
                first_closed_before_second_created.append(created[0].close.called)
            ps = create_autospec(redis.client.PubSub, instance=True, spec_set=True)
            ps.get_message.side_effect = redis.ConnectionError("wire dropped")
            created.append(ps)
            if len(created) >= 2:
                cache._stop_event.set()
            return ps

        fake_redis = create_autospec(redis.Redis, instance=True, spec_set=True)
        fake_redis.pubsub.side_effect = make_pubsub

        with patch("app.services.cache.get_redis", autospec=True, return_value=fake_redis):
            cache._listen_loop()

        assert len(created) == 2
        created[0].close.assert_called_once()
        created[1].close.assert_called_once()
        assert first_closed_before_second_created == [True]


class TestInvalidationPublishing:
    """invalidate_cache clears local state and publishes cross-worker."""

    def test_invalidate_cache_publishes_on_invalidation_channel(self, monkeypatch):
        """invalidate_cache publishes to the shared channel so other
        workers' subscriber loops drop their local caches too."""
        monkeypatch.setattr(settings, "redis_enabled", False)
        cache = CatalogueStatsCache(
            MagicMock(name="pool"),
            policy_fingerprint=_POLICY_FINGERPRINT,
            source_names=("archive",),
        )
        fake_redis = create_autospec(redis.Redis, instance=True, spec_set=True)
        with patch("app.services.cache.get_redis", autospec=True, return_value=fake_redis):
            cache.invalidate_cache()
        fake_redis.publish.assert_called_once_with(_INVALIDATION_CHANNEL, "1")

    def test_publish_only_mode_still_invalidates_and_publishes(self, monkeypatch):
        """Invalidate local state and publish in subscribe=False mode."""
        monkeypatch.setattr(settings, "redis_enabled", True)
        cache = CatalogueStatsCache(
            MagicMock(name="pool"),
            policy_fingerprint=_POLICY_FINGERPRINT,
            source_names=("archive",),
            subscribe=False,
        )
        cache._freshness = (None, 0.0)
        generation_before = cache._generation
        fake_redis = create_autospec(redis.Redis, instance=True, spec_set=True)
        with patch("app.services.cache.get_redis", autospec=True, return_value=fake_redis):
            cache.invalidate_cache()
        fake_redis.publish.assert_called_once_with(_INVALIDATION_CHANNEL, "1")
        assert cache._generation == generation_before + 1
        assert cache._freshness is None


class TestSubscriberShutdown:
    """stop() must be safe to call regardless of subscriber mode."""

    def test_stop_is_safe_no_op_in_publish_only_mode(self, monkeypatch, caplog):
        """Stop safely without warning when no subscriber thread was started."""
        monkeypatch.setattr(settings, "redis_enabled", True)
        cache = CatalogueStatsCache(
            MagicMock(name="pool"),
            policy_fingerprint=_POLICY_FINGERPRINT,
            source_names=("archive",),
            subscribe=False,
        )
        assert cache._subscriber_thread is None

        with caplog.at_level(logging.WARNING, logger="app.services.cache"):
            cache.stop()

        assert cache._stop_event.is_set()
        assert not any("did not exit cleanly" in rec.getMessage() for rec in caplog.records)

    def test_stop_warns_when_subscriber_thread_does_not_exit_in_time(self, caplog):
        """Warn when the subscriber remains alive after the join timeout."""
        cache = CatalogueStatsCache.__new__(CatalogueStatsCache)
        cache._stop_event = MagicMock()
        stuck_thread = MagicMock()
        stuck_thread.is_alive.return_value = True
        cache._subscriber_thread = stuck_thread

        with caplog.at_level(logging.WARNING, logger="app.services.cache"):
            cache.stop()

        stuck_thread.join.assert_called_once_with(timeout=5.0)
        assert any("did not exit cleanly" in rec.getMessage() for rec in caplog.records)


class TestCatalogueStatsSourceSelection:
    """Source-selection errors cannot start a cache subscriber."""

    @pytest.mark.parametrize(
        "source_names",
        [(), ("archive_alpha", "archive_alpha")],
        ids=["empty", "duplicate-name"],
    )
    def test_invalid_source_sets_fail_before_subscriber_start(self, source_names):
        """Invalid source sets fail before subscriber start."""
        pool = MagicMock(name="pool")
        with (
            patch.object(
                CatalogueStatsCache, "_start_subscriber", autospec=True
            ) as start_subscriber,
            pytest.raises(ValueError),
        ):
            CatalogueStatsCache(
                pool, policy_fingerprint=_POLICY_FINGERPRINT, source_names=source_names
            )

        start_subscriber.assert_not_called()
        pool.connection.assert_not_called()


class TestGlobalStatsCache:
    """Only freshness is cached; every public total comes from a live query."""

    async def test_freshness_is_cached_until_invalidated_with_live_totals(
        self, monkeypatch, guarded_cache_reads
    ):
        """Freeze source selection and freshness while totals change on each read."""
        monkeypatch.setattr(settings, "redis_enabled", False)

        pool = MagicMock(name="pool")
        source_names = ["archive_alpha", "archive_beta"]
        cache = CatalogueStatsCache(
            pool, policy_fingerprint=_POLICY_FINGERPRINT, source_names=source_names
        )
        source_names.append("later_archive")

        rebuilt_at = datetime(2026, 10, 18, tzinfo=UTC)
        fetch_freshness = create_autospec(_real_get_last_full_rebuild_date, return_value=rebuilt_at)
        fetch_count = create_autospec(_real_get_total_dataset_count, side_effect=[42, 41, 43, 44])
        monkeypatch.setattr("app.services.cache.get_last_full_rebuild_date", fetch_freshness)
        monkeypatch.setattr("app.services.cache.get_total_dataset_count", fetch_count)

        assert await cache.get_global_stats() == GlobalStats(42, rebuilt_at)
        assert await cache.get_global_stats() == GlobalStats(41, rebuilt_at)
        assert await cache.get_total_datasets() == 43
        assert await cache.get_last_full_rebuild() == rebuilt_at
        fetch_freshness.assert_awaited_once_with(
            guarded_cache_reads.connection_for(pool),
            source_names=("archive_alpha", "archive_beta"),
        )

        cache.invalidate_cache()

        assert await cache.get_global_stats() == GlobalStats(44, rebuilt_at)
        assert fetch_freshness.await_count == 2
        assert fetch_freshness.await_args.kwargs == {
            "source_names": ("archive_alpha", "archive_beta")
        }
        assert fetch_count.await_count == 4
        assert all(
            call.args == (guarded_cache_reads.connection_for(pool),)
            for call in fetch_count.await_args_list
        )

    @pytest.mark.parametrize("redis_enabled", [False, True], ids=["disabled", "missed-message"])
    async def test_public_totals_change_on_both_workers_without_invalidation(
        self, monkeypatch, redis_enabled
    ):
        """A hidden or restored row changes totals despite stale caches on both workers."""
        monkeypatch.setattr(settings, "redis_enabled", redis_enabled)
        pool = MagicMock(name="pool")
        workers = [
            CatalogueStatsCache(
                pool,
                policy_fingerprint=_POLICY_FINGERPRINT,
                source_names=("archive",),
                subscribe=False,
            )
            for _ in range(2)
        ]
        rebuilt_at = datetime(2026, 10, 18, tzinfo=UTC)
        visible_count = 2

        async def current_count(_pool):
            """Return the current visible count without caching it."""
            return visible_count

        fetch_freshness = create_autospec(_real_get_last_full_rebuild_date, return_value=rebuilt_at)
        fetch_count = create_autospec(_real_get_total_dataset_count, side_effect=current_count)
        monkeypatch.setattr(cache_module, "get_last_full_rebuild_date", fetch_freshness)
        monkeypatch.setattr(cache_module, "get_total_dataset_count", fetch_count)

        for worker in workers:
            assert await worker.get_global_stats() == GlobalStats(2, rebuilt_at)

        visible_count = 1
        for worker in workers:
            assert await worker.get_global_stats() == GlobalStats(1, rebuilt_at)
            assert await worker.get_total_datasets() == 1

        visible_count = 2
        for worker in workers:
            assert await worker.get_global_stats() == GlobalStats(2, rebuilt_at)
            assert await worker.get_total_datasets() == 2

        assert fetch_freshness.await_count == 2
        for worker in workers:
            assert worker._freshness is not None
            assert worker._freshness[0] == rebuilt_at
        assert fetch_count.await_count == 10

    @pytest.mark.parametrize("method_name", ["get_global_stats", "get_total_datasets"])
    async def test_live_count_failure_never_returns_cached_total(
        self, monkeypatch, method_name, guarded_cache_reads
    ):
        """A failed live query propagates even when freshness is already cached."""
        cache = CatalogueStatsCache(
            MagicMock(name="pool"),
            policy_fingerprint=_POLICY_FINGERPRINT,
            source_names=("archive",),
            subscribe=False,
        )
        fetch_freshness = create_autospec(_real_get_last_full_rebuild_date, return_value=None)
        monkeypatch.setattr(cache_module, "get_last_full_rebuild_date", fetch_freshness)
        await cache.get_last_full_rebuild()
        fetch_count = create_autospec(
            _real_get_total_dataset_count, side_effect=RuntimeError("count query failed")
        )
        monkeypatch.setattr(cache_module, "get_total_dataset_count", fetch_count)

        with pytest.raises(RuntimeError, match="count query failed"):
            await getattr(cache, method_name)()

        fetch_count.assert_awaited_once_with(guarded_cache_reads.connection_for(cache._pool))
        fetch_freshness.assert_awaited_once()

    async def test_public_count_is_read_after_freshness_lookup(
        self, monkeypatch, guarded_cache_reads
    ):
        """A hide committed while freshness loads is reflected by the later count read."""
        cache = CatalogueStatsCache(
            MagicMock(name="pool"),
            policy_fingerprint=_POLICY_FINGERPRINT,
            source_names=("archive",),
            subscribe=False,
        )
        freshness_started = asyncio.Event()
        release_freshness = asyncio.Event()
        visible_count = 2

        async def slow_freshness(*_args, **_kwargs):
            """Signal freshness lookup and wait until the test releases it."""
            freshness_started.set()
            await release_freshness.wait()

        async def current_count(_pool):
            """Return the current visible count without caching it."""
            return visible_count

        fetch_freshness = create_autospec(
            _real_get_last_full_rebuild_date, side_effect=slow_freshness
        )
        fetch_count = create_autospec(_real_get_total_dataset_count, side_effect=current_count)
        monkeypatch.setattr(cache_module, "get_last_full_rebuild_date", fetch_freshness)
        monkeypatch.setattr(cache_module, "get_total_dataset_count", fetch_count)

        reader = asyncio.create_task(cache.get_global_stats())
        try:
            await asyncio.wait_for(freshness_started.wait(), timeout=1)
            fetch_count.assert_not_awaited()
            visible_count = 1
            release_freshness.set()
            assert await asyncio.wait_for(reader, timeout=1) == GlobalStats(1, None)
            fetch_count.assert_awaited_once_with(guarded_cache_reads.connection_for(cache._pool))
        finally:
            release_freshness.set()
            reader.cancel()
            await asyncio.gather(reader, return_exceptions=True)


class TestConcurrentFreshnessFill:
    """Deterministic cache-fill concurrency, cancellation, and invalidation
    checks through guarded CatalogueStatsCache public reads."""

    @pytest.fixture
    def cache(self):
        """Return a freshness cache for archive without starting a subscriber thread."""
        return CatalogueStatsCache(
            object(),
            policy_fingerprint=_POLICY_FINGERPRINT,
            source_names=("archive",),
            subscribe=False,
        )

    async def test_concurrent_cache_misses_share_one_fill(self, cache, monkeypatch):
        """Concurrent cache misses share one fill."""
        started = asyncio.Event()
        release = asyncio.Event()

        async def slow(*_args, **_kwargs):
            """Signal the fill start and wait until the test releases it."""
            started.set()
            await release.wait()

        fetch_freshness = create_autospec(_real_get_last_full_rebuild_date, side_effect=slow)
        monkeypatch.setattr(cache_module, "get_last_full_rebuild_date", fetch_freshness)

        async def read():
            """Return the cached rebuild timestamp for this reader."""
            return await cache.get_last_full_rebuild()

        tasks = [asyncio.create_task(read()) for _ in range(25)]
        try:
            await asyncio.wait_for(started.wait(), timeout=1)
            await asyncio.sleep(0)
            assert fetch_freshness.await_count == 1
            release.set()
            values = await asyncio.wait_for(asyncio.gather(*tasks), timeout=1)
            assert all(value == values[0] for value in values)
            fetch_freshness.assert_awaited_once()
            assert await read() == values[0]
            fetch_freshness.assert_awaited_once()
        finally:
            release.set()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def test_failed_fill_releases_lock_for_next_reader(self, cache, monkeypatch):
        """Failed fill releases lock for next reader."""
        fetch_freshness = create_autospec(
            _real_get_last_full_rebuild_date,
            side_effect=[RuntimeError("query failed"), None],
        )
        monkeypatch.setattr(cache_module, "get_last_full_rebuild_date", fetch_freshness)

        async def read():
            """Return the cached rebuild timestamp for this reader."""
            return await cache.get_last_full_rebuild()

        with pytest.raises(RuntimeError, match="query failed"):
            await read()
        result = await asyncio.wait_for(read(), timeout=1)
        assert result is None
        assert fetch_freshness.await_count == 2

    async def test_cancelled_filler_does_not_strand_waiter(self, cache, monkeypatch):
        """Cancelled filler does not strand waiter."""
        started = asyncio.Event()
        never = asyncio.Event()
        calls = 0

        async def fetch_freshness_impl(*_args, **_kwargs):
            """Count fills and block only the first until it is cancelled."""
            nonlocal calls
            calls += 1
            if calls == 1:
                started.set()
                await never.wait()

        fetch_freshness = create_autospec(
            _real_get_last_full_rebuild_date, side_effect=fetch_freshness_impl
        )
        monkeypatch.setattr(cache_module, "get_last_full_rebuild_date", fetch_freshness)

        async def read():
            """Return the cached rebuild timestamp for this reader."""
            return await cache.get_last_full_rebuild()

        leader = asyncio.create_task(read())
        waiter = None
        try:
            await asyncio.wait_for(started.wait(), timeout=1)
            waiter = asyncio.create_task(read())
            await asyncio.sleep(0)
            leader.cancel()
            with pytest.raises(asyncio.CancelledError):
                await leader
            assert await asyncio.wait_for(waiter, timeout=1) is None
            assert calls == 2
        finally:
            leader.cancel()
            if waiter is not None:
                waiter.cancel()
            await asyncio.gather(
                leader, *([waiter] if waiter is not None else []), return_exceptions=True
            )

    async def test_cross_thread_invalidation_during_fill_is_not_cached(self, cache, monkeypatch):
        """Cross thread invalidation during fill is not cached."""
        calls = 0

        async def fetch_freshness_impl(*_args, **_kwargs):
            """Invalidate on another thread during the first fill and return a distinct timestamp
            per call.
            """
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
            return datetime(2026, 10, 18, tzinfo=UTC) + timedelta(seconds=calls)

        fetch_freshness = create_autospec(
            _real_get_last_full_rebuild_date, side_effect=fetch_freshness_impl
        )
        monkeypatch.setattr(cache_module, "get_last_full_rebuild_date", fetch_freshness)

        async def read():
            """Return the cached rebuild timestamp for this reader."""
            return await cache.get_last_full_rebuild()

        old = await read()
        fresh = await read()
        assert old != fresh
        assert await read() == fresh
        assert calls == 2


@pytest.mark.parametrize("rebuilt_at", [None, datetime(2026, 10, 18, tzinfo=UTC)])
@pytest.mark.parametrize(
    "method", ["get_global_stats", "get_last_full_rebuild", "get_total_datasets"]
)
async def test_real_query_paths_only_count_catalogue_rows_for_live_totals(
    rebuilt_at, method, guarded_cache_reads
):
    """Exercise real dataset-service SQL so a combined-query regression cannot hide in a mock."""
    statements = []
    visible_count = 7
    row = None
    cursor = make_async_cursor()

    async def execute(statement, params=None):
        """Capture SQL and select fake count/freshness rows matching the queried relations."""
        nonlocal row
        text = statement.as_string()
        statements.append(text)
        catalogue = "catalogue_discovery" in text
        freshness = "sync_status" in text
        if catalogue and freshness:
            row = (visible_count, rebuilt_at)
        elif catalogue:
            row = (visible_count,)
        else:
            assert freshness, text
            assert params == (["archive"],)
            row = (rebuilt_at,)

    cursor.execute.side_effect = execute
    cursor.fetchone.side_effect = lambda: row
    pool = MagicMock(name="pool")
    cache = CatalogueStatsCache(
        pool, policy_fingerprint=_POLICY_FINGERPRINT, source_names=("archive",), subscribe=False
    )
    with patch.object(
        datasets, "get_catalogue_cursor", autospec=True, return_value=FakeCursorCtx(cursor)
    ) as scope:
        first = await getattr(cache, method)()
        visible_count = 8
        second = await getattr(cache, method)()

    if method == "get_global_stats":
        assert (first, second) == (GlobalStats(7, rebuilt_at), GlobalStats(8, rebuilt_at))
    elif method == "get_last_full_rebuild":
        assert first == second == rebuilt_at
    else:
        assert (first, second) == (7, 8)
    assert sum("catalogue_discovery" in query for query in statements) == (
        0 if method == "get_last_full_rebuild" else 2
    )
    assert sum("sync_status" in query for query in statements) == (
        0 if method == "get_total_datasets" else 1
    )
    assert all(
        call.args == (guarded_cache_reads.connection_for(pool), "public")
        for call in scope.call_args_list
    )


@pytest.mark.parametrize("initial", [None, datetime(2026, 10, 18, tzinfo=UTC)])
async def test_freshness_none_and_timestamps_are_cached_until_ttl_expiry(
    monkeypatch, initial, guarded_cache_reads
):
    """The entry's outer tuple distinguishes unknown freshness from an unfilled cache."""
    updated = datetime(2026, 10, 19, tzinfo=UTC)
    fetch = create_autospec(_real_get_last_full_rebuild_date, side_effect=[initial, updated])
    monkeypatch.setattr(cache_module, "get_last_full_rebuild_date", fetch)
    cache = CatalogueStatsCache(
        MagicMock(name="pool"),
        policy_fingerprint=_POLICY_FINGERPRINT,
        source_names=("archive",),
        subscribe=False,
    )
    assert await cache.get_last_full_rebuild() == initial
    assert await cache.get_last_full_rebuild() == initial
    fetch.assert_awaited_once_with(
        guarded_cache_reads.connection_for(cache._pool), source_names=("archive",)
    )
    assert cache._freshness is not None
    with cache._lock:
        cache._freshness = (
            initial,
            cache_module.time.monotonic() - cache_module._STATS_CACHE_TTL_SECONDS - 1,
        )
    assert await cache.get_last_full_rebuild() == updated
    assert await cache.get_last_full_rebuild() == updated
    assert fetch.await_count == 2
