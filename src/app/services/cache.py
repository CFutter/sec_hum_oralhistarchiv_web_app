"""In-memory cache for non-sensitive, catalogue-wide statistics.

Caches the total dataset count and last successful full-rebuild timestamp.
Authorization-sensitive tier facets and keyword counts are always queried
directly from PostgreSQL.
"""

import asyncio
import logging
import threading
import time
from datetime import datetime
from typing import NamedTuple

import redis
from psycopg_pool import AsyncConnectionPool

from config import settings

from .datasets import get_global_catalogue_stats
from .redis_client import get_redis

logger = logging.getLogger(__name__)

# Legacy channel name retained so mixed-version web/scheduler deployments
# continue to exchange invalidations.
_INVALIDATION_CHANNEL = "facet_cache:invalidate"
_RECONNECT_BACKOFF_MAX = 60.0  # seconds
_STATS_CACHE_TTL_SECONDS = 3600


class GlobalStats(NamedTuple):
    """Dataset count and UTC full-rebuild time, or None before a rebuild."""

    total_datasets: int
    last_full_rebuild: datetime | None


class CatalogueStatsCache:
    """Cache global statistics for one hour with Redis invalidation.

    Async reads must share one event loop; invalidation is thread-safe.
    Concurrent fills coalesce. Invalidation prevents caching an in-flight
    result but does not prevent returning it to its waiting callers.
    """

    def __init__(self, pool: AsyncConnectionPool, subscribe: bool = True):
        """Store the pool and start a daemon subscriber when Redis and subscribe are enabled."""
        self._pool = pool
        self._subscribe = subscribe
        self._global: tuple[GlobalStats, float] | None = None
        self._generation = 0
        self._lock = threading.Lock()
        # One application event loop owns fills; the subscriber only invalidates.
        self._global_fill_lock = asyncio.Lock()
        self._stop_event = threading.Event()
        self._subscriber_thread: threading.Thread | None = None
        self._start_subscriber()  # last — the thread reads the state above

    def _fresh(self, built_at: float) -> bool:
        """Return whether built_at, in monotonic seconds, is at most one hour old."""
        return time.monotonic() - built_at <= _STATS_CACHE_TTL_SECONDS

    def _listen_loop(self) -> None:
        """Subscribe until stopped, retrying failures with 1-60-second backoff.

        Redis read timeouts continue on the existing subscription; other
        exceptions reconnect after closing the pub/sub client.
        """
        backoff = 1.0
        while not self._stop_event.is_set():
            pubsub = None
            try:
                r = get_redis()
                if r is None:
                    self._stop_event.wait(timeout=backoff)
                    backoff = min(backoff * 2, _RECONNECT_BACKOFF_MAX)
                    continue

                pubsub = r.pubsub()
                pubsub.subscribe(_INVALIDATION_CHANNEL)
                logger.info("CatalogueStatsCache subscribed to %s", _INVALIDATION_CHANNEL)
                backoff = 1.0

                while not self._stop_event.is_set():
                    try:
                        msg = pubsub.get_message(timeout=1.0)
                    except redis.TimeoutError:
                        continue
                    if msg is None:
                        continue
                    if msg["type"] != "message":
                        continue
                    self._on_invalidation_message()

            except redis.ConnectionError as e:
                logger.warning(
                    "CatalogueStatsCache subscriber lost Redis connection: %s. "
                    "Reconnecting in %.1fs.",
                    e,
                    backoff,
                )
            except Exception:
                logger.exception(
                    "CatalogueStatsCache subscriber error (non-connection). Reconnecting in %.1fs.",
                    backoff,
                )
            finally:
                if pubsub is not None:
                    try:
                        pubsub.close()
                    except Exception:
                        logger.debug(
                            "Error closing pubsub during cleanup (ignoring)",
                            exc_info=True,
                        )

            self._stop_event.wait(timeout=backoff)
            backoff = min(backoff * 2, _RECONNECT_BACKOFF_MAX)

        logger.info("CatalogueStatsCache subscriber thread exiting cleanly")

    def _start_subscriber(self) -> None:
        """Start a daemon subscriber unless Redis or subscription is disabled."""
        if not settings.redis_enabled or not self._subscribe:
            return

        t = threading.Thread(
            target=self._listen_loop,
            daemon=True,
            name="catalogue-stats-cache-sub",
        )
        t.start()
        self._subscriber_thread = t

    async def _get_global(self) -> GlobalStats:
        """Coalesce concurrent global fills; never cache an invalidated result."""
        with self._lock:
            entry = self._global
            if entry is not None and self._fresh(entry[1]):
                return entry[0]

        async with self._global_fill_lock:
            with self._lock:
                entry = self._global
                if entry is not None and self._fresh(entry[1]):
                    return entry[0]
                generation = self._generation

            total_datasets, last_full_rebuild = await get_global_catalogue_stats(self._pool)
            stats = GlobalStats(
                total_datasets=total_datasets,
                last_full_rebuild=last_full_rebuild,
            )
            with self._lock:
                if self._generation == generation:
                    self._global = (stats, time.monotonic())
            return stats

    async def get_global_stats(self) -> GlobalStats:
        """Return one internally consistent global-statistics snapshot."""
        return await self._get_global()

    async def get_total_datasets(self) -> int:
        """Return the cached dataset count, querying PostgreSQL on a miss."""
        return (await self._get_global()).total_datasets

    async def get_last_full_rebuild(self) -> datetime | None:
        """Return the cached UTC rebuild time, or None before any completed rebuild."""
        return (await self._get_global()).last_full_rebuild

    def invalidate_cache(self) -> None:
        """Clear local global statistics and notify other web workers."""
        with self._lock:
            self._global = None
            self._generation += 1

        redis_client = get_redis()
        if redis_client is not None:
            try:
                redis_client.publish(_INVALIDATION_CHANNEL, "1")
            except Exception as exc:
                logger.warning("Failed to publish statistics-cache invalidation: %s", exc)

    def _on_invalidation_message(self) -> None:
        """Clear global statistics after receiving an external signal."""
        with self._lock:
            self._global = None
            self._generation += 1

        logger.debug("CatalogueStatsCache invalidated by external signal")

    def stop(self) -> None:
        """Request subscriber shutdown and wait at most five seconds; log if still alive."""
        self._stop_event.set()
        if self._subscriber_thread is not None and self._subscriber_thread.is_alive():
            self._subscriber_thread.join(timeout=5.0)
            if self._subscriber_thread.is_alive():
                logger.warning("CatalogueStatsCache subscriber thread did not exit cleanly")
