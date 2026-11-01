"""Live catalogue totals with cached selected-source rebuild freshness.

Public dataset totals are always queried directly from PostgreSQL so local
withdrawals do not depend on cross-worker cache invalidation. Rebuild
freshness caches only the selected sources' oldest rebuild timestamp.
Tier-sensitive facet suggestions are also queried live by their owning
dataset service.
"""

import asyncio
import logging
import threading
import time
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from datetime import datetime
from typing import NamedTuple

import redis
from psycopg import AsyncConnection
from psycopg_pool import AsyncConnectionPool

from config import settings

from .datasets import get_last_full_rebuild_date, get_total_dataset_count
from .db import get_db_cursor
from .redis_client import get_redis
from .search_projection import guard_catalogue_policy_cur
from .sync_state import _validated_source_names

logger = logging.getLogger(__name__)

# Preserve this channel across mixed-version web/scheduler deployments.
_INVALIDATION_CHANNEL = "facet_cache:invalidate"
_RECONNECT_BACKOFF_MAX = 60.0  # seconds
_STATS_CACHE_TTL_SECONDS = 3600
_POLICY_FINGERPRINT_LENGTH = 64


def _validated_fingerprint(value: str) -> str:
    """Return a 64-character lowercase hexadecimal fingerprint or raise ValueError."""
    if (
        not isinstance(value, str)
        or len(value) != _POLICY_FINGERPRINT_LENGTH
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ValueError("Catalogue policy fingerprint must be 64 lowercase hexadecimal characters")
    return value


class GlobalStats(NamedTuple):
    """Catalogue count and oldest selected-source rebuild, or None if incomplete.

    Public cache methods supply a live count and cached freshness; those
    values need not come from the same database snapshot.
    """

    total_datasets: int
    last_full_rebuild: datetime | None


class CatalogueStatsCache:
    """Return live totals and cache rebuild freshness for one hour.

    Async reads must share one event loop; invalidation is thread-safe.
    Concurrent freshness fills coalesce. Invalidation prevents caching an
    in-flight freshness result but does not prevent returning that timestamp
    to its waiting callers. Public totals bypass that snapshot on every read,
    including when Redis is disabled or a worker misses an invalidation.
    Every public read first guards its policy fingerprint on the same database
    connection used for live queries, including when freshness is already warm.
    """

    def __init__(
        self,
        pool: AsyncConnectionPool,
        *,
        source_names: Sequence[str],
        policy_fingerprint: str,
        subscribe: bool = True,
    ) -> None:
        """Snapshot a valid source scope before optionally starting the Redis subscriber."""
        self._source_names = _validated_source_names(source_names)
        self._policy_fingerprint = _validated_fingerprint(policy_fingerprint)
        self._pool = pool
        self._subscribe = subscribe
        self._freshness: tuple[datetime | None, float] | None = None
        self._generation = 0
        self._lock = threading.Lock()
        # One application event loop owns fills; the subscriber only invalidates.
        self._freshness_fill_lock = asyncio.Lock()
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

    @asynccontextmanager
    async def _read_scope(self) -> AsyncIterator[tuple[AsyncConnection, tuple[str, ...], int]]:
        """Hold the policy guard through both cached and live public statistics."""
        with self._lock:
            source_names = self._source_names
            fingerprint = self._policy_fingerprint
            generation = self._generation
        async with get_db_cursor(self._pool) as cursor:
            await guard_catalogue_policy_cur(cursor, fingerprint)
            yield cursor.connection, source_names, generation

    async def _get_freshness(
        self, connection: AsyncConnection, *, source_names: tuple[str, ...], generation: int
    ) -> datetime | None:
        """Cache only rebuild freshness, including a valid unknown (None) result."""
        with self._lock:
            entry = self._freshness
            if self._generation == generation and entry is not None and self._fresh(entry[1]):
                return entry[0]

        async with self._freshness_fill_lock:
            with self._lock:
                entry = self._freshness
                if self._generation == generation and entry is not None and self._fresh(entry[1]):
                    return entry[0]

            last_full_rebuild = await get_last_full_rebuild_date(
                connection,
                source_names=source_names,
            )
            with self._lock:
                if self._generation == generation:
                    self._freshness = (last_full_rebuild, time.monotonic())
            return last_full_rebuild

    def replace_source_names(self, source_names: Sequence[str], *, policy_fingerprint: str) -> None:
        """Publish a validated scope and discard freshness from the previous selection.

        In-flight readers can finish with their captured scope, but their result
        cannot repopulate this cache after replacement. The subscriber is retained;
        selection changes are local and do not broadcast to other app instances.
        """
        names = _validated_source_names(source_names)
        fingerprint = _validated_fingerprint(policy_fingerprint)
        with self._lock:
            self._source_names = names
            self._policy_fingerprint = fingerprint
            self._freshness = None
            self._generation += 1

    async def get_global_stats(self) -> GlobalStats:
        """Return a live public count with independently cached rebuild freshness.

        Read the count after the freshness lookup. A completed hide or restore
        is reflected by this query without Redis invalidation or a restart.
        Database failures propagate rather than returning a cached count.
        """
        async with self._read_scope() as (connection, names, generation):
            last_full_rebuild = await self._get_freshness(
                connection, source_names=names, generation=generation
            )
            total_datasets = await get_total_dataset_count(connection)
        return GlobalStats(total_datasets, last_full_rebuild)

    async def get_total_datasets(self) -> int:
        """Return the live public dataset count; never fall back to cached totals."""
        async with self._read_scope() as (connection, _names, _generation):
            return await get_total_dataset_count(connection)

    async def get_last_full_rebuild(self) -> datetime | None:
        """Return the oldest selected-source UTC rebuild, or None if incomplete."""
        async with self._read_scope() as (connection, names, generation):
            return await self._get_freshness(connection, source_names=names, generation=generation)

    def invalidate_cache(self) -> None:
        """Clear local rebuild freshness and notify other web workers."""
        with self._lock:
            self._freshness = None
            self._generation += 1

        redis_client = get_redis()
        if redis_client is not None:
            try:
                redis_client.publish(_INVALIDATION_CHANNEL, "1")
            except Exception as exc:
                logger.warning("Failed to publish statistics-cache invalidation: %s", exc)

    def _on_invalidation_message(self) -> None:
        """Clear rebuild freshness after receiving an external signal."""
        with self._lock:
            self._freshness = None
            self._generation += 1

        logger.debug("CatalogueStatsCache invalidated by external signal")

    def stop(self) -> None:
        """Request subscriber shutdown and wait at most five seconds; log if still alive."""
        self._stop_event.set()
        if self._subscriber_thread is not None and self._subscriber_thread.is_alive():
            self._subscriber_thread.join(timeout=5.0)
            if self._subscriber_thread.is_alive():
                logger.warning("CatalogueStatsCache subscriber thread did not exit cleanly")
