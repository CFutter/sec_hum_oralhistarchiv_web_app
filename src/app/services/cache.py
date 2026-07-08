"""In-memory cache for search facets (keywords, languages, access levels).

Avoids a database round-trip on every search page load. The cache is
refreshed by the background scheduler after each sync and lazily
initialized on first access.
"""

import logging
import threading
import time

import redis

from psycopg_pool import AsyncConnectionPool

from .access_tiers import AccessTier
from .datasets import get_facets
from .redis_client import get_redis

from config import settings

logger = logging.getLogger(__name__)

_INVALIDATION_CHANNEL = "facet_cache:invalidate"
_RECONNECT_BACKOFF_MAX = 60.0  # seconds
_CACHE_TTL_SECONDS = 3600  # 1 hour

class FacetCache:
    """Thread-safe facet cache with cross-worker invalidation via Redis pub/sub.
    
    Includes a TTL safety net: even if pub/sub invalidations are missed,
    the cache is rebuilt at least every _CACHE_TTL_SECONDS (1 hour).
    """

    def __init__(self, pool: AsyncConnectionPool):
        self._pool = pool
        self._cache: dict[str, dict[str, list[str]]] = {}  
        self._cache_built_at: float | None = None
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._subscriber_thread: threading.Thread | None = None
        self._start_subscriber()

    def _listen_loop(self) -> None:
        """Subscribe to invalidations and self-heal on connection errors.
        
        Any exception (Redis outage, broken connection, malformed message)
        is caught and triggers a reconnect with exponential backoff.
        The thread exits only on explicit shutdown via stop().
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
                logger.info("FacetCache subscribed to %s", _INVALIDATION_CHANNEL)
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
                logger.warning("FacetCache subscriber lost Redis connection: %s. Reconnecting in %.1fs.", e, backoff)
            except Exception:
                logger.exception("FacetCache subscriber error (non-connection). Reconnecting in %.1fs.", backoff)
            finally:
                if pubsub is not None:
                    try:
                        pubsub.close()
                    except Exception:
                        logger.debug("Error closing pubsub during cleanup (ignoring)", exc_info=True)

            self._stop_event.wait(timeout=backoff)
            backoff = min(backoff * 2, _RECONNECT_BACKOFF_MAX)

        logger.info("FacetCache subscriber thread exiting cleanly")

    def _start_subscriber(self) -> None:
        """Start the background subscriber thread.
        
        No-op when Redis is not configured — the cache operates in
        local-only mode (invalidations from other workers are not
        received, but a single-worker dev setup works fine).
        """
        if not settings.redis_enabled:
            return

        t = threading.Thread(
            target=self._listen_loop,
            daemon=True,
            name="facet-cache-sub",
        )
        t.start()
        self._subscriber_thread = t


    
    def _is_stale(self) -> bool:
        """Cache is stale if empty or older than CACHE_TTL_SECONDS."""
        if not self._cache:
            return True
        if self._cache_built_at is None:
            return True
        return time.time() - self._cache_built_at > _CACHE_TTL_SECONDS


    async def get_cached_facets(self, user_tier: AccessTier) -> dict[str, list[str]]:
        """Return cached facets for the given tier, rebuilding if stale or missing.

        Facets are tier-dependent: a public user must not see keywords or
        languages that only occur in datasets above their visibility tier.
        The cache holds one entry per tier (at most three), all sharing a
        single TTL/invalidation lifecycle since they derive from the same
        table. A tier's entry is computed lazily on first request.
        """
        with self._lock:
            if self._is_stale():
                self._cache = {}
                self._cache_built_at = time.time()
            cached = self._cache.get(user_tier)
        if cached is not None:
            return cached

        facets = await get_facets(self._pool, user_tier)

        with self._lock:
            return self._cache.setdefault(user_tier, facets)

    def invalidate_cache(self) -> None:
        """Clear local cache and publish invalidation to other workers."""
        with self._lock:
            self._cache = {}
            self._cache_built_at = None
        r = get_redis()
        if r is not None:
            try:
                r.publish(_INVALIDATION_CHANNEL, "1")
            except Exception as e:
                logger.warning("Failed to publish facet invalidation: %s", e)

    def _on_invalidation_message(self) -> None:
        """Internal helper called when an invalidation message arrives via pub/sub."""
        with self._lock:
            self._cache = {}
            self._cache_built_at = None
        logger.debug("FacetCache invalidated by external signal")

    def stop(self) -> None:
        """Stop the subscriber thread (called on application shutdown).
        
        Sets the stop event and waits up to 5s for the thread to exit.
        """
        self._stop_event.set()
        if self._subscriber_thread is not None and self._subscriber_thread.is_alive():
            self._subscriber_thread.join(timeout=5.0)
            if self._subscriber_thread.is_alive():
                logger.warning("FacetCache subscriber thread did not exit cleanly")