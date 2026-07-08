"""Shared Redis client for rate limiting and cross-worker cache invalidation.

Lazy-initialized so import-time failures don't crash the app when
Redis is disabled (dev mode). After a connection failure, attempts
are suppressed for a cooldown period to avoid log spam during
Redis outages.
"""
import logging
import threading
import time

import redis

from config import settings

logger = logging.getLogger(__name__)

_client: redis.Redis | None = None
_client_lock = threading.Lock()
_last_failure_time: float | None = None
_FAILURE_COOLDOWN_SECONDS = 30.0


def get_redis() -> redis.Redis | None:
    """Return the shared Redis client, or None if Redis is disabled or unreachable.

    Thread-safe initialization via double-checked locking.
    On failure, suppresses retries for _FAILURE_COOLDOWN_SECONDS to
    prevent log spam during outages.
    """
    global _client, _last_failure_time

    if not settings.redis_enabled:
        return None

    if _client is not None:
        return _client

    if (
        _last_failure_time is not None
        and time.monotonic() - _last_failure_time < _FAILURE_COOLDOWN_SECONDS
    ):
        return None

    with _client_lock:
        if _client is not None:
            return _client

        if (
            _last_failure_time is not None
            and time.monotonic() - _last_failure_time < _FAILURE_COOLDOWN_SECONDS
        ):
            return None

        try:
            client = redis.Redis.from_url(
                settings.redis_url.get_secret_value(),
                decode_responses=True,
                socket_timeout=2.0,
                socket_connect_timeout=2.0,
            )
            client.ping()
            _client = client
            _last_failure_time = None          # reset on success — None, not 0.0
            logger.info("Redis client initialized")
            return _client
        except (redis.RedisError, ValueError) as e:
            logger.error("Redis connection failed: %s", e)
            _last_failure_time = time.monotonic()
            return None