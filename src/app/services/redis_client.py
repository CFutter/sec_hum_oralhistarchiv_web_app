"""Lazy, process-local Redis client for best-effort cache invalidation.

Uses REDIS_ENABLED and REDIS_URL; security rate limiting uses a separate
client. Initial connection failures suppress retries for 30 seconds.
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
    """Return the shared client, or None when disabled or initialization fails.

    Initialization is thread-safe, pings Redis, and uses two-second connect
    and socket timeouts. RedisError and ValueError trigger a 30-second
    cooldown. A cached client is returned without another health check;
    subsequent operation failures do not clear it.
    """
    global _client, _last_failure_time  # noqa: PLW0603 - module-level singleton state is intentional here

    if not settings.redis_enabled:
        return None

    cached = _client
    if cached is not None:
        return cached

    if (
        _last_failure_time is not None
        and time.monotonic() - _last_failure_time < _FAILURE_COOLDOWN_SECONDS
    ):
        return None

    with _client_lock:
        # Re-read under the lock: another thread may have initialized the
        # client between the fast-path check above and acquiring the lock.
        cached = _client
        if cached is not None:
            return cached

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
            _last_failure_time = None
            logger.info("Redis client initialized")
            return _client
        except (redis.RedisError, ValueError) as e:
            logger.error("Redis connection failed: %s", e)  # noqa: TRY400
            _last_failure_time = time.monotonic()
            return None
