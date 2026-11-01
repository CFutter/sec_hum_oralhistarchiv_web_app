"""Lazy, process-local Redis client for best-effort cache invalidation.

Uses REDIS_ENABLED and REDIS_URL; security rate limiting uses a separate
client. Initial connection failures suppress retries for 30 seconds.
"""

import logging
import threading
import time

import redis
from redis.backoff import NoBackoff
from redis.retry import Retry

from config import redis_connection_policy_issues, redis_url_policy_issues, settings

logger = logging.getLogger(__name__)

_client: redis.Redis | None = None
_client_lock = threading.Lock()
_last_failure_time: float | None = None
_FAILURE_COOLDOWN_SECONDS = 30.0


def _create_client() -> redis.Redis:
    """Construct and inspect the client before making any network request."""
    url = settings.redis_url.get_secret_value()
    if redis_url_policy_issues(url, hardened=settings.is_hardened):
        raise ValueError("Redis URL violates the connection policy")
    client = redis.Redis.from_url(
        url,
        decode_responses=True,
        socket_timeout=2.0,
        socket_connect_timeout=2.0,
        retry=Retry(NoBackoff(), 0),
        retry_on_timeout=False,
    )
    pool = client.connection_pool
    if redis_connection_policy_issues(
        {**pool.connection_kwargs, "connection_class": pool.connection_class},
        maximum_timeout=2.0,
    ):
        client.close()
        raise ValueError("Effective Redis connection violates the connection policy")
    return client


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
            client = _create_client()
            client.ping()
            _client = client
            _last_failure_time = None
            logger.info("Redis client initialized")
            return _client
        except (redis.RedisError, ValueError):
            logger.error(  # noqa: TRY400 - dependency exception text may contain credentials
                "Redis connection failed; cache invalidation is temporarily unavailable"
            )
            _last_failure_time = time.monotonic()
            return None
