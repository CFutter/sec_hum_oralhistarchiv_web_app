"""Compatibility boundary for the locked SlowAPI/limits/redis dependencies.

Only this module may inspect SlowAPI's private layout or call its request
checker. Upgrades must pass the shape checks AND the memory/Redis behavior
regressions (route overrides, exemptions, default limits and failure policy).
No network work is performed during shape validation.
"""

import inspect
from collections.abc import Callable
from typing import Any, cast

from limits.storage import Storage
from limits.storage.memory import MemoryStorage
from limits.storage.redis import RedisStorage
from limits.strategies import FixedWindowRateLimiter
from redis import Redis
from redis.backoff import NoBackoff
from redis.retry import Retry
from slowapi import Limiter
from starlette.requests import Request

from config import redis_connection_policy_issues

REDIS_OPERATION_TIMEOUT_SECONDS = 0.5
_REDIS_STORAGE_OPTION_KEYS = frozenset(
    {
        "retry",
        "retry_on_timeout",
        "socket_connect_timeout",
        "socket_timeout",
        "wrap_exceptions",
        "counter_capacity",
        "cleanup_batch_size",
    }
)


def core_configuration_issues(
    active_limiter: Limiter,
    *,
    key_func: Callable[..., str],
    enabled: bool,
    key_prefix: str,
) -> list[str]:
    """Return deviations from the required identity, strategy, key, fallback and header policy."""
    issues: list[str] = []
    if active_limiter._key_func is not key_func:
        issues.append("limiter client identity function differs from the reviewed HMAC policy")
    if active_limiter._application_limits:
        issues.append("cross-route application limits are configured outside the edge policy")
    if active_limiter.enabled != enabled:
        issues.append("enabled state differs from RATE_LIMIT_ENABLED")
    if active_limiter._swallow_errors:
        issues.append("storage errors are configured to be swallowed")
    if active_limiter._in_memory_fallback_enabled:
        issues.append("process-local fallback is enabled")
    if active_limiter._headers_enabled:
        issues.append("SlowAPI response-header I/O is enabled")
    if active_limiter._strategy != "fixed-window" or not isinstance(
        active_limiter.limiter, FixedWindowRateLimiter
    ):
        issues.append("limiter strategy is not fixed-window")
    if active_limiter._key_style != "endpoint":
        issues.append("limiter key style is not endpoint")
    if active_limiter._key_prefix != key_prefix:
        issues.append("limiter key prefix differs from the reviewed namespace")
    return issues


def redis_configuration_issues(
    active_limiter: Limiter,
    storage: Storage,
) -> list[str]:
    """Return deviations from Redis storage and the exact timeout/retry/wrapping option contract."""
    issues: list[str] = []
    if not isinstance(storage, RedisStorage):
        issues.append("rate-limit Redis URL did not construct Redis storage")
    if not getattr(storage, "wrap_exceptions", False):
        issues.append("Redis storage exceptions are not wrapped")

    # SlowAPI annotates this boundary as ``dict[str, str]`` even though
    # limits/redis explicitly accepts numeric, boolean and Retry values.
    options = cast(dict[str, Any], active_limiter._storage_options)
    if set(options) != _REDIS_STORAGE_OPTION_KEYS:
        issues.append("Redis storage options differ from the reviewed exact set")
    for option_name in ("socket_connect_timeout", "socket_timeout"):
        option_value = options.get(option_name)
        if (
            isinstance(option_value, bool)
            or not isinstance(option_value, (int, float))
            or not 0 < option_value <= REDIS_OPERATION_TIMEOUT_SECONDS
        ):
            issues.append(f"{option_name} is absent or exceeds 0.5 seconds")
    retry = options.get("retry")
    if (
        not isinstance(retry, Retry)
        or retry.get_retries() != 0
        or not isinstance(retry._backoff, NoBackoff)
    ):
        issues.append("Redis retries are not disabled")
    if options.get("retry_on_timeout") is not False:
        issues.append("Redis retry_on_timeout is not disabled")
    if options.get("wrap_exceptions") is not True:
        issues.append("Redis wrap_exceptions option is not enabled")
    for name, maximum in (("counter_capacity", 20000), ("cleanup_batch_size", 1024)):
        value = options.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
            issues.append(f"{name} is absent or exceeds its supported bound")
    if isinstance(storage, RedisStorage):
        pool = cast(Redis, storage.get_connection()).connection_pool
        issues.extend(
            redis_connection_policy_issues(
                {**pool.connection_kwargs, "connection_class": pool.connection_class},
                maximum_timeout=REDIS_OPERATION_TIMEOUT_SECONDS,
            )
        )
    return issues


def validate_dependency_shape(active_limiter: Limiter) -> None:
    """Raise RuntimeError if the private SlowAPI containers/checker signature are incompatible.

    No network I/O or configuration-value validation occurs.
    """
    required = {
        "_key_func",
        "_application_limits",
        "_swallow_errors",
        "_in_memory_fallback_enabled",
        "_headers_enabled",
        "_strategy",
        "_key_style",
        "_key_prefix",
        "_storage_options",
        "_storage_uri",
        "_exempt_routes",
        "_route_limits",
        "_dynamic_route_limits",
    }
    if not all(hasattr(active_limiter, name) for name in required):
        raise RuntimeError("Incompatible SlowAPI dependency layout")
    if (
        not isinstance(active_limiter._exempt_routes, set)
        or not isinstance(active_limiter._route_limits, dict)
        or not isinstance(active_limiter._dynamic_route_limits, dict)
        or not isinstance(active_limiter._storage_options, dict)
        or not isinstance(active_limiter._application_limits, list)
    ):
        raise RuntimeError("Incompatible SlowAPI dependency containers")  # noqa: TRY004 - startup ABI failure
    try:
        signature = inspect.signature(active_limiter._check_request_limit)
        signature.bind(object(), object(), in_middleware=False)
        parameters = tuple(signature.parameters)
    except (AttributeError, TypeError, ValueError):
        raise RuntimeError("Incompatible SlowAPI request checker") from None
    if parameters != ("request", "endpoint_func", "in_middleware"):
        raise RuntimeError("Incompatible SlowAPI request checker signature")


def configured_storage_uri(active_limiter: Limiter) -> str | None:
    """Return the constructor's URI for exact configuration validation."""
    return active_limiter._storage_uri


def is_memory_storage(storage: Storage) -> bool:
    """Recognize the reviewed process-local development backend."""
    return isinstance(storage, MemoryStorage)


def route_is_exempt(active_limiter: Limiter, handler: Callable[..., Any]) -> bool:
    """Return whether SlowAPI exempted the handler by its module/name decorator identity."""
    return f"{handler.__module__}.{handler.__name__}" in active_limiter._exempt_routes


def check_request_limit(
    active_limiter: Limiter, request: Request, handler: Callable[..., Any]
) -> None:
    """Evaluate endpoint overrides/defaults and update SlowAPI request/limiter state.

    Raise RateLimitExceeded or storage errors on refusal/failure. The bounded
    worker must serialize calls; in_middleware=False includes decorated limits.
    """
    active_limiter._check_request_limit(request, handler, in_middleware=False)
