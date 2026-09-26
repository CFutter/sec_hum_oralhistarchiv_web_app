"""Fail-closed SlowAPI admission before session/database work.

Use dedicated shared Redis in hardened environments; development may
select memory storage. There is no runtime memory fallback. HTTP checks
run in one serialized worker, with bounded queue/admission and 0.5-second
Redis connect/read timeouts, no retries. Evaluation budgets only warn.

GET/HEAD static assets and decorated exemptions bypass checks. Other
requests use endpoint buckets; unmatched paths/methods share one bucket
and skip session lookup. Keys HMAC canonical IPv4 or IPv6 /64 identities
using an import-time SECRET_KEY-derived key. Successful response headers
are disabled; rejected checks capture 429 statistics in the worker.
"""

import hashlib
import hmac
import inspect
import ipaddress
import logging
import secrets
import threading
import time
from collections.abc import Callable
from functools import partial
from typing import Any, cast

from anyio import CapacityLimiter, WouldBlock
from fastapi import FastAPI, Request, Response
from limits.errors import ConcurrentUpdateError, ConfigurationError, StorageError
from limits.storage import Storage
from limits.storage.memory import MemoryStorage
from limits.storage.redis import RedisStorage
from limits.strategies import FixedWindowRateLimiter
from redis.backoff import NoBackoff
from redis.exceptions import (
    AuthenticationError,
    AuthorizationError,
    MaxConnectionsError,
    NoPermissionError,
    OutOfMemoryError,
    RedisError,
    ResponseError,
)
from redis.exceptions import (
    ConnectionError as RedisConnectionError,
)
from redis.exceptions import (
    TimeoutError as RedisTimeoutError,
)
from redis.retry import Retry
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.routing import Match
from starlette.types import ASGIApp

from config import settings

from ..request_utils import get_client_ip, safe_request_path
from ..thread_work import ThreadWorkAdmissionTimeout, run_thread_work
from .security_headers import build_secure_headers

logger = logging.getLogger(__name__)
_storage_lock = threading.Lock()

_DEFAULT_ADMISSION_TIMEOUT_SECONDS = 0.25
_DEFAULT_MAX_OUTSTANDING_CHECKS = 8
_DEFAULT_BUSY_RETRY_AFTER_SECONDS = 1
_DEFAULT_EVALUATION_BUDGET_SECONDS = 1.0
_BACKEND_STARTUP_ADMISSION_TIMEOUT_SECONDS = 1.0
_REDIS_OPERATION_TIMEOUT_SECONDS = 0.5
_BACKEND_PROBE_TTL_SECONDS = 5
_RATE_LIMIT_KEY_PREFIX = "oralhistarchiv-security-v1"
_RATE_LIMIT_CLIENT_ID_CONTEXT = b"oralhistarchiv-rate-limit-client-id-v1"
_REDIS_STORAGE_OPTION_KEYS = frozenset(
    {
        "retry",
        "retry_on_timeout",
        "socket_connect_timeout",
        "socket_timeout",
        "wrap_exceptions",
    }
)

_STATIC_ASSET_PREFIX = "/static/"
_RATE_LIMIT_ROUTE_UNMATCHED_STATE = "rate_limit_route_unmatched"
_RATE_LIMIT_LOG_PATH_STATE = "rate_limit_log_path"
_UNMATCHED_LOG_PATH = "/<unmatched>"
_UNRESOLVED_LOG_PATH = "/<unresolved>"
_RATE_LIMIT_BACKEND_ERRORS = (
    ConfigurationError,
    ConcurrentUpdateError,
    RedisError,
    StorageError,
)

_early_response_secure_headers = build_secure_headers(settings.is_production)

# Redis and its AOF must not contain raw client IP addresses. SECRET_KEY is a
# persistent, high-entropy application key; derive a purpose-specific subkey
# so compromise or reuse of another HMAC output cannot cross protocol domains.
# Rotating SECRET_KEY deliberately creates fresh limiter identities and must be
# coordinated as a non-overlapping web restart (documented in the runbook).
_rate_limit_client_id_key = hmac.new(
    settings.secret_key.get_secret_value().encode("utf-8"),
    _RATE_LIMIT_CLIENT_ID_CONTEXT,
    hashlib.sha256,
).digest()


def get_rate_limit_client_id(request: Request) -> str:
    """Return ip-v2:HMAC for a canonical IPv4 address or IPv6 /64 network.

    Apply trusted-proxy attribution first; mapped IPv6 uses IPv4, scope IDs
    are removed, and invalid addresses share the unknown bucket. SECRET_KEY
    rotation changes all identities.
    """
    client_ip = get_client_ip(request)
    try:
        address = ipaddress.ip_address(client_ip)
        if isinstance(address, ipaddress.IPv6Address):
            address = ipaddress.IPv6Address(address.packed)  # remove scope ID
            if address.ipv4_mapped is not None:
                address = address.ipv4_mapped
            else:
                address = ipaddress.IPv6Network((address, 64), strict=False).network_address
        canonical_identity = str(address)
    except ValueError:
        canonical_identity = "unknown"

    digest = hmac.new(
        _rate_limit_client_id_key,
        canonical_identity.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return f"ip-v2:{digest}"


def _backend_failure_category(error: BaseException) -> tuple[str, str]:
    """Return (bounded category, exception class name),
    unwrapping at most four StorageError causes.
    """
    current = error
    for _ in range(4):
        if not isinstance(current, StorageError):
            break
        cause = current.__cause__
        if cause is None or cause is current:
            break
        current = cause

    if isinstance(current, (OutOfMemoryError, MaxConnectionsError)):
        category = "capacity"
    elif isinstance(current, AuthenticationError):
        category = "authentication"
    elif isinstance(current, (AuthorizationError, NoPermissionError)):
        category = "authorization"
    elif isinstance(current, RedisTimeoutError):
        category = "timeout"
    elif isinstance(current, RedisConnectionError):
        category = "connection"
    elif isinstance(current, ResponseError):
        category = "command"
    elif isinstance(current, ConcurrentUpdateError):
        category = "concurrency"
    elif isinstance(current, ConfigurationError):
        category = "configuration"
    else:
        category = "storage"
    return category, type(current).__name__


def _coarse_unmatched_route_bucket(request: Request) -> None:
    """Serve only as a stable 404/405 bucket identity; invocation raises RuntimeError."""
    raise RuntimeError(f"Rate-limit sentinel was called for {request.method}")


def _is_static_asset_request(request: Request) -> bool:
    """Return whether the reviewed DB-free StaticFiles path is exempt."""
    return request.method.upper() in {"GET", "HEAD"} and _is_static_path(request)


def _is_static_path(request: Request) -> bool:
    """Return whether the path is exactly /static or below /static/."""
    return request.url.path == "/static" or request.url.path.startswith(_STATIC_ASSET_PREFIX)


def _resolve_rate_limit_handler(request: Request) -> tuple[Callable[..., Any], bool, str]:
    """Return (endpoint, unmatched flag, log template) before routing.

    Static mutations and 404/405 requests share the sentinel bucket;
    request.app.routes must expose callable identities for full matches or
    RuntimeError is raised. The eventual router still determines the response.
    """
    # Read-only static traffic was returned by the exact exemption in
    # dispatch. Other methods still match Starlette's Mount as FULL, but are
    # semantically method mismatches; charge the stable sentinel and skip the
    # session lookup before StaticFiles returns its authoritative response.
    if _is_static_path(request):
        return _coarse_unmatched_route_bucket, True, _UNMATCHED_LOG_PATH

    for route in request.app.routes:
        match, child_scope = route.matches(request.scope)
        if match == Match.FULL:
            endpoint = child_scope.get("endpoint", getattr(route, "endpoint", None))
            if (
                callable(endpoint)
                and hasattr(endpoint, "__module__")
                and hasattr(endpoint, "__name__")
            ):
                route_path = getattr(route, "path", None)
                if not isinstance(route_path, str) or not route_path.startswith("/"):
                    route_path = "/<route>"
                return endpoint, False, route_path

            # The only mounted ASGI application is StaticFiles, which is
            # handled by the exact exemption before this resolver. A future
            # unnamed mount might require authentication, so it must fail
            # closed instead of receiving the 404/405 session-skip marker.
            logger.error(
                "Full route has no stable rate-limit endpoint identity",
                extra={"event_type": "rate_limit_endpoint_identity_missing"},
            )
            raise RuntimeError("Full route has no stable rate-limit endpoint identity")

    # Match.PARTIAL (405) and an all-NONE result (404) deliberately share the
    # same stable identity and session-skip behavior.
    return _coarse_unmatched_route_bucket, True, _UNMATCHED_LOG_PATH


def redis_storage_options() -> dict[str, Any]:
    """Return 0.5-second connect/read deadlines, zero retries, and wrapped storage exceptions."""
    return {
        "socket_connect_timeout": _REDIS_OPERATION_TIMEOUT_SECONDS,
        "socket_timeout": _REDIS_OPERATION_TIMEOUT_SECONDS,
        "retry": Retry(NoBackoff(), 0),
        "retry_on_timeout": False,
        "wrap_exceptions": True,
    }


def _build_limiter() -> Limiter:
    """Build an endpoint-keyed fixed-window limiter from settings
    without headers or memory fallback.

    Use configured minute/hour/day defaults and enabled state; unresolved
    storage selects memory. Construction errors propagate.
    """
    storage_uri = settings.rate_limit_storage_uri
    return Limiter(
        key_func=get_rate_limit_client_id,
        default_limits=[
            f"{settings.rate_limit_per_minute}/minute",
            f"{settings.rate_limit_per_hour}/hour",
            f"{settings.rate_limit_per_day}/day",
        ],
        strategy="fixed-window",
        storage_uri=storage_uri or "memory://",
        storage_options=redis_storage_options() if storage_uri is not None else {},
        enabled=settings.rate_limit_enabled,
        headers_enabled=False,
        key_prefix=_RATE_LIMIT_KEY_PREFIX,
        key_style="endpoint",
        in_memory_fallback_enabled=False,
        swallow_errors=False,
    )


limiter = _build_limiter()


def _core_configuration_issues(active_limiter: Limiter) -> list[str]:
    """Return deviations from the required identity, enabled, strategy,
    key, fallback, and header policies.
    """
    issues: list[str] = []
    if active_limiter._key_func is not get_rate_limit_client_id:
        issues.append("limiter client identity function differs from the reviewed HMAC policy")
    if active_limiter._application_limits:
        issues.append("cross-route application limits are configured outside the edge policy")
    if active_limiter.enabled != settings.rate_limit_enabled:
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
    if active_limiter._key_prefix != _RATE_LIMIT_KEY_PREFIX:
        issues.append("limiter key prefix differs from the reviewed namespace")
    return issues


def _redis_configuration_issues(
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
            or not 0 < option_value <= _REDIS_OPERATION_TIMEOUT_SECONDS
        ):
            issues.append(f"{option_name} is absent or exceeds 0.5 seconds")
    retry = options.get("retry")
    if (
        not isinstance(retry, Retry)
        or retry._retries != 0
        or not isinstance(retry._backoff, NoBackoff)
    ):
        issues.append("Redis retries are not disabled")
    if options.get("retry_on_timeout") is not False:
        issues.append("Redis retry_on_timeout is not disabled")
    if options.get("wrap_exceptions") is not True:
        issues.append("Redis wrap_exceptions option is not enabled")
    return issues


def validate_rate_limit_configuration(active_limiter: Limiter = limiter) -> None:
    """Raise RuntimeError for unsafe effective SlowAPI settings, including hidden overrides.

    Require configured storage/identity/strategy/key policy, no swallowed
    errors or fallback, and bounded Redis options. Hardened mode requires
    a configured Redis URI; development alone permits MemoryStorage.
    """
    issues = _core_configuration_issues(active_limiter)
    storage = active_limiter.limiter.storage
    resolved_storage_uri = settings.rate_limit_storage_uri
    expected_storage_uri = resolved_storage_uri or "memory://"
    if active_limiter._storage_uri != expected_storage_uri:
        issues.append("constructed storage URI differs from resolved limiter settings")
    if settings.is_hardened and resolved_storage_uri is None:
        issues.append("hardened environment has no dedicated rate-limit Redis URL")

    if resolved_storage_uri is not None:
        issues.extend(_redis_configuration_issues(active_limiter, storage))
    elif not isinstance(storage, MemoryStorage):
        issues.append("development memory mode constructed unexpected storage")

    if issues:
        raise RuntimeError("Unsafe effective rate-limit configuration: " + "; ".join(issues))


def _probe_rate_limit_backend(storage: Storage) -> bool:
    """Check backend ping, increment/read, five-second expiry, and deletion with a random key.

    Return False for unexpected values; storage errors propagate. After a
    successful increment, always clear and verify removal; residual state
    raises RuntimeError. A lost increment response can leave a TTL-bound key.
    """
    probe_key = f"startup-readiness-{secrets.token_hex(16)}"
    increment_completed = False

    try:
        # RedisStorage.check() deliberately swallows every connection error
        # into False, which would erase the safe failure category needed for
        # operations. Call the pinned client's PING directly so typed failures
        # propagate through the scrubbed startup telemetry below.
        if isinstance(storage, RedisStorage):
            backend_ready = bool(storage.get_connection().ping())
        else:
            backend_ready = storage.check()
        if not backend_ready:
            return False

        value = storage.incr(probe_key, _BACKEND_PROBE_TTL_SECONDS)
        increment_completed = True
        if value != 1 or storage.get(probe_key) != 1:
            return False
        expires_at = storage.get_expiry(probe_key)
        observed_at = time.time()
        return observed_at < expires_at <= observed_at + _BACKEND_PROBE_TTL_SECONDS + 1
    finally:
        if increment_completed:
            storage.clear(probe_key)
            if storage.get(probe_key) != 0:
                raise RuntimeError("Rate-limit backend readiness probe cleanup failed")


async def validate_rate_limit_backend() -> None:
    """Validate configuration, then probe enabled non-memory storage in a bounded worker.

    Raise RuntimeError and log safe categories on probe failure. Disabled
    limiting/development memory skips the probe; cancellation propagates.
    """
    validate_rate_limit_configuration()
    if not settings.rate_limit_enabled or settings.rate_limit_storage_uri is None:
        return

    capacity = CapacityLimiter(1)
    try:
        healthy = await run_thread_work(
            partial(_probe_rate_limit_backend, limiter.limiter.storage),
            capacity,
            admission_timeout_seconds=_BACKEND_STARTUP_ADMISSION_TIMEOUT_SECONDS,
        )
    except (ThreadWorkAdmissionTimeout, *_RATE_LIMIT_BACKEND_ERRORS) as exc:
        category, exception_type = _backend_failure_category(exc)
        logger.critical(
            "Required rate-limit backend failed its startup probe",
            extra={
                "event_type": "rate_limit_startup_probe_failed",
                "backend_failure_category": category,
                "exception_type": exception_type,
            },
        )
        raise RuntimeError("Required rate-limit backend is unavailable") from None
    except Exception as exc:
        logger.critical(
            "Unexpected rate-limit backend startup-probe failure",
            extra={
                "event_type": "rate_limit_startup_probe_failed",
                "backend_failure_category": "unexpected",
                "exception_type": type(exc).__name__,
            },
        )
        raise RuntimeError("Rate-limit backend readiness check failed") from None

    if not healthy:
        logger.critical(
            "Required rate-limit backend failed its startup probe",
            extra={
                "event_type": "rate_limit_startup_probe_failed",
                "backend_failure_category": "storage",
                "exception_type": "ProbeResultInvalid",
            },
        )
        raise RuntimeError("Required rate-limit backend is unavailable")

    logger.info("Required rate-limit backend is ready")


def _evaluate_limits(
    request: Request,
    handler: Callable[..., Any],
    active_limiter: Limiter,
    *,
    evaluation_budget_seconds: float,
) -> RateLimitExceeded | None:
    """Check registered/default limits under the process-wide storage lock.

    Run only in a worker. Return a caught RateLimitExceeded with window
    stats in request.state, or None; storage errors propagate. Mark the
    check complete even on failure and record elapsed seconds. Exceeding
    evaluation_budget_seconds only logs a warning; it does not stop work.
    """
    started_at = time.monotonic()
    try:
        with _storage_lock:
            try:
                active_limiter._check_request_limit(request, handler, False)
            except RateLimitExceeded as exc:
                current = getattr(request.state, "view_rate_limit", None)
                if current is not None:
                    item, identifiers = current
                    request.state.rate_limit_stats = active_limiter.limiter.get_window_stats(
                        item, *identifiers
                    )
                return exc
            finally:
                request.state._rate_limiting_complete = True
        return None
    finally:
        elapsed = time.monotonic() - started_at
        request.state.rate_limit_evaluation_seconds = elapsed
        if elapsed > evaluation_budget_seconds:
            logger.warning(
                "Rate-limit evaluation exceeded its execution budget",
                extra={
                    "event_type": "rate_limit_evaluation_slow",
                    "elapsed_seconds": elapsed,
                    "budget_seconds": evaluation_budget_seconds,
                },
            )


class BoundedRateLimitMiddleware(BaseHTTPMiddleware):
    """Run a bounded number of serialized checks outside the event loop.

    Admission wait and queue size are bounded independently from Redis's
    per-operation socket deadlines. Cancellation does not abandon a running
    worker; the lock also protects shared state across test loops. Storage
    failure is fail-closed: it never falls back to process-local counters.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        admission_timeout_seconds: float = _DEFAULT_ADMISSION_TIMEOUT_SECONDS,
        max_outstanding_checks: int = _DEFAULT_MAX_OUTSTANDING_CHECKS,
        busy_retry_after_seconds: int = _DEFAULT_BUSY_RETRY_AFTER_SECONDS,
        evaluation_budget_seconds: float = _DEFAULT_EVALUATION_BUDGET_SECONDS,
    ) -> None:
        """Configure positive admission/evaluation seconds and positive queue/retry values.

        max_outstanding_checks includes running and waiting requests; invalid
        values raise ValueError. evaluation_budget_seconds is a warning threshold.
        Async capacities are created lazily in the owning event loop.
        """
        super().__init__(app)
        if admission_timeout_seconds <= 0:
            raise ValueError("admission_timeout_seconds must be positive")
        if max_outstanding_checks < 1:
            raise ValueError("max_outstanding_checks must be at least 1")
        if busy_retry_after_seconds < 1:
            raise ValueError("busy_retry_after_seconds must be at least 1")
        if evaluation_budget_seconds <= 0:
            raise ValueError("evaluation_budget_seconds must be positive")

        self._admission_timeout_seconds = admission_timeout_seconds
        self._max_outstanding_checks = max_outstanding_checks
        self._busy_retry_after_seconds = busy_retry_after_seconds
        self._evaluation_budget_seconds = evaluation_budget_seconds

        # AnyIO limiters need an active async backend, so construct them on the
        # first request rather than during FastAPI's synchronous app setup.
        self._worker_capacity: CapacityLimiter | None = None
        self._outstanding_capacity: CapacityLimiter | None = None

    def _capacities(self) -> tuple[CapacityLimiter, CapacityLimiter]:
        """Return lazily created worker/outstanding limiters;
        inconsistent initialization raises RuntimeError.
        """
        if self._worker_capacity is None:
            self._worker_capacity = CapacityLimiter(1)
            self._outstanding_capacity = CapacityLimiter(self._max_outstanding_checks)
        if self._outstanding_capacity is None:
            raise RuntimeError("Rate-limit capacity initialization failed")
        return self._worker_capacity, self._outstanding_capacity

    async def _harden_early_response(self, request: Request, response: Response) -> Response:
        """Mutate and return response using the app hardener, or security headers plus no-store.

        Support synchronous or awaitable hardeners; errors propagate.
        """
        hardener = getattr(request.app.state, "harden_early_response", None)
        if hardener is not None:
            result = hardener(request, response)
            if inspect.isawaitable(result):
                await result
        else:
            # Standalone applications can install this middleware directly.
            # Preserve the essential header contract even without main.py's
            # path-aware response hardener.
            await _early_response_secure_headers.set_headers_async(response)  # type: ignore[arg-type]
            response.headers["Cache-Control"] = "no-store"
        return response

    async def _unavailable_response(
        self,
        request: Request,
        *,
        event_type: str,
        backend_error: BaseException | None = None,
        unexpected_error: BaseException | None = None,
    ) -> Response:
        """Log safe admission/backend diagnostics and return a hardened 503
        with the configured Retry-After.
        """
        log_context = {
            "event_type": event_type,
            "request_id": getattr(request.state, "request_id", "unknown"),
            "path": safe_request_path(request),
        }
        if backend_error is not None:
            category, exception_type = _backend_failure_category(backend_error)
            logger.error(
                "Rate-limit backend unavailable",
                extra={
                    **log_context,
                    "backend_failure_category": category,
                    "exception_type": exception_type,
                },
            )
        elif unexpected_error is None:
            logger.warning(
                "Rate-limit admission unavailable",
                extra=log_context,
            )
        else:
            logger.error(
                "Unexpected rate-limit evaluation failure",
                extra={
                    **log_context,
                    "backend_failure_category": "unexpected",
                    "exception_type": type(unexpected_error).__name__,
                },
            )

        response = Response(
            "Rate-limit service temporarily unavailable.",
            status_code=503,
            media_type="text/plain",
            headers={
                "Retry-After": str(self._busy_retry_after_seconds),
                "Cache-Control": "no-store",
            },
        )
        return await self._harden_early_response(request, response)

    async def dispatch(  # noqa: PLR0911 - each rejection path must fail closed before call_next
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """Admit through bounded serialized checks before calling downstream.

        Bypass disabled/static/exempt requests. Route, capacity, timeout, and
        backend/evaluation failures return hardened 503; exceeded limits call
        the registered RateLimitExceeded handler. Release capacity on exit;
        cancellation and downstream/handler failures propagate.
        """
        active_limiter = request.app.state.limiter
        if not active_limiter.enabled:
            return await call_next(request)

        # Static files are served by nginx in deployment and by a DB-free
        # StaticFiles mount in development. Preserve that deliberate exact
        # exemption without trying to treat an ASGI object as a function.
        if _is_static_asset_request(request):
            return await call_next(request)

        # Store a bounded route label before attempting route resolution.
        setattr(request.state, _RATE_LIMIT_LOG_PATH_STATE, _UNRESOLVED_LOG_PATH)
        try:
            handler, route_unmatched, log_path = _resolve_rate_limit_handler(request)
            setattr(request.state, _RATE_LIMIT_LOG_PATH_STATE, log_path)
            name = f"{handler.__module__}.{handler.__name__}"
            route_exempt = name in active_limiter._exempt_routes
        except Exception as exc:
            return await self._unavailable_response(
                request,
                event_type="rate_limit_route_resolution_failed",
                unexpected_error=exc,
            )

        if route_unmatched:
            setattr(request.state, _RATE_LIMIT_ROUTE_UNMATCHED_STATE, True)

        if route_exempt:
            return await call_next(request)
        worker_capacity, outstanding_capacity = self._capacities()
        try:
            outstanding_capacity.acquire_nowait()
        except WouldBlock:
            return await self._unavailable_response(
                request,
                event_type="rate_limit_capacity_exhausted",
            )

        try:
            try:
                error = await run_thread_work(
                    partial(
                        _evaluate_limits,
                        request,
                        handler,
                        active_limiter,
                        evaluation_budget_seconds=self._evaluation_budget_seconds,
                    ),
                    worker_capacity,
                    admission_timeout_seconds=self._admission_timeout_seconds,
                )
            except ThreadWorkAdmissionTimeout:
                return await self._unavailable_response(
                    request,
                    event_type="rate_limit_admission_timed_out",
                )
            except _RATE_LIMIT_BACKEND_ERRORS as exc:
                return await self._unavailable_response(
                    request,
                    event_type="rate_limit_backend_unavailable",
                    backend_error=exc,
                )
            except Exception as exc:
                return await self._unavailable_response(
                    request,
                    event_type="rate_limit_evaluation_failed",
                    unexpected_error=exc,
                )
        finally:
            outstanding_capacity.release()

        if error is not None:
            result = request.app.exception_handlers[RateLimitExceeded](request, error)
            response: Response = await result if inspect.isawaitable(result) else result
            return response
        return await call_next(request)


def setup_rate_limiting(app: FastAPI) -> None:
    """Validate and register the global limiter and middleware when enabled; otherwise do nothing.

    Callers must install the RateLimitExceeded exception handler and run
    backend readiness validation separately.
    """
    if not settings.rate_limit_enabled:
        return
    validate_rate_limit_configuration()
    app.state.limiter = limiter
    app.add_middleware(BoundedRateLimitMiddleware)
