"""Fail-closed SlowAPI admission before session/database work.

Hardened modes require dedicated shared Redis; dev may use memory. There
is no runtime fallback. Serialize checks in a bounded worker queue; Redis
connect/read timeouts are 0.5 seconds with no retries. Evaluation budgets
only warn. Static GET/HEAD bypasses admission; GET /search still consumes
the global start budget when per-client limiting is disabled or exempt.

Other requests use endpoint buckets; unmatched paths/methods share one
bucket and skip session lookup when limiting is enabled. Keys HMAC
canonical IPv4 or IPv6 /64 identities with an import-time SECRET_KEY-derived
key. Only rejected checks capture window statistics for response headers.
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
from typing import Any

from anyio import CapacityLimiter, WouldBlock
from fastapi import FastAPI, Request, Response
from limits.errors import ConcurrentUpdateError, ConfigurationError, StorageError
from limits.storage import Storage
from limits.storage.redis import RedisStorage
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

from config import redis_url_policy_issues, settings

from ..request_log_contract import RATE_LIMIT_LOG_PATH_STATE
from ..request_utils import get_client_ip, safe_request_path
from ..thread_work import ThreadWorkAdmissionTimeout, run_thread_work
from .bounded_rate_limit_storage import (
    BoundedRedisStorage,
    CounterCapacityError,
    SearchStartGate,
    bounded_redis_uri,
)
from .security_headers import build_secure_headers
from .slowapi_compat import (
    REDIS_OPERATION_TIMEOUT_SECONDS as _REDIS_OPERATION_TIMEOUT_SECONDS,
)
from .slowapi_compat import (
    check_request_limit,
    configured_storage_uri,
    core_configuration_issues,
    is_memory_storage,
    route_is_exempt,
    validate_dependency_shape,
)
from .slowapi_compat import (
    redis_configuration_issues as _redis_configuration_issues,
)

logger = logging.getLogger(__name__)
_storage_lock = threading.Lock()

_DEFAULT_ADMISSION_TIMEOUT_SECONDS = 0.25
_DEFAULT_MAX_OUTSTANDING_CHECKS = 8
_DEFAULT_BUSY_RETRY_AFTER_SECONDS = 1
_DEFAULT_EVALUATION_BUDGET_SECONDS = 1.0
_BACKEND_STARTUP_ADMISSION_TIMEOUT_SECONDS = 1.0
_BACKEND_PROBE_TTL_SECONDS = 5
_RATE_LIMIT_KEY_PREFIX = "oralhistarchiv-security-v1"
_RATE_LIMIT_CLIENT_ID_CONTEXT = b"oralhistarchiv-rate-limit-client-id-v1"
_STATIC_ASSET_PREFIX = "/static/"
_RATE_LIMIT_ROUTE_UNMATCHED_STATE = "rate_limit_route_unmatched"
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
    """Return category and class name after unwrapping at most four StorageError causes."""
    current = error
    for _ in range(4):
        if not isinstance(current, StorageError):
            break
        cause = current.__cause__
        if cause is None or cause is current:
            break
        current = cause

    if isinstance(current, (OutOfMemoryError, MaxConnectionsError, CounterCapacityError)):
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
    # Mounts match unsupported methods as FULL; charge them as 405s before DB lookup.
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

            # Unknown mounts may require authentication; never mark them session-free.
            logger.error(
                "Full route has no stable rate-limit endpoint identity",
                extra={"event_type": "rate_limit_endpoint_identity_missing"},
            )
            raise RuntimeError("Full route has no stable rate-limit endpoint identity")

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


def bounded_storage_options() -> dict[str, Any]:
    """Return fresh Redis connection options and configured counter/cleanup bounds."""
    return {
        **redis_storage_options(),
        "counter_capacity": settings.limiter_counter_capacity,
        "cleanup_batch_size": settings.limiter_cleanup_batch_size,
    }


def _build_limiter() -> Limiter:
    """Build the settings-driven fixed-window limiter without headers or fallback.

    Use minute/hour/day defaults, endpoint keys and enabled state; absent
    RATE_LIMIT_STORAGE_URI selects memory. Construction errors propagate.
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
        storage_uri=bounded_redis_uri(storage_uri) if storage_uri else "memory://",
        storage_options=bounded_storage_options() if storage_uri is not None else {},
        enabled=settings.rate_limit_enabled,
        headers_enabled=False,
        key_prefix=_RATE_LIMIT_KEY_PREFIX,
        key_style="endpoint",
        in_memory_fallback_enabled=False,
        swallow_errors=False,
    )


limiter = _build_limiter()

_search_start_gate = SearchStartGate(
    limiter.limiter.storage if isinstance(limiter.limiter.storage, BoundedRedisStorage) else None,
    rate=settings.search_global_rate_per_second,
    burst=settings.search_global_burst,
)


def get_search_start_gate() -> SearchStartGate:
    """Return the shared search gate, independent of per-client limiting."""
    return _search_start_gate


async def validate_search_start_gate() -> None:
    """Probe/initialize shared search admission; raise RuntimeError if unsafe or unavailable.

    Require Redis in hardened modes and rate/burst matching settings. Perform
    blocking checks in a capacity-limited thread; cancellation propagates.
    """
    gate = get_search_start_gate()
    if settings.is_hardened and gate.storage is None:
        raise RuntimeError("Shared search admission requires dedicated Redis")
    if (
        gate.rate != settings.search_global_rate_per_second
        or gate.burst != settings.search_global_burst
    ):
        raise RuntimeError("Search admission configuration differs from settings")
    try:
        ready = await run_thread_work(
            gate.check,
            CapacityLimiter(1),
            admission_timeout_seconds=_BACKEND_STARTUP_ADMISSION_TIMEOUT_SECONDS,
        )
    except Exception:
        raise RuntimeError("Required search admission backend is unavailable") from None
    if not ready:
        raise RuntimeError("Required search admission backend is unavailable")


def validate_rate_limit_configuration(active_limiter: Limiter) -> None:
    """Raise RuntimeError for unsafe effective SlowAPI settings, including hidden overrides.

    Require configured storage/identity/strategy/key policy, no swallowed
    errors or fallback, and bounded Redis options. Hardened mode requires
    a configured Redis URI; development alone permits MemoryStorage.
    """
    validate_dependency_shape(active_limiter)
    issues = core_configuration_issues(
        active_limiter,
        key_func=get_rate_limit_client_id,
        enabled=settings.rate_limit_enabled,
        key_prefix=_RATE_LIMIT_KEY_PREFIX,
    )
    storage = active_limiter.limiter.storage
    resolved_storage_uri = settings.rate_limit_storage_uri
    expected_storage_uri = (
        bounded_redis_uri(resolved_storage_uri) if resolved_storage_uri else "memory://"
    )
    if configured_storage_uri(active_limiter) != expected_storage_uri:
        issues.append("constructed storage URI differs from resolved limiter settings")
    if settings.is_hardened and resolved_storage_uri is None:
        issues.append("hardened environment has no dedicated rate-limit Redis URL")
    if settings.is_hardened and (not settings.rate_limit_enabled or not active_limiter.enabled):
        issues.append("hardened web admission must be enabled")

    if resolved_storage_uri is not None:
        issues.extend(
            redis_url_policy_issues(
                resolved_storage_uri, hardened=settings.is_hardened, dedicated=True
            )
        )
        issues.extend(_redis_configuration_issues(active_limiter, storage))
        if not isinstance(storage, BoundedRedisStorage):
            issues.append("Redis storage does not enforce bounded counter allocation")
        elif (
            storage.counter_capacity != settings.limiter_counter_capacity
            or storage.cleanup_batch_size != settings.limiter_cleanup_batch_size
        ):
            issues.append("effective counter allocation bounds differ from settings")
    elif not is_memory_storage(storage):
        issues.append("development memory mode constructed unexpected storage")

    if issues:
        raise RuntimeError("Unsafe effective rate-limit configuration: " + "; ".join(issues))


def _probe_rate_limit_backend(storage: Storage) -> bool:
    """Probe bounded Redis readiness, or test a random five-second counter on other storage.

    Bounded Redis validates its namespace and set/read/TTL/deletes a fixed
    readiness key. Other backends ping/check, increment/read and verify expiry;
    after successful increment always clear and verify deletion. Return False
    for invalid results; storage/cleanup errors propagate. A lost increment
    response may leave a TTL-bound key.
    """
    if isinstance(storage, BoundedRedisStorage):
        return storage.probe()
    probe_key = f"startup-readiness-{secrets.token_hex(16)}"
    increment_completed = False

    try:
        # Bypass check(), which hides typed connection errors needed by startup telemetry.
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


async def validate_rate_limit_backend(active_limiter: Limiter) -> None:
    """Validate configuration, then probe enabled non-memory storage in a bounded worker.

    Raise RuntimeError and log safe categories on probe failure. Disabled
    limiting/development memory skips the probe; cancellation propagates.
    """
    validate_rate_limit_configuration(active_limiter)
    if not settings.rate_limit_enabled or settings.rate_limit_storage_uri is None:
        return

    capacity = CapacityLimiter(1)
    try:
        healthy = await run_thread_work(
            partial(_probe_rate_limit_backend, active_limiter.limiter.storage),
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
    search_start: bool = False,
) -> RateLimitExceeded | bool | None:
    """Check per-client limits and optional search admission under the process-wide lock.

    Run only in a worker. Return RateLimitExceeded with captured window stats,
    False for an exhausted search start budget, or None when admitted; storage
    errors propagate. Mark enabled checks complete and record elapsed seconds
    on request.state. evaluation_budget_seconds only triggers a warning.
    """
    started_at = time.monotonic()
    try:
        with _storage_lock:
            if active_limiter.enabled:
                try:
                    check_request_limit(active_limiter, request, handler)
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
            # An already exhausted client must not consume the shared budget.
            # Both decisions still happen before downstream session/database work.
            if search_start and not get_search_start_gate().acquire():
                return False
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
        search_busy_response: Callable[[Request], Response] | None = None,
    ) -> None:
        """Configure positive admission/evaluation seconds and positive queue/retry values.

        max_outstanding_checks includes running and waiting requests; invalid
        values raise ValueError. evaluation_budget_seconds is a warning threshold.
        Async capacities are created lazily in the owning event loop. An optional
        search-busy renderer must not resolve sessions, access the database or
        write cookies; it runs before downstream admission.
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
        self._search_busy_response = search_busy_response

        # AnyIO limiters need an active async backend, so construct them on the
        # first request rather than during FastAPI's synchronous app setup.
        self._worker_capacity: CapacityLimiter | None = None
        self._outstanding_capacity: CapacityLimiter | None = None

    def _capacities(self) -> tuple[CapacityLimiter, CapacityLimiter]:
        """Return lazy worker/queue limiters; raise RuntimeError for inconsistent initialization."""
        if self._worker_capacity is None:
            self._worker_capacity = CapacityLimiter(1)
            self._outstanding_capacity = CapacityLimiter(self._max_outstanding_checks)
        if self._outstanding_capacity is None:
            raise RuntimeError("Rate-limit capacity initialization failed")
        return self._worker_capacity, self._outstanding_capacity

    async def _unavailable_response(
        self,
        request: Request,
        *,
        event_type: str,
        backend_error: BaseException | None = None,
        unexpected_error: BaseException | None = None,
    ) -> Response:
        """Log safe admission/backend diagnostics and return a hardened 503.

        Distinguish a consumed search start budget from unavailable admission
        storage in the public wording and text logs; retain Retry-After.
        """
        search_busy = event_type == "search_start_budget_exhausted"
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
                "Search start budget exhausted"
                if search_busy
                else "Rate-limit admission unavailable",
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

        if search_busy and self._search_busy_response is not None:
            response = self._search_busy_response(request)
        else:
            response = Response(
                (
                    "Search is temporarily busy. Please wait briefly and try again."
                    if search_busy
                    else "Rate-limit service temporarily unavailable."
                ),
                media_type="text/plain",
            )
        response.status_code = 503
        response.headers["Retry-After"] = str(self._busy_retry_after_seconds)
        response.headers["Cache-Control"] = "no-store"
        # Early refusals bypass the downstream security-header middleware.
        await _early_response_secure_headers.set_headers_async(response)  # type: ignore[arg-type]
        return response

    async def dispatch(  # noqa: PLR0911 - each rejection path must fail closed before call_next
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """Admit through bounded serialized checks before calling downstream.

        Static GET/HEAD bypasses admission. Disabled/exempt per-client checks still
        apply the global budget to GET /search. Route, queue, timeout and backend
        failures return secured no-store 503 responses; exceeded client limits use
        the registered RateLimitExceeded handler. Release capacity on exit;
        cancellation and downstream/handler failures propagate.
        """
        active_limiter = request.app.state.limiter
        # StaticFiles is ASGI, so exempt it before resolving callable handler identities.
        if _is_static_asset_request(request):
            return await call_next(request)

        setattr(request.state, RATE_LIMIT_LOG_PATH_STATE, _UNRESOLVED_LOG_PATH)
        try:
            handler, route_unmatched, log_path = _resolve_rate_limit_handler(request)
            setattr(request.state, RATE_LIMIT_LOG_PATH_STATE, log_path)
            route_exempt = route_is_exempt(active_limiter, handler)
        except Exception as exc:
            return await self._unavailable_response(
                request,
                event_type="rate_limit_route_resolution_failed",
                unexpected_error=exc,
            )

        if route_unmatched and active_limiter.enabled:
            setattr(request.state, _RATE_LIMIT_ROUTE_UNMATCHED_STATE, True)

        search_start = request.method == "GET" and not route_unmatched and log_path == "/search"
        if not search_start and (route_exempt or not active_limiter.enabled):
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
                        search_start=search_start,
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

        if error is False:
            return await self._unavailable_response(
                request,
                event_type="search_start_budget_exhausted",
            )
        if error is not None:
            result = request.app.exception_handlers[RateLimitExceeded](request, error)
            response: Response = await result if inspect.isawaitable(result) else result
            return response
        return await call_next(request)


def setup_rate_limiting(
    app: FastAPI,
    active_limiter: Limiter,
    *,
    search_busy_response: Callable[[Request], Response] | None = None,
) -> None:
    """Register admission before session resolution, including when limits are disabled.

    Readiness must validate this same app.state.limiter. Applications using
    decorated routes must pass the instance that owns those declarations. The
    optional renderer customizes only exhausted search budgets, retaining the
    early refusal's status and response-security headers.
    """
    app.state.limiter = active_limiter
    validate_rate_limit_configuration(active_limiter)
    app.add_middleware(BoundedRateLimitMiddleware, search_busy_response=search_busy_response)
