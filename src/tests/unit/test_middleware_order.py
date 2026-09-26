"""Pin the live nesting order of the application's middleware stack.

``Starlette.add_middleware`` inserts each call at the front of
``app.user_middleware``, so that list is already outermost-first: index 0
processes a request before index 1, and so on down to the router. This
module asserts against ``app.user_middleware`` directly rather than
re-deriving the ordering rules, and keeps the two known gaps between the
wiring and its own docstrings visible as strict, marked failures instead of
silently passing tests.
"""

from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.main import app
from app.middleware.audit_logging import AuditLoggingMiddleware
from app.middleware.csrf import CSRFCookieMiddleware
from app.middleware.rate_limiting import BoundedRateLimitMiddleware
from app.middleware.session import SessionResolutionMiddleware


def _outer_to_inner() -> list[Middleware]:
    return list(app.user_middleware)


def _index_of(cls: type) -> int:
    for index, middleware in enumerate(_outer_to_inner()):
        if middleware.cls is cls:
            return index
    raise AssertionError(f"{cls.__name__} is not wired into app.user_middleware")


def _index_of_secure_headers() -> int:
    """The security-headers step is a plain ``@app.middleware("http")``
    function, so it is wired as ``BaseHTTPMiddleware(dispatch=set_secure_headers)``
    rather than under its own class."""
    for index, middleware in enumerate(_outer_to_inner()):
        dispatch = middleware.kwargs.get("dispatch")
        if middleware.cls is BaseHTTPMiddleware and getattr(dispatch, "__name__", None) == (
            "set_secure_headers"
        ):
            return index
    raise AssertionError("set_secure_headers is not wired into app.user_middleware")


class TestTheWiredMiddlewareOrder:
    """The order actually built by ``app.main`` at import time."""

    def test_trusted_host_is_the_outermost_middleware(self):
        """TrustedHost must reject an unknown Host header before any other
        middleware — including CORS and audit logging — spends cycles on
        the request."""
        assert _index_of(TrustedHostMiddleware) == 0

    def test_csrf_cookie_is_the_innermost_middleware(self):
        """CSRF cookie issuance is the last middleware step before routing,
        so it can decide off the final, most-specific request state."""
        assert _index_of(CSRFCookieMiddleware) == len(_outer_to_inner()) - 1

    def test_audit_logging_is_outside_session_resolution(self):
        """Audit must observe the whole request, including a session
        lookup that fails or never runs, so it wraps session resolution."""
        assert _index_of(AuditLoggingMiddleware) < _index_of(SessionResolutionMiddleware)

    def test_secure_headers_is_inside_rate_admission(self):
        """The security-headers step must run only for requests rate
        admission has already let through, so it nests inside
        BoundedRateLimitMiddleware."""
        assert _index_of_secure_headers() > _index_of(BoundedRateLimitMiddleware)


class TestTheOrderTheMiddlewareDocstringsClaim:
    """Two gaps between what the middleware modules document and what
    ``app.main`` actually wires. Each is recorded as a strict failure so a
    future ordering refactor is forced to either fix the wiring or remove
    the marker — not silently regress a passing assertion.
    """

    def test_rate_admission_wraps_session_resolution(self):
        """``rate_limiting.py`` and ``session.py`` both document rate
        admission running outside (wrapping) session resolution, so that a
        429 is decided before any database session lookup. The wired stack
        does the opposite."""
        assert _index_of(BoundedRateLimitMiddleware) < _index_of(SessionResolutionMiddleware)

    def test_pool_saturation_is_mapped_to_503_before_rate_admission(self):
        """A dedicated exception-mapping middleware is specified to sit
        between CORS/TrustedHost and rate admission, converting a
        database-pool-exhaustion exception into a 503 before the limiter
        runs. No such middleware is registered."""
        candidates = [
            middleware
            for middleware in _outer_to_inner()
            if "capacity" in middleware.cls.__name__.lower()
            or "pool" in middleware.cls.__name__.lower()
        ]
        assert candidates, "no database-capacity exception-mapping middleware is registered"
        capacity_index = _outer_to_inner().index(candidates[0])
        assert (
            _index_of(TrustedHostMiddleware)
            < capacity_index
            < _index_of(BoundedRateLimitMiddleware)
        )
