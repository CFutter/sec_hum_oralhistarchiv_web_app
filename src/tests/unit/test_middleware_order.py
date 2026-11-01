"""Pin the live nesting order of the application's middleware stack."""

from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.main import app
from app.middleware.audit_logging import AuditLoggingMiddleware
from app.middleware.csrf import CSRFCookieMiddleware
from app.middleware.rate_limiting import BoundedRateLimitMiddleware
from app.middleware.session import SessionResolutionMiddleware


def _outer_to_inner() -> list[Middleware]:
    """Return configured middleware in outer-to-inner registration order."""
    return list(app.user_middleware)


def _index_of(cls: type) -> int:
    """Find a middleware factory by identity, failing if it is absent."""
    for index, middleware in enumerate(_outer_to_inner()):
        factory: object = middleware.cls
        if factory is cls:
            return index
    raise AssertionError(f"{cls.__name__} is not wired into app.user_middleware")


def _index_of_secure_headers() -> int:
    """The security-headers step is a plain ``@app.middleware("http")``
    function, so it is wired as ``BaseHTTPMiddleware(dispatch=set_secure_headers)``
    rather than under its own class."""
    for index, middleware in enumerate(_outer_to_inner()):
        factory: object = middleware.cls
        dispatch = middleware.kwargs.get("dispatch")
        if factory is BaseHTTPMiddleware and getattr(dispatch, "__name__", None) == (
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
    """The live stack preserves the middleware's documented admission boundaries."""

    def test_rate_admission_wraps_session_resolution(self):
        """Rate admission can reject a request before database session lookup."""
        assert _index_of(BoundedRateLimitMiddleware) < _index_of(SessionResolutionMiddleware)

    def test_pool_saturation_is_mapped_to_503_before_rate_admission(self):
        """Database-capacity handling sits inside TrustedHost and wraps rate admission."""
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
