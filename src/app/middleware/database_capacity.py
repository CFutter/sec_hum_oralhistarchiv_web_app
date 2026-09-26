"""Translate exhausted PostgreSQL pool admission into retryable no-store HTTP 503 responses."""

from fastapi import FastAPI, Request, Response
from psycopg_pool import PoolTimeout, TooManyRequests
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from config import settings

from .security_headers import build_secure_headers

_RETRY_AFTER_SECONDS = 5
_secure_headers = build_secure_headers(settings.is_production)


class DatabaseCapacityMiddleware(BaseHTTPMiddleware):
    """Catch PoolTimeout/TooManyRequests from downstream and apply security headers."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Return downstream output or a secured 503 with Retry-After: 5 on pool saturation."""
        try:
            return await call_next(request)
        except (PoolTimeout, TooManyRequests):
            response = Response(
                "Service temporarily unavailable. Please try again shortly.",
                status_code=503,
                media_type="text/plain",
                headers={"Retry-After": str(_RETRY_AFTER_SECONDS), "Cache-Control": "no-store"},
            )
            await _secure_headers.set_headers_async(response)  # type: ignore[arg-type]
            return response


def setup_database_capacity_middleware(app: FastAPI) -> None:
    """Register the pool-capacity error boundary on app."""
    app.add_middleware(DatabaseCapacityMiddleware)
