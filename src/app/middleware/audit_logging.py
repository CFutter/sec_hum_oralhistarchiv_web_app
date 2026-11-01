"""Audit request IDs, scrubbed URLs, statuses and response-start durations.

Skip statuses below 400 for /health and paths beginning /static/; audit
/health/detail and all errors. Host logging owns retention.
"""

import logging
import time
import uuid
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from ..request_utils import (
    get_client_ip,
    safe_request_path,
    scrub_sensitive_query,
)

audit_logger = logging.getLogger("audit")


class AuditLoggingMiddleware(BaseHTTPMiddleware):
    """Attach correlation IDs and audit completed requests or escaping Exceptions."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Set request.state.request_id, call downstream, and audit status/duration/user.

        Add X-Request-ID to returned responses. Skip successful/redirected
        health/static requests; log escaping Exceptions as 500 and re-raise.
        Duration ends when downstream returns its response, before body streaming.
        """
        request_id = uuid.uuid4().hex[:16]
        start_time = time.monotonic()

        request.state.request_id = request_id
        scrubbed_query = scrub_sensitive_query(str(request.url.query))

        try:
            response = await call_next(request)
        except Exception:
            duration_ms = (time.monotonic() - start_time) * 1000
            safe_path = safe_request_path(request)

            audit_logger.exception(
                "Request failed with unhandled exception",
                extra={
                    "request_id": request_id,
                    "event_type": "request_error",
                    "client_ip": get_client_ip(request),
                    "method": request.method,
                    "path": safe_path,
                    "duration_ms": round(duration_ms, 2),
                    "query_string": scrubbed_query,
                    "user_id": getattr(
                        getattr(request.state, "user", None),
                        "id",
                        None,
                    ),
                    "status_code": 500,
                },
            )
            raise

        duration_ms = (time.monotonic() - start_time) * 1000
        safe_path = safe_request_path(request)

        response.headers["X-Request-ID"] = request_id

        status_code = response.status_code
        if status_code >= 500:  # noqa: PLR2004
            log_level = logging.ERROR
        elif status_code >= 400:  # noqa: PLR2004
            log_level = logging.WARNING
        else:
            log_level = logging.INFO

        # Successful probes/assets would crowd user actions out of host retention.
        if (
            (request.url.path == "/health" or request.url.path.startswith("/static/"))
            and status_code < 400  # noqa: PLR2004
        ):
            return response

        audit_logger.log(
            log_level,
            "%s %s → %s",
            request.method,
            safe_path,
            status_code,
            extra={
                "request_id": request_id,
                "event_type": "request",
                "client_ip": get_client_ip(request),
                "method": request.method,
                "path": safe_path,
                "status_code": status_code,
                "duration_ms": round(duration_ms, 2),
                "query_string": scrubbed_query,
                "user_id": getattr(getattr(request.state, "user", None), "id", None),
            },
        )

        return response


def setup_audit_logging(app: FastAPI) -> None:
    """Add audit logging middleware to the application."""
    app.add_middleware(AuditLoggingMiddleware)
