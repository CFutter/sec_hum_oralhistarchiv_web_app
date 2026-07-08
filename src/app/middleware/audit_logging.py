"""
Audit logging middleware.

Logs every request with:
- Unique request ID (for tracing)
- Client IP
- Method, path, status code
- Duration
- User ID (from session middleware)

Sensitive data (tokens in URL paths, free-text query parameters) is scrubbed
before logging. Audit log retention is managed by systemd-journald — see
/etc/systemd/journald.conf.d/oralhistarchiv.conf and the deploy runbook for
retention configuration.
"""

import logging
import time
import uuid
import re

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from .utils import get_client_ip

audit_logger = logging.getLogger("audit")


_TOKEN_PATH_REGEX = re.compile(
    r"^(/(?:reset-password|verify-email|account/confirm-email))/[^/?]+"
)


_SAFE_QUERY_PARAMS = frozenset({
    "page",
    "keyword",
    "language",
    "access_level"     
})


def _scrub_path(path: str) -> str:
    """Replace token segments in sensitive paths with a placeholder."""
    return _TOKEN_PATH_REGEX.sub(r"\1/<token>", path)


def _scrub_query(query_string: str) -> str:
    """Redact non-allowlisted query parameter values.

    Free-text params (search 'q', 'email') may contain PII that shouldn't
    persist for the audit-log retention window (journald-configured; see
    the deployment runbook). Categorical params (page, language, etc.) are
    kept for analytics.
    """
    if not query_string:
        return ""
    
    pairs = []
    for kv in query_string.split("&"):
        if "=" not in kv:
            pairs.append(kv)
            continue
        key, _, value = kv.partition("=")
        if key in _SAFE_QUERY_PARAMS:
            pairs.append(f"{key}={value}")
        else:
            pairs.append(f"{key}=<redacted>")
    return "&".join(pairs)


class AuditLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        """Log every request with a unique ID, client IP, status, and duration."""
        request_id = uuid.uuid4().hex[:16]
        start_time = time.monotonic()

        request.state.request_id = request_id
        scrubbed_path = _scrub_path(request.url.path)
        scrubbed_query = _scrub_query(str(request.url.query))

        try:
            response = await call_next(request)
        except Exception:
            duration_ms = (time.monotonic() - start_time) * 1000
            audit_logger.exception(
                "Request failed with unhandled exception",
                extra={
                    "request_id": request_id,
                    "event_type": "request_error",
                    "client_ip": get_client_ip(request),
                    "method": request.method,
                    "path": scrubbed_path,
                    "duration_ms": round(duration_ms, 2),
                    "query_string": scrubbed_query,
                },
            )
            raise

        duration_ms = (time.monotonic() - start_time) * 1000

        response.headers["X-Request-ID"] = request_id

        status_code = response.status_code
        if status_code >= 500:
            log_level = logging.ERROR
        elif status_code >= 400:
            log_level = logging.WARNING
        else:
            log_level = logging.INFO

        audit_logger.log(
            log_level,
            f"{request.method} {scrubbed_path} → {status_code}",
            extra={
                "request_id": request_id,
                "event_type": "request",
                "client_ip": get_client_ip(request),
                "method": request.method,
                "path": scrubbed_path,
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