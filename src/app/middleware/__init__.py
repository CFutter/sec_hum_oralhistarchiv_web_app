"""Middleware components — headers, sessions, CSRF, rate limiting, and audit."""

from .audit_logging import setup_audit_logging
from .content_type import validate_form_content_type
from .cookies import get_session_id_from_cookie
from .csrf import (
    CSRF_COOKIE_NAME,
    get_csrf_token,
    setup_csrf_middleware,
    verify_csrf,
)
from .database_capacity import setup_database_capacity_middleware
from .rate_limiting import limiter, setup_rate_limiting
from .security_headers import build_secure_headers
from .session import (
    clear_session_cookie,
    require_admin,
    require_full_session,
    require_local_auth,
    require_login,
    require_public_or_full_session,
    require_totp_enrollment_session,
    set_session_cookie,
    setup_session_middleware,
)
from .validators import validate_security_settings

__all__ = [
    "CSRF_COOKIE_NAME",
    "build_secure_headers",
    "clear_session_cookie",
    "get_csrf_token",
    "get_session_id_from_cookie",
    "limiter",
    "require_admin",
    "require_full_session",
    "require_local_auth",
    "require_login",
    "require_public_or_full_session",
    "require_totp_enrollment_session",
    "set_session_cookie",
    "setup_audit_logging",
    "setup_csrf_middleware",
    "setup_database_capacity_middleware",
    "setup_rate_limiting",
    "setup_session_middleware",
    "validate_form_content_type",
    "validate_security_settings",
    "verify_csrf",
]
